package nodeid

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"time"

	"offgrid/dtn-node/internal/bundle"
)

// The role certificate of docs/node-network.md §2.2: a CBOR map with the
// FIXED key order 0..7, wrapped in a COSE_Sign1 (RFC 9052) signed by the
// offline anchor key. Encoding goes through the single canonical CBOR
// encoder of internal/bundle; decoding through the same package's minimal
// canonical reader (reader.go) — the same bytes fail the same way in C
// (esp32/components/dtn_core/dtn_rolecert.c).

const (
	// CertVersion is the only valid `v` (an unknown v is invalid, §2.2).
	CertVersion = 1
	// MaxCertSkew is the §4.3 skew rule applied to issued_ts:
	// issued_ts MUST be ≤ verifier now + 300.
	MaxCertSkew = int64(300)
	// MaxLevel is the highest authority ceiling (§2.4, L3 ownership).
	MaxLevel = 3
	// coseAlgEdDSA is the RFC 9052 algorithm label for EdDSA (Ed25519).
	coseAlgEdDSA = int64(-8)
	// coseHeaderAlg / coseHeaderKid are the COSE common parameters used:
	// protected {1: -8}, unprotected {4: kid}.
	coseHeaderAlg = 1
	coseHeaderKid = 4
	// maxCertPayload bounds the cert map a verifier will even look at
	// (the realistic cert is ≈ 100-130 bytes; 1 KiB is generous).
	maxCertPayload = 1024
)

// Roles of §2.3 (provisioned, signed, static in v1).
const (
	RoleEdge    = "edge"
	RoleRelay   = "relay"
	RoleBridge  = "bridge"
	RoleManager = "manager"
	RoleAnchor  = "anchor"
)

// ValidRoles is the closed set of §2.3 role names; anything else fails the
// schema check (fail-closed: a typo must not silently mint a role).
var ValidRoles = map[string]bool{
	RoleEdge: true, RoleRelay: true, RoleBridge: true, RoleManager: true, RoleAnchor: true,
}

// VerifyError classifies every role-cert rejection with the stable codes the
// shared vectors (tests/vectors/nodeid/vectors.json) and the capsuletool CLI
// print. Code is machine-stable; Msg is for humans.
type VerifyError struct {
	Code string
	Msg  string
}

func (e *VerifyError) Error() string { return "nodeid: " + e.Code + ": " + e.Msg }

// Stable verification failure codes (the negative vectors cover a subset).
const (
	CodeCOSEShape          = "cose_shape"
	CodeBadProtected       = "bad_protected"
	CodeWrongAnchorFP      = "wrong_anchor_fp"
	CodeBadSignature       = "bad_signature"
	CodeCertSchema         = "cert_schema"
	CodeBadVersion         = "bad_version"
	CodeUnknownRole        = "unknown_role"
	CodeLevelRolesMismatch = "level_roles_mismatch"
	CodeBadEIDBinding      = "bad_eid_binding"
	CodeBadTimestamps      = "bad_ts"
	CodeBadSeq             = "bad_seq"
	CodeExpired            = "expired"
)

func verr(code, format string, a ...any) error {
	return &VerifyError{Code: code, Msg: fmt.Sprintf(format, a...)}
}

// ErrorCode extracts the stable code from an error ("" if not a VerifyError).
func ErrorCode(err error) string {
	var ve *VerifyError
	if errors.As(err, &ve) {
		return ve.Code
	}
	return ""
}

// ErrExpired marks a genuinely-signed cert whose validity window has passed
// (§2.5 rule 5: treated as absent — no authority; mail MAY still forward).
var ErrExpired = errors.New("nodeid: role certificate expired")

// Cert is a parsed, signature-verified role certificate. raw is the exact
// COSE_Sign1 byte string received — the merge rules of §2.5 compare raw
// bytes at equal seq, so it is never re-serialized.
type Cert struct {
	Version   uint64
	EID       string
	NodeKey   []byte // 32 bytes
	Roles     []string
	Level     uint64
	IssuedTS  int64
	ExpiresTS int64
	Seq       uint64

	raw []byte
}

// Raw returns the exact COSE_Sign1 bytes the cert was parsed from (nil on a
// cert that was never parsed).
func (c *Cert) Raw() []byte { return c.raw }

// Revocation reports whether this is a §2.5 rule-4 revocation record: roles
// cleared. It blocks management authority; mail stays receivable.
func (c *Cert) Revocation() bool { return len(c.Roles) == 0 }

// Expired applies the §2.5 rule-5 boundary: expires_ts < now (strictly — a
// cert expiring exactly at now is still live).
func (c *Cert) Expired(now int64) bool { return c.ExpiresTS < now }

// HasRole reports membership in the closed §2.3 set.
func (c *Cert) HasRole(role string) bool {
	for _, r := range c.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// String is the operator-facing one-liner (capsuletool request/verify echo
// the same fields).
func (c *Cert) String() string {
	return fmt.Sprintf("eid=%s roles=%s level=%d issued_ts=%d expires_ts=%d seq=%d",
		c.EID, strings.Join(c.Roles, ","), c.Level, c.IssuedTS, c.ExpiresTS, c.Seq)
}

// ValidateCertFields enforces the §2.2 constraint column against a wall
// clock. It is the exact check set of VerifyCert, separated so the signer
// (capsuletool rolecert sign) refuses to BUILD a cert it would itself
// reject. roles empty + level 0 is the revocation form and is valid here;
// expiry is NOT a schema violation (an expired cert parses fine; §2.5 rule 5
// decides what it is worth at evaluation time).
func ValidateCertFields(eid string, nodeKey []byte, roles []string, level uint64, issued, expires int64, seq uint64, now int64) error {
	if len(nodeKey) != KeyLen {
		return verr(CodeCertSchema, "node_key must be %d bytes, got %d", KeyLen, len(nodeKey))
	}
	if err := ValidateBinding(nodeKey, eid); err != nil {
		return verr(CodeBadEIDBinding, "%v", err)
	}
	seen := make(map[string]bool, len(roles))
	for _, r := range roles {
		if !ValidRoles[r] {
			return verr(CodeUnknownRole, "role %q is not one of edge|relay|bridge|manager|anchor", r)
		}
		if seen[r] {
			return verr(CodeCertSchema, "duplicate role %q (roles are a set)", r)
		}
		seen[r] = true
	}
	if level > MaxLevel {
		return verr(CodeLevelRolesMismatch, "level %d exceeds the ceiling 3", level)
	}
	// 0 iff roles empty: an empty-roles record is a revocation (level 0
	// mandatory); any real role carries at least L1.
	if len(roles) == 0 && level != 0 {
		return verr(CodeLevelRolesMismatch, "revocation record (empty roles) MUST carry level 0, got %d", level)
	}
	if len(roles) > 0 && level == 0 {
		return verr(CodeLevelRolesMismatch, "cert with roles %s MUST carry level ≥ 1, got 0", strings.Join(roles, ","))
	}
	if issued <= 0 {
		return verr(CodeBadTimestamps, "issued_ts must be > 0, got %d", issued)
	}
	if issued > now+MaxCertSkew {
		return verr(CodeBadTimestamps, "issued_ts %d is more than %ds ahead of now %d", issued, MaxCertSkew, now)
	}
	if expires <= issued {
		return verr(CodeBadTimestamps, "expires_ts %d must be > issued_ts %d", expires, issued)
	}
	if seq < 1 {
		return verr(CodeBadSeq, "seq must be ≥ 1, got %d", seq)
	}
	return nil
}

// EncodeCertMap writes the §2.2 CBOR map — keys 0..7 in ascending order,
// the canonical encoding — with the shared bundle encoder.
func EncodeCertMap(c *Cert) []byte {
	return bundle.EncodeCbor(func(e *bundle.Cbor) {
		e.MapHead(8)
		e.Uint(0)
		e.Uint(uint64(c.Version))
		e.Uint(1)
		e.Tstr(c.EID)
		e.Uint(2)
		e.Bstr(c.NodeKey)
		e.Uint(3)
		e.Array(len(c.Roles))
		for _, r := range c.Roles {
			e.Tstr(r)
		}
		e.Uint(4)
		e.Uint(c.Level)
		e.Uint(5)
		e.Uint(uint64(c.IssuedTS))
		e.Uint(6)
		e.Uint(uint64(c.ExpiresTS))
		e.Uint(7)
		e.Uint(c.Seq)
	})
}

// coseProtectedHeader is the exact protected header of v1: {1: -8}.
func coseProtectedHeader() []byte {
	return bundle.EncodeCbor(func(e *bundle.Cbor) {
		e.MapHead(1)
		e.Uint(coseHeaderAlg)
		e.Negint(coseAlgEdDSA)
	})
}

// signCertBytes encodes + signs a Cert whose fields are already validated:
// Sig_structure = ["Signature1", protected, external_aad(empty bstr),
// payload] per RFC 9052 §4.4; the COSE_Sign1 carries the unprotected kid =
// the anchor fingerprint (8 bytes of SHA-256) for key selection.
func signCertBytes(anchor KeyPair, c *Cert) ([]byte, error) {
	payload := EncodeCertMap(c)
	protected := coseProtectedHeader()
	sigStruct := bundle.EncodeCbor(func(e *bundle.Cbor) {
		e.Array(4)
		e.Tstr("Signature1")
		e.Bstr(protected)
		e.Bstr(nil) // external_aad: empty bstr, frozen by §2.2
		e.Bstr(payload)
	})
	sig := ed25519.Sign(anchor.Private, sigStruct)
	fp := Fingerprint(anchor.Public)
	return bundle.EncodeCbor(func(e *bundle.Cbor) {
		e.Array(4) // COSE_Sign1
		e.Bstr(protected)
		e.MapHead(1)
		e.Uint(coseHeaderKid)
		e.Bstr(fp[:])
		e.Bstr(payload)
		e.Bstr(sig)
	}), nil
}

// SignCert builds and signs a role certificate (§2.2). Fields are validated
// FIRST (the same rules VerifyCert applies), so the ceremony cannot issue a
// cert the fleet would drop.
func SignCert(anchor KeyPair, nodePub []byte, eid string, roles []string, level uint64, issued, expires int64, seq uint64, now int64) ([]byte, error) {
	if len(anchor.Public) != KeyLen || len(anchor.Private) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("nodeid: anchor keypair is not a complete Ed25519 pair")
	}
	c := &Cert{Version: CertVersion, EID: eid, NodeKey: append([]byte(nil), nodePub...),
		Roles: append([]string(nil), roles...), Level: level, IssuedTS: issued, ExpiresTS: expires, Seq: seq}
	if err := ValidateCertFields(eid, nodePub, roles, level, issued, expires, seq, now); err != nil {
		return nil, err
	}
	return signCertBytes(anchor, c)
}

// SignCertFull is SignCert for a fully-populated Cert (the vector generator
// and the CLI use it): it validates, then produces the COSE_Sign1 bytes.
func SignCertFull(anchor KeyPair, c *Cert, now int64) ([]byte, error) {
	return SignCert(anchor, c.NodeKey, c.EID, c.Roles, c.Level, c.IssuedTS, c.ExpiresTS, c.Seq, now)
}

// VerifyCert parses and fully verifies a COSE_Sign1 role certificate
// against the PINNED anchor public key at wall clock now (§2.2):
//
//  1. COSE_Sign1 shape: [bstr protected, map unprotected, bstr payload,
//     bstr(64) signature]; no trailing bytes.
//  2. protected decodes to EXACTLY {1: -8} in canonical bytes.
//  3. unprotected kid (bstr(8)) MUST equal SHA-256(anchorPub)[0:8].
//  4. Ed25519 verify over the reconstructed RFC 9052 Sig_structure.
//  5. Schema: the §2.2 table, every row (ValidateCertFields).
//  6. Expiry: expires_ts < now → the Cert plus ErrExpired (the bytes were
//     genuinely signed; §2.5 rule 5 decides what they are worth: absent).
func VerifyCert(cose, anchorPub []byte, now int64) (*Cert, error) {
	if len(anchorPub) != KeyLen {
		return nil, verr(CodeCOSEShape, "anchor public key must be %d bytes, got %d", KeyLen, len(anchorPub))
	}
	protected, kid, payload, sig, err := parseCOSE(cose)
	if err != nil {
		return nil, err
	}

	// Protected: exactly the canonical bytes of {1: -8}. Anything else — a
	// second header, a different alg, a non-canonical encoding — fails
	// closed (the Sig_structure is built from these very bytes, so the
	// signature may be genuinely valid over garbage unless the header is
	// pinned here).
	wantProtected := coseProtectedHeader()
	if string(protected) != string(wantProtected) {
		return nil, verr(CodeBadProtected, "protected header must be exactly {1: -8}, got %x", protected)
	}

	// Unprotected kid selects the anchor: MUST match the pinned key's
	// fingerprint byte-for-byte.
	fp := Fingerprint(anchorPub)
	if len(kid) != FingerprintLen || string(kid) != string(fp[:]) {
		return nil, verr(CodeWrongAnchorFP, "unprotected kid %x is not the pinned anchor fingerprint %x", kid, fp)
	}

	sigStruct := bundle.EncodeCbor(func(e *bundle.Cbor) {
		e.Array(4)
		e.Tstr("Signature1")
		e.Bstr(protected)
		e.Bstr(nil) // external_aad: empty bstr
		e.Bstr(payload)
	})
	if !ed25519.Verify(anchorPub, sigStruct, sig) {
		return nil, verr(CodeBadSignature, "Ed25519 verification failed against the pinned anchor")
	}

	c, err := parseCertMap(payload)
	if err != nil {
		return nil, err
	}
	c.raw = append([]byte(nil), cose...)
	if err := ValidateCertFields(c.EID, c.NodeKey, c.Roles, c.Level, c.IssuedTS, c.ExpiresTS, c.Seq, now); err != nil {
		return nil, err
	}
	if c.Expired(now) {
		return c, fmt.Errorf("%w: %w", ErrExpired, verr(CodeExpired, "expires_ts %d < now %d — treated as absent (§2.5 rule 5)", c.ExpiresTS, now))
	}
	return c, nil
}

// parseCOSE takes the COSE_Sign1 array apart. Shape failures are cose_shape.
func parseCOSE(cose []byte) (protected, kid, payload, sig []byte, err error) {
	r := bundle.NewCborReader(cose)
	n, err := r.Array()
	if err != nil {
		return nil, nil, nil, nil, verr(CodeCOSEShape, "not a COSE_Sign1 array: %v", err)
	}
	if n != 4 {
		return nil, nil, nil, nil, verr(CodeCOSEShape, "COSE_Sign1 must be array(4), got array(%d)", n)
	}
	if protected, err = r.Bstr(); err != nil {
		return nil, nil, nil, nil, verr(CodeCOSEShape, "protected header: %v", err)
	}
	if protected, err = copyOf(protected); err != nil {
		return nil, nil, nil, nil, verr(CodeCOSEShape, "%v", err)
	}
	if err = parseUnprotected(r, &kid); err != nil {
		return nil, nil, nil, nil, err
	}
	if payload, err = r.Bstr(); err != nil {
		return nil, nil, nil, nil, verr(CodeCOSEShape, "payload: %v", err)
	}
	if payload, err = copyOf(payload); err != nil {
		return nil, nil, nil, nil, verr(CodeCOSEShape, "%v", err)
	}
	if sig, err = r.Bstr(); err != nil {
		return nil, nil, nil, nil, verr(CodeCOSEShape, "signature: %v", err)
	}
	if sig, err = copyOf(sig); err != nil {
		return nil, nil, nil, nil, verr(CodeCOSEShape, "%v", err)
	}
	if !r.Done() {
		return nil, nil, nil, nil, verr(CodeCOSEShape, "%d trailing bytes after the COSE_Sign1", len(cose)-r.Pos())
	}
	return protected, kid, payload, sig, nil
}

// parseUnprotected reads exactly {4: bstr(8)} (the kid map).
func parseUnprotected(r *bundle.CborReader, kid *[]byte) error {
	n, err := r.Map()
	if err != nil {
		return verr(CodeCOSEShape, "unprotected header: %v", err)
	}
	defer r.Pop()
	if n != 1 {
		return verr(CodeCOSEShape, "unprotected header must be map(1), got map(%d)", n)
	}
	label, err := r.Uint()
	if err != nil {
		return verr(CodeCOSEShape, "unprotected label: %v", err)
	}
	if label != coseHeaderKid {
		return verr(CodeCOSEShape, "unprotected header must carry label 4 (kid), got %d", label)
	}
	k, err := r.Bstr()
	if err != nil {
		return verr(CodeCOSEShape, "kid: %v", err)
	}
	if len(k) != FingerprintLen {
		return verr(CodeCOSEShape, "kid must be bstr(8), got %d bytes", len(k))
	}
	*kid = append([]byte(nil), k...)
	return nil
}

func copyOf(b []byte) ([]byte, error) {
	out := make([]byte, len(b))
	copy(out, b)
	return out, nil
}

// parseCertMap walks the §2.2 cert map: exactly 8 pairs, keys 0..7 in
// ascending order, each value the table's type. Anything else — an extra
// key, a missing key, a reordered map, a wrong type — fails closed: the
// merge rules compare raw bytes at equal seq, so a lenient parser here
// would make the conflict signal unreliable.
func parseCertMap(payload []byte) (*Cert, error) {
	schema := func(format string, a ...any) error {
		return verr(CodeCertSchema, format, a...)
	}
	r := bundle.NewCborReader(payload)
	n, err := r.Map()
	if err != nil {
		return nil, schema("cert payload: %v", err)
	}
	defer r.Pop()
	if n != 8 {
		return nil, schema("cert map must have exactly 8 pairs, got %d", n)
	}
	c := &Cert{}
	// keys arrive in canonical ascending order 0..7 (fixed key order, §2.2).
	for want := 0; want < 8; want++ {
		k, err := r.Uint()
		if err != nil {
			return nil, schema("cert map key %d: %v", want, err)
		}
		if k != uint64(want) {
			return nil, schema("cert map keys must be 0..7 in order, got %d where %d was due", k, want)
		}
		switch want {
		case 0: // v
			if c.Version, err = r.Uint(); err != nil {
				return nil, schema("v: %v", err)
			}
			if c.Version != CertVersion {
				return nil, verr(CodeBadVersion, "cert v must be %d, got %d", CertVersion, c.Version)
			}
		case 1: // node_eid
			if c.EID, err = r.Tstr(); err != nil {
				return nil, schema("node_eid: %v", err)
			}
		case 2: // node_key
			if c.NodeKey, err = r.Bstr(); err != nil {
				return nil, schema("node_key: %v", err)
			}
			if len(c.NodeKey) != KeyLen {
				return nil, schema("node_key must be bstr(32), got %d bytes", len(c.NodeKey))
			}
			c.NodeKey = append([]byte(nil), c.NodeKey...)
		case 3: // roles
			m, err := r.Array()
			if err != nil {
				return nil, schema("roles: %v", err)
			}
			if m > len(ValidRoles) {
				return nil, schema("roles array has %d entries (the role set has %d)", m, len(ValidRoles))
			}
			for i := 0; i < m; i++ {
				role, err := r.Tstr()
				if err != nil {
					return nil, schema("roles[%d]: %v", i, err)
				}
				c.Roles = append(c.Roles, role)
			}
			r.Pop()
		case 4: // level
			if c.Level, err = r.Uint(); err != nil {
				return nil, schema("level: %v", err)
			}
		case 5: // issued_ts
			var u uint64
			if u, err = r.Uint(); err != nil {
				return nil, schema("issued_ts: %v", err)
			}
			c.IssuedTS = int64(u)
		case 6: // expires_ts
			var u uint64
			if u, err = r.Uint(); err != nil {
				return nil, schema("expires_ts: %v", err)
			}
			c.ExpiresTS = int64(u)
		case 7: // seq
			if c.Seq, err = r.Uint(); err != nil {
				return nil, schema("seq: %v", err)
			}
		}
	}
	if !r.Done() {
		return nil, schema("%d trailing bytes inside the cert map", len(payload)-r.Pos())
	}
	return c, nil
}

// DefaultCertLifetime is the ceremony default when capsuletool sign is not
// given --expires-ts: 90 days.
const DefaultCertLifetime = 90 * 24 * time.Hour
