// Package capsule implements release capsule format v1
// (docs/offline-maintenance.md §2.1, reused VERBATIM by the node plane per
// docs/node-network.md §9.1) plus the node-plane chunk transport that
// carries a capsule across the plane as bulk bundles (§9.1, frozen in
// §9.4), and the staging hand-off (§2.4.4's binding staging semantics as a
// library — the entry-point-agnostic core both the future #37 HTTP
// endpoint and the §9.4 reassembler call).
//
// FORMAT (offline-maintenance §2.1.1, byte-exact):
//
//	offset   size        field
//	0        8           magic   "OFGRIDUP"
//	8        2           format  big-endian uint16, MUST be 1
//	10       4           mlen    big-endian uint32, metadata length M ≤ 1024
//	14       M           metadata  UTF-8 canonical JSON, fixed member order
//	14+M     P           payload   the release binary, byte-exact
//	14+M+P   64          sig     Ed25519 detached signature over meta ‖ payload
//
// The signature is made with the RELEASE key — the SECOND pinned Ed25519
// key of an island, distinct from the §2.2 anchor key. Key separation is a
// pinned property: the anchor key signs role certificates (COSE_Sign1,
// kid = the anchor fingerprint); the release key signs capsules (a
// detached signature over raw bytes, pinned at /opt/dtn-node/release-key.pub
// per §2.2.3). Neither key verifies the other's artifacts, and a leak of
// one never widens into the other's authority — the §2.7 compromise
// analyses are per-key for exactly this reason.
//
// HONESTY NOTE (issue #33 P3.7): the #37 staging ENDPOINT (§2.4's HTTP
// surface) and the apply machinery (§2.5, the #22 boot/apply units) do not
// exist yet — #37 is an open issue whose only landed artifact is the
// design record. This package implements the §2.1 format and the §2.4.4
// staging SEMANTICS (verify → anti-rollback → atomic stage) as a library;
// the HTTP endpoint, the release ldflags stamp (§2.4.3) and the apply
// wiring land with #37 itself. Nothing here touches the #22 upgrade
// machinery — applying a staged capsule stays #22's documented path.
package capsule

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// Frozen format v1 constants (offline-maintenance §2.1.1).
const (
	// Magic is the exact 8-byte "OFGRIDUP" prologue.
	Magic = "OFGRIDUP"
	// FormatV1 is the only format version this package reads or writes.
	FormatV1 = 1
	// HeaderLen is magic(8) + format(2) + mlen(4).
	HeaderLen = 14
	// SigLen is the Ed25519 detached signature length.
	SigLen = 64
	// MaxMetadataLen is the M budget of §2.1.2 (enforced at parse; future
	// additive members share it).
	MaxMetadataLen = 1024
	// MinPayloadLen / MaxPayloadLen bound P. The §2.4.2 staging body cap
	// (48 MiB + 64 KiB) is the honest upper bound — the ESP32 firmware
	// image (≈ 1.5 MB) and the Pi binary (≈ 11 MB) both ride under it.
	MaxPayloadLen = 48<<20 + 64<<10
)

// Arch is the §9.1 arch enum (the additive extension of the §2.1.2
// metadata block): the build.sh target classes a capsule can carry.
// Consumers MUST ignore unknown arch values (§9.1) — Parse accepts any
// string; the STAGING gate compares the node's own arch (Stager.Stage).
var archEnum = map[string]bool{
	"armv6":   true, // Pi Zero/1 class (install.sh: armv6l)
	"armv7":   true, // Pi 3/4 32-bit class (armv7l)
	"arm64":   true, // Pi 64-bit class (aarch64)
	"esp32s3": true, // the #39 fleet baseline (16 MB reference)
	"esp32":   true, // the #39 minimum board (4 MB)
}

// ValidArch reports whether arch is in the §9.1 enum. The signer tool
// refuses to sign outside the enum; verifiers do not (unknown values are
// the format's own extension space).
func ValidArch(arch string) bool { return archEnum[arch] }

// Stable failure codes — the shared vocabulary of the Go and C rejection
// tables and of the vectors' expect_code fields (the bundle package's
// discipline). The §2.4.2 HTTP classes group them:
//
//	400 invalid_capsule      ← bad_magic, bad_format, bad_length,
//	                           bad_metadata, bad_version, created_at_skew
//	400 corrupted_capsule    ← sha_mismatch, length_mismatch
//	400 bad_capsule_signature← bad_signature
//	409 stale_capsule        ← stale
//	400 too_old_capsule      ← too_old
//
// plus the node-plane-only verdicts §9.4 adds: wrong_arch (the capsule is
// for another board), unpinned (no release key pinned — §2.4.1's "staging
// unavailable"), updates_off (the §9.4 admission policy).
const (
	CodeMagic       = "bad_magic"
	CodeFormat      = "bad_format"
	CodeLength      = "bad_length" // truncated, or the total size is incoherent
	CodeMetadata    = "bad_metadata"
	CodeVersion     = "bad_version"
	CodeCreatedAt   = "created_at_skew"
	CodeSHA         = "sha_mismatch"
	CodeLenMismatch = "length_mismatch"
	CodeSignature   = "bad_signature"
	CodeStale       = "stale"
	CodeTooOld      = "too_old"
	CodeWrongArch   = "wrong_arch"
	CodeUnpinned    = "unpinned"
	CodeUpdatesOff  = "updates_off"
)

// Error is every rejection this package produces; Code carries the stable
// code above (ErrorCode extracts it).
type Error struct {
	Code string
	msg  string
}

func (e *Error) Error() string { return e.msg }

func errf(code, format string, a ...any) error {
	return &Error{Code: code, msg: "capsule: " + fmt.Sprintf(format, a...)}
}

// ErrorCode maps an error to its stable code ("" when err is nil or not
// from this package).
func ErrorCode(err error) string {
	var ce *Error
	if errors.As(err, &ce) {
		return ce.Code
	}
	return ""
}

// Metadata is the §2.1.2 metadata block — exactly these members, in
// exactly this order on the wire (canonical JSON; never sorted).
type Metadata struct {
	V              int    // format version; MUST be 1
	Release        uint64 // the monotonic anti-rollback key (§2.6); MUST be ≥ 1
	Semver         string // display tag; the signer asserts agreement with Release
	VCS            string // git describe of the build
	Arch           string // the §9.1 enum (armv6|armv7|arm64|esp32s3|esp32)
	MinUpgradeFrom uint64 // the oldest release this capsule may upgrade
	SPAEmbedded    bool   // MUST be true (§2.1.2 member 7)
	PayloadSHA256  string // 64 lowercase hex over the payload bytes
	PayloadBytes   int    // P, length-coherent with the actual bytes
	CreatedAt      int64  // unix seconds; > 0, ≤ now + 300 at staging
}

// Capsule is a parsed capsule. Payload and metaBytes view the Parse input
// (copy what outlives it).
type Capsule struct {
	Meta      Metadata
	metaOff   int    // metadata starts (== HeaderLen)
	Payload   []byte // view: the P payload bytes
	metaBytes []byte // view: the verbatim M metadata bytes (the signature's input)
	sig       []byte // view: the 64-byte detached signature
}

// ReleaseFromSemver applies the frozen §2.1.2 formula
// (major*1_000_000 + minor*1_000 + patch). The formula is frozen for
// format version 1; a different scheme bumps v.
func ReleaseFromSemver(major, minor, patch int) uint64 {
	return uint64(major)*1_000_000 + uint64(minor)*1_000 + uint64(patch)
}

// Build assembles the §2.1.1 byte layout around metadata and payload and
// signs metaBytes ‖ payload with the release private key (seed form, as
// stored by capsuletool capsule keygen — 32 bytes). The metadata is
// serialized canonically here (fixed member order, minimal integers); the
// caller's metadata fields are validated exactly as a verifier will
// validate them, so Build can never mint a capsule Parse would refuse.
func Build(priv []byte, meta Metadata, payload []byte) ([]byte, error) {
	if len(priv) != ed25519.SeedSize {
		return nil, errf(CodeSignature, "release private key must be %d bytes (a seed), got %d", ed25519.SeedSize, len(priv))
	}
	if err := validateSignable(meta, payload); err != nil {
		return nil, err
	}
	metaBytes := canonicalMetadata(meta)
	blob := make([]byte, 0, HeaderLen+len(metaBytes)+len(payload)+SigLen)
	blob = append(blob, Magic...)
	blob = append(blob, byte(FormatV1>>8), byte(FormatV1))
	mlen := len(metaBytes)
	blob = append(blob, byte(mlen>>24), byte(mlen>>16), byte(mlen>>8), byte(mlen))
	blob = append(blob, metaBytes...)
	blob = append(blob, payload...)
	key := ed25519.NewKeyFromSeed(priv)
	sig := ed25519.Sign(key, blob[HeaderLen:])
	blob = append(blob, sig...)
	return blob, nil
}

// validateSignable enforces the §2.1.2 constraint column at signing time —
// the signer tool asserts semver/release agreement here too.
func validateSignable(meta Metadata, payload []byte) error {
	switch {
	case meta.V != FormatV1:
		return errf(CodeVersion, "metadata v must be %d, got %d", FormatV1, meta.V)
	case meta.Release < 1:
		return errf(CodeMetadata, "release must be ≥ 1")
	case meta.Semver == "":
		return errf(CodeMetadata, "semver must be non-empty")
	case meta.Arch == "" || !ValidArch(meta.Arch):
		return errf(CodeMetadata, "arch %q is outside the §9.1 enum (armv6|armv7|arm64|esp32s3|esp32)", meta.Arch)
	case !meta.SPAEmbedded:
		return errf(CodeMetadata, "spa_embedded must be true (a daemon without the portal strands every mule's client)")
	case len(meta.PayloadSHA256) != 64 || !isLowerHex(meta.PayloadSHA256):
		return errf(CodeMetadata, "payload_sha256 must be 64 lowercase hex chars")
	case meta.PayloadBytes != len(payload):
		return errf(CodeLenMismatch, "payload_bytes %d does not match the payload length %d", meta.PayloadBytes, len(payload))
	case meta.CreatedAt <= 0:
		return errf(CodeCreatedAt, "created_at must be > 0")
	case len(payload) == 0 || len(payload) > MaxPayloadLen:
		return errf(CodeLength, "payload length %d outside [1, %d]", len(payload), MaxPayloadLen)
	}
	sum := sha256.Sum256(payload)
	if hex.EncodeToString(sum[:]) != meta.PayloadSHA256 {
		return errf(CodeSHA, "payload_sha256 does not match the payload bytes")
	}
	return nil
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' && c < 'a' || c > 'f' {
			return false
		}
	}
	return len(s) > 0
}

// canonicalMetadata serializes the §2.1.2 block: UTF-8, no whitespace,
// minimal integers, FIXED member order (protocol §5 discipline — never
// sorted). String values are JSON-escaped minimally (", \, control
// chars); the v1 string members (semver, vcs, arch, hex digest) are
// §8.1-ASCII, so the escape path never fires for tool-signed capsules.
func canonicalMetadata(m Metadata) []byte {
	esc := func(s string) string {
		out := make([]byte, 0, len(s)+2)
		for i := 0; i < len(s); i++ {
			c := s[i]
			switch {
			case c == '"':
				out = append(out, '\\', '"')
			case c == '\\':
				out = append(out, '\\', '\\')
			case c < 0x20:
				out = append(out, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xf])
			default:
				out = append(out, c)
			}
		}
		return string(out)
	}
	return []byte(`{"v":` + itoa(m.V) +
		`,"release":` + utoa(m.Release) +
		`,"semver":"` + esc(m.Semver) +
		`","vcs":"` + esc(m.VCS) +
		`","arch":"` + esc(m.Arch) +
		`","min_upgrade_from":` + utoa(m.MinUpgradeFrom) +
		`,"spa_embedded":` + boolWord(m.SPAEmbedded) +
		`,"payload_sha256":"` + m.PayloadSHA256 +
		`","payload_bytes":` + itoa(m.PayloadBytes) +
		`,"created_at":` + utoa(uint64(m.CreatedAt)) + `}`)
}

const hexDigits = "0123456789abcdef"

func itoa(n int) string { return utoa(uint64(n)) }

func utoa(u uint64) string {
	if u == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for u > 0 {
		i--
		buf[i] = hexDigits[u%10]
		u /= 10
	}
	return string(buf[i:])
}

func boolWord(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// Parse reads the §2.1.1 layout and validates every NON-cryptographic
// rule: magic, format, the M budget, the canonical fixed-order metadata,
// and the length coherence of payload_bytes (§2.4.4 step 1). The SHA-256
// and signature checks are Verify's (steps 1-2 of §2.4.4 in the endpoint's
// order); Parse alone never trusts a capsule.
func Parse(blob []byte) (*Capsule, error) {
	if len(blob) < HeaderLen+SigLen || string(blob[:8]) != Magic {
		return nil, errf(CodeMagic, "not an off-grid release capsule (magic)")
	}
	format := int(blob[8])<<8 | int(blob[9])
	if format != FormatV1 {
		return nil, errf(CodeFormat, "format version %d is not %d", format, FormatV1)
	}
	mlen := int(blob[10])<<24 | int(blob[11])<<16 | int(blob[12])<<8 | int(blob[13])
	if mlen <= 0 || mlen > MaxMetadataLen {
		return nil, errf(CodeLength, "metadata length %d outside [1, %d]", mlen, MaxMetadataLen)
	}
	bodyLen := len(blob) - HeaderLen - mlen - SigLen
	if bodyLen < 0 {
		return nil, errf(CodeLength, "truncated capsule: %d bytes cannot hold %d metadata + %d signature", len(blob), mlen, SigLen)
	}
	metaBytes := blob[HeaderLen : HeaderLen+mlen]
	payload := blob[HeaderLen+mlen : HeaderLen+mlen+bodyLen]
	sig := blob[HeaderLen+mlen+bodyLen:]

	meta, err := parseMetadata(metaBytes)
	if err != nil {
		return nil, err
	}
	if meta.PayloadBytes != bodyLen {
		return nil, errf(CodeLenMismatch, "payload_bytes %d does not match the actual payload length %d (length-coherence, §2.4.4 step 1)", meta.PayloadBytes, bodyLen)
	}
	return &Capsule{
		Meta:      meta,
		metaOff:   HeaderLen,
		Payload:   payload,
		metaBytes: metaBytes,
		sig:       sig,
	}, nil
}

// Verify completes §2.4.4's steps 1-2 against a capsule from Parse:
// the payload SHA-256 (a corrupted payload dies here, before any
// cryptography) and the Ed25519 detached signature over the VERBATIM
// metadata ‖ payload bytes against the pinned release public key.
// Verification is byte-exact by construction: nothing is canonicalized or
// re-serialized before hashing (§2.1.3).
func (c *Capsule) Verify(pub []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return errf(CodeUnpinned, "release public key must be %d bytes, got %d", ed25519.PublicKeySize, len(pub))
	}
	sum := sha256.Sum256(c.Payload)
	if hex.EncodeToString(sum[:]) != c.Meta.PayloadSHA256 {
		return errf(CodeSHA, "payload SHA-256 mismatch (corrupted payload, §2.4.2)")
	}
	signed := make([]byte, 0, len(c.metaBytes)+len(c.Payload))
	signed = append(signed, c.metaBytes...)
	signed = append(signed, c.Payload...)
	if !ed25519.Verify(ed25519.PublicKey(pub), signed, c.sig) {
		return errf(CodeSignature, "Ed25519 signature verification failed against the pinned release key")
	}
	return nil
}

// ---------------------------------------------------------------------------
// The strict metadata scanner. v1 pins the 10 members in fixed order
// (§2.1.2); future additive members MUST be ignored by verifiers while
// remaining signature-covered — so the scanner requires the frozen
// sequence first and tolerates canonical extra members AFTER it.
// ---------------------------------------------------------------------------

// parseMetadata scans the canonical JSON object. Canonical means: no
// whitespace anywhere, members separated by single commas, minimal
// integer forms (no leading zeros, no signs, no exponents), strings with
// JSON escapes decoded. Anything else is bad_metadata — the signer tool
// always emits this exact shape, so a non-canonical block is a forged or
// foreign artifact, not a formatting nuance.
func parseMetadata(metaBytes []byte) (Metadata, error) {
	var m Metadata
	s := &scan{b: metaBytes}
	if !s.take('{') {
		return m, errf(CodeMetadata, "metadata must be a JSON object")
	}
	want := [...]string{"v", "release", "semver", "vcs", "arch", "min_upgrade_from", "spa_embedded", "payload_sha256", "payload_bytes", "created_at"}
	for i := 0; i < len(want); i++ {
		if i > 0 && !s.take(',') {
			return m, errf(CodeMetadata, "member %d: expected ',' at offset %d", i, s.pos)
		}
		key, err := s.string()
		if err != nil {
			return m, err
		}
		if key != want[i] {
			return m, errf(CodeMetadata, "member %d must be %q (fixed §2.1.2 order), got %q", i, want[i], key)
		}
		if !s.take(':') {
			return m, errf(CodeMetadata, "member %q: expected ':' at offset %d", key, s.pos)
		}
		if err := s.member(i, &m); err != nil {
			return m, err
		}
	}
	// Additive space (§2.1.2): canonical unknown members after the frozen
	// ten are tolerated and ignored (the signature still covers them).
	for s.peek() == ',' {
		s.pos++
		if _, err := s.string(); err != nil {
			return m, err
		}
		if !s.take(':') {
			return m, errf(CodeMetadata, "extra member: expected ':' at offset %d", s.pos)
		}
		if err := s.skipValue(); err != nil {
			return m, err
		}
	}
	if !s.take('}') || s.pos != len(metaBytes) {
		return m, errf(CodeMetadata, "metadata must end at the closing brace (offset %d of %d)", s.pos, len(metaBytes))
	}
	// The §2.1.2 constraint column, verbatim.
	switch {
	case m.V != FormatV1:
		return m, errf(CodeVersion, "metadata v must be %d, got %d", FormatV1, m.V)
	case m.Release < 1:
		return m, errf(CodeMetadata, "release must be ≥ 1")
	case !isLowerHex(m.PayloadSHA256) || len(m.PayloadSHA256) != 64:
		return m, errf(CodeMetadata, "payload_sha256 must be 64 lowercase hex chars")
	case !m.SPAEmbedded:
		return m, errf(CodeMetadata, "spa_embedded must be true (§2.1.2 member 7)")
	case m.CreatedAt <= 0:
		return m, errf(CodeCreatedAt, "created_at must be > 0")
	}
	return m, nil
}

// scan is a minimal canonical-JSON cursor (no allocation, byte offsets
// only). It exists because encoding/json cannot pin the fixed member
// order, reject inter-member whitespace and keep the raw bytes verbatim
// at once — and §2.1.2 needs all three.
type scan struct {
	b   []byte
	pos int
}

func (s *scan) peek() byte {
	if s.pos < len(s.b) {
		return s.b[s.pos]
	}
	return 0
}

func (s *scan) take(c byte) bool {
	if s.peek() == c {
		s.pos++
		return true
	}
	return false
}

// string reads one JSON string, decoding escapes; canonical input from
// the signer never carries escapes (the members are §8.1-ASCII), but a
// future additive member may, so the decoder is complete.
func (s *scan) string() (string, error) {
	if !s.take('"') {
		return "", errf(CodeMetadata, "expected a string at offset %d", s.pos)
	}
	out := make([]byte, 0, 16)
	for {
		if s.pos >= len(s.b) {
			return "", errf(CodeMetadata, "unterminated string at offset %d", s.pos)
		}
		c := s.b[s.pos]
		s.pos++
		switch {
		case c == '"':
			return string(out), nil
		case c == '\\':
			if s.pos >= len(s.b) {
				return "", errf(CodeMetadata, "dangling escape at offset %d", s.pos)
			}
			e := s.b[s.pos]
			s.pos++
			switch e {
			case '"', '\\', '/':
				out = append(out, e)
			case 'b':
				out = append(out, '\b')
			case 'f':
				out = append(out, '\f')
			case 'n':
				out = append(out, '\n')
			case 'r':
				out = append(out, '\r')
			case 't':
				out = append(out, '\t')
			case 'u':
				if s.pos+4 > len(s.b) {
					return "", errf(CodeMetadata, "truncated \\u escape at offset %d", s.pos)
				}
				r, ok := parseHex4(s.b[s.pos : s.pos+4])
				if !ok {
					return "", errf(CodeMetadata, "bad \\u escape at offset %d", s.pos-2)
				}
				s.pos += 4
				out = appendRune(out, r)
			default:
				return "", errf(CodeMetadata, "unknown escape \\%c at offset %d", e, s.pos-2)
			}
		case c < 0x20:
			return "", errf(CodeMetadata, "raw control byte 0x%02x inside a string at offset %d", c, s.pos-1)
		default:
			out = append(out, c)
		}
	}
}

func parseHex4(b []byte) (rune, bool) {
	var v rune
	for _, c := range b {
		var d rune
		switch {
		case c >= '0' && c <= '9':
			d = rune(c - '0')
		case c >= 'a' && c <= 'f':
			d = rune(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = rune(c-'A') + 10
		default:
			return 0, false
		}
		v = v<<4 | d
	}
	return v, true
}

func appendRune(out []byte, r rune) []byte {
	if r < 0x80 {
		return append(out, byte(r))
	}
	if r < 0x800 {
		return append(out, byte(0xC0|r>>6), byte(0x80|r&0x3F))
	}
	return append(out, byte(0xE0|r>>12), byte(0x80|(r>>6)&0x3F), byte(0x80|r&0x3F))
}

// uint reads one minimal non-negative integer (canonical: no leading
// zeros, no sign, no fraction/exponent).
func (s *scan) uint() (uint64, error) {
	start := s.pos
	var v uint64
	for s.pos < len(s.b) && s.b[s.pos] >= '0' && s.b[s.pos] <= '9' {
		v = v*10 + uint64(s.b[s.pos]-'0')
		s.pos++
		if v > 1<<62 {
			return 0, errf(CodeMetadata, "integer overflow at offset %d", start)
		}
	}
	if s.pos == start {
		return 0, errf(CodeMetadata, "expected an integer at offset %d", start)
	}
	if s.b[start] == '0' && s.pos-start > 1 {
		return 0, errf(CodeMetadata, "leading-zero integer at offset %d (canonical JSON)", start)
	}
	return v, nil
}

// member reads the value of the i-th frozen member into m.
func (s *scan) member(i int, m *Metadata) error {
	switch i {
	case 0: // v
		v, err := s.uint()
		if err != nil {
			return err
		}
		m.V = int(v)
	case 1: // release
		v, err := s.uint()
		if err != nil {
			return err
		}
		m.Release = v
	case 2: // semver
		v, err := s.string()
		if err != nil {
			return err
		}
		m.Semver = v
	case 3: // vcs
		v, err := s.string()
		if err != nil {
			return err
		}
		m.VCS = v
	case 4: // arch
		v, err := s.string()
		if err != nil {
			return err
		}
		m.Arch = v
	case 5: // min_upgrade_from
		v, err := s.uint()
		if err != nil {
			return err
		}
		m.MinUpgradeFrom = v
	case 6: // spa_embedded
		if s.take4("true") {
			m.SPAEmbedded = true
			return nil
		}
		if s.take4("false") {
			return nil
		}
		return errf(CodeMetadata, "spa_embedded must be true or false at offset %d", s.pos)
	case 7: // payload_sha256
		v, err := s.string()
		if err != nil {
			return err
		}
		m.PayloadSHA256 = v
	case 8: // payload_bytes
		v, err := s.uint()
		if err != nil {
			return err
		}
		m.PayloadBytes = int(v)
	default: // 9: created_at
		v, err := s.uint()
		if err != nil {
			return err
		}
		m.CreatedAt = int64(v)
	}
	return nil
}

// skipValue walks one arbitrary canonical JSON value (object, array,
// string, number, literal) without interpreting it — the additive-member
// tolerance of §2.1.2.
func (s *scan) skipValue() error {
	switch c := s.peek(); {
	case c == '"':
		_, err := s.string()
		return err
	case c == '{' || c == '[':
		open, close := c, byte('}')
		if c == '[' {
			close = ']'
		}
		depth := 0
		for {
			if s.pos >= len(s.b) {
				return errf(CodeMetadata, "unterminated %c at offset %d", open, s.pos)
			}
			switch cur := s.b[s.pos]; {
			case cur == '"': // a nested string may hold brackets; walk it whole
				if _, err := s.string(); err != nil {
					return err
				}
				continue
			case cur == open:
				depth++
			case cur == close:
				depth--
			}
			s.pos++
			if depth == 0 {
				return nil
			}
		}
	case c == 't':
		if !s.take4("true") {
			return errf(CodeMetadata, "bad literal at offset %d", s.pos)
		}
		return nil
	case c == 'f':
		if !s.take4("false") {
			return errf(CodeMetadata, "bad literal at offset %d", s.pos)
		}
		return nil
	case c == 'n':
		if !s.take4("null") {
			return errf(CodeMetadata, "bad literal at offset %d", s.pos)
		}
		return nil
	case c == '-' || c >= '0' && c <= '9':
		start := s.pos
		if s.take('-') {
			start = s.pos // a leading '-' alone is not canonical, but skip-lenient
		}
		for s.pos < len(s.b) && (s.b[s.pos] >= '0' && s.b[s.pos] <= '9' ||
			s.b[s.pos] == '.' || s.b[s.pos] == 'e' || s.b[s.pos] == 'E' ||
			s.b[s.pos] == '+' || s.b[s.pos] == '-') {
			s.pos++
		}
		if s.pos == start {
			return errf(CodeMetadata, "bad number at offset %d", start)
		}
		return nil
	default:
		return errf(CodeMetadata, "unexpected byte 0x%02x at offset %d (canonical JSON value expected)", c, s.pos)
	}
}

func (s *scan) take4(lit string) bool {
	for i := 0; i < len(lit); i++ {
		if !s.take(lit[i]) {
			return false
		}
	}
	return true
}
