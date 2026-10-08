// handshake.go — the §6.1 EDHOC-shaped three-message link handshake
// (RFC 9528 as normative reference, EDHOC-shaped minimal exchange):
//
//	msg1 = [1(suite), 1(curve), g_x(32), c_i]                      — 38 B
//	msg2 = [g_y(32), c_r, ct2]                                     — 134 B
//	       ct2 = AEAD(K2, th1(8) ‖ id_cred_r(8) ‖ sig_r(64))       — 96 B
//	msg3 = [ct3]                                                   — 91 B
//	       ct3 = AEAD(K3, id_cred_i(8) ‖ sig_i(64))                — 88 B
//
// with th1 = SHA-256(msg1)[0:8], id_cred = SHA-256(node_key)[0:8]
// (nodeid.Fingerprint). The §6.1 sentence "signatures over the transcript
// (th1 ‖ both EIDs)" is implemented as the union across the two
// signatures, because the literal reading is internally impossible in a
// three-message exchange — the responder must sign BEFORE the initiator's
// EID reaches it in msg3:
//
//	sig_r = Ed25519 over th1 ‖ EID_r
//	sig_i = Ed25519 over th1 ‖ EID_r ‖ EID_i   (the full transcript)
//
// (doc §6.1 receives this pin in the 1.3.0 changelog; the wire layout is
// untouched and stays 38/134/91 B).
//
//	K2 = HKDF(dh, salt = SHA-256(msg1),       info = "offgrid-link-v1 k2")
//	K3 = HKDF(dh, salt = SHA-256(msg1 ‖ g_y), info = "offgrid-link-v1 k3")
//
// followed by the §6.2 session-key schedule:
//
//	prk    = HKDF-Extract(SHA-256(msg1 ‖ msg2 ‖ msg3), dh)
//	master = HKDF-Expand(prk, "offgrid-link-v1", 32)
//	k_i2r / s_i2r / k_r2i / s_r2i = HKDF-Expand(master, "offgrid-link-v1 …", …)
//
// c_i = 0 and c_r = 1 are pinned constants (v1 links are pairwise, one
// session per radio peer; the constants keep the §6.1 sizes byte-exact at
// 38/134/91 — the same numbers bundle/spike.go measures). Handshake AEAD
// nonces follow the §6.2 length profile: hsSalt ‖ BE8(message number),
// hsSalt = SHA-256("offgrid-link-v1-handshake")[0:5]. Each ct ciphertext
// is AAD-bound to the exact message bytes that precede its CBOR head.
//
// Fail-closed: every verification failure returns before any Session
// exists and drops the partial key material; a node whose peer cannot be
// authenticated has no session and carries nothing but beacons (§6.1).
package link

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"offgrid/dtn-node/internal/bundle"
	"offgrid/dtn-node/internal/nodeid"
)

// Frozen handshake parameters (§6.1).
const (
	SuiteV1     = 1 // method/suite identifier
	CurveX25519 = 1 // curve identifier
	CIValue     = 0 // pinned c_i
	CRValue     = 1 // pinned c_r
	// TH1Len is the transcript-hash prefix carried in ct2.
	TH1Len = 8
	// SigLen is the Ed25519 signature length.
	SigLen = 64
	// InfoPrefix is the §6.2 HKDF info prefix.
	InfoPrefix = "offgrid-link-v1"
)

// hsSalt is the handshake AEAD salt: SHA-256("offgrid-link-v1-handshake")[0:5].
var hsSalt = func() [NonceSaltLen]byte {
	sum := sha256.Sum256([]byte(InfoPrefix + "-handshake"))
	var s [NonceSaltLen]byte
	copy(s[:], sum[:NonceSaltLen])
	return s
}()

// hsNonce builds the handshake AEAD nonce for message number n (2 = ct2,
// 3 = ct3).
func hsNonce(n byte) [NonceLen]byte {
	return Nonce(hsSalt, uint64(n))
}

// msg3AAD is the AAD of ct3: msg3's single array head (the bytes that
// precede the ct3 CBOR head).
var msg3AAD = func() []byte { return bundle.EncodeCbor(func(e *bundle.Cbor) { e.Array(1) }) }()

// Handshake errors wrap ErrHandshake; nodeid.ErrPeerKeyChanged passes
// through when the ExpectedPeer gate fires (the loud TOFU sentinel, §6.1).
var ErrUnknownPeer = fmt.Errorf("%w: peer fingerprint has no role certificate or pin", ErrHandshake)

// PeerKeys resolves an id_cred fingerprint to the peer's Ed25519 node key:
// the role-cert cache first (§6.1: the certificate is the authority), then
// the TOFU pin store (nodeid.PinStore; peers are keyed by EID, which is a
// pure function of the fingerprint). A fingerprint with neither fails the
// handshake: an Ed25519 signature cannot be verified without the full key,
// so first-contact trust is established when provisioning or a role
// certificate delivers the peer key into the pin store — never from the
// handshake wire itself, which carries only the 8-byte id_cred.
type PeerKeys struct {
	certs map[[nodeid.FingerprintLen]byte]ed25519.PublicKey
	pins  *nodeid.PinStore
}

// NewPeerKeys builds the resolver over a pin store (may be nil).
func NewPeerKeys(pins *nodeid.PinStore) *PeerKeys {
	return &PeerKeys{certs: make(map[[nodeid.FingerprintLen]byte]ed25519.PublicKey), pins: pins}
}

// AddCert installs a verified role certificate's node key (the caller has
// verified the COSE_Sign1 and applied the §2.5 merge rules before this).
func (k *PeerKeys) AddCert(pub ed25519.PublicKey) error {
	if len(pub) != nodeid.KeyLen {
		return fmt.Errorf("link: node key must be %d bytes, got %d", nodeid.KeyLen, len(pub))
	}
	k.certs[nodeid.Fingerprint(pub)] = pub
	return nil
}

// CertCount is the number of cached certified keys.
func (k *PeerKeys) CertCount() int { return len(k.certs) }

// Lookup resolves fp → node key (cert cache first, then TOFU pins).
func (k *PeerKeys) Lookup(fp [nodeid.FingerprintLen]byte) (ed25519.PublicKey, error) {
	if pub, ok := k.certs[fp]; ok {
		return pub, nil
	}
	if k.pins != nil {
		if pub, ok := k.pins.Peer(nodeid.EID(fp)); ok {
			return ed25519.PublicKey(pub), nil
		}
	}
	return nil, fmt.Errorf("%w: %s", ErrUnknownPeer, nodeid.EID(fp))
}

// Config configures both handshake roles.
type Config struct {
	// Local is the local node's Ed25519 key pair.
	Local nodeid.KeyPair
	// Keys resolves the peer's fingerprint to its node key (§6.1). Required.
	Keys *PeerKeys
	// ExpectedPeer, when non-empty, is the EID the authenticated peer
	// MUST present. A valid signature under any other key fails the
	// session loudly with nodeid.ErrPeerKeyChanged (§6.1: a key change
	// without a higher-seq certificate never opens a session).
	ExpectedPeer string
	// EphemeralScalar returns the 32-byte X25519 private scalar for THIS
	// handshake's ephemeral. nil = crypto/rand. Production code leaves it
	// nil; only tests/vectors inject fixed scalars for determinism.
	EphemeralScalar func() ([]byte, error)
}

// ephemeral builds the X25519 ephemeral from the config (crypto/rand when
// no scalar source is configured).
func (c *Config) ephemeral() (*ecdh.PrivateKey, error) {
	if c.EphemeralScalar != nil {
		s, err := c.EphemeralScalar()
		if err != nil {
			return nil, err
		}
		return ecdh.X25519().NewPrivateKey(s)
	}
	scalar := make([]byte, 32)
	if _, err := rand.Read(scalar); err != nil {
		return nil, err
	}
	return ecdh.X25519().NewPrivateKey(scalar)
}

// x25519Shared runs the ECDH against the peer's public key.
func x25519Shared(priv *ecdh.PrivateKey, peerPub []byte) ([]byte, error) {
	remote, err := ecdh.X25519().NewPublicKey(peerPub)
	if err != nil {
		return nil, fmt.Errorf("%w: bad X25519 peer public: %v", ErrHandshake, err)
	}
	shared, err := priv.ECDH(remote)
	if err != nil {
		return nil, fmt.Errorf("%w: X25519 failed: %v", ErrHandshake, err)
	}
	return shared, nil
}

// th1Of is the transcript prefix: SHA-256(msg1)[0:8] (§6.1).
func th1Of(msg1 []byte) [TH1Len]byte {
	sum := sha256.Sum256(msg1)
	var th [TH1Len]byte
	copy(th[:], sum[:TH1Len])
	return th
}

// transcriptHash is SHA-256 over the concatenated parts (key-schedule salt).
func transcriptHash(parts ...[]byte) []byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

// sigMessageR is the responder's signature transcript: th1 ‖ EID_r (all
// the transcript the responder has seen when it signs — msg2 precedes
// msg3, so the initiator's EID is not yet known to it).
func sigMessageR(th1 [TH1Len]byte, eidResponder string) []byte {
	b := make([]byte, 0, TH1Len+len(eidResponder))
	b = append(b, th1[:]...)
	b = append(b, eidResponder...)
	return b
}

// sigMessageI is the initiator's signature transcript — the FULL §6.1
// transcript: th1 ‖ EID_r ‖ EID_i.
func sigMessageI(th1 [TH1Len]byte, eidResponder, eidInitiator string) []byte {
	b := make([]byte, 0, TH1Len+len(eidResponder)+len(eidInitiator))
	b = append(b, th1[:]...)
	b = append(b, eidResponder...)
	b = append(b, eidInitiator...)
	return b
}

// keyFromFp resolves and binding-checks a peer key: the resolved key's own
// fingerprint must equal the presented id_cred (a corrupt store must never
// authenticate).
func keyFromFp(keys *PeerKeys, fp [nodeid.FingerprintLen]byte) (ed25519.PublicKey, string, error) {
	pub, err := keys.Lookup(fp)
	if err != nil {
		return nil, "", err
	}
	if nodeid.Fingerprint(pub) != fp {
		return nil, "", fmt.Errorf("%w: key store entry for %s does not match its own fingerprint", ErrHandshake, nodeid.EID(fp))
	}
	return pub, nodeid.EID(fp), nil
}

// checkExpectedPeer is the loud TOFU gate: the verified peer EID must be
// the configured one, else nodeid.ErrPeerKeyChanged (§6.1).
func checkExpectedPeer(expected, verified string) error {
	if expected != "" && verified != expected {
		return fmt.Errorf("%w: authenticated peer is %s, expected %s (key changed with no higher-seq certificate)", nodeid.ErrPeerKeyChanged, verified, expected)
	}
	return nil
}

// sessionKeys derives the §6.2 per-direction traffic keys from the full
// transcript and the shared secret.
func sessionKeys(dh []byte, transcript []byte) (kI2R, kR2I [KeyLen]byte, sI2R, sR2I [NonceSaltLen]byte, err error) {
	prk := HkdfExtract(transcriptHash(transcript), dh)
	masterRaw, err := HkdfExpand(prk, []byte(InfoPrefix), 32)
	if err != nil {
		return
	}
	var master [HashLen]byte
	copy(master[:], masterRaw)
	derive := func(label string, n int) ([]byte, error) {
		return HkdfExpand(master, []byte(InfoPrefix+" "+label), n)
	}
	k2r, err := derive("i2r key", KeyLen)
	if err != nil {
		return
	}
	s2r, err := derive("i2r salt", NonceSaltLen)
	if err != nil {
		return
	}
	kri, err := derive("r2i key", KeyLen)
	if err != nil {
		return
	}
	sri, err := derive("r2i salt", NonceSaltLen)
	if err != nil {
		return
	}
	copy(kI2R[:], k2r)
	copy(sI2R[:], s2r)
	copy(kR2I[:], kri)
	copy(sR2I[:], sri)
	return
}

// key16 re-wraps an HKDF output as an AES-128 key.
func key16(b []byte) [KeyLen]byte {
	var k [KeyLen]byte
	copy(k[:], b)
	return k
}

// ---------------------------------------------------------------------------
// Initiator
// ---------------------------------------------------------------------------

// Initiator is the msg1-sending side's state machine.
type Initiator struct {
	cfg    Config
	msg1   []byte
	th1    [TH1Len]byte
	eph    *ecdh.PrivateKey
	dh     []byte
	gy     []byte
	msg2   []byte
	eidR   string
	msg3   []byte
	sess   *Session
	failed bool
}

// NewInitiator starts the exchange and returns msg1 (38 B, §6.1).
func NewInitiator(cfg Config) (*Initiator, []byte, error) {
	if cfg.Keys == nil {
		return nil, nil, fmt.Errorf("%w: no peer key resolver configured", ErrHandshake)
	}
	eph, err := cfg.ephemeral()
	if err != nil {
		return nil, nil, fmt.Errorf("%w: ephemeral: %v", ErrHandshake, err)
	}
	i := &Initiator{cfg: cfg, eph: eph}
	i.msg1 = bundle.EncodeCbor(func(e *bundle.Cbor) {
		e.Array(4)
		e.Uint(SuiteV1)
		e.Uint(CurveX25519)
		e.Bstr(eph.PublicKey().Bytes())
		e.Uint(CIValue)
	})
	i.th1 = th1Of(i.msg1)
	return i, i.msg1, nil
}

// Read2 consumes the responder's msg2 (134 B): decrypts ct2 under K2,
// checks the transcript prefix, resolves and verifies the responder's
// signature (§6.1). On error the handshake is dead: Session() stays nil
// and no key material is retained.
func (i *Initiator) Read2(msg2 []byte) error {
	if i.failed || i.msg1 == nil {
		return fmt.Errorf("%w: initiator is not in msg2 state", ErrHandshake)
	}
	gy, cr, ct2, ct2Head, err := parseMsg2(msg2)
	if err != nil {
		i.fail()
		return err
	}
	if cr != CRValue {
		i.fail()
		return fmt.Errorf("%w: msg2 c_r = %d, want %d", ErrHandshake, cr, CRValue)
	}
	dh, err := x25519Shared(i.eph, gy)
	if err != nil {
		i.fail()
		return err
	}
	k2, err := HkdfKey(dh, transcriptHash(i.msg1), []byte(InfoPrefix+" k2"), KeyLen)
	if err != nil {
		i.fail()
		return err
	}
	// AAD = the msg2 bytes before the ct2 CBOR head.
	pt, err := Open(key16(k2), hsNonce(2), msg2[:ct2Head], ct2)
	if err != nil {
		i.fail()
		return fmt.Errorf("%w: ct2: %v", ErrHandshake, err)
	}
	if len(pt) != TH1Len+nodeid.FingerprintLen+SigLen {
		i.fail()
		return fmt.Errorf("%w: ct2 plaintext is %d bytes, want %d", ErrHandshake, len(pt), TH1Len+nodeid.FingerprintLen+SigLen)
	}
	var th [TH1Len]byte
	copy(th[:], pt[:TH1Len])
	if th != i.th1 {
		i.fail()
		return fmt.Errorf("%w: ct2 transcript prefix mismatch", ErrHandshake)
	}
	var fp [nodeid.FingerprintLen]byte
	copy(fp[:], pt[TH1Len:TH1Len+nodeid.FingerprintLen])
	sig := append([]byte(nil), pt[TH1Len+nodeid.FingerprintLen:]...)
	keyR, eidR, err := keyFromFp(i.cfg.Keys, fp)
	if err != nil {
		i.fail()
		return err
	}
	if err := checkExpectedPeer(i.cfg.ExpectedPeer, eidR); err != nil {
		i.fail()
		return err
	}
	if !ed25519.Verify(keyR, sigMessageR(i.th1, eidR), sig) {
		i.fail()
		return fmt.Errorf("%w: responder signature invalid", ErrHandshake)
	}
	i.gy = append([]byte(nil), gy...)
	i.dh = dh
	i.msg2 = append([]byte(nil), msg2...)
	i.eidR = eidR
	return nil
}

// Write3 produces msg3 (91 B) and derives the §6.2 session.
func (i *Initiator) Write3() ([]byte, error) {
	if i.failed || i.dh == nil {
		return nil, fmt.Errorf("%w: initiator is not in msg3 state", ErrHandshake)
	}
	k3, err := HkdfKey(i.dh, transcriptHash(i.msg1, i.gy), []byte(InfoPrefix+" k3"), KeyLen)
	if err != nil {
		i.fail()
		return nil, err
	}
	eidI := nodeid.EID(nodeid.Fingerprint(i.cfg.Local.Public))
	sig := ed25519.Sign(i.cfg.Local.Private, sigMessageI(i.th1, i.eidR, eidI))
	fpI := nodeid.Fingerprint(i.cfg.Local.Public)
	pt := make([]byte, 0, nodeid.FingerprintLen+SigLen)
	pt = append(pt, fpI[:]...)
	pt = append(pt, sig...)
	ct3, err := Seal(key16(k3), hsNonce(3), msg3AAD, pt)
	if err != nil {
		i.fail()
		return nil, err
	}
	i.msg3 = bundle.EncodeCbor(func(e *bundle.Cbor) {
		e.Array(1)
		e.Bstr(ct3)
	})
	kI2R, kR2I, sI2R, sR2I, err := sessionKeys(i.dh, append(append(append([]byte{}, i.msg1...), i.msg2...), i.msg3...))
	if err != nil {
		i.fail()
		return nil, err
	}
	i.sess = NewSession(DirI2R, kI2R, kR2I, sI2R, sR2I, nil, nil)
	i.eph = nil // the ephemeral is spent
	i.dh = nil
	return i.msg3, nil
}

// Session returns the established §6.2 session (nil until Write3 succeeded
// — and permanently nil after any failure).
func (i *Initiator) Session() *Session { return i.sess }

// PeerEID returns the authenticated responder EID (valid after Read2).
func (i *Initiator) PeerEID() string { return i.eidR }

func (i *Initiator) fail() {
	i.failed = true
	i.sess = nil
	i.eph = nil
	i.dh = nil
}

// ---------------------------------------------------------------------------
// Responder
// ---------------------------------------------------------------------------

// Responder is the msg2-sending side's state machine.
type Responder struct {
	cfg    Config
	msg1   []byte
	th1    [TH1Len]byte
	gx     []byte // the initiator's ephemeral public (from msg1)
	eph    *ecdh.PrivateKey
	gy     []byte
	dh     []byte
	msg2   []byte
	eidI   string
	msg3   []byte
	sess   *Session
	failed bool
}

// NewResponder creates the responder half.
func NewResponder(cfg Config) (*Responder, error) {
	if cfg.Keys == nil {
		return nil, fmt.Errorf("%w: no peer key resolver configured", ErrHandshake)
	}
	return &Responder{cfg: cfg}, nil
}

// Read1 consumes the initiator's msg1 (38 B).
func (r *Responder) Read1(msg1 []byte) error {
	if r.failed || r.msg1 != nil {
		return fmt.Errorf("%w: responder is not in msg1 state", ErrHandshake)
	}
	suite, curve, gx, ci, err := parseMsg1(msg1)
	if err != nil {
		r.fail()
		return err
	}
	if suite != SuiteV1 || curve != CurveX25519 || ci != CIValue {
		r.fail()
		return fmt.Errorf("%w: msg1 suite/curve/c_i = %d/%d/%d, want %d/%d/%d", ErrHandshake, suite, curve, ci, SuiteV1, CurveX25519, CIValue)
	}
	r.msg1 = append([]byte(nil), msg1...)
	r.gx = gx
	r.th1 = th1Of(r.msg1)
	return nil
}

// Write2 produces msg2 (134 B): fresh ephemeral y, ct2 carrying the
// responder's transcript signature (responder-first order, above).
func (r *Responder) Write2() ([]byte, error) {
	if r.failed || r.msg1 == nil {
		return nil, fmt.Errorf("%w: responder is not in msg2 state", ErrHandshake)
	}
	eph, err := r.cfg.ephemeral()
	if err != nil {
		r.fail()
		return nil, fmt.Errorf("%w: ephemeral: %v", ErrHandshake, err)
	}
	gy := eph.PublicKey().Bytes()
	dh, err := x25519Shared(eph, r.gx)
	if err != nil {
		r.fail()
		return nil, err
	}
	k2, err := HkdfKey(dh, transcriptHash(r.msg1), []byte(InfoPrefix+" k2"), KeyLen)
	if err != nil {
		r.fail()
		return nil, err
	}
	eidR := nodeid.EID(nodeid.Fingerprint(r.cfg.Local.Public))
	sig := ed25519.Sign(r.cfg.Local.Private, sigMessageR(r.th1, eidR))
	fpR := nodeid.Fingerprint(r.cfg.Local.Public)
	pt := make([]byte, 0, TH1Len+nodeid.FingerprintLen+SigLen)
	pt = append(pt, r.th1[:]...)
	pt = append(pt, fpR[:]...)
	pt = append(pt, sig...)
	// AAD = the msg2 bytes before the ct2 CBOR head: the fixed
	// [array(3), bstr(g_y), c_r] prefix.
	prefix := bundle.EncodeCbor(func(e *bundle.Cbor) {
		e.Array(3)
		e.Bstr(gy)
		e.Uint(CRValue)
	})
	ct2, err := Seal(key16(k2), hsNonce(2), prefix, pt)
	if err != nil {
		r.fail()
		return nil, err
	}
	msg2 := bundle.EncodeCbor(func(e *bundle.Cbor) {
		e.Array(3)
		e.Bstr(gy)
		e.Uint(CRValue)
		e.Bstr(ct2)
	})
	r.eph = eph
	r.gy = append([]byte(nil), gy...)
	r.dh = dh
	r.msg2 = msg2
	return msg2, nil
}

// Read3 consumes msg3 (91 B): decrypts ct3 under K3, resolves and verifies
// the initiator's signature, and derives the §6.2 session.
func (r *Responder) Read3(msg3 []byte) error {
	if r.failed || r.dh == nil {
		return fmt.Errorf("%w: responder is not in msg3 state", ErrHandshake)
	}
	ct3, err := parseMsg3(msg3)
	if err != nil {
		r.fail()
		return err
	}
	k3, err := HkdfKey(r.dh, transcriptHash(r.msg1, r.gy), []byte(InfoPrefix+" k3"), KeyLen)
	if err != nil {
		r.fail()
		return err
	}
	pt, err := Open(key16(k3), hsNonce(3), msg3AAD, ct3)
	if err != nil {
		r.fail()
		return fmt.Errorf("%w: ct3: %v", ErrHandshake, err)
	}
	if len(pt) != nodeid.FingerprintLen+SigLen {
		r.fail()
		return fmt.Errorf("%w: ct3 plaintext is %d bytes, want %d", ErrHandshake, len(pt), nodeid.FingerprintLen+SigLen)
	}
	var fp [nodeid.FingerprintLen]byte
	copy(fp[:], pt[:nodeid.FingerprintLen])
	sig := append([]byte(nil), pt[nodeid.FingerprintLen:]...)
	keyI, eidI, err := keyFromFp(r.cfg.Keys, fp)
	if err != nil {
		r.fail()
		return err
	}
	eidR := nodeid.EID(nodeid.Fingerprint(r.cfg.Local.Public))
	if err := checkExpectedPeer(r.cfg.ExpectedPeer, eidI); err != nil {
		r.fail()
		return err
	}
	if !ed25519.Verify(keyI, sigMessageI(r.th1, eidR, eidI), sig) {
		r.fail()
		return fmt.Errorf("%w: initiator signature invalid", ErrHandshake)
	}
	r.msg3 = append([]byte(nil), msg3...)
	r.eidI = eidI
	kI2R, kR2I, sI2R, sR2I, err := sessionKeys(r.dh, append(append(append([]byte{}, r.msg1...), r.msg2...), r.msg3...))
	if err != nil {
		r.fail()
		return err
	}
	r.sess = NewSession(DirR2I, kR2I, kI2R, sR2I, sI2R, nil, nil)
	r.eph = nil // the ephemeral is spent
	r.dh = nil
	return nil
}

// Session returns the established session (nil until Read3 succeeded and
// permanently nil after any failure).
func (r *Responder) Session() *Session { return r.sess }

// PeerEID returns the authenticated initiator EID (valid after Read3).
func (r *Responder) PeerEID() string { return r.eidI }

func (r *Responder) fail() {
	r.failed = true
	r.sess = nil
	r.eph = nil
	r.dh = nil
}

// ---------------------------------------------------------------------------
// Message parsing (strict, fail-closed)
// ---------------------------------------------------------------------------

func parseMsg1(msg1 []byte) (suite, curve uint64, gx []byte, ci uint64, err error) {
	r := bundle.NewCborReader(msg1)
	var n int
	if n, err = r.Array(); err != nil {
		return
	}
	if n != 4 {
		return 0, 0, nil, 0, fmt.Errorf("%w: msg1 array of %d, want 4", ErrHandshake, n)
	}
	if suite, err = r.Uint(); err != nil {
		return
	}
	if curve, err = r.Uint(); err != nil {
		return
	}
	if gx, err = r.Bstr(); err != nil {
		return
	}
	if len(gx) != 32 {
		return 0, 0, nil, 0, fmt.Errorf("%w: msg1 g_x is %d bytes, want 32", ErrHandshake, len(gx))
	}
	gx = append([]byte(nil), gx...)
	if ci, err = r.Uint(); err != nil {
		return
	}
	if !r.Done() {
		return 0, 0, nil, 0, fmt.Errorf("%w: msg1 has trailing bytes", ErrHandshake)
	}
	return
}

func parseMsg2(msg2 []byte) (gy []byte, cr uint64, ct2 []byte, ct2Head int, err error) {
	r := bundle.NewCborReader(msg2)
	var n int
	if n, err = r.Array(); err != nil {
		return
	}
	if n != 3 {
		return nil, 0, nil, 0, fmt.Errorf("%w: msg2 array of %d, want 3", ErrHandshake, n)
	}
	if gy, err = r.Bstr(); err != nil {
		return
	}
	if len(gy) != 32 {
		return nil, 0, nil, 0, fmt.Errorf("%w: msg2 g_y is %d bytes, want 32", ErrHandshake, len(gy))
	}
	gy = append([]byte(nil), gy...)
	if cr, err = r.Uint(); err != nil {
		return
	}
	ct2Head = r.Pos() // everything before the ct2 head is the AAD
	if ct2, err = r.Bstr(); err != nil {
		return
	}
	if !r.Done() {
		return nil, 0, nil, 0, fmt.Errorf("%w: msg2 has trailing bytes", ErrHandshake)
	}
	return
}

func parseMsg3(msg3 []byte) (ct3 []byte, err error) {
	r := bundle.NewCborReader(msg3)
	var n int
	if n, err = r.Array(); err != nil {
		return
	}
	if n != 1 {
		return nil, fmt.Errorf("%w: msg3 array of %d, want 1", ErrHandshake, n)
	}
	if ct3, err = r.Bstr(); err != nil {
		return
	}
	if !r.Done() {
		return nil, fmt.Errorf("%w: msg3 has trailing bytes", ErrHandshake)
	}
	return
}
