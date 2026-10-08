// Package nodeid implements the node identity of docs/node-network.md §2
// (issue #33 P3.1): self-certifying Ed25519 node EIDs, the COSE_Sign1 role
// certificates of §2.2, the seq merge rules of §2.5 (offline-maintenance
// §3.4, verbatim) and the TOFU pin store of §6.1 (offline-maintenance §3.5,
// the same pattern). The C counterpart lives in
// esp32/components/dtn_core/{dtn_nodeid,dtn_rolecert}.c and is verified
// against the SAME vectors (tests/vectors/nodeid/vectors.json); the C side
// is verify-only by design — the anchor that signs never runs there.
//
// Crypto is Go stdlib only (crypto/ed25519, crypto/sha256); the CBOR bytes
// come from the single canonical encoder of internal/bundle (the P3.0
// spike's), never from a second implementation.
package nodeid

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// FingerprintLen is the EID fingerprint length: SHA-256(pub)[0:8], hexed to
// 16 lowercase chars (docs/node-network.md §2.1).
const (
	FingerprintLen = 8
	FingerprintHex = 16
	// KeyLen is the Ed25519 public key length.
	KeyLen = 32
	// SeedLen is the Ed25519 seed (private key) length.
	SeedLen = 32
	// eidPrefix/eidSuffix delimit the only EID form of the node plane.
	eidPrefix = "dtn://og."
	eidSuffix = "/"
	// EIDLen is the exact length of a node EID: "dtn://og." + 16 hex + "/".
	EIDLen = len(eidPrefix) + FingerprintHex + len(eidSuffix)
)

// KeyPair is an Ed25519 key pair of the node plane (node key or anchor key
// — both are plain Ed25519; their roles differ only in ceremony, §2.6).
type KeyPair struct {
	Public  ed25519.PublicKey  // 32 bytes
	Private ed25519.PrivateKey // 64 bytes (seed ‖ public)
}

// NewKeyPairFromSeed derives the key pair from a 32-byte Ed25519 seed (the
// offline ceremonies store exactly this, hexed, in *.seed files 0600).
func NewKeyPairFromSeed(seed []byte) (KeyPair, error) {
	if len(seed) != SeedLen {
		return KeyPair{}, fmt.Errorf("nodeid: seed must be %d bytes, got %d", SeedLen, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return KeyPair{Public: priv.Public().(ed25519.PublicKey), Private: priv}, nil
}

// GenerateKeyPair creates a fresh key pair from crypto/rand (host-side
// ceremonies only; nothing on this plane generates keys at runtime).
func GenerateKeyPair() (KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return KeyPair{}, err
	}
	return KeyPair{Public: pub, Private: priv}, nil
}

// Fingerprint is the node-plane identity primitive: the first 8 bytes of
// SHA-256 over the Ed25519 public key (§2.1). The EID is derived, never
// chosen; a 64-bit fingerprint is the entire public identity on the wire.
func Fingerprint(pub []byte) [8]byte {
	var fp [8]byte
	if len(pub) != KeyLen {
		return fp // all-zero: callers validate key length first
	}
	sum := sha256.Sum256(pub)
	copy(fp[:], sum[:8])
	return fp
}

// EID renders dtn://og.<16 lowercase hex>/ from a fingerprint (§2.1).
func EID(fingerprint [FingerprintLen]byte) string {
	return eidPrefix + hex.EncodeToString(fingerprint[:]) + eidSuffix
}

// EIDFromPub is EID(Fingerprint(pub)) — the one-liner every provisioning
// ceremony and handshake ends with.
func EIDFromPub(pub []byte) (string, error) {
	if len(pub) != KeyLen {
		return "", fmt.Errorf("nodeid: public key must be %d bytes, got %d", KeyLen, len(pub))
	}
	return EID(Fingerprint(pub)), nil
}

// ParseEID validates the exact node-EID form and returns its fingerprint.
// It rejects every deviation — wrong length, wrong prefix/suffix, uppercase
// hex, non-hex bytes — because the EID is a key fingerprint, not a name.
func ParseEID(eid string) ([FingerprintLen]byte, error) {
	var fp [FingerprintLen]byte
	if len(eid) != EIDLen || !strings.HasPrefix(eid, eidPrefix) || !strings.HasSuffix(eid, eidSuffix) {
		return fp, fmt.Errorf("nodeid: %q is not a node EID (want %s<%d lowercase hex>%s)", eid, eidPrefix, FingerprintHex, eidSuffix)
	}
	hx := eid[len(eidPrefix) : len(eid)-len(eidSuffix)]
	raw, err := hex.DecodeString(hx)
	if err != nil {
		return fp, fmt.Errorf("nodeid: EID fingerprint is not hex: %w", err)
	}
	// hex.DecodeString accepts uppercase; the fingerprint form does not.
	if hx != hex.EncodeToString(raw) {
		return fp, fmt.Errorf("nodeid: EID fingerprint must be lowercase hex")
	}
	copy(fp[:], raw)
	return fp, nil
}

// ValidateBinding is the §2.1 self-certification check every verifier MUST
// run: the EID's fingerprint MUST equal SHA-256(node_key)[0:8] of the
// certified key. Without it the EID is just a name; with it, a cert cannot
// claim someone else's identity without the private key.
func ValidateBinding(pub []byte, eid string) error {
	if len(pub) != KeyLen {
		return fmt.Errorf("nodeid: public key must be %d bytes, got %d", KeyLen, len(pub))
	}
	if _, err := ParseEID(eid); err != nil {
		return err
	}
	want := EID(Fingerprint(pub))
	if want != eid {
		return fmt.Errorf("nodeid: EID binding failed: %s certifies key %s", eid, want)
	}
	return nil
}

// FingerprintOfEID parses the EID and returns its 8-byte fingerprint (the
// COSE kid slot and the PinStore key on it).
func FingerprintOfEID(eid string) ([FingerprintLen]byte, error) {
	return ParseEID(eid)
}
