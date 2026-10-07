package nodeid

// The identity primitives of docs/node-network.md §2.1, pinned against the
// RFC 8032 test keys and a couple of derived properties the spec requires
// (derivation, binding, closed parsing).

import (
	"encoding/hex"
	"strings"
	"testing"
)

// RFC 8032 §7.1 TEST1: the seed/pair every Ed25519 implementation quotes.
const rfc8032Test1PubHex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"

func TestNewKeyPairFromSeed(t *testing.T) {
	seed, _ := hex.DecodeString(vecAnchorSeedHex)
	kp, err := NewKeyPairFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	if len(kp.Public) != KeyLen || len(kp.Private) != 64 {
		t.Fatalf("key sizes: pub %d priv %d", len(kp.Public), len(kp.Private))
	}
	if hex.EncodeToString(kp.Public) != rfc8032Test1PubHex {
		t.Fatalf("pub %s, want the RFC 8032 §7.1 TEST1 public key", hex.EncodeToString(kp.Public))
	}
	if _, err := NewKeyPairFromSeed(seed[:31]); err == nil {
		t.Fatal("31-byte seed accepted")
	}
	// Determinism: same seed, same pair.
	again, err := NewKeyPairFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(again.Public) != hex.EncodeToString(kp.Public) {
		t.Fatal("seed derivation is not deterministic")
	}
}

func TestFingerprintAndEID(t *testing.T) {
	pub, _ := hex.DecodeString(rfc8032Test1PubHex)
	fp := Fingerprint(pub)
	if len(fp) != FingerprintLen {
		t.Fatalf("fingerprint length %d", len(fp))
	}
	eid := EID(fp)
	if len(eid) != EIDLen || eid[:9] != "dtn://og." || eid[25] != '/' {
		t.Fatalf("eid shape %q", eid)
	}
	if eid != strings.ToLower(eid) {
		t.Fatal("fingerprint must be lowercase")
	}
	// The EID is derived, never chosen: same key -> same EID, always.
	if eid2 := EID(Fingerprint(pub)); eid2 != eid {
		t.Fatal("derivation unstable")
	}
	// FromPub wraps the two.
	e, err := EIDFromPub(pub)
	if err != nil || e != eid {
		t.Fatalf("EIDFromPub: %q %v", e, err)
	}
	if _, err := EIDFromPub(pub[:31]); err == nil {
		t.Fatal("short key accepted")
	}
}

func TestParseEID(t *testing.T) {
	pub, _ := hex.DecodeString(rfc8032Test1PubHex)
	wantPubFP := Fingerprint(pub)
	want := EID(wantPubFP)
	fp, err := ParseEID(want)
	if err != nil {
		t.Fatalf("valid EID rejected: %v", err)
	}
	if hex.EncodeToString(fp[:]) != hex.EncodeToString(wantPubFP[:]) {
		t.Fatal("round-trip mismatch")
	}
	for _, bad := range []string{
		"",
		"dtn://og.0123456789abcdef",       // no trailing slash
		"dtn://og.0123456789abcdefg/",     // 17 chars
		"dtn://og.0123456789ABCDEF/",      // uppercase
		"dtn://og.0123456789abcde/",       // 15 chars
		"dtn://other.0123456789abcdef/",   // wrong prefix
		"https://og.0123456789abcdef/",    // wrong scheme
		"dtn://og.0123456789abcdef/extra", // trailing junk
		"dtn://og.zzzzzzzzzzzzzzzz/",      // not hex
	} {
		if _, err := ParseEID(bad); err == nil {
			t.Errorf("ParseEID(%q) accepted", bad)
		}
	}
}

func TestValidateBinding(t *testing.T) {
	kp, err := NewKeyPairFromSeed(mustTestHex(vecNodeSeedHex))
	if err != nil {
		t.Fatal(err)
	}
	good := EID(Fingerprint(kp.Public))
	if err := ValidateBinding(kp.Public, good); err != nil {
		t.Fatalf("valid binding rejected: %v", err)
	}
	// Another key's EID: exactly what a stolen/forged cert would claim.
	other, _ := NewKeyPairFromSeed(mustTestHex(vecNode2SeedHex))
	if err := ValidateBinding(kp.Public, EID(Fingerprint(other.Public))); err == nil {
		t.Fatal("mismatched binding accepted")
	}
	if err := ValidateBinding(kp.Public[:31], good); err == nil {
		t.Fatal("short key accepted")
	}
}

func mustTestHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
