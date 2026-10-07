package nodeid

// The role-cert surface of §2.2 beyond the shared vectors: signer-side
// refusal, canonical shape, key-order bytes, COSE structure, and the schema
// checks the vector set samples. Together with vectors_test.go this file is
// the `node/internal/nodeid/rolecert_test.go` promise of §11 row d.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"offgrid/dtn-node/internal/bundle"
)

func testKeypairs(t *testing.T) (anchor, node, node2 KeyPair) {
	t.Helper()
	var err error
	if anchor, err = NewKeyPairFromSeed(mustTestHex(vecAnchorSeedHex)); err != nil {
		t.Fatal(err)
	}
	if node, err = NewKeyPairFromSeed(mustTestHex(vecNodeSeedHex)); err != nil {
		t.Fatal(err)
	}
	if node2, err = NewKeyPairFromSeed(mustTestHex(vecNode2SeedHex)); err != nil {
		t.Fatal(err)
	}
	return
}

func TestSignVerifyRoundTrip(t *testing.T) {
	anchor, node, _ := testKeypairs(t)
	now := vecNow
	eid := EID(Fingerprint(node.Public))
	cose, err := SignCert(anchor, node.Public, eid, []string{RoleBridge, RoleEdge}, 2, now-10, now+86400, 7, now)
	if err != nil {
		t.Fatal(err)
	}
	c, err := VerifyCert(cose, anchor.Public, now)
	if err != nil {
		t.Fatalf("own cert rejected: %v", err)
	}
	if c.Seq != 7 || c.Level != 2 || len(c.Roles) != 2 || !c.HasRole(RoleBridge) {
		t.Fatalf("fields: %s", c)
	}
	if !bytes.Equal(c.Raw(), cose) {
		t.Fatal("Raw() must be the exact received bytes")
	}
	if c.Revocation() || c.Expired(now) {
		t.Fatal("live cert misread")
	}
}

func TestSignerRefusesToBuildInvalidCerts(t *testing.T) {
	anchor, node, _ := testKeypairs(t)
	now := vecNow
	eid := EID(Fingerprint(node.Public))
	cases := []struct {
		name  string
		roles []string
		level uint64
		iss   int64
		exp   int64
		seq   uint64
		code  string
	}{
		{"unknown role", []string{"operator"}, 1, now - 1, now + 100, 1, CodeUnknownRole},
		{"level 0 with roles", []string{RoleEdge}, 0, now - 1, now + 100, 1, CodeLevelRolesMismatch},
		{"revocation above L0", nil, 2, now - 1, now + 100, 1, CodeLevelRolesMismatch},
		{"level above ceiling", []string{RoleEdge}, 4, now - 1, now + 100, 1, CodeLevelRolesMismatch},
		{"duplicate roles", []string{RoleEdge, RoleEdge}, 1, now - 1, now + 100, 1, CodeCertSchema},
		{"expires before issued", []string{RoleEdge}, 1, now - 1, now - 2, 1, CodeBadTimestamps},
		{"issued beyond skew", []string{RoleEdge}, 1, now + MaxCertSkew + 1, now + 100000, 1, CodeBadTimestamps},
		{"issued at zero", []string{RoleEdge}, 1, 0, now + 100, 1, CodeBadTimestamps},
		{"seq zero", []string{RoleEdge}, 1, now - 1, now + 100, 0, CodeBadSeq},
		{"eid of another key", []string{RoleEdge}, 1, now - 1, now + 100, 1, CodeBadEIDBinding},
	}
	for _, tc := range cases {
		useEID := eid
		if tc.code == CodeBadEIDBinding {
			useEID = "dtn://og.0123456789abcdef/"
		}
		if _, err := SignCert(anchor, node.Public, useEID, tc.roles, tc.level, tc.iss, tc.exp, tc.seq, now); err == nil {
			t.Errorf("%s: signer accepted an invalid cert", tc.name)
		} else if got := ErrorCode(err); got != tc.code {
			t.Errorf("%s: code %q want %q", tc.name, got, tc.code)
		}
	}
}

func TestCertMapCanonicalShape(t *testing.T) {
	_, node, _ := testKeypairs(t)
	c := &Cert{Version: CertVersion, EID: EID(Fingerprint(node.Public)), NodeKey: node.Public,
		Roles: []string{RoleEdge}, Level: 1, IssuedTS: 1000, ExpiresTS: 2000, Seq: 1}
	m := EncodeCertMap(c)
	// Fixed key order 0..7: the map head is A8 and the key bytes are the
	// canonical single-byte uints 0x00..0x07 in ascending order.
	if m[0] != 0xA8 {
		t.Fatalf("cert map head 0x%02x, want A8 (map of 8)", m[0])
	}
	// Robust check: re-parse with the reader and confirm key order.
	r := newCborReader(m)
	n, err := r.Map()
	if err != nil || n != 8 {
		t.Fatalf("map head: %v n=%d", err, n)
	}
	for want := 0; want < 8; want++ {
		k, err := r.Uint()
		if err != nil || k != uint64(want) {
			t.Fatalf("key %d: got %d err %v", want, k, err)
		}
		if err := r.Skip(); err != nil {
			t.Fatalf("value %d: %v", want, err)
		}
	}
	if !r.Done() {
		t.Fatal("trailing bytes in cert map")
	}
	// And the canonical byte pattern: map head A8, keys 00..07.
	for i, want := range []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07} {
		found := false
		for _, b := range m {
			if b == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("key byte %d (0x%02x) missing at index %d", i, want, i)
		}
	}
}

func TestCOSEStructure(t *testing.T) {
	anchor, node, _ := testKeypairs(t)
	now := vecNow
	cose, err := SignCert(anchor, node.Public, EID(Fingerprint(node.Public)), []string{RoleEdge}, 1, now-1, now+100, 1, now)
	if err != nil {
		t.Fatal(err)
	}
	if cose[0] != 0x84 {
		t.Fatalf("COSE_Sign1 head 0x%02x, want 0x84", cose[0])
	}
	// protected = bstr({1:-8}); CBOR -8 is major 1, n=7 -> 0x27 (0x26 is
	// ES256's -7 — a distinction the kid/alg pinning below makes load-bearing).
	if !bytes.HasPrefix(cose[1:], []byte{0x43, 0xA1, 0x01, 0x27}) {
		t.Fatalf("protected header % x, want 43 A1 01 27", cose[1:5])
	}
	// unprotected {4: bstr(8)}: A1 04 48 + 8 bytes
	if !bytes.HasPrefix(cose[5:], []byte{0xA1, 0x04, 0x48}) {
		t.Fatalf("unprotected header % x, want A1 04 48", cose[5:8])
	}
	kid := cose[8:16]
	if kid[0] != anchorFP0(t, anchor) {
		t.Fatal("kid is not the anchor fingerprint")
	}
}

func anchorFP0(t *testing.T, anchor KeyPair) byte {
	t.Helper()
	return Fingerprint(anchor.Public)[0]
}

func TestVerifyRejectsCOSEGarbage(t *testing.T) {
	anchor, node, _ := testKeypairs(t)
	now := vecNow
	eid := EID(Fingerprint(node.Public))
	cose, err := SignCert(anchor, node.Public, eid, []string{RoleEdge}, 1, now-1, now+100, 1, now)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		cose []byte
		code string
	}{
		{"empty", nil, CodeCOSEShape},
		{"not an array", []byte{0x01}, CodeCOSEShape},
		{"truncated mid-sig", cose[:len(cose)-10], CodeCOSEShape},
		{"trailing byte", append(append([]byte(nil), cose...), 0x00), CodeCOSEShape},
		{"wrong kid", func() []byte {
			bad := append([]byte(nil), cose...)
			bad[8] ^= 0xff // inside the 8-byte kid
			return bad
		}(), CodeWrongAnchorFP},
	}
	for _, tc := range cases {
		anchorPub := anchor.Public
		if tc.name == "wrong anchor key" {
			_, _, other := testKeypairs(t)
			anchorPub = other.Public // valid shape, unknown anchor
		}
		_, err := VerifyCert(tc.cose, anchorPub, now)
		if err == nil {
			t.Errorf("%s: accepted", tc.name)
			continue
		}
		if got := ErrorCode(err); got != tc.code {
			t.Errorf("%s: code %q want %q", tc.name, got, tc.code)
		}
	}
	// A tampered payload must fail the SIGNATURE (not schema): the cert map
	// says one thing, the anchor signed another. Layout tail: ... 58 <len>
	// <payload ...> 58 40 <sig(64)> — so len-67 is the LAST payload byte.
	tampered := append([]byte(nil), cose...)
	tampered[len(tampered)-67] ^= 0x01
	if _, err := VerifyCert(tampered, anchor.Public, now); ErrorCode(err) != CodeBadSignature {
		t.Fatalf("tampered payload: %v", err)
	}
}

func TestProtectedHeaderPinned(t *testing.T) {
	anchor, node, _ := testKeypairs(t)
	now := vecNow
	// Build a COSE_Sign1 whose protected header carries the right alg but
	// non-canonical bytes (0x38 0x07 = -8 with a 1-byte argument head): the
	// signature would be genuinely valid over those bytes, and the verifier
	// MUST still refuse — the protected header is pinned, not interpreted.
	otherProtected := bundle.EncodeCbor(func(e *bundle.Cbor) {
		e.MapHead(1)
		e.Uint(coseHeaderAlg)
		e.Bstr([]byte{0x26}) // junk under label 1, not a Negint
	})
	payload := EncodeCertMap(&Cert{Version: CertVersion, EID: EID(Fingerprint(node.Public)),
		NodeKey: node.Public, Roles: []string{RoleEdge}, Level: 1, IssuedTS: now - 1, ExpiresTS: now + 100, Seq: 1})
	sigStruct := bundle.EncodeCbor(func(e *bundle.Cbor) {
		e.Array(4)
		e.Tstr("Signature1")
		e.Bstr(otherProtected)
		e.Bstr(nil)
		e.Bstr(payload)
	})
	sig := signRaw(anchor, sigStruct)
	cose := bundle.EncodeCbor(func(e *bundle.Cbor) {
		e.Array(4)
		e.Bstr(otherProtected)
		e.MapHead(1)
		e.Uint(coseHeaderKid)
		e.Bstr(kidBytes(anchor))
		e.Bstr(payload)
		e.Bstr(sig)
	})
	_, err := VerifyCert(cose, anchor.Public, now)
	if got := ErrorCode(err); got != CodeBadProtected {
		t.Fatalf("non-canonical protected header: %v (want %s)", err, CodeBadProtected)
	}
}

func TestSchemaViaReader(t *testing.T) {
	anchor, node, _ := testKeypairs(t)
	now := vecNow
	// A cert map missing a pair (7 keys): the signer refuses, so build one
	// by hand with a valid signature over the broken payload.
	broken := bundle.EncodeCbor(func(e *bundle.Cbor) {
		e.MapHead(7)
		e.Uint(0)
		e.Uint(1)
		e.Uint(1)
		e.Tstr(EID(Fingerprint(node.Public)))
		e.Uint(2)
		e.Bstr(node.Public)
		e.Uint(3)
		e.Array(1)
		e.Tstr(RoleEdge)
		e.Uint(4)
		e.Uint(1)
		e.Uint(5)
		e.Uint(uint64(now - 1))
		e.Uint(6)
		e.Uint(uint64(now + 100))
		// key 7 (seq) missing
	})
	cose := handSignedCOSE(t, anchor, broken)
	if _, err := VerifyCert(cose, anchor.Public, now); ErrorCode(err) != CodeCertSchema {
		t.Fatalf("missing pair: %v (want %s)", err, CodeCertSchema)
	}
	// An extra unknown pair (9 keys) must also fail: the map is fingerprint
	// material, extensions change the schema (a real extension bumps v).
	extra := bundle.EncodeCbor(func(e *bundle.Cbor) {
		e.MapHead(9)
		for i := 0; i < 8; i++ {
			e.Uint(uint64(i))
		}
		e.Uint(1) // garbage filler values
		e.Uint(0)
		e.Tstr(EID(Fingerprint(node.Public)))
		e.Bstr(node.Public)
		e.Array(0)
		e.Uint(1)
		e.Uint(uint64(now - 1))
		e.Uint(uint64(now + 100))
		e.Uint(1)
		e.Uint(9)
		e.Uint(99)
	})
	cose = handSignedCOSE(t, anchor, extra)
	if _, err := VerifyCert(cose, anchor.Public, now); ErrorCode(err) != CodeCertSchema {
		t.Fatalf("extra pair: %v (want %s)", err, CodeCertSchema)
	}
	// Key order swapped (1 before 0): canonical order is part of the schema.
	swapped := bundle.EncodeCbor(func(e *bundle.Cbor) {
		e.MapHead(8)
		e.Uint(1)
		e.Tstr(EID(Fingerprint(node.Public)))
		e.Uint(0)
		e.Uint(1)
		e.Uint(2)
		e.Bstr(node.Public)
		e.Uint(3)
		e.Array(1)
		e.Tstr(RoleEdge)
		e.Uint(4)
		e.Uint(1)
		e.Uint(5)
		e.Uint(uint64(now - 1))
		e.Uint(6)
		e.Uint(uint64(now + 100))
		e.Uint(7)
		e.Uint(1)
	})
	cose = handSignedCOSE(t, anchor, swapped)
	if _, err := VerifyCert(cose, anchor.Public, now); ErrorCode(err) != CodeCertSchema {
		t.Fatalf("swapped keys: %v (want %s)", err, CodeCertSchema)
	}
	// Wrong type in a field (roles as a tstr): schema failure.
	badType := bundle.EncodeCbor(func(e *bundle.Cbor) {
		e.MapHead(8)
		e.Uint(0)
		e.Uint(1)
		e.Uint(1)
		e.Tstr(EID(Fingerprint(node.Public)))
		e.Uint(2)
		e.Bstr(node.Public)
		e.Uint(3)
		e.Tstr(RoleEdge) // not an array
		e.Uint(4)
		e.Uint(1)
		e.Uint(5)
		e.Uint(uint64(now - 1))
		e.Uint(6)
		e.Uint(uint64(now + 100))
		e.Uint(7)
		e.Uint(1)
	})
	cose = handSignedCOSE(t, anchor, badType)
	if _, err := VerifyCert(cose, anchor.Public, now); ErrorCode(err) != CodeCertSchema {
		t.Fatalf("roles as tstr: %v (want %s)", err, CodeCertSchema)
	}
}

func TestExpiryBoundaryAndSentinel(t *testing.T) {
	anchor, node, _ := testKeypairs(t)
	now := vecNow
	mk := func(expires int64) []byte {
		cose, err := SignCert(anchor, node.Public, EID(Fingerprint(node.Public)), []string{RoleEdge}, 1, now-100, expires, 1, now)
		if err != nil {
			t.Fatal(err)
		}
		return cose
	}
	// expires == now is still live (rule 5 is strict `<`).
	if _, err := VerifyCert(mk(now), anchor.Public, now); err != nil {
		t.Fatalf("expires == now rejected: %v", err)
	}
	c, err := VerifyCert(mk(now-1), anchor.Public, now)
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("expired cert: %v (want ErrExpired)", err)
	}
	if ErrorCode(err) != CodeExpired {
		t.Fatalf("expired code %q", ErrorCode(err))
	}
	if c == nil || !c.Expired(now) {
		t.Fatal("expired verify must still expose the cert")
	}
	if c.Expired(now - 1) {
		t.Fatal("boundary off by one")
	}
	// Revocation shape: empty roles, level 0 — verifies as a live cert.
	rev, err := SignCert(anchor, node.Public, EID(Fingerprint(node.Public)), nil, 0, now-100, now+100, 2, now)
	if err != nil {
		t.Fatal(err)
	}
	rc, err := VerifyCert(rev, anchor.Public, now)
	if err != nil || !rc.Revocation() {
		t.Fatalf("revocation: %v %s", err, rc)
	}
}

func TestStringAndCodes(t *testing.T) {
	anchor, node, _ := testKeypairs(t)
	now := vecNow
	cose, err := SignCert(anchor, node.Public, EID(Fingerprint(node.Public)), []string{RoleRelay}, 1, now-100, now+100, 3, now)
	if err != nil {
		t.Fatal(err)
	}
	c, err := VerifyCert(cose, anchor.Public, now)
	if err != nil {
		t.Fatal(err)
	}
	s := c.String()
	for _, want := range []string{"eid=dtn://og.", "roles=relay", "level=1", "seq=3"} {
		if !strings.Contains(s, want) {
			t.Fatalf("String() %q missing %q", s, want)
		}
	}
}

// --- helpers ----------------------------------------------------------------

func signRaw(anchor KeyPair, sigStruct []byte) []byte {
	return ed25519.Sign(anchor.Private, sigStruct)
}

func kidBytes(anchor KeyPair) []byte {
	fp := Fingerprint(anchor.Public)
	return fp[:]
}

func handSignedCOSE(t *testing.T, anchor KeyPair, payload []byte) []byte {
	t.Helper()
	protected := coseProtectedHeader()
	sigStruct := bundle.EncodeCbor(func(e *bundle.Cbor) {
		e.Array(4)
		e.Tstr("Signature1")
		e.Bstr(protected)
		e.Bstr(nil)
		e.Bstr(payload)
	})
	return bundle.EncodeCbor(func(e *bundle.Cbor) {
		e.Array(4)
		e.Bstr(protected)
		e.MapHead(1)
		e.Uint(coseHeaderKid)
		e.Bstr(kidBytes(anchor))
		e.Bstr(payload)
		e.Bstr(signRaw(anchor, sigStruct))
	})
}

// The C host suite (test_nodeid.c) pins the RFC 8032 §7.1/§7.2 vectors as a
// sanity check of the TweetNaCl verify path; this test pins the same hex
// constants on the Go side so the two suites cannot drift apart silently.
func TestRFC8032SanityVectorsSharedWithC(t *testing.T) {
	type vec struct {
		pub, sig string
		msg      string
	}
	vectors := []vec{
		{
			// §7.1 TEST1: empty message
			pub: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
			sig: "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
				"5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
		},
		{
			// §7.2 TEST2: one-byte message 0x72
			pub: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
			sig: "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da" +
				"085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
			msg: "72",
		},
	}
	for i, v := range vectors {
		pub, err := hex.DecodeString(v.pub)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := hex.DecodeString(v.sig)
		if err != nil {
			t.Fatal(err)
		}
		msg, err := hex.DecodeString(v.msg)
		if err != nil {
			t.Fatal(err)
		}
		if !ed25519.Verify(pub, msg, sig) {
			t.Errorf("vector %d: the hex constants shared with the C suite do not verify", i)
		}
	}
}
