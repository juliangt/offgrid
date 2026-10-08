package directory

// card_test.go — the §9.3 card format pinned byte-for-byte: §3.1.1's
// canonical JSON with the detached self-signature, the §3.1.2 worked vector
// reproduced exactly, every §3.1/§3.2 rejection class, and the emission
// bundle shape.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"offgrid/dtn-node/internal/bundle"
	"offgrid/dtn-node/internal/nodeid"
)

// The RFC 8032 §7.1 TEST1 key — the same catalogue seed the nodeid and mgmt
// vectors use (traceable, reproducible), and the identity of the §3.1.2
// worked vector.
var testUserSeed = mustSeed("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")

var testX = mustX("offgrid-directory-test-x1")

const testTS = int64(1791072000)

// The §3.1.2 worked-vector literals (offline-maintenance §3.1.2, same
// identity as protocol §4.6/§4.7).
const (
	vecXB64   = "/R7hH59JUnnBjDLCUFTQ46F9eKg0kK8Chze1mEQpqVg="
	vecSigned = `{"v":1,"alias":"alice_77","ed":"11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=","x":"/R7hH59JUnnBjDLCUFTQ46F9eKg0kK8Chze1mEQpqVg=","ts":1791072000,"seq":1}`
	vecSigB64 = "+ZQ/Mk1S6ouEM+jHGTZTe0hP8FEvQ+5rw71Ef3jlW/zrif+nmnp2F90RMlFIwRuBtfa1UCL9soGz95pkBwzADA=="
)

func mustSeed(hx string) []byte {
	b, err := base64.StdEncoding.DecodeString(mustB64OfHex(hx))
	if err != nil {
		panic(err)
	}
	return b
}

// mustB64OfHex is a tiny readability shim: the seeds are written hex in the
// RFC catalogue; base64 keeps this file free of a hex import.
func mustB64OfHex(hx string) string {
	raw := make([]byte, len(hx)/2)
	var v int
	for i := 0; i < len(hx); i += 2 {
		hi := hexVal(hx[i])
		lo := hexVal(hx[i+1])
		raw[v] = byte(hi<<4 | lo)
		v++
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	}
	panic("bad hex")
}

func mustX(label string) []byte {
	s := sha256.Sum256([]byte(label))
	return s[:]
}

func testUser(t *testing.T) nodeid.KeyPair {
	t.Helper()
	kp, err := nodeid.NewKeyPairFromSeed(testUserSeed)
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

func mustCard(t *testing.T, user nodeid.KeyPair, alias string, x []byte, ts int64, seq uint64) []byte {
	t.Helper()
	card, err := SignCard(user, alias, x, ts, seq)
	if err != nil {
		t.Fatal(err)
	}
	return card
}

// TestCardWorkedVector pins §3.1.2 byte-for-byte: the implementation mints
// the documented signed string and the documented signature exactly — the
// same card a mule-carried JSON payload would carry.
func TestCardWorkedVector(t *testing.T) {
	user := testUser(t)
	vecX, err := base64.StdEncoding.DecodeString(vecXB64)
	if err != nil {
		t.Fatal(err)
	}
	signed := cardSignedString(&Card{V: 1, Alias: "alice_77", Ed25519: user.Public, X25519: vecX, CreatedTS: 1791072000, Seq: 1})
	if string(signed) != vecSigned {
		t.Fatalf("signed string:\n got %q\nwant %q", signed, vecSigned)
	}
	if len(signed) != 153 {
		t.Fatalf("signed string is %d bytes, the §3.1.2 table says 153", len(signed))
	}
	card := mustCard(t, user, "alice_77", vecX, 1791072000, 1)
	wantCard := vecSigned[:len(vecSigned)-1] + `,"sig":"` + vecSigB64 + `"}`
	if string(card) != wantCard {
		t.Fatalf("complete card:\n got %q\nwant %q", card, wantCard)
	}
	// And it verifies.
	if _, err := VerifyCard(card, 1791072000); err != nil {
		t.Fatalf("the worked vector must verify: %v", err)
	}
}

func TestCardLayoutRoundTrip(t *testing.T) {
	user := testUser(t)
	card := mustCard(t, user, "alice_77", testX, testTS, 7)

	parsed, err := ParseCard(card)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.V != 1 || parsed.Alias != "alice_77" || parsed.Seq != 7 || parsed.CreatedTS != testTS {
		t.Fatalf("fields: %+v", parsed)
	}
	if !bytes.Equal(parsed.Ed25519, user.Public) || !bytes.Equal(parsed.X25519, testX) {
		t.Fatalf("keys: ed %x x %x", parsed.Ed25519, parsed.X25519)
	}

	// VerifyCard at the issue time and at the skew ceiling; a card created
	// more than MaxCreatedSkew into the RECEIVER's future is dropped (the
	// receiver's clock is the reference, §3.1: "≤ merge time + 300").
	if _, err := VerifyCard(card, testTS); err != nil {
		t.Fatalf("verify at ts: %v", err)
	}
	if _, err := VerifyCard(card, testTS-MaxCreatedSkew); err != nil {
		t.Fatalf("verify at the skew ceiling: %v", err)
	}
	if _, err := VerifyCard(card, testTS-MaxCreatedSkew-1); err == nil {
		t.Fatal("verify accepted a card beyond the §3.1 skew ceiling")
	}

	// The published Base64 is canonical and round-trips the exact bytes.
	if got := CanonicalB64(card); got != base64.StdEncoding.EncodeToString(card) {
		t.Fatal("CanonicalB64 is not the std encoding")
	}

	// The signature really is Ed25519 detached over §3.1.1's signed string
	// with the card's OWN key (rescan and rebuild the signed string
	// independently — the prefix plus the closing brace).
	_, sig, signedLen, err := scanCard(card)
	if err != nil {
		t.Fatal(err)
	}
	signed := append(append([]byte(nil), card[:signedLen]...), '}')
	if !ed25519.Verify(user.Public, signed, sig) {
		t.Fatal("the self-signature does not verify against the card's own key")
	}
}

func TestCardSizeBudget(t *testing.T) {
	user := testUser(t)
	// The realistic card is far under the §3.1 cap (§3.1.2's ≈ 370 B class).
	card := mustCard(t, user, "alice_77", testX, testTS, 1)
	if len(card) >= 300 {
		t.Fatalf("realistic card is %d bytes — the ≈300 B budget is gone", len(card))
	}
}

func TestCardRejections(t *testing.T) {
	user := testUser(t)
	other, err := nodeid.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	good := mustCard(t, user, "alice_77", testX, testTS, 1)
	fillerSig := base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))

	// raw renders a canonical-shaped card with arbitrary field values (the
	// rejection tests' workhorse — fields the constructor would refuse).
	raw := func(alias string, edB64, xB64 string, ts, seq string) []byte {
		return []byte(`{"v":1,"alias":"` + alias + `","ed":"` + edB64 + `","x":"` + xB64 + `","ts":` + ts + `,"seq":` + seq + `,"sig":"` + fillerSig + `"}`)
	}
	goodEd := base64.StdEncoding.EncodeToString(user.Public)
	goodX := base64.StdEncoding.EncodeToString(testX)
	shortEd := base64.StdEncoding.EncodeToString(user.Public[:31])
	shortX := base64.StdEncoding.EncodeToString(testX[:31])

	cases := []struct {
		name    string
		card    []byte
		now     int64
		parseOK bool   // true = the SHAPE is valid; only VerifyCard must fail
		want    string // the VerifyCard error substring
	}{
		{"empty", nil, testTS, false, "length 0 outside"},
		{"oversize", bytes.Repeat([]byte{0x7B}, CardMaxBytes+1), testTS, false, "outside [1"},
		{"not_json", []byte("hello"), testTS, false, "expected {\"v\":1,\"alias\":\""},
		{"flipped_sig", func() []byte {
			// Corrupt the signature itself, not the framing: decode the sig
			// member, flip one bit of the raw 64 bytes, re-encode — the card
			// stays canonical end to end and must die at the verify step.
			b := append([]byte(nil), good...)
			s := string(b)
			const marker = `,"sig":"`
			i := strings.Index(s, marker)
			if i < 0 {
				t.Fatal("no sig member")
			}
			sig, err := base64.StdEncoding.DecodeString(s[i+len(marker) : len(s)-2])
			if err != nil {
				t.Fatal(err)
			}
			sig[0] ^= 0x01
			mut := s[:i+len(marker)] + base64.StdEncoding.EncodeToString(sig) + s[len(s)-2:]
			return []byte(mut)
		}(), testTS, true, "signature check failed"},
		{"bad_b64_sig", []byte(`{"v":1,"alias":"alice_77","ed":"` + goodEd + `","x":"` + goodX + `","ts":1,"seq":1,"sig":"$$ this is not Base64 at all $$"}`), testTS, false, "sig must be 88"},
		{"v2", []byte(`{"v":2,"alias":"alice_77","ed":"` + goodEd + `","x":"` + goodX + `","ts":1,"seq":1,"sig":"` + fillerSig + `"}`), testTS, false, "expected {\"v\":1,\"alias\":\""},
		{"bad_alias", raw("alice bob!", goodEd, goodX, "1", "1"), testTS, false, "alias"},
		{"long_alias", raw(strings.Repeat("a", 25), goodEd, goodX, "1", "1"), testTS, false, "alias"},
		{"short_ed", raw("alice_77", shortEd, goodX, "1", "1"), testTS, false, "ed must be"},
		{"short_x", raw("alice_77", goodEd, shortX, "1", "1"), testTS, false, "x must be"},
		{"zero_ts", raw("alice_77", goodEd, goodX, "0", "1"), testTS, false, "ts must be > 0"},
		{"leading_zero_ts", raw("alice_77", goodEd, goodX, "01", "1"), testTS, false, "leading zero"},
		{"zero_seq", raw("alice_77", goodEd, goodX, "1", "0"), testTS, false, "seq must be"},
		{"whitespace", []byte(`{"v":1, "alias":"alice_77","ed":"` + goodEd + `","x":"` + goodX + `","ts":1,"seq":1,"sig":"` + fillerSig + `"}`), testTS, false, "expected "},
		{"trailing", append(append([]byte(nil), good...), '}'), testTS, false, "trailing bytes"},
		{"skew", mustCard(t, user, "alice_77", testX, testTS+MaxCreatedSkew+1, 1), testTS, true, "ahead of the receiver"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.parseOK {
				if _, err := ParseCard(tc.card); err != nil {
					t.Fatalf("the blind door must accept the %s shape, got: %v", tc.name, err)
				}
			} else if _, err := ParseCard(tc.card); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ParseCard error = %v, want substring %q", err, tc.want)
			}
			if _, err := VerifyCard(tc.card, tc.now); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("VerifyCard error = %v, want substring %q", err, tc.want)
			}
		})
	}

	// A card signed by a DIFFERENT key than it carries is not a forgery —
	// it verifies as THAT key's card (the signature is self-certifying).
	forged := mustCard(t, other, "alice_77", testX, testTS, 1)
	if _, err := VerifyCard(forged, testTS); err != nil {
		t.Fatalf("a self-consistent card from another key must verify (it is that key's card): %v", err)
	}
	// ...but it is a DIFFERENT identity: its ed is other's key, which the
	// merge dedup treats as a different pubkey row (§3.4 rule 1).
	fc, err := ParseCard(forged)
	if err != nil || bytes.Equal(fc.Ed25519, user.Public) {
		t.Fatalf("forged card identity: %v", err)
	}
}

func TestSignCardConstructorRefusals(t *testing.T) {
	user := testUser(t)
	if _, err := SignCard(user, "bad alias!", testX, testTS, 1); err == nil {
		t.Fatal("accepted a bad alias")
	}
	if _, err := SignCard(user, "alice_77", testX[:31], testTS, 1); err == nil {
		t.Fatal("accepted a 31-byte x25519")
	}
	if _, err := SignCard(user, "alice_77", testX, 0, 1); err == nil {
		t.Fatal("accepted ts 0")
	}
	if _, err := SignCard(user, "alice_77", testX, testTS, 0); err == nil {
		t.Fatal("accepted seq 0")
	}
}

func TestEmitCardBundleShape(t *testing.T) {
	user := testUser(t)
	card := mustCard(t, user, "alice_77", testX, testTS, 1)
	kp, err := nodeid.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	eid, err := nodeid.EIDFromPub(kp.Public)
	if err != nil {
		t.Fatal(err)
	}
	pdu, err := EmitCardBundle(eid, card, time.Unix(testTS, 0).UnixMilli(), 3)
	if err != nil {
		t.Fatal(err)
	}
	b, err := bundle.Parse(pdu, time.Unix(testTS, 0))
	if err != nil {
		t.Fatalf("parse emitted bundle: %v", err)
	}
	if b.Destination.String() != DirEID || b.Source.String() != eid {
		t.Fatalf("bundle addresses: %s -> %s", b.Source, b.Destination)
	}
	if b.Hop != 0 || b.Lifetime != CardBundleLifetime || b.Sequence != 3 {
		t.Fatalf("hop/lifetime/seq: %d/%d/%d", b.Hop, b.Lifetime, b.Sequence)
	}
	// The payload is the §3.1 card VERBATIM (the P3.0 freeze: hop octet ‖
	// the card's canonical JSON bytes verbatim — one serialization, two
	// transports).
	if !bytes.Equal(b.Payload, card) {
		t.Fatal("the emitted payload is not the card's exact bytes")
	}
	if _, err := VerifyCard(b.Payload, testTS); err != nil {
		t.Fatalf("the emitted payload must verify: %v", err)
	}
	if _, err := EmitCardBundle(eid, make([]byte, CardMaxBytes+1), 0, 1); err == nil {
		t.Fatal("emitted an over-cap card")
	}
}
