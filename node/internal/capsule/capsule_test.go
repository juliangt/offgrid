package capsule

// capsule_test.go — the §2.1 format v1 conformance suite (the vectors in
// vectors_test.go pin the Go↔C byte identity; these tests pin the Go
// behavioral contract): the byte layout, the canonical metadata scanner,
// Build/Parse/Verify roundtrip, and every refusal class of §2.4.2/§2.6 —
// tampered payload, tampered metadata, wrong key, bad version, length
// incoherence, non-canonical metadata, the additive-member tolerance.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// testKey is a fixed RFC 8032 §7.1 TEST1 seed — the same key the shared
// vectors sign with, so a failure here and a vector failure point at the
// same key material.
var testSeed = mustHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func testMeta(payload []byte) Metadata {
	sum := sha256.Sum256(payload)
	return Metadata{
		V:              1,
		Release:        1012000,
		Semver:         "v1.12.0",
		VCS:            "v1.12.0-3-gdeadbeef",
		Arch:           "esp32s3",
		MinUpgradeFrom: 1009000,
		SPAEmbedded:    true,
		PayloadSHA256:  hex.EncodeToString(sum[:]),
		PayloadBytes:   len(payload),
		CreatedAt:      1791072000,
	}
}

func buildOK(t *testing.T, priv, payload []byte, mutate func(*Metadata)) []byte {
	t.Helper()
	meta := testMeta(payload)
	if mutate != nil {
		mutate(&meta)
		if meta.PayloadSHA256 == "" || meta.PayloadBytes == 0 && len(payload) > 0 {
			sum := sha256.Sum256(payload)
			meta.PayloadSHA256 = hex.EncodeToString(sum[:])
			meta.PayloadBytes = len(payload)
		}
	}
	blob, err := Build(priv, meta, payload)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return blob
}

func TestRoundtripAndLayout(t *testing.T) {
	payload := bytes.Repeat([]byte("OFGRID-PAYLOAD-"), 70) // 1050 B, synthetic
	blob := buildOK(t, testSeed, payload, nil)

	// The frozen layout: magic, format, mlen, metadata, payload, sig.
	if string(blob[:8]) != "OFGRIDUP" {
		t.Fatalf("magic: %q", blob[:8])
	}
	if blob[8] != 0 || blob[9] != 1 {
		t.Fatalf("format bytes: %x", blob[8:10])
	}
	mlen := int(blob[10])<<24 | int(blob[11])<<16 | int(blob[12])<<8 | int(blob[13])
	if mlen <= 0 || mlen > MaxMetadataLen {
		t.Fatalf("mlen %d out of budget", mlen)
	}
	if len(blob) != HeaderLen+mlen+len(payload)+SigLen {
		t.Fatalf("total %d, want 14+%d+%d+64", len(blob), mlen, len(payload))
	}

	c, err := Parse(blob)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !bytes.Equal(c.Payload, payload) {
		t.Fatalf("payload not byte-exact")
	}
	if c.Meta != testMeta(payload) {
		t.Fatalf("metadata mismatch: %+v", c.Meta)
	}
	pub := ed25519.NewKeyFromSeed(testSeed).Public().(ed25519.PublicKey)
	if err := c.Verify(pub); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestMetadataIsCanonicalFixedOrder(t *testing.T) {
	payload := []byte("payload")
	blob := buildOK(t, testSeed, payload, nil)
	mlen := int(blob[10])<<24 | int(blob[11])<<16 | int(blob[12])<<8 | int(blob[13])
	meta := string(blob[HeaderLen : HeaderLen+mlen])
	want := `{"v":1,"release":1012000,"semver":"v1.12.0","vcs":"v1.12.0-3-gdeadbeef","arch":"esp32s3",` +
		`"min_upgrade_from":1009000,"spa_embedded":true,"payload_sha256":"` +
		hex.EncodeToString(mustSum(payload)) + `","payload_bytes":7,"created_at":1791072000}`
	if meta != want {
		t.Fatalf("canonical metadata bytes drifted:\n got %s\nwant %s", meta, want)
	}
}

func mustSum(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

func TestBuildValidatesLikeAVerifier(t *testing.T) {
	payload := []byte("payload")
	cases := []struct {
		name string
		meta Metadata
		code string
	}{
		{"wrong v", func() Metadata { m := testMeta(payload); m.V = 2; return m }(), CodeVersion},
		{"release 0", func() Metadata { m := testMeta(payload); m.Release = 0; return m }(), CodeMetadata},
		{"empty semver", func() Metadata { m := testMeta(payload); m.Semver = ""; return m }(), CodeMetadata},
		{"arch outside enum", func() Metadata { m := testMeta(payload); m.Arch = "riscv"; return m }(), CodeMetadata},
		{"spa not embedded", func() Metadata { m := testMeta(payload); m.SPAEmbedded = false; return m }(), CodeMetadata},
		{"sha not hex", func() Metadata {
			m := testMeta(payload)
			m.PayloadSHA256 = strings.ToUpper(hex.EncodeToString(mustSum(payload)))
			return m
		}(), CodeMetadata},
		{"payload_bytes lie", func() Metadata { m := testMeta(payload); m.PayloadBytes = 6; return m }(), CodeLenMismatch},
		{"created_at 0", func() Metadata { m := testMeta(payload); m.CreatedAt = 0; return m }(), CodeCreatedAt},
		{"sha mismatch", func() Metadata {
			m := testMeta(payload)
			m.PayloadSHA256 = hex.EncodeToString(mustSum([]byte("other")))
			return m
		}(), CodeSHA},
	}
	for _, tc := range cases {
		if _, err := Build(testSeed, tc.meta, payload); ErrorCode(err) != tc.code {
			t.Fatalf("%s: Build err = %v, want code %s", tc.name, err, tc.code)
		}
	}
	// A wrong-size key is refused, not ignored.
	if _, err := Build([]byte("short"), testMeta(payload), payload); ErrorCode(err) != CodeSignature {
		t.Fatalf("short key: %v", err)
	}
}

func TestTamperPayload(t *testing.T) {
	payload := bytes.Repeat([]byte("A"), 300)
	blob := buildOK(t, testSeed, payload, nil)
	blob[len(blob)-SigLen-1] ^= 0x01 // the LAST payload byte, before the sig
	c, err := Parse(blob)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	pub := ed25519.NewKeyFromSeed(testSeed).Public().(ed25519.PublicKey)
	if err := c.Verify(pub); ErrorCode(err) != CodeSHA {
		t.Fatalf("tampered payload: %v, want %s", err, CodeSHA)
	}
}

func TestTamperMetadataKillsSignature(t *testing.T) {
	payload := []byte("payload")
	blob := buildOK(t, testSeed, payload, nil)
	// Flip a byte INSIDE the metadata (the semver region sits a few bytes
	// past the header): Parse may still succeed but the signature is over
	// the verbatim bytes, so Verify must refuse.
	blob[HeaderLen+20] ^= 0x04
	c, err := Parse(blob)
	if err != nil {
		// A flipped byte can also break the canonical shape — also fine.
		return
	}
	pub := ed25519.NewKeyFromSeed(testSeed).Public().(ed25519.PublicKey)
	if err := c.Verify(pub); ErrorCode(err) != CodeSignature {
		t.Fatalf("tampered metadata: %v, want %s", err, CodeSignature)
	}
}

func TestTamperSignature(t *testing.T) {
	payload := []byte("payload")
	blob := buildOK(t, testSeed, payload, nil)
	blob[len(blob)-1] ^= 0x80
	c, err := Parse(blob)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	pub := ed25519.NewKeyFromSeed(testSeed).Public().(ed25519.PublicKey)
	if err := c.Verify(pub); ErrorCode(err) != CodeSignature {
		t.Fatalf("tampered sig: %v, want %s", err, CodeSignature)
	}
}

func TestWrongKeyRefused(t *testing.T) {
	payload := []byte("payload")
	blob := buildOK(t, testSeed, payload, nil)
	c, _ := Parse(blob)
	other := sha256.Sum256([]byte("another release key"))
	if err := c.Verify(other[:]); ErrorCode(err) != CodeSignature {
		t.Fatalf("wrong key: %v, want %s", err, CodeSignature)
	}
	if err := c.Verify([]byte("nope")); ErrorCode(err) != CodeUnpinned {
		t.Fatalf("bad key size: %v, want %s", err, CodeUnpinned)
	}
}

func TestParseRefusals(t *testing.T) {
	payload := []byte("payload")
	good := buildOK(t, testSeed, payload, nil)

	if _, err := Parse([]byte("NOTACAPS")); ErrorCode(err) != CodeMagic {
		t.Fatalf("bad magic: %v", err)
	}
	if _, err := Parse(nil); ErrorCode(err) != CodeMagic {
		t.Fatalf("empty: %v", err)
	}
	bad := append([]byte(nil), good...)
	bad[9] = 2
	if _, err := Parse(bad); ErrorCode(err) != CodeFormat {
		t.Fatalf("format 2: %v", err)
	}
	if _, err := Parse(good[:len(good)-10]); err == nil {
		t.Fatalf("truncated capsule must fail")
	}
	// mlen over the §2.1.2 budget.
	huge := append([]byte(nil), good[:HeaderLen]...)
	huge[10], huge[11], huge[12], huge[13] = 0, 0, 0x10, 0x00 // 4096
	if _, err := Parse(append(huge, good[HeaderLen:]...)); ErrorCode(err) != CodeLength {
		t.Fatalf("mlen over budget: %v", err)
	}
	// payload_bytes incoherent with the actual length.
	incoh := append([]byte(nil), good...)
	// 7 → 8 the metadata payload_bytes member (last digit before created_at).
	idx := bytes.Index(incoh, []byte(`"payload_bytes":7,`))
	if idx < 0 {
		t.Fatalf("test setup: member not found")
	}
	incoh[idx+len(`"payload_bytes":`)] = '8'
	if _, err := Parse(incoh); ErrorCode(err) != CodeLenMismatch {
		t.Fatalf("incoherent payload_bytes: %v", err)
	}
}

func TestMetadataScannerStrictness(t *testing.T) {
	// A canonical, correctly-signed capsule whose metadata is NOT the
	// frozen shape is refused at Parse — canonical-but-foreign is a forged
	// artifact, never a formatting nuance.
	payload := []byte("payload")
	sum := hex.EncodeToString(mustSum(payload))
	cases := []struct {
		name string
		meta string
	}{
		{"sorted order", `{"arch":"esp32s3","min_upgrade_from":1,"payload_bytes":7,"payload_sha256":"` + sum + `","release":1,"semver":"x","spa_embedded":true,"v":1,"vcs":"","created_at":5}`},
		{"whitespace", `{"v":1, "release":1}`},
		{"missing member", `{"v":1,"release":1,"semver":"x","vcs":"","arch":"esp32","min_upgrade_from":1,"spa_embedded":true,"payload_sha256":"` + sum + `","payload_bytes":7}`},
		{"leading zero", `{"v":01,"release":1}`},
		{"negative release", `{"v":1,"release":-1}`},
		{"spa_embedded false", `{"v":1,"release":1,"semver":"x","vcs":"","arch":"esp32","min_upgrade_from":1,"spa_embedded":false,"payload_sha256":"` + sum + `","payload_bytes":7,"created_at":5}`},
		{"unknown member between frozen ones", `{"v":1,"release":1,"extra":true,"semver":"x","vcs":"","arch":"esp32","min_upgrade_from":1,"spa_embedded":true,"payload_sha256":"` + sum + `","payload_bytes":7,"created_at":5}`},
		{"trailing garbage", `{"v":1,"release":1,"semver":"x","vcs":"","arch":"esp32","min_upgrade_from":1,"spa_embedded":true,"payload_sha256":"` + sum + `","payload_bytes":7,"created_at":5}}`},
		{"v=2", `{"v":2,"release":1,"semver":"x","vcs":"","arch":"esp32","min_upgrade_from":1,"spa_embedded":true,"payload_sha256":"` + sum + `","payload_bytes":7,"created_at":5}`},
	}
	for _, tc := range cases {
		blob, err := buildUnsignedWithMeta(tc.meta, payload)
		if err != nil {
			t.Fatalf("%s: setup: %v", tc.name, err)
		}
		if _, err := Parse(blob); ErrorCode(err) != CodeMetadata && ErrorCode(err) != CodeVersion {
			t.Fatalf("%s: Parse err = %v, want bad_metadata/bad_version", tc.name, err)
		}
	}
}

// buildUnsignedWithMeta assembles a capsule around a raw metadata string
// (unsigned — Parse runs before Verify, so the shape refusals fire first).
func buildUnsignedWithMeta(meta string, payload []byte) ([]byte, error) {
	blob := make([]byte, 0, HeaderLen+len(meta)+len(payload)+SigLen)
	blob = append(blob, Magic...)
	blob = append(blob, 0, 1)
	mlen := len(meta)
	blob = append(blob, byte(mlen>>24), byte(mlen>>16), byte(mlen>>8), byte(mlen))
	blob = append(blob, meta...)
	blob = append(blob, payload...)
	blob = append(blob, make([]byte, SigLen)...)
	return blob, nil
}

// handSignedCapsule assembles a capsule around a RAW metadata string and
// signs meta ‖ payload with the test release key — the tool for metadata
// Build itself would refuse (foreign arch strings, additive members): the
// §9.1 rule is that verifiers ACCEPT unknown arch at the format level and
// refuse it at the node's arch gate, so the gate needs a genuinely
// well-signed foreign-arch capsule to bite on.
func handSignedCapsule(t *testing.T, meta string, payload []byte) []byte {
	t.Helper()
	blob, err := buildUnsignedWithMeta(meta, payload)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	key := ed25519.NewKeyFromSeed(testSeed)
	mlen := len(meta)
	sig := ed25519.Sign(key, blob[HeaderLen:HeaderLen+mlen+len(payload)])
	copy(blob[HeaderLen+mlen+len(payload):], sig)
	return blob
}

func canonMeta(t *testing.T, payload []byte, arch string, release uint64) string {
	t.Helper()
	sum := sha256.Sum256(payload)
	return `{"v":1,"release":` + utoa(release) + `,"semver":"v1.12.0","vcs":"x","arch":"` + arch +
		`","min_upgrade_from":0,"spa_embedded":true,"payload_sha256":"` + hex.EncodeToString(sum[:]) +
		`","payload_bytes":` + itoa(len(payload)) + `,"created_at":1791072000}`
}

func TestAdditiveMetadataMemberTolerated(t *testing.T) {
	// §2.1.2: future additive members live AFTER the frozen ten, stay
	// signature-covered, and are ignored by verifiers.
	payload := []byte("payload")
	meta := canonMeta(t, payload, "esp32s3", 1012000)
	meta = meta[:len(meta)-1] + `,"delta_base":"1011000"}`
	blob := handSignedCapsule(t, meta, payload)

	c, err := Parse(blob)
	if err != nil {
		t.Fatalf("additive member must parse: %v", err)
	}
	pub := ed25519.NewKeyFromSeed(testSeed).Public().(ed25519.PublicKey)
	if err := c.Verify(pub); err != nil {
		t.Fatalf("additive member must verify: %v", err)
	}
	if c.Meta.Release != 1012000 {
		t.Fatalf("frozen members still parsed: %+v", c.Meta)
	}
}

func TestArchEnum(t *testing.T) {
	for _, a := range []string{"armv6", "armv7", "arm64", "esp32s3", "esp32"} {
		if !ValidArch(a) {
			t.Fatalf("arch %q must be in the §9.1 enum", a)
		}
	}
	for _, a := range []string{"", "riscv", "x86_64", "ARM64", "esp32-s3"} {
		if ValidArch(a) {
			t.Fatalf("arch %q must NOT be in the §9.1 enum", a)
		}
	}
}

func TestReleaseFromSemver(t *testing.T) {
	if got := ReleaseFromSemver(1, 12, 0); got != 1012000 {
		t.Fatalf("ReleaseFromSemver(1,12,0) = %d, want 1012000", got)
	}
	if got := ReleaseFromSemver(0, 0, 7); got != 7 {
		t.Fatalf("ReleaseFromSemver(0,0,7) = %d, want 7", got)
	}
}

func TestParseViewsNotCopies(t *testing.T) {
	payload := []byte("payload")
	blob := buildOK(t, testSeed, payload, nil)
	c, _ := Parse(blob)
	// Documented behavior: Payload views the input. A caller that mutates
	// it corrupts its own capsule — Verify catches it (sha).
	blob[len(blob)-SigLen-1] ^= 0xFF
	if err := c.Verify(ed25519.NewKeyFromSeed(testSeed).Public().(ed25519.PublicKey)); ErrorCode(err) != CodeSHA {
		t.Fatalf("mutation through the view must be caught by the sha: %v", err)
	}
}
