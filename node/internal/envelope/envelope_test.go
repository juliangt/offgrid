package envelope

import (
	"encoding/base64"
	"strings"
	"testing"
)

// specVector is the normative test envelope of docs/protocolo.md §3.2, whose
// §6.2 test vector 2 fixes the id for this exact canonical serialization.
const specVectorPayload = "f46MqdLy8TaHj3lnjcYvHnOuAU8lrXD/nDHUzwGAW/5rQERh00/2ez0ZkfsZz6yc2FpGq2ukrJYxb/P0OQPt6vbAt4I3TKcA21aBVxCxjX4ZZZA23cub/SQusRHDZzjPDmI3HQj6ZpTbEntNfCKagXtQY/MCjvusFuP24DZVGxRhZ0K6l1KKsV0fZ5MOgg+QfFheegNat7plIFMf1Y0TuQrii+JffAfgGh1vAWRr3OvAxWyRbH04Ofw/UBrKZLdevwAcCUcn7mgYcCrXZvSFlHavFH84Pyk2egL0mnPXubm9iMVQOraXcklUzgYVbGlme8w+0yZrDNE="

// b64 returns the standard padded Base64 of size deterministic bytes.
func b64(size int) string {
	raw := make([]byte, size)
	for i := range raw {
		raw[i] = byte(i % 251)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// validEnv returns an envelope that passes Validate for any now >= its
// created_at. It is the base for every mutation-based boundary test below.
func validEnv() Envelope {
	return Envelope{
		V:         1,
		ID:        strings.Repeat("ab", 32),
		DestHint:  "9f3ab02c1d77e4c1",
		CreatedAt: 1000,
		TTL:       3600,
		Payload:   b64(MinPayloadLen),
	}
}

// TestValidateSpecTestVector pins the normative envelope of protocolo.md
// §3.2: it must validate at its own creation time, and its payload must
// decode to 332 bytes (inside [248, 400]).
func TestValidateSpecTestVector(t *testing.T) {
	e := Envelope{
		V:         1,
		ID:        "d375c17f54525e1816e5f2c01da100e17176c38fd016ea07acb5d3077eb6444f",
		DestHint:  "9f3ab02c1d77e4c1",
		CreatedAt: 1759500000,
		TTL:       604800,
		Payload:   specVectorPayload,
	}
	if err := e.Validate(1759500000); err != nil {
		t.Fatalf("normative test vector must validate: %v", err)
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(e.Payload)
	if err != nil || len(raw) != 248 {
		t.Fatalf("test vector payload must decode to 248 bytes (the §8.2 floor case), got %d (err=%v)", len(raw), err)
	}
}

// TestValidateBoundary exercises every boundary of §10.5 through mutations of
// a valid envelope.
func TestValidateBoundary(t *testing.T) {
	const now = int64(1000)

	cases := []struct {
		name    string
		mutate  func(*Envelope)
		wantErr bool
	}{
		// version
		{"v=1 ok", func(e *Envelope) {}, false},
		{"v=0 rejected", func(e *Envelope) { e.V = 0 }, true},
		{"v=2 rejected", func(e *Envelope) { e.V = 2 }, true},
		// id
		{"id ok", func(e *Envelope) {}, false},
		{"id uppercase rejected", func(e *Envelope) { e.ID = strings.Repeat("AB", 32) }, true},
		{"id 63 chars rejected", func(e *Envelope) { e.ID = strings.Repeat("a", 63) }, true},
		{"id 65 chars rejected", func(e *Envelope) { e.ID = strings.Repeat("a", 65) }, true},
		{"id non-hex rejected", func(e *Envelope) { e.ID = strings.Repeat("g", 64) }, true},
		{"id empty rejected", func(e *Envelope) { e.ID = "" }, true},
		// dest_hint
		{"dest_hint 15 chars rejected", func(e *Envelope) { e.DestHint = "9f3ab02c1d77e4c" }, true},
		{"dest_hint 17 chars rejected", func(e *Envelope) { e.DestHint = "9f3ab02c1d77e4c11" }, true},
		{"dest_hint uppercase rejected", func(e *Envelope) { e.DestHint = "9F3AB02C1D77E4C1" }, true},
		{"dest_hint empty rejected", func(e *Envelope) { e.DestHint = "" }, true},
		// created_at
		{"created_at=now ok", func(e *Envelope) { e.CreatedAt = now }, false},
		{"created_at=now+300 ok", func(e *Envelope) { e.CreatedAt = now + ClockSkewSeconds }, false},
		{"created_at=now+301 rejected", func(e *Envelope) { e.CreatedAt = now + ClockSkewSeconds + 1 }, true},
		{"created_at=0 rejected", func(e *Envelope) { e.CreatedAt = 0 }, true},
		{"created_at negative rejected", func(e *Envelope) { e.CreatedAt = -1 }, true},
		// ttl
		{"ttl=3600 ok", func(e *Envelope) { e.TTL = 3600 }, false},
		{"ttl=2592000 ok", func(e *Envelope) { e.TTL = 2592000 }, false},
		{"ttl=3599 rejected", func(e *Envelope) { e.TTL = 3599 }, true},
		{"ttl=2592001 rejected", func(e *Envelope) { e.TTL = 2592001 }, true},
		{"ttl=0 rejected", func(e *Envelope) { e.TTL = 0 }, true},
		{"ttl negative rejected", func(e *Envelope) { e.TTL = -3600 }, true},
		// payload
		{"payload 248 decoded ok", func(e *Envelope) { e.Payload = b64(248) }, false},
		{"payload 400 decoded ok", func(e *Envelope) { e.Payload = b64(400) }, false},
		{"payload 247 decoded rejected", func(e *Envelope) { e.Payload = b64(247) }, true},
		{"payload 401 decoded rejected", func(e *Envelope) { e.Payload = b64(401) }, true},
		{"payload empty rejected", func(e *Envelope) { e.Payload = "" }, true},
		{"payload not base64 rejected", func(e *Envelope) { e.Payload = "not*base64!!" }, true},
		{"payload base64url rejected", func(e *Envelope) { e.Payload = strings.ReplaceAll(b64(248), "+", "-") }, true},
		{"payload with newline rejected", func(e *Envelope) { e.Payload = b64(248)[:10] + "\n" + b64(248)[10:] }, true},
		{"payload unpadded rejected", func(e *Envelope) { e.Payload = strings.TrimRight(b64(250), "=") }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := validEnv()
			tc.mutate(&e)
			err := e.Validate(now)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected success, got error: %v", err)
			}
		})
	}
}

// TestValidateNowBoundary pins that Validate is anchored to the caller's now
// (clock skew tolerance moves with it).
func TestValidateNowBoundary(t *testing.T) {
	e := validEnv()
	e.CreatedAt = 2000
	if err := e.Validate(1700); err != nil { // 2000 == 1700+300
		t.Fatalf("envelope at exactly skew edge must pass: %v", err)
	}
	if err := e.Validate(1699); err == nil { // 2000 > 1699+300
		t.Fatalf("envelope beyond skew edge must fail")
	}
}

// TestValidAlias covers the shared alias regex of §8.1.
func TestValidAlias(t *testing.T) {
	valid := []string{"a", "alice_77", "A.b-C_d", "0123456789", "-ok-", strings.Repeat("x", 24)}
	for _, a := range valid {
		if !ValidAlias(a) {
			t.Errorf("alias %q must be valid", a)
		}
	}
	invalid := []string{"", "has space", "unicode-ñ", "no/exclamation!", strings.Repeat("x", 25)}
	for _, a := range invalid {
		if ValidAlias(a) {
			t.Errorf("alias %q must be invalid", a)
		}
	}
}
