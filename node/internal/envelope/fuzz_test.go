package envelope

// fuzz_test.go — Go native fuzz target over the server-side parse+validate
// path of the envelope format (issue #16 Phase 4, Track 4: the chaos suite
// turns real fuzzing on with chaos_fuzz_parsers.sh; plain `go test` runs
// only the seed corpora below, fast, so the normal suite stays deterministic).
//
// The property under fuzz is the one FAILURE_MATRIX.md pins for the
// "malformed envelope flood" row: ARBITRARY bytes through §10.5/§15.3 can
// only produce a decode error or a validation error — never a panic, and a
// valid envelope stays valid through a marshal round trip.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
)

// fuzzNow is a fixed server clock (unix seconds): validation is deterministic
// with respect to the input bytes alone.
const fuzzNow int64 = 1759400000

// FuzzParseEnvelope feeds raw bytes through the exact admission path of a
// pushed envelope: JSON decode into the §3.1 struct, then Envelope.Validate
// (§10.5 checks plus the §15.3 version set and per-version meta rules).
//
// Assertions:
//   - json.Unmarshal either succeeds or returns an error — a malformed body
//     is an ERROR, never a panic (the flood must be shed, not fatal);
//   - Validate returns nil or an error — never a panic — for ANY decodable
//     input, including hostile meta members, absurd timestamps/sizes and
//     invalid Base64;
//   - an envelope Validate accepts (nil error) must STILL validate after a
//     marshal → unmarshal round trip: what the node stores and later serves
//     is the marshaled form, so acceptance must be stable across it.
func FuzzParseEnvelope(f *testing.F) {
	// A valid §8.2-floor payload fixture (248 decoded bytes), reused by the
	// accepted-path seeds below.
	floorPayload := base64.StdEncoding.EncodeToString(make([]byte, 248))
	id := "d375c17f54525e1816e5f2c01da100e17176c38fd016ea07acb5d3077eb6444f"
	hint := "9f3ab02c1d77e4c1"
	validV1 := fmt.Sprintf(`{"v":1,"id":"%s","dest_hint":"%s","created_at":%d,"ttl":3600,"payload":"%s"}`, id, hint, fuzzNow, floorPayload)
	validV2 := fmt.Sprintf(`{"v":2,"id":"%s","dest_hint":"%s","created_at":%d,"ttl":3600,"payload":"%s","meta":{"orig_v":1}}`, id, hint, fuzzNow, floorPayload)

	// Seeds: the interesting corners of the format — the accepted v1/v2
	// paths, the §15.3 structural refusals (v1+meta, bad orig_v, v: 3),
	// hostile meta and Base64, wrong types, truncated JSON, plain garbage.
	f.Add([]byte(validV1))
	f.Add([]byte(validV2))
	f.Add([]byte(fmt.Sprintf(`{"v":2,"id":"%s","dest_hint":"%s","created_at":%d,"ttl":3600,"payload":"%s","meta":{"orig_v":2}}`, id, hint, fuzzNow, floorPayload)))
	f.Add([]byte(`{"v":1,"id":"` + id + `","meta":{"orig_v":1}}`))
	f.Add([]byte(`{"v":2,"id":"x","dest_hint":"","created_at":-1,"ttl":0,"payload":"!!!!"}`))
	f.Add([]byte(`{"v":3,"id":"ffff","created_at":1e999}`))
	f.Add([]byte(`{"id":123,"payload":[1,2,3],"ttl":"3600"}`))
	f.Add([]byte(`{"v":2`))
	f.Add([]byte(``))
	f.Add([]byte{0x00, 0xff, 0xfe, 0xfd, 0x01, 0x02})

	f.Fuzz(func(t *testing.T, data []byte) {
		var e Envelope
		if err := json.Unmarshal(data, &e); err != nil {
			return // malformed JSON is a decode error: shed, never crash
		}
		if err := e.Validate(fuzzNow); err != nil {
			return // any validation error is a clean shed
		}
		// Accepted envelopes must stay accepted through the store round trip:
		// the node persists and serves the marshaled form (§15.3: payload
		// bytes are never re-encoded), so acceptance must not depend on
		// quirks the re-marshal would normalize away.
		remarshaled, merr := json.Marshal(e)
		if merr != nil {
			t.Fatalf("an envelope that passed Validate failed to re-marshal: %v (envelope: %+v)", merr, e)
		}
		var e2 Envelope
		if uerr := json.Unmarshal(remarshaled, &e2); uerr != nil {
			t.Fatalf("an envelope that passed Validate failed to re-decode: %v (remarshaled: %s)", uerr, remarshaled)
		}
		if err := e2.Validate(fuzzNow); err != nil {
			t.Fatalf("validation is not stable across the marshal round trip: original accepted, remarshaled refused with %v (remarshaled: %s)", err, remarshaled)
		}
	})
}
