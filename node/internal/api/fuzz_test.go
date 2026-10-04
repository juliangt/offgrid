package api

// fuzz_test.go — Go native fuzz target over the POST /api/v1/sync entry
// point (issue #16 Phase 4, Track 4). chaos_fuzz_parsers.sh turns real
// fuzzing on with a small -fuzztime; plain `go test` runs only the seed
// corpus below, fast and deterministic.
//
// The property under fuzz is the handler-level half of the FAILURE_MATRIX.md
// "malformed envelope flood" row: ARBITRARY request bytes through the FULL
// stack (limitBody → decodeJSON → §8.1 shape checks → §10.5/§15.3 envelope
// validation → storage) can only produce a clean answer —
//
//	200          accepted (or silently deduped),
//	400          any request/validation violation (§10.5, §15.3, §10.1),
//	413          body over MaxBodyBytes (§8.1),
//
// and NEVER a 5xx and NEVER a panic. A 5xx from untrusted input would mean
// the shed contract of §10.1 is leaking internals; a panic would take the
// whole single-binary node down (net/http recovers per connection, but the
// request still dies half-served — fail closed means answer, not crash).

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"offgrid/dtn-node/internal/storage"
)

// fuzzID is a well-formed 64-hex envelope id reused by the seeds.
const fuzzID = "d375c17f54525e1816e5f2c01da100e17176c38fd016ea07acb5d3077eb6444f"

// b64Floor is a valid §8.2-floor payload fixture (248 zero bytes, padded
// standard Base64).
func b64Floor() string {
	return base64.StdEncoding.EncodeToString(make([]byte, 248))
}

// knownIDs renders n quoted ids inside JSON array braces (for the
// just-over-the-limit §8.1 known_ids seed).
func knownIDs(n int) string {
	ids := make([]string, n)
	for i := range ids {
		ids[i] = `"` + fuzzID + `"`
	}
	return "[" + strings.Join(ids, ",") + "]"
}

// FuzzSyncHandler runs arbitrary bytes through the real sync handler backed
// by a real (fresh, throwaway) SQLite store per execution.
//
// The admission-control budgets are widened to the point of irrelevance via
// the overrideAdmissionLimits test hook of ratelimit.go: this target fuzzes
// the PARSER and the validator, not the token buckets (a budget-exhausted
// 429 would be correct behavior, but it would drown the input→status signal
// we actually want the fuzzer to explore).
func FuzzSyncHandler(f *testing.F) {
	restore := overrideAdmissionLimits(1<<30, 0, 1<<30, 1<<30, 1<<20, time.Minute)
	defer restore()

	// Seeds: a well-formed push/pull body, the §15.3 structural refusals,
	// the §8.1 shape violations, hostile JSON shapes, and plain garbage.
	f.Add([]byte(`{"known_ids":["` + fuzzID + `"],"push_envelopes":[{"v":1,"id":"` + fuzzID + `","dest_hint":"9f3ab02c1d77e4c1","created_at":1759400000,"ttl":3600,"payload":"` + b64Floor() + `"}],"limit":50}`))
	f.Add([]byte(`{"known_ids":[],"push_envelopes":[],"limit":50}`))
	f.Add([]byte(`{"known_ids":["nothex"],"push_envelopes":[],"limit":0}`))
	f.Add([]byte(`{"known_ids":[],"push_envelopes":[],"limit":1000000}`))
	f.Add([]byte(`{"known_ids":[],"push_envelopes":[{"v":3}],"limit":50}`))
	f.Add([]byte(`{"known_ids":[],"push_envelopes":[{"v":1,"meta":{"orig_v":1}}],"limit":50}`))
	f.Add([]byte(`{"known_ids":[],"push_envelopes":[{"v":1,"id":"zz","payload":"AAA="}],"limit":50}`))
	f.Add([]byte(`{"known_ids":` + knownIDs(501) + `,"push_envelopes":[],"limit":50}`))
	f.Add([]byte(`{"known_ids":null,"push_envelopes":{},"limit":"50"}`))
	f.Add([]byte(`{"known_ids":[{"deep":{"deeper":[1,2,{"x":-1e999}]}}],"push_envelopes":[true,false],"limit":-0}`))
	f.Add([]byte(``))
	f.Add([]byte{0x00, 0x01, 0x02, 0xff})

	f.Fuzz(func(t *testing.T, body []byte) {
		s, err := storage.Open(filepath.Join(t.TempDir(), "fuzz.db"))
		if err != nil {
			t.Fatalf("open fuzz store: %v", err)
		}
		defer s.Close()
		h, err := New(s, testBuild, testWebFS)
		if err != nil {
			t.Fatalf("build fuzz handler: %v", err)
		}

		rec := do(t, h, http.MethodPost, "/api/v1/sync", CanonicalHost, body, "application/json")

		switch rec.Code {
		case http.StatusOK:
			var resp syncResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("200 response is not a decodable §10.4 syncResponse: %v (body: %.200s)", err, rec.Body.String())
			}
			if resp.Status != "ok" {
				t.Fatalf("200 response carries status %q, want \"ok\"", resp.Status)
			}
		case http.StatusBadRequest, http.StatusRequestEntityTooLarge:
			var errBody map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &errBody); err != nil {
				t.Fatalf("clean-shed response is not a decodable §10.1 error shape: %v (status %d, body: %.200s)", err, rec.Code, rec.Body.String())
			}
			if errBody["status"] != "error" {
				t.Fatalf("clean-shed response carries status %q, want \"error\" (§10.1)", errBody["status"])
			}
		default:
			t.Fatalf("arbitrary input produced HTTP %d, want only 200/400/413 — untrusted bytes must never leak a 5xx (body: %.200s)", rec.Code, rec.Body.String())
		}
	})
}
