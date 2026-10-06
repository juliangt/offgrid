package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"offgrid/dtn-node/internal/envelope"
	"offgrid/dtn-node/internal/storage"
)

// Conformance tests for the §10.5 unknown-recipient behavior (issue #37,
// docs/protocol.md §15.7 row q): the sync push path NEVER consults the
// directory table — dest_hint is a one-way hash derivation (§6.1), not a
// directory key — so an envelope whose dest_hint addresses no registered
// identity is STORED, SERVED and TTL-EXPIRED exactly like any other envelope,
// and its rejection is FORBIDDEN (a rejection/bounce would hand the open AP a
// recipient-existence oracle — an information leak, §13.2/§13.5).
//
// The strongest honest form of the pin is structural: these tests run against
// a node whose directory table is EMPTY throughout — successful storage with
// no directory to consult IS the proof that no code path consults it.

// TestUnknownRecipientStoredServedExpired pins the full lifecycle on an empty
// directory: a valid envelope whose dest_hint matches no directory entry is
// accepted 200 and stored; a pull presenting that dest_hint receives it
// byte-identical; the §10.6 expiry boundary deletes it; and the directory
// table is empty before, between and after every leg.
func TestUnknownRecipientStoredServedExpired(t *testing.T) {
	h, s := newTestHandler(t)

	// The directory starts empty and must stay empty for the whole test:
	// every dest_hint in existence is therefore an "unknown" hint, and a
	// successful store proves the push path never needed a directory entry.
	assertDirectoryEmpty(t, h, s)

	now := time.Now().Unix()
	env := validEnv(hexID(7), now)

	// (a) Accepted and stored. The push response must be the ordinary 200
	// ok shape — nothing about it may signal "unknown recipient".
	rec := postJSON(t, h, "/api/v1/sync", map[string]any{
		"known_ids":      []string{env.ID}, // do not pull our own push back (§10.4)
		"push_envelopes": []envelope.Envelope{env},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("push with a dest_hint matching no directory entry: got %d, want 200 (body: %s)",
			rec.Code, rec.Body.String())
	}
	assertSyncShape(t, rec.Body.Bytes(), "push")
	if n, err := s.EnvelopeCount(); err != nil || n != 1 {
		t.Fatalf("unknown-recipient envelope must be stored like any other, envelope count = %d (err: %v)", n, err)
	}
	assertDirectoryEmpty(t, h, s)

	// (b) Served byte-identical to a puller that presents that dest_hint.
	rec = postJSON(t, h, "/api/v1/sync", map[string]any{
		"known_ids": []string{},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("pull: got %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	assertSyncShape(t, rec.Body.Bytes(), "pull")
	var resp struct {
		PullEnvelopes []envelope.Envelope `json:"pull_envelopes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode pull response: %v", err)
	}
	if len(resp.PullEnvelopes) != 1 {
		t.Fatalf("pull must serve the unknown-recipient envelope, got %d envelopes", len(resp.PullEnvelopes))
	}
	got := resp.PullEnvelopes[0]
	if got.ID != env.ID || got.DestHint != env.DestHint || got.CreatedAt != env.CreatedAt ||
		got.TTL != env.TTL || got.Payload != env.Payload || got.V != env.V {
		t.Fatalf("served envelope must be byte-identical to the pushed one:\n  got  %+v\n  want %+v", got, env)
	}
	if !bytes.Equal(mustMarshal(t, got), mustMarshal(t, env)) {
		t.Fatalf("served envelope must marshal byte-identical:\n  got  %s\n  want %s", mustMarshal(t, got), mustMarshal(t, env))
	}
	assertDirectoryEmpty(t, h, s)

	// (c) Expired by the TTL janitor (§10.6). The janitor's only action is
	// store.DeleteExpired(now) — the exclusive boundary — on its 15-minute
	// cadence plus the startup sweep; calling it at the envelope's deadline
	// +1 s is exactly what the next sweep performs, with no sleeping.
	deleted, err := s.DeleteExpired(env.CreatedAt + env.TTL + 1)
	if err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("the TTL janitor must reap the unknown-recipient envelope, deleted %d rows", deleted)
	}
	if n, err := s.EnvelopeCount(); err != nil || n != 0 {
		t.Fatalf("expired envelope must be gone, envelope count = %d (err: %v)", n, err)
	}
	rec = postJSON(t, h, "/api/v1/sync", map[string]any{"known_ids": []string{}})
	var after struct {
		PullEnvelopes []envelope.Envelope `json:"pull_envelopes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &after); err != nil {
		t.Fatalf("decode post-expiry pull: %v", err)
	}
	if len(after.PullEnvelopes) != 0 {
		t.Fatalf("expired envelope must not be served, got %+v", after.PullEnvelopes)
	}

	// (d) The directory was never consulted: still empty after the full
	// stored → served → expired cycle.
	assertDirectoryEmpty(t, h, s)
}

// TestUnknownRecipientResponseIndistinguishable pins the no-oracle half of
// §10.5: the response to a push whose dest_hint addresses a REGISTERED user
// and the response to the same push made against an EMPTY directory are
// indistinguishable — same status code, same response member set, same
// "status" value, no extra member of any kind. Any observable difference
// would be a recipient-existence oracle (§13.5), so the member-set equality
// is the pin.
func TestUnknownRecipientResponseIndistinguishable(t *testing.T) {
	h, _ := newTestHandler(t)
	now := time.Now().Unix()

	// Push against the empty directory (every hint is unknown).
	unknownEnv := validEnv(hexID(8), now)
	recUnknown := postJSON(t, h, "/api/v1/sync", map[string]any{
		"known_ids":      []string{},
		"push_envelopes": []envelope.Envelope{unknownEnv},
	})
	if recUnknown.Code != http.StatusOK {
		t.Fatalf("push against an empty directory: got %d, want 200", recUnknown.Code)
	}

	// Register a user, then push an envelope with the same dest_hint — from
	// the pusher's point of view this is the "known recipient" case.
	recDir := postJSON(t, h, "/api/v1/directory", map[string]string{
		"alias": "alice_77", "pubkey": keyB64(1), "x25519": keyB64(2),
	})
	if recDir.Code != http.StatusOK {
		t.Fatalf("directory upsert: got %d (body: %s)", recDir.Code, recDir.Body.String())
	}
	knownEnv := validEnv(hexID(9), now)
	recKnown := postJSON(t, h, "/api/v1/sync", map[string]any{
		"known_ids":      []string{unknownEnv.ID}, // keep the two pull sets the same size
		"push_envelopes": []envelope.Envelope{knownEnv},
	})
	if recKnown.Code != http.StatusOK {
		t.Fatalf("push against a populated directory: got %d, want 200", recKnown.Code)
	}

	// Indistinguishable: same status code; decoding both bodies as generic
	// JSON objects yields exactly the same member set with the same
	// "status" value — neither response carries any error, warning or
	// "unknown" marker the other lacks.
	if recUnknown.Code != recKnown.Code {
		t.Fatalf("status codes differ: unknown-recipient push %d, known-recipient push %d",
			recUnknown.Code, recKnown.Code)
	}
	var unknownObj, knownObj map[string]json.RawMessage
	if err := json.Unmarshal(recUnknown.Body.Bytes(), &unknownObj); err != nil {
		t.Fatalf("decode unknown-recipient response: %v", err)
	}
	if err := json.Unmarshal(recKnown.Body.Bytes(), &knownObj); err != nil {
		t.Fatalf("decode known-recipient response: %v", err)
	}
	if len(unknownObj) != len(knownObj) {
		t.Fatalf("response member sets differ: unknown %v, known %v", keysOf(unknownObj), keysOf(knownObj))
	}
	for k, v := range unknownObj {
		if _, ok := knownObj[k]; !ok {
			t.Fatalf("known-recipient response lacks member %q (oracle leak)", k)
		}
		if k == "status" && string(v) != string(knownObj[k]) {
			t.Fatalf("status member differs: unknown %s, known %s", v, knownObj[k])
		}
	}
	// Both carry the ordinary pull set of size 1 (known_ids kept them equal).
	for name, obj := range map[string]map[string]json.RawMessage{"unknown": unknownObj, "known": knownObj} {
		var pulls []json.RawMessage
		if err := json.Unmarshal(obj["pull_envelopes"], &pulls); err != nil {
			t.Fatalf("%s response pull_envelopes: %v", name, err)
		}
		if len(pulls) != 1 {
			t.Fatalf("%s response must carry exactly one pulled envelope, got %d", name, len(pulls))
		}
	}
}

// assertDirectoryEmpty fails the test unless the directory table is empty,
// checked both through the public GET (what a client could observe) and the
// store count (what the push path could have consulted and did not).
func assertDirectoryEmpty(t *testing.T, h http.Handler, s *storage.Store) {
	t.Helper()
	rec := do(t, h, http.MethodGet, "/api/v1/directory", CanonicalHost, nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET directory: got %d, want 200", rec.Code)
	}
	var entries []storage.DirectoryEntry
	if err := json.Unmarshal(rec.Body.Bytes(), &entries); err != nil {
		t.Fatalf("decode directory: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("directory must be empty for the unknown-recipient pin, got %+v", entries)
	}
	if n, err := s.DirectoryCount(); err != nil || n != 0 {
		t.Fatalf("directory table must be empty, count = %d (err: %v)", n, err)
	}
}

// assertSyncShape verifies a §10.4 response body carries exactly the two
// specified members with "status" = "ok" — no error, warning or
// recipient-existence marker.
func assertSyncShape(t *testing.T, body []byte, leg string) {
	t.Helper()
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		t.Fatalf("%s: decode response: %v", leg, err)
	}
	if len(obj) != 2 {
		t.Fatalf("%s: response must carry exactly {status, pull_envelopes}, got %v", leg, keysOf(obj))
	}
	if _, ok := obj["pull_envelopes"]; !ok {
		t.Fatalf("%s: response lacks pull_envelopes", leg)
	}
	if string(obj["status"]) != `"ok"` {
		t.Fatalf("%s: response status must be \"ok\", got %s", leg, obj["status"])
	}
}

// keysOf returns the sorted member names of a decoded JSON object.
func keysOf(obj map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}

// mustMarshal marshals v with the same encoding the API uses for envelopes
// (encoding/json over the envelope struct) so the byte-identical comparison
// compares like with like.
func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}
