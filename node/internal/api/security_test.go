package api

// security_test.go — regression tests for the issue #14 security audit
// (Phase 1, node daemon): the directory capacity shed of NODE-01. The
// header fix has its own file (security_headers_test.go).
//
//   - TestDirectoryCapShedsNewRegistrationsWithNodeFull pins NODE-01: the
//     unauthenticated directory table is bounded (storage.MaxDirectoryEntries);
//     a NEW registration at the cap is shed with 429 node_full (the same
//     capacity class POST /api/v1/sync answers at envelope capacity), while
//     a refresh of an entry that already exists always succeeds — a full
//     directory must never lock existing users out of their own
//     republication.
//   - TestDirectoryBelowCapAcceptsNewRegistrations is the guard rail: below
//     the cap, ordinary registration behavior is byte-for-byte the pre-fix
//     contract (200 {"status":"ok"}).

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"offgrid/dtn-node/internal/storage"
)

// TestDirectoryCapShedsNewRegistrationsWithNodeFull verifies the NODE-01 fix
// end to end through the HTTP surface: with the directory filled to its
// storage cap, a registration for a NEW pubkey is refused with 429 node_full
// and stores nothing, a registration for a pubkey ALREADY present answers
// 200 and refreshes the entry, and the GET surface keeps serving.
func TestDirectoryCapShedsNewRegistrationsWithNodeFull(t *testing.T) {
	h, store := newTestHandler(t)

	// Restore the node clock the upsert path reads (any fixed instant; the
	// §6.1 epoch value is not what this test pins).
	restore := stubTimeNow(t, time.Unix(1791072000, 0))
	defer restore()

	// Fill the directory to exactly its enforced cap with direct store
	// upserts (distinct pubkeys; 32 bytes each so the API's key validation
	// accepts them on the requests below).
	keyAt := func(n int) string {
		raw := make([]byte, 32)
		raw[0], raw[1] = byte(n), byte(n>>8)
		raw[2] = 0xAB
		return base64.StdEncoding.EncodeToString(raw)
	}
	capEntries := storage.MaxDirectoryEntries()
	for i := 0; i < capEntries; i++ {
		if err := store.UpsertDirectory(keyAt(i), keyAt(i), "user", 100, 0, nil); err != nil {
			t.Fatalf("fill directory entry %d: %v", i, err)
		}
	}

	// A NEW pubkey over the API: 429 with the node_full code — the same shed
	// class the sync endpoint answers at envelope capacity.
	rec := postJSON(t, h, "/api/v1/directory", map[string]string{
		"alias": "newcomer", "pubkey": keyAt(capEntries + 1), "x25519": keyAt(capEntries + 1),
	})
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("new registration at directory cap: got %d, want 429 (body: %s)", rec.Code, rec.Body.String())
	}
	var errBody map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &errBody); err != nil || errBody["error"] != "node_full" {
		t.Fatalf("429 must carry the node_full code, got %s", rec.Body.String())
	}

	// Fail closed: the refused registration stored nothing (count unchanged).
	if n, err := store.DirectoryCount(); err != nil || n != int64(capEntries) {
		t.Fatalf("rejected registration must store nothing, got %d entries err=%v", n, err)
	}

	// An EXISTING pubkey keeps full refresh service at the cap: 200, alias
	// and bundle updated, no new row.
	rec = postJSON(t, h, "/api/v1/directory", map[string]any{
		"alias": "refreshed", "pubkey": keyAt(0), "x25519": keyAt(0),
		"prekeys": prekeyTestBundle(3, 4),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("existing-pubkey refresh at cap: got %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	if n, err := store.DirectoryCount(); err != nil || n != int64(capEntries) {
		t.Fatalf("refresh must not add a row, got %d entries err=%v", n, err)
	}
	entries, err := store.GetDirectory(10)
	if err != nil {
		t.Fatalf("re-read directory: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.Pubkey == keyAt(0) {
			found = true
			if e.Alias != "refreshed" || e.Prekeys == nil {
				t.Fatalf("refreshed entry must carry the new alias and bundle, got %+v", e)
			}
		}
	}
	if !found {
		t.Fatalf("the refreshed entry vanished from the directory")
	}

	// The read surface is unaffected by the cap: the GET still answers.
	rec = do(t, h, http.MethodGet, "/api/v1/directory", CanonicalHost, nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET directory at cap: got %d, want 200", rec.Code)
	}
}

// TestDirectoryBelowCapAcceptsNewRegistrations is the guard-rail companion to
// the cap test: a fresh, empty directory must accept new registrations with
// the exact pre-fix behavior (200 {"status":"ok"}) — the cap is a shed at
// capacity, never a new validation gate on ordinary traffic.
func TestDirectoryBelowCapAcceptsNewRegistrations(t *testing.T) {
	h, _ := newTestHandler(t)

	rec := postJSON(t, h, "/api/v1/directory", map[string]string{
		"alias": "alice", "pubkey": keyB64(1), "x25519": keyB64(2),
	})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"ok"`) {
		t.Fatalf("registration below cap: got %d (body: %s)", rec.Code, rec.Body.String())
	}
}
