package storage

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"offgrid/dtn-node/internal/envelope"
)

// newTestStore opens a fresh Store in the test's temp directory.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// hexID renders n as a deterministic 64-char lowercase hex id.
func hexID(n int) string {
	return fmt.Sprintf("%064x", n)
}

// makeEnv builds a structurally valid envelope with the given id and created_at.
func makeEnv(id string, createdAt int64) envelope.Envelope {
	return envelope.Envelope{
		V:         1,
		ID:        id,
		DestHint:  "9f3ab02c1d77e4c1",
		CreatedAt: createdAt,
		TTL:       3600,
		Payload:   strings.Repeat("A", 332), // 248 bytes -> 332 base64 chars; opaque to storage
	}
}

// TestInsertEnvelopesDedup verifies the INSERT OR IGNORE mechanism (§10.4): a
// second insert of the same id is silently ignored and reports 0 rows.
func TestInsertEnvelopesDedup(t *testing.T) {
	s := newTestStore(t)

	inserted, err := s.InsertEnvelopes([]envelope.Envelope{makeEnv(hexID(1), 100)})
	if err != nil || inserted != 1 {
		t.Fatalf("first insert: got %d inserted, err=%v", inserted, err)
	}
	inserted, err = s.InsertEnvelopes([]envelope.Envelope{makeEnv(hexID(1), 100)})
	if err != nil {
		t.Fatalf("duplicate insert: %v", err)
	}
	if inserted != 0 {
		t.Fatalf("duplicate insert must be ignored, got %d inserted", inserted)
	}

	pulled, err := s.PullEnvelopes(nil, 10, 100)
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	if len(pulled) != 1 || pulled[0].ID != hexID(1) {
		t.Fatalf("expected exactly one envelope after dedup, got %+v", pulled)
	}
}

// TestPullExcludesKnownIDsAndOrders verifies the pull select of §10.4 step 3:
// known ids are excluded, order is created_at DESC with id ASC tie-break, and
// limit applies.
func TestPullExcludesKnownIDsAndOrders(t *testing.T) {
	s := newTestStore(t)

	envs := []envelope.Envelope{
		makeEnv(hexID(1), 100),
		makeEnv(hexID(2), 300),
		makeEnv(hexID(3), 200),
		makeEnv(hexID(4), 200), // same created_at as hexID(3) -> tie-break by id ASC
	}
	if _, err := s.InsertEnvelopes(envs); err != nil {
		t.Fatalf("insert: %v", err)
	}

	pulled, err := s.PullEnvelopes([]string{hexID(2)}, 10, 400)
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	want := []string{hexID(3), hexID(4), hexID(1)} // 300 excluded; 200-tie: id ASC; then 100
	if len(pulled) != len(want) {
		t.Fatalf("expected %d envelopes, got %d: %+v", len(want), len(pulled), pulled)
	}
	for i, id := range want {
		if pulled[i].ID != id {
			t.Fatalf("position %d: want %s, got %s (all: %+v)", i, id, pulled[i].ID, pulled)
		}
	}

	limited, err := s.PullEnvelopes(nil, 2, 400)
	if err != nil {
		t.Fatalf("pull limited: %v", err)
	}
	if len(limited) != 2 || limited[0].ID != hexID(2) || limited[1].ID != hexID(3) {
		t.Fatalf("limit must keep the newest envelopes, got %+v", limited)
	}

	none, err := s.PullEnvelopes([]string{hexID(1), hexID(2), hexID(3), hexID(4)}, 10, 400)
	if err != nil || len(none) != 0 {
		t.Fatalf("all known ids must exclude everything, got %+v err=%v", none, err)
	}
}

// TestPullTTLBoundaryAndDeleteExpired pins the inclusive/exclusive expiry pair
// of §10.4/§10.6: created_at + ttl == now is still servable but not deleted;
// anything older is excluded from pulls and removed by the janitor.
func TestPullTTLBoundaryAndDeleteExpired(t *testing.T) {
	s := newTestStore(t)

	boundary := envelope.Envelope{ // created_at + ttl == now exactly
		V: 1, ID: hexID(1), DestHint: "9f3ab02c1d77e4c1", CreatedAt: 100, TTL: 100,
		Payload: strings.Repeat("A", 332),
	}
	expired := envelope.Envelope{ // created_at + ttl < now
		V: 1, ID: hexID(2), DestHint: "9f3ab02c1d77e4c1", CreatedAt: 99, TTL: 100,
		Payload: strings.Repeat("B", 332),
	}
	if _, err := s.InsertEnvelopes([]envelope.Envelope{boundary, expired}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	pulled, err := s.PullEnvelopes(nil, 10, 200)
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	if len(pulled) != 1 || pulled[0].ID != hexID(1) {
		t.Fatalf("boundary envelope must be servable, expired one not; got %+v", pulled)
	}

	deleted, err := s.DeleteExpired(200)
	if err != nil {
		t.Fatalf("delete expired: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("janitor must delete exactly the expired envelope, deleted %d", deleted)
	}

	pulled, err = s.PullEnvelopes(nil, 10, 200)
	if err != nil {
		t.Fatalf("pull after cleanup: %v", err)
	}
	if len(pulled) != 1 || pulled[0].ID != hexID(1) {
		t.Fatalf("boundary envelope must survive cleanup, got %+v", pulled)
	}
}

// TestInsertEnvelopesCapacityGuard exercises the anti-abuse cap of §8.1
// (plan §7 risk "Llenado del nodo por abuso"): the unexported maxEnvelopes
// var is lowered as a test hook, the store is filled to the cap, and the next
// insert is rejected with the typed ErrCapacity while pulls keep working.
func TestInsertEnvelopesCapacityGuard(t *testing.T) {
	s := newTestStore(t)

	old := maxEnvelopes
	maxEnvelopes = 5
	t.Cleanup(func() { maxEnvelopes = old })

	for i := 0; i < 5; i++ {
		inserted, err := s.InsertEnvelopes([]envelope.Envelope{makeEnv(hexID(i), 100)})
		if err != nil || inserted != 1 {
			t.Fatalf("insert %d below cap: got %d inserted, err=%v", i, inserted, err)
		}
	}

	// At the cap: a new envelope is rejected with the typed error.
	if _, err := s.InsertEnvelopes([]envelope.Envelope{makeEnv(hexID(99), 100)}); !errors.Is(err, ErrCapacity) {
		t.Fatalf("insert at cap: want ErrCapacity, got %v", err)
	}

	// Fail closed (§10.4 step 1): even a dedup-only re-push of an existing id
	// is rejected while the node is full — the batch is refused before any
	// row is touched.
	if _, err := s.InsertEnvelopes([]envelope.Envelope{makeEnv(hexID(0), 100)}); !errors.Is(err, ErrCapacity) {
		t.Fatalf("re-push at cap must fail closed with ErrCapacity, got %v", err)
	}

	// Pulls must keep working at the cap (a full node still serves mail).
	pulled, err := s.PullEnvelopes(nil, 10, 200)
	if err != nil {
		t.Fatalf("pull at cap: %v", err)
	}
	if len(pulled) != 5 {
		t.Fatalf("pull at cap must return the 5 stored envelopes, got %d", len(pulled))
	}
}

// TestInsertEnvelopesDefaultCapacity pins the real default cap (5000) with a
// full-scale run: one batch of 5000 tiny rows is accepted, the next insert
// hits ErrCapacity, and pulls still serve (capped by the limit).
func TestInsertEnvelopesDefaultCapacity(t *testing.T) {
	s := newTestStore(t)

	batch := make([]envelope.Envelope, 0, maxEnvelopes)
	for i := 0; i < maxEnvelopes; i++ {
		batch = append(batch, makeEnv(hexID(i), 100))
	}
	inserted, err := s.InsertEnvelopes(batch)
	if err != nil || inserted != maxEnvelopes {
		t.Fatalf("full-capacity batch: got %d inserted, err=%v", inserted, err)
	}

	if _, err := s.InsertEnvelopes([]envelope.Envelope{makeEnv(hexID(maxEnvelopes), 100)}); !errors.Is(err, ErrCapacity) {
		t.Fatalf("insert past the default cap: want ErrCapacity, got %v", err)
	}

	pulled, err := s.PullEnvelopes(nil, 200, 200)
	if err != nil {
		t.Fatalf("pull at full capacity: %v", err)
	}
	if len(pulled) != 200 {
		t.Fatalf("pull at full capacity must serve up to the limit, got %d", len(pulled))
	}
}

// TestDirectoryUpsertRefreshAndOrdering verifies the directory upsert keyed by
// pubkey (last_seen refresh, alias update) and the last_seen DESC / pubkey ASC
// ordering of §10.3.
func TestDirectoryUpsertRefreshAndOrdering(t *testing.T) {
	s := newTestStore(t)

	keyA := strings.Repeat("A", 44) // 32 bytes -> 44 base64 chars; opaque to storage
	keyB := strings.Repeat("B", 44)
	keyC := strings.Repeat("C", 44)

	if err := s.UpsertDirectory(keyA, keyA, "alice", 100); err != nil {
		t.Fatalf("upsert alice: %v", err)
	}
	if err := s.UpsertDirectory(keyB, keyB, "bob", 200); err != nil {
		t.Fatalf("upsert bob: %v", err)
	}
	// Tie case: carol and dave share last_seen -> pubkey ASC tie-break.
	if err := s.UpsertDirectory(keyC, keyC, "carol", 300); err != nil {
		t.Fatalf("upsert carol: %v", err)
	}
	// keyB sorts before the dave key below, so dave must come first at 300.
	keyD := "D" + strings.Repeat("E", 43)
	if err := s.UpsertDirectory(keyD, keyD, "dave", 300); err != nil {
		t.Fatalf("upsert dave: %v", err)
	}

	// Refresh alice: new alias and newer last_seen.
	if err := s.UpsertDirectory(keyA, keyA, "alice_prime", 400); err != nil {
		t.Fatalf("refresh alice: %v", err)
	}

	// Expected order: alice (400), then the 300-tie by pubkey ASC
	// ("CCC..." < "DEEE..." so carol before dave), then bob (200).
	want := []struct{ alias, pubkey string }{
		{"alice_prime", keyA},
		{"carol", keyC},
		{"dave", keyD},
		{"bob", keyB},
	}
	entries, err := s.GetDirectory(500)
	if err != nil {
		t.Fatalf("get directory: %v", err)
	}
	if len(entries) != len(want) {
		t.Fatalf("expected %d entries, got %d: %+v", len(want), len(entries), entries)
	}
	for i, w := range want {
		if entries[i].Alias != w.alias || entries[i].Pubkey != w.pubkey {
			t.Fatalf("position %d: want %s/%s, got %s/%s", i, w.alias, w.pubkey, entries[i].Alias, entries[i].Pubkey)
		}
	}
	if entries[0].LastSeen != 400 {
		t.Fatalf("refreshed last_seen must be 400, got %d", entries[0].LastSeen)
	}

	limited, err := s.GetDirectory(2)
	if err != nil || len(limited) != 2 {
		t.Fatalf("limit must cap results, got %+v err=%v", limited, err)
	}
}

// TestPullChunkedKnownIDs forces the NOT IN chunking path with 1100 known ids
// (two chunks of the 900-id chunk size) and proves exclusion semantics still
// hold across chunk boundaries.
func TestPullChunkedKnownIDs(t *testing.T) {
	s := newTestStore(t)

	kept := makeEnv(hexID(9001), 100) // id outside the known set
	excluded := makeEnv(hexID(1099), 200)
	if _, err := s.InsertEnvelopes([]envelope.Envelope{kept, excluded}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	known := make([]string, 0, 1100)
	for i := 0; i < 1100; i++ { // includes hexID(1099), spans chunk boundary at 900
		known = append(known, hexID(i))
	}

	pulled, err := s.PullEnvelopes(known, 10, 400)
	if err != nil {
		t.Fatalf("chunked pull: %v", err)
	}
	if len(pulled) != 1 || pulled[0].ID != hexID(9001) {
		t.Fatalf("chunked exclusion failed, got %+v", pulled)
	}

	all, err := s.PullEnvelopes(append(known, hexID(9001)), 10, 400)
	if err != nil {
		t.Fatalf("chunked pull 2: %v", err)
	}
	if len(all) != 0 {
		t.Fatalf("full exclusion across chunks must return nothing, got %+v", all)
	}
}
