package storage

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"offgrid/dtn-node/internal/envelope"
)

// legacySchema1 is the exact §9 schema as originally deployed — storage
// schema version 1 (§15.3): no envelopes.v column and no user_version marker.
// Only the migration test's fixture uses it.
const legacySchema1 = `
CREATE TABLE envelopes (
  id         TEXT PRIMARY KEY,
  dest_hint  TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  ttl        INTEGER NOT NULL,
  payload    TEXT NOT NULL
);
CREATE INDEX idx_envelopes_dest_hint ON envelopes(dest_hint);
CREATE INDEX idx_envelopes_expiry    ON envelopes(created_at, ttl);

CREATE TABLE directory (
  pubkey    TEXT PRIMARY KEY,
  x25519    TEXT NOT NULL,
  alias     TEXT NOT NULL,
  last_seen INTEGER NOT NULL
);
`

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

// userVersion reads PRAGMA user_version from db.
func userVersion(t *testing.T, db *sql.DB) int {
	t.Helper()
	var v int
	if err := db.QueryRow("PRAGMA user_version").Scan(&v); err != nil {
		t.Fatalf("read user_version: %v", err)
	}
	return v
}

// tableColumns returns the column names of the named table (PRAGMA
// table_info; the table name is always a test-controlled literal).
func tableColumns(t *testing.T, db *sql.DB, table string) []string {
	t.Helper()
	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		t.Fatalf("table_info(%s): %v", table, err)
	}
	defer rows.Close()
	var cols []string
	for rows.Next() {
		var (
			cid       int
			name      string
			ctype     string
			notNull   int
			dfltValue any
			pk        int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dfltValue, &pk); err != nil {
			t.Fatalf("scan table_info(%s): %v", table, err)
		}
		cols = append(cols, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate table_info(%s): %v", table, err)
	}
	return cols
}

// hasColumn reports whether cols contains name.
func hasColumn(cols []string, name string) bool {
	for _, c := range cols {
		if c == name {
			return true
		}
	}
	return false
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

	if err := s.UpsertDirectory(keyA, keyA, "alice", 100, 0, nil); err != nil {
		t.Fatalf("upsert alice: %v", err)
	}
	if err := s.UpsertDirectory(keyB, keyB, "bob", 200, 0, nil); err != nil {
		t.Fatalf("upsert bob: %v", err)
	}
	// Tie case: carol and dave share last_seen -> pubkey ASC tie-break.
	if err := s.UpsertDirectory(keyC, keyC, "carol", 300, 0, nil); err != nil {
		t.Fatalf("upsert carol: %v", err)
	}
	// keyB sorts before the dave key below, so dave must come first at 300.
	keyD := "D" + strings.Repeat("E", 43)
	if err := s.UpsertDirectory(keyD, keyD, "dave", 300, 0, nil); err != nil {
		t.Fatalf("upsert dave: %v", err)
	}

	// Refresh alice: new alias and newer last_seen.
	if err := s.UpsertDirectory(keyA, keyA, "alice_prime", 400, 4, nil); err != nil {
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

// TestFreshDatabaseAtSchemaVersion4 verifies that a newly created database is
// born directly at the current schema version (§15.3: no simulated history):
// user_version == SchemaVersion, the envelopes.v column exists, and the
// directory.epoch column of §6.1 and the nullable directory.prekeys column
// of §4.6 exist.
func TestFreshDatabaseAtSchemaVersion4(t *testing.T) {
	s := newTestStore(t)

	if got := userVersion(t, s.db); got != SchemaVersion {
		t.Fatalf("fresh database must carry user_version=%d, got %d", SchemaVersion, got)
	}
	cols := tableColumns(t, s.db, "envelopes")
	if !hasColumn(cols, "v") {
		t.Fatalf("the current schema must include envelopes.v, got columns %v", cols)
	}
	if !hasColumn(tableColumns(t, s.db, "directory"), "epoch") {
		t.Fatalf("the current schema must include directory.epoch (§6.1), got columns %v", tableColumns(t, s.db, "directory"))
	}
	if !hasColumn(tableColumns(t, s.db, "directory"), "prekeys") {
		t.Fatalf("the current schema must include directory.prekeys (§4.6), got columns %v", tableColumns(t, s.db, "directory"))
	}
}

// TestSchemaV2MigratesToV3PreservesDirectory is the §15.3 chain step
// introduced with the §6.1 rotating dest_hint (issue #26): a hand-crafted
// schema-2 database (envelopes.v present, directory without epoch,
// user_version = 2) holding populated directory rows is migrated on open —
// user_version becomes SchemaVersion, directory.epoch appears backfilled to
// 0 (deliberately stale epoch-zero), every pre-existing row survives, and
// the next upsert stamps the entry with a fresh server-set epoch.
func TestSchemaV2MigratesToV3PreservesDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "schema2.db")

	// Build the schema-2 fixture: exactly the version-2 schema (§15.3 table)
	// with populated envelopes AND directory rows, marked user_version = 2.
	v2, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open schema-2 fixture: %v", err)
	}
	defer v2.Close()
	if _, err := v2.Exec(`CREATE TABLE envelopes (
  id TEXT PRIMARY KEY, dest_hint TEXT NOT NULL, created_at INTEGER NOT NULL,
  ttl INTEGER NOT NULL, payload TEXT NOT NULL, v INTEGER NOT NULL DEFAULT 1);
CREATE TABLE directory (
  pubkey TEXT PRIMARY KEY, x25519 TEXT NOT NULL, alias TEXT NOT NULL,
  last_seen INTEGER NOT NULL);
PRAGMA user_version = 2;`); err != nil {
		t.Fatalf("create schema-2 fixture: %v", err)
	}
	if _, err := v2.Exec(
		`INSERT INTO envelopes (id, dest_hint, created_at, ttl, payload, v) VALUES (?, ?, ?, ?, ?, ?)`,
		hexID(7), "9f3ab02c1d77e4c1", 100, 3600, strings.Repeat("A", 332), 2,
	); err != nil {
		t.Fatalf("seed envelope: %v", err)
	}
	keyA := strings.Repeat("A", 44)
	keyB := strings.Repeat("B", 44)
	for _, row := range []struct{ key, alias string }{{keyA, "alice"}, {keyB, "bob"}} {
		if _, err := v2.Exec(
			`INSERT INTO directory (pubkey, x25519, alias, last_seen) VALUES (?, ?, ?, ?)`,
			row.key, row.key, row.alias, 50,
		); err != nil {
			t.Fatalf("seed directory %s: %v", row.alias, err)
		}
	}
	if got := userVersion(t, v2); got != 2 {
		t.Fatalf("fixture must mimic a schema-2 database (user_version=2), got %d", got)
	}
	if err := v2.Close(); err != nil {
		t.Fatalf("close schema-2 fixture: %v", err)
	}

	// Open with the current build: the chain 2→3 must run.
	s, err := Open(path)
	if err != nil {
		t.Fatalf("open migrated store: %v", err)
	}
	defer s.Close()

	if got := userVersion(t, s.db); got != SchemaVersion {
		t.Fatalf("after migration user_version must be %d, got %d", SchemaVersion, got)
	}
	if !hasColumn(tableColumns(t, s.db, "directory"), "epoch") {
		t.Fatalf("migration must add directory.epoch, got columns %v", tableColumns(t, s.db, "directory"))
	}

	// Every pre-existing envelope row survives the migration untouched.
	pulled, err := s.PullEnvelopes(nil, 10, 400)
	if err != nil || len(pulled) != 1 || pulled[0].ID != hexID(7) || pulled[0].V != 2 || pulled[0].Payload != strings.Repeat("A", 332) {
		t.Fatalf("pre-existing envelope must survive migration intact, got %+v err=%v", pulled, err)
	}

	// Directory rows survive; epoch is backfilled to 0 (stale on purpose).
	entries, err := s.GetDirectory(10)
	if err != nil || len(entries) != 2 {
		t.Fatalf("both directory rows must survive the migration, got %+v err=%v", entries, err)
	}
	byKey := make(map[string]DirectoryEntry, len(entries))
	for _, e := range entries {
		byKey[e.Pubkey] = e
	}
	if byKey[keyA].Alias != "alice" || byKey[keyB].Alias != "bob" {
		t.Fatalf("directory rows must keep alias and key, got %+v", entries)
	}
	for _, e := range entries {
		if e.Epoch != 0 {
			t.Fatalf("migrated directory rows must read epoch 0 (DEFAULT backfill), got %+v", e)
		}
	}

	// A fresh upsert stamps the server-set epoch; the other entry stays at
	// the backfilled 0 until its owner re-publishes.
	if err := s.UpsertDirectory(keyA, keyA, "alice", 1791072000, 1791072000/HintEpochSeconds, nil); err != nil {
		t.Fatalf("post-migration upsert: %v", err)
	}
	entries, err = s.GetDirectory(10)
	if err != nil || len(entries) != 2 {
		t.Fatalf("re-read directory: got %+v err=%v", entries, err)
	}
	byKey = make(map[string]DirectoryEntry, len(entries))
	for _, e := range entries {
		byKey[e.Pubkey] = e
	}
	if byKey[keyA].Epoch != 1791072000/HintEpochSeconds || byKey[keyA].LastSeen != 1791072000 {
		t.Fatalf("upsert must stamp last_seen and epoch, got %+v", byKey[keyA])
	}
	if byKey[keyB].Epoch != 0 || byKey[keyB].Alias != "bob" {
		t.Fatalf("untouched entry must keep the backfilled epoch 0, got %+v", byKey[keyB])
	}
}

// TestLegacySchema1MigratesAndPreservesEnvelopes is matrix item §15.7a: a
// hand-crafted schema-1 database (the §9 schema, user_version = 0) holding
// pre-existing envelope rows is migrated on open — user_version becomes
// SchemaVersion, envelopes.v appears, and every pre-existing row stays intact
// and servable with v == 1 and byte-identical payloads (the DEFAULT 1
// backfill is historically correct, §15.3).
func TestLegacySchema1MigratesAndPreservesEnvelopes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")

	// Build the legacy fixture: schema version 1 exactly as old builds left
	// it — populated rows, no marker (user_version = 0, §15.3).
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open legacy fixture: %v", err)
	}
	defer legacy.Close()
	if _, err := legacy.Exec(legacySchema1); err != nil {
		t.Fatalf("create legacy schema: %v", err)
	}
	payloadA := strings.Repeat("A", 332) // 248 bytes; opaque to storage
	payloadB := strings.Repeat("B", 332)
	insertEnv := `INSERT INTO envelopes (id, dest_hint, created_at, ttl, payload) VALUES (?, ?, ?, ?, ?)`
	if _, err := legacy.Exec(insertEnv, hexID(1), "9f3ab02c1d77e4c1", 100, 3600, payloadA); err != nil {
		t.Fatalf("seed envelope 1: %v", err)
	}
	if _, err := legacy.Exec(insertEnv, hexID(2), "9f3ab02c1d77e4c1", 200, 3600, payloadB); err != nil {
		t.Fatalf("seed envelope 2: %v", err)
	}
	if _, err := legacy.Exec(
		`INSERT INTO directory (pubkey, x25519, alias, last_seen) VALUES (?, ?, ?, ?)`,
		strings.Repeat("k", 44), strings.Repeat("x", 44), "alice", 50,
	); err != nil {
		t.Fatalf("seed directory: %v", err)
	}
	if got := userVersion(t, legacy); got != 0 {
		t.Fatalf("fixture must mimic a pre-marker database (user_version=0), got %d", got)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("close legacy fixture: %v", err)
	}

	// Open with the current build: the chain 1→2 must run.
	s, err := Open(path)
	if err != nil {
		t.Fatalf("open migrated store: %v", err)
	}
	defer s.Close()

	if got := userVersion(t, s.db); got != SchemaVersion {
		t.Fatalf("after migration user_version must be %d, got %d", SchemaVersion, got)
	}
	if !hasColumn(tableColumns(t, s.db, "envelopes"), "v") {
		t.Fatalf("migration must add envelopes.v, got columns %v", tableColumns(t, s.db, "envelopes"))
	}

	pulled, err := s.PullEnvelopes(nil, 10, 400)
	if err != nil {
		t.Fatalf("pull migrated rows: %v", err)
	}
	if len(pulled) != 2 {
		t.Fatalf("both pre-existing envelopes must survive migration, got %+v", pulled)
	}
	byID := make(map[string]envelope.Envelope, len(pulled))
	for _, e := range pulled {
		byID[e.ID] = e
	}
	for _, want := range []struct {
		id        string
		createdAt int64
		payload   string
	}{
		{hexID(1), 100, payloadA},
		{hexID(2), 200, payloadB},
	} {
		e, ok := byID[want.id]
		if !ok {
			t.Fatalf("pre-existing envelope %s lost in migration", want.id)
		}
		if e.V != 1 {
			t.Fatalf("pre-existing row must read back as v=1 (DEFAULT backfill, §15.3), got %+v", e)
		}
		if e.Payload != want.payload {
			t.Fatalf("migration must not rewrite payload bytes (§15.3): %s", want.id)
		}
		if e.CreatedAt != want.createdAt || e.TTL != 3600 || e.DestHint != "9f3ab02c1d77e4c1" {
			t.Fatalf("migration must leave core fields untouched, got %+v", e)
		}
		if len(e.Meta) != 0 {
			t.Fatalf("served envelope must never carry meta (§15.3), got %s", e.Meta)
		}
	}

	entries, err := s.GetDirectory(10)
	if err != nil || len(entries) != 1 || entries[0].Alias != "alice" {
		t.Fatalf("migration must leave the directory table intact, got %+v err=%v", entries, err)
	}
}

// TestOpenRefusesNewerSchemaLeavesFileUntouched is matrix item §15.7b: a
// database whose user_version exceeds the binary's SchemaVersion is refused
// with an error naming BOTH versions, and the database file stays
// byte-identical (no write, no schema operation before the refusal, §15.3).
func TestOpenRefusesNewerSchemaLeavesFileUntouched(t *testing.T) {
	for _, dbVersion := range []int{SchemaVersion + 1, SchemaVersion + 5} {
		t.Run("user_version="+strconv.Itoa(dbVersion), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "future.db")
			s, err := Open(path)
			if err != nil {
				t.Fatalf("seed open: %v", err)
			}
			if err := s.Close(); err != nil {
				t.Fatalf("close seeded store: %v", err)
			}

			// Simulate a database written by a newer binary.
			future, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatalf("open future fixture: %v", err)
			}
			if _, err := future.Exec(fmt.Sprintf("PRAGMA user_version = %d", dbVersion)); err != nil {
				t.Fatalf("stamp future user_version: %v", err)
			}
			if err := future.Close(); err != nil {
				t.Fatalf("close future fixture: %v", err)
			}

			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("snapshot database: %v", err)
			}

			refused, err := Open(path)
			if err == nil {
				refused.Close()
				t.Fatalf("open of a schema-%d database by a schema-%d binary must be refused", dbVersion, SchemaVersion)
			}
			if !strings.Contains(err.Error(), strconv.Itoa(dbVersion)) || !strings.Contains(err.Error(), strconv.Itoa(SchemaVersion)) {
				t.Fatalf("refusal must name both versions (database %d, binary %d), got: %v", dbVersion, SchemaVersion, err)
			}

			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("re-read database: %v", err)
			}
			if !bytes.Equal(before, after) {
				t.Fatalf("refused open must leave the database byte-untouched: %d before vs %d after bytes", len(before), len(after))
			}
		})
	}
}

// TestOpenQuarantinesCorruptDatabaseAndRebuilds pins the corrupt-DB
// self-recovery of issue #16 Phase 2: a database that fails to open with an
// SQLite corruption error (garbage bytes → SQLITE_NOTADB; truncated file →
// SQLITE_CORRUPT) is quarantined as <file>.corrupt-<unixts> together with
// its -wal/-shm sidecars, a FRESH database appears at the original path, and
// startup succeeds — at the documented cost of every envelope the corrupt
// file held (accepted data expectation; the .corrupt-* files stay on disk as
// operator-recoverable evidence).
func TestOpenQuarantinesCorruptDatabaseAndRebuilds(t *testing.T) {
	t.Run("garbage bytes", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "node.db")
		if err := os.WriteFile(path, []byte("THIS IS DEFINITELY NOT A SQLITE DATABASE, JUST GARBAGE BYTES ...."), 0o644); err != nil {
			t.Fatalf("write garbage fixture: %v", err)
		}

		s, err := Open(path)
		if err != nil {
			t.Fatalf("open over a garbage file must quarantine and rebuild, got: %v", err)
		}
		defer s.Close()

		// The fresh store works and starts empty.
		if pulled, err := s.PullEnvelopes(nil, 10, 100); err != nil || len(pulled) != 0 {
			t.Fatalf("rebuilt store must start empty, got %+v err=%v", pulled, err)
		}
		if _, err := s.InsertEnvelopes([]envelope.Envelope{makeEnv(hexID(1), 100)}); err != nil {
			t.Fatalf("rebuilt store must accept inserts: %v", err)
		}

		// The corrupt evidence was kept under .corrupt-*. (Sidecar handling
		// is pinned exactly by TestQuarantineCorruptDatabaseMovesSidecars-
		// First below; live SQLite recreates fresh sidecars for the rebuilt
		// store as soon as it is used, so presence of a -wal here is normal.)
		if matches, err := filepath.Glob(path + ".corrupt-*"); err != nil || len(matches) != 1 {
			t.Fatalf("expected exactly one .corrupt-* quarantine of %s, got %v (err=%v)", path, matches, err)
		}
	})

	t.Run("truncated real database", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "node.db")
		s, err := Open(path)
		if err != nil {
			t.Fatalf("seed open: %v", err)
		}
		for i := 0; i < 3; i++ {
			if _, err := s.InsertEnvelopes([]envelope.Envelope{makeEnv(hexID(i), 100)}); err != nil {
				t.Fatalf("seed insert: %v", err)
			}
		}
		if err := s.Close(); err != nil {
			t.Fatalf("close seeded store: %v", err)
		}

		// Half a database file: the header survives, the page data does not —
		// SQLite reports the image as malformed.
		full, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read database: %v", err)
		}
		if err := os.WriteFile(path, full[:len(full)/2], 0o644); err != nil {
			t.Fatalf("truncate database: %v", err)
		}

		rebuilt, err := Open(path)
		if err != nil {
			t.Fatalf("open over a truncated database must quarantine and rebuild, got: %v", err)
		}
		defer rebuilt.Close()

		// Data loss is the documented, accepted outcome.
		if pulled, err := rebuilt.PullEnvelopes(nil, 10, 400); err != nil || len(pulled) != 0 {
			t.Fatalf("rebuilt store must start empty (documented loss), got %+v err=%v", pulled, err)
		}
		matches, _ := filepath.Glob(path + ".corrupt-*")
		if len(matches) != 1 {
			t.Fatalf("expected the truncated predecessor quarantined, got %v", matches)
		}
	})

	t.Run("healthy database is never quarantined", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "node.db")
		s, err := Open(path)
		if err != nil {
			t.Fatalf("open healthy store: %v", err)
		}
		if _, err := s.InsertEnvelopes([]envelope.Envelope{makeEnv(hexID(1), 100)}); err != nil {
			t.Fatalf("insert: %v", err)
		}
		if err := s.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}

		// Reopening the healthy database must not quarantine anything.
		s2, err := Open(path)
		if err != nil {
			t.Fatalf("reopen healthy store: %v", err)
		}
		defer s2.Close()
		if matches, _ := filepath.Glob(path + ".corrupt-*"); len(matches) != 0 {
			t.Fatalf("healthy database must not be quarantined, found %v", matches)
		}
		pulled, err := s2.PullEnvelopes(nil, 10, 400)
		if err != nil || len(pulled) != 1 || pulled[0].ID != hexID(1) {
			t.Fatalf("healthy reopen must keep the data, got %+v err=%v", pulled, err)
		}
	})
}

// TestQuarantineCorruptDatabaseMovesSidecarsFirst exercises the quarantine
// helper directly: database and -wal/-shm sidecars are all renamed to
// <file>.corrupt-<stamp>, and a rename failure aborts with an error (the
// startup-fails-loudly contract for an unwritable directory).
func TestQuarantineCorruptDatabaseMovesSidecarsFirst(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "node.db")
	for _, f := range []string{path, path + "-wal", path + "-shm"} {
		if err := os.WriteFile(f, []byte("corrupt evidence"), 0o644); err != nil {
			t.Fatalf("write fixture %s: %v", f, err)
		}
	}

	quarantined, err := quarantineCorruptDatabase(path, 1700000000)
	if err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	want := []string{
		path + "-wal.corrupt-1700000000",
		path + "-shm.corrupt-1700000000",
		path + ".corrupt-1700000000",
	}
	if len(quarantined) != len(want) {
		t.Fatalf("quarantined %v, want %v", quarantined, want)
	}
	for i, w := range want {
		if quarantined[i] != w {
			t.Fatalf("position %d: got %s, want %s (sidecars must move before the main file)", i, quarantined[i], w)
		}
		if _, err := os.Stat(w); err != nil {
			t.Fatalf("quarantined file missing: %v", err)
		}
		if _, err := os.Stat(strings.TrimSuffix(w, ".corrupt-1700000000")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("original must be gone after quarantine: %v", err)
		}
	}

	// An unwritable directory aborts the quarantine with an error instead of
	// silently continuing (Open then fails startup loudly).
	hostile := t.TempDir()
	hostilePath := filepath.Join(hostile, "broken.db")
	if err := os.WriteFile(hostilePath, []byte("x"), 0o644); err != nil {
		t.Fatalf("write hostile fixture: %v", err)
	}
	if err := os.Chmod(hostile, 0o500); err != nil {
		t.Fatalf("chmod hostile dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(hostile, 0o700) })

	if _, err := quarantineCorruptDatabase(hostilePath, 1700000001); err == nil {
		if os.Geteuid() == 0 {
			t.Skip("running as root: the read-only directory fixture is writable, skipping")
		}
		t.Fatalf("quarantine in an unwritable directory must fail loudly")
	}
}

// TestOpenWarnsOnOversizedWALSidecar pins the disk-exhaustion early warning:
// a -wal sidecar above maxWALWarnBytes logs a stderr warning line but open
// still succeeds, and the wal_autocheckpoint pragma is really engaged at the
// documented default (1000 pages).
func TestOpenWarnsOnOversizedWALSidecar(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("seed open: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close seed store: %v", err)
	}

	// Plant an oversized sidecar and shrink the guard so it trips.
	if err := os.WriteFile(path+"-wal", make([]byte, 64), 0o644); err != nil {
		t.Fatalf("write oversized wal fixture: %v", err)
	}
	oldGuard := maxWALWarnBytes
	maxWALWarnBytes = 16
	t.Cleanup(func() { maxWALWarnBytes = oldGuard })

	var logBuf bytes.Buffer
	oldOut := log.Writer()
	log.SetOutput(&logBuf)
	defer log.SetOutput(oldOut)

	s2, err := Open(path)
	if err != nil {
		t.Fatalf("open with oversized wal must only warn, got: %v", err)
	}
	defer s2.Close()

	logged := logBuf.String()
	if !strings.Contains(logged, "wal") || !strings.Contains(logged, filepath.Base(path)) {
		t.Fatalf("oversized wal must log a warning naming the sidecar, got: %q", logged)
	}

	// The checkpoint pragma is engaged at the documented default.
	var pages int
	if err := s2.db.QueryRow("PRAGMA wal_autocheckpoint").Scan(&pages); err != nil {
		t.Fatalf("read wal_autocheckpoint: %v", err)
	}
	if pages != 1000 {
		t.Fatalf("wal_autocheckpoint must stay at the 1000-page default, got %d", pages)
	}

	// Control: a right-sized sidecar logs nothing.
	logBuf.Reset()
	if err := s2.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := os.WriteFile(path+"-wal", make([]byte, 8), 0o644); err != nil {
		t.Fatalf("write small wal fixture: %v", err)
	}
	s3, err := Open(path)
	if err != nil {
		t.Fatalf("open with small wal: %v", err)
	}
	defer s3.Close()
	if logBuf.String() != "" {
		t.Fatalf("small wal must not warn, got: %q", logBuf.String())
	}
}

// TestInsertPullRoundTripPreservesStoredVersion verifies that envelopes.v is
// the authoritative stored version (§15.3): insert/query round-trips keep the
// inserted v, and envelopes never come back with meta.
func TestInsertPullRoundTripPreservesStoredVersion(t *testing.T) {
	s := newTestStore(t)

	v1 := makeEnv(hexID(1), 100)
	if _, err := s.InsertEnvelopes([]envelope.Envelope{v1}); err != nil {
		t.Fatalf("insert v1: %v", err)
	}

	v2 := makeEnv(hexID(2), 200)
	v2.V = 2
	v2.Meta = json.RawMessage(`{"orig_v":1}`)
	if _, err := s.InsertEnvelopes([]envelope.Envelope{v2}); err != nil {
		t.Fatalf("insert v2: %v", err)
	}

	pulled, err := s.PullEnvelopes(nil, 10, 400)
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	if len(pulled) != 2 {
		t.Fatalf("expected both envelopes back, got %+v", pulled)
	}
	byID := make(map[string]envelope.Envelope, len(pulled))
	for _, e := range pulled {
		byID[e.ID] = e
	}
	if e := byID[hexID(1)]; e.V != 1 {
		t.Fatalf("stored v1 must round-trip as v=1, got %+v", e)
	}
	if e := byID[hexID(2)]; e.V != 2 {
		t.Fatalf("stored v2 must round-trip as v=2 (authoritative column, §15.3), got %+v", e)
	}
	for _, e := range pulled {
		if len(e.Meta) != 0 {
			t.Fatalf("meta is not persisted (§15.3); envelope %s came back with meta %s", e.ID, e.Meta)
		}
	}
}

// TestSchemaV3MigratesToV4PreservesDirectory is the §15.3 chain step
// introduced with the §4.6 prekey bundles (issue #27): a hand-crafted
// schema-3 database (directory with epoch but without prekeys,
// user_version = 3) holding populated directory rows and envelopes is
// migrated on open — user_version becomes SchemaVersion (4), the nullable
// directory.prekeys column appears with every pre-existing row reading NULL
// (bundle-less, §15.3 row 4), every pre-existing row survives untouched, and
// the next upsert stores a bundle verbatim (and a POST-less upsert clears
// it again — the §9 downgrade self-heal).
func TestSchemaV3MigratesToV4PreservesDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "schema3.db")

	// Build the schema-3 fixture: exactly the version-3 schema (§15.3 table)
	// with populated envelopes AND directory rows, marked user_version = 3.
	v3, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open schema-3 fixture: %v", err)
	}
	defer v3.Close()
	if _, err := v3.Exec(`CREATE TABLE envelopes (
  id TEXT PRIMARY KEY, dest_hint TEXT NOT NULL, created_at INTEGER NOT NULL,
  ttl INTEGER NOT NULL, payload TEXT NOT NULL, v INTEGER NOT NULL DEFAULT 1);
CREATE TABLE directory (
  pubkey TEXT PRIMARY KEY, x25519 TEXT NOT NULL, alias TEXT NOT NULL,
  last_seen INTEGER NOT NULL, epoch INTEGER NOT NULL DEFAULT 0);
PRAGMA user_version = 3;`); err != nil {
		t.Fatalf("create schema-3 fixture: %v", err)
	}
	if _, err := v3.Exec(
		`INSERT INTO envelopes (id, dest_hint, created_at, ttl, payload, v) VALUES (?, ?, ?, ?, ?, ?)`,
		hexID(11), "9f3ab02c1d77e4c1", 100, 3600, strings.Repeat("B", 332), 2,
	); err != nil {
		t.Fatalf("seed envelope: %v", err)
	}
	keyA := strings.Repeat("C", 44)
	keyB := strings.Repeat("D", 44)
	for _, row := range []struct {
		key, alias string
		epoch      int64
	}{{keyA, "alice", 20730}, {keyB, "bob", 0}} {
		if _, err := v3.Exec(
			`INSERT INTO directory (pubkey, x25519, alias, last_seen, epoch) VALUES (?, ?, ?, ?, ?)`,
			row.key, row.key, row.alias, 50, row.epoch,
		); err != nil {
			t.Fatalf("seed directory %s: %v", row.alias, err)
		}
	}
	if got := userVersion(t, v3); got != 3 {
		t.Fatalf("fixture must mimic a schema-3 database (user_version=3), got %d", got)
	}
	if err := v3.Close(); err != nil {
		t.Fatalf("close schema-3 fixture: %v", err)
	}

	// Open with the current build: the chain 3→4 must run.
	s, err := Open(path)
	if err != nil {
		t.Fatalf("open migrated store: %v", err)
	}
	defer s.Close()

	if got := userVersion(t, s.db); got != SchemaVersion {
		t.Fatalf("after migration user_version must be %d, got %d", SchemaVersion, got)
	}
	if !hasColumn(tableColumns(t, s.db, "directory"), "prekeys") {
		t.Fatalf("migration must add directory.prekeys, got columns %v", tableColumns(t, s.db, "directory"))
	}

	// Every pre-existing envelope row survives the migration untouched.
	pulled, err := s.PullEnvelopes(nil, 10, 400)
	if err != nil || len(pulled) != 1 || pulled[0].ID != hexID(11) || pulled[0].V != 2 || pulled[0].Payload != strings.Repeat("B", 332) {
		t.Fatalf("pre-existing envelope must survive migration intact, got %+v err=%v", pulled, err)
	}

	// Directory rows survive; prekeys is NULL (bundle-less) on every row.
	entries, err := s.GetDirectory(10)
	if err != nil || len(entries) != 2 {
		t.Fatalf("both directory rows must survive the migration, got %+v err=%v", entries, err)
	}
	byKey := make(map[string]DirectoryEntry, len(entries))
	for _, e := range entries {
		byKey[e.Pubkey] = e
	}
	if byKey[keyA].Alias != "alice" || byKey[keyA].Epoch != 20730 {
		t.Fatalf("directory rows must keep alias and epoch, got %+v", entries)
	}
	if byKey[keyB].Epoch != 0 {
		t.Fatalf("the stale entry must keep epoch 0, got %+v", byKey[keyB])
	}
	for _, e := range entries {
		if e.Prekeys != nil {
			t.Fatalf("migrated directory rows must read prekeys NULL (bundle-less), got %s", string(e.Prekeys))
		}
	}

	// The next upsert stores the bundle VERBATIM (§4.6: the node never
	// verifies the signature and never mutates the member).
	bundle := []byte(`{"v":1,"spk":"` + keyA + `","spk_sig":"` + strings.Repeat("s", 88) + `","ts":1791072000,"opks":["` + keyA + `","` + keyB + `"]}`)
	if err := s.UpsertDirectory(keyA, keyA, "alice", 1791072000, 1791072000/HintEpochSeconds, bundle); err != nil {
		t.Fatalf("post-migration upsert with bundle: %v", err)
	}
	entries, err = s.GetDirectory(10)
	if err != nil || len(entries) != 2 {
		t.Fatalf("re-read directory: got %+v err=%v", entries, err)
	}
	byKey = make(map[string]DirectoryEntry, len(entries))
	for _, e := range entries {
		byKey[e.Pubkey] = e
	}
	if string(byKey[keyA].Prekeys) != string(bundle) {
		t.Fatalf("bundle must round-trip verbatim, got %s want %s", string(byKey[keyA].Prekeys), string(bundle))
	}
	// The other entry stays bundle-less until its owner publishes.
	if byKey[keyB].Prekeys != nil {
		t.Fatalf("untouched entry must stay bundle-less, got %s", string(byKey[keyB].Prekeys))
	}

	// A POST without the member clears the stored bundle (§9 downgrade
	// self-heal) while keeping the rest of the row.
	if err := s.UpsertDirectory(keyA, keyA, "alice", 1791072100, 1791072100/HintEpochSeconds, nil); err != nil {
		t.Fatalf("clearing upsert: %v", err)
	}
	entries, err = s.GetDirectory(10)
	if err != nil || len(entries) != 2 {
		t.Fatalf("re-read directory after clear: got %+v err=%v", entries, err)
	}
	for _, e := range entries {
		if e.Pubkey == keyA && e.Prekeys != nil {
			t.Fatalf("bundle-less upsert must clear prekeys, got %s", string(e.Prekeys))
		}
	}
}
