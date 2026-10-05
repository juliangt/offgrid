// Package storage implements the node's SQLite dead-drop persistence layer
// per docs/protocol.md §9: two tables (envelopes, directory), WAL journaling,
// a busy timeout, and a single serialized connection. Storage schema
// versioning follows §15.3: an explicit PRAGMA user_version marker, a
// forward-only transactional migration chain, and refusal to open databases
// written by newer binaries.
//
// The store is deliberately dumb and blind: envelopes are opaque rows keyed by
// a client-computed id, deduplicated with INSERT OR IGNORE, served by a
// TTL-aware NOT IN select, and reaped by DeleteExpired. No cryptography ever
// happens here.
package storage

import (
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"offgrid/dtn-node/internal/envelope"

	"modernc.org/sqlite" // pure-Go SQLite driver (no CGO), registered as "sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// SchemaVersion is the storage schema version this build creates and
// understands (§15.3). Version 1 is the §9 schema as originally deployed;
// old builds left those databases unmarked (user_version = 0), which §15.3
// defines as schema version 1. Version 2 adds the envelopes.v column, the
// authoritative stored version of each envelope. Version 3 adds the
// directory.epoch column (§6.1, issue #26): the server-set hint epoch —
// floor(now / HintEpochSeconds) at upsert — the node publishes so senders
// derive rotating dest_hints from NODE time, never their own clocks.
const SchemaVersion = 3

// HintEpochSeconds is the §6.1 epoch length: a 24-hour UTC epoch. The
// directory's epoch column and the capabilities document's
// hint_epoch_seconds/hint_epoch_current members both derive from this one
// constant — the node clock is the shared reference for the rotating
// dest_hint derivation (§6.1), and the node NEVER validates hint-vs-key
// relationships (it cannot: it does not know which epoch a hint was
// derived under — blindness preserved, §13).
const HintEpochSeconds = 86400

// schemaV3 is the complete schema of storage version 3 (§9 as amended by
// §15.3 and §6.1): the §9 tables plus envelopes.v plus directory.epoch. It
// is applied in one transaction to fresh databases only — existing
// databases reach version 3 exclusively through the migration chain, and a
// database already marked version 3 is trusted as-is (the marker is
// authoritative, §15.3).
const schemaV3 = `
CREATE TABLE IF NOT EXISTS envelopes (
  id         TEXT PRIMARY KEY,      -- envelope id, 64 lowercase hex chars (client-computed)
  dest_hint  TEXT NOT NULL,         -- 16 lowercase hex chars
  created_at INTEGER NOT NULL,     -- unix seconds
  ttl        INTEGER NOT NULL,      -- seconds
  payload    TEXT NOT NULL,         -- Base64( eph_pub || nonce || box )
  v          INTEGER NOT NULL DEFAULT 1 -- stored envelope format version (§15.3)
);
CREATE INDEX IF NOT EXISTS idx_envelopes_dest_hint ON envelopes(dest_hint);
CREATE INDEX IF NOT EXISTS idx_envelopes_expiry    ON envelopes(created_at, ttl);

CREATE TABLE IF NOT EXISTS directory (
  pubkey    TEXT PRIMARY KEY,      -- ed25519 public key, Base64 (identity)
  x25519    TEXT NOT NULL,         -- X25519 public key, Base64 (encryption)
  alias     TEXT NOT NULL,
  last_seen INTEGER NOT NULL,      -- unix seconds, set by the node on upsert
  epoch     INTEGER NOT NULL DEFAULT 0 -- server-set hint epoch, floor(last_seen / 86400) (§6.1)
);
`

// migrations is the forward-only migration chain of §15.3: migrations[from]
// holds the statements upgrading a database at schema version `from` to
// `from+1`. Each step — DDL and the user_version bump — runs inside a single
// transaction, so a crash mid-chain leaves a consistent prefix of the chain
// and the next open resumes from user_version. Migrations never rewrite or
// re-encode stored envelope payload bytes (§15.3); the DEFAULT 1 backfill of
// migration 1→2 is historically correct (every pre-existing row predates v2),
// and the DEFAULT 0 backfill of 2→3 is epoch-0 (1970) — deliberately stale:
// senders reading such an entry fall back to the legacy static hint (§6.1)
// until the entry is refreshed by an upsert.
var migrations = map[int][]string{
	1: {`ALTER TABLE envelopes ADD COLUMN v INTEGER NOT NULL DEFAULT 1`},
	2: {`ALTER TABLE directory ADD COLUMN epoch INTEGER NOT NULL DEFAULT 0`},
}

// knownIDChunkSize bounds how many known_ids placeholders go into a single
// `id NOT IN (...)` clause. Chunking keeps us far below any SQLite
// host-parameter limit (conservatively 999) even though the API layer caps
// known_ids at 500 entries.
const knownIDChunkSize = 900

// maxEnvelopes is the per-node hard cap on stored envelopes (5000): the open
// access point accepts anonymous pushes, so without a ceiling the node could
// be filled by abuse (plan §7 risk "Llenado del nodo por abuso"; normative
// row in docs/protocol.md §8.1). At or over the cap, InsertEnvelopes rejects
// the whole batch with ErrCapacity (fail closed, §10.4) and the API maps that
// to 429 node_full.
//
// The eviction POLICY is "reject newest, keep oldest", on purpose (issue #16
// Phase 2): nothing that has been accepted is ever deleted outside the TTL
// janitor (DeleteExpired, §10.6) — there is no LRU, no overwriting, no
// shedding of stored mail. When the store is full, the NEWEST writers get
// 429 node_full; the oldest legitimate mail stays servable until it expires
// naturally. Under a flood this means the flood's fresh junk is refused
// while the pre-existing mailbox keeps working.
//
// It is a var instead of a const purely as a test hook: tests lower it to
// exercise the guard without inserting 5000 rows. Production code must never
// reassign it.
var maxEnvelopes = 5000

// ErrCapacity is returned by InsertEnvelopes when the node is at or over its
// envelope capacity (maxEnvelopes). Callers should surface it as HTTP 429.
var ErrCapacity = errors.New("storage: envelope capacity reached")

// DirectoryEntry is one registered identity in the node's public directory,
// served as JSON by GET /api/v1/directory with exactly these field names
// (§10.3). Epoch is the server-set §6.1 hint epoch of the upsert that last
// touched the entry: senders derive the rotating dest_hint from it (never
// from their own clock), so sender and node share one time reference.
type DirectoryEntry struct {
	Alias    string `json:"alias"`
	Pubkey   string `json:"pubkey"`
	X25519   string `json:"x25519"`
	LastSeen int64  `json:"last_seen"`
	Epoch    int64  `json:"epoch"`
}

// Store wraps the SQLite database. All access is serialized through a single
// connection (SetMaxOpenConns(1)): it removes write contention entirely, which
// is the right trade-off for the trivial load of a Pi Zero 2 W node (§9).
// path is retained so DBSizeBytes can report the on-disk footprint of the
// database and its sidecars (health snapshot, issue #31).
type Store struct {
	db   *sql.DB
	path string
}

// Open creates or opens the database at path with the binding pragmas of §9
// (journal_mode=WAL, busy_timeout=5000) applied on the DSN so every
// connection gets them, plus an explicit wal_autocheckpoint (see the DSN
// comment below), and enforces the single-connection policy.
//
// Schema versioning per §15.3: user_version is read before ANY other
// statement — no write, no schema operation — so a database written by a
// newer binary is refused while leaving the file byte-untouched (the defined
// rollback behavior; read-only mode is explicitly not implemented). A database
// older than SchemaVersion is migrated forward through the migration chain.
//
// # Corrupt-database self-recovery (issue #16 Phase 2, Track 2)
//
// A solar-powered node on an SD card WILL eventually suffer a corrupt
// database (power loss mid-write, flash wear) and MUST come back on its own
// — no manual SSH is available. If open or schema application fails with an
// SQLite corruption error, the daemon QUARANTINES the database: the file and
// its -wal/-shm sidecars are renamed to <file>.corrupt-<unixts>, a fresh
// database is created at the original path, and startup CONTINUES.
//
// This LOSES every envelope stored in the quarantined file — that loss is
// the accepted data expectation for this failure mode (blind relay of
// best-effort mail; the failure-mode matrix pins it in a later phase). The
// .corrupt-* files are operator-recoverable evidence, kept on disk for
// post-mortem inspection (the runbook delivered in a later phase covers
// examining and discarding them). If even the quarantine rename fails —
// e.g. an unwritable directory — startup fails loudly instead of looping.
func Open(path string) (*Store, error) {
	s, err := open(path)
	if err == nil {
		return s, nil
	}
	if !isSQLiteCorruption(err) {
		return nil, err
	}

	stamp := time.Now().Unix()
	quarantined, qerr := quarantineCorruptDatabase(path, stamp)
	if qerr != nil {
		return nil, fmt.Errorf("storage: %s: database is corrupt (%v) and quarantining it failed: %w; refusing to start over an unremovable corrupt database", path, err, qerr)
	}
	log.Printf("[storage] database at %s is corrupt (%v); quarantined as %s — every envelope stored in it is LOST (accepted by design); the .corrupt-* files are kept as operator-recoverable evidence (runbook, later phase)",
		path, err, strings.Join(quarantined, ", "))

	s, err = open(path)
	if err != nil {
		return nil, err
	}
	log.Printf("[storage] created a fresh database at %s and continuing startup (corrupt predecessor quarantined)", path)
	return s, nil
}

// open is the plain open path: create/connect, apply the §15.3 versioning
// rules, verify WAL engagement. It is what Open wraps with the corruption
// quarantine.
func open(path string) (*Store, error) {
	// wal_autocheckpoint keeps the SQLite default (1000 pages ≈ 4 MiB at the
	// 4 KiB page size): on a Pi Zero 2 W-class workload this checkpoints the
	// WAL long before it can grow meaningfully, bounding the sidecar under
	// sustained write floods without tuning a storage engine we do not need
	// to tune. Under a push flood the checkpoint cadence means writers stall
	// briefly every ~4 MiB of WAL — acceptable, and the WAL never becomes an
	// unbounded disk-exhaustion vector by itself.
	dsn := fmt.Sprintf(
		"file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=wal_autocheckpoint(1000)",
		path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("storage: open %s: %w", path, err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	stored, err := readSchemaVersion(db)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("storage: %s: %w", path, err)
	}
	if stored > SchemaVersion {
		// Downgrade / rollback contract (§15.3): refuse to open a database
		// written by a newer binary, naming both versions, and touch nothing.
		db.Close()
		return nil, fmt.Errorf(
			"storage: %s: refusing to open: database schema version is %d but this binary supports at most schema version %d; run the newer binary that wrote this database (downgrades are unsupported and no migration was attempted)",
			path, stored, SchemaVersion)
	}
	if err := upgrade(db, stored); err != nil {
		db.Close()
		return nil, fmt.Errorf("storage: %s: %w", path, err)
	}

	// Fail fast if WAL was not actually engaged (e.g. unsupported filesystem).
	var mode string
	if err := db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		db.Close()
		return nil, fmt.Errorf("storage: check journal_mode: %w", err)
	}
	if !strings.EqualFold(mode, "wal") {
		db.Close()
		return nil, fmt.Errorf("storage: journal_mode is %q, want wal", mode)
	}

	// Disk-exhaustion early warning (issue #16 Phase 2): a -wal sidecar that
	// outgrew maxWALWarnBytes means the checkpoint is not keeping up or the
	// volume is nearly full. Enforcement stays with wal_autocheckpoint — this
	// is a visible stderr line for the operator/runbook, not a gate.
	if info, err := os.Stat(path + "-wal"); err == nil && info.Size() > maxWALWarnBytes {
		log.Printf("[storage] warning: WAL sidecar %s-wal holds %d bytes, over the %d-byte disk-exhaustion guard; wal_autocheckpoint normally keeps it at a few MiB — check disk pressure on the node",
			path, info.Size(), maxWALWarnBytes)
	}
	return &Store{db: db, path: path}, nil
}

// maxWALWarnBytes is the WAL sidecar size over which open() logs a warning
// (64 MiB — far above what wal_autocheckpoint allows in normal operation,
// far below the free space a corrupted run would need to eat on a small SD
// partition before anything else notices). Var purely as a test hook;
// production code must never reassign it.
var maxWALWarnBytes int64 = 64 << 20

// isSQLiteCorruption reports whether err is an SQLite corruption failure:
// SQLITE_CORRUPT ("database disk image is malformed", e.g. a truncated or
// bit-rotted file), SQLITE_NOTADB ("file is not a database", e.g. garbage
// bytes where the header should be), or any wrapped error whose text names
// corruption. The typed check inspects modernc.org/sqlite's *sqlite.Error
// code; the string match is the documented fallback for driver layers that
// re-wrap the failure.
func isSQLiteCorruption(err error) bool {
	if err == nil {
		return false
	}
	var sqlErr *sqlite.Error
	if errors.As(err, &sqlErr) {
		switch sqlErr.Code() {
		case sqlite3.SQLITE_CORRUPT, sqlite3.SQLITE_NOTADB:
			return true
		}
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "malformed") ||
		strings.Contains(msg, "corrupt") ||
		strings.Contains(msg, "not a database")
}

// quarantineCorruptDatabase renames the corrupt database and its -wal/-shm
// sidecars to <file>.corrupt-<stamp>, returning the new paths. The sidecars
// are moved FIRST: a stale -wal beside a freshly created database would let
// SQLite replay the old (corrupt) frames into the new file, so an aborted
// quarantine must leave the main file in place. A failed rename (unwritable
// directory, cross-device mishap) aborts the recovery: Open fails startup
// loudly rather than silently looping on a database it cannot replace.
func quarantineCorruptDatabase(path string, stamp int64) ([]string, error) {
	var quarantined []string
	for _, f := range []string{path + "-wal", path + "-shm", path} {
		if _, err := os.Stat(f); err != nil {
			continue // sidecar not present: nothing to quarantine
		}
		dst := fmt.Sprintf("%s.corrupt-%d", f, stamp)
		if err := os.Rename(f, dst); err != nil {
			return quarantined, fmt.Errorf("rename %s to %s: %w", f, dst, err)
		}
		quarantined = append(quarantined, dst)
	}
	return quarantined, nil
}

// readSchemaVersion reads PRAGMA user_version — a pure read with no write and
// no schema operation, run before anything else so the §15.3 downgrade
// refusal can guarantee a byte-untouched database file.
func readSchemaVersion(db *sql.DB) (int, error) {
	var v int
	if err := db.QueryRow("PRAGMA user_version").Scan(&v); err != nil {
		return 0, fmt.Errorf("read user_version: %w", err)
	}
	return v, nil
}

// upgrade brings a database at schema version `stored` up to SchemaVersion by
// running the forward-only chain of §15.3 sequentially, one transaction per
// step. Fresh databases (no envelopes table yet — an empty file reads
// user_version 0 just like the legacy schema-1 databases) are created
// directly at SchemaVersion, without simulating the historical versions.
func upgrade(db *sql.DB, stored int) error {
	if stored == SchemaVersion {
		return nil // the marker is authoritative (§15.3): nothing to do
	}
	fresh, err := tableExists(db, "envelopes")
	if err != nil {
		return err
	}
	if !fresh {
		return createSchemaV3(db)
	}
	from := stored
	if from == 0 {
		from = 1 // pre-marker databases are schema version 1 (§15.3)
	}
	for v := from; v < SchemaVersion; v++ {
		if err := migrateStep(db, v); err != nil {
			return err
		}
	}
	return nil
}

// createSchemaV3 creates the full current schema (version 3) and sets the
// user_version marker inside a single transaction, so a crash mid-creation
// leaves either an empty (fresh) database or a complete, correctly marked one.
func createSchemaV3(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin create schema: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(schemaV3); err != nil {
		return fmt.Errorf("apply schema: %w", err)
	}
	if err := setUserVersion(tx, SchemaVersion); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit create schema: %w", err)
	}
	return nil
}

// migrateStep applies one link of the migration chain: schema version `from`
// to `from+1`, with the user_version bump in the same transaction (crash-safe
// resumption from user_version, §15.3).
func migrateStep(db *sql.DB, from int) error {
	stmts, ok := migrations[from]
	if !ok {
		return fmt.Errorf("no migration from schema version %d to %d", from, from+1)
	}
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin migration %d->%d: %w", from, from+1, err)
	}
	defer tx.Rollback()
	for _, stmt := range stmts {
		if _, err := tx.Exec(stmt); err != nil {
			return fmt.Errorf("migration %d->%d: %w", from, from+1, err)
		}
	}
	if err := setUserVersion(tx, from+1); err != nil {
		return fmt.Errorf("migration %d->%d: %w", from, from+1, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration %d->%d: %w", from, from+1, err)
	}
	return nil
}

// setUserVersion stamps the schema version marker inside the current
// transaction (user_version lives in the database header and is
// transactional, so DDL and marker move atomically).
func setUserVersion(tx *sql.Tx, version int) error {
	if _, err := tx.Exec("PRAGMA user_version = " + strconv.Itoa(version)); err != nil {
		return fmt.Errorf("set user_version = %d: %w", version, err)
	}
	return nil
}

// tableExists reports whether the named table exists — the discriminator
// between a fresh database and a populated legacy one: both read
// user_version 0, so the schema (not the marker) tells them apart.
func tableExists(db *sql.DB, name string) (bool, error) {
	var n int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, name,
	).Scan(&n); err != nil {
		return false, fmt.Errorf("inspect schema: %w", err)
	}
	return n > 0, nil
}

// Close releases the database handle.
func (s *Store) Close() error {
	return s.db.Close()
}

// MaxEnvelopes reports the per-node envelope cap (§8.1, 5000). It is an
// exported accessor so the health snapshot (issue #31) can advertise
// envelope_capacity from the same source the admission guard enforces,
// instead of copying the constant.
func MaxEnvelopes() int {
	return maxEnvelopes
}

// EnvelopeCount returns the number of envelopes currently stored (§9). The
// health snapshot serves it as the "envelopes" aggregate; it never inspects
// or returns any row content.
func (s *Store) EnvelopeCount() (int64, error) {
	var n int64
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM envelopes`).Scan(&n); err != nil {
		return 0, fmt.Errorf("storage: count envelopes: %w", err)
	}
	return n, nil
}

// DirectoryCount returns the number of directory entries (§9). Served by the
// health snapshot as the "directory_entries" aggregate.
func (s *Store) DirectoryCount() (int64, error) {
	var n int64
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM directory`).Scan(&n); err != nil {
		return 0, fmt.Errorf("storage: count directory: %w", err)
	}
	return n, nil
}

// DBSizeBytes returns the database's size on disk: the main file plus its
// -wal and -shm sidecars, so a stale or growing WAL is visible to the
// operator (a full-card symptom, docs/hardening.md §3). Sidecars that do not
// currently exist contribute zero; any other stat error surfaces.
func (s *Store) DBSizeBytes() (int64, error) {
	var total int64
	for _, p := range []string{s.path, s.path + "-wal", s.path + "-shm"} {
		info, err := os.Stat(p)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return 0, fmt.Errorf("storage: stat %s: %w", p, err)
		}
		total += info.Size()
	}
	return total, nil
}

// InsertEnvelopes inserts every envelope in one transaction using
// INSERT OR IGNORE: rows whose id already exists are silently skipped. This
// is the global deduplication mechanism across nodes (§10.4 step 2). It
// returns the number of newly inserted rows. Dedup is by id alone and
// therefore version-agnostic (§15.1): re-pushing a converted envelope (same
// id, different v) is absorbed.
//
// Each row stores the envelope's validated version v in the envelopes.v
// column — the authoritative stored version (§15.3). Meta (§15.1) is
// admission-time container metadata and is NOT persisted: the schema defines
// no column for it (§15.3).
//
// Before inserting, it counts the table and rejects the WHOLE batch with
// ErrCapacity when the store is already at or over maxEnvelopes (fail closed,
// §10.4 step 1). A batch accepted just below the cap may overshoot it by at
// most one request's worth of envelopes (≤ 100, the §8.1 push limit).
func (s *Store) InsertEnvelopes(envs []envelope.Envelope) (int, error) {
	if len(envs) == 0 {
		return 0, nil
	}
	var current int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM envelopes`).Scan(&current); err != nil {
		return 0, fmt.Errorf("storage: count envelopes: %w", err)
	}
	if current >= maxEnvelopes {
		return 0, ErrCapacity
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("storage: begin insert: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO envelopes (id, dest_hint, created_at, ttl, payload, v) VALUES (?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return 0, fmt.Errorf("storage: prepare insert: %w", err)
	}
	defer stmt.Close()

	inserted := 0
	for _, e := range envs {
		res, err := stmt.Exec(e.ID, e.DestHint, e.CreatedAt, e.TTL, e.Payload, e.V)
		if err != nil {
			return 0, fmt.Errorf("storage: insert envelope %s: %w", e.ID, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return 0, fmt.Errorf("storage: rows affected for %s: %w", e.ID, err)
		}
		inserted += int(n)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("storage: commit insert: %w", err)
	}
	return inserted, nil
}

// PullEnvelopes selects up to limit envelopes that are still valid at time now
// (created_at + ttl >= now, inclusive serving boundary, §10.4) and whose ids
// are NOT among knownIDs (the mule's inbox ∪ transit ∪ already-seen set).
// Results are ordered created_at DESC with id ASC as the deterministic
// tie-break. knownIDs are chunked into multiple NOT IN clauses to stay below
// SQLite's host-parameter limits.
//
// Schema-version-2 builds select envelopes.v (§15.3): every returned envelope
// carries its stored version and never meta (§15.3 — meta is admission-time
// metadata and is not persisted, so served envelopes cannot carry it and
// clients MUST NOT rely on it surviving a node round-trip).
func (s *Store) PullEnvelopes(knownIDs []string, limit int, now int64) ([]envelope.Envelope, error) {
	var clauses []string
	args := []any{now}
	for start := 0; start < len(knownIDs); start += knownIDChunkSize {
		end := start + knownIDChunkSize
		if end > len(knownIDs) {
			end = len(knownIDs)
		}
		clauses = append(clauses, fmt.Sprintf("id NOT IN (%s)", placeholders(end-start)))
		for _, id := range knownIDs[start:end] {
			args = append(args, id)
		}
	}
	where := "created_at + ttl >= ?"
	if len(clauses) > 0 {
		where += " AND " + strings.Join(clauses, " AND ")
	}
	args = append(args, limit)

	query := fmt.Sprintf(
		`SELECT id, dest_hint, created_at, ttl, payload, v FROM envelopes WHERE %s ORDER BY created_at DESC, id ASC LIMIT ?`,
		where,
	)
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("storage: pull envelopes: %w", err)
	}
	defer rows.Close()

	result := make([]envelope.Envelope, 0, limit)
	for rows.Next() {
		var e envelope.Envelope
		if err := rows.Scan(&e.ID, &e.DestHint, &e.CreatedAt, &e.TTL, &e.Payload, &e.V); err != nil {
			return nil, fmt.Errorf("storage: scan envelope: %w", err)
		}
		// e.V comes from the envelopes.v column, the authoritative stored
		// version (§15.3). Meta is left at its zero value: it is never
		// persisted, and a nil json.RawMessage is omitted when the envelope
		// is marshaled for the pull response.
		result = append(result, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: iterate envelopes: %w", err)
	}
	return result, nil
}

// placeholders renders n comma-separated '?' markers.
func placeholders(n int) string {
	if n <= 0 {
		return "NULL" // NOT IN (NULL) is never true, matching an empty exclusion set
	}
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

// UpsertDirectory inserts or refreshes a directory entry keyed by the
// Ed25519 public key, setting last_seen and the §6.1 hint epoch to the
// values supplied by the node (§10.3: last_seen = now on every upsert;
// §6.1: epoch = floor(now / HintEpochSeconds) — the server clock, never a
// client-supplied value). The POST body shape is unchanged: clients cannot
// influence the epoch, only observe it.
func (s *Store) UpsertDirectory(pubkey, x25519, alias string, lastSeen int64, epoch int64) error {
	_, err := s.db.Exec(
		`INSERT INTO directory (pubkey, x25519, alias, last_seen, epoch) VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(pubkey) DO UPDATE SET x25519 = excluded.x25519, alias = excluded.alias, last_seen = excluded.last_seen, epoch = excluded.epoch`,
		pubkey, x25519, alias, lastSeen, epoch,
	)
	if err != nil {
		return fmt.Errorf("storage: upsert directory %s: %w", pubkey, err)
	}
	return nil
}

// GetDirectory returns up to limit entries ordered by last_seen DESC with
// pubkey ASC as the deterministic tie-break (§10.3). The 500-entry cap is
// applied by the caller through limit; directory rows are never auto-deleted
// in Phase 1. Schema-version-3 builds select directory.epoch (§6.1): every
// entry carries the server-set hint epoch senders derive the rotating
// dest_hint from.
func (s *Store) GetDirectory(limit int) ([]DirectoryEntry, error) {
	rows, err := s.db.Query(
		`SELECT pubkey, x25519, alias, last_seen, epoch FROM directory ORDER BY last_seen DESC, pubkey ASC LIMIT ?`,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("storage: get directory: %w", err)
	}
	defer rows.Close()

	entries := make([]DirectoryEntry, 0, limit)
	for rows.Next() {
		var d DirectoryEntry
		if err := rows.Scan(&d.Pubkey, &d.X25519, &d.Alias, &d.LastSeen, &d.Epoch); err != nil {
			return nil, fmt.Errorf("storage: scan directory: %w", err)
		}
		entries = append(entries, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: iterate directory: %w", err)
	}
	return entries, nil
}

// DeleteExpired removes envelopes whose validity window has fully elapsed
// (created_at + ttl < now, exclusive cleanup boundary, §10.6) and returns the
// number of rows deleted. Combined with the inclusive serving boundary of
// PullEnvelopes, an envelope is always either servable or deleted — never in
// limbo.
func (s *Store) DeleteExpired(now int64) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM envelopes WHERE created_at + ttl < ?`, now)
	if err != nil {
		return 0, fmt.Errorf("storage: delete expired: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("storage: deleted rows affected: %w", err)
	}
	return n, nil
}
