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
	"strconv"
	"strings"

	"offgrid/dtn-node/internal/envelope"

	_ "modernc.org/sqlite" // pure-Go SQLite driver (no CGO), registered as "sqlite"
)

// SchemaVersion is the storage schema version this build creates and
// understands (§15.3). Version 1 is the §9 schema as originally deployed;
// old builds left those databases unmarked (user_version = 0), which §15.3
// defines as schema version 1. Version 2 adds the envelopes.v column, the
// authoritative stored version of each envelope.
const SchemaVersion = 2

// schemaV2 is the complete schema of storage version 2 (§9 as amended by
// §15.3): the §9 tables plus envelopes.v. It is applied in one transaction to
// fresh databases only — existing databases reach version 2 exclusively
// through the migration chain, and a database already marked version 2 is
// trusted as-is (the marker is authoritative, §15.3).
const schemaV2 = `
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
  last_seen INTEGER NOT NULL       -- unix seconds, set by the node on upsert
);
`

// migrations is the forward-only migration chain of §15.3: migrations[from]
// holds the statements upgrading a database at schema version `from` to
// `from+1`. Each step — DDL and the user_version bump — runs inside a single
// transaction, so a crash mid-chain leaves a consistent prefix of the chain
// and the next open resumes from user_version. Migrations never rewrite or
// re-encode stored envelope payload bytes (§15.3); the DEFAULT 1 backfill of
// migration 1→2 is historically correct (every pre-existing row predates v2).
var migrations = map[int][]string{
	1: {`ALTER TABLE envelopes ADD COLUMN v INTEGER NOT NULL DEFAULT 1`},
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
// It is a var instead of a const purely as a test hook: tests lower it to
// exercise the guard without inserting 5000 rows. Production code must never
// reassign it.
var maxEnvelopes = 5000

// ErrCapacity is returned by InsertEnvelopes when the node is at or over its
// envelope capacity (maxEnvelopes). Callers should surface it as HTTP 429.
var ErrCapacity = errors.New("storage: envelope capacity reached")

// DirectoryEntry is one registered identity in the node's public directory,
// served as JSON by GET /api/v1/directory with exactly these field names
// (§10.3).
type DirectoryEntry struct {
	Alias    string `json:"alias"`
	Pubkey   string `json:"pubkey"`
	X25519   string `json:"x25519"`
	LastSeen int64  `json:"last_seen"`
}

// Store wraps the SQLite database. All access is serialized through a single
// connection (SetMaxOpenConns(1)): it removes write contention entirely, which
// is the right trade-off for the trivial load of a Pi Zero 2 W node (§9).
type Store struct {
	db *sql.DB
}

// Open creates or opens the database at path with the binding pragmas of §9
// (journal_mode=WAL, busy_timeout=5000) applied on the DSN so every
// connection gets them, and enforces the single-connection policy.
//
// Schema versioning per §15.3: user_version is read before ANY other
// statement — no write, no schema operation — so a database written by a
// newer binary is refused while leaving the file byte-untouched (the defined
// rollback behavior; read-only mode is explicitly not implemented). A database
// older than SchemaVersion is migrated forward through the migration chain.
func Open(path string) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)", path)
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
	return &Store{db: db}, nil
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
		return createSchemaV2(db)
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

// createSchemaV2 creates the full version-2 schema and sets the user_version
// marker inside a single transaction, so a crash mid-creation leaves either
// an empty (fresh) database or a complete, correctly marked one.
func createSchemaV2(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin create schema: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(schemaV2); err != nil {
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
// Ed25519 public key, setting last_seen to the value supplied by the node
// (§10.3: last_seen = now on every upsert).
func (s *Store) UpsertDirectory(pubkey, x25519, alias string, lastSeen int64) error {
	_, err := s.db.Exec(
		`INSERT INTO directory (pubkey, x25519, alias, last_seen) VALUES (?, ?, ?, ?)
		 ON CONFLICT(pubkey) DO UPDATE SET x25519 = excluded.x25519, alias = excluded.alias, last_seen = excluded.last_seen`,
		pubkey, x25519, alias, lastSeen,
	)
	if err != nil {
		return fmt.Errorf("storage: upsert directory %s: %w", pubkey, err)
	}
	return nil
}

// GetDirectory returns up to limit entries ordered by last_seen DESC with
// pubkey ASC as the deterministic tie-break (§10.3). The 500-entry cap is
// applied by the caller through limit; directory rows are never auto-deleted
// in Phase 1.
func (s *Store) GetDirectory(limit int) ([]DirectoryEntry, error) {
	rows, err := s.db.Query(
		`SELECT pubkey, x25519, alias, last_seen FROM directory ORDER BY last_seen DESC, pubkey ASC LIMIT ?`,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("storage: get directory: %w", err)
	}
	defer rows.Close()

	entries := make([]DirectoryEntry, 0, limit)
	for rows.Next() {
		var d DirectoryEntry
		if err := rows.Scan(&d.Pubkey, &d.X25519, &d.Alias, &d.LastSeen); err != nil {
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
