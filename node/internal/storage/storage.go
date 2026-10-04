// Package storage implements the node's SQLite dead-drop persistence layer
// per docs/protocol.md §9: two tables (envelopes, directory), WAL journaling,
// a busy timeout, and a single serialized connection.
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
	"strings"

	"offgrid/dtn-node/internal/envelope"

	_ "modernc.org/sqlite" // pure-Go SQLite driver (no CGO), registered as "sqlite"
)

// schema is the exact normative schema of §9. It uses IF NOT EXISTS so an
// existing database is upgraded in place without touching its data.
const schema = `
CREATE TABLE IF NOT EXISTS envelopes (
  id         TEXT PRIMARY KEY,      -- envelope id, 64 lowercase hex chars (client-computed)
  dest_hint  TEXT NOT NULL,         -- 16 lowercase hex chars
  created_at INTEGER NOT NULL,     -- unix seconds
  ttl        INTEGER NOT NULL,      -- seconds
  payload    TEXT NOT NULL          -- Base64( eph_pub || nonce || box )
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
func Open(path string) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("storage: open %s: %w", path, err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("storage: apply schema: %w", err)
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

// Close releases the database handle.
func (s *Store) Close() error {
	return s.db.Close()
}

// InsertEnvelopes inserts every envelope in one transaction using
// INSERT OR IGNORE: rows whose id already exists are silently skipped. This
// is the global deduplication mechanism across nodes (§10.4 step 2). It
// returns the number of newly inserted rows.
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

	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO envelopes (id, dest_hint, created_at, ttl, payload) VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		return 0, fmt.Errorf("storage: prepare insert: %w", err)
	}
	defer stmt.Close()

	inserted := 0
	for _, e := range envs {
		res, err := stmt.Exec(e.ID, e.DestHint, e.CreatedAt, e.TTL, e.Payload)
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
		`SELECT id, dest_hint, created_at, ttl, payload FROM envelopes WHERE %s ORDER BY created_at DESC, id ASC LIMIT ?`,
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
		if err := rows.Scan(&e.ID, &e.DestHint, &e.CreatedAt, &e.TTL, &e.Payload); err != nil {
			return nil, fmt.Errorf("storage: scan envelope: %w", err)
		}
		// The §9 schema does not persist `v`: only envelopes with v == 1 pass
		// push validation (§10.5), so every stored row IS a v=1 envelope and
		// the reconstruction must say so — a pulled envelope marshaled with
		// v=0 is invalid per §3.1 and clients would rightly reject it.
		e.V = 1
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
