// Package forward implements the P3.5 forwarding engine of the node plane
// (docs/node-network.md §7, issue #33): the bundle store (§7.5), the
// controlled epidemic contact sync v1 (§7.1) with the priority queue
// discipline (§7.3), and the receiving side of the §7.4 per-contact budget
// (the egress half lives in the tcpcl session).
//
// The store is the node-plane analogue of internal/storage (the user-plane
// envelope dead drop): SQLite WAL in its OWN database file (the node-plane
// namespace of §7.5 — the envelope store's schema chain and §15.3 versioning
// are user-plane property and are never touched), the same modernc.org/sqlite
// driver, the same single-connection discipline, the same caps/janitor
// idiom. Everything here is blind relay cargo: PDUs are stored and served
// byte-unmodified except the one mutable byte the profile allows (the §3.1
// hop octet, rewritten by the relay on transfer; the store keeps the bytes
// exactly as admitted).
package forward

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"sync/atomic"
	"time"

	"offgrid/dtn-node/internal/bundle"

	_ "modernc.org/sqlite" // pure-Go SQLite driver (no CGO); registers "sqlite" via init
)

// SchemaVersion is the bundle store's own schema version marker (its
// user_version is independent of the user-plane storage.SchemaVersion: the
// two planes share no tables and never migrate together).
const SchemaVersion = 1

// DefaultCap is the Pi-default bundle cap of §7.5 (5000 bundles). The ESP32
// cap is whatever its flash budget honestly allows and is reported via
// capabilities, never fabricated — the dtn_core mirror takes the cap as an
// explicit parameter for exactly that reason.
const DefaultCap = 5000

// AdminEID is the well-known admin destination of §8.1 (dtn://og-admin/):
// the one destination EID that classifies a bundle as management cargo in
// v1 (see Classify).
const AdminEID = "dtn://og-admin/"

// MailGroupEID is the anonymous mail group of P-4 (dtn:og-mail).
const MailGroupEID = "dtn:og-mail"

// Class is the local priority class of §7.3: management > mail > bulk.
// The numeric order IS the priority order (lower = more important), which
// the eviction rule and the send scheduler both exploit. It is never a wire
// field — the profile deliberately has no priority on the wire (§7.3).
type Class int

const (
	ClassManagement Class = iota // admin/management cargo (dtn://og-admin/)
	ClassMail                    // anonymous mail (dtn:none → dtn:og-mail)
	ClassBulk                    // everything else: updates, cards, sync summaries
)

func (c Class) String() string {
	switch c {
	case ClassManagement:
		return "management"
	case ClassMail:
		return "mail"
	}
	return "bulk"
}

// Classify pins the v1 EID-based admission classification (deliberately
// SIMPLE; P3.6/P3.7 extend it in place):
//
//   - management: destination is the well-known admin EID dtn://og-admin/
//     (§8.1 — commands, and the admin records that ride the same address);
//   - mail: source is dtn:none AND destination is the og-mail group (the
//     P-4 anonymous mail shape — the §14.2 envelope's bundle wrapper);
//   - everything else is bulk: identified point-to-point bundles (node →
//     node EID), group addresses other than og-mail, capsule chunks (§9.1),
//     directory cards (§9.3), and the §7.1 sync summaries themselves.
//
// The issue's "source carries a role cert" clause of the management class
// is NOT EID-based and lands with P3.6 (which parses COSE payloads); until
// then an identified bundle addressed anywhere but og-admin is bulk, which
// only ever affects queue priority, never delivery.
func Classify(dest, src bundle.EID) Class {
	if dest.String() == AdminEID {
		return ClassManagement
	}
	if src.IsNone() && dest.String() == MailGroupEID {
		return ClassMail
	}
	return ClassBulk
}

// Verdict is the admission outcome of one Accept call.
type Verdict int

const (
	VerdictAccepted  Verdict = iota // stored
	VerdictDup                      // bundle_id already present — absorbed (P-7)
	VerdictExpired                  // creation + lifetime already past the local clock
	VerdictHopCapped                // hop octet at the §3.1 ceiling (7) — dead cargo
	VerdictAtCap                    // store at cap and nothing evictable — refused
)

func (v Verdict) String() string {
	switch v {
	case VerdictAccepted:
		return "accepted"
	case VerdictDup:
		return "dup"
	case VerdictExpired:
		return "expired"
	case VerdictHopCapped:
		return "hop_capped"
	}
	return "at_cap"
}

// Sentinel errors Accept can return. Dup/expired/hop-capped are POLICY
// drops, not failures: the transfer is acknowledged (the receiver processed
// the bytes and disposed of them per §7.2) — a sender must never retry
// them, so they are not refusals. Only capacity (ErrCapacity) and malformed
// PDUs (ErrMalformed) refuse the transfer at the TCPCL layer.
var (
	// ErrCapacity is the store-at-cap refusal (the TCPCL layer answers
	// XFER_REFUSE "No Resources").
	ErrCapacity = errors.New("forward: bundle store at capacity")
	// ErrMalformed covers PDUs that fail profile Parse at the store's own
	// re-validation (the session layer already refuses those; reaching the
	// store with one is a contract break).
	ErrMalformed = errors.New("forward: not a profile bundle")
)

// Counters is the RAM-only bookkeeping of every admission path (the §10.7
// counter discipline: no persistence, dies with the process). Zero value is
// ready; all methods are safe for concurrent use.
type Counters struct {
	Accepted      atomic.Uint64
	Dup           atomic.Uint64
	Expired       atomic.Uint64 // admission-refused AND janitor-swept
	HopCapped     atomic.Uint64
	AtCapRejected atomic.Uint64
	Evicted       atomic.Uint64
}

// Snapshot is a plain read of the counters at one instant.
type CountersSnapshot struct {
	Accepted, Dup, Expired, HopCapped, AtCapRejected, Evicted uint64
}

// Snapshot renders the current values.
func (c *Counters) Snapshot() CountersSnapshot {
	return CountersSnapshot{
		Accepted:      c.Accepted.Load(),
		Dup:           c.Dup.Load(),
		Expired:       c.Expired.Load(),
		HopCapped:     c.HopCapped.Load(),
		AtCapRejected: c.AtCapRejected.Load(),
		Evicted:       c.Evicted.Load(),
	}
}

// Entry is one live bundle as the sync layer sees it: its P-7 id and the
// local class it was admitted under.
type Entry struct {
	ID    [sha256.Size]byte
	Class Class
}

// Config opens a bundle store. Path is required; Cap <= 0 means DefaultCap;
// Now pins the clock (tests).
type Config struct {
	Path string
	Cap  int
	Now  func() time.Time
	Log  *log.Logger
}

// Store is the §7.5 bundle store: SQLite WAL, own bundles table, one
// serialized connection (the storage.go trade-off — a Pi Zero 2 W node has
// no write contention worth optimizing for). All methods are safe for
// concurrent use.
type Store struct {
	db       *sql.DB
	cap      int
	now      func() time.Time
	log      *log.Logger
	counters Counters
}

// Open creates or opens the bundle store at cfg.Path. The database is
// created with the binding pragmas of the storage engine (WAL, busy
// timeout, default autocheckpoint — the §9 idiom reused verbatim) and its
// own user_version marker: a database written by a NEWER binary is refused
// (the §15.3 downgrade stance, applied to the node-plane namespace).
func Open(cfg Config) (*Store, error) {
	if cfg.Path == "" {
		return nil, fmt.Errorf("forward: open bundle store: path is required")
	}
	cap := cfg.Cap
	if cap <= 0 {
		cap = DefaultCap
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	dsn := fmt.Sprintf(
		"file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=wal_autocheckpoint(1000)",
		cfg.Path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("forward: open %s: %w", cfg.Path, err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if err := initSchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("forward: %s: %w", cfg.Path, err)
	}
	var mode string
	if err := db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		db.Close()
		return nil, fmt.Errorf("forward: check journal_mode: %w", err)
	}
	if mode != "wal" {
		db.Close()
		return nil, fmt.Errorf("forward: journal_mode is %q, want wal", mode)
	}
	return &Store{db: db, cap: cap, now: now, log: cfg.Log}, nil
}

// schemaV1 is the node-plane bundles table of §7.5: bundle_id PK (64 hex of
// the P-7 digest), the full canonical PDU as admitted, the local class, the
// hop octet at admission, the absolute expiry (creation + lifetime,
// evaluated against the LOCAL clock at admission — P-6) and the admission
// time (eviction tie-break).
const schemaV1 = `
CREATE TABLE IF NOT EXISTS bundles (
  bundle_id   TEXT PRIMARY KEY, -- 64 lowercase hex chars of SHA-256(PDU-after-hop) (P-7)
  pdu         BLOB NOT NULL,    -- the full canonical two-block PDU, byte-exact as admitted
  class       INTEGER NOT NULL, -- 0 management, 1 mail, 2 bulk (§7.3)
  hop         INTEGER NOT NULL, -- the §3.1 hop octet at admission
  expires_at  INTEGER NOT NULL, -- unix seconds: creation + lifetime at admission (P-6)
  received_at INTEGER NOT NULL  -- unix seconds of admission (eviction tie-break)
);
CREATE INDEX IF NOT EXISTS idx_bundles_expiry    ON bundles(expires_at);
CREATE INDEX IF NOT EXISTS idx_bundles_class_exp ON bundles(class, expires_at);
`

func initSchema(db *sql.DB) error {
	var v int
	if err := db.QueryRow("PRAGMA user_version").Scan(&v); err != nil {
		return fmt.Errorf("read user_version: %w", err)
	}
	if v > SchemaVersion {
		return fmt.Errorf("refusing to open: bundle store schema version is %d but this binary supports at most %d (downgrades are unsupported)", v, SchemaVersion)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'bundles'`).Scan(&n); err != nil {
		return fmt.Errorf("inspect schema: %w", err)
	}
	if n > 0 && v == SchemaVersion {
		return nil // the marker is authoritative: nothing to do
	}
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin create schema: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(schemaV1); err != nil {
		return fmt.Errorf("apply schema: %w", err)
	}
	if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", SchemaVersion)); err != nil {
		return fmt.Errorf("set user_version: %w", err)
	}
	return tx.Commit()
}

// Close releases the database handle.
func (s *Store) Close() error { return s.db.Close() }

// Cap reports the enforced bundle cap (§7.5 honesty: the cap admission
// enforces is the one this returns).
func (s *Store) Cap() int { return s.cap }

// Accept implements the admission pipeline and satisfies the tcpcl.BundleSink
// seam: Parse (fail-closed), the skew rule is Parse's (P-6, against the
// local clock), the hop ceiling, dedup by bundle_id, classification, and the
// cap with priority-aware eviction. See Verdict for the outcomes; the
// returned error is non-nil only for ErrMalformed and ErrCapacity (both
// refuse the transfer at the session layer).
func (s *Store) Accept(pdu []byte) error {
	_, err := s.accept(pdu)
	return err
}

// accept runs the pipeline and reports the verdict.
func (s *Store) accept(pdu []byte) (Verdict, error) {
	now := s.now()
	b, err := bundle.Parse(pdu, now)
	if err != nil {
		return VerdictAtCap, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	// §3.1 hop ceiling: a bundle AT the limit is dead cargo for a v1 relay
	// (it can never be forwarded again — RewriteHop refuses — and v1 has no
	// local delivery; P3.6's consumption path sinks such bundles before this
	// rule fires). Dropped and counted, transfer acknowledged.
	if b.Hop >= 7 {
		s.counters.HopCapped.Add(1)
		return VerdictHopCapped, nil
	}
	// Expiry is local (P-6): expires_at = creation + lifetime evaluated
	// against the receiver's clock, at admission. Already-expired cargo is
	// never stored — "expired bundles never re-transferred" starts here.
	createdUnixS := int64(b.CreationDTNms)/1000 + bundle.DTNEpochUnixS
	expiresAt := createdUnixS + int64(b.Lifetime)
	if expiresAt <= now.Unix() {
		s.counters.Expired.Add(1)
		return VerdictExpired, nil
	}
	class := Classify(b.Destination, b.Source)
	id := sha256.Sum256(b.Payload) // P-7: SHA-256 over the PDU after the hop octet
	pduCopy := append([]byte(nil), pdu...)

	tx, err := s.db.Begin()
	if err != nil {
		return VerdictAtCap, fmt.Errorf("forward: begin admit: %w", err)
	}
	defer tx.Rollback()

	res, err := tx.Exec(
		`INSERT OR IGNORE INTO bundles (bundle_id, pdu, class, hop, expires_at, received_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		hex.EncodeToString(id[:]), pduCopy, int(class), int(b.Hop), expiresAt, now.Unix())
	if err != nil {
		return VerdictAtCap, fmt.Errorf("forward: insert bundle: %w", err)
	}
	inserted, err := res.RowsAffected()
	if err != nil {
		return VerdictAtCap, fmt.Errorf("forward: rows affected: %w", err)
	}
	if inserted == 0 {
		s.counters.Dup.Add(1)
		return VerdictDup, nil
	}

	var count int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM bundles`).Scan(&count); err != nil {
		return VerdictAtCap, fmt.Errorf("forward: count bundles: %w", err)
	}
	if count > s.cap {
		// §7.5 cap, priority-aware eviction (see evictOne): make room by
		// evicting the soonest-expiring bundle of the lowest-priority class
		// at-or-below the newcomer's importance; refuse when nothing may be
		// evicted (refuse-newest, the storage.go stance — nothing that would
		// break the priority order is ever deleted).
		evicted, err := evictOne(tx, class, id)
		if err != nil {
			return VerdictAtCap, err
		}
		if !evicted {
			s.counters.AtCapRejected.Add(1)
			return VerdictAtCap, ErrCapacity
		}
		s.counters.Evicted.Add(1)
	}
	if err := tx.Commit(); err != nil {
		return VerdictAtCap, fmt.Errorf("forward: commit admit: %w", err)
	}
	s.counters.Accepted.Add(1)
	return VerdictAccepted, nil
}

// evictOne deletes exactly one row to make room for the newcomer (id, class):
// the evictee comes from the LOWEST-priority class whose priority is
// at-or-below the newcomer's (class number >= incoming class), and within
// that class the bundle that expires SOONEST — "refuse-newest for the
// oldest-expiring", with the §7.3 discipline baked in: an unexpired
// management bundle is never evicted while a bulk or mail bundle exists,
// and a bulk arrival never evicts mail or management (it is refused
// instead). Deterministic tie-breaks (received_at ASC, bundle_id ASC) keep
// Go and C eviction orders identical. Reports false when no evictable row
// exists.
func evictOne(tx *sql.Tx, incoming Class, keep [sha256.Size]byte) (bool, error) {
	var victim string
	err := tx.QueryRow(
		`SELECT bundle_id FROM bundles
		 WHERE class >= ? AND bundle_id != ?
		 ORDER BY class DESC, expires_at ASC, received_at ASC, bundle_id ASC
		 LIMIT 1`,
		int(incoming), hex.EncodeToString(keep[:])).Scan(&victim)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("forward: select evictee: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM bundles WHERE bundle_id = ?`, victim); err != nil {
		return false, fmt.Errorf("forward: evict %s: %w", victim, err)
	}
	return true, nil
}

// Entries lists every LIVE bundle (not yet past expires_at — expired cargo
// is never re-transferred, §7.2) as (id, class) pairs, ordered for
// determinism. The sync layer's Bloom summaries and diffs are built from
// this.
func (s *Store) Entries() ([]Entry, error) {
	rows, err := s.db.Query(
		`SELECT bundle_id, class FROM bundles WHERE expires_at >= ? ORDER BY bundle_id ASC`,
		s.now().Unix())
	if err != nil {
		return nil, fmt.Errorf("forward: list bundles: %w", err)
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var idHex string
		var class int
		if err := rows.Scan(&idHex, &class); err != nil {
			return nil, fmt.Errorf("forward: scan bundle: %w", err)
		}
		raw, err := hex.DecodeString(idHex)
		if err != nil || len(raw) != sha256.Size {
			return nil, fmt.Errorf("forward: corrupt bundle_id %q in store", idHex)
		}
		var id [sha256.Size]byte
		copy(id[:], raw)
		out = append(out, Entry{ID: id, Class: Class(class)})
	}
	return out, rows.Err()
}

// Get loads the stored PDU of one bundle (byte-exact as admitted — the hop
// rewrite happens on the SEND path, never in storage).
func (s *Store) Get(id [sha256.Size]byte) ([]byte, bool, error) {
	var pdu []byte
	err := s.db.QueryRow(`SELECT pdu FROM bundles WHERE bundle_id = ?`,
		hex.EncodeToString(id[:])).Scan(&pdu)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("forward: get bundle: %w", err)
	}
	return pdu, true, nil
}

// Count returns the number of stored rows (live or expired — the janitor's
// job, not every reader's).
func (s *Store) Count() (int, error) {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM bundles`).Scan(&n); err != nil {
		return 0, fmt.Errorf("forward: count bundles: %w", err)
	}
	return n, nil
}

// Janitor deletes every bundle past its expiry (expires_at < now — the
// exclusive boundary, matching storage.DeleteExpired: a bundle is servable
// or deleted, never in limbo) and returns the number of rows deleted. The
// daemon runs it on the same cadence as the envelope janitor (§10.6 idiom).
func (s *Store) Janitor() (int64, error) {
	res, err := s.db.Exec(`DELETE FROM bundles WHERE expires_at < ?`, s.now().Unix())
	if err != nil {
		return 0, fmt.Errorf("forward: janitor: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("forward: janitor rows affected: %w", err)
	}
	if n > 0 {
		s.counters.Expired.Add(uint64(n))
	}
	return n, nil
}

// CountersSnapshot exposes the admission counters (internal observability;
// /status wiring is P3.6's).
func (s *Store) CountersSnapshot() CountersSnapshot { return s.counters.Snapshot() }
