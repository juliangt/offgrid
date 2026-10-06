package storage

// storage_status_test.go — the store-side aggregates the field status page
// serves (issue #36): the expiring-soon TTL buckets (with boundary cases)
// and the on-disk schema version probe behind the pending-migration flag.
// Every query involved is a pure COUNT/pragma read that never inspects row
// content (docs/protocol.md §13).

import (
	"testing"
	"time"

	"offgrid/dtn-node/internal/envelope"
)

// expiringEnv builds a storage-valid envelope whose expiry (created_at +
// ttl) lands exactly on expiresAt. The store does not validate payloads —
// this is a row fixture shaped for the counters, not a protocol check.
func expiringEnv(seed int, createdAt, expiresAt int64) envelope.Envelope {
	e := makeEnv(hexID(seed), createdAt)
	e.TTL = expiresAt - createdAt
	return e
}

// TestExpiringCountsBuckets seeds crafted rows around every bucket boundary
// and asserts the cumulative 1 h / 6 h / 24 h triple. Boundary rule (§10.7):
// an envelope counts in the X-hour bucket iff it is still live at now AND
// expires strictly before now+X — at exactly now+1h it sits in the 6 h
// bucket.
func TestExpiringCountsBuckets(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().Unix()

	rows := []envelope.Envelope{
		expiringEnv(1, now-7200, now-3600),   // already expired: outside every bucket
		expiringEnv(2, now-600, now+1800),    // 30 min → 1h, 6h, 24h
		expiringEnv(3, now-600, now+3600),    // exactly 1 h → 6h, 24h (strict upper bound)
		expiringEnv(4, now-600, now+2*3600),  // 2 h → 6h, 24h
		expiringEnv(5, now-600, now+6*3600),  // exactly 6 h → 24h (strict upper bound)
		expiringEnv(6, now-600, now+10*3600), // 10 h → 24h
		expiringEnv(7, now-600, now+24*3600), // exactly 24 h → nothing (strict upper bound)
		expiringEnv(8, now-600, now+30*3600), // beyond the horizon
	}
	if inserted, err := s.InsertEnvelopes(rows); err != nil || inserted != len(rows) {
		t.Fatalf("seed rows: inserted %d err=%v", inserted, err)
	}

	c, err := s.ExpiringCounts(now)
	if err != nil {
		t.Fatalf("ExpiringCounts: %v", err)
	}
	if c.Within1h != 1 {
		t.Errorf("within 1 h: got %d, want 1 (only the 30-min envelope)", c.Within1h)
	}
	if c.Within6h != 3 {
		t.Errorf("within 6 h: got %d, want 3 (30 min, exactly-1h, 2 h)", c.Within6h)
	}
	if c.Within24h != 5 {
		t.Errorf("within 24 h: got %d, want 5 (+ exactly-6h, 10 h)", c.Within24h)
	}
}

// TestExpiringCountsEmptyStore pins the zero value on a fresh node.
func TestExpiringCountsEmptyStore(t *testing.T) {
	s := newTestStore(t)
	c, err := s.ExpiringCounts(time.Now().Unix())
	if err != nil {
		t.Fatalf("empty store: %v", err)
	}
	if c != (ExpCounts{}) {
		t.Fatalf("empty store must report zero buckets, got %+v", c)
	}
}

// TestSchemaVersionOnDisk verifies the pending-migration probe: a freshly
// opened store is already at the build's schema version (the §15.3
// migration runs inside Open, before the daemon ever serves).
func TestSchemaVersionOnDisk(t *testing.T) {
	s := newTestStore(t)
	got, err := s.SchemaVersionOnDisk()
	if err != nil {
		t.Fatalf("SchemaVersionOnDisk: %v", err)
	}
	if got != SchemaVersion {
		t.Fatalf("freshly opened store: on-disk = %d, want %d (migration ran before serve, §15.3)", got, SchemaVersion)
	}
}
