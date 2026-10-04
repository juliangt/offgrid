package health

import "testing"

// TestCountersRecordAndTotals pins the counter arithmetic: acceptance and
// rejection are independent one-per-request increments, rejection classes
// bucket exactly by class, dedup hits are envelope-granular and never
// negative, and a sweep refreshes both the lifetime totals and the
// last-cleanup pair.
func TestCountersRecordAndTotals(t *testing.T) {
	c := NewCounters()

	if got := c.Totals(); got.PushesAccepted != 0 || got.PushesRejected != 0 || got.DedupHits != 0 ||
		got.TTLSweeps != 0 || got.LastCleanupUnix != 0 {
		t.Fatalf("fresh counters must be zero, got %+v", got)
	}

	c.RecordPushAccepted()
	c.RecordPushAccepted()
	c.RecordDedupHits(3)
	c.RecordPushRejected(ClassInvalid)
	c.RecordPushRejected(ClassRateLimited)
	c.RecordPushRejected(ClassNodeFull)
	c.RecordPushRejected(ClassStorageUnavailable)
	c.RecordPushRejected(ClassTooLarge)
	c.RecordPushRejected(ClassInvalid) // default bucket, explicit
	c.RecordSweep(1700000000, 7)

	got := c.Totals()
	if got.PushesAccepted != 2 {
		t.Fatalf("pushes_accepted: got %d, want 2", got.PushesAccepted)
	}
	if got.PushesRejected != 6 {
		t.Fatalf("pushes_rejected: got %d, want 6", got.PushesRejected)
	}
	if got.RejectedInvalid != 2 || got.RejectedRateLimited != 1 || got.RejectedNodeFull != 1 ||
		got.RejectedStorageUnavailable != 1 || got.RejectedTooLarge != 1 {
		t.Fatalf("rejection class buckets wrong: %+v", got)
	}
	if got.PushesRejected != got.RejectedInvalid+got.RejectedRateLimited+got.RejectedNodeFull+
		got.RejectedStorageUnavailable+got.RejectedTooLarge {
		t.Fatalf("rejected total must equal the sum of the classes: %+v", got)
	}
	if got.DedupHits != 3 {
		t.Fatalf("dedup_hits: got %d, want 3", got.DedupHits)
	}
	if got.TTLSweeps != 1 || got.TTLSweptEnvelopes != 7 {
		t.Fatalf("ttl totals wrong: %+v", got)
	}
	if got.LastCleanupUnix != 1700000000 || got.LastCleanupEnvelopesDeleted != 7 {
		t.Fatalf("last cleanup pair must describe the most recent sweep: %+v", got)
	}

	// The last-cleanup pair moves with the newest sweep; lifetime totals grow.
	c.RecordSweep(1700000060, 0)
	got = c.Totals()
	if got.TTLSweeps != 2 || got.TTLSweptEnvelopes != 7 {
		t.Fatalf("second sweep must accumulate: %+v", got)
	}
	if got.LastCleanupUnix != 1700000060 || got.LastCleanupEnvelopesDeleted != 0 {
		t.Fatalf("last cleanup pair must describe the most recent sweep: %+v", got)
	}
}

// TestRecordDedupHitsIgnoresNegative pins the guard: a negative count (a
// caller bug) must never move the counter.
func TestRecordDedupHitsIgnoresNegative(t *testing.T) {
	c := NewCounters()
	c.RecordDedupHits(2)
	c.RecordDedupHits(-5)
	if got := c.Totals().DedupHits; got != 2 {
		t.Fatalf("negative dedup hits must be ignored, got %d", got)
	}
}
