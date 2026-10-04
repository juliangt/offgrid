// Package health holds the node's RAM-only aggregate counters (issue #31):
// the numbers served by GET /api/v1/health and the operator status view
// (GET /status, docs/protocol.md §10.7).
//
// Privacy is a hard constraint here (docs/protocol.md §13; A7 of
// docs/hardening.md): every value is an aggregate integer. There is no
// per-envelope, per-alias or per-IP datum anywhere in this package, nothing
// is ever persisted to disk, and nothing is logged per request. The counters
// live and die with the process — restart resets them to zero — which is the
// same accepted graceful degradation as the write-path admission budgets:
// liveness and coarse load are observable, never who did what.
//
// These counters are deliberately the single hook that future anti-abuse
// telemetry reads: a new defense should consume Totals(), never invent its
// own persistent state.
package health

import "sync/atomic"

// Rejection classes of POST /api/v1/sync, counted at the handler/middleware
// boundary. Each maps 1:1 to the short error code the endpoint answered
// (docs/protocol.md §10.1): ClassInvalid covers every 400 shape, ClassTooLarge
// the 413 body cap, ClassRateLimited and ClassNodeFull the two 429 shapes and
// ClassStorageUnavailable the 507 shed.
type RejectionClass int

const (
	ClassInvalid RejectionClass = iota
	ClassRateLimited
	ClassNodeFull
	ClassStorageUnavailable
	ClassTooLarge
)

// Counters carries every aggregate of the diagnostics surface. The zero
// value is usable; production passes one shared instance to the API server
// and to the cleanup-recording janitor (wired in the main package), so the
// snapshot and the recorder always observe the same process-lifetime totals.
//
// Every field is an atomic: the push path records from concurrently serving
// goroutines while the health handler reads. Nothing here has a setter that
// takes an absolute value — counters only ever increase (RecordSweep refreshes
// the last-cleanup pair, the one non-monotonic exception, by design: it
// describes the MOST RECENT sweep, not a lifetime total).
type Counters struct {
	pushesAccepted atomic.Int64
	pushesRejected atomic.Int64

	rejectedInvalid            atomic.Int64
	rejectedRateLimited        atomic.Int64
	rejectedNodeFull           atomic.Int64
	rejectedStorageUnavailable atomic.Int64
	rejectedTooLarge           atomic.Int64

	dedupHits atomic.Int64

	ttlSweeps         atomic.Int64
	ttlSweptEnvelopes atomic.Int64

	lastCleanupUnix    atomic.Int64
	lastCleanupDeleted atomic.Int64
}

// NewCounters returns a fresh, zeroed counter set.
func NewCounters() *Counters {
	return &Counters{}
}

// RecordPushAccepted counts one POST /api/v1/sync request that ended 200 with
// at least one pushed envelope stored (envelopes absorbed by dedup still
// count the request as accepted; they are counted separately as dedup hits).
func (c *Counters) RecordPushAccepted() { c.pushesAccepted.Add(1) }

// RecordPushRejected counts one POST /api/v1/sync request that ended in an
// error response, under its rejection class.
func (c *Counters) RecordPushRejected(class RejectionClass) {
	c.pushesRejected.Add(1)
	switch class {
	case ClassRateLimited:
		c.rejectedRateLimited.Add(1)
	case ClassNodeFull:
		c.rejectedNodeFull.Add(1)
	case ClassStorageUnavailable:
		c.rejectedStorageUnavailable.Add(1)
	case ClassTooLarge:
		c.rejectedTooLarge.Add(1)
	default:
		c.rejectedInvalid.Add(1)
	}
}

// RecordDedupHits counts n envelope ids absorbed by INSERT OR IGNORE in one
// accepted push (the batch contained ids the store already held). Dedup hits
// are envelope-granular on purpose: that is the number the §10.4 dedup
// mechanism actually absorbed.
func (c *Counters) RecordDedupHits(n int) {
	if n > 0 {
		c.dedupHits.Add(int64(n))
	}
}

// RecordSweep records one completed TTL janitor pass (§10.6) at unix time now
// that deleted deleted envelopes. A FAILED sweep must not be recorded: the
// counters only ever report what actually happened. The pair
// (LastCleanupUnix, LastCleanupEnvelopesDeleted) always describes the most
// recent completed sweep.
func (c *Counters) RecordSweep(now, deleted int64) {
	c.ttlSweeps.Add(1)
	c.ttlSweptEnvelopes.Add(deleted)
	c.lastCleanupUnix.Store(now)
	c.lastCleanupDeleted.Store(deleted)
}

// Totals is the plain-data export of the counters for the health snapshot:
// one consistent, contention-free read of every aggregate. Numbers are loaded
// individually (no cross-counter transactionality is attempted or needed —
// these are gauges and lifetime totals, not an audit log).
type Totals struct {
	PushesAccepted int64
	PushesRejected int64

	RejectedInvalid            int64
	RejectedRateLimited        int64
	RejectedNodeFull           int64
	RejectedStorageUnavailable int64
	RejectedTooLarge           int64

	DedupHits int64

	TTLSweeps         int64
	TTLSweptEnvelopes int64

	LastCleanupUnix             int64 // 0 = no sweep completed since process start
	LastCleanupEnvelopesDeleted int64
}

// Totals snapshots every counter for serving.
func (c *Counters) Totals() Totals {
	return Totals{
		PushesAccepted: c.pushesAccepted.Load(),
		PushesRejected: c.pushesRejected.Load(),

		RejectedInvalid:            c.rejectedInvalid.Load(),
		RejectedRateLimited:        c.rejectedRateLimited.Load(),
		RejectedNodeFull:           c.rejectedNodeFull.Load(),
		RejectedStorageUnavailable: c.rejectedStorageUnavailable.Load(),
		RejectedTooLarge:           c.rejectedTooLarge.Load(),

		DedupHits: c.dedupHits.Load(),

		TTLSweeps:         c.ttlSweeps.Load(),
		TTLSweptEnvelopes: c.ttlSweptEnvelopes.Load(),

		LastCleanupUnix:             c.lastCleanupUnix.Load(),
		LastCleanupEnvelopesDeleted: c.lastCleanupDeleted.Load(),
	}
}
