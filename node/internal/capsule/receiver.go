// receiver.go — the node-plane updates consumer (docs/node-network.md
// §9.4): the seam the forward.Sink calls for every chunk bundle addressed
// to THIS node. A Receiver owns the reassembler and the Stager; on capsule
// completion it runs the §2.4.4 order (verify → arch → anti-rollback →
// floor → atomic stage) and counts every verdict.
//
// Counters (RAM-only, §10.7 discipline) and the §2.6.2 mapping — the
// node-plane names mirror offline-maintenance's HTTP counters so one
// operator vocabulary serves both entry points:
//
//	HTTP plane (§2.4.2/§2.6.2, lands with #37)   node plane (this file)
//	200 accepted (capsules_accepted)             Accepted
//	409 stale_capsule (…_rejected_stale)         Stale
//	400 bad_capsule_signature (…_signature)      Signature
//	400 invalid/corrupted (…_malformed)          Malformed (incl. too old)
//	—                                            WrongArch (§9.1 gate)
//	503 update_key_unpinned                      Unpinned (refuses)
//	—                                            UpdatesOff (refuses, sink/store)
//
// The HTTP plane's 409 stale refusal maps onto the node plane to a
// silently-consumed capsule + the Stale counter: the bundle plane has no
// error packets to strangers (the §13.6 refusal-to-confirm pattern), and
// §2.6's semantics — the capsule is NEVER staged — are preserved exactly.
// Where a management command triggered the delivery, the command path's
// own telemetry reply code 1 (an authorized command whose local execution
// failed, §8.3) carries the refusal back to the manager; the plain chunk
// path carries only the counter.
package capsule

import "sync/atomic"

// UpdatesCounters is the Receiver's RAM-only bookkeeping. Chunk-level
// arithmetic (chunks seen, duplicates absorbed) lives on the reassembler's
// own counters (Reassembler.Counters).
type UpdatesCounters struct {
	Reassembled atomic.Uint64 // byte-exact capsules reassembled
	Accepted    atomic.Uint64 // verified + anti-rollback-passed + staged
	Stale       atomic.Uint64 // §2.6 rule 2 refusals (the 409 class)
	Signature   atomic.Uint64 // bad-capsule-signature refusals
	Malformed   atomic.Uint64 // invalid/corrupted/too-old refusals
	WrongArch   atomic.Uint64 // §9.1 arch-gate refusals
	Unpinned    atomic.Uint64 // refused: no release key pinned (§2.4.1)
}

// UpdatesCountersSnapshot is a plain read of the counters.
type UpdatesCountersSnapshot struct {
	Reassembled, Accepted, Stale    uint64
	Signature, Malformed, WrongArch uint64
	Unpinned                        uint64
}

// Snapshot renders the current values.
func (c *UpdatesCounters) Snapshot() UpdatesCountersSnapshot {
	return UpdatesCountersSnapshot{
		Reassembled: c.Reassembled.Load(),
		Accepted:    c.Accepted.Load(),
		Stale:       c.Stale.Load(),
		Signature:   c.Signature.Load(),
		Malformed:   c.Malformed.Load(),
		WrongArch:   c.WrongArch.Load(),
		Unpinned:    c.Unpinned.Load(),
	}
}

// Receiver consumes chunk bundles addressed to this node and stages
// completed capsules. Constructing one IS the node's `updates_enabled`
// configuration (default OFF — updates are L2/L3 policy, §9.4): with the
// policy off there is NO Receiver and the sink/store refuse chunk bundles
// at admission; a Receiver whose Stager has no pinned release key is the
// degraded §2.4.1 state (staging unavailable — everything refused,
// honestly counted, nothing written).
type Receiver struct {
	Reasm *Reassembler
	Stage *Stager

	counters UpdatesCounters
}

// NewReceiver wires the updates consumer over a reassembler and stager.
func NewReceiver(r *Reassembler, s *Stager) *Receiver {
	return &Receiver{Reasm: r, Stage: s}
}

// CountersSnapshot exposes the counters (the /status updates member is
// #37 §2.6.2's surface; until then this is -tcpcl-debug observability).
func (rc *Receiver) CountersSnapshot() UpdatesCountersSnapshot {
	return rc.counters.Snapshot()
}

// OfferChunk consumes one chunk bundle payload (after the hop octet) with
// its bundle's lifetime (P-6: the partial expires with the cargo's own TTL —
// the §9.4 rule; senders pin capsule-chunk bundles at ChunkLifetime). There
// is no per-chunk error channel on the bundle plane — every verdict lands
// in the counters, exactly like the enforcement pipeline's silent drops.
func (rc *Receiver) OfferChunk(payload []byte, lifetimeSec uint64) {
	assembled, err := rc.Reasm.Offer(payload, lifetimeSec)
	if err != nil {
		return // chunk-level corruption/overflow — counted by the reassembler
	}
	if assembled == nil {
		return // a partial step, or an absorbed duplicate
	}
	rc.counters.Reassembled.Add(1)
	if _, err := rc.Stage.Stage(assembled); err != nil {
		switch ErrorCode(err) {
		case CodeStale:
			rc.counters.Stale.Add(1) // the 409 class — replay refused, never staged
		case CodeSignature:
			rc.counters.Signature.Add(1)
		case CodeUnpinned:
			rc.counters.Unpinned.Add(1)
		case CodeWrongArch:
			rc.counters.WrongArch.Add(1)
		default:
			rc.counters.Malformed.Add(1) // invalid/corrupted/too_old (the §2.6.2 malformed bucket)
		}
		return
	}
	rc.counters.Accepted.Add(1)
}
