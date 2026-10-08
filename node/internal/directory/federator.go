package directory

// federator.go — the receiving half of §9.3: the sink consumer that
// verifies an arriving card and applies the §3.4 merge rules VERBATIM to
// the EXISTING user-plane directory storage, plus the RAM-only counter set
// §3.4 names (the §10.7 discipline: aggregates only, RAM-only, reset on
// restart).
//
// Re-admission (the §8.5 pattern): a verified card's bundle copy is handed
// back to the caller's Inject hook so the local §7.1 summaries cover it —
// a consumed card must never become a perpetual redelivery, and the
// epidemic sync is what carries one registration island-wide.

import (
	"sync/atomic"
	"time"

	"offgrid/dtn-node/internal/bundle"
)

// MergeOutcome is the §3.4 verdict for one verified card. The strings are
// the shared Go/C vocabulary the directory vectors pin (the C enum's
// numeric twin lives in dtn_dirfed.h).
type MergeOutcome int

const (
	MergeInsert       MergeOutcome = iota // rule 1: absent pubkey → new federated row (source 1)
	MergeReplace                          // rule 2: higher seq → alias/x25519/card replaced
	MergeStale                            // rule 3: lower seq → dropped (stale)
	MergeDuplicate                        // rule 4: equal seq, byte-equal card → no-op
	MergeConflict                         // rule 4: equal seq, differing bytes → keep existing (attack signal)
	MergeDroppedAtCap                     // rule 1 at a full table of locals → dropped (see storage.MergeFederatedCard)
)

func (o MergeOutcome) String() string {
	switch o {
	case MergeInsert:
		return "insert"
	case MergeReplace:
		return "replace"
	case MergeStale:
		return "stale"
	case MergeDuplicate:
		return "duplicate"
	case MergeConflict:
		return "conflict"
	default:
		return "dropped_at_cap"
	}
}

// CardMerge is one VERIFIED card handed to the directory store. The store
// re-checks nothing (verification happened in VerifyCard; the store trusts
// its caller the way the API door trusts its blind validation).
type CardMerge struct {
	CardB64  string // the card exactly as published (canonical Base64 of the COSE) — stored verbatim
	Raw      []byte // the COSE bytes (the §3.4 rule-4 byte comparison)
	Pubkey   string // Base64 of ed — the §3.4 rule-1 dedup key
	X25519   string // Base64 of x
	Alias    string
	Seq      uint64
	LastSeen int64 // the node clock at merge (the store derives epoch from it, §6.1)
}

// MergeResult is the outcome of one applied card: the §3.4 verdict plus the
// number of federated rows evicted to make room (§3.4's federation_evictions,
// nonzero only on inserts into a table at its hard cap).
type MergeResult struct {
	Outcome   MergeOutcome
	Evictions int
}

// MergeSink is the directory store's merge surface (satisfied by
// *storage.Store; an interface keeps this package free of the SQL layer the
// same way forward's MgmtConsumer keeps it free of the mgmt engine).
type MergeSink interface {
	MergeFederatedCard(c CardMerge) (MergeResult, error)
}

// Counters is the §3.4 counter set plus this package's two bookkeeping
// counters, all RAM-only (§10.7: aggregates only, never persisted). Zero
// value ready; safe for concurrent use.
type Counters struct {
	Accepted      atomic.Uint64 // §3.4 federation_accepted (rule-1 inserts)
	Replaced      atomic.Uint64 // rule-2 replacements (key rotations propagate here)
	StaleDropped  atomic.Uint64 // §3.4 federation_stale_dropped (rule 3)
	Duplicates    atomic.Uint64 // §3.4 federation_duplicates (rule 4, byte-equal)
	Conflicts     atomic.Uint64 // §3.4 federation_conflicts (rule 4, differing — THE attack signal)
	Evictions     atomic.Uint64 // §3.4 federation_evictions (cap pressure, federated rows only)
	Rejected      atomic.Uint64 // cards that failed VerifyCard (shape/signature/skew)
	DroppedAtCap  atomic.Uint64 // rule-1 inserts a full locals-only table refused
	StoreErrors   atomic.Uint64 // the merge could not run (I/O) — the card is dropped
	InjectDropped atomic.Uint64 // a verified copy could not be re-admitted for propagation
}

// CountersSnapshot is a plain read of the counters at one instant.
type CountersSnapshot struct {
	Accepted, Replaced, StaleDropped, Duplicates, Conflicts, Evictions uint64
	Rejected, DroppedAtCap, StoreErrors, InjectDropped                 uint64
}

// Snapshot renders the current values.
func (c *Counters) Snapshot() CountersSnapshot {
	return CountersSnapshot{
		Accepted:      c.Accepted.Load(),
		Replaced:      c.Replaced.Load(),
		StaleDropped:  c.StaleDropped.Load(),
		Duplicates:    c.Duplicates.Load(),
		Conflicts:     c.Conflicts.Load(),
		Evictions:     c.Evictions.Load(),
		Rejected:      c.Rejected.Load(),
		DroppedAtCap:  c.DroppedAtCap.Load(),
		StoreErrors:   c.StoreErrors.Load(),
		InjectDropped: c.InjectDropped.Load(),
	}
}

// Federator is the §9.3 receiving consumer: one per daemon, wired into the
// forward sink the way the mgmt Enforcer is (§8.5). Every field except Now
// is required for a functioning federation leg; a nil Store or a nil Inject
// degrades to verify-and-drop (counted), never to storing unverified cargo.
type Federator struct {
	// Store is the user-plane directory storage the §3.4 rules land in.
	Store MergeSink
	// Enabled is the federation policy gate (§9.3: one flag gates emission
	// AND absorption; transit relay stays unconditional DTN duty). When it
	// returns false the consumer DECLINES the bundle — the sink then stores
	// it as ordinary bulk transit cargo, relayed but never merged.
	Enabled func() bool
	// Inject re-admits a consumed card's bundle into the forward store (the
	// §8.5 convergence rule — the §7.1 summaries must cover it).
	Inject func(pdu []byte) error

	Now func() time.Time

	counters Counters
}

// CountersSnapshot exposes the §3.4 counters (internal observability; the
// additive health member is #37 §3.4's surface).
func (f *Federator) CountersSnapshot() CountersSnapshot { return f.counters.Snapshot() }

// ConsumeDirectory is the forward.Sink seam for bundles addressed to the
// dtn://og-dir/ group (§9.3). Handled=true means the bytes were directory
// business — the sink must NOT store them (verified copies are re-admitted
// through Inject by this method itself). Handled=false = the federation
// gate is off: the sink falls through to the store, which relays the bundle
// as ordinary bulk transit (the DTN's unconditional duty) while this node
// absorbs nothing.
func (f *Federator) ConsumeDirectory(b *bundle.Bundle) (handled bool) {
	if f.Enabled != nil && !f.Enabled() {
		return false
	}
	now := f.Now
	if now == nil {
		now = time.Now
	}
	card, err := VerifyCard(b.Payload, now().Unix())
	if err != nil {
		// §3.4 preamble: verification failure → drop the card, count it,
		// continue. Still directory business (never relay garbage the
		// og-door refused): handled=true without re-admission.
		f.counters.Rejected.Add(1)
		return true
	}
	if f.Store != nil {
		res, err := f.Store.MergeFederatedCard(CardMerge{
			CardB64:  CanonicalB64(b.Payload),
			Raw:      append([]byte(nil), b.Payload...),
			Pubkey:   card.PubkeyB64(),
			X25519:   card.X25519B64(),
			Alias:    card.Alias,
			Seq:      card.Seq,
			LastSeen: now().Unix(),
		})
		switch {
		case err != nil:
			f.counters.StoreErrors.Add(1)
		case res.Outcome == MergeInsert:
			f.counters.Accepted.Add(1)
			f.counters.Evictions.Add(uint64(res.Evictions))
		case res.Outcome == MergeReplace:
			f.counters.Replaced.Add(1)
		case res.Outcome == MergeStale:
			f.counters.StaleDropped.Add(1)
		case res.Outcome == MergeDuplicate:
			f.counters.Duplicates.Add(1)
		case res.Outcome == MergeConflict:
			f.counters.Conflicts.Add(1)
		default: // MergeDroppedAtCap
			f.counters.DroppedAtCap.Add(1)
		}
	}
	// §8.5 convergence: the verified copy is re-admitted whatever the merge
	// verdict — propagation is the epidemic sync's job; the merge rules only
	// bound what this node's own directory does with the card.
	if f.Inject != nil {
		pdu, err := bundle.Encode(b)
		if err != nil {
			f.counters.InjectDropped.Add(1)
			return true
		}
		if err := f.Inject(pdu); err != nil {
			f.counters.InjectDropped.Add(1)
		}
	}
	return true
}
