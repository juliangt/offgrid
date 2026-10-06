// activity.go — the aggregate active-client tracker of the status page
// (issue #36, docs/protocol.md §10.7 "active_clients").
//
// Aggregate-only guarantee (binding, reviewed by tests): the tracker holds
// client keys (the same port-stripped source IPs the admission budgets of
// ratelimit.go already hold, in the same RAM-only spirit) for exactly one
// purpose — making "how many distinct clients were active in the trailing
// window" a DISTINCT count. The ONLY value that leaves this type is that
// integer count. There is no accessor for keys, no serialization, no log
// line, and nothing is persisted: keys live in RAM and vanish on restart
// or window expiry, exactly like the budget buckets (docs/protocol.md §13,
// A7 of docs/hardening.md).
//
// Boundedness: the map is capped at activeClientCap entries. A flood of
// unique keys triggers an eager prune of expired entries and, if still
// over cap, drops the OLDEST entries first — the tracker can never grow
// unbounded, whatever the request rate.

package status

import (
	"sync"
	"time"
)

// activeClientWindow is the trailing window of the "active clients" count:
// a portal session counts for 15 minutes after its last activity (a page
// load is a sync POST; an idle-but-connected phone drops out after the
// window). Documented in §10.7.
const activeClientWindow = 15 * time.Minute

// activeClientCap bounds the tracker's map (same order as the budget
// maps' eviction floor in ratelimit.go: a quiet village square holds
// dozens, not thousands).
const activeClientCap = 4096

// activityTracker is the capped, windowed map of client keys to their last
// activity instant.
type activityTracker struct {
	mu       sync.Mutex
	lastSeen map[string]time.Time
	now      func() time.Time
}

// note records one activity. Bounding happens inline: once the map reaches
// the cap, expired entries are pruned and — should the flood still exceed
// the cap — the oldest entries are dropped.
func (a *activityTracker) note(key string, now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.lastSeen == nil {
		a.lastSeen = make(map[string]time.Time)
	}
	if len(a.lastSeen) >= activeClientCap {
		a.pruneLocked(now)
		if len(a.lastSeen) >= activeClientCap {
			a.dropOldestLocked(len(a.lastSeen) - activeClientCap + 1)
		}
	}
	a.lastSeen[key] = now
}

// count returns how many distinct keys were active within the trailing
// window before now. This is the tracker's only output.
func (a *activityTracker) count(now time.Time) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	cutoff := now.Add(-activeClientWindow)
	for _, t := range a.lastSeen {
		if t.After(cutoff) {
			n++
		}
	}
	return n
}

// prune evicts entries idle longer than the window; called every sampler
// tick and on cap pressure.
func (a *activityTracker) prune(now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pruneLocked(now)
}

func (a *activityTracker) pruneLocked(now time.Time) {
	cutoff := now.Add(-activeClientWindow)
	for k, t := range a.lastSeen {
		if !t.After(cutoff) {
			delete(a.lastSeen, k)
		}
	}
}

// dropOldestLocked evicts the n oldest entries (cap-pressure fallback).
func (a *activityTracker) dropOldestLocked(n int) {
	for i := 0; i < n; i++ {
		var oldestKey string
		var oldest time.Time
		first := true
		for k, t := range a.lastSeen {
			if first || t.Before(oldest) {
				oldestKey, oldest, first = k, t, false
			}
		}
		if first {
			return
		}
		delete(a.lastSeen, oldestKey)
	}
}
