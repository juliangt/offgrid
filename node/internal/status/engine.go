// Package status is the background sampler behind the field status page
// (issue #36, docs/protocol.md §10.7): a goroutine that wakes once a
// minute, takes one cheap sample (a handful of /proc and /sys file reads,
// one battery sensor read when configured, a few pure-COUNT queries), and
// feeds fixed-capacity RAM-only ring buffers. The request path never
// samples: GET /api/v1/health and GET /status read the engine's latest
// snapshot out of memory, so the diagnostics surface stays as cheap as the
// #31 counters it extends.
//
// Design trade-off (deliberate, documented): the ring buffers are RAM-only
// and die with the process — restart clears the projections and the page
// honestly shows "not enough data yet" until the minimum-data rule is
// satisfied again. Persistence would buy projections that survive a reboot
// at the cost of writing per-day rollups to the SD card; RAM-only was
// chosen, consistent with the #31 counters' design (nothing operational is
// ever written to disk, docs/protocol.md §13).
//
// Privacy is the binding constraint of this package, as it is for
// internal/health: every value it exposes is an aggregate integer (or an
// electrical/thermal measurement of the node itself). The ONE structure
// that touches client keys — the active-client tracker in activity.go —
// keeps strictly more than the per-IP rate budgets already keep, in RAM
// only, and exposes ONLY a count; no key ever leaves it.
package status

import (
	"sync"
	"time"

	"offgrid/dtn-node/internal/health"
	"offgrid/dtn-node/internal/power"
	"offgrid/dtn-node/internal/storage"
	"offgrid/dtn-node/internal/sysres"
)

// DefaultSampleInterval is the production sampling cadence: one minute.
// A sample costs a few file reads and a handful of SQL COUNTs — noise on a
// Pi Zero W — while the projections it feeds stay minutes-fresh. Var purely
// as a test hook (the maxEnvelopes pattern); production code must never
// reassign it.
var DefaultSampleInterval = time.Minute

// ringCapacity bounds every ring buffer: 1440 one-minute samples = a 24 h
// trailing window, the longest projection the page draws. RAM cost is a
// few hundred KiB — accepted on the armv6 budget.
const ringCapacity = 1440

// StoreStats is the store surface the sampler reads: the #31 count/size
// queries plus the issue-#36 expiring buckets and the on-disk schema
// version. Satisfied by *storage.Store; pure COUNT/pragma reads, never row
// content.
type StoreStats interface {
	EnvelopeCount() (int64, error)
	DBSizeBytes() (int64, error)
	ExpiringCounts(now int64) (storage.ExpCounts, error)
	SchemaVersionOnDisk() (int, error)
}

// CounterSource is the aggregate-counter source (internal/health). Kept as
// an interface for tests; *health.Counters satisfies it.
type CounterSource interface {
	Totals() health.Totals
}

// BatteryReader is the power-chain surface the sampler needs (*power.Chain
// satisfies it). Nil in the engine means the whole battery section renders
// N/A — the stock no-hardware node.
type BatteryReader interface {
	Read() (power.Reading, bool)
	ReadHealth() (float64, bool)
	Overview(r power.Reading) power.Overview
	DODFloor() float64
	CapacityWh() float64
}

// Deps wires the engine's collaborators. Every member is optional: a nil
// one degrades its section of the status page to N/A, never to an error.
type Deps struct {
	Store    StoreStats
	Counters CounterSource
	Battery  BatteryReader
	System   sysres.Readers // zero value = no system telemetry
}

// sample is one ring-buffer entry. Counters are snapshots (lifetime
// totals at that instant); projections derive deltas from first/last.
type sample struct {
	At          time.Time
	Envelopes   int64
	DBSizeBytes int64
	Totals      health.Totals
	BatteryWh   *float64 // remaining energy above empty, when measurable
}

// Engine is the RAM-only sampler state: the ring buffers, the latest
// sensor readings and the active-client aggregate. Safe for concurrent
// use; the request path touches only Snapshot/NoteClientActivity.
type Engine struct {
	mu   sync.Mutex
	deps Deps
	now  func() time.Time

	ring    []sample // ordered oldest→newest, capped at ringCapacity
	sampled int

	// Latest per-section readings (nil/zero = not yet sampled or
	// unavailable — rendered N/A, never zeros).
	lastPower     *power.Overview
	lastHealth    *float64
	lastSystem    sysres.Readings
	lastExpiring  *storage.ExpCounts
	schemaOnDisk  *int
	diskFree      *int64
	envelopeCap   int
	activeClients activityTracker
}

// NewEngine builds an engine over the given deps. Production passes the
// shared *storage.Store and *health.Counters (same instances the API and
// the janitor hold) plus the configured battery chain and the default
// sysres readers. The envelope capacity for the days-to-capacity
// projection comes from the same source admission enforces
// (storage.MaxEnvelopes) — never a copied constant.
func NewEngine(deps Deps) *Engine {
	return &Engine{
		deps:        deps,
		now:         time.Now,
		envelopeCap: storage.MaxEnvelopes(),
	}
}

// SetNow swaps the clock (test hook only).
func (e *Engine) SetNow(now func() time.Time) { e.now = now }

// Run starts the sampling loop: one sample immediately and synchronously
// (a freshly booted node shows live battery/system figures at once, while
// the projections honestly wait for the minimum-data rule), then one per
// interval — or DefaultSampleInterval when interval <= 0 — until ctx is
// cancelled.
func (e *Engine) Run(ctx interface{ Done() <-chan struct{} }, interval time.Duration) {
	if interval <= 0 {
		interval = DefaultSampleInterval
	}
	e.Sample()
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				e.Sample()
			}
		}
	}()
}

// Sample takes exactly one tick: the collectors, the store aggregates, the
// battery chain, one ring push and the active-client prune. Failures are
// ordinary: each piece that fails simply does not refresh (its section
// renders N/A / stays at its last honest state) — sampling never errors
// and never logs per tick (quiet journal, docs/hardening.md A7).
func (e *Engine) Sample() {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()

	s := sample{At: now}

	if e.deps.Store != nil {
		if n, err := e.deps.Store.EnvelopeCount(); err == nil {
			s.Envelopes = n
		}
		if size, err := e.deps.Store.DBSizeBytes(); err == nil {
			s.DBSizeBytes = size
		}
		if c, err := e.deps.Store.ExpiringCounts(now.Unix()); err == nil {
			e.lastExpiring = &c
		}
		if v, err := e.deps.Store.SchemaVersionOnDisk(); err == nil {
			e.schemaOnDisk = &v
		}
	}
	if e.deps.Counters != nil {
		s.Totals = e.deps.Counters.Totals()
	}
	if e.deps.Battery != nil {
		if rd, ok := e.deps.Battery.Read(); ok {
			ov := e.deps.Battery.Overview(rd)
			e.lastPower = &ov
			if e.deps.Battery.CapacityWh() > 0 && rd.SOC != nil {
				wh := e.deps.Battery.CapacityWh() * rd.SOC.Percent / 100
				s.BatteryWh = &wh
			}
		}
		if h, ok := e.deps.Battery.ReadHealth(); ok {
			e.lastHealth = &h
		}
	}
	e.lastSystem = e.deps.System.Collect()
	if e.lastSystem.Disk != nil {
		free := e.lastSystem.Disk.FreeBytes
		e.diskFree = &free
	}

	e.push(s)
	e.activeClients.prune(now)
}

// push appends one sample to the ring, evicting the oldest at capacity.
func (e *Engine) push(s sample) {
	if len(e.ring) == ringCapacity {
		copy(e.ring, e.ring[1:])
		e.ring[len(e.ring)-1] = s
		return
	}
	e.ring = append(e.ring, s)
	e.sampled++
}

// NoteClientActivity records that the client behind key did something —
// called by the API layer at the exact points where clientKey(r) is already
// computed for the admission budgets, so no identity is retained beyond
// what rate limiting already keeps. The key never leaves the tracker: it
// exists only to make the "active clients" count distinct (activity.go).
func (e *Engine) NoteClientActivity(key string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.activeClients.note(key, e.now())
}

// SampleCount reports how many samples the ring holds (test/inspection).
func (e *Engine) SampleCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.ring)
}

// Snapshot returns the RAM-cached view the API layer renders: the latest
// per-section readings plus the ring-derived projections. It never samples
// anything — no /proc read, no sensor, no SQLite — so a request flood
// costs nothing beyond a mutex check (the boundedness contract of §10.7).
// Before the first tick everything is unavailable: the zero Snapshot
// renders an honest page of N/A, never zeros.
func (e *Engine) Snapshot() Snapshot {
	e.mu.Lock()
	defer e.mu.Unlock()
	snap := Snapshot{
		System:        e.lastSystem,
		BatteryHealth: e.lastHealth,
		ActiveClients: e.activeClients.count(e.now()),
	}
	if len(e.ring) > 0 {
		last := e.ring[len(e.ring)-1]
		snap.SampledAt = last.At
	}
	snap.SampleCount = len(e.ring)
	if e.lastPower != nil {
		snap.Battery = e.lastPower
	}
	if e.lastExpiring != nil {
		c := *e.lastExpiring
		snap.Expiring = &c
	}
	if e.schemaOnDisk != nil {
		v := *e.schemaOnDisk
		snap.SchemaOnDisk = &v
	}
	ring := e.ringCopyLocked()
	snap.Projections = computeProjections(ring, e.envelopeCap, e.diskFree)
	snap.CountersDelta = computeCountersDelta(ring)
	return snap
}

// ringCopyLocked returns the ring contents ordered oldest→newest.
func (e *Engine) ringCopyLocked() []sample {
	out := make([]sample, len(e.ring))
	copy(out, e.ring)
	return out
}
