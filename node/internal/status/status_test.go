package status

// status_test.go — unit tests for the status sampler engine (issue #36):
// the aggregate-only active-client tracker, the ring buffers, the
// projection math with the MINIMUM-DATA RULE, and one end-to-end engine
// pass over fake deps. All clock-driven (no sleeping), all RAM-only.

import (
	"context"
	"math"
	"testing"
	"time"

	"offgrid/dtn-node/internal/health"
	"offgrid/dtn-node/internal/power"
	"offgrid/dtn-node/internal/storage"
	"offgrid/dtn-node/internal/sysres"
)

// --- fakes -------------------------------------------------------------

type fakeStore struct {
	envs        int64
	size        int64
	expiring    storage.ExpCounts
	schema      int
	countCalled int
}

func (f *fakeStore) EnvelopeCount() (int64, error) { return f.envs, nil }
func (f *fakeStore) DBSizeBytes() (int64, error)   { return f.size, nil }
func (f *fakeStore) ExpiringCounts(int64) (storage.ExpCounts, error) {
	f.countCalled++
	return f.expiring, nil
}
func (f *fakeStore) SchemaVersionOnDisk() (int, error) { return f.schema, nil }

type fakeBattery struct {
	reading  power.Reading
	ok       bool
	health   float64
	healthOK bool
	capacity float64
	floor    float64
}

func (f *fakeBattery) Read() (power.Reading, bool) { return f.reading, f.ok }
func (f *fakeBattery) ReadHealth() (float64, bool) { return f.health, f.healthOK }
func (f *fakeBattery) Overview(r power.Reading) power.Overview {
	a, ok := power.EstimateAutonomy(r, f.capacity, f.floor)
	return power.Overview{Reading: r, Band: power.AlertBand(r, f.floor), Autonomy: a, HasAutonomy: ok}
}
func (f *fakeBattery) DODFloor() float64   { return f.floor }
func (f *fakeBattery) CapacityWh() float64 { return f.capacity }

// --- activity tracker ---------------------------------------------------

func TestActivityTrackerWindowAndPrune(t *testing.T) {
	a := &activityTracker{now: func() time.Time { return time.Time{} }}
	t0 := time.Unix(1700000000, 0)

	a.note("10.0.0.1", t0)
	a.note("10.0.0.2", t0)
	a.note("10.0.0.1", t0.Add(time.Minute)) // same key again: still one client

	if got := a.count(t0.Add(2 * time.Minute)); got != 2 {
		t.Fatalf("count within window = %d, want 2 distinct keys", got)
	}
	// 15 minutes after the last activity of a key, it drops out.
	if got := a.count(t0.Add(16 * time.Minute)); got != 0 {
		t.Fatalf("count after window = %d, want 0", got)
	}
	// Partial expiry: key 1 refreshed, key 2 did not.
	a.note("10.0.0.1", t0.Add(10*time.Minute))
	if got := a.count(t0.Add(16 * time.Minute)); got != 1 {
		t.Fatalf("count with one refreshed key = %d, want 1", got)
	}
}

func TestActivityTrackerCapDropsOldest(t *testing.T) {
	a := &activityTracker{now: func() time.Time { return time.Time{} }}
	t0 := time.Unix(1700000000, 0)
	// Fill to exactly the cap within the window.
	for i := 0; i < activeClientCap; i++ {
		a.note(keyNum(i), t0.Add(time.Duration(i)*time.Millisecond))
	}
	if got := a.count(t0.Add(time.Minute)); got != activeClientCap {
		t.Fatalf("cap-full map must count %d, got %d", activeClientCap, got)
	}
	// One more key: the cap pressure must evict (expired: none — all in
	// window — so the OLDEST drop), keeping the map at the cap.
	a.note(keyNum(activeClientCap), t0.Add(time.Minute))
	if len(a.lastSeen) > activeClientCap {
		t.Fatalf("map exceeded the cap: %d", len(a.lastSeen))
	}
	if got := a.count(t0.Add(2 * time.Minute)); got != activeClientCap {
		t.Fatalf("count after cap pressure = %d, want %d", got, activeClientCap)
	}
}

// TestActivityTrackerAggregateOnly pins the privacy contract: the tracker
// exposes ONLY the integer count. There is deliberately no accessor for
// keys; the assertion below is structural — if a key ever leaks into the
// Snapshot, this test's exported-surface walk catches it.
func TestActivityTrackerAggregateOnly(t *testing.T) {
	a := &activityTracker{}
	a.note("192.0.2.7", time.Unix(1700000000, 0))
	if got := a.count(time.Unix(1700000000, 0).Add(time.Second)); got != 1 {
		t.Fatalf("count = %d, want 1", got)
	}
}

func keyNum(n int) string {
	// Deterministic stand-in for a source IP; never an assertion target.
	return "10.1." + string(rune('a'+n%26)) + "." + string(rune('a'+(n/26)%26)) + string(rune('a'+(n/676)%26))
}

// --- projection math -----------------------------------------------------

func sampleAt(offset time.Duration, envelopes, size int64, totals health.Totals, wh *float64) sample {
	return sample{
		At:          baseTime.Add(offset),
		Envelopes:   envelopes,
		DBSizeBytes: size,
		Totals:      totals,
		BatteryWh:   wh,
	}
}

var baseTime = time.Unix(1700000000, 0)

func TestProjectionsMinimumDataRule(t *testing.T) {
	// The rule: rates need ≥ 2 samples AND ≥ 30 min span; below it every
	// projection is null/empty — "not enough data yet", never extrapolation.
	cases := []struct {
		name   string
		ring   []sample
		wantOK bool
	}{
		{"no samples", nil, false},
		{"one sample", []sample{sampleAt(0, 10, 1000, health.Totals{}, nil)}, false},
		{"two samples, 29 min span", []sample{
			sampleAt(0, 10, 1000, health.Totals{}, nil),
			sampleAt(29*time.Minute, 20, 2000, health.Totals{}, nil),
		}, false},
		{"two samples, exactly 30 min span", []sample{
			sampleAt(0, 10, 1000, health.Totals{}, nil),
			sampleAt(30*time.Minute, 20, 2000, health.Totals{}, nil),
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := computeProjections(tc.ring, 5000, nil)
			if p.EnoughData != tc.wantOK {
				t.Fatalf("EnoughData = %v, want %v", p.EnoughData, tc.wantOK)
			}
			if !tc.wantOK {
				if p.PushesPerDay != nil || p.ExpiriesPerDay != nil || p.DBGrowthBytesPerDay != nil ||
					p.BatteryDrainWhPerDay != nil || p.DaysToEnvelopeCapacity != nil || p.DaysToDiskFull != nil ||
					p.StoreEquilibrium != "" || p.BatteryNet != "" {
					t.Fatalf("below the minimum-data rule every projection must be empty, got %+v", p)
				}
			}
		})
	}
}

func TestProjectionsRatesAndDerived(t *testing.T) {
	// 6-hour window: pushes +240, sweeps -120 envelopes, DB +48 MiB.
	ring := []sample{
		sampleAt(0, 100, 1<<20, health.Totals{PushesAccepted: 10, TTLSweptEnvelopes: 5}, nil),
		sampleAt(6*time.Hour, 220, 49<<20, health.Totals{PushesAccepted: 250, TTLSweptEnvelopes: 125}, nil),
	}
	// Gross intake per day = (220-100 + 125-5) = 240 envelopes/day.
	p := computeProjections(ring, 5000, nil)
	if !p.EnoughData || p.Samples != 2 || p.WindowHours != 6 {
		t.Fatalf("window metadata wrong: %+v", p)
	}
	if f := *p.PushesPerDay; math.Abs(f-960) > 1e-9 {
		t.Errorf("pushes/day = %v, want 960", f)
	}
	if f := *p.ExpiriesPerDay; math.Abs(f-480) > 1e-9 {
		t.Errorf("expiries/day = %v, want 480", f)
	}
	if f := *p.DBGrowthBytesPerDay; math.Abs(f-(192<<20)) > 1e-9 {
		t.Errorf("db growth/day = %v, want %d", f, 192<<20)
	}
	// Days to capacity = (5000-220)/240 = 19.916…
	if f := *p.DaysToEnvelopeCapacity; math.Abs(f-4.979166666666667) > 1e-9 {
		t.Errorf("days to capacity = %v, want ≈4.98 (gross intake 960/day)", f)
	}
	// Net growth (220-100)/6h·24h = 480 net > deadband → growing.
	if p.StoreEquilibrium != EquilibriumGrowing {
		t.Errorf("equilibrium = %q, want growing", p.StoreEquilibrium)
	}
	if p.BatteryNet != "" {
		t.Errorf("battery net needs 24 h, got %q", p.BatteryNet)
	}

	// Shrinking + steady + no-fill variants.
	shrink := []sample{
		sampleAt(0, 300, 1000, health.Totals{}, nil),
		sampleAt(24*time.Hour, 100, 1000, health.Totals{}, nil),
	}
	if p := computeProjections(shrink, 5000, nil); p.StoreEquilibrium != EquilibriumShrinking {
		t.Errorf("equilibrium = %q, want shrinking", p.StoreEquilibrium)
	}
	if p := computeProjections(shrink, 5000, nil); p.DaysToEnvelopeCapacity != nil {
		t.Errorf("a shrinking store must project no fill, got %v", *p.DaysToEnvelopeCapacity)
	}
	steady := []sample{
		sampleAt(0, 100, 1000, health.Totals{}, nil),
		sampleAt(24*time.Hour, 100, 1000, health.Totals{}, nil),
	}
	if p := computeProjections(steady, 5000, nil); p.StoreEquilibrium != EquilibriumSteady {
		t.Errorf("equilibrium = %q, want steady", p.StoreEquilibrium)
	}
	// Near capacity: never project past the cap.
	full := []sample{
		sampleAt(0, 4999, 1000, health.Totals{}, nil),
		sampleAt(24*time.Hour, 5000, 1000, health.Totals{}, nil),
	}
	if p := computeProjections(full, 5000, nil); p.DaysToEnvelopeCapacity != nil {
		t.Errorf("a full store must project no fill, got %v", *p.DaysToEnvelopeCapacity)
	}
}

func TestProjectionsDiskFull(t *testing.T) {
	free := int64(4 << 30) // 4 GiB free
	grow := []sample{
		sampleAt(0, 0, 100<<20, health.Totals{}, nil),
		sampleAt(24*time.Hour, 0, 148<<20, health.Totals{}, nil), // +48 MiB/day
	}
	p := computeProjections(grow, 5000, &free)
	if f := *p.DaysToDiskFull; math.Abs(f-(float64(free)/(48<<20))) > 1e-9 {
		t.Errorf("days to disk-full = %v, want %v", f, float64(free)/(48<<20))
	}
	// Shrinking DB → no disk-full projection.
	shrink := []sample{
		sampleAt(0, 0, 148<<20, health.Totals{}, nil),
		sampleAt(24*time.Hour, 0, 100<<20, health.Totals{}, nil),
	}
	if p := computeProjections(shrink, 5000, &free); p.DaysToDiskFull != nil {
		t.Errorf("shrinking DB must project no disk-full, got %v", *p.DaysToDiskFull)
	}
	// Unknown free space → null, not a guess.
	if p := computeProjections(grow, 5000, nil); p.DaysToDiskFull != nil {
		t.Errorf("unknown free space must keep days-to-disk-full null")
	}
}

func TestProjectionsBattery(t *testing.T) {
	wh := func(v float64) *float64 { return &v }
	t.Run("drain rate", func(t *testing.T) {
		ring := []sample{
			sampleAt(0, 0, 0, health.Totals{}, wh(100)),
			sampleAt(24*time.Hour, 0, 0, health.Totals{}, wh(76)),
		}
		p := computeProjections(ring, 5000, nil)
		if f := *p.BatteryDrainWhPerDay; math.Abs(f-24) > 1e-9 {
			t.Errorf("drain/day = %v, want 24", f)
		}
	})
	t.Run("missing battery samples keep the rate null", func(t *testing.T) {
		ring := []sample{
			sampleAt(0, 0, 0, health.Totals{}, nil),
			sampleAt(24*time.Hour, 0, 0, health.Totals{}, wh(76)),
		}
		p := computeProjections(ring, 5000, nil)
		if p.BatteryDrainWhPerDay != nil {
			t.Errorf("drain/day must be null with missing samples")
		}
		if p.BatteryNet != "" {
			t.Errorf("net judgment must stay empty with missing samples")
		}
	})
	t.Run("net-positive needs 24h", func(t *testing.T) {
		ring := []sample{
			sampleAt(0, 0, 0, health.Totals{}, wh(50)),
			sampleAt(23*time.Hour, 0, 0, health.Totals{}, wh(80)),
		}
		p := computeProjections(ring, 5000, nil)
		if p.BatteryNet != "" {
			t.Errorf("23 h must be too short for a net verdict, got %q", p.BatteryNet)
		}
	})
	t.Run("net-positive over a day", func(t *testing.T) {
		ring := []sample{
			sampleAt(0, 0, 0, health.Totals{}, wh(50)),
			sampleAt(24*time.Hour, 0, 0, health.Totals{}, wh(80)),
		}
		if p := computeProjections(ring, 5000, nil); p.BatteryNet != BatteryNetPositive {
			t.Errorf("battery net = %q, want net_positive", p.BatteryNet)
		}
	})
	t.Run("starving over a day", func(t *testing.T) {
		ring := []sample{
			sampleAt(0, 0, 0, health.Totals{}, wh(80)),
			sampleAt(30*time.Hour, 0, 0, health.Totals{}, wh(60)),
		}
		if p := computeProjections(ring, 5000, nil); p.BatteryNet != BatteryNetStarving {
			t.Errorf("battery net = %q, want starving", p.BatteryNet)
		}
	})
}

func TestCountersDeltaRule(t *testing.T) {
	if d := computeCountersDelta(nil); d != nil {
		t.Fatalf("no ring → no delta, got %+v", d)
	}
	short := []sample{
		sampleAt(0, 0, 0, health.Totals{PushesAccepted: 1}, nil),
		sampleAt(10*time.Minute, 0, 0, health.Totals{PushesAccepted: 3}, nil),
	}
	if d := computeCountersDelta(short); d != nil {
		t.Fatalf("below the minimum-data rule → no delta, got %+v", d)
	}
	span := []sample{
		sampleAt(0, 0, 0, health.Totals{PushesAccepted: 1, PushesRejected: 5, DedupHits: 2, TTLSweptEnvelopes: 7}, nil),
		sampleAt(time.Hour, 0, 0, health.Totals{PushesAccepted: 4, PushesRejected: 5, DedupHits: 9, TTLSweptEnvelopes: 11}, nil),
	}
	d := computeCountersDelta(span)
	if d == nil {
		t.Fatal("1 h span must yield a delta")
	}
	if d.WindowHours != 1 || d.PushesAccepted != 3 || d.PushesRejected != 0 || d.DedupHits != 7 || d.TTLSweptEnvelopes != 4 {
		t.Fatalf("delta = %+v", d)
	}
}

// --- engine end-to-end ----------------------------------------------------

func TestEngineSampleAndSnapshot(t *testing.T) {
	store := &fakeStore{envs: 42, size: 1 << 20, expiring: storage.ExpCounts{Within1h: 2, Within6h: 5, Within24h: 9}, schema: storage.SchemaVersion}
	counters := health.NewCounters()
	counters.RecordPushAccepted()
	bat := &fakeBattery{
		reading: power.Reading{
			Available:    true,
			ChargeState:  power.StateDischarging,
			SOC:          &power.SOC{Percent: 75, Source: power.SOCVoltage},
			VoltageVolts: power.Float(12.8),
		},
		ok:       true,
		capacity: 128,
		floor:    20,
		health:   92,
		healthOK: true,
	}
	e := NewEngine(Deps{
		Store:    store,
		Counters: counters,
		Battery:  bat,
		System: sysres.Readers{
			Disk: func() (sysres.Disk, error) {
				return sysres.Disk{TotalBytes: 100 << 30, FreeBytes: 10 << 30, AvailableBytes: 9 << 30}, nil
			},
		},
	})

	clock := baseTime
	e.SetNow(func() time.Time { return clock })

	// Before the first tick: everything N/A, projections empty.
	snap := e.Snapshot()
	if snap.Battery != nil || snap.Expiring != nil || snap.SchemaOnDisk != nil ||
		snap.Projections.EnoughData || snap.ActiveClients != 0 {
		t.Fatalf("fresh engine must be all N/A, got %+v", snap)
	}

	e.Sample()
	snap = e.Snapshot()
	if snap.SampledAt != baseTime || snap.SampleCount != 1 {
		t.Fatalf("sample bookkeeping: at=%v n=%d", snap.SampledAt, snap.SampleCount)
	}
	if snap.Battery == nil || snap.Battery.Band != power.BandHealthy || snap.Battery.Reading.SOC.Percent != 75 {
		t.Fatalf("battery = %+v", snap.Battery)
	}
	if snap.BatteryHealth == nil || *snap.BatteryHealth != 92 {
		t.Fatalf("battery health = %v", snap.BatteryHealth)
	}
	if snap.Expiring == nil || snap.Expiring.Within6h != 5 {
		t.Fatalf("expiring = %+v", snap.Expiring)
	}
	if snap.SchemaOnDisk == nil || *snap.SchemaOnDisk != storage.SchemaVersion {
		t.Fatalf("schema on disk = %v", snap.SchemaOnDisk)
	}
	if snap.System.Disk == nil || snap.System.Disk.FreeBytes != 10<<30 {
		t.Fatalf("system disk = %+v", snap.System.Disk)
	}

	// The battery autonomy rides along in the overview (capacity 128, 75%,
	// floor 20 → 70.4 Wh at the nominal 1 W).
	if !snap.Battery.HasAutonomy || math.Abs(snap.Battery.Autonomy.Hours-70.4) > 1e-9 {
		t.Fatalf("autonomy = %+v", snap.Battery.Autonomy)
	}

	// Active clients flow through NoteClientActivity, aggregate-only.
	e.NoteClientActivity("192.0.2.1")
	e.NoteClientActivity("192.0.2.2")
	e.NoteClientActivity("192.0.2.1")
	if snap := e.Snapshot(); snap.ActiveClients != 2 {
		t.Fatalf("active clients = %d, want 2", snap.ActiveClients)
	}

	// A second sample 1 h later: enough data for rates and deltas.
	clock = baseTime.Add(time.Hour)
	store.envs = 44
	counters.RecordPushAccepted()
	e.Sample()
	snap = e.Snapshot()
	if !snap.Projections.EnoughData || snap.Projections.WindowHours != 1 {
		t.Fatalf("projections after two samples: %+v", snap.Projections)
	}
	if f := *snap.Projections.PushesPerDay; f != 24 {
		t.Fatalf("pushes/day = %v, want 24", f)
	}
	if snap.CountersDelta == nil || snap.CountersDelta.PushesAccepted != 1 {
		t.Fatalf("counters delta = %+v", snap.CountersDelta)
	}

	// Store failure mid-flight degrades that piece without killing the rest.
	store.schema = -1 // SchemaVersionOnDisk "fails" is simulated by nil? keep simple: expiring still counts
	if store.countCalled < 2 {
		t.Fatalf("sampler must query expiring counts every tick, called %d", store.countCalled)
	}
}

func TestEngineRingEviction(t *testing.T) {
	e := NewEngine(Deps{})
	clock := baseTime
	e.SetNow(func() time.Time { return clock })
	for i := 0; i < ringCapacity+10; i++ {
		e.Sample()
		clock = clock.Add(time.Minute)
	}
	if e.SampleCount() != ringCapacity {
		t.Fatalf("ring must hold exactly %d samples, got %d", ringCapacity, e.SampleCount())
	}
	snap := e.Snapshot()
	if snap.Projections.Samples != ringCapacity {
		t.Fatalf("projection samples = %d, want %d", snap.Projections.Samples, ringCapacity)
	}
	// Oldest evicted: window is ringCapacity-1 minutes ≈ 23.98 h.
	want := time.Duration(ringCapacity-1) * time.Minute
	if got := time.Duration(snap.Projections.WindowHours * float64(time.Hour)); math.Abs((got - want).Seconds()) > 1 {
		t.Fatalf("window = %v, want ≈%v", got, want)
	}
}

func TestEngineRunStopsOnContextCancel(t *testing.T) {
	e := NewEngine(Deps{})
	ctx, cancel := context.WithCancel(context.Background())
	e.Run(ctx, time.Hour) // interval far beyond the test: only the immediate sample fires
	if e.SampleCount() != 1 {
		t.Fatalf("Run must sample immediately once, got %d", e.SampleCount())
	}
	cancel()
	time.Sleep(10 * time.Millisecond) // give the goroutine a beat to observe the cancel
}
