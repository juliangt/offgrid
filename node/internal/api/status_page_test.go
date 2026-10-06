package api

// status_page_test.go — the field status extensions of issue #36
// (docs/protocol.md §10.7): the additive JSON members with the sampler
// engine wired (and the N/A convention without it), the extended operator
// page (all cards render, zero JS, N/A on a sensor-less macOS-style host),
// the minimum-data rule across the HTTP surface, the aggregate-only
// active-clients count, and the privacy of every new member.

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"offgrid/dtn-node/internal/envelope"
	"offgrid/dtn-node/internal/health"
	"offgrid/dtn-node/internal/power"
	"offgrid/dtn-node/internal/status"
	"offgrid/dtn-node/internal/storage"
	"offgrid/dtn-node/internal/sysres"
)

// scriptedBattery is a scripted status.BatteryReader backed by the REAL
// power math (band, autonomy), so the handler mapping is tested against the
// genuine formulas, not a parallel copy.
type scriptedBattery struct {
	state      power.ChargeState
	soc        *power.SOC
	volts      *float64
	amps       *float64
	capacityWh float64
	floor      float64
}

func (b *scriptedBattery) Read() (power.Reading, bool) {
	rd := power.Reading{Available: true, ChargeState: b.state, SOC: b.soc, VoltageVolts: b.volts, CurrentAmps: b.amps}
	return rd, true
}
func (b *scriptedBattery) ReadHealth() (float64, bool) { return 0, false }
func (b *scriptedBattery) Overview(r power.Reading) power.Overview {
	a, ok := power.EstimateAutonomy(r, b.capacityWh, b.floor)
	return power.Overview{
		Reading:         r,
		Band:            power.AlertBand(r, b.floor),
		Autonomy:        a,
		HasAutonomy:     ok,
		DODFloorPercent: b.floor,
		CapacityWh:      b.capacityWh,
	}
}
func (b *scriptedBattery) DODFloor() float64   { return b.floor }
func (b *scriptedBattery) CapacityWh() float64 { return b.capacityWh }

// statusTestHandler wires a server WITH a sampler engine over the given
// battery/system readers (nil battery = the no-hardware node), sharing the
// store and counters exactly as main() does.
func statusTestHandler(t *testing.T, battery status.BatteryReader, system sysres.Readers) (http.Handler, *storage.Store, *status.Engine) {
	t.Helper()
	s, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	counters := health.NewCounters()
	engine := status.NewEngine(status.Deps{Store: s, Counters: counters, Battery: battery, System: system})
	h, err := NewWithCounters(s, counters, testBuild, testWebFS, WithStatusEngine(engine))
	if err != nil {
		t.Fatalf("build handler: %v", err)
	}
	return h, s, engine
}

// TestStatusPageAllSectionsRenderNA pins the stock-node case (no hardware,
// no engine data yet — the macOS dev box and a fresh Pi alike): the page
// renders every issue-#36 card with N/A where nothing is observable, keeps
// the CSP, keeps zero JS, and shows the honest "not enough data yet" for
// the projections.
func TestStatusPageAllSectionsRenderNA(t *testing.T) {
	h, _ := newTestHandler(t)
	code, header, body := getHealth(t, h, "/status")
	if code != http.StatusOK {
		t.Fatalf("got %d (body: %s)", code, body)
	}
	if !strings.Contains(body, `http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'self'"`) {
		t.Fatal("the status page must keep the closed CSP meta tag (no inline anything)")
	}
	_ = header
	if strings.Contains(body, "<script") {
		t.Fatal("the status page must require no JavaScript")
	}
	for _, want := range []string{
		"Node status",
		"Power &amp; battery",
		"System",
		"Software identity",
		"Store",
		"Counters (since process start)",
		"Load projections",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("status page must carry the %q section", want)
		}
	}
	// Everything unavailable: N/A everywhere in the new cards.
	if got := strings.Count(body, "N/A"); got < 12 {
		t.Errorf("a sensor-less node must render N/A liberally, found %d", got)
	}
	// The minimum-data rule's honest string on a fresh sampler.
	if !strings.Contains(body, "not enough data yet") {
		t.Error(`projections must read "not enough data yet" before the minimum-data rule is satisfied`)
	}
}

// TestHealthStatusWithBatteryAndSystem drives the full engine: a scripted
// battery (discharging at a measured draw), fixture system collectors,
// seeded expiring envelopes and two active clients — every new member
// filled and truthful, the projections honestly empty until the window
// refills.
func TestHealthStatusWithBatteryAndSystem(t *testing.T) {
	volts, amps := 12.4, -0.35
	battery := &scriptedBattery{
		state:      power.StateDischarging,
		soc:        &power.SOC{Percent: 42, Source: power.SOCVoltage},
		volts:      &volts,
		amps:       &amps,
		capacityWh: 128,
		floor:      20,
	}
	system := sysres.Readers{
		LoadAvg:    func() ([]byte, error) { return []byte("0.10 0.20 0.30 1/50 1"), nil },
		MemInfo:    func() ([]byte, error) { return []byte("MemTotal: 100 kB\nMemAvailable: 60 kB\n"), nil },
		UptimeFile: func() ([]byte, error) { return []byte("7200.5 7200.5\n"), nil },
		Temp:       func() ([]byte, error) { return []byte("47500"), nil },
		Throttled:  func() ([]byte, error) { return []byte("throttled=0x0"), nil },
		Disk: func() (sysres.Disk, error) {
			return sysres.Disk{TotalBytes: 16 << 30, FreeBytes: 1 << 30, AvailableBytes: 1 << 30}, nil
		},
	}
	h, store, engine := statusTestHandler(t, battery, system)

	// Seed one envelope expiring 30 minutes after the ENGINE clock instant
	// (bucket: 1h/6h/24h) and one beyond 24 h (no bucket). The sampler
	// evaluates the buckets at its own pinned clock, so the rows are cut to
	// that instant, not to time.Now().
	t0 := time.Unix(1700000000, 0)
	engine.SetNow(func() time.Time { return t0 })
	envSoon := validEnv(hexID(301), t0.Unix()-600)
	envSoon.TTL = 2400 // expires at t0+1800 → 30 min out
	envFar := validEnv(hexID(302), t0.Unix()-600)
	envFar.TTL = 25*3600 + 600 // expires at t0+25 h → no bucket
	if inserted, err := store.InsertEnvelopes([]envelope.Envelope{envSoon, envFar}); err != nil || inserted != 2 {
		t.Fatalf("seed: inserted %d err=%v", inserted, err)
	}

	// Two distinct clients do things (pull-only sync POSTs — the diagnostics
	// GETs deliberately do not count as portal activity).
	if rec := postJSON(t, h, "/api/v1/sync", map[string]any{}); rec.Code != http.StatusOK {
		t.Fatalf("sync: got %d", rec.Code)
	}
	if rec := syncBodyFrom(t, h, "198.51.100.55", nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("sync from second client: got %d", rec.Code)
	}

	engine.Sample()
	// Bust the 1 s snapshot cache so the assertions read the post-sample state.
	defer overrideHealthNow(func() time.Time { return time.Now().Add(time.Second) })()
	code, _, body := getHealth(t, h, "/api/v1/health")
	if code != http.StatusOK {
		t.Fatalf("health: got %d (body: %s)", code, body)
	}
	hr := decodeHealthBody(t, body)

	// Battery: discharging at 42% (voltage estimate — HEALTHY at ≥ 30),
	// measured draw, autonomy down to the DoD floor.
	if hr.Battery == nil {
		t.Fatal("battery member must be filled with a reading chain present")
	}
	b := hr.Battery
	if b.ChargeState == nil || *b.ChargeState != "discharging" {
		t.Errorf("charge_state = %v, want discharging", b.ChargeState)
	}
	if b.SOCPercent == nil || *b.SOCPercent != 42 {
		t.Errorf("soc_percent = %v, want 42", b.SOCPercent)
	}
	if b.SOCSource == nil || *b.SOCSource != "voltage" {
		t.Errorf("soc_source = %v, want voltage", b.SOCSource)
	}
	if b.VoltageVolts == nil || *b.VoltageVolts != 12.4 {
		t.Errorf("voltage = %v, want 12.4", b.VoltageVolts)
	}
	if b.CurrentAmps == nil || *b.CurrentAmps != -0.35 {
		t.Errorf("current = %v, want -0.35", b.CurrentAmps)
	}
	if b.CapacityWh == nil || *b.CapacityWh != 128 {
		t.Errorf("capacity = %v, want 128", b.CapacityWh)
	}
	if b.DODFloorPercent != 20 {
		t.Errorf("dod floor = %v, want 20", b.DODFloorPercent)
	}
	if b.AlertBand == nil || *b.AlertBand != "HEALTHY" {
		t.Errorf("band = %v, want HEALTHY (42 ≥ 30)", b.AlertBand)
	}
	if b.AutonomyBasis == nil || *b.AutonomyBasis != "measured" {
		t.Errorf("autonomy basis = %v, want measured (current fixture present)", b.AutonomyBasis)
	}
	// reserve = (42-20)/100 × 128 Wh = 28.16 Wh at the measured 4.34 W.
	wantHours := 28.16 / (12.4 * 0.35)
	if b.AutonomyHours == nil || diff(*b.AutonomyHours, wantHours) > 1e-9 {
		t.Errorf("autonomy hours = %v, want %v", b.AutonomyHours, wantHours)
	}

	// System figures.
	if hr.System == nil {
		t.Fatal("system member must be filled with collectors present")
	}
	sys := hr.System
	if sys.Load15 == nil || *sys.Load15 != 0.30 || sys.CPUSaturated == nil || *sys.CPUSaturated {
		t.Errorf("load/saturation = %+v", sys)
	}
	if sys.MemUsedBytes == nil || *sys.MemUsedBytes != 40*1024 {
		t.Errorf("mem used = %v, want 40960", sys.MemUsedBytes)
	}
	if sys.DiskFreeBytes == nil || *sys.DiskFreeBytes != 1<<30 {
		t.Errorf("disk free = %v", sys.DiskFreeBytes)
	}
	if sys.DiskFreeLow == nil || *sys.DiskFreeLow {
		t.Errorf("disk_free_low = %v, want false (1 GiB above the 50 MiB floor)", sys.DiskFreeLow)
	}
	if sys.SOCTempCelsius == nil || diff(*sys.SOCTempCelsius, 47.5) > 1e-9 {
		t.Errorf("temp = %v, want 47.5", sys.SOCTempCelsius)
	}
	if sys.CPUThrottled == nil || *sys.CPUThrottled {
		t.Errorf("throttled = %v, want false", sys.CPUThrottled)
	}
	if sys.SystemUptimeSeconds == nil || *sys.SystemUptimeSeconds != 7200 {
		t.Errorf("system uptime = %v, want 7200", sys.SystemUptimeSeconds)
	}

	// Software identity: on-disk schema current, nothing pending.
	if hr.Software == nil || hr.Software.SchemaVersionOnDisk == nil || hr.Software.PendingMigration == nil {
		t.Fatal("software member must be filled")
	}
	if *hr.Software.SchemaVersionOnDisk != storage.SchemaVersion || *hr.Software.PendingMigration {
		t.Errorf("software = on-disk %d pending %v, want %d/false",
			*hr.Software.SchemaVersionOnDisk, *hr.Software.PendingMigration, storage.SchemaVersion)
	}

	// Store: expiring buckets + the aggregate active-clients count.
	if hr.StoreStatus == nil {
		t.Fatal("store member must be filled once sampled")
	}
	st := hr.StoreStatus
	if st.ExpiringWithin1h == nil || *st.ExpiringWithin1h != 1 ||
		*st.ExpiringWithin6h != 1 || *st.ExpiringWithin24h != 1 {
		t.Errorf("expiring buckets = %+v, want 1/1/1", st)
	}
	if st.ActiveClients == nil || *st.ActiveClients != 2 {
		t.Errorf("active clients = %v, want 2 (sync POST + health GET from distinct IPs)", st.ActiveClients)
	}
	if st.CountersDelta != nil {
		t.Errorf("counters delta before enough data = %+v, want nil", st.CountersDelta)
	}

	// Projections: minimum-data rule visible on the JSON twin.
	if hr.Projections == nil || hr.Projections.EnoughData {
		t.Fatalf("projections must start not-enough-data, got %+v", hr.Projections)
	}
	if hr.Projections.PushesPerDay != nil || hr.Projections.DaysToDiskFull != nil || hr.Projections.StoreEquilibrium != nil {
		t.Errorf("below the minimum-data rule every projection must be null, got %+v", hr.Projections)
	}

	// The page renders the same reality, and leaks no identity.
	code, _, page := getHealth(t, h, "/status")
	if code != http.StatusOK {
		t.Fatalf("status: got %d", code)
	}
	for _, want := range []string{
		"discharging",
		"42 %",                // state of charge
		"HEALTHY",             // band
		"6.5 h",               // autonomy
		"0.3 nights",          // nights of autonomy
		"47.5 °C",             // SoC temperature
		"not enough data yet", // projections
		"1 / 1 / 1",           // expiring buckets
	} {
		if !strings.Contains(page, want) {
			t.Errorf("status page must show %q", want)
		}
	}
	for _, secret := range []string{"198.51.100.55", "192.0.2.1"} {
		if strings.Contains(page, secret) || strings.Contains(body, secret) {
			t.Errorf("a client address leaked into the diagnostics surface (%q)", secret)
		}
	}
}

func diff(a, b float64) float64 {
	if a > b {
		return a - b
	}
	return b - a
}

// TestStatusProjectionsBecomeNumbers drives the sampler across a ≥ 30 min
// window and verifies the projections turn from "not enough data yet" into
// windowed numbers on both the JSON and the page (the test-only seam:
// engine.SetNow, never a production flag).
func TestStatusProjectionsBecomeNumbers(t *testing.T) {
	h, store, engine := statusTestHandler(t, nil, sysres.Readers{})
	clock := time.Unix(1700000000, 0)
	engine.SetNow(func() time.Time { return clock })

	engine.Sample() // empty store
	now := time.Now().Unix()
	if _, err := store.InsertEnvelopes([]envelope.Envelope{validEnv(hexID(401), now)}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	clock = clock.Add(2 * time.Hour)
	engine.Sample()

	_, _, body := getHealth(t, h, "/api/v1/health")
	hr := decodeHealthBody(t, body)
	p := hr.Projections
	if p == nil || !p.EnoughData || p.WindowHours != 2 {
		t.Fatalf("projections after a 2 h window: %+v", p)
	}
	// No pushes were recorded, so the push rate is 0/day — a number, not a guess.
	if p.PushesPerDay == nil || *p.PushesPerDay != 0 {
		t.Fatalf("pushes/day = %v, want 0 (recorded deltas, not rows)", p.PushesPerDay)
	}
	// Gross intake = net (1 envelope / 2 h = 12/day) + 0 expiries.
	if p.DaysToEnvelopeCapacity == nil || diff(*p.DaysToEnvelopeCapacity, 4999.0/12.0) > 1e-9 {
		t.Fatalf("days to capacity = %v, want %.2f", p.DaysToEnvelopeCapacity, 4999.0/12.0)
	}
	if p.StoreEquilibrium == nil || *p.StoreEquilibrium != "growing" {
		t.Errorf("equilibrium = %v, want growing (1 envelope net over the window)", p.StoreEquilibrium)
	}
	// Disk collector absent (nil readers): the projection stays null —
	// honest N/A, never a guess from unknown free space.
	if p.DaysToDiskFull != nil {
		t.Errorf("days-to-disk-full must stay null with unknown free space, got %v", *p.DaysToDiskFull)
	}

	_, _, page := getHealth(t, h, "/status")
	if !strings.Contains(page, "Over the last 2.0 h") {
		t.Errorf("the page must label the projection window, got: %.200s", page)
	}
	// The rate lines are numbers now; only the battery net judgment (its own
	// 24 h rule) still honestly reports not-enough-data.
	if !strings.Contains(page, "<dd>0 pushes/day</dd>") {
		t.Error("the pushes projection must be a number after the window fills")
	}
	if !strings.Contains(page, "needs a full 24 h") {
		t.Error("the battery net judgment must keep asking for its 24 h window")
	}
}

// TestActiveClientsAggregateOnly pins the aggregate-only guarantee at the
// HTTP surface: many requests from one IP collapse to count 1, and the
// document never contains the address or any per-client datum.
func TestActiveClientsAggregateOnly(t *testing.T) {
	h, _, engine := statusTestHandler(t, nil, sysres.Readers{})
	engine.SetNow(func() time.Time { return time.Unix(1700000000, 0) })

	for i := 0; i < 5; i++ {
		if rec := syncBodyFrom(t, h, "203.0.113.77", nil, nil); rec.Code != http.StatusOK {
			t.Fatalf("sync: got %d", rec.Code)
		}
	}
	if got := engine.Snapshot().ActiveClients; got != 1 {
		t.Fatalf("active clients = %d, want exactly 1 (five requests, one client)", got)
	}
	// Bust the snapshot cache and verify the served document too.
	defer overrideHealthNow(func() time.Time { return time.Now().Add(time.Second) })()
	code, _, body := getHealth(t, h, "/api/v1/health")
	if code != http.StatusOK {
		t.Fatalf("health: got %d", code)
	}
	hr := decodeHealthBody(t, body)
	if hr.StoreStatus == nil || hr.StoreStatus.ActiveClients == nil || *hr.StoreStatus.ActiveClients != 1 {
		t.Fatalf("active clients = %+v, want 1", hr.StoreStatus)
	}
	if strings.Contains(body, "203.0.113.77") {
		t.Fatal("the tracker's key leaked into the document — aggregate-only violated")
	}
}

// TestBudgetShedClientStillActive verifies a client shed by the health
// budget still counts as active: activity is observed where the key is
// already handled, before admission.
func TestBudgetShedClientStillActive(t *testing.T) {
	// Burst 1, no refill: the second sync from the same IP is shed at the
	// budget boundary — but activity was already observed where the key is
	// handled, before admission.
	restore := overrideAdmissionLimits(1, time.Hour, syncEnvelopeBurst, syncEnvelopeRefillPerHour, bucketEvictionFloor, bucketIdleTTL)
	defer restore()
	h, _, engine := statusTestHandler(t, nil, sysres.Readers{})
	engine.SetNow(func() time.Time { return time.Unix(1700000000, 0) })

	if rec := syncBodyFrom(t, h, "198.51.100.9", nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("first sync: got %d", rec.Code)
	}
	if rec := syncBodyFrom(t, h, "198.51.100.9", nil, nil); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second sync: got %d, want 429", rec.Code)
	}
	if got := engine.Snapshot().ActiveClients; got != 1 {
		t.Fatalf("a shed client is still an active client, got %d", got)
	}
}

// overridingStore wraps a real store and pins SchemaVersionOnDisk to a
// chosen value — the seam that makes the §15.3-impossible divergence
// observable in a test (Open migrates before serving, so the only way the
// flag can ever be true is the mapping below).
type overridingStore struct {
	*storage.Store
	schema int
}

func (o *overridingStore) SchemaVersionOnDisk() (int, error) { return o.schema, nil }

// TestPendingMigrationFlagTrueOnDivergence verifies the display-only flag:
// on-disk marker behind the build → pending_migration true; current → false.
func TestPendingMigrationFlagTrueOnDivergence(t *testing.T) {
	s, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	counters := health.NewCounters()
	engine := status.NewEngine(status.Deps{Store: &overridingStore{Store: s, schema: storage.SchemaVersion - 1}, Counters: counters})
	engine.Sample()
	snap := engine.Snapshot()
	if snap.SchemaOnDisk == nil || *snap.SchemaOnDisk != storage.SchemaVersion-1 {
		t.Fatalf("schema on disk = %v, want %d", snap.SchemaOnDisk, storage.SchemaVersion-1)
	}
	h, err := NewWithCounters(&overridingStore{Store: s, schema: storage.SchemaVersion - 1}, counters, testBuild, testWebFS, WithStatusEngine(engine))
	if err != nil {
		t.Fatalf("build handler: %v", err)
	}
	_, _, body := getHealth(t, h, "/api/v1/health")
	hr := decodeHealthBody(t, body)
	if hr.Software == nil || hr.Software.SchemaVersionOnDisk == nil || hr.Software.PendingMigration == nil {
		t.Fatalf("software member = %+v, want filled", hr.Software)
	}
	if *hr.Software.SchemaVersionOnDisk != storage.SchemaVersion-1 || !*hr.Software.PendingMigration {
		t.Fatalf("pending_migration must be true when on-disk (%d) diverges from the build (%d)",
			*hr.Software.SchemaVersionOnDisk, storage.SchemaVersion)
	}
}
