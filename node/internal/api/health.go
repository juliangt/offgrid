// health.go — the diagnostics surface of issues #31 and #36: GET
// /api/v1/health (the machine-readable snapshot of docs/protocol.md §10.7)
// and GET /status (the human-readable field-node status view of the same
// data).
//
// Three properties are binding:
//
//   - Privacy (§13): the response is aggregates and node-local electrical/
//     thermal measurements only — no envelope id, no dest_hint, no alias,
//     no key, no payload fragment, no source address. The counters come
//     from internal/health (RAM-only, never persisted, never logged per
//     request), the store figures come from COUNT(*)-class queries that
//     never inspect row content, and the active-clients count is the ONE
//     integer an aggregate-only tracker exposes (internal/status/activity.go
//     — keys never leave it). This is reviewed and asserted by
//     TestHealthPrivacy.
//   - Boundedness: both endpoints answer from a snapshot cached in RAM for
//     healthCacheTTL, so a flood of GETs cannot turn the diagnostics surface
//     into the storage-DoS surface it reports on (at most one store refresh
//     per interval, whatever the request rate), and each client additionally
//     sits behind a small per-IP token budget (429 rate_limited + Retry-After
//     on exhaustion, same shape as the write paths). The document itself is a
//     fixed member set — no query parameters, no way to inflate the answer.
//     The NEW (issue #36) members are fed exclusively by the background
//     sampler of internal/status: the request path never reads /proc, never
//     runs vcgencmd, never touches a sensor.
//   - Honest N/A: every unavailable datum is JSON null (and the page's
//     "N/A"), never zeros and never a guess. Projections obey the
//     minimum-data rule: before the sampler's ring holds enough history the
//     page renders "not enough data yet" (null in the JSON twin).
//
// Liveness alignment: "status":"ok" means exactly one thing — the daemon
// process that systemd's sd_notify watchdog keeps alive (Type=notify,
// raspberry/systemd/dtn-node.service) is up and answering on this socket.
// No further health judgment is invented: a node has no TLS and no uplink BY
// DESIGN, and the sdnotify implementation holds no queryable runtime state
// (it sends fire-and-forget datagrams), so no watchdog detail is fabricated
// into the response.

package api

import (
	"fmt"
	"html/template"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"offgrid/dtn-node/internal/envelope"
	"offgrid/dtn-node/internal/status"
	"offgrid/dtn-node/internal/storage"
	"offgrid/dtn-node/internal/sysres"
)

// healthCacheTTL bounds how often the snapshot is refreshed from SQLite. One
// second: fresh enough to be operationally truthful (and well inside the
// < 50 ms budget, since serving is a mutex check plus a marshaled copy),
// coarse enough that even a request flood costs the store nothing.
const healthCacheTTL = time.Second

// healthNow is the clock the snapshot cache reads. Package var purely as a
// test hook (the maxEnvelopes pattern of the storage package); production
// code must never reassign it.
var healthNow = time.Now

// healthResponse is the GET /api/v1/health document (§10.7). The member set
// is exactly these eighteen top-level members (thirteen of #31 plus the five
// issue-#36 members); new members may only be added additively (§15.4) and
// MUST be ignored by clients. The four identity members (api, build,
// envelope_versions, schema_version) are filled from the very same sources
// as the §15.5 capabilities document — they can never diverge between the
// two endpoints because there is one source in code.
//
// N/A convention (§10.7, binding): the five #36 members are present at all
// times; an unavailable datum is JSON null (a null member object or a null
// field), and every present value is an aggregate integer, a node-local
// electrical/thermal measurement, or a projection number. Nothing here can
// link envelopes to users.
type healthResponse struct {
	Status                      string             `json:"status"`
	API                         string             `json:"api"`
	Build                       string             `json:"build"`
	EnvelopeVersions            []int64            `json:"envelope_versions"`
	SchemaVersion               int                `json:"schema_version"`
	UptimeSeconds               int64              `json:"uptime_seconds"`
	Envelopes                   int64              `json:"envelopes"`
	EnvelopeCapacity            int                `json:"envelope_capacity"`
	DirectoryEntries            int64              `json:"directory_entries"`
	DBSizeBytes                 int64              `json:"db_size_bytes"`
	LastCleanupUnix             int64              `json:"last_cleanup_unix"`
	LastCleanupEnvelopesDeleted int64              `json:"last_cleanup_envelopes_deleted"`
	Counters                    healthCountersJSON `json:"counters"`

	Battery     *batteryJSON     `json:"battery"`
	System      *systemJSON      `json:"system"`
	Software    *softwareJSON    `json:"software"`
	StoreStatus *storeJSON       `json:"store"`
	Projections *projectionsJSON `json:"projections"`

	// NodePlane is the P3.6 additive member (docs/node-network.md §8; null
	// when the node plane is off or no source is wired — the N/A convention).
	NodePlane *nodePlaneJSON `json:"node_plane"`
}

// healthCountersJSON is the "counters" member of the health document: the
// process-lifetime aggregates of internal/health. All RAM-only; every value
// resets to zero on restart by design (documented in §10.7).
type healthCountersJSON struct {
	PushesAccepted        int64                      `json:"pushes_accepted"`
	PushesRejected        int64                      `json:"pushes_rejected"`
	PushesRejectedByClass healthRejectionClassesJSON `json:"pushes_rejected_by_class"`
	DedupHits             int64                      `json:"dedup_hits"`
	TTLSweeps             int64                      `json:"ttl_sweeps"`
	TTLSweptEnvelopes     int64                      `json:"ttl_swept_envelopes"`
}

// healthRejectionClassesJSON breaks pushes_rejected down by the error code
// the sync endpoint answered (§10.1): invalid = any 400 shape, too_large =
// 413, rate_limited/node_full = the two 429 shapes, storage_unavailable = 507.
type healthRejectionClassesJSON struct {
	Invalid            int64 `json:"invalid"`
	RateLimited        int64 `json:"rate_limited"`
	NodeFull           int64 `json:"node_full"`
	StorageUnavailable int64 `json:"storage_unavailable"`
	TooLarge           int64 `json:"too_large"`
}

// batteryJSON is the "battery" member (issue #36): the node's power state
// from the reading chain I2C sensor → power_supply sysfs → voltage estimate
// → unknown. Null as a whole when no sensor answered (or no sampler is
// wired). voltage/current are node-local electrical measurements;
// soc_percent carries its provenance in soc_source so clients can label the
// accuracy ("voltage" = coarse on a LiFePO4 4S flat curve). autonomy_* is
// the projection down to the DoD floor at the measured (or nominal design)
// load, expressed in hours and 24-hour nights.
type batteryJSON struct {
	ChargeState     *string  `json:"charge_state"`
	SOCPercent      *float64 `json:"soc_percent"`
	SOCSource       *string  `json:"soc_source"`
	VoltageVolts    *float64 `json:"voltage_volts"`
	CurrentAmps     *float64 `json:"current_amps"`
	CapacityWh      *float64 `json:"capacity_wh"`
	DODFloorPercent float64  `json:"dod_floor_percent"`
	AlertBand       *string  `json:"alert_band"`
	AutonomyHours   *float64 `json:"autonomy_hours"`
	AutonomyNights  *float64 `json:"autonomy_nights"`
	AutonomyBasis   *string  `json:"autonomy_basis"`
	HealthPercent   *float64 `json:"health_percent"`
}

// systemJSON is the "system" member (issue #36): CPU load with the coarse
// saturation indicator, memory, the database volume's disk usage with the
// free-space floor warning, SoC temperature, throttle state and system
// uptime. Feature-detected on every host: members are null where the
// platform has no /proc, /sys thermal zone or vcgencmd.
type systemJSON struct {
	Load1               *float64 `json:"load1"`
	Load5               *float64 `json:"load5"`
	Load15              *float64 `json:"load15"`
	CPUSaturated        *bool    `json:"cpu_saturated"`
	MemTotalBytes       *int64   `json:"mem_total_bytes"`
	MemUsedBytes        *int64   `json:"mem_used_bytes"`
	MemAvailableBytes   *int64   `json:"mem_available_bytes"`
	DiskTotalBytes      *int64   `json:"disk_total_bytes"`
	DiskFreeBytes       *int64   `json:"disk_free_bytes"`
	DiskUsedBytes       *int64   `json:"disk_used_bytes"`
	DiskFreeLow         *bool    `json:"disk_free_low"`
	SOCTempCelsius      *float64 `json:"soc_temp_celsius"`
	CPUThrottled        *bool    `json:"cpu_throttled"`
	SystemUptimeSeconds *int64   `json:"system_uptime_seconds"`
}

// softwareJSON is the "software" member (issue #36): display-only identity
// beyond the §15.5 members — the storage schema actually on disk (PRAGMA
// user_version) and whether it diverges from this build's storage.SchemaVersion.
// In normal operation both are false-positive-free: the §15.3 migration
// completes before the daemon serves, so pending_migration is false; a true
// value would mean the store marker moved after boot (diagnose before
// touching anything). Display-only: no update checking, ever.
type softwareJSON struct {
	SchemaVersionOnDisk *int  `json:"schema_version_on_disk"`
	PendingMigration    *bool `json:"pending_migration"`
}

// storeJSON is the "store" member (issue #36): the expiring-soon TTL
// buckets (cumulative: Within24h ⊇ Within6h ⊇ Within1h), the aggregate
// active-clients count and the recent-window request-counter deltas.
// active_clients is the ONLY output of the aggregate-only tracker — no
// key, no address, no per-client anything.
type storeJSON struct {
	ExpiringWithin1h  *int64             `json:"expiring_within_1h"`
	ExpiringWithin6h  *int64             `json:"expiring_within_6h"`
	ExpiringWithin24h *int64             `json:"expiring_within_24h"`
	ActiveClients     *int64             `json:"active_clients"`
	CountersDelta     *countersDeltaJSON `json:"counters_delta"`
}

// countersDeltaJSON is the recent-window delta of the #31 request counters
// (null until the sampler's minimum-data rule is satisfied).
type countersDeltaJSON struct {
	WindowHours       float64 `json:"window_hours"`
	PushesAccepted    int64   `json:"pushes_accepted"`
	PushesRejected    int64   `json:"pushes_rejected"`
	DedupHits         int64   `json:"dedup_hits"`
	TTLSweptEnvelopes int64   `json:"ttl_swept_envelopes"`
}

// projectionsJSON is the "projections" member (issue #36): sliding-window
// rates and derived projections. The minimum-data rule is binding: before
// the sampler's ring holds ≥ 2 samples over ≥ 30 min, every numeric member
// is null and enough_data is false — the page renders "not enough data
// yet", never an extrapolation from nothing. The battery net judgment
// additionally requires a ≥ 24 h window. Members may still be null with
// enough_data true: that means "no fill/drain projected at the current
// rates" (e.g. a shrinking store never projects days-to-capacity).
type projectionsJSON struct {
	Samples                int      `json:"samples"`
	WindowHours            float64  `json:"window_hours"`
	EnoughData             bool     `json:"enough_data"`
	PushesPerDay           *float64 `json:"pushes_per_day"`
	ExpiriesPerDay         *float64 `json:"expiries_per_day"`
	DBGrowthBytesPerDay    *float64 `json:"db_growth_bytes_per_day"`
	BatteryDrainWhPerDay   *float64 `json:"battery_drain_wh_per_day"`
	DaysToEnvelopeCapacity *float64 `json:"days_to_envelope_capacity"`
	DaysToDiskFull         *float64 `json:"days_to_disk_full"`
	StoreEquilibrium       *string  `json:"store_equilibrium"`
	BatteryNet             *string  `json:"battery_net"`
}

// hasSystemReadings reports whether the sampler observed ANY system figure
// (the Readings struct holds func fields and is not comparable directly).
func hasSystemReadings(r sysres.Readings) bool {
	return r.Load != nil || r.Memory != nil || r.Disk != nil ||
		r.TempCelsius != nil || r.Throttled != nil || r.UptimeSeconds != nil
}

// statusFromSnapshot converts the sampler engine's RAM-cached snapshot into
// the §10.7 JSON members. Every datum the sampler could not observe stays
// nil (null on the wire). Pure mapping — trivially reviewable against the
// privacy rules.
func statusFromSnapshot(s *status.Snapshot) (*batteryJSON, *systemJSON, *softwareJSON, *storeJSON, *projectionsJSON) {
	if s == nil {
		return nil, nil, nil, nil, nil
	}

	var battery *batteryJSON
	if s.Battery != nil {
		b := &batteryJSON{DODFloorPercent: s.Battery.DODFloorPercent}
		rd := s.Battery.Reading
		if rd.ChargeState != "" {
			st := string(rd.ChargeState)
			b.ChargeState = &st
		}
		if rd.SOC != nil {
			b.SOCPercent = &rd.SOC.Percent
			src := string(rd.SOC.Source)
			b.SOCSource = &src
		}
		b.VoltageVolts = rd.VoltageVolts
		b.CurrentAmps = rd.CurrentAmps
		if cw := s.Battery.CapacityWh; cw > 0 {
			b.CapacityWh = &cw
		}
		if s.Battery.Band != "" {
			band := string(s.Battery.Band)
			b.AlertBand = &band
		}
		if s.Battery.HasAutonomy {
			h, n := s.Battery.Autonomy.Hours, s.Battery.Autonomy.Nights
			basis := s.Battery.Autonomy.Basis
			b.AutonomyHours, b.AutonomyNights, b.AutonomyBasis = &h, &n, &basis
		}
		b.HealthPercent = s.BatteryHealth
		battery = b
	}

	var system *systemJSON
	if hasSystemReadings(s.System) {
		sys := &systemJSON{}
		if l := s.System.Load; l != nil {
			one, five, fifteen := l.One, l.Five, l.Fifteen
			sys.Load1, sys.Load5, sys.Load15 = &one, &five, &fifteen
			sys.CPUSaturated = &l.Saturated
		}
		if m := s.System.Memory; m != nil {
			total, used, avail := m.TotalBytes, m.UsedBytes(), m.AvailableBytes
			sys.MemTotalBytes, sys.MemUsedBytes, sys.MemAvailableBytes = &total, &used, &avail
		}
		if d := s.System.Disk; d != nil {
			low := d.LowFree()
			used := d.UsedBytes()
			sys.DiskTotalBytes, sys.DiskFreeBytes = &d.TotalBytes, &d.FreeBytes
			sys.DiskUsedBytes = &used
			sys.DiskFreeLow = &low
		}
		sys.SOCTempCelsius = s.System.TempCelsius
		sys.CPUThrottled = s.System.Throttled
		sys.SystemUptimeSeconds = s.System.UptimeSeconds
		system = sys
	}

	var software *softwareJSON
	if s.SchemaOnDisk != nil {
		pending := *s.SchemaOnDisk != storage.SchemaVersion
		software = &softwareJSON{SchemaVersionOnDisk: s.SchemaOnDisk, PendingMigration: &pending}
	}

	var store *storeJSON
	if s.Expiring != nil || s.ActiveClients > 0 || s.CountersDelta != nil {
		store = &storeJSON{
			// The aggregate count is valid whenever the engine is wired
			// (0 = nobody active in the window) — it never depends on the
			// store being readable.
			ActiveClients: func() *int64 { c := int64(s.ActiveClients); return &c }(),
		}
		if s.Expiring != nil {
			h1, h6, h24 := s.Expiring.Within1h, s.Expiring.Within6h, s.Expiring.Within24h
			store.ExpiringWithin1h, store.ExpiringWithin6h, store.ExpiringWithin24h = &h1, &h6, &h24
		}
		if s.CountersDelta != nil {
			store.CountersDelta = &countersDeltaJSON{
				WindowHours:       s.CountersDelta.WindowHours,
				PushesAccepted:    s.CountersDelta.PushesAccepted,
				PushesRejected:    s.CountersDelta.PushesRejected,
				DedupHits:         s.CountersDelta.DedupHits,
				TTLSweptEnvelopes: s.CountersDelta.TTLSweptEnvelopes,
			}
		}
	}

	var proj *projectionsJSON
	{
		p := s.Projections
		proj = &projectionsJSON{
			Samples:     p.Samples,
			WindowHours: p.WindowHours,
			EnoughData:  p.EnoughData,
		}
		if p.EnoughData {
			proj.PushesPerDay = p.PushesPerDay
			proj.ExpiriesPerDay = p.ExpiriesPerDay
			proj.DBGrowthBytesPerDay = p.DBGrowthBytesPerDay
			proj.BatteryDrainWhPerDay = p.BatteryDrainWhPerDay
			proj.DaysToEnvelopeCapacity = p.DaysToEnvelopeCapacity
			proj.DaysToDiskFull = p.DaysToDiskFull
			if p.StoreEquilibrium != "" {
				eq := p.StoreEquilibrium
				proj.StoreEquilibrium = &eq
			}
			// BatteryNet may legitimately still be "" at enough_data: its
			// own window (24 h) is longer than the rate window.
			if p.BatteryNet != "" {
				net := p.BatteryNet
				proj.BatteryNet = &net
			}
		}
	}
	return battery, system, software, store, proj
}

// statusTemplate is the operator status view (GET /status): server-rendered
// from the same cached snapshot as /api/v1/health, plain HTML, zero
// JavaScript (it must render on the cheap captive-portal browser of any
// phone a field operator carries). The look is the portal's own stylesheet;
// the CSP keeps the same closed shape as index.html (no inline anything).
// The page deliberately carries NO link to or from the portal: the portal
// index never mentions /status, so ordinary visitors are never shown
// operational detail (§10.7). Every datum the node cannot observe renders
// as the literal "N/A"; every projection line names its window and the
// "projection" wording.
var statusTemplate = template.Must(template.New("status").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="referrer" content="no-referrer">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'self'">
  <title>Node status — offgrid</title>
  <link rel="stylesheet" href="/css/app.css">
</head>
<body>
<main>
  <h1>Node status</h1>
  <p class="hint">Operator view — not linked from the public portal. Machine-readable twin:
  <code>/api/v1/health</code>. Aggregates only: this page holds nothing about individual
  messages, senders, recipients or devices.</p>
  <div class="card">
    <h2>Node</h2>
    <dl>
      <dt>Status</dt><dd>{{.Snap.Status}}</dd>
      <dt>Process uptime</dt><dd>{{.UptimeText}} ({{.Snap.UptimeSeconds}} s)</dd>
    </dl>
  </div>
  <div class="card">
    <h2>Power &amp; battery</h2>
    <dl>
      <dt>Charge state</dt><dd>{{.BatteryStateText}}</dd>
      <dt>State of charge</dt><dd>{{.BatterySOCText}}</dd>
      <dt>Pack voltage</dt><dd>{{.BatteryVoltageText}}</dd>
      <dt>Current</dt><dd>{{.BatteryCurrentText}}</dd>
      <dt>Capacity (configured)</dt><dd>{{.BatteryCapacityText}}</dd>
      <dt>Alert band</dt><dd>{{.BatteryBandText}} — LOW is below the 30% overnight floor,
      CRITICAL at or below the 20% depth-of-discharge floor (docs/hardware.md §2.2, §8)</dd>
      <dt>Autonomy (projection)</dt><dd>{{.BatteryAutonomyText}}</dd>
      <dt>Battery health (wear)</dt><dd>{{.BatteryHealthText}}</dd>
    </dl>
    <p class="hint">Accuracy: voltage-derived state of charge is COARSE — a LiFePO4 4S pack
    discharges on a nearly flat curve, so mid-range readings can be off by tens of percent.
    Only a coulomb-counting BMS (power_supply capacity / I2C coulomb counter) is precise.
    The autonomy figure is a projection, never a promise.</p>
  </div>
  <div class="card">
    <h2>System</h2>
    <dl>
      <dt>Load average (1/5/15 min)</dt><dd>{{.LoadText}}</dd>
      <dt>CPU saturation</dt><dd>{{.SaturationText}}</dd>
      <dt>Memory</dt><dd>{{.MemoryText}}</dd>
      <dt>Disk (database volume)</dt><dd>{{.DiskText}}</dd>
      <dt>Disk free-space warning</dt><dd>{{.DiskWarningText}}</dd>
      <dt>SoC temperature</dt><dd>{{.TempText}}</dd>
      <dt>Throttling</dt><dd>{{.ThrottleText}}</dd>
      <dt>System uptime</dt><dd>{{.SysUptimeText}}</dd>
    </dl>
  </div>
  <div class="card">
    <h2>Software identity</h2>
    <dl>
      <dt>Build</dt><dd><code>{{.Snap.Build}}</code></dd>
      <dt>API</dt><dd>{{.Snap.API}} — envelope versions {{.VersionsText}}</dd>
      <dt>Storage schema version (this build)</dt><dd>{{.Snap.SchemaVersion}}</dd>
      <dt>Storage schema version (on disk)</dt><dd>{{.SchemaOnDiskText}}</dd>
      <dt>Pending migration</dt><dd>{{.PendingMigrationText}}</dd>
    </dl>
    <p class="hint">Display-only: the node has no uplink and performs no update checking.</p>
  </div>
  <div class="card">
    <h2>Store</h2>
    <dl>
      <dt>Envelopes held</dt><dd>{{.Snap.Envelopes}} / capacity {{.Snap.EnvelopeCapacity}}</dd>
      <dt>Expiring within 1 h / 6 h / 24 h</dt><dd>{{.ExpiringText}}</dd>
      <dt>Directory entries (registered users)</dt><dd>{{.Snap.DirectoryEntries}}</dd>
      <dt>Active clients (last 15 min, aggregate)</dt><dd>{{.ActiveClientsText}}</dd>
      <dt>Database size on disk</dt><dd>{{.DBSizeText}} ({{.Snap.DBSizeBytes}} bytes)</dd>
      <dt>Last cleanup</dt><dd>{{if .Snap.LastCleanupUnix}}{{.Snap.LastCleanupUnix}} (deleted {{.Snap.LastCleanupEnvelopesDeleted}}){{else}}none recorded since start{{end}}</dd>
    </dl>
  </div>
  <div class="card">
    <h2>Counters (since process start)</h2>
    <dl>
      <dt>Pushes accepted</dt><dd>{{.Snap.Counters.PushesAccepted}}</dd>
      <dt>Pushes rejected</dt><dd>{{.Snap.Counters.PushesRejected}} (invalid {{.Snap.Counters.PushesRejectedByClass.Invalid}}, rate-limited {{.Snap.Counters.PushesRejectedByClass.RateLimited}}, node full {{.Snap.Counters.PushesRejectedByClass.NodeFull}}, storage unavailable {{.Snap.Counters.PushesRejectedByClass.StorageUnavailable}}, too large {{.Snap.Counters.PushesRejectedByClass.TooLarge}})</dd>
      <dt>Dedup hits</dt><dd>{{.Snap.Counters.DedupHits}}</dd>
      <dt>TTL sweeps</dt><dd>{{.Snap.Counters.TTLSweeps}} ({{.Snap.Counters.TTLSweptEnvelopes}} envelopes swept)</dd>
      <dt>Recent window ({{.DeltasWindowText}})</dt><dd>{{.DeltasText}}</dd>
    </dl>
  </div>
  <div class="card">
    <h2>Node plane (issue #33)</h2>
    <dl>
      <dt>Provisioned role / level</dt><dd>{{.NodePlaneRoleText}}</dd>
      <dt>Bundle store (fill / cap)</dt><dd>{{.NodePlaneStoreText}}</dd>
      <dt>Pinned peers (count only — no identities)</dt><dd>{{.NodePlanePeersText}}</dd>
      <dt>Established sessions</dt><dd>{{.NodePlaneSessionsText}}</dd>
      <dt>Commands accepted (since process start)</dt><dd>{{.NodePlaneAcceptedText}}</dd>
      <dt>Commands dropped</dt><dd>{{.NodePlaneDroppedText}}</dd>
      <dt>Telemetry replies sent / received</dt><dd>{{.NodePlaneRepliesText}}</dd>
      <dt>Cert merges stale-dropped / conflicts</dt><dd>{{.NodePlaneCertText}}</dd>
    </dl>
    <p class="hint">Aggregates only: this card holds no node or peer identities, no command
    content and no per-user data (docs/protocol.md §10.7). Cert conflicts &gt; 0 mean two
    different certificates at one sequence — investigate before trusting the island.</p>
  </div>
  <div class="card">
    <h2>Load projections</h2>
    <p>{{.ProjectionsIntro}}</p>
    <dl>
      <dt>Pushes (projection)</dt><dd>{{.PushesRateText}}</dd>
      <dt>TTL expiries (projection)</dt><dd>{{.ExpiriesRateText}}</dd>
      <dt>Database growth (projection)</dt><dd>{{.DBGrowthText}}</dd>
      <dt>Battery drain (projection)</dt><dd>{{.BatteryDrainText}}</dd>
      <dt>Days to envelope capacity (projection)</dt><dd>{{.DaysToCapacityText}}</dd>
      <dt>Days to disk-full (projection)</dt><dd>{{.DaysToDiskFullText}}</dd>
      <dt>Store equilibrium (projection)</dt><dd>{{.EquilibriumText}}</dd>
      <dt>Battery over the multi-day window (projection)</dt><dd>{{.BatteryNetText}}</dd>
    </dl>
    <p class="hint">Every figure above is computed from a rolling in-RAM window since process
    start; a reboot clears it and the page honestly declines to extrapolate until the window
    refills. Projections describe the recent past continued forward — never a promise.</p>
  </div>
</main>
</body>
</html>
`))

// naText is the operator-page rendering of the JSON null convention.
const naText = "N/A"

// notEnoughDataText is the minimum-data rule's honest string.
const notEnoughDataText = "not enough data yet"

// statusView is the data the status template renders: the snapshot plus
// operator-friendly renderings computed once per request. Every new section
// arrives as a ready-to-print string so the template stays dumb and the N/A
// convention lives in exactly one place.
type statusView struct {
	Snap         *healthResponse
	VersionsText string
	UptimeText   string
	DBSizeText   string

	BatteryStateText    string
	BatterySOCText      string
	BatteryVoltageText  string
	BatteryCurrentText  string
	BatteryCapacityText string
	BatteryBandText     string
	BatteryAutonomyText string
	BatteryHealthText   string

	LoadText             string
	SaturationText       string
	MemoryText           string
	DiskText             string
	DiskWarningText      string
	TempText             string
	ThrottleText         string
	SysUptimeText        string
	SchemaOnDiskText     string
	PendingMigrationText string

	ExpiringText      string
	ActiveClientsText string
	DeltasWindowText  string
	DeltasText        string

	ProjectionsIntro   string
	PushesRateText     string
	ExpiriesRateText   string
	DBGrowthText       string
	BatteryDrainText   string
	DaysToCapacityText string
	DaysToDiskFullText string
	EquilibriumText    string
	BatteryNetText     string

	NodePlaneRoleText     string
	NodePlaneStoreText    string
	NodePlanePeersText    string
	NodePlaneSessionsText string
	NodePlaneAcceptedText string
	NodePlaneDroppedText  string
	NodePlaneRepliesText  string
	NodePlaneCertText     string
}

// buildStatusView pre-renders every template line from the snapshot (the
// N/A convention: null → "N/A"; minimum-data rule → "not enough data yet").
func buildStatusView(snap *healthResponse) statusView {
	v := statusView{
		Snap:         snap,
		VersionsText: joinInt64s(snap.EnvelopeVersions),
		UptimeText:   formatUptime(snap.UptimeSeconds),
		DBSizeText:   formatBytes(snap.DBSizeBytes),

		BatteryStateText:    naText,
		BatterySOCText:      naText,
		BatteryVoltageText:  naText,
		BatteryCurrentText:  naText,
		BatteryCapacityText: naText,
		BatteryBandText:     naText,
		BatteryAutonomyText: naText,
		BatteryHealthText:   naText,

		LoadText:         naText,
		SaturationText:   naText,
		MemoryText:       naText,
		DiskText:         naText,
		DiskWarningText:  naText,
		TempText:         naText,
		ThrottleText:     naText,
		SysUptimeText:    naText,
		SchemaOnDiskText: naText,

		PendingMigrationText: naText,
		ExpiringText:         naText,
		ActiveClientsText:    naText,
		DeltasWindowText:     "since process start",
		DeltasText:           naText,

		ProjectionsIntro:   notEnoughDataText + " — the sampler needs at least two samples over thirty minutes before any rate or projection is drawn.",
		PushesRateText:     notEnoughDataText,
		ExpiriesRateText:   notEnoughDataText,
		DBGrowthText:       notEnoughDataText,
		BatteryDrainText:   notEnoughDataText,
		DaysToCapacityText: notEnoughDataText,
		DaysToDiskFullText: notEnoughDataText,
		EquilibriumText:    notEnoughDataText,
		BatteryNetText:     notEnoughDataText,

		NodePlaneRoleText:     naText,
		NodePlaneStoreText:    naText,
		NodePlanePeersText:    naText,
		NodePlaneSessionsText: naText,
		NodePlaneAcceptedText: naText,
		NodePlaneDroppedText:  naText,
		NodePlaneRepliesText:  naText,
		NodePlaneCertText:     naText,
	}

	if snap.Battery != nil {
		b := snap.Battery
		if b.ChargeState != nil {
			v.BatteryStateText = *b.ChargeState
		}
		if b.SOCPercent != nil {
			txt := fmt.Sprintf("%.0f %%", *b.SOCPercent)
			if b.SOCSource != nil {
				switch *b.SOCSource {
				case "voltage":
					txt += " (voltage estimate — coarse)"
				case "coulomb":
					txt += " (BMS coulomb count)"
				}
			}
			v.BatterySOCText = txt
		}
		if b.VoltageVolts != nil {
			v.BatteryVoltageText = fmt.Sprintf("%.2f V", *b.VoltageVolts)
		}
		if b.CurrentAmps != nil {
			dir := "discharging"
			if *b.CurrentAmps > 0 {
				dir = "charging"
			}
			v.BatteryCurrentText = fmt.Sprintf("%.2f A (%s)", math.Abs(*b.CurrentAmps), dir)
		}
		if b.CapacityWh != nil {
			v.BatteryCapacityText = fmt.Sprintf("%.0f Wh", *b.CapacityWh)
		}
		if b.AlertBand != nil {
			v.BatteryBandText = *b.AlertBand
		}
		if b.AutonomyHours != nil && b.AutonomyNights != nil && b.AutonomyBasis != nil {
			load := "the nominal 1 W design load"
			if *b.AutonomyBasis == "measured" {
				load = "the measured draw"
			}
			v.BatteryAutonomyText = fmt.Sprintf("%.1f h (%.1f nights of autonomy) at %s", *b.AutonomyHours, *b.AutonomyNights, load)
		} else {
			v.BatteryAutonomyText = "N/A — configure -battery-capacity-wh (and a SoC source) to project"
		}
		if b.HealthPercent != nil {
			v.BatteryHealthText = fmt.Sprintf("%.0f %% of design capacity", *b.HealthPercent)
		}
	}

	if snap.System != nil {
		sys := snap.System
		if sys.Load1 != nil && sys.Load5 != nil && sys.Load15 != nil {
			v.LoadText = fmt.Sprintf("%.2f / %.2f / %.2f", *sys.Load1, *sys.Load5, *sys.Load15)
		}
		if sys.CPUSaturated != nil {
			v.SaturationText = boolText(*sys.CPUSaturated, "saturated (15-min load at or above the core count)", "not saturated")
		}
		if sys.MemTotalBytes != nil && sys.MemUsedBytes != nil && sys.MemAvailableBytes != nil {
			v.MemoryText = fmt.Sprintf("%s used / %s total (%s available)",
				formatBytes(*sys.MemUsedBytes), formatBytes(*sys.MemTotalBytes), formatBytes(*sys.MemAvailableBytes))
		}
		if sys.DiskTotalBytes != nil && sys.DiskFreeBytes != nil && sys.DiskUsedBytes != nil {
			v.DiskText = fmt.Sprintf("%s used / %s free / %s total",
				formatBytes(*sys.DiskUsedBytes), formatBytes(*sys.DiskFreeBytes), formatBytes(*sys.DiskTotalBytes))
		}
		if sys.DiskFreeLow != nil {
			v.DiskWarningText = boolText(*sys.DiskFreeLow,
				"LOW — under 50 MiB free on the database volume: check the SD card",
				"ok (50 MiB free floor)")
		}
		if sys.SOCTempCelsius != nil {
			v.TempText = fmt.Sprintf("%.1f °C", *sys.SOCTempCelsius)
		}
		if sys.CPUThrottled != nil {
			v.ThrottleText = boolText(*sys.CPUThrottled, "throttling observed since last clear", "no throttling")
		}
		if sys.SystemUptimeSeconds != nil {
			v.SysUptimeText = formatUptime(*sys.SystemUptimeSeconds)
		}
	}

	if snap.Software != nil {
		if snap.Software.SchemaVersionOnDisk != nil {
			v.SchemaOnDiskText = strconv.Itoa(*snap.Software.SchemaVersionOnDisk)
		}
		if snap.Software.PendingMigration != nil {
			v.PendingMigrationText = boolText(*snap.Software.PendingMigration, "YES — the on-disk schema diverges from this build", "no")
		}
	}

	if snap.StoreStatus != nil {
		st := snap.StoreStatus
		if st.ExpiringWithin1h != nil && st.ExpiringWithin6h != nil && st.ExpiringWithin24h != nil {
			v.ExpiringText = fmt.Sprintf("%d / %d / %d", *st.ExpiringWithin1h, *st.ExpiringWithin6h, *st.ExpiringWithin24h)
		}
		if st.ActiveClients != nil {
			v.ActiveClientsText = fmt.Sprintf("%d", *st.ActiveClients)
		}
		if d := st.CountersDelta; d != nil {
			v.DeltasWindowText = fmt.Sprintf("last %.1f h", d.WindowHours)
			v.DeltasText = fmt.Sprintf("accepted %d, rejected %d, dedup %d, swept %d",
				d.PushesAccepted, d.PushesRejected, d.DedupHits, d.TTLSweptEnvelopes)
		}
	}

	if snap.NodePlane != nil {
		np := snap.NodePlane
		if np.Role != nil && np.Level != nil {
			v.NodePlaneRoleText = fmt.Sprintf("%s / L%d", *np.Role, *np.Level)
		} else {
			v.NodePlaneRoleText = "no role certificate — mail works, management does not"
		}
		v.NodePlaneStoreText = fmt.Sprintf("%d / %d", np.StoreFill, np.StoreCap)
		v.NodePlanePeersText = fmt.Sprintf("%d", np.PeerCount)
		v.NodePlaneSessionsText = fmt.Sprintf("%d", np.ActiveSessions)
		v.NodePlaneAcceptedText = fmt.Sprintf("%d", np.Mgmt.CommandsAccepted)
		v.NodePlaneDroppedText = fmt.Sprintf(
			"by level %d, seq %d, signature/authority %d, expired %d, unknown %d, target %d, shape %d",
			np.Mgmt.DroppedByLevel, np.Mgmt.DroppedSeq, np.Mgmt.DroppedSig,
			np.Mgmt.DroppedExpired, np.Mgmt.DroppedUnknown, np.Mgmt.DroppedTarget, np.Mgmt.DroppedShape)
		v.NodePlaneRepliesText = fmt.Sprintf("%d / %d", np.Mgmt.RepliesSent, np.Mgmt.RepliesReceived)
		v.NodePlaneCertText = fmt.Sprintf("%d / %d", np.CertStaleDropped, np.CertConflicts)
	}

	if snap.Projections != nil {
		p := snap.Projections
		if p.EnoughData {
			v.ProjectionsIntro = fmt.Sprintf("Over the last %.1f h (%d samples). Projections — the recent window continued forward, never a promise.", p.WindowHours, p.Samples)
			v.PushesRateText = fmt.Sprintf("%.0f pushes/day", *p.PushesPerDay)
			v.ExpiriesRateText = fmt.Sprintf("%.0f TTL expiries/day", *p.ExpiriesPerDay)
			growth := "steady (±0)"
			if *p.DBGrowthBytesPerDay > 0 {
				growth = "+" + formatBytes(int64(*p.DBGrowthBytesPerDay)) + "/day"
			} else if *p.DBGrowthBytesPerDay < 0 {
				growth = "-" + formatBytes(int64(-*p.DBGrowthBytesPerDay)) + "/day"
			}
			v.DBGrowthText = growth
			if p.BatteryDrainWhPerDay != nil {
				switch {
				case *p.BatteryDrainWhPerDay > 0:
					v.BatteryDrainText = fmt.Sprintf("%.1f Wh/day", *p.BatteryDrainWhPerDay)
				case *p.BatteryDrainWhPerDay < 0:
					v.BatteryDrainText = fmt.Sprintf("%.1f Wh/day net gain (solar intake exceeds draw)", -*p.BatteryDrainWhPerDay)
				default:
					v.BatteryDrainText = "steady"
				}
			} else {
				v.BatteryDrainText = naText
			}
			if p.DaysToEnvelopeCapacity != nil {
				v.DaysToCapacityText = fmt.Sprintf("%.1f days at the current intake", *p.DaysToEnvelopeCapacity)
			} else {
				v.DaysToCapacityText = "no fill projected — the store is not growing at the current rates"
			}
			if p.DaysToDiskFull != nil {
				v.DaysToDiskFullText = fmt.Sprintf("%.1f days at the current growth", *p.DaysToDiskFull)
			} else {
				v.DaysToDiskFullText = "no fill projected — the database is not growing at the current rates"
			}
			v.EquilibriumText = *p.StoreEquilibrium
			if p.BatteryNet != nil {
				switch *p.BatteryNet {
				case "net_positive":
					v.BatteryNetText = "net-positive — solar intake exceeds draw over the window"
				case "starving":
					v.BatteryNetText = "STARVING — the battery lost charge over the window: check panel, sun and load"
				default:
					v.BatteryNetText = "steady over the window"
				}
			} else {
				v.BatteryNetText = notEnoughDataText + " — the net judgment needs a full 24 h of samples"
			}
		}
	}
	return v
}

// boolText renders a boolean with operator-friendly yes/no wording.
func boolText(b bool, yes, no string) string {
	if b {
		return yes
	}
	return no
}

// snapshot returns the cached health document, refreshing it from the store
// at most once per healthCacheTTL. On a store read failure the error is
// surfaced (507, the §10.1 clean shed): a stale snapshot silently freezing
// the numbers would lie to the operator diagnosing exactly that storage —
// truthful beats available here, and the endpoint stays cheap either way.
// The issue-#36 members are merged from the sampler engine's RAM state
// (never sampled here: no /proc read, no vcgencmd, no sensor in the request
// path).
func (s *server) snapshot() (*healthResponse, error) {
	s.healthMu.Lock()
	defer s.healthMu.Unlock()
	now := healthNow()
	if s.healthCache != nil && now.Sub(s.healthCachedAt) < healthCacheTTL {
		return s.healthCache, nil
	}
	envelopes, err := s.store.EnvelopeCount()
	if err != nil {
		return nil, err
	}
	directory, err := s.store.DirectoryCount()
	if err != nil {
		return nil, err
	}
	dbSize, err := s.store.DBSizeBytes()
	if err != nil {
		return nil, err
	}
	totals := s.counters.Totals()
	snap := &healthResponse{
		// "ok" is a liveness statement, not a health judgment: the node
		// answering IS the alive signal (§10.7). No TLS, no uplink, no
		// watchdog state is invented around it.
		Status:                      "ok",
		API:                         "v1",
		Build:                       s.build,
		EnvelopeVersions:            envelope.SupportedVersions,
		SchemaVersion:               storage.SchemaVersion,
		UptimeSeconds:               int64(time.Since(s.started).Seconds()),
		Envelopes:                   envelopes,
		EnvelopeCapacity:            storage.MaxEnvelopes(),
		DirectoryEntries:            directory,
		DBSizeBytes:                 dbSize,
		LastCleanupUnix:             totals.LastCleanupUnix,
		LastCleanupEnvelopesDeleted: totals.LastCleanupEnvelopesDeleted,
		Counters: healthCountersJSON{
			PushesAccepted: totals.PushesAccepted,
			PushesRejected: totals.PushesRejected,
			PushesRejectedByClass: healthRejectionClassesJSON{
				Invalid:            totals.RejectedInvalid,
				RateLimited:        totals.RejectedRateLimited,
				NodeFull:           totals.RejectedNodeFull,
				StorageUnavailable: totals.RejectedStorageUnavailable,
				TooLarge:           totals.RejectedTooLarge,
			},
			DedupHits:         totals.DedupHits,
			TTLSweeps:         totals.TTLSweeps,
			TTLSweptEnvelopes: totals.TTLSweptEnvelopes,
		},
	}
	var statusSnap *status.Snapshot
	if s.status != nil {
		ss := s.status.Snapshot()
		statusSnap = &ss
	}
	snap.Battery, snap.System, snap.Software, snap.StoreStatus, snap.Projections = statusFromSnapshot(statusSnap)
	if s.nodePlane != nil {
		snap.NodePlane = nodePlaneFromSnapshot(s.nodePlane.NodePlaneSnapshot())
	}
	s.healthCache = snap
	s.healthCachedAt = now
	return snap, nil
}

// withHealthBudget wraps both diagnostics handlers in the per-IP health
// budget (burst 60, refill 1 request/second — generous for an operator
// polling from a phone, exhausting under any scripted flood). Exhaustion
// answers 429 rate_limited with Retry-After, exactly like the write paths.
// One budget covers both endpoints: they are one diagnostics surface. The
// diagnostics GETs deliberately do NOT feed the active-clients aggregate:
// an operator polling the status page is the observer, not a portal
// session, and the count must not include them.
func (s *server) withHealthBudget(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if ok, wait := s.healthBudget.allow(clientKey(r), 1); !ok {
			writeRateLimited(w, wait)
			return
		}
		next(w, r)
	}
}

// handleHealth serves the machine-readable snapshot (§10.7).
func (s *server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	snap, err := s.snapshot()
	if err != nil {
		writeError(w, http.StatusInsufficientStorage, codeStorageUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, snap)
}

// handleStatus serves the operator status view (§10.7): the same cached
// snapshot, server-rendered as static HTML. An unavailable store answers the
// same 507 shed as the JSON endpoint.
func (s *server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	snap, err := s.snapshot()
	if err != nil {
		writeError(w, http.StatusInsufficientStorage, codeStorageUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	_ = statusTemplate.Execute(w, buildStatusView(snap)) // fixed-shape data; cannot fail mid-body in practice
}

// joinInt64s renders a version slice as "1, 2" for the status page.
func joinInt64s(xs []int64) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = strconv.FormatInt(x, 10)
	}
	return strings.Join(parts, ", ")
}

// formatUptime renders seconds as "Nd HH:MM:SS" (or "HH:MM:SS" under a day)
// for the status page.
func formatUptime(seconds int64) string {
	d := seconds / 86400
	rem := seconds % 86400
	h, m, sec := rem/3600, (rem%3600)/60, rem%60
	body := fmt.Sprintf("%02d:%02d:%02d", h, m, sec)
	if d > 0 {
		return fmt.Sprintf("%dd %s", d, body)
	}
	return body
}

// formatBytes renders a byte count in binary units (B / KiB / MiB / GiB) for
// the status page.
func formatBytes(n int64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	v := float64(n)
	i := 0
	for v >= 1024 && i < len(units)-1 {
		v /= 1024
		i++
	}
	if i == 0 {
		return strconv.FormatInt(n, 10) + " B"
	}
	if v == math.Trunc(v) {
		return strconv.FormatInt(int64(v), 10) + " " + units[i]
	}
	return fmt.Sprintf("%.1f", v) + " " + units[i]
}
