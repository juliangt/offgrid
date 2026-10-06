// projections.go — the load projections of the field status page
// (issue #36, docs/protocol.md §10.7): sliding-window rates and derived
// projections computed from the RAM-only ring buffers, each labelled with
// its window and never presented as a promise.
//
// The MINIMUM-DATA RULE is binding: until the ring holds at least
// minRateSamples samples spanning at least minRateWindow, every numeric
// projection is null — the page renders the honest string "not enough
// data yet" instead of extrapolating from nothing. The battery
// net-positive/starving judgment is held to an even higher bar (a full
// multi-day window, minBatteryNetWindow) because one cloudy afternoon
// would otherwise look like starvation.

package status

import (
	"time"

	"offgrid/dtn-node/internal/power"
	"offgrid/dtn-node/internal/storage"
	"offgrid/dtn-node/internal/sysres"
)

// Projection rule constants (documented in §10.7).
const (
	// minRateSamples is the fewest ring samples any rate is computed from.
	minRateSamples = 2
	// minRateWindow is the shortest span rates are computed over: half an
	// hour of one-minute samples. Below it, "not enough data yet".
	minRateWindow = 30 * time.Minute
	// minBatteryNetWindow is the span the battery net judgment needs: the
	// hardware acceptance rule of docs/hardware.md §8 is defined over a
	// full day (net-positive by evening, never below 30% overnight), so a
	// verdict needs at least 24 h of samples.
	minBatteryNetWindow = 24 * time.Hour
	// equilibriumDeadbandPerDay is the |net envelope growth| below which
	// the store counts as steady: under one envelope net per day the store
	// is neither filling nor draining in any operationally meaningful way.
	equilibriumDeadbandPerDay = 1.0
)

// Projection verdict strings (rendered verbatim on the page).
const (
	EquilibriumGrowing   = "growing"
	EquilibriumShrinking = "shrinking"
	EquilibriumSteady    = "steady"
	BatteryNetPositive   = "net_positive"
	BatteryNetStarving   = "starving"
	BatteryNetSteady     = "steady"
)

// Projections is the derived half of the status snapshot. Every numeric
// member is a pointer: nil means "not enough data yet" (the minimum-data
// rule) or "no fill/drain projected at the current rates" — the page
// distinguishes the two via EnoughData.
type Projections struct {
	Samples     int     // ring samples backing the numbers
	WindowHours float64 // span of that window (the label the page shows)
	EnoughData  bool    // the minimum-data rule for rates

	PushesPerDay           *float64
	ExpiriesPerDay         *float64
	DBGrowthBytesPerDay    *float64
	BatteryDrainWhPerDay   *float64
	DaysToEnvelopeCapacity *float64
	DaysToDiskFull         *float64
	StoreEquilibrium       string // growing / shrinking / steady ("" before enough data)
	BatteryNet             string // net_positive / starving / steady ("" before 24 h)
}

// CountersDelta is the recent-window delta of the #31 request counters
// (shown alongside the lifetime totals).
type CountersDelta struct {
	WindowHours       float64
	PushesAccepted    int64
	PushesRejected    int64
	DedupHits         int64
	TTLSweptEnvelopes int64
}

// Snapshot is the read-only view the API layer renders. Everything is
// RAM-cached state of the last sample; reading it never touches /proc, a
// sensor or SQLite.
type Snapshot struct {
	SampledAt     time.Time // when the last sample was taken (zero = never)
	SampleCount   int       // ring depth
	Battery       *power.Overview
	BatteryHealth *float64
	System        sysres.Readings
	Expiring      *storage.ExpCounts
	SchemaOnDisk  *int
	ActiveClients int
	Projections   Projections
	CountersDelta *CountersDelta
}

// computeProjections derives the projections from the ring contents.
// diskFree is the last known free space of the DB volume (nil = unknown →
// days-to-disk-full stays null); envelopeCap the node's capacity.
// Pure function — unit-tested in isolation.
func computeProjections(ring []sample, envelopeCap int, diskFree *int64) Projections {
	p := Projections{Samples: len(ring)}
	if len(ring) < minRateSamples {
		return p
	}
	first, last := ring[0], ring[len(ring)-1]
	span := last.At.Sub(first.At)
	p.WindowHours = span.Hours()
	if span < minRateWindow {
		return p // the minimum-data rule: never extrapolate from nothing
	}
	p.EnoughData = true

	days := span.Hours() / 24
	if days <= 0 {
		return p
	}

	dP := func(d int64) *float64 { f := float64(d) / days; return &f }
	p.PushesPerDay = dP(last.Totals.PushesAccepted - first.Totals.PushesAccepted)
	p.ExpiriesPerDay = dP(last.Totals.TTLSweptEnvelopes - first.Totals.TTLSweptEnvelopes)
	p.DBGrowthBytesPerDay = dP(last.DBSizeBytes - first.DBSizeBytes)

	if first.BatteryWh != nil && last.BatteryWh != nil {
		drain := (*first.BatteryWh - *last.BatteryWh) / days // positive = draining
		p.BatteryDrainWhPerDay = &drain
	}

	// Days to envelope capacity at the current GROSS intake: the store's
	// net growth is intake minus TTL expiry, so intake is net + expired.
	intakePerDay := float64(last.Envelopes-first.Envelopes)/days + *p.ExpiriesPerDay
	if intakePerDay > 0 && envelopeCap > 0 && last.Envelopes < int64(envelopeCap) {
		d := (float64(envelopeCap) - float64(last.Envelopes)) / intakePerDay
		p.DaysToEnvelopeCapacity = &d
	}

	// Days to disk-full at the current DB growth, from the last known free
	// space of the DB volume.
	if diskFree != nil && p.DBGrowthBytesPerDay != nil && *p.DBGrowthBytesPerDay > 0 {
		d := float64(*diskFree) / *p.DBGrowthBytesPerDay
		p.DaysToDiskFull = &d
	}

	// Store equilibrium: net growth vs the deadband.
	net := float64(last.Envelopes-first.Envelopes) / days
	switch {
	case net > equilibriumDeadbandPerDay:
		p.StoreEquilibrium = EquilibriumGrowing
	case net < -equilibriumDeadbandPerDay:
		p.StoreEquilibrium = EquilibriumShrinking
	default:
		p.StoreEquilibrium = EquilibriumSteady
	}

	// Battery net judgment: held to the multi-day window.
	if span >= minBatteryNetWindow && first.BatteryWh != nil && last.BatteryWh != nil {
		diff := *last.BatteryWh - *first.BatteryWh
		switch {
		case diff > 0:
			p.BatteryNet = BatteryNetPositive
		case diff < 0:
			p.BatteryNet = BatteryNetStarving
		default:
			p.BatteryNet = BatteryNetSteady
		}
	}
	return p
}

// computeCountersDelta derives the recent-window counter deltas (nil before
// the minimum-data rule). Pure function.
func computeCountersDelta(ring []sample) *CountersDelta {
	if len(ring) < minRateSamples {
		return nil
	}
	first, last := ring[0], ring[len(ring)-1]
	span := last.At.Sub(first.At)
	if span < minRateWindow {
		return nil
	}
	return &CountersDelta{
		WindowHours:       span.Hours(),
		PushesAccepted:    last.Totals.PushesAccepted - first.Totals.PushesAccepted,
		PushesRejected:    last.Totals.PushesRejected - first.Totals.PushesRejected,
		DedupHits:         last.Totals.DedupHits - first.Totals.DedupHits,
		TTLSweptEnvelopes: last.Totals.TTLSweptEnvelopes - first.Totals.TTLSweptEnvelopes,
	}
}
