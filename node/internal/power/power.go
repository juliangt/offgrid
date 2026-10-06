// Package power reads the node's power and battery state for the field
// status page (issue #36, docs/protocol.md §10.7).
//
// The reading chain degrades gracefully and never becomes a dependency:
//
//	INA219/INA260-class sensor over Linux I2C sysfs (/dev/i2c-N)
//		→ Linux power_supply sysfs (/sys/class/power_supply/*)
//		→ voltage-only estimate from whatever voltage source exists
//		→ honest "unknown" (rendered N/A everywhere).
//
// Every reader is optional and every failure is reported as an unavailable
// datum, never an error surfaced to a request path. Nothing here touches the
// network, persists anything, or logs: the readings are node-local
// electrical measurements with no user-identifying content whatsoever
// (docs/protocol.md §13; A7 of docs/hardening.md).
//
// Accuracy honesty (binding for the status page): LiFePO4 4S packs have a
// very flat discharge curve between ~30% and ~90%, so ANY voltage-derived
// state of charge is coarse — a few percent of error is normal and the
// rendered page says so. Only a battery management system that reports
// coulomb-counted capacity (exposed by the power_supply sysfs interface on
// some packs) is more precise; the reading carries its source so the page
// can label the accuracy.
package power

import (
	"fmt"
	"math"
)

// ChargeState is the battery's charge condition, as coarse as the available
// sensor allows.
type ChargeState string

const (
	// StateUnknown means no sensor answered; the page renders N/A.
	StateUnknown ChargeState = ""
	// StateCharging: net current flows INTO the battery.
	StateCharging ChargeState = "charging"
	// StateDischarging: net current flows OUT of the battery.
	StateDischarging ChargeState = "discharging"
	// StateIdle: neither (resting, or balancing within the noise floor).
	StateIdle ChargeState = "idle"
)

// SOCSource states WHERE the state-of-charge figure came from, so the page
// can label its accuracy honestly.
type SOCSource string

const (
	// SOCNone: no state of charge available.
	SOCNone SOCSource = ""
	// SOCCoulomb: the source coulomb-counts (BMS-computed capacity; the
	// most accurate figure this node can show).
	SOCCoulomb SOCSource = "coulomb"
	// SOCVoltage: derived from pack voltage against the configured
	// full/empty voltages. Coarse for LiFePO4 4S (flat curve) — the page
	// says so next to the number.
	SOCVoltage SOCSource = "voltage"
)

// Reading is one snapshot of the electrical state. Pointer members are nil
// when the datum is unavailable (no sensor, failed read) — the JSON layer
// turns nil into null (§10.7 N/A convention). CurrentAmps follows the
// battery-centric sign convention: positive = charging, negative =
// discharging.
type Reading struct {
	Available    bool        // any sensor answered at all
	ChargeState  ChargeState // StateUnknown when not observable
	VoltageVolts *float64    // pack voltage
	CurrentAmps  *float64    // positive = charging (battery-centric)
	SOC          *SOC
}

// SOC is the coarse state of charge and its provenance.
type SOC struct {
	Percent float64   // 0..100
	Source  SOCSource // how it was obtained (accuracy label)
}

// Float returns a pointer to v (test/fixture helper).
func Float(v float64) *float64 { return &v }

// Band is the alert word rendered on the status page: one of CHARGING,
// HEALTHY, LOW, CRITICAL, or "" (unknown — N/A). The thresholds are the
// field rules of docs/hardware.md: LOW begins below 30% state of charge
// (§8: a healthy solar node must never dip below 30% overnight — the
// acceptance rule), CRITICAL at or below the depth-of-discharge floor
// (§2.2: the design stops at 20% remaining, so being there means the node
// is living on its protection margin).
type Band string

const (
	BandUnknown  Band = ""
	BandCharging Band = "CHARGING"
	BandHealthy  Band = "HEALTHY"
	BandLow      Band = "LOW"
	BandCritical Band = "CRITICAL"
)

// LowSOCThreshold is the LOW band boundary in percent state of charge: at
// 30% the node is below the overnight floor that docs/hardware.md §8 uses
// as the field acceptance rule ("never dips under 30% overnight"), so it is
// worth a look even if it survived the night.
const LowSOCThreshold = 30.0

// DefaultDODFloorPercent is the depth-of-discharge floor of the sizing
// math (docs/hardware.md §2.2: DoD 0.80 = the node stops drawing at 20%
// remaining). Fixed unless overridden via configuration.
const DefaultDODFloorPercent = 20.0

// AlertBand classifies a reading into the status-page band. The DoD floor
// (percent) is the CRITICAL boundary. A charging battery is CHARGING
// regardless of its state of charge (it is recovering); everything else is
// classified by SoC, and an unavailable SoC yields BandUnknown (N/A) unless
// the pack is charging.
func AlertBand(r Reading, dodFloorPercent float64) Band {
	if r.ChargeState == StateCharging {
		return BandCharging
	}
	if r.SOC == nil {
		return BandUnknown
	}
	if r.SOC.Percent <= dodFloorPercent {
		return BandCritical
	}
	if r.SOC.Percent < LowSOCThreshold {
		return BandLow
	}
	return BandHealthy
}

// NominalLoadWatts is the design electrical load of a node (docs/hardware.md
// §1: ~1 W continuous after the power trim). It is the fallback for the
// autonomy projection when no current sensor measures the real draw; the
// page labels such a projection "nominal".
const NominalLoadWatts = 1.0

// Autonomy is the projected remaining runtime down to the DoD floor.
// BasisWatts records whether the load figure was measured (a current
// sensor) or nominal (the design target of hardware.md §1).
type Autonomy struct {
	Hours  float64
	Nights float64 // Hours / 24 — "nights of autonomy" is the operator's unit
	Basis  string  // "measured" or "nominal"
}

// EstimateAutonomy projects how long the node can run from the current
// state of charge down to the DoD floor, at the given load. It returns
// ok=false (and the zero Autonomy) whenever the math has no honest input:
// no state of charge, or no configured capacity. The load is the
// battery-side power draw in watts; measured loads win over the nominal
// design figure. The projection is linearity assumption on top of a coarse
// SoC — the page must keep calling it a projection, never a promise.
func EstimateAutonomy(r Reading, capacityWh, dodFloorPercent float64) (Autonomy, bool) {
	if r.SOC == nil || capacityWh <= 0 {
		return Autonomy{}, false
	}
	reserveFrac := (r.SOC.Percent - dodFloorPercent) / 100.0
	if reserveFrac <= 0 {
		// At or below the floor already: zero honest runtime left. Report
		// 0 rather than N/A — the operator must read "now", not "?".
		return Autonomy{Hours: 0, Nights: 0, Basis: "measured"}, true
	}
	load := NominalLoadWatts
	basis := "nominal"
	if r.VoltageVolts != nil && r.CurrentAmps != nil {
		if p := math.Abs(*r.VoltageVolts * *r.CurrentAmps); p > 0 {
			load = p
			basis = "measured"
		}
	}
	hours := reserveFrac * capacityWh / load
	return Autonomy{Hours: hours, Nights: hours / 24, Basis: basis}, true
}

// VoltageEstimator derives a coarse state of charge from pack voltage
// against configured full/empty voltages. Documented accuracy limit: a
// LiFePO4 4S pack spends most of its discharge on a nearly flat curve, so
// the mid-range estimate can be off by tens of percent; it is trustworthy
// mainly near the ends (full ≈ 13.6 V resting, empty ≈ the ~11.6-12.0 V
// region where the BMS protection nears — docs/hardware.md §9). The
// defaults below are the hardware.md resting-voltage anchors.
type VoltageEstimator struct {
	FullVolts  float64 // resting voltage at 100%
	EmptyVolts float64 // resting voltage at 0%
}

// DefaultVoltageEstimator matches a LiFePO4 4S pack (12.8 V nominal) using
// the voltage anchors of docs/hardware.md §2.2/§9.
func DefaultVoltageEstimator() VoltageEstimator {
	return VoltageEstimator{FullVolts: 13.6, EmptyVolts: 12.0}
}

// Estimate maps a pack voltage to 0..100 percent, clamped. It returns
// ok=false when the estimator is unconfigured (full <= empty) or the
// voltage is missing.
func (e VoltageEstimator) Estimate(volts *float64) (SOC, bool) {
	if volts == nil || e.FullVolts <= e.EmptyVolts {
		return SOC{}, false
	}
	frac := (*volts - e.EmptyVolts) / (e.FullVolts - e.EmptyVolts)
	pct := frac * 100
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	return SOC{Percent: pct, Source: SOCVoltage}, true
}

// String renders the charge state for logs (never used on request paths).
func (r Reading) String() string {
	return fmt.Sprintf("power.Reading{available=%v state=%q}", r.Available, r.ChargeState)
}
