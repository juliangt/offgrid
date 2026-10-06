// powersupply.go — the Linux power_supply sysfs reader (/sys/class/power_supply/*)
// of the battery chain (issue #36). On a Pi node this is where an
// off-the-shelf UPS/BMS HAT shows up: the kernel exports one directory per
// supply with status, voltage_now, current_now and — when the BMS
// coulomb-counts — capacity, charge_full and charge_full_design.
//
// Every file is parsed from bytes by the exported functions below (fixture
// unit tests run on any OS); the reader itself only exists on Linux and
// reports "unavailable" everywhere else. A missing file, a non-numeric
// value or a missing power_supply tree is the ordinary case: unavailable,
// never an error surfaced anywhere (docs/protocol.md §10.7 N/A convention).
package power

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// powerSupplyBase is the sysfs tree the reader scans. Var purely as a test
// hook; production code must never reassign it.
var powerSupplyBase = "/sys/class/power_supply"

// ParseChargeState maps a power_supply `status` file's value to a
// ChargeState. "Charging"/"Discharging" map directly; "Not charging",
// "Full" and anything else readable map to idle (the pack is not being
// charged and the node is running, so it is effectively resting).
func ParseChargeState(status []byte) ChargeState {
	switch strings.ToLower(strings.TrimSpace(string(status))) {
	case "charging":
		return StateCharging
	case "discharging":
		return StateDischarging
	case "not charging", "full", "idle":
		return StateIdle
	default:
		return StateUnknown
	}
}

// ParseMicroVolts decodes a `voltage_now` file (microvolts) into volts.
func ParseMicroVolts(b []byte) (float64, error) {
	v, err := strconv.ParseFloat(strings.TrimSpace(string(b)), 64)
	if err != nil {
		return 0, fmt.Errorf("power: parse voltage_now: %w", err)
	}
	return v / 1e6, nil
}

// ParseMicroAmps decodes a `current_now` file (microamps) into amps. Sign
// conventions differ per driver; the reader normalizes against the
// status file (see powerSupplyReader.read).
func ParseMicroAmps(b []byte) (float64, error) {
	v, err := strconv.ParseFloat(strings.TrimSpace(string(b)), 64)
	if err != nil {
		return 0, fmt.Errorf("power: parse current_now: %w", err)
	}
	return v / 1e6, nil
}

// ParsePercent decodes a `capacity` file (0..100 integer percent).
func ParsePercent(b []byte) (float64, error) {
	v, err := strconv.ParseFloat(strings.TrimSpace(string(b)), 64)
	if err != nil || v < 0 || v > 100 {
		return 0, fmt.Errorf("power: parse capacity %q", strings.TrimSpace(string(b)))
	}
	return v, nil
}

// ParseMicroWattHours decodes an `energy_full`-class file (µWh) into Wh.
func ParseMicroWattHours(b []byte) (float64, error) {
	v, err := strconv.ParseFloat(strings.TrimSpace(string(b)), 64)
	if err != nil {
		return 0, fmt.Errorf("power: parse energy value: %w", err)
	}
	return v / 1e6, nil
}

// ParseMicroAmpHours decodes a `charge_full`-class file (µAh) into Ah —
// multiplied by the nominal pack voltage by the caller when a Wh figure is
// needed.
func ParseMicroAmpHours(b []byte) (float64, error) {
	v, err := strconv.ParseFloat(strings.TrimSpace(string(b)), 64)
	if err != nil {
		return 0, fmt.Errorf("power: parse charge value: %w", err)
	}
	return v / 1e6, nil
}

// powerSupplyReader reads the first "Battery"-type supply under the sysfs
// tree.
type powerSupplyReader struct {
	base string // settable for tests; production instances use powerSupplyBase
}

// newPowerSupplyReader returns the sysfs reader (always constructible; the
// first read discovers whether a battery supply exists).
func newPowerSupplyReader() *powerSupplyReader {
	return &powerSupplyReader{base: powerSupplyBase}
}

// read harvests one reading from the sysfs tree. It reports available=true
// only when a battery-type supply answered with at least a status or a
// capacity/voltage file — otherwise the chain falls through to the next
// reader (and eventually to honest unknown).
//
// Current sign normalization: several drivers report current_now positive
// while DISCHARGING (it is the load-side convention). The status file is
// the authoritative state, so the reader flips the current sign to the
// battery-centric convention (positive = charging) whenever the two
// disagree.
func (r *powerSupplyReader) read() (Reading, bool) {
	dir, ok := r.findBatteryDir()
	if !ok {
		return Reading{}, false
	}
	rd := Reading{}
	if b, err := os.ReadFile(filepath.Join(dir, "status")); err == nil {
		if st := ParseChargeState(b); st != StateUnknown {
			rd.ChargeState = st
			rd.Available = true
		}
	}
	if b, err := os.ReadFile(filepath.Join(dir, "voltage_now")); err == nil {
		if v, err := ParseMicroVolts(b); err == nil && v > 0 {
			rd.VoltageVolts = &v
			rd.Available = true
		}
	}
	var amps *float64
	if b, err := os.ReadFile(filepath.Join(dir, "current_now")); err == nil {
		if a, err := ParseMicroAmps(b); err == nil {
			amps = &a
		}
	}
	if amps != nil {
		switch rd.ChargeState {
		case StateDischarging:
			a := -*amps // load-side convention → battery-centric
			amps = &a
		case StateCharging:
			if *amps < 0 {
				a := -*amps
				amps = &a
			}
		}
		rd.CurrentAmps = amps
		if rd.ChargeState == StateUnknown {
			rd.ChargeState = chargeStateFromCurrent(amps)
		}
	}
	// State of charge: a coulomb-counting BMS publishes `capacity` — the
	// most accurate figure this node can show; without it the chain's
	// voltage estimator gets a turn with whatever voltage was read.
	if b, err := os.ReadFile(filepath.Join(dir, "capacity")); err == nil {
		if pct, err := ParsePercent(b); err == nil {
			rd.SOC = &SOC{Percent: pct, Source: SOCCoulomb}
			rd.Available = true
		}
	}
	return rd, rd.Available
}

// findBatteryDir scans the supply directories and returns the first one
// whose `type` file reads "Battery". A scan failure (missing tree — the
// macOS dev box and every non-Linux host) yields ok=false.
func (r *powerSupplyReader) findBatteryDir() (string, bool) {
	entries, err := os.ReadDir(r.base)
	if err != nil {
		return "", false
	}
	for _, e := range entries {
		if !e.IsDir() && e.Type()&os.ModeSymlink == 0 {
			continue
		}
		b, err := os.ReadFile(filepath.Join(r.base, e.Name(), "type"))
		if err != nil {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(string(b)), "Battery") {
			return filepath.Join(r.base, e.Name()), true
		}
	}
	return "", false
}

// readHealth returns the pack's estimated state of health in percent —
// full capacity over design capacity (charge_full/charge_full_design in
// µAh, or the energy_* twins in µWh) — when the BMS publishes both. A
// voltage-only setup cannot measure wear: unavailable.
func (r *powerSupplyReader) readHealth() (float64, bool) {
	dir, ok := r.findBatteryDir()
	if !ok {
		return 0, false
	}
	pairs := [][2]string{
		{"energy_full", "energy_full_design"},
		{"charge_full", "charge_full_design"},
	}
	for _, p := range pairs {
		fullB, err := os.ReadFile(filepath.Join(dir, p[0]))
		if err != nil {
			continue
		}
		designB, err := os.ReadFile(filepath.Join(dir, p[1]))
		if err != nil {
			continue
		}
		// µWh and µAh share the 1e6 scale, so the ratio is unit-agnostic.
		full, err1 := ParseMicroWattHours(fullB)
		design, err2 := ParseMicroWattHours(designB)
		if err1 != nil {
			full, err1 = ParseMicroAmpHours(fullB)
		}
		if err2 != nil {
			design, err2 = ParseMicroAmpHours(designB)
		}
		if err1 == nil && err2 == nil && design > 0 && full > 0 {
			pct := full / design * 100
			if pct > 0 && pct <= 100 {
				return pct, true
			}
		}
	}
	return 0, false
}
