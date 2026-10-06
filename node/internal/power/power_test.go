package power

// power_test.go — unit tests for the battery reading chain (issue #36):
// INA219 register-decode math against fixture registers (no hardware), the
// voltage estimator, alert bands, autonomy math with the DoD floor, the
// power_supply sysfs parsers against fixture files, and the chain's
// graceful degradation. Everything here runs on any OS: the I2C transport
// is exercised only as "unavailable" on non-Linux hosts.

import (
	"math"
	"os"
	"path/filepath"
	"testing"
)

// TestINACalibrationRegister pins the calibration-word math (SBOS549 §8.5.2)
// for the shipped default (0.1 Ω shunt, 3.2 A full scale) and rejects
// unusable configs with 0 (the reader then stays out of the chain).
func TestINACalibrationRegister(t *testing.T) {
	cases := []struct {
		name      string
		shuntOhms float64
		maxAmps   float64
		want      uint16
	}{
		{"shipped default", 0.1, 3.2, 4194},
		{"half-scale current", 0.1, 1.6, 8388},
		{"zero shunt", 0, 3.2, 0},
		{"zero current", 0.1, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := inaCalibrationRegister(tc.shuntOhms, tc.maxAmps); got != tc.want {
				t.Fatalf("inaCalibrationRegister(%g, %g) = %d, want %d", tc.shuntOhms, tc.maxAmps, got, tc.want)
			}
		})
	}
}

// TestINADecodeBusVolts pins the bus-voltage register decode (bits 15..3,
// 4 mV LSB) with fixture words: 12.48 V for a 4S pack mid-discharge.
func TestINADecodeBusVolts(t *testing.T) {
	// 12.48 V = 12480 mV = 3120 LSBs = 0xC30 shifted into the top 13 bits.
	if got := inaDecodeBusVolts(0x6180); math.Abs(got-12.48) > 1e-9 {
		t.Fatalf("inaDecodeBusVolts(0x6180) = %v, want 12.48", got)
	}
	// 0 V raw (sensor absent) decodes to 0 — callers treat that as unavailable.
	if got := inaDecodeBusVolts(0); got != 0 {
		t.Fatalf("inaDecodeBusVolts(0) = %v, want 0", got)
	}
}

// TestINADecodeShuntAndCurrent pins the signed shunt/current decodes against
// the calibration divider.
func TestINADecodeShuntAndCurrent(t *testing.T) {
	// Shunt: signed 16-bit, 10 µV/LSB.
	if got := inaDecodeShuntVolts(1000); math.Abs(got-0.01) > 1e-9 {
		t.Fatalf("shunt 1000 = %v V, want 0.01", got)
	}
	if got := inaDecodeShuntVolts(0x8000); math.Abs(got+0.32768) > 1e-9 {
		t.Fatalf("shunt 0x8000 = %v V, want -0.32768", got)
	}
	// Current with the shipped calibration: 2048 LSB ≈ 200 mA.
	lsb := inaCurrentLSBAmps(4194, 0.1)
	if got := inaDecodeCurrentAmps(2048, 4194, 0.1); math.Abs(got-2048*lsb) > 1e-12 || math.Abs(got-0.2) > 1e-3 {
		t.Fatalf("current 2048 = %v A, want ≈0.2", got)
	}
	// Negative raw = discharge (battery-centric sign).
	if got := inaDecodeCurrentAmps(0xF000, 4194, 0.1); got >= 0 {
		t.Fatalf("current 0xF000 must decode negative (discharging), got %v", got)
	}
}

// TestChargeStateFromCurrent pins the deadband classification.
func TestChargeStateFromCurrent(t *testing.T) {
	cases := []struct {
		amps float64
		want ChargeState
	}{
		{0.5, StateCharging},
		{0.021, StateCharging},
		{0.0, StateIdle},
		{-0.019, StateIdle}, // inside the deadband: noise, not discharge
		{-0.5, StateDischarging},
	}
	for _, tc := range cases {
		a := tc.amps
		if got := chargeStateFromCurrent(&a); got != tc.want {
			t.Errorf("chargeStateFromCurrent(%g) = %q, want %q", tc.amps, got, tc.want)
		}
	}
	if got := chargeStateFromCurrent(nil); got != StateUnknown {
		t.Errorf("chargeStateFromCurrent(nil) = %q, want unknown", got)
	}
}

// TestVoltageEstimator pins the coarse voltage→SoC mapping and its clamps.
func TestVoltageEstimator(t *testing.T) {
	e := DefaultVoltageEstimator() // 13.6 V full, 12.0 V empty (hardware.md anchors)
	cases := []struct {
		volts float64
		want  float64
	}{
		{13.6, 100},
		{12.0, 0},
		{12.8, 50},
		{14.4, 100}, // absorption voltage: clamped, never > 100
		{11.6, 0},   // protection nearing: clamped at 0
	}
	for _, tc := range cases {
		v := tc.volts
		got, ok := e.Estimate(&v)
		if !ok || math.Abs(got.Percent-tc.want) > 1e-9 || got.Source != SOCVoltage {
			t.Errorf("Estimate(%g) = %+v ok=%v, want %.0f (voltage source)", tc.volts, got, ok, tc.want)
		}
	}
	if _, ok := e.Estimate(nil); ok {
		t.Errorf("Estimate(nil) must fail")
	}
	if _, ok := (VoltageEstimator{FullVolts: 12, EmptyVolts: 12}).Estimate(Float(12.4)); ok {
		t.Errorf("unconfigured estimator (full <= empty) must fail")
	}
}

// TestAlertBand pins the band table: CHARGING wins; LOW begins below the
// 30% overnight floor of hardware.md §8; CRITICAL at/below the DoD floor
// of hardware.md §2.2; unknown SoC renders unknown unless charging.
func TestAlertBand(t *testing.T) {
	const floor = DefaultDODFloorPercent // 20
	cases := []struct {
		name  string
		state ChargeState
		soc   *float64
		want  Band
	}{
		{"charging", StateCharging, Float(10), BandCharging},
		{"healthy high", StateDischarging, Float(95), BandHealthy},
		{"healthy at 30", StateDischarging, Float(30), BandHealthy},
		{"low below 30", StateDischarging, Float(29.9), BandLow},
		{"critical at floor", StateDischarging, Float(20), BandCritical},
		{"critical below floor", StateDischarging, Float(7), BandCritical},
		{"idle classifies by soc", StateIdle, Float(25), BandLow},
		{"unknown soc discharging", StateDischarging, nil, BandUnknown},
		{"unknown soc charging", StateCharging, nil, BandCharging},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := Reading{Available: true, ChargeState: tc.state}
			if tc.soc != nil {
				r.SOC = &SOC{Percent: *tc.soc, Source: SOCVoltage}
			}
			if got := AlertBand(r, floor); got != tc.want {
				t.Fatalf("AlertBand = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestEstimateAutonomy pins the autonomy projection: reserve above the DoD
// floor at the measured (or nominal) load, expressed in hours and 24-hour
// nights, with the honest-basis label and the N/A rule (no capacity, no
// SoC → no projection).
func TestEstimateAutonomy(t *testing.T) {
	t.Run("measured load", func(t *testing.T) {
		r := Reading{
			Available:    true,
			ChargeState:  StateDischarging,
			VoltageVolts: Float(12.8),
			CurrentAmps:  Float(-1.0),
			SOC:          &SOC{Percent: 80, Source: SOCVoltage},
		}
		a, ok := EstimateAutonomy(r, 128, 20)
		if !ok {
			t.Fatal("must project with capacity and SoC present")
		}
		// reserve = (80-20)/100 × 128 Wh = 76.8 Wh at 12.8 W measured → 6 h.
		if math.Abs(a.Hours-6.0) > 1e-9 || math.Abs(a.Nights-0.25) > 1e-9 || a.Basis != "measured" {
			t.Fatalf("got %+v, want 6 h / 0.25 nights / measured", a)
		}
	})
	t.Run("nominal load without current sensor", func(t *testing.T) {
		r := Reading{ChargeState: StateDischarging, SOC: &SOC{Percent: 80, Source: SOCCoulomb}}
		a, ok := EstimateAutonomy(r, 128, 20)
		if !ok || a.Basis != "nominal" || math.Abs(a.Hours-76.8) > 1e-9 {
			t.Fatalf("got %+v ok=%v, want 76.8 h nominal (1 W design load)", a, ok)
		}
		if math.Abs(a.Nights-3.2) > 1e-9 {
			t.Fatalf("nights must be hours/24 (3.2), got %v", a.Nights)
		}
	})
	t.Run("at the floor", func(t *testing.T) {
		r := Reading{SOC: &SOC{Percent: 15, Source: SOCCoulomb}}
		a, ok := EstimateAutonomy(r, 128, 20)
		if !ok || a.Hours != 0 || a.Nights != 0 {
			t.Fatalf("at/below the floor must project a truthful 0, got %+v ok=%v", a, ok)
		}
	})
	t.Run("no capacity", func(t *testing.T) {
		r := Reading{SOC: &SOC{Percent: 80, Source: SOCCoulomb}}
		if _, ok := EstimateAutonomy(r, 0, 20); ok {
			t.Fatal("autonomy without configured capacity must be N/A")
		}
	})
	t.Run("no soc", func(t *testing.T) {
		if _, ok := EstimateAutonomy(Reading{}, 128, 20); ok {
			t.Fatal("autonomy without SoC must be N/A")
		}
	})
}

// writeSupplyFile creates a fake power_supply directory with the given files.
func writeSupplyFile(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	bat := filepath.Join(dir, "BAT0")
	if err := os.MkdirAll(bat, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(bat, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// TestPowerSupplyReaderParsers pins the sysfs file parsers.
func TestPowerSupplyReaderParsers(t *testing.T) {
	if got := ParseChargeState([]byte("Charging\n")); got != StateCharging {
		t.Errorf("status Charging = %q", got)
	}
	if got := ParseChargeState([]byte("Discharging")); got != StateDischarging {
		t.Errorf("status Discharging = %q", got)
	}
	if got := ParseChargeState([]byte("Not charging")); got != StateIdle {
		t.Errorf("status Not charging = %q (idle)", got)
	}
	if got := ParseChargeState([]byte("Full")); got != StateIdle {
		t.Errorf("status Full = %q (idle)", got)
	}
	if got := ParseChargeState([]byte("Unknown")); got != StateUnknown {
		t.Errorf("status Unknown = %q", got)
	}
	if v, err := ParseMicroVolts([]byte("12800000\n")); err != nil || v != 12.8 {
		t.Errorf("voltage_now 12800000 = %v err=%v, want 12.8", v, err)
	}
	if a, err := ParseMicroAmps([]byte("-200000")); err != nil || a != -0.2 {
		t.Errorf("current_now -200000 = %v err=%v, want -0.2", a, err)
	}
	if p, err := ParsePercent([]byte("75\n")); err != nil || p != 75 {
		t.Errorf("capacity 75 = %v err=%v", p, err)
	}
	if _, err := ParsePercent([]byte("101")); err == nil {
		t.Errorf("capacity 101 must fail")
	}
	if wh, err := ParseMicroWattHours([]byte("96000000")); err != nil || wh != 96 {
		t.Errorf("energy_full 96000000 = %v err=%v, want 96 Wh", wh, err)
	}
	if ah, err := ParseMicroAmpHours([]byte("8000000")); err != nil || ah != 8 {
		t.Errorf("charge_full 8000000 = %v err=%v, want 8 Ah", ah, err)
	}
}

// TestPowerSupplyReaderRead drives the sysfs reader over a fixture tree: a
// coulomb-counting BMS (status + capacity + voltage + current) reads back
// with the battery-centric current sign (positive = charging).
func TestPowerSupplyReaderRead(t *testing.T) {
	t.Run("coulomb BMS, discharging flips sign", func(t *testing.T) {
		r := &powerSupplyReader{base: writeSupplyFile(t, map[string]string{
			"type":        "Battery\n",
			"status":      "Discharging",
			"voltage_now": "12800000",
			"current_now": "300000", // load-side convention: positive while discharging
			"capacity":    "42",
		})}
		rd, ok := r.read()
		if !ok {
			t.Fatal("fixture battery must read available")
		}
		if rd.ChargeState != StateDischarging {
			t.Fatalf("charge state = %q, want discharging", rd.ChargeState)
		}
		if rd.SOC == nil || rd.SOC.Percent != 42 || rd.SOC.Source != SOCCoulomb {
			t.Fatalf("soc = %+v, want 42 (coulomb source)", rd.SOC)
		}
		if rd.CurrentAmps == nil || *rd.CurrentAmps != -0.3 {
			t.Fatalf("current = %v, want -0.3 (battery-centric)", rd.CurrentAmps)
		}
		if rd.VoltageVolts == nil || *rd.VoltageVolts != 12.8 {
			t.Fatalf("voltage = %v, want 12.8", rd.VoltageVolts)
		}
	})
	t.Run("voltage-only supply feeds the estimator, not coulomb", func(t *testing.T) {
		r := &powerSupplyReader{base: writeSupplyFile(t, map[string]string{
			"type":        "Battery\n",
			"status":      "Charging",
			"voltage_now": "13600000",
		})}
		chain := NewChain(Config{Estimator: DefaultVoltageEstimator()})
		rd, ok := r.read()
		if !ok {
			t.Fatal("fixture battery must read available")
		}
		if rd.SOC != nil {
			t.Fatalf("sysfs reader alone must not invent a SoC, got %+v", rd.SOC)
		}
		chain.finish(&rd) // the chain's voltage-estimate step
		if rd.SOC == nil || rd.SOC.Percent != 100 || rd.SOC.Source != SOCVoltage {
			t.Fatalf("chain SoC = %+v, want 100 (voltage source)", rd.SOC)
		}
	})
	t.Run("no battery tree", func(t *testing.T) {
		r := &powerSupplyReader{base: filepath.Join(t.TempDir(), "missing")}
		if _, ok := r.read(); ok {
			t.Fatal("missing power_supply tree must read unavailable")
		}
		if _, ok := r.readHealth(); ok {
			t.Fatal("missing power_supply tree must have no health figure")
		}
	})
}

// TestPowerSupplyReadHealth pins the state-of-health estimate (full/design)
// and its absence on voltage-only setups.
func TestPowerSupplyReadHealth(t *testing.T) {
	t.Run("energy twins", func(t *testing.T) {
		r := &powerSupplyReader{base: writeSupplyFile(t, map[string]string{
			"type":               "Battery\n",
			"energy_full":        "96000000",  // 96 Wh
			"energy_full_design": "120000000", // 120 Wh
		})}
		h, ok := r.readHealth()
		if !ok || math.Abs(h-80) > 1e-9 {
			t.Fatalf("health = %v ok=%v, want 80", h, ok)
		}
	})
	t.Run("charge twins", func(t *testing.T) {
		r := &powerSupplyReader{base: writeSupplyFile(t, map[string]string{
			"type":               "Battery\n",
			"charge_full":        "8000000",  // 8 Ah
			"charge_full_design": "10000000", // 10 Ah
		})}
		h, ok := r.readHealth()
		if !ok || math.Abs(h-80) > 1e-9 {
			t.Fatalf("health = %v ok=%v, want 80", h, ok)
		}
	})
	t.Run("voltage-only", func(t *testing.T) {
		r := &powerSupplyReader{base: writeSupplyFile(t, map[string]string{
			"type":        "Battery\n",
			"voltage_now": "12800000",
		})}
		if _, ok := r.readHealth(); ok {
			t.Fatal("voltage-only setups must render health N/A")
		}
	})
}

// TestChainDegradation pins the chain order and its honest unknown: an
// unconfigured I2C link is skipped, a missing sysfs tree is skipped, and a
// chain with nothing answers unavailable — never an error, never zeros.
func TestChainDegradation(t *testing.T) {
	t.Run("nothing available (the macOS / stock dev case)", func(t *testing.T) {
		c := NewChain(Config{Estimator: DefaultVoltageEstimator()})
		c.sysfs = &powerSupplyReader{base: filepath.Join(t.TempDir(), "missing")}
		if _, ok := c.Read(); ok {
			t.Fatal("empty chain must answer unavailable")
		}
	})
	t.Run("configured i2c that cannot open stays out of the chain", func(t *testing.T) {
		c := NewChain(Config{I2C: I2CConfig{BusPath: filepath.Join(t.TempDir(), "no-such-i2c"), ShuntOhms: 0.1, MaxCurrentAmps: 3.2}})
		if c.I2CAvailable() {
			t.Fatal("a failed I2C open must not mark the link available")
		}
		c.sysfs = &powerSupplyReader{base: filepath.Join(t.TempDir(), "missing")}
		if _, ok := c.Read(); ok {
			t.Fatal("chain without working links must answer unavailable")
		}
	})
	t.Run("sysfs wins when i2c is unconfigured", func(t *testing.T) {
		c := NewChain(Config{
			CapacityWh:      128,
			DODFloorPercent: 20,
			Estimator:       DefaultVoltageEstimator(),
		})
		c.sysfs = &powerSupplyReader{base: writeSupplyFile(t, map[string]string{
			"type":        "Battery\n",
			"status":      "Discharging",
			"voltage_now": "13300000",
			"current_now": "500000",
			"capacity":    "88",
		})}
		rd, ok := c.Read()
		if !ok {
			t.Fatal("sysfs link must answer")
		}
		ov := c.Overview(rd)
		if ov.Band != BandHealthy || ov.Reading.SOC == nil || ov.Reading.SOC.Percent != 88 {
			t.Fatalf("overview = %+v, want HEALTHY at 88%%", ov)
		}
		if !ov.HasAutonomy {
			t.Fatal("autonomy must project with configured capacity")
		}
		// reserve = (88-20)/100 × 128 = 87.04 Wh at 12.6×0.5 = 6.3 W measured.
		want := (88 - 20) / 100.0 * 128 / (13.3 * 0.5)
		if math.Abs(ov.Autonomy.Hours-want) > 1e-9 {
			t.Fatalf("autonomy = %v h, want %v", ov.Autonomy.Hours, want)
		}
	})
	t.Run("floor default applies", func(t *testing.T) {
		c := NewChain(Config{DODFloorPercent: 0}) // unset → the hardware.md default
		if c.DODFloor() != DefaultDODFloorPercent {
			t.Fatalf("floor = %v, want the %v default", c.DODFloor(), DefaultDODFloorPercent)
		}
	})
}
