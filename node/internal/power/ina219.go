// ina219.go — the platform-neutral half of the INA219/INA260-class reader:
// register decode math and the calibration-word computation, unit-tested
// against fixture registers with no hardware attached (issue #36). The
// Linux transport (pure-Go SMBus ioctls over /dev/i2c-N, no cgo) lives in
// ina219_linux.go; other platforms get ina219_other.go, where the reader
// simply reports unavailable.
//
// The datasheet math (TI INA219, SBOS549): the bus-voltage register carries
// the reading in bits 15..3 with a 4 mV LSB; the shunt-voltage register is
// a signed 16-bit value with a 10 µV LSB; the current and power registers
// are signed 16-bit values scaled by the calibration divider computed from
// the shunt resistance and the configured full-scale current.
package power

import "math"

// I2CConfig configures the optional INA219-class reader.
type I2CConfig struct {
	BusPath        string  // e.g. /dev/i2c-1; empty = reader disabled
	Address        uint8   // 7-bit I2C address (INA219: 0x40..0x45)
	ShuntOhms      float64 // shunt resistance (common breakouts: 0.1 Ω)
	MaxCurrentAmps float64 // expected full-scale current (sizes the calibration)
}

// ina219Registers — the register pointers used by the reader (SBOS549 §8.6).
const (
	inaRegConfig      = 0x00
	inaRegBusVoltage  = 0x02
	inaRegPower       = 0x03
	inaRegCurrent     = 0x04
	inaRegCalibration = 0x05
)

// inaConfigWord is the configuration register word written at open: 32 V
// bus range (a 4S LiFePO4 pack never exceeds it), ±320 mV PGA (full-scale
// for a 0.1 Ω shunt at 3.2 A), 12-bit ADC resolution both sides,
// continuous conversion. It is the long-standing default word for this
// class of breakout (0x399F).
const inaConfigWord = 0x399F

// inaCurrentLSBAmps returns the current-register LSB in amperes for a
// calibration divisor: currentLSB = 0.04096 / (calibration × R_shunt)
// (SBOS549 §8.5.2).
func inaCurrentLSBAmps(calibration uint16, shuntOhms float64) float64 {
	if calibration == 0 || shuntOhms <= 0 {
		return 0
	}
	return 0.04096 / (float64(calibration) * shuntOhms)
}

// inaCalibrationRegister computes the calibration register value that makes
// the current register's LSB ≤ MaxCurrentAmps/32768 (the largest divider
// that still covers the wanted full scale): cal = floor(0.04096 /
// (currentLSB × R_shunt)). Returns 0 when the config is unusable (the
// reader then reports unavailable rather than publishing garbage).
func inaCalibrationRegister(shuntOhms, maxCurrentAmps float64) uint16 {
	if shuntOhms <= 0 || maxCurrentAmps <= 0 {
		return 0
	}
	currentLSB := maxCurrentAmps / 32768.0
	cal := math.Floor(0.04096 / (currentLSB * shuntOhms))
	if cal <= 0 || cal > 65535 {
		return 0
	}
	return uint16(cal)
}

// inaDecodeBusVolts decodes the raw bus-voltage register: bits 15..3,
// 4 mV per LSB, in volts.
func inaDecodeBusVolts(raw uint16) float64 {
	return float64(raw>>3) * 0.004
}

// inaDecodeShuntVolts decodes the raw shunt-voltage register: signed 16-bit,
// 10 µV per LSB, in volts.
func inaDecodeShuntVolts(raw uint16) float64 {
	return float64(int16(raw)) * 0.00001
}

// inaDecodeCurrentAmps decodes the raw current register against the
// calibration: signed 16-bit × currentLSB, in amperes.
func inaDecodeCurrentAmps(raw uint16, calibration uint16, shuntOhms float64) float64 {
	return float64(int16(raw)) * inaCurrentLSBAmps(calibration, shuntOhms)
}

// inaDecodePowerWatts decodes the raw power register: signed 16-bit ×
// 20 × currentLSB, in watts (SBOS549 §8.5.3).
func inaDecodePowerWatts(raw uint16, calibration uint16, shuntOhms float64) float64 {
	return float64(int16(raw)) * 20 * inaCurrentLSBAmps(calibration, shuntOhms)
}

// chargeStateFromCurrent classifies the battery-centric current sign into a
// ChargeState, with a small deadband so sensor noise cannot flip the state
// between ticks: positive = charging, negative = discharging, in between =
// idle.
func chargeStateFromCurrent(amps *float64) ChargeState {
	if amps == nil {
		return StateUnknown
	}
	const deadbandAmps = 0.02
	switch {
	case *amps > deadbandAmps:
		return StateCharging
	case *amps < -deadbandAmps:
		return StateDischarging
	default:
		return StateIdle
	}
}
