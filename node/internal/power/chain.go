// chain.go — the battery reading chain of the status page (issue #36):
// I2C sensor → power_supply sysfs → voltage estimate → honest unknown.
// The chain is the ONE power.Reader the status sampler talks to; it owns
// the configured capacity and DoD floor and reduces a raw Reading to the
// operator-facing Overview (alert band + autonomy projection).
//
// No reader is ever a hard dependency: an unconfigured or failing link is
// skipped, and a chain with no answer at all reports unavailable — the
// JSON layer renders null (N/A) and the page says so. Nothing in this
// package persists, logs or touches the network (docs/protocol.md §13).
package power

import "sync"

// Config is the operator-provided battery configuration (flags -battery-*
// in node/main.go).
type Config struct {
	I2C             I2CConfig // enabled only when I2C.BusPath != ""
	CapacityWh      float64   // 0 = unknown capacity → autonomy renders N/A
	DODFloorPercent float64   // CRITICAL band boundary; default DefaultDODFloorPercent
	Estimator       VoltageEstimator
}

// Reader is anything that can take one electrical measurement.
type Reader interface {
	Read() Reading
}

// Chain is the configured reader chain plus the capacity/floor context the
// page math needs. Safe for concurrent use (the status sampler is the only
// production caller; the mutex keeps tests honest too).
type Chain struct {
	mu    sync.Mutex
	cfg   Config
	i2c   *i2cReader
	sysfs *powerSupplyReader
}

// NewChain builds the chain from the configuration. The I2C link is
// attempted only when BusPath is set; a failed open (wrong device, no
// sensor, non-Linux host) is logged by the caller once at startup — NOT by
// this package — and simply leaves the chain without that link.
func NewChain(cfg Config) *Chain {
	c := &Chain{cfg: cfg}
	if cfg.DODFloorPercent <= 0 || cfg.DODFloorPercent >= 100 {
		c.cfg.DODFloorPercent = DefaultDODFloorPercent
	}
	if cfg.I2C.BusPath != "" {
		if r, err := newI2CReader(cfg.I2C); err == nil {
			c.i2c = r
		}
	}
	c.sysfs = newPowerSupplyReader()
	return c
}

// I2CAvailable reports whether the I2C link opened — startup logs one line
// about the battery configuration based on this.
func (c *Chain) I2CAvailable() bool { return c.i2c != nil }

// Read walks the chain: the I2C sensor wins when configured and answering
// (it also carries the measured current the autonomy math prefers); the
// power_supply sysfs tree is next; the voltage estimator turns any voltage
// into a coarse SoC last. Returns (Reading, false) when nothing answered —
// the honest unknown.
func (c *Chain) Read() (Reading, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.i2c != nil {
		if rd, ok := c.i2c.read(); ok {
			c.finish(&rd)
			return rd, true
		}
	}
	if rd, ok := c.sysfs.read(); ok {
		c.finish(&rd)
		return rd, true
	}
	return Reading{}, false
}

// ReadHealth returns the pack state-of-health estimate (percent) when the
// attached BMS publishes full-vs-design capacity; unavailable otherwise
// (voltage-only setups cannot measure wear — the page renders N/A).
func (c *Chain) ReadHealth() (float64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sysfs.readHealth()
}

// finish tops up a raw sensor reading with the derived SoC when the sensor
// did not provide one (the chain's voltage-estimate step) — never
// overwriting a coulomb-counted figure.
func (c *Chain) finish(rd *Reading) {
	if rd.SOC == nil {
		if soc, ok := c.cfg.Estimator.Estimate(rd.VoltageVolts); ok {
			rd.SOC = &soc
		}
	}
}

// DODFloor returns the effective DoD floor percentage (the configured
// value, or the hardware.md §2.2 default).
func (c *Chain) DODFloor() float64 { return c.cfg.DODFloorPercent }

// CapacityWh returns the configured pack capacity in watt-hours (0 =
// unknown — autonomy renders N/A without it).
func (c *Chain) CapacityWh() float64 { return c.cfg.CapacityWh }

// Overview is the operator-facing reduction of one reading: the raw state
// plus the alert band and the autonomy projection, all N/A-able. It is the
// shape the JSON battery member is built from. DODFloorPercent echoes the
// configured CRITICAL boundary and CapacityWh the configured pack capacity
// (0 = unknown) so the page can state both next to the numbers they gate.
type Overview struct {
	Reading         Reading
	Band            Band
	Autonomy        Autonomy
	HasAutonomy     bool
	DODFloorPercent float64
	CapacityWh      float64
}

// Overview reduces r against the chain's configuration.
func (c *Chain) Overview(r Reading) Overview {
	autonomy, ok := EstimateAutonomy(r, c.cfg.CapacityWh, c.cfg.DODFloorPercent)
	return Overview{
		Reading:         r,
		Band:            AlertBand(r, c.cfg.DODFloorPercent),
		Autonomy:        autonomy,
		HasAutonomy:     ok,
		DODFloorPercent: c.cfg.DODFloorPercent,
		CapacityWh:      c.cfg.CapacityWh,
	}
}
