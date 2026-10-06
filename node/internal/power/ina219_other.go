//go:build !linux

// ina219_other.go — the non-Linux stub of the INA219-class reader: the
// sensor is simply unavailable (no i2c-dev), which is exactly the graceful
// degradation the status page renders as N/A. The decode math in
// ina219.go stays platform-neutral and unit-tested everywhere (issue #36).
package power

import "fmt"

// i2cReader does not exist off Linux; the type only survives so the chain
// can hold the nil pointer uniformly.
type i2cReader struct{}

// newI2CReader always fails off Linux: the I2C sysfs interface is a Linux
// thing. Every failure is uniform "reader unavailable" for the caller.
func newI2CReader(cfg I2CConfig) (*i2cReader, error) {
	return nil, fmt.Errorf("power: i2c is not available on this platform")
}

// read is never reached off Linux (no reader can be constructed).
func (r *i2cReader) read() (Reading, bool) { return Reading{}, false }

func (r *i2cReader) close() error { return nil }
