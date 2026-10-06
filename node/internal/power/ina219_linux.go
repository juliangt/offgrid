//go:build linux

// ina219_linux.go — the Linux transport of the INA219-class reader: a
// pure-Go SMBus master over the i2c-dev character device (/dev/i2c-N) using
// golang.org/x/sys/unix ioctls. No cgo, no external libraries — the binary
// stays self-contained (docs/BUILD.md), and the reader is constructed only
// when the operator explicitly configures it (-battery-i2c, issue #36).
//
// Privacy note (docs/protocol.md §13): this transport speaks to a local
// hardware sensor. It reads electrical measurements and nothing else; there
// is no identity, address or message content anywhere near this code path.
package power

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// i2c-dev ioctl numbers (include/uapi/linux/i2c-dev.h).
const (
	i2cSlave     = 0x0703 // set the 7-bit slave address
	i2cSMBUS     = 0x0720 // perform one SMBus transaction
	i2cSMBUSRead = 1
	i2cSMBUSWord = 3 // I2C_SMBUS_WORD_DATA
)

// i2cSMBusData mirrors `struct i2c_smbus_ioctl_data` (the ioctl argument):
// read_write and command are bytes, size a u32, data a pointer to the
// exchange buffer. Field order and Go struct layout match the C ABI on
// every Linux architecture this repo targets (armv6/armv7/arm64 via
// build.sh, plus amd64 dev boxes).
type i2cSMBusData struct {
	readWrite uint8
	command   uint8
	size      uint32
	data      uintptr
}

// i2cReader reads one INA219/INA260-class sensor over i2c-dev. Constructed
// only from an explicitly configured I2CConfig (issue #36: no hard
// dependency — construction failure just drops this link from the chain).
type i2cReader struct {
	cfg I2CConfig
	cal uint16
	f   *os.File
}

// newI2CReader opens the bus, selects the slave address and initializes the
// sensor (configuration + calibration registers).
func newI2CReader(cfg I2CConfig) (*i2cReader, error) {
	cal := inaCalibrationRegister(cfg.ShuntOhms, cfg.MaxCurrentAmps)
	if cal == 0 {
		return nil, fmt.Errorf("power: unusable INA219 config (shunt %g Ω, max current %g A)", cfg.ShuntOhms, cfg.MaxCurrentAmps)
	}
	f, err := os.OpenFile(cfg.BusPath, os.O_RDWR, 0) // i2c-dev needs read/write even for reads
	if err != nil {
		return nil, fmt.Errorf("power: open %s: %w", cfg.BusPath, err)
	}
	if err := ioctl(f.Fd(), i2cSlave, uintptr(cfg.Address)); err != nil {
		f.Close()
		return nil, fmt.Errorf("power: select address 0x%02x on %s: %w", cfg.Address, cfg.BusPath, err)
	}
	r := &i2cReader{cfg: cfg, cal: cal, f: f}
	if err := r.writeRegister(inaRegConfig, inaConfigWord); err != nil {
		f.Close()
		return nil, fmt.Errorf("power: configure INA219: %w", err)
	}
	if err := r.writeRegister(inaRegCalibration, cal); err != nil {
		f.Close()
		return nil, fmt.Errorf("power: calibrate INA219: %w", err)
	}
	return r, nil
}

// read takes one measurement: bus voltage, shunt-derived current and power.
// Any failed register read marks the whole reading unavailable (a partial
// electrical picture is worse than an honest N/A — the page would mix
// instants).
func (r *i2cReader) read() (Reading, bool) {
	busRaw, err := r.readRegister(inaRegBusVoltage)
	if err != nil {
		return Reading{}, false
	}
	shuntRaw, err := r.readRegister(inaRegCurrent)
	if err != nil {
		return Reading{}, false
	}
	current := inaDecodeCurrentAmps(shuntRaw, r.cal, r.cfg.ShuntOhms)
	volts := inaDecodeBusVolts(busRaw)
	if volts <= 0 || current == 0 {
		// An all-zero register pair usually means the sensor dropped off
		// the bus or was never wired: report unavailable, not "0 V".
		return Reading{}, false
	}
	v := volts
	a := current
	return Reading{
		Available:    true,
		ChargeState:  chargeStateFromCurrent(&a),
		VoltageVolts: &v,
		CurrentAmps:  &a,
	}, true
}

// writeRegister sets the register pointer and writes one 16-bit register
// (pointer byte, then MSB, then LSB — the plain byte writes of i2c-dev).
func (r *i2cReader) writeRegister(reg uint8, value uint16) error {
	if err := r.writeByte(reg); err != nil {
		return err
	}
	if err := r.writeByte(uint8(value >> 8)); err != nil {
		return err
	}
	return r.writeByte(uint8(value & 0xff))
}

// readRegister reads one 16-bit register: SMBus write of the register
// pointer followed by an SMBus read-word transaction, byte-swapped (SMBus
// words arrive low byte first; the INA219 register is big-endian).
func (r *i2cReader) readRegister(reg uint8) (uint16, error) {
	var word uint16
	d := i2cSMBusData{
		readWrite: i2cSMBUSRead,
		command:   reg,
		size:      i2cSMBUSWord,
		data:      uintptr(unsafe.Pointer(&word)),
	}
	if err := ioctl(r.f.Fd(), i2cSMBUS, uintptr(unsafe.Pointer(&d))); err != nil {
		return 0, fmt.Errorf("power: read register 0x%02x: %w", reg, err)
	}
	return (word >> 8) | (word << 8), nil
}

// writeByte performs one SMBus byte write (a plain one-byte write() on
// i2c-dev sets the register pointer).
func (r *i2cReader) writeByte(reg uint8) error {
	_, err := r.f.Write([]byte{reg})
	return err
}

// ioctl is the raw syscall wrapper shared by both transaction kinds.
func ioctl(fd, request, arg uintptr) error {
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, fd, request, arg); errno != 0 {
		return errno
	}
	return nil
}

// close releases the bus.
func (r *i2cReader) close() error { return r.f.Close() }
