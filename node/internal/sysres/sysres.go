// Package sysres collects the node's system-resource figures for the field
// status page (issue #36, docs/protocol.md §10.7): CPU load, memory, the
// database volume's disk usage, SoC temperature, throttle state and system
// uptime. Everything comes from plain /proc and /sys reads plus one statfs
// call — no external tooling is required, so it is cheap enough for the
// armv6 budget of a Pi Zero W, and every collector is feature-detected:
// a missing /proc or /sys (macOS dev boxes, containers) means the datum is
// reported unavailable, never an error and never a request-path failure.
//
// All parsers are exported and take raw bytes, so the unit tests run on any
// OS against fixture files; the default readers merely wrap os.ReadFile of
// the platform paths. The collectors hold no per-client state and nothing
// here is persisted or logged (docs/protocol.md §13).
package sysres

import (
	"fmt"
	"strconv"
	"strings"
)

// LowFreeBytesFloor is the free-space floor of the disk warning: below 50
// MiB free on the database volume the page renders a warning. The node's
// whole dataset is ≤ 5 MB hot data plus WAL sidecars (docs/hardware.md §5),
// so 50 MiB of headroom means something else is eating the card — a
// full-card symptom long before writes start failing.
const LowFreeBytesFloor = 50 << 20

// Load is the CPU load-average triple plus the coarse saturation
// indicator: fifteen-minute load at or above the core count means the
// single core (Pi Zero W) has been fully busy — a symptom worth an
// operator's glance, nothing finer.
type Load struct {
	One       float64
	Five      float64
	Fifteen   float64
	Cores     int
	Saturated bool
}

// Memory is the memory picture in bytes: total, available (the kernel's
// own estimate — caches included), and used (total − available, the number
// that answers "is the node under memory pressure?").
type Memory struct {
	TotalBytes     int64
	AvailableBytes int64
}

// UsedBytes derives used = total − available.
func (m Memory) UsedBytes() int64 {
	used := m.TotalBytes - m.AvailableBytes
	if used < 0 {
		return 0
	}
	return used
}

// Disk is one filesystem's usage picture in bytes (the database volume —
// statfs of the DB path's directory).
type Disk struct {
	TotalBytes     int64
	FreeBytes      int64
	AvailableBytes int64 // unprivileged-usable free space
}

// UsedBytes derives used = total − free (the operator's "how full is the
// card" number), clamped at zero.
func (d Disk) UsedBytes() int64 {
	used := d.TotalBytes - d.FreeBytes
	if used < 0 {
		return 0
	}
	return used
}

// LowFree reports the free-space floor warning (see LowFreeBytesFloor).
func (d Disk) LowFree() bool {
	return d.FreeBytes > 0 && d.FreeBytes < LowFreeBytesFloor
}

// Readings is one sample of everything the package can observe; a nil
// member means that collector is unavailable on this host (the §10.7 N/A
// convention). Pointers rather than flags keep the zero value "nothing
// known" honestly.
type Readings struct {
	Load          *Load
	Memory        *Memory
	Disk          *Disk
	TempCelsius   *float64
	Throttled     *bool
	UptimeSeconds *int64
}

// ParseLoadAvg parses /proc/loadavg ("0.15 0.10 0.05 1/234 12345") into the
// load triple.
func ParseLoadAvg(b []byte) (Load, error) {
	fields := strings.Fields(string(b))
	if len(fields) < 3 {
		return Load{}, fmt.Errorf("sysres: loadavg needs 3 fields, got %d", len(fields))
	}
	var l Load
	var err error
	if l.One, err = strconv.ParseFloat(fields[0], 64); err != nil {
		return Load{}, fmt.Errorf("sysres: loadavg 1m: %w", err)
	}
	if l.Five, err = strconv.ParseFloat(fields[1], 64); err != nil {
		return Load{}, fmt.Errorf("sysres: loadavg 5m: %w", err)
	}
	if l.Fifteen, err = strconv.ParseFloat(fields[2], 64); err != nil {
		return Load{}, fmt.Errorf("sysres: loadavg 15m: %w", err)
	}
	return l, nil
}

// ParseMemInfo parses /proc/meminfo into the memory picture. Values are
// reported in kB by the kernel; they are returned in bytes. MemAvailable is
// the honest "can the node allocate?" figure (reclaimable caches counted);
// pre-3.14 kernels without it leave the parser to fail — reported N/A, not
// guessed.
func ParseMemInfo(b []byte) (Memory, error) {
	var m Memory
	found := 0
	for _, line := range strings.Split(string(b), "\n") {
		name, value, ok := cutMemInfoLine(line)
		if !ok {
			continue
		}
		switch name {
		case "MemTotal":
			m.TotalBytes = value * 1024
			found++
		case "MemAvailable":
			m.AvailableBytes = value * 1024
			found++
		}
	}
	if found < 2 {
		return Memory{}, fmt.Errorf("sysres: meminfo lacks MemTotal/MemAvailable")
	}
	return m, nil
}

// cutMemInfoLine splits one meminfo line ("MemTotal: 16326484 kB") into its
// name and kB value.
func cutMemInfoLine(line string) (string, int64, bool) {
	name, rest, ok := strings.Cut(line, ":")
	if !ok {
		return "", 0, false
	}
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return "", 0, false
	}
	v, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return "", 0, false
	}
	return strings.TrimSpace(name), v, true
}

// ParseUptime parses /proc/uptime ("12345.67 23456.78") into whole seconds
// of system uptime.
func ParseUptime(b []byte) (int64, error) {
	fields := strings.Fields(string(b))
	if len(fields) < 1 {
		return 0, fmt.Errorf("sysres: empty uptime")
	}
	f, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || f < 0 {
		return 0, fmt.Errorf("sysres: parse uptime %q", fields[0])
	}
	return int64(f), nil
}

// ParseThermalTemp parses one /sys/class/thermal zone `temp` file
// (millidegrees Celsius) into degrees Celsius.
func ParseThermalTemp(b []byte) (float64, error) {
	v, err := strconv.ParseFloat(strings.TrimSpace(string(b)), 64)
	if err != nil {
		return 0, fmt.Errorf("sysres: parse thermal temp %q", strings.TrimSpace(string(b)))
	}
	return v / 1000.0, nil
}

// ParseThrottled parses `vcgencmd get_throttled` output ("throttled=0x0"):
// any nonzero bitmask means the SoC has throttled (undervoltage or
// temperature) since the last clear — coarse by design, a truthful
// "something power/thermal happened" flag for the page.
func ParseThrottled(b []byte) (bool, error) {
	s := strings.TrimSpace(string(b))
	_, hex, ok := strings.Cut(s, "=")
	if !ok {
		return false, fmt.Errorf("sysres: vcgencmd output %q has no value", s)
	}
	v, err := strconv.ParseUint(strings.TrimSpace(hex), 0, 64)
	if err != nil {
		return false, fmt.Errorf("sysres: parse vcgencmd value %q", hex)
	}
	return v != 0, nil
}
