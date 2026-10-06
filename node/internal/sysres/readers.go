// readers.go — the default collectors of the sysres package: plain file
// reads of /proc and /sys, one statfs of the database volume and (only when
// the binary happens to be installed) one vcgencmd execution — all run at
// the status sampler's cadence (once a minute), never per request
// (issue #36). Every collector is a func field, so tests substitute fixture
// readers and hosts without /proc degrade to unavailable members.
package sysres

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"golang.org/x/sys/unix"
)

// Readers bundles the collectors. The zero value is usable and reports
// nothing (every member nil) — the "no system telemetry" configuration.
type Readers struct {
	// LoadAvg reads /proc/loadavg's bytes.
	LoadAvg func() ([]byte, error)
	// MemInfo reads /proc/meminfo's bytes.
	MemInfo func() ([]byte, error)
	// UptimeFile reads /proc/uptime's bytes.
	UptimeFile func() ([]byte, error)
	// Thermal reads one SoC thermal-zone temp file's bytes.
	Temp func() ([]byte, error)
	// Throttled runs the throttle probe (vcgencmd) and returns its output.
	Throttled func() ([]byte, error)
	// DiskFS stats the database volume.
	Disk func() (Disk, error)
}

// DefaultPaths are the Linux paths the default readers probe.
const (
	procLoadAvg = "/proc/loadavg"
	procMemInfo = "/proc/meminfo"
	procUptime  = "/proc/uptime"
	thermalGlob = "/sys/class/thermal/thermal_zone*/temp"
)

// DefaultReaders returns the production collector set. dbPath's parent
// directory is the database volume whose free space the page watches.
// vcgencmd is feature-detected ONCE here (a PATH lookup at construction):
// on a stock Pi OS Lite without libraspberrypi-bin the collector is simply
// absent — the package must never require it.
func DefaultReaders(dbPath string) Readers {
	return Readers{
		LoadAvg:    func() ([]byte, error) { return os.ReadFile(procLoadAvg) },
		MemInfo:    func() ([]byte, error) { return os.ReadFile(procMemInfo) },
		UptimeFile: func() ([]byte, error) { return os.ReadFile(procUptime) },
		Temp:       thermalZoneReader(),
		Throttled:  vcgencmdThrottledReader(),
		Disk:       func() (Disk, error) { return StatDisk(dbPath) },
	}
}

// thermalZoneReader returns a reader over the first readable
// /sys/class/thermal zone temp file, or nil (unavailable) when the glob
// matches nothing — resolved once at construction, cheap on every host.
func thermalZoneReader() func() ([]byte, error) {
	zones, err := filepath.Glob(thermalGlob)
	if err != nil || len(zones) == 0 {
		return nil
	}
	path := zones[0]
	return func() ([]byte, error) { return os.ReadFile(path) }
}

// vcgencmdThrottledReader returns a reader that execs `vcgencmd
// get_throttled` when vcgencmd exists in PATH, else nil.
func vcgencmdThrottledReader() func() ([]byte, error) {
	path, err := exec.LookPath("vcgencmd")
	if err != nil {
		return nil
	}
	return func() ([]byte, error) {
		out, err := exec.Command(path, "get_throttled").Output()
		if err != nil {
			return nil, err
		}
		return out, nil
	}
}

// StatDisk stats the filesystem holding path (the DB volume) into the Disk
// picture. Pure statfs — works identically on the Pi and on macOS dev
// boxes, so the disk figures are the one system reading a dev machine
// shows for real.
func StatDisk(path string) (Disk, error) {
	dir := filepath.Dir(path)
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return Disk{}, err
	}
	d := Disk{
		TotalBytes:     int64(st.Blocks) * int64(st.Bsize),
		FreeBytes:      int64(st.Bfree) * int64(st.Bsize),
		AvailableBytes: int64(st.Bavail) * int64(st.Bsize),
	}
	if d.TotalBytes <= 0 {
		return Disk{}, ErrUnavailable
	}
	return d, nil
}

// ErrUnavailable marks a collector whose platform data does not exist; it
// is never surfaced anywhere — callers map it to a nil Readings member.
var ErrUnavailable = unavailableError{}

type unavailableError struct{}

func (unavailableError) Error() string { return "sysres: unavailable on this platform" }

// Collect runs every configured collector, mapping each failure to an
// unavailable member (nil) and never failing as a whole: a missing /proc
// on a dev box must not perturb anything but that one reading.
func (r Readers) Collect() Readings {
	var out Readings
	if r.LoadAvg != nil {
		if b, err := r.LoadAvg(); err == nil {
			if l, err := ParseLoadAvg(b); err == nil {
				l.Cores = runtime.NumCPU()
				l.Saturated = l.Fifteen >= float64(l.Cores)
				out.Load = &l
			}
		}
	}
	if r.MemInfo != nil {
		if b, err := r.MemInfo(); err == nil {
			if m, err := ParseMemInfo(b); err == nil {
				out.Memory = &m
			}
		}
	}
	if r.Disk != nil {
		if d, err := r.Disk(); err == nil {
			out.Disk = &d
		}
	}
	if r.Temp != nil {
		if b, err := r.Temp(); err == nil {
			if t, err := ParseThermalTemp(b); err == nil {
				out.TempCelsius = &t
			}
		}
	}
	if r.Throttled != nil {
		if b, err := r.Throttled(); err == nil {
			if th, err := ParseThrottled(b); err == nil {
				out.Throttled = &th
			}
		}
	}
	if r.UptimeFile != nil {
		if b, err := r.UptimeFile(); err == nil {
			if u, err := ParseUptime(b); err == nil {
				out.UptimeSeconds = &u
			}
		}
	}
	return out
}
