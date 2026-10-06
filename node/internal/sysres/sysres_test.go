package sysres

// sysres_test.go — unit tests for the system-resource collectors
// (issue #36): byte parsers against fixture files, unavailable fallbacks
// on hosts without /proc or /sys (this suite runs on macOS dev machines —
// the disk collector is the one that answers for real there, via statfs),
// and the saturation indicator.

import (
	"errors"
	"math"
	"strings"
	"testing"
)

func TestParseLoadAvg(t *testing.T) {
	l, err := ParseLoadAvg([]byte("0.15 0.10 0.05 1/234 12345\n"))
	if err != nil {
		t.Fatal(err)
	}
	if l.One != 0.15 || l.Five != 0.10 || l.Fifteen != 0.05 {
		t.Fatalf("got %+v, want 0.15/0.10/0.05", l)
	}
	if _, err := ParseLoadAvg([]byte("1.0 2.0")); err == nil {
		t.Fatal("two fields must fail")
	}
	if _, err := ParseLoadAvg([]byte("x y z 1/1 1")); err == nil {
		t.Fatal("non-numeric fields must fail")
	}
}

func TestParseMemInfo(t *testing.T) {
	fixture := strings.Join([]string{
		"MemTotal:        8192000 kB",
		"MemFree:         1234567 kB",
		"MemAvailable:    4096000 kB",
		"Buffers:          123456 kB",
		"Cached:          2456789 kB",
		"SwapTotal:             0 kB",
		"",
	}, "\n")
	m, err := ParseMemInfo([]byte(fixture))
	if err != nil {
		t.Fatal(err)
	}
	if m.TotalBytes != 8192000*1024 || m.AvailableBytes != 4096000*1024 {
		t.Fatalf("got %+v, want total/available in bytes", m)
	}
	if got := m.UsedBytes(); got != (8192000-4096000)*1024 {
		t.Fatalf("used = %d, want %d", got, (8192000-4096000)*1024)
	}
	if _, err := ParseMemInfo([]byte("MemTotal: 100 kB\n")); err == nil {
		t.Fatal("missing MemAvailable must fail (N/A, not guessed)")
	}
	// Used never goes negative even on a weird fixture.
	m2, err := ParseMemInfo([]byte("MemTotal: 100 kB\nMemAvailable: 200 kB\n"))
	if err != nil {
		t.Fatal(err)
	}
	if m2.UsedBytes() != 0 {
		t.Fatalf("negative used must clamp to 0, got %d", m2.UsedBytes())
	}
}

func TestParseUptime(t *testing.T) {
	u, err := ParseUptime([]byte("123456.78 234567.89\n"))
	if err != nil || u != 123456 {
		t.Fatalf("got %d err=%v, want 123456", u, err)
	}
	if _, err := ParseUptime([]byte("")); err == nil {
		t.Fatal("empty input must fail")
	}
}

func TestParseThermalTemp(t *testing.T) {
	c, err := ParseThermalTemp([]byte("45500\n"))
	if err != nil || c != 45.5 {
		t.Fatalf("got %v err=%v, want 45.5", c, err)
	}
	if _, err := ParseThermalTemp([]byte("hot")); err == nil {
		t.Fatal("non-numeric temp must fail")
	}
}

func TestParseThrottled(t *testing.T) {
	ok, err := ParseThrottled([]byte("throttled=0x0\n"))
	if err != nil || ok {
		t.Fatalf("0x0 must be unthrottled, got %v err=%v", ok, err)
	}
	ok, err = ParseThrottled([]byte("throttled=0x50005"))
	if err != nil || !ok {
		t.Fatalf("nonzero mask must be throttled, got %v err=%v", ok, err)
	}
	if _, err := ParseThrottled([]byte("no value here")); err == nil {
		t.Fatal("output without a value must fail")
	}
}

func TestDiskLowFreeFloor(t *testing.T) {
	if d := (Disk{FreeBytes: LowFreeBytesFloor + 1}); d.LowFree() {
		t.Fatal("free above the floor must not warn")
	}
	if d := (Disk{FreeBytes: LowFreeBytesFloor - 1}); !d.LowFree() {
		t.Fatal("free below the floor must warn")
	}
	if d := (Disk{}); d.LowFree() {
		t.Fatal("unknown disk (zero) must not warn — N/A, not a warning")
	}
}

func TestCollectUnavailableFallBack(t *testing.T) {
	// The zero Readers collects nothing: every member stays nil — the
	// honest "this host has no system telemetry" shape.
	out := Readers{}.Collect()
	if out.Load != nil || out.Memory != nil || out.Disk != nil ||
		out.TempCelsius != nil || out.Throttled != nil || out.UptimeSeconds != nil {
		t.Fatalf("zero readers must collect nothing, got %+v", out)
	}

	// Failing collectors are the same as absent ones: one broken file must
	// never turn into an error or a partial figure.
	failing := Readers{
		LoadAvg:    func() ([]byte, error) { return nil, errors.New("no /proc here") },
		MemInfo:    func() ([]byte, error) { return nil, errors.New("no /proc here") },
		UptimeFile: func() ([]byte, error) { return nil, errors.New("no /proc here") },
		Temp:       func() ([]byte, error) { return nil, errors.New("no /sys here") },
		Throttled:  func() ([]byte, error) { return nil, errors.New("no vcgencmd here") },
		Disk:       func() (Disk, error) { return Disk{}, errors.New("no fs here") },
	}
	out = failing.Collect()
	if out.Load != nil || out.Memory != nil || out.Disk != nil ||
		out.TempCelsius != nil || out.Throttled != nil || out.UptimeSeconds != nil {
		t.Fatalf("failing collectors must degrade to nil members, got %+v", out)
	}
}

func TestCollectHappyPath(t *testing.T) {
	r := Readers{
		LoadAvg:    func() ([]byte, error) { return []byte("1.50 1.00 0.50 2/100 999"), nil },
		MemInfo:    func() ([]byte, error) { return []byte("MemTotal: 100 kB\nMemAvailable: 50 kB\n"), nil },
		UptimeFile: func() ([]byte, error) { return []byte("3600.5 7200.0\n"), nil },
		Temp:       func() ([]byte, error) { return []byte("47500"), nil },
		Throttled:  func() ([]byte, error) { return []byte("throttled=0x0"), nil },
		Disk:       func() (Disk, error) { return Disk{TotalBytes: 100, FreeBytes: 10, AvailableBytes: 5}, nil },
	}
	out := r.Collect()
	if out.Load == nil || out.Load.One != 1.5 || out.Load.Fifteen != 0.5 {
		t.Fatalf("load = %+v", out.Load)
	}
	if out.Memory == nil || out.Memory.UsedBytes() != 50*1024 {
		t.Fatalf("memory = %+v", out.Memory)
	}
	if out.Disk == nil || out.Disk.FreeBytes != 10 {
		t.Fatalf("disk = %+v", out.Disk)
	}
	if out.TempCelsius == nil || math.Abs(*out.TempCelsius-47.5) > 1e-9 {
		t.Fatalf("temp = %v", out.TempCelsius)
	}
	if out.Throttled == nil || *out.Throttled {
		t.Fatalf("throttled = %v", out.Throttled)
	}
	if out.UptimeSeconds == nil || *out.UptimeSeconds != 3600 {
		t.Fatalf("uptime = %v", out.UptimeSeconds)
	}
}

func TestStatDiskAnswersOnUnixHosts(t *testing.T) {
	// statfs works identically on macOS dev boxes and the Pi: the one
	// system figure this suite can assert for real. A temp dir's volume
	// must report a positive total, and free ≤ total.
	d, err := StatDisk(t.TempDir() + "/node_storage.db")
	if err != nil {
		t.Fatalf("statfs of a temp volume: %v", err)
	}
	if d.TotalBytes <= 0 || d.FreeBytes <= 0 || d.FreeBytes > d.TotalBytes {
		t.Fatalf("implausible disk picture: %+v", d)
	}
	if bad, err := StatDisk("/no/such/path/anywhere/db.sqlite"); err == nil {
		t.Fatalf("statfs of a missing path must fail, got %+v", bad)
	}
}
