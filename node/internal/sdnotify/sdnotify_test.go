package sdnotify

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// startFakeManager emulates the service manager's end of $NOTIFY_SOCKET: it
// listens on a unixgram socket in a temp directory. It returns the socket
// address, a reader that fetches the next datagram with a deadline, and a
// prober that asserts nothing arrives within its own (short) window.
func startFakeManager(t *testing.T) (addr string, next func() string, expectSilence func()) {
	t.Helper()
	addr = filepath.Join(t.TempDir(), "notify.sock")
	if len(addr) >= 100 {
		// darwin caps sun_path at 104 bytes (including NUL); when the platform
		// temp dir makes the path too long, fall back to a short one. The dir
		// is left behind on purpose: the pinger under test is intentionally
		// immortal and must keep finding its socket for the rest of the run.
		dir, err := os.MkdirTemp("/tmp", "sdnotify-test")
		if err != nil {
			t.Fatalf("short temp dir: %v", err)
		}
		addr = filepath.Join(dir, "notify.sock")
	}
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: addr, Net: "unixgram"})
	if err != nil {
		t.Fatalf("listen %s: %v", addr, err)
	}
	// Deliberately NOT closed in a t.Cleanup: the process-lifetime pinger
	// keeps sending to this socket after the test ends, and closing it here
	// would fill the test log with expected ECONNREFUSED lines.

	read := func(wait time.Duration) (string, error) {
		buf := make([]byte, 64)
		if err := conn.SetReadDeadline(time.Now().Add(wait)); err != nil {
			t.Fatalf("set read deadline: %v", err)
		}
		n, _, err := conn.ReadFromUnix(buf)
		if err != nil {
			return "", err
		}
		return string(buf[:n]), nil
	}

	next = func() string {
		msg, err := read(2 * time.Second)
		if err != nil {
			t.Fatalf("read datagram: %v", err)
		}
		return msg
	}
	expectSilence = func() {
		// A pinger with a sane cadence would have delivered at least one ping
		// within this window (the first ping is immediate by design).
		if msg, err := read(60 * time.Millisecond); err == nil {
			t.Fatalf("unexpected datagram %q: no pinger should be running", msg)
		}
	}
	return addr, next, expectSilence
}

// TestReadyAndWatchdogPings runs the package against a fake service manager:
// Ready must deliver exactly READY=1, and StartWatchdog must start pinging
// WATCHDOG=1 with a cadence derived from a (short, fake) WATCHDOG_USEC.
func TestReadyAndWatchdogPings(t *testing.T) {
	addr, next, _ := startFakeManager(t)
	t.Setenv("NOTIFY_SOCKET", addr)
	t.Setenv("WATCHDOG_USEC", "40000") // 40 ms -> expected ping cadence 20 ms

	if err := Ready(); err != nil {
		t.Fatalf("Ready: %v", err)
	}
	StartWatchdog()

	if got := next(); got != "READY=1" {
		t.Fatalf("first datagram = %q, want %q", got, "READY=1")
	}
	// The first watchdog ping is immediate; the next follows the half-interval
	// cadence. Both must arrive well inside the 2 s reader deadline.
	if got := next(); got != "WATCHDOG=1" {
		t.Fatalf("second datagram = %q, want %q", got, "WATCHDOG=1")
	}
	if got := next(); got != "WATCHDOG=1" {
		t.Fatalf("third datagram = %q, want %q", got, "WATCHDOG=1")
	}
}

// TestNoopOutsideSystemd verifies the silent-no-op contract: with the
// environment unset, Ready reports no error and StartWatchdog does not panic
// or send anything (there is no socket to send to).
func TestNoopOutsideSystemd(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	t.Setenv("WATCHDOG_USEC", "40000")
	if err := Ready(); err != nil {
		t.Fatalf("Ready without NOTIFY_SOCKET: %v", err)
	}
	StartWatchdog()
}

// TestWatchdogSkipsOnMalformedUseC verifies that a non-numeric WATCHDOG_USEC
// is skipped silently instead of spawning a pinger with a bogus interval.
func TestWatchdogSkipsOnMalformedUseC(t *testing.T) {
	addr, _, expectSilence := startFakeManager(t)
	t.Setenv("NOTIFY_SOCKET", addr)
	t.Setenv("WATCHDOG_USEC", "soon")
	StartWatchdog()
	expectSilence()
}

// TestWatchdogSkipsOnZeroUseC verifies that a zero (or negative) WATCHDOG_USEC
// disables the pinger rather than spinning with a zero interval.
func TestWatchdogSkipsOnZeroUseC(t *testing.T) {
	addr, _, expectSilence := startFakeManager(t)
	t.Setenv("NOTIFY_SOCKET", addr)
	t.Setenv("WATCHDOG_USEC", "0")
	StartWatchdog()
	expectSilence()
}
