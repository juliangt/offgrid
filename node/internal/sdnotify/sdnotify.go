// Package sdnotify implements the small slice of the systemd sd_notify(3)
// protocol that dtn-node needs to run as a Type=notify service with a
// watchdog (raspberry/systemd/dtn-node.service): a READY=1 datagram once the
// HTTP listener is up, and periodic WATCHDOG=1 pings so the service manager
// restarts the daemon if it ever wedges.
//
// It is pure Go over the AF_UNIX datagram socket named by $NOTIFY_SOCKET —
// no cgo and no third-party dependency, keeping the static-binary deployment
// model of build.sh intact. Every entry point degrades to a silent no-op when
// the environment is unset, so the same binary keeps working under `go run .`
// and outside systemd.
package sdnotify

import (
	"log"
	"net"
	"os"
	"strconv"
	"time"
)

// envSocket returns the service manager's socket address, or "" when not
// running under one. Abstract-namespace sockets (systemd's default, written
// "@...") pass through unchanged: net.Dial maps a leading "@" onto the Linux
// abstract namespace natively.
func envSocket() string {
	return os.Getenv("NOTIFY_SOCKET")
}

// notify sends one datagram to the service manager.
func notify(addr, msg string) error {
	conn, err := net.Dial("unixgram", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte(msg))
	return err
}

// Ready announces READY=1 to the service manager. Call it once the daemon is
// actually serving traffic: under Type=notify, startup is not considered
// complete (and units ordered after this one are not started) until the
// message is sent. Returns the transport outcome so the caller can log it;
// a nil error outside systemd is the normal no-op case.
func Ready() error {
	addr := envSocket()
	if addr == "" {
		return nil
	}
	return notify(addr, "READY=1")
}

// StartWatchdog spawns the WATCHDOG=1 pinger and returns immediately.
//
// The service manager allows WATCHDOG_USEC microseconds per round; per the
// sd_notify(3) guidance the daemon pings at half that interval. The first
// ping is sent immediately — the manager restarts its timeout on every ping,
// so sending early maximizes the safety margin. When WATCHDOG_USEC is unset
// or malformed there is no watchdog to satisfy and this function does
// nothing. The goroutine intentionally lives for the whole process lifetime:
// if pings stop, the manager kills the process anyway, so no stop channel is
// required.
func StartWatchdog() {
	addr := envSocket()
	usec, err := strconv.Atoi(os.Getenv("WATCHDOG_USEC"))
	if addr == "" || err != nil || usec <= 0 {
		return
	}
	interval := time.Duration(usec) * time.Microsecond / 2
	go watchdogLoop(addr, interval)
}

// watchdogLoop dials the manager's socket ONCE (the connected datagram socket
// keeps delivering after that, matching systemd's own sd_notify implementation,
// which holds one fd) and pings at the given cadence. If the socket dies the
// watchdog is unsatisfiable — the manager is stopping us and will kill the
// process — so the loop reports it and exits instead of spamming errors
// forever.
func watchdogLoop(addr string, interval time.Duration) {
	conn, err := net.Dial("unixgram", addr)
	if err != nil {
		log.Printf("dtn-node: watchdog socket connect failed: %v", err)
		return
	}
	defer conn.Close()
	ping := func() {
		if _, err := conn.Write([]byte("WATCHDOG=1")); err != nil {
			log.Printf("dtn-node: watchdog ping failed: %v", err)
		}
	}
	ping()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		ping()
	}
}
