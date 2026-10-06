// Command dtn-node is the self-contained HTTP daemon of Module B: a blind
// SQLite dead-drop node for the off-grid DTN messaging system. It serves the
// embedded portal SPA, the exact API surface of docs/protocol.md §10
// (including the §15.5 capabilities document), the canonical-host redirect
// with captive-probe exemption (§10.2), the 15-minute expired-envelope
// janitor (§10.6), and the field status surface (§10.7, issues #31/#36:
// health snapshot + operator status view with battery, system and load
// projections fed by a once-a-minute RAM-only sampler).
//
// Usage:
//
//	dtn-node [-addr :8080] [-db node_storage.db]
//	           [-battery-i2c /dev/i2c-1] [-battery-addr 0x40]
//	           [-battery-capacity-wh 128] [-battery-dod-floor 20]
//	           [-battery-full-v 13.6] [-battery-empty-v 12.0]
//
// The daemon is a single static binary (see build.sh): the web UI travels
// inside it via go:embed, so a node is deployed by copying one file. Every
// battery flag is optional — with none set the status page renders the
// battery section as N/A (the reading chain degrades gracefully and never
// becomes a dependency, docs/protocol.md §10.7).
package main

import (
	"context"
	"embed"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"offgrid/dtn-node/internal/api"
	"offgrid/dtn-node/internal/cleanup"
	"offgrid/dtn-node/internal/health"
	"offgrid/dtn-node/internal/power"
	"offgrid/dtn-node/internal/sdnotify"
	"offgrid/dtn-node/internal/status"
	"offgrid/dtn-node/internal/storage"
	"offgrid/dtn-node/internal/sysres"
)

// webFS embeds the portal UI sources: index.html, the /guide quick-start
// page (issue #23) with its screenshots under img/guide/, the stylesheet,
// the plain ES5 scripts under css/ and js/, the §12.1 web app manifest and
// the PNG icons under icons/. They travel inside the single
// static binary (see build.sh) and are served same-origin by the api
// package; a node is still deployed by copying one file.
//
//go:embed web
var webFS embed.FS

// cleanupInterval is the binding janitor period of §10.6 (plus one sweep at
// startup, performed by cleanup.Start).
const cleanupInterval = 15 * time.Minute

// build is the node build identifier served by GET /api/v1/capabilities
// (§15.5: non-empty, free-form — version or VCS string). It defaults to
// "dev"; release builds stamp it at link time, e.g.:
//
//	go build -ldflags "-X main.build=$(git describe --always --dirty)"
//
// The -X key is main.build (not the module path): the linker records a
// source-built main package as "main", so the module-path form does not
// resolve. node/build.sh stamps exactly this way (issue #22: the upgrade
// health gate identities the serving binary by this member).
var build = "dev"

// shutdownTimeout bounds the graceful-drain window on SIGINT/SIGTERM.
const shutdownTimeout = 10 * time.Second

// recordingJanitor adapts *storage.Store to cleanup.Janitor, recording every
// COMPLETED TTL sweep in the shared health counters (issue #31): ttl_sweeps,
// ttl_swept_envelopes and the last_cleanup_unix / last_cleanup_envelopes_deleted
// pair the health snapshot serves. A failed sweep is not recorded — the
// counters only ever report what actually happened. The counters themselves
// are RAM-only and die with the process (internal/health; docs/protocol.md
// §10.7, §13).
type recordingJanitor struct {
	store    *storage.Store
	counters *health.Counters
}

// DeleteExpired implements cleanup.Janitor.
func (r recordingJanitor) DeleteExpired(now int64) (int64, error) {
	deleted, err := r.store.DeleteExpired(now)
	if err == nil {
		r.counters.RecordSweep(now, deleted)
	}
	return deleted, err
}

// ensureDBDir creates the parent directory of dbPath when it does not exist
// yet, so a cold start succeeds on a fresh filesystem — e.g. -db
// /var/lib/dtn-node/node_storage.db on a stock system, where provision.sh
// normally owns that directory but a manual run must not die on first boot.
// It reports whether a directory was created (so the caller can log it);
// bare filenames in the current directory (dir == ".") are a no-op.
func ensureDBDir(dbPath string) (bool, error) {
	dir := filepath.Dir(dbPath)
	if dir == "" || dir == "." {
		return false, nil
	}
	if _, err := os.Stat(dir); !errors.Is(err, fs.ErrNotExist) {
		// Directory exists, or stat failed for another reason: in that case
		// storage.Open below surfaces the real error.
		return false, nil
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return false, fmt.Errorf("create data directory %s: %w", dir, err)
	}
	return true, nil
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("dtn-node: ")

	addr := flag.String("addr", ":8080", "HTTP listen address")
	dbPath := flag.String("db", "node_storage.db", "SQLite database file path")

	// Battery configuration (issue #36, all optional — the status page
	// renders N/A for whatever is not configured; the reading chain is
	// I2C sensor → power_supply sysfs → voltage estimate → unknown).
	batteryI2C := flag.String("battery-i2c", "", "I2C bus device for an INA219/INA260-class sensor (e.g. /dev/i2c-1); empty = disabled")
	batteryAddr := flag.String("battery-addr", "0x40", "I2C address of the sensor (7-bit, 0x hex or decimal)")
	batteryCapacityWh := flag.Float64("battery-capacity-wh", 0, "battery pack capacity in Wh (0 = unknown; autonomy renders N/A without it)")
	batteryDODFloor := flag.Float64("battery-dod-floor", power.DefaultDODFloorPercent, "depth-of-discharge floor in % SoC (CRITICAL band boundary; hardware.md §2.2 default 20)")
	batteryFullV := flag.Float64("battery-full-v", 13.6, "resting full voltage of the pack (4S LiFePO4 default; SoC voltage-estimate anchor)")
	batteryEmptyV := flag.Float64("battery-empty-v", 12.0, "resting empty voltage of the pack (4S LiFePO4 default; SoC voltage-estimate anchor)")

	flag.Parse()

	// Cold start: create the -db parent directory when missing (log it, since
	// an unexpected directory in the filesystem is worth knowing about).
	created, err := ensureDBDir(*dbPath)
	if err != nil {
		log.Fatalf("cannot prepare database location: %v", err)
	}
	if created {
		log.Printf("cold start: created data directory %s", filepath.Dir(*dbPath))
	}

	store, err := storage.Open(*dbPath)
	if err != nil {
		log.Fatalf("cannot open storage: %v", err)
	}
	defer store.Close()

	// One shared RAM-only counter set feeds both the health snapshot (served
	// by the API) and the janitor's sweep bookkeeping (issue #31).
	counters := health.NewCounters()

	// Battery reading chain (issue #36): constructed only when explicitly
	// configured; a failed I2C open (wrong device, no sensor, wrong address)
	// leaves the chain without that link and logs one startup line — it is
	// never a startup failure.
	i2cAddr, err := strconv.ParseUint(*batteryAddr, 0, 16)
	if err != nil || i2cAddr > 0x7f {
		log.Fatalf("invalid -battery-addr %q (want 7-bit I2C address, e.g. 0x40)", *batteryAddr)
	}
	batteryChain := power.NewChain(power.Config{
		I2C: power.I2CConfig{
			BusPath:        *batteryI2C,
			Address:        uint8(i2cAddr),
			ShuntOhms:      0.1, // the common INA219 breakout shunt
			MaxCurrentAmps: 3.2, // full-scale for that shunt (hardware.md §3 BOM class)
		},
		CapacityWh:      *batteryCapacityWh,
		DODFloorPercent: *batteryDODFloor,
		Estimator:       power.VoltageEstimator{FullVolts: *batteryFullV, EmptyVolts: *batteryEmptyV},
	})
	if *batteryI2C != "" && batteryChain.I2CAvailable() {
		log.Printf("battery sensor on %s at 0x%02x (capacity %.0f Wh, DoD floor %.0f%%)", *batteryI2C, i2cAddr, *batteryCapacityWh, batteryChain.DODFloor())
	} else {
		log.Printf("battery: no I2C sensor (%s); power_supply sysfs and voltage estimate apply as available", *batteryI2C)
	}

	// The field status sampler (issue #36): once a minute it takes one cheap
	// sample — a handful of /proc and /sys reads, a few SQL COUNTs, one
	// sensor read when configured — into RAM-only ring buffers. The request
	// path never samples; a reboot clears the projections and the page
	// honestly reports "not enough data yet" until the window refills.
	statusEngine := status.NewEngine(status.Deps{
		Store:    store,
		Counters: counters,
		Battery:  batteryChain,
		System:   sysres.DefaultReaders(*dbPath),
	})

	// The embedded web assets (index.html + css/js) are validated and loaded
	// here as well: a broken embed must fail startup, not first request.
	handler, err := api.NewWithCounters(store, counters, build, webFS, api.WithStatusEngine(statusEngine))
	if err != nil {
		log.Fatalf("cannot load embedded web assets: %v", err)
	}

	// Shutdown context: cancelled by SIGINT/SIGTERM; stop() restores the
	// default signal behavior afterwards so a second signal still kills us.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cleanupCtx, cancelCleanup := context.WithCancel(context.Background())
	defer cancelCleanup()
	cleanup.Start(cleanupCtx, recordingJanitor{store: store, counters: counters}, cleanupInterval)

	statusCtx, cancelStatus := context.WithCancel(context.Background())
	defer cancelStatus()
	statusEngine.Run(statusCtx, 0) // 0 → the default one-minute cadence

	srv := &http.Server{
		Addr:              *addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	// Bind before serving so readiness is a hard fact: the sd_notify READY=1
	// below must only be sent once the socket truly accepts connections.
	// (Outside systemd sdnotify is a no-op and this behaves like plain
	// ListenAndServe.)
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("cannot listen on %s: %v", *addr, err)
	}

	serverErr := make(chan error, 1)
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	// Type=notify contract (raspberry/systemd/dtn-node.service): announce
	// readiness once listening, then keep the watchdog fed at half its
	// interval. Both are silent no-ops when not running under systemd.
	if err := sdnotify.Ready(); err != nil {
		log.Printf("sd_notify READY failed (continuing): %v", err)
	}
	sdnotify.StartWatchdog()

	log.Printf("listening on %s (db: %s) — canonical origin http://%s/", *addr, *dbPath, api.CanonicalHost)

	select {
	case err := <-serverErr:
		log.Printf("server error: %v", err)
		_ = srv.Close()
		os.Exit(1)
	case <-ctx.Done():
		stop()
		log.Printf("shutting down...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Printf("graceful shutdown timed out: %v", err)
		}
		cancelCleanup() // stop the janitor before the database handle
		cancelStatus()  // stop the status sampler (issue #36)
		log.Printf("stopped")
	}
}
