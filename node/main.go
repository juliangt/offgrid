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
//	           [-tcpcl -tcpcl-node-seed nodeid/node.seed [-tcpcl-addr :4556]
//	            [-tcpcl-peers host:port,...] [-tcpcl-pins node_tcpcl_pins.json]
//	            [-tcpcl-mtls required|optional] [-tcpcl-budget-mib 64]
//	            [-tcpcl-keepalive 30] [-tcpcl-store node_bundles.db]
//	            [-tcpcl-store-cap 5000] [-tcpcl-dial-interval 30]
//	            [-tcpcl-updates -tcpcl-release-key release.pub
//	             [-tcpcl-updates-dir staged/] [-tcpcl-updates-arch esp32s3]
//	            [-tcpcl-debug]]
//
// The daemon is a single static binary (see build.sh): the web UI travels
// inside it via go:embed, so a node is deployed by copying one file. Every
// battery flag is optional — with none set the status page renders the
// battery section as N/A (the reading chain degrades gracefully and never
// becomes a dependency, docs/protocol.md §10.7). The node-plane flags
// (issue #33 P3.4/P3.5) are OFF by default: the daemon is a pure user-plane
// mailbox until -tcpcl turns on the Wi-Fi convergence layer (nodeplane.go;
// received bundles land in the §7.5 bundle store and epidemic-sync at every
// contact — docs/node-network.md §7).
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
	"strings"
	"syscall"
	"time"

	"offgrid/dtn-node/internal/api"
	"offgrid/dtn-node/internal/cleanup"
	"offgrid/dtn-node/internal/forward"
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

// releaseVersion is this build's own §2.1.2 release integer (the anti-
// rollback floor of offline-maintenance §2.6; the node-network §9.1
// staging gate). It is stamped at link time as a STRING (the -X linker
// flag only writes strings) and parsed once at boot:
//
//	go build -ldflags "-X main.releaseVersion=1012000"
//
// Empty (the default) or 0 means "unknown": a build that predates the
// capsule stamp — the anti-rollback floor then rests on the staged capsule
// alone, and a capsule whose min_upgrade_from exceeds the (unknown)
// running release is refused rather than blind-staged (internal/capsule
// Stager.RunningRelease). Stamping this from build.sh is #37 §2.4.3's
// work; the variable and its parsing exist now so the node plane is
// already version-aware.
var releaseVersion = ""

// parseReleaseVersion decodes the -X main.releaseVersion stamp (a decimal
// string; empty or malformed = 0 = unknown, the pre-capsule-build stance —
// never a boot failure: version knowledge degrades, the daemon does not).
func parseReleaseVersion(s string) uint64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0
	}
	return v
}

// shutdownTimeout bounds the graceful-drain window on SIGINT/SIGTERM.
const shutdownTimeout = 10 * time.Second

// HTTP server timeouts (issue #14, NODE-02). ReadHeaderTimeout was always
// set; the remaining three bound the connection-lifetime attacks the
// MaxBytesReader body cap cannot (it bounds SIZE, not TIME) and that
// net/http otherwise leaves at "no timeout":
//
//   - ReadTimeout caps the whole request lifetime (headers + body): a
//     slowloris client can no longer drip a ≤ 1 MiB body indefinitely,
//     holding a connection and its goroutine. 60 s is orders of magnitude
//     above any legitimate phone interaction on the node's own AP (a full
//     1 MiB push is well under 5 s at Wi-Fi speeds).
//   - WriteTimeout caps the response write: a client that never reads cannot
//     pin a writer goroutine. 60 s covers the largest legal response (the
//     ~1 MiB worst-case directory GET, §8.1 NOTE) at captive-portal speeds.
//   - IdleTimeout reaps keep-alive sockets between requests: without it a
//     handful of hoarded idle connections linger forever. 120 s is well
//     above browser keep-alive habits, so honest clients never see a race.
//
// Defense in depth, same spirit as the Track 2 budgets of ratelimit.go: the
// reference deployment's firewall connlimits (32/source, hardening.md §2)
// remain the first brake; the daemon no longer assumes they exist.
const (
	readHeaderTimeout = 5 * time.Second
	readTimeout       = 60 * time.Second
	writeTimeout      = 60 * time.Second
	idleTimeout       = 120 * time.Second
)

// newHTTPServer builds the daemon's http.Server with the full timeout set
// above. Kept as a function (not an inline literal) so the timeout contract
// is assertable by TestNewHTTPServerTimeouts — a regression that silently
// drops one of these fields must fail the suite, not just code review.
func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}
}

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

	// Node-plane TCPCLv4 (issue #33 P3.4, docs/node-network.md §6.3) —
	// OPTIONAL and OFF by default: the fleet behavior and every existing
	// test are untouched unless the operator turns it on. P3.5 wires the
	// real forwarding core behind it (§7 store + sync).
	tcpclEnabled := flag.Bool("tcpcl", false, "serve + dial the node plane (TCPCLv4, RFC 9174 subset) over Wi-Fi/IP; default off")
	tcpclAddr := flag.String("tcpcl-addr", ":4556", "TCPCL listen address (4556 is the IANA TCPCL port)")
	tcpclPeers := flag.String("tcpcl-peers", "", "comma-separated host:port list of node-plane peers to dial opportunistically")
	tcpclNodeSeed := flag.String("tcpcl-node-seed", "", "path to node.seed (64-hex Ed25519 seed, the §2.6 ceremony file); required with -tcpcl")
	tcpclPins := flag.String("tcpcl-pins", "node_tcpcl_pins.json", "path to the TOFU pin store (0600, checkpointed every minute and on shutdown)")
	tcpclMTLS := flag.String("tcpcl-mtls", "required", "client-certificate policy: required|optional (§6.2 item 4: mTLS optional-but-defined)")
	tcpclBudgetMiB := flag.Int("tcpcl-budget-mib", 64, "per-contact transfer budget in MiB (§7.4: 64 MiB, enforced on ingress and egress)")
	tcpclKeepalive := flag.Int("tcpcl-keepalive", 30, "advertised keepalive interval in seconds (RFC 9174 §5.1.1 recommends 30–600; 0 → 30)")
	tcpclStore := flag.String("tcpcl-store", "", "bundle store path (§7.5; default: the -db path with _bundles.db)")
	tcpclStoreCap := flag.Int("tcpcl-store-cap", forward.DefaultCap, "bundle store cap (§7.5: Pi default 5000)")
	tcpclDialInterval := flag.Int("tcpcl-dial-interval", 30, "opportunistic dial interval in seconds (±25% jitter; 0 → 30)")
	tcpclDebug := flag.Bool("tcpcl-debug", false, "log node-plane counter snapshots every minute (RAM-only bookkeeping)")
	// P3.6 management plane (issue #33, docs/node-network.md §8): both files
	// come from the §2.6 provisioning kit. Without the pinned anchor the
	// management plane is OFF (no command or cert could ever verify); without
	// the own cert the node enforces but carries no authority of its own.
	tcpclAnchorPub := flag.String("tcpcl-anchor-pub", "", "path to anchor.pub (the §2.6 pinned trust root); the management plane is OFF without it")
	tcpclNodeCert := flag.String("tcpcl-node-cert", "", "path to node_cert.cbor (the §2.2 provisioned role cert; optional)")
	// P3.7 updates over the plane (issue #33, docs/node-network.md §9):
	// updates_enabled is OFF by default — updates are L2/L3 policy. When on,
	// capsule-chunk bundles are accepted, reassembled and — after signature
	// verification against the PINNED RELEASE KEY and the anti-rollback
	// check — staged atomically into -tcpcl-updates-dir. Nothing is ever
	// AUTO-APPLIED over the plane (the #22 apply path stays operator-gated).
	tcpclUpdates := flag.Bool("tcpcl-updates", false, "accept capsule-chunk bundles (§9.4 updates_enabled; default OFF — chunk cargo is refused and counted)")
	tcpclUpdatesDir := flag.String("tcpcl-updates-dir", "", "staging directory (§2.4.4: <data>/staged/update.capsule; default: the -db directory + /staged)")
	tcpclReleaseKey := flag.String("tcpcl-release-key", "", "path to release.pub (the pinned release key, offline-maintenance §2.2.3); WITHOUT it staging is unavailable and every capsule is refused + counted (fail-closed)")
	tcpclUpdatesArch := flag.String("tcpcl-updates-arch", "", "this node's arch (§9.1 enum: armv6|armv7|arm64|esp32s3|esp32); empty disables the arch gate (stamp from provisioning when #37 lands)")

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

	// Shutdown context: cancelled by SIGINT/SIGTERM; stop() restores the
	// default signal behavior afterwards so a second signal still kills us.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The node plane (P3.4 wiring, P3.5 forwarding core, P3.6 management
	// plane): started ONLY when -tcpcl is set, BEFORE the HTTP handler so
	// the diagnostics surface can read its snapshot (§10.7 node_plane).
	// Its lifetime rides the same signal context, and stop() runs the §6.1
	// graceful SESS_TERM per live session and closes the bundle store before
	// exit. The bundle store defaults to a sibling of the envelope database
	// (its own §7.5 namespace).
	tcpclStorePath := *tcpclStore
	if tcpclStorePath == "" {
		tcpclStorePath = deriveStorePath(*dbPath)
	}
	// The §2.4.4 staging directory defaults to a sibling of the envelope
	// database: on a provisioned Pi (-db /var/lib/dtn-node/node_storage.db,
	// ReadWritePaths=/var/lib/dtn-node) that is exactly the #22 convention
	// /var/lib/dtn-node/staged/update.capsule — the file the upgrade
	// machinery and the future #37 boot-apply unit consume.
	tcpclUpdatesPath := *tcpclUpdatesDir
	if tcpclUpdatesPath == "" {
		tcpclUpdatesPath = filepath.Join(filepath.Dir(*dbPath), "staged")
	}
	nodePlane, err := startNodePlane(ctx, buildTCPCLOptions(
		*tcpclEnabled, *tcpclAddr, *tcpclPeers, *tcpclNodeSeed, *tcpclPins,
		*tcpclMTLS, *tcpclBudgetMiB, *tcpclKeepalive,
		tcpclStorePath, *tcpclStoreCap, *tcpclDialInterval, *tcpclDebug,
		*tcpclNodeCert, *tcpclAnchorPub,
		tcpclUpdatesOptions{
			Enabled:    *tcpclUpdates,
			Dir:        tcpclUpdatesPath,
			ReleaseKey: *tcpclReleaseKey,
			Arch:       *tcpclUpdatesArch,
			OwnRelease: parseReleaseVersion(releaseVersion),
		}), log.Default())
	if err != nil {
		log.Fatalf("cannot start the node plane: %v", err)
	}
	var planeStatus api.NodePlaneSource
	if nodePlane != nil {
		planeStatus = nodePlane // nil members inside render the §10.7 N/A way
	}

	// The embedded web assets (index.html + css/js) are validated and loaded
	// here as well: a broken embed must fail startup, not first request.
	handler, err := api.NewWithCounters(store, counters, build, webFS,
		api.WithStatusEngine(statusEngine), api.WithNodePlane(planeStatus))
	if err != nil {
		log.Fatalf("cannot load embedded web assets: %v", err)
	}

	cleanupCtx, cancelCleanup := context.WithCancel(context.Background())
	defer cancelCleanup()
	cleanup.Start(cleanupCtx, recordingJanitor{store: store, counters: counters}, cleanupInterval)

	statusCtx, cancelStatus := context.WithCancel(context.Background())
	defer cancelStatus()
	statusEngine.Run(statusCtx, 0) // 0 → the default one-minute cadence

	// Bound every phase of a connection's life (see the timeout consts and
	// newHTTPServer above): the bare inline literal with only
	// ReadHeaderTimeout let slow-body drips and idle keep-alive sockets hold
	// connections forever (issue #14, NODE-02).
	srv := newHTTPServer(*addr, handler)

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
		if nodePlane != nil {
			nodePlane.stop() // §6.1 SESS_TERM per session + the pin checkpoint
		}
		cancelCleanup() // stop the janitor before the database handle
		cancelStatus()  // stop the status sampler (issue #36)
		log.Printf("stopped")
	}
}
