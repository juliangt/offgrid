// Command dtn-node is the self-contained HTTP daemon of Module B: a blind
// SQLite dead-drop node for the off-grid DTN messaging system. It serves the
// embedded portal SPA, the exact API surface of docs/protocolo.md §10, the
// canonical-host redirect with captive-probe exemption (§10.2) and the
// 15-minute expired-envelope janitor (§10.6).
//
// Usage:
//
//	dtn-node [-addr :8080] [-db node_storage.db]
//
// The daemon is a single static binary (see build.sh): the web UI travels
// inside it via go:embed, so a node is deployed by copying one file.
package main

import (
	"context"
	"embed"
	"errors"
	"flag"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"offgrid/dtn-node/internal/api"
	"offgrid/dtn-node/internal/cleanup"
	"offgrid/dtn-node/internal/sdnotify"
	"offgrid/dtn-node/internal/storage"
)

// webFS embeds the single-file portal UI. Sprint 2 replaces the placeholder
// index.html with the real SPA; the endpoint and embedding stay identical.
//
//go:embed web
var webFS embed.FS

// cleanupInterval is the binding janitor period of §10.6 (plus one sweep at
// startup, performed by cleanup.Start).
const cleanupInterval = 15 * time.Minute

// shutdownTimeout bounds the graceful-drain window on SIGINT/SIGTERM.
const shutdownTimeout = 10 * time.Second

func main() {
	log.SetFlags(0)
	log.SetPrefix("dtn-node: ")

	addr := flag.String("addr", ":8080", "HTTP listen address")
	dbPath := flag.String("db", "node_storage.db", "SQLite database file path")
	flag.Parse()

	indexHTML, err := fs.ReadFile(webFS, "web/index.html")
	if err != nil {
		log.Fatalf("embedded web/index.html is missing: %v", err)
	}

	store, err := storage.Open(*dbPath)
	if err != nil {
		log.Fatalf("cannot open storage: %v", err)
	}
	defer store.Close()

	// Shutdown context: cancelled by SIGINT/SIGTERM; stop() restores the
	// default signal behavior afterwards so a second signal still kills us.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cleanupCtx, cancelCleanup := context.WithCancel(context.Background())
	defer cancelCleanup()
	cleanup.Start(cleanupCtx, store, cleanupInterval)

	srv := &http.Server{
		Addr:              *addr,
		Handler:           api.New(store, indexHTML),
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
		log.Printf("stopped")
	}
}
