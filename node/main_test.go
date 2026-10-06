package main

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"offgrid/dtn-node/internal/envelope"
	"offgrid/dtn-node/internal/health"
	"offgrid/dtn-node/internal/storage"
)

// TestEnsureDBDirCreatesNestedPath verifies the cold-start bootstrap: -db in
// a nonexistent nested directory under a temp root gets its parent chain
// created (mode 0750, no world access), reports created=true, and the full
// open path — the exact sequence of main() — succeeds and serves an empty
// pull.
func TestEnsureDBDirCreatesNestedPath(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "var", "lib", "dtn-node", "node_storage.db")

	created, err := ensureDBDir(dbPath)
	if err != nil {
		t.Fatalf("ensureDBDir: %v", err)
	}
	if !created {
		t.Fatalf("a fresh nested directory must be created")
	}

	info, err := os.Stat(filepath.Dir(dbPath))
	if err != nil {
		t.Fatalf("stat created directory: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("parent of db must be a directory")
	}
	if perm := info.Mode().Perm(); perm&0o007 != 0 {
		t.Fatalf("created directory must not be world-accessible, got %o", perm)
	}

	// Full cold-start path as in main(): bootstrap, then open the store.
	store, err := storage.Open(dbPath)
	if err != nil {
		t.Fatalf("storage.Open after bootstrap: %v", err)
	}
	defer store.Close()

	pulled, err := store.PullEnvelopes(nil, 10, time.Now().Unix())
	if err != nil {
		t.Fatalf("pull on fresh store: %v", err)
	}
	if len(pulled) != 0 {
		t.Fatalf("fresh store must be empty, got %+v", pulled)
	}
}

// TestEnsureDBDirNoopWhenExists verifies idempotency: an existing directory
// is left untouched and reported as not-created.
func TestEnsureDBDirNoopWhenExists(t *testing.T) {
	dir := t.TempDir() // exists already

	created, err := ensureDBDir(filepath.Join(dir, "node_storage.db"))
	if err != nil || created {
		t.Fatalf("existing directory must be a no-op, got created=%v err=%v", created, err)
	}

	created, err = ensureDBDir(filepath.Join(dir, "sub", "node_storage.db"))
	if err != nil || !created {
		t.Fatalf("nested missing directory must be created, got created=%v err=%v", created, err)
	}
}

// TestEnsureDBDirBareFilenameIsNoop verifies that a bare filename in the
// current directory (dir == ".") is not mangled: nothing is created anywhere.
func TestEnsureDBDirBareFilenameIsNoop(t *testing.T) {
	created, err := ensureDBDir("node_storage.db")
	if err != nil || created {
		t.Fatalf("bare filename must be a no-op, got created=%v err=%v", created, err)
	}
}

// TestRecordingJanitorRecordsSweeps verifies the issue #31 wiring between the
// §10.6 janitor and the health counters: a completed sweep lands in the
// counters (ttl_sweeps, ttl_swept_envelopes, last_cleanup_* pair) while a
// FAILED sweep is not recorded — the counters only ever report what actually
// happened. This is exactly what main() wraps cleanup.Start with.
func TestRecordingJanitorRecordsSweeps(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "node_storage.db")
	store, err := storage.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	counters := health.NewCounters()
	janitor := recordingJanitor{store: store, counters: counters}

	now := time.Now().Unix()
	expired := envelopeForTest(0xaa, now-7200) // created 2 h ago, ttl 1 h → expired
	live := envelopeForTest(0xbb, now)
	if _, err := store.InsertEnvelopes([]envelope.Envelope{expired, live}); err != nil {
		t.Fatalf("seed envelopes: %v", err)
	}

	deleted, err := janitor.DeleteExpired(now + 1)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("sweep must reap exactly the expired envelope, deleted %d", deleted)
	}
	totals := counters.Totals()
	if totals.TTLSweeps != 1 || totals.TTLSweptEnvelopes != 1 {
		t.Fatalf("completed sweep must be recorded, got %+v", totals)
	}
	if totals.LastCleanupUnix == 0 || totals.LastCleanupEnvelopesDeleted != 1 {
		t.Fatalf("last-cleanup pair must describe the sweep, got %+v", totals)
	}

	// A failing sweep (closed store = the stand-in for a dead storage engine)
	// must leave the counters untouched.
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	if _, err := janitor.DeleteExpired(now + 2); err == nil {
		t.Fatalf("sweep on a closed store must fail")
	}
	totals = counters.Totals()
	if totals.TTLSweeps != 1 || totals.TTLSweptEnvelopes != 1 {
		t.Fatalf("failed sweep must not be recorded, got %+v", totals)
	}
}

// envelopeForTest builds a storage-valid envelope (the §3 shape the store
// persists) with a deterministic id from the seed suffix.
func envelopeForTest(seed byte, createdAt int64) envelope.Envelope {
	raw := make([]byte, 248)
	for i := range raw {
		raw[i] = seed ^ byte(i)
	}
	return envelope.Envelope{
		V:         1,
		ID:        strings.Repeat(fmt.Sprintf("%02x", seed), 32),
		DestHint:  "9f3ab02c1d77e4c1",
		CreatedAt: createdAt,
		TTL:       3600,
		Payload:   base64.StdEncoding.EncodeToString(raw),
	}
}

// TestNewHTTPServerTimeouts pins the connection-lifetime bounds of issue #14
// (NODE-02): every phase of a connection's life must be time-boxed. The
// pre-fix server set only ReadHeaderTimeout, so a hostile station could hold
// connections indefinitely — a slow-body drip (MaxBytesReader bounds SIZE,
// never TIME) or idle keep-alive hoarding — with no daemon-level brake
// (hardening.md A3, Track 2's "shields may be bypassed" assumption). A
// regression that drops one of these fields must fail here, not in review.
func TestNewHTTPServerTimeouts(t *testing.T) {
	handler := http.NewServeMux()
	srv := newHTTPServer(":8080", handler)

	if srv.Handler != http.Handler(handler) {
		t.Fatalf("newHTTPServer must wire the given handler")
	}
	if srv.Addr != ":8080" {
		t.Fatalf("Addr: got %q, want :8080", srv.Addr)
	}
	if srv.ReadHeaderTimeout != readHeaderTimeout {
		t.Fatalf("ReadHeaderTimeout: got %v, want %v", srv.ReadHeaderTimeout, readHeaderTimeout)
	}
	if srv.ReadTimeout != readTimeout {
		t.Fatalf("ReadTimeout: got %v, want %v (slow-body drip must be bounded)", srv.ReadTimeout, readTimeout)
	}
	if srv.WriteTimeout != writeTimeout {
		t.Fatalf("WriteTimeout: got %v, want %v (unread responses must not pin writers)", srv.WriteTimeout, writeTimeout)
	}
	if srv.IdleTimeout != idleTimeout {
		t.Fatalf("IdleTimeout: got %v, want %v (idle keep-alive sockets must be reaped)", srv.IdleTimeout, idleTimeout)
	}
	// The bounds must actually bite: all four are strictly positive and the
	// body/idle windows are longer than the header window (a slow header is
	// cut first; a legitimate big body still fits the generous read window).
	if readHeaderTimeout <= 0 || readTimeout <= 0 || writeTimeout <= 0 || idleTimeout <= 0 {
		t.Fatalf("all timeouts must be positive, got header=%v read=%v write=%v idle=%v",
			readHeaderTimeout, readTimeout, writeTimeout, idleTimeout)
	}
	if readTimeout <= readHeaderTimeout || idleTimeout < readHeaderTimeout {
		t.Fatalf("timeout ordering sanity: read=%v idle=%v must exceed header=%v",
			readTimeout, idleTimeout, readHeaderTimeout)
	}
}
