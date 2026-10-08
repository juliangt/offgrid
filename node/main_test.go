package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"offgrid/dtn-node/internal/bundle"
	"offgrid/dtn-node/internal/envelope"
	"offgrid/dtn-node/internal/forward"
	"offgrid/dtn-node/internal/health"
	"offgrid/dtn-node/internal/nodeid"
	"offgrid/dtn-node/internal/storage"
	"offgrid/dtn-node/internal/tcpcl"
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

// ---------------------------------------------------------------------------
// Node plane (issue #33 P3.4, nodeplane.go): the config-gated TCPCLv4
// wiring — OFF by default (the tests above and every other suite run with
// it off), ON here: listener + stub sink + honest shutdown.
// ---------------------------------------------------------------------------

// TestNodePlaneDisabledIsNoop pins the default: without -tcpcl the daemon
// boots with NO node-plane endpoints — startNodePlane returns nil, nil and
// nothing listens anywhere.
func TestNodePlaneDisabledIsNoop(t *testing.T) {
	np, err := startNodePlane(context.Background(), tcpclOptions{enabled: false}, testLogger(t))
	if err != nil {
		t.Fatalf("disabled plane must not fail: %v", err)
	}
	if np != nil {
		t.Fatalf("disabled plane must return nil")
	}
	if np.addr() != "" {
		t.Fatalf("a nil plane has no address")
	}
}

// TestNodePlaneRequiresSeed pins the loud config gate: -tcpcl without the
// §2.6 identity file refuses to boot.
func TestNodePlaneRequiresSeed(t *testing.T) {
	opts := tcpclOptions{enabled: true, addr: "127.0.0.1:0", nodeSeedPath: "", pinsPath: filepath.Join(t.TempDir(), "pins.json")}
	if _, err := startNodePlane(context.Background(), opts, testLogger(t)); err == nil {
		t.Fatalf("-tcpcl without -tcpcl-node-seed must fail the boot")
	}
	opts.nodeSeedPath = filepath.Join(t.TempDir(), "missing.seed")
	if _, err := startNodePlane(context.Background(), opts, testLogger(t)); err == nil {
		t.Fatalf("a missing seed file must fail the boot")
	}
}

// TestNodePlaneEndToEnd is the daemon-level leg of §11 rows g/h: the real
// wiring (listener + TOFU pin store + the P3.5 forwarding core) receives a
// bundle from a client session into the §7.5 store, refuses a malformed
// one, answers the §7.1 summary exchange with its own summary bundle,
// checkpoints the pin store, and shuts down gracefully (store closed).
func TestNodePlaneEndToEnd(t *testing.T) {
	dir := t.TempDir()

	// The daemon's identity, straight from the §2.6 file format.
	kp, err := nodeid.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	seedPath := filepath.Join(dir, "node.seed")
	if err := os.WriteFile(seedPath, []byte(hex.EncodeToString(kp.Private.Seed())+"\n"), 0o600); err != nil {
		t.Fatalf("write seed: %v", err)
	}
	daemonEID, err := nodeid.EIDFromPub(kp.Public)
	if err != nil {
		t.Fatalf("eid: %v", err)
	}
	pinsPath := filepath.Join(dir, "pins.json")
	storePath := filepath.Join(dir, "bundles.db")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	np, err := startNodePlane(ctx, tcpclOptions{
		enabled:         true,
		addr:            "127.0.0.1:0",
		nodeSeedPath:    seedPath,
		pinsPath:        pinsPath,
		mtls:            "required",
		budgetMiB:       1,
		keepaliveSec:    5,
		storePath:       storePath,
		storeCap:        100,
		dialIntervalSec: 30,
	}, testLogger(t))
	if err != nil {
		t.Fatalf("start node plane: %v", err)
	}
	if np == nil || !strings.HasPrefix(np.addr(), "127.0.0.1:") {
		t.Fatalf("the plane must serve on an ephemeral loopback port, got %q", np.addr())
	}

	// A client node: fresh identity, pinning the daemon on first contact
	// (TOFU — the exact §6.1 bootstrapping path). Its sink only counts.
	ckp, err := nodeid.GenerateKeyPair()
	if err != nil {
		t.Fatalf("client keygen: %v", err)
	}
	ceid, _ := nodeid.EIDFromPub(ckp.Public)
	ccert, err := nodeid.SelfSignedX509(ckp, ceid, time.Hour)
	if err != nil {
		t.Fatalf("client cert: %v", err)
	}
	clientSink := &countingSink{}
	clientCfg := tcpcl.Config{
		EID:           ceid,
		Identity:      ccert,
		Pins:          nodeid.NewPinStore(),
		MTLS:          tcpcl.MTLSRequired,
		Keepalive:     5 * time.Second,
		ContactBudget: tcpcl.DefaultContactBudget,
		Sink:          clientSink,
		Log:           testLogger(t),
	}
	sess, err := tcpcl.Dial(context.Background(), "tcp", np.addr(), clientCfg)
	if err != nil {
		t.Fatalf("dial the daemon: %v", err)
	}
	if got := sess.PeerEID(); got != daemonEID {
		t.Fatalf("the daemon's certified EID must be %s, got %q", daemonEID, got)
	}

	// One valid bundle lands in the §7.5 store (valid + stored).
	pdu := validMailBundle(t, []byte("daemon-bound envelope"))
	if err := sess.SendBundle(context.Background(), pdu); err != nil {
		t.Fatalf("send to daemon: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if n, _ := np.store.Count(); n == 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if n, _ := np.store.Count(); n != 1 {
		t.Fatalf("the store must hold exactly one bundle, got %d", n)
	}
	if snap := np.store.CountersSnapshot(); snap.Accepted != 1 {
		t.Fatalf("admission counter: %+v", snap)
	}
	// The §7.1 handshake ran: the daemon sent its summary bundle to the
	// client (an ordinary profile bundle; a non-sync peer just absorbs it).
	if got := np.engine.CountersSnapshot().SummariesSent; got != 1 {
		t.Fatalf("the daemon must have sent one summary bundle, got %d", got)
	}

	// A malformed transfer is refused fail-closed.
	if err := sess.SendBundle(context.Background(), []byte("not a bundle")); err == nil {
		t.Fatalf("the malformed transfer must be refused")
	}

	// The §6.1 goodbye, then the plane's own shutdown (idempotent; the
	// bundle store closes last).
	if err := sess.Terminate(tcpcl.TermUnknown); err != nil {
		t.Fatalf("client terminate: %v", err)
	}
	np.stop()
	np.stop() // the second call must be a no-op, never a panic
	if _, err := tcpcl.Dial(context.Background(), "tcp", np.addr(), clientCfg); err == nil {
		t.Fatalf("after shutdown the listener must be gone")
	}

	// The pin store checkpoint exists and parses (trust state persisted).
	raw, err := os.ReadFile(pinsPath)
	if err != nil {
		t.Fatalf("read pin store: %v", err)
	}
	pins, err := nodeid.UnmarshalPinStore(raw)
	if err != nil {
		t.Fatalf("pin store round-trip: %v", err)
	}
	if _, ok := pins.Peer(ceid); !ok {
		t.Fatalf("the daemon must have pinned its first-contact peer %s", ceid)
	}

	// The store survived the shutdown and still holds the bundle (WAL
	// commit on close).
	st, err := forward.Open(forward.Config{Path: storePath})
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer st.Close()
	if n, _ := st.Count(); n != 1 {
		t.Fatalf("reopened store holds %d bundles, want 1", n)
	}
}

// TestDeriveStorePath pins the §7.5 namespace rule: the bundle store is a
// sibling of the envelope database, never inside it.
func TestDeriveStorePath(t *testing.T) {
	cases := map[string]string{
		"node_storage.db":        "node_storage_bundles.db",
		"/var/lib/dtn/node.db":   "/var/lib/dtn/node_bundles.db",
		"plainname":              "plainname_bundles.db",
		"/tmp/x/node_storage.db": "/tmp/x/node_storage_bundles.db",
	}
	for in, want := range cases {
		if got := deriveStorePath(in); got != want {
			t.Fatalf("deriveStorePath(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestBuildTCPCLOptionsPinsPeers pins the flag-to-options mapping.
func TestBuildTCPCLOptionsParsesPeers(t *testing.T) {
	opts := buildTCPCLOptions(true, ":4556", "10.0.0.1:4556, 10.0.0.2:4556", "s", "p", "optional", 32, 60,
		"bundles.db", 5000, 15, true)
	if !opts.enabled || opts.addr != ":4556" || opts.mtls != "optional" || opts.budgetMiB != 32 || opts.keepaliveSec != 60 {
		t.Fatalf("scalar mapping: %+v", opts)
	}
	if len(opts.peers) != 2 || opts.peers[0] != "10.0.0.1:4556" || opts.peers[1] != " 10.0.0.2:4556" {
		t.Fatalf("peer list: %+v", opts.peers)
	}
	if opts.storePath != "bundles.db" || opts.storeCap != 5000 || opts.dialIntervalSec != 15 || !opts.debug {
		t.Fatalf("P3.5 options: %+v", opts)
	}
}

// countingSink is a tcpcl.BundleSink that only counts (the client leg of
// the daemon-level test).
type countingSink struct{ n atomic.Uint64 }

func (s *countingSink) Accept(pdu []byte) error { s.n.Add(1); return nil }

func (s *countingSink) total() uint64 { return s.n.Load() }

// testLogger discards output unless the test fails (kept quiet by
// default; point it at os.Stderr when debugging).
func testLogger(t *testing.T) *log.Logger {
	t.Helper()
	return log.New(io.Discard, "", 0)
}

// validMailBundle encodes a profile-valid mail bundle (the P3.2 codec).
func validMailBundle(t *testing.T, payload []byte) []byte {
	t.Helper()
	b, err := bundle.NewMail(payload, time.Now().UnixMilli(), 3600)
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	pdu, err := bundle.Encode(b)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return pdu
}
