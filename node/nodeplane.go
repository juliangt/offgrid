package main

// nodeplane.go — the daemon wiring of the node plane (docs/node-network.md
// §6.3, §7; issue #33): the TCPCLv4 listener + dialer, the P3.5 bundle store
// (§7.5) and the epidemic sync engine (§7.1) behind the §7.3/§7.4
// discipline. Everything here is config-gated: with no -tcpcl flag the
// daemon behaves EXACTLY as before (the whole existing suite stays green
// with the plane OFF).
//
// P3.5 replaces the P3.4 counting stub: received bundles land in the
// SQLite bundle store, every established session runs the §7.1
// summary/diff exchange (summaries ride the bundle plane — see
// internal/forward/sync.go), and the outbound pump honors the §7.4 budget
// (deferrals retry on the next contact). Counters stay internal RAM-only
// bookkeeping — /status wiring is P3.6's; -tcpcl-debug logs snapshots.

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"math/rand"
	"os"
	"strings"
	"sync"
	"time"

	"offgrid/dtn-node/internal/forward"
	"offgrid/dtn-node/internal/nodeid"
	"offgrid/dtn-node/internal/tcpcl"
)

// bundleJanitorInterval is the node-plane bundle janitor cadence: the §10.6
// idiom (15 min + one sweep at boot) applied to the §7.5 expiry.
const bundleJanitorInterval = 15 * time.Minute

// contactWindow bounds ONE outbound contact (the RFC 4838 opportunistic-
// contact model, §2.7/§7.1): the session is held just long enough for the
// §7.1 summary exchange and the diff pump — both complete in milliseconds
// between two daemons, and SummaryWait bounds the wait for a non-syncing
// peer — then it is terminated and the loop waits for the next (jittered)
// interval. Bundles injected AFTER a contact ride the NEXT one, exactly
// like cargo arriving between LoRa wake windows.
const contactWindow = 2 * time.Second

// tcpclOptions is the parsed -tcpcl-* flag set (built by main, consumed by
// startNodePlane so tests can drive the wiring without flag parsing).
type tcpclOptions struct {
	enabled         bool
	addr            string
	peers           []string
	nodeSeedPath    string
	pinsPath        string
	mtls            string
	budgetMiB       int
	keepaliveSec    int
	storePath       string // "" → derived from the -db path
	storeCap        int    // 0 → forward.DefaultCap
	dialIntervalSec int    // 0 → 30 s; opportunistic dial cadence with jitter
	debug           bool   // periodic counter/log snapshots
}

// nodePlane owns the running TCPCL endpoints and the forwarding engine of
// this daemon.
type nodePlane struct {
	cfg      tcpcl.Config
	ln       *tcpcl.Listener // always present while the plane runs
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	pinsPath string
	stopOnce sync.Once

	store  *forward.Store
	engine *forward.Engine
	sink   *forward.Sink
	pins   *nodeid.PinStore
}

// deriveStorePath names the bundle-store file for a given envelope-store
// path: node_storage.db → node_storage_bundles.db (sibling file, own
// namespace per §7.5 — the user-plane database is never touched).
func deriveStorePath(dbPath string) string {
	const suffix = ".db"
	p := dbPath
	if strings.HasSuffix(p, suffix) {
		p = strings.TrimSuffix(p, suffix) + "_bundles.db"
	} else {
		p = p + "_bundles.db"
	}
	return p
}

// loadNodeSeed reads a 32-byte hex Ed25519 seed (the capsuletool
// node.seed format) and derives the node identity.
func loadNodeSeed(path string) (nodeid.KeyPair, string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nodeid.KeyPair{}, "", err
	}
	hx := strings.TrimSpace(string(raw))
	if len(hx) != 2*nodeid.SeedLen {
		return nodeid.KeyPair{}, "", fmt.Errorf("%s: want %d hex chars (a %d-byte seed), got %d chars", path, 2*nodeid.SeedLen, nodeid.SeedLen, len(hx))
	}
	seed, err := hex.DecodeString(hx)
	if err != nil {
		return nodeid.KeyPair{}, "", fmt.Errorf("%s: not hex: %w", path, err)
	}
	kp, err := nodeid.NewKeyPairFromSeed(seed)
	if err != nil {
		return nodeid.KeyPair{}, "", err
	}
	eid, err := nodeid.EIDFromPub(kp.Public)
	if err != nil {
		return nodeid.KeyPair{}, "", err
	}
	return kp, eid, nil
}

// loadPinStore loads the TOFU pin store from path, creating an empty one
// (0600) when absent. A corrupt store FAILS the boot — pins are trust
// state, never something to silently discard.
func loadPinStore(path string) (*nodeid.PinStore, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		pins := nodeid.NewPinStore()
		if err := writePinStore(path, pins); err != nil {
			return nil, err
		}
		return pins, nil
	}
	pins, err := nodeid.UnmarshalPinStore(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return pins, nil
}

// writePinStore persists the pin store atomically (temp file + rename,
// 0600 — it is trust state).
func writePinStore(path string, pins *nodeid.PinStore) error {
	blob, err := pins.Marshal()
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, blob, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// startNodePlane boots the node plane: identity → certificate → pin store →
// bundle store → sync engine → listener (+ peer dial loop + bundle janitor).
// ctx cancellation shuts everything down gracefully (§6.1 SESS_TERM per
// session, via Listener.Close; the store commits and closes last).
func startNodePlane(ctx context.Context, opts tcpclOptions, lg *log.Logger) (*nodePlane, error) {
	if !opts.enabled {
		return nil, nil
	}
	if opts.nodeSeedPath == "" {
		return nil, fmt.Errorf("-tcpcl needs -tcpcl-node-seed (the node identity of docs/node-network.md §2)")
	}
	kp, eid, err := loadNodeSeed(opts.nodeSeedPath)
	if err != nil {
		return nil, fmt.Errorf("load node seed: %w", err)
	}
	if info, statErr := os.Stat(opts.nodeSeedPath); statErr == nil && info.Mode().Perm()&0o077 != 0 {
		lg.Printf("node-plane: WARNING: %s is readable beyond the owner (mode %o) — the §2.6 ceremony wants 0600", opts.nodeSeedPath, info.Mode().Perm())
	}
	cert, err := nodeid.SelfSignedX509(kp, eid, nodeid.DefaultCertValidity)
	if err != nil {
		return nil, fmt.Errorf("build node certificate: %w", err)
	}
	pins, err := loadPinStore(opts.pinsPath)
	if err != nil {
		return nil, fmt.Errorf("load pin store: %w", err)
	}

	var mtls tcpcl.MTLSMode
	switch opts.mtls {
	case "", "required":
		mtls = tcpcl.MTLSRequired
	case "optional":
		mtls = tcpcl.MTLSOptional
	default:
		return nil, fmt.Errorf("-tcpcl-mtls must be required|optional, got %q", opts.mtls)
	}
	budget := int64(opts.budgetMiB) << 20
	if budget <= 0 {
		budget = tcpcl.DefaultContactBudget
	}
	keepalive := time.Duration(opts.keepaliveSec) * time.Second
	if keepalive == 0 {
		keepalive = tcpcl.DefaultKeepalive
	}

	// The P3.5 forwarding core (§7.5 store + §7.1 sync engine + the routing
	// sink that tells summary bundles from cargo). main fills storePath
	// (derived from the -db path when the flag is empty).
	store, err := forward.Open(forward.Config{Path: opts.storePath, Cap: opts.storeCap, Log: lg})
	if err != nil {
		return nil, fmt.Errorf("open bundle store: %w", err)
	}
	engine := forward.NewEngine(store, eid, lg)
	sink := &forward.Sink{Store: store, Engine: engine, LocalEID: eid}

	np := &nodePlane{
		pins:     pins,
		pinsPath: opts.pinsPath,
		store:    store,
		engine:   engine,
		sink:     sink,
	}
	np.cfg = tcpcl.Config{
		EID:           eid,
		Identity:      cert,
		Pins:          pins,
		MTLS:          mtls,
		Keepalive:     keepalive,
		ContactBudget: budget,
		Sink:          sink,
		OnEstablished: engine.HandleSession,
		Log:           lg,
	}

	// Own context: the plane outlives this function, dies with ctx.
	planeCtx, cancel := context.WithCancel(context.Background())
	np.cancel = cancel

	ln, err := tcpcl.Listen("tcp", opts.addr, np.cfg)
	if err != nil {
		cancel()
		store.Close()
		return nil, fmt.Errorf("tcpcl listen %s: %w", opts.addr, err)
	}
	np.ln = ln
	np.wg.Add(1)
	go func() {
		defer np.wg.Done()
		if err := ln.Serve(); err != nil {
			lg.Printf("node-plane: listener on %s failed: %v", opts.addr, err)
		}
	}()
	if n, cerr := store.Count(); cerr == nil {
		lg.Printf("node-plane: TCPCLv4 (RFC 9174 subset, node-network §6.3) listening on %s — eid=%s mtls=%s budget=%dMiB keepalive=%s pins=%s store=%s (cap %d, %d bundles)",
			ln.Addr(), eid, mtls, opts.budgetMiB, keepalive, opts.pinsPath, opts.storePath, store.Cap(), n)
	}

	// Periodic pin-store checkpoint (TOFU pins learned mid-flight survive
	// an unclean restart), bundle janitor (§7.5 expiry, the §10.6 cadence)
	// and — with -tcpcl-debug — counter snapshots for the operator. All
	// RAM-only bookkeeping; /status wiring stays P3.6's.
	np.wg.Add(1)
	go func() {
		defer np.wg.Done()
		pinsTick := time.NewTicker(time.Minute)
		defer pinsTick.Stop()
		janitorTick := time.NewTicker(bundleJanitorInterval)
		defer janitorTick.Stop()
		// Boot sweep: expired cargo never lingers past startup.
		if n, err := store.Janitor(); err != nil {
			lg.Printf("node-plane: bundle janitor failed: %v", err)
		} else if n > 0 {
			lg.Printf("node-plane: boot janitor swept %d expired bundle(s)", n)
		}
		for {
			select {
			case <-planeCtx.Done():
				return
			case <-pinsTick.C:
				if err := writePinStore(opts.pinsPath, pins); err != nil {
					lg.Printf("node-plane: pin store checkpoint failed: %v", err)
				}
			case <-janitorTick.C:
				if n, err := store.Janitor(); err != nil {
					lg.Printf("node-plane: bundle janitor failed: %v", err)
				} else if n > 0 && opts.debug {
					lg.Printf("node-plane: janitor swept %d expired bundle(s)", n)
				}
			case <-time.After(time.Minute):
				if opts.debug {
					logCounters(lg, store, engine)
				}
			}
		}
	}()

	// Opportunistic dial loop per configured peer (§2.7 contact model:
	// nodes are convergence-layer peers; every established session runs
	// the §7.1 summary/diff exchange through OnEstablished).
	interval := time.Duration(opts.dialIntervalSec) * time.Second
	if interval <= 0 {
		interval = 30 * time.Second
	}
	for _, peer := range opts.peers {
		peer := strings.TrimSpace(peer)
		if peer == "" {
			continue
		}
		np.wg.Add(1)
		go np.dialLoop(planeCtx, peer, interval, lg)
	}

	// Tie the plane's lifetime to the caller's ctx.
	go func() {
		<-ctx.Done()
		np.stop()
	}()
	return np, nil
}

// logCounters is the -tcpcl-debug snapshot: store admission counters,
// engine sync counters, session counters — one honest log line each.
func logCounters(lg *log.Logger, store *forward.Store, engine *forward.Engine) {
	n, err := store.Count()
	if err == nil {
		lg.Printf("node-plane: store %d bundle(s) (cap %d), admission %+v", n, store.Cap(), store.CountersSnapshot())
	}
	lg.Printf("node-plane: sync %+v", engine.CountersSnapshot())
}

// dialLoop keeps one outbound contact cadence alive: dial, hold the
// session for the §7.1 contact window, terminate (§6.1 graceful), then
// wait the configured interval with ±25 % jitter (a fleet of nodes must
// not sync in lockstep). Config.ExpectedPeer is deliberately NOT set: the
// TOFU pin (first contact records, change fails loudly) is the v1 trust
// anchor.
func (np *nodePlane) dialLoop(ctx context.Context, peer string, interval time.Duration, lg *log.Logger) {
	defer np.wg.Done()
	for {
		if ctx.Err() != nil {
			return
		}
		dialCtx, cancel := context.WithTimeout(ctx, tcpcl.HandshakeTimeout)
		sess, err := tcpcl.Dial(dialCtx, "tcp", peer, np.cfg)
		cancel()
		if err != nil {
			lg.Printf("node-plane: dial %s failed (%v); retry in ~%s", peer, err, interval)
			if !sleepJitter(ctx, interval) {
				return
			}
			continue
		}
		lg.Printf("node-plane: outbound session with %s (%s) established", peer, sess.PeerEID())
		// The episodic contact window (see contactWindow): the §7.1
		// exchange runs in its own goroutine (OnEstablished); this bounds
		// the session and ends it gracefully.
		select {
		case <-ctx.Done():
			_ = sess.Terminate(tcpcl.TermUnknown)
			return
		case <-sess.Done():
			lg.Printf("node-plane: outbound session with %s ended (%v)", peer, sess.Err())
		case <-time.After(contactWindow):
			// §6.1 graceful SESS_TERM (reason Unknown is the table's normal
			// goodbye); the window elapsed — the next contact re-diffs.
			_ = sess.Terminate(tcpcl.TermUnknown)
		}
		if !sleepJitter(ctx, interval) {
			return
		}
	}
}

// sleepJitter waits interval ± 25 % (jittered), interruptibly; false when
// the context ended first.
func sleepJitter(ctx context.Context, interval time.Duration) bool {
	j := interval + time.Duration(rand.Int63n(int64(interval/2))) - interval/4 //nolint:gosec // de-synchronization jitter, not security
	if j < time.Second {
		j = time.Second
	}
	t := time.NewTimer(j)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// stop shuts the plane down: graceful SESS_TERM per live session (via
// Listener.Close), the dial loops, and ONE final pin-store checkpoint,
// then the bundle store (its SQLite WAL commits on close). Exactly-once:
// main's shutdown path and the ctx watcher may both call it; a second call
// finds everything already closed (and must not write again — the trust
// state on disk is frozen at the first stop).
func (np *nodePlane) stop() {
	if np == nil {
		return
	}
	np.stopOnce.Do(func() {
		np.cancel()
		if np.ln != nil {
			_ = np.ln.Close() // §6.1 graceful Terminate per active session
		}
		np.wg.Wait()
		if np.pinsPath != "" {
			if err := writePinStore(np.pinsPath, np.pins); err != nil {
				np.cfg.Log.Printf("node-plane: final pin store checkpoint failed: %v", err)
			}
		}
		if np.store != nil {
			if err := np.store.Close(); err != nil {
				np.cfg.Log.Printf("node-plane: bundle store close: %v", err)
			}
		}
	})
}

// addr reports the bound listener address ("" when not serving).
func (np *nodePlane) addr() string {
	if np == nil || np.ln == nil {
		return ""
	}
	return np.ln.Addr().String()
}

// buildTCPCLOptions maps the flags (kept here so main stays readable).
func buildTCPCLOptions(enabled bool, addr, peers, nodeSeed, pins, mtls string, budgetMiB, keepaliveSec int,
	storePath string, storeCap, dialIntervalSec int, debug bool) tcpclOptions {
	var peerList []string
	if peers != "" {
		peerList = strings.Split(peers, ",")
	}
	return tcpclOptions{
		enabled:         enabled,
		addr:            addr,
		peers:           peerList,
		nodeSeedPath:    nodeSeed,
		pinsPath:        pins,
		mtls:            mtls,
		budgetMiB:       budgetMiB,
		keepaliveSec:    keepaliveSec,
		storePath:       storePath,
		storeCap:        storeCap,
		dialIntervalSec: dialIntervalSec,
		debug:           debug,
	}
}
