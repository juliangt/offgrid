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

	"offgrid/dtn-node/internal/api"
	"offgrid/dtn-node/internal/capsule"
	"offgrid/dtn-node/internal/forward"
	"offgrid/dtn-node/internal/mgmt"
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

	// P3.6 management plane (docs/node-network.md §8): the §2.6 ceremony
	// files. Both optional: without the pinned anchor there is NO management
	// plane (no cert can ever verify — fail-closed by construction); with
	// the anchor but no own cert the node still enforces commands (it can
	// verify managers) but carries no authority of its own.
	nodeCertPath  string // node_cert.cbor (the §2.2 role cert)
	anchorPubPath string // anchor.pub (the §2.6 pinned trust root)

	// P3.7 updates over the plane (docs/node-network.md §9, §9.4): the
	// `updates_enabled` policy (default OFF) and the staging seams. Without
	// the pinned release key the Receiver is STILL constructed when enabled
	// — the Stager answers unpinned for every capsule (the §2.4.1 "staging
	// unavailable, not misbehaving" state, honestly counted).
	updates tcpclUpdatesOptions
}

// tcpclUpdatesOptions carries the -tcpcl-updates-* flag set (built by main,
// consumed by startNodePlane so tests drive the wiring without flags).
type tcpclUpdatesOptions struct {
	Enabled    bool   // `updates_enabled` (§9.4; the L2/L3 policy lever)
	Dir        string // the §2.4.4 staging directory (<data>/staged)
	ReleaseKey string // release.pub path ("" = unpinned — refuse + count)
	Arch       string // the §9.1 arch gate ("" = gate disabled)
	OwnRelease uint64 // the §2.4.3 release stamp (0 = unknown/pre-capsule build)
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

	// P3.6 management plane (§8): the §2.5 cert cache, the pinned anchor,
	// the enforcement pipeline and its policy store. mgmt is nil when no
	// anchor was provisioned — the honest "no management plane" state.
	cache     *nodeid.Cache
	anchorPub []byte
	mgmt      *mgmt.Enforcer

	// P3.7 (§9.4): the updates consumer when the updates_enabled policy is
	// on (nil = off; the /status `update` member stays #37 §2.6.2's — until
	// then these counters are -tcpcl-debug observability).
	updates *capsule.Receiver

	// wake bookkeeping for the L1 trigger_sync executor: one channel per
	// live dial loop; SyncNow sends a non-blocking token to each.
	wakeMu   sync.Mutex
	wakeChs  map[chan struct{}]struct{}
	baseDial time.Duration
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

	// The P3.6 management plane (docs/node-network.md §8): the §2.5 cert
	// cache behind the PINNED ANCHOR, the §8.2 enforcement pipeline, and the
	// §8.1 executors wired to the store, the dial loops and the policy.
	// Fail-closed by construction: no anchor → no enforcer → the sink keeps
	// the exact P3.5 behavior and every command would be unverifiable anyway.
	cache := nodeid.NewCache()
	var anchorPub []byte
	var enforcer *mgmt.Enforcer
	if opts.anchorPubPath != "" {
		anchorPub, err = loadAnchorPub(opts.anchorPubPath)
		if err != nil {
			store.Close()
			return nil, fmt.Errorf("load anchor public key: %w", err)
		}
		enforcer = mgmt.NewEnforcer(cache, anchorPub, eid, kp)
		if opts.nodeCertPath != "" {
			seedOwnCert(cache, anchorPub, opts.nodeCertPath, lg)
		} else {
			lg.Printf("node-plane: no -tcpcl-node-cert provisioned — this node enforces commands but carries NO role certificate of its own (mail works, management authority does not; docs/node-network.md §2.6)")
		}
	} else {
		lg.Printf("node-plane: no -tcpcl-anchor-pub pinned — the management plane is OFF (no command or certificate could ever verify; docs/node-network.md §8)")
	}
	sink := &forward.Sink{Store: store, Engine: engine, LocalEID: eid}

	// The P3.7 updates consumer (docs/node-network.md §9.4): constructed
	// ONLY when the updates_enabled policy is on (default OFF — with the
	// policy off there is no receiver and the store refuses chunk cargo at
	// admission, counted). An unpinned release key degrades to the §2.4.1
	// state: reassembly runs, every capsule is refused unpinned + counted,
	// nothing is written.
	if opts.updates.Enabled {
		store.SetUpdatesEnabled(true)
		stager := &capsule.Stager{
			Dir:            opts.updates.Dir,
			Arch:           opts.updates.Arch,
			RunningRelease: opts.updates.OwnRelease,
		}
		if opts.updates.ReleaseKey != "" {
			pub, kerr := loadAnchorPub(opts.updates.ReleaseKey) // same 32-byte hex file format
			if kerr != nil {
				store.Close()
				return nil, fmt.Errorf("load pinned release key: %w", kerr)
			}
			stager.Pub = pub
		} else {
			lg.Printf("node-plane: updates ON without -tcpcl-release-key — staging is UNAVAILABLE (§2.4.1): every capsule is refused + counted, nothing is written")
		}
		if err := stager.Load(); err != nil {
			// A capsule staged by a previous life that no longer parses is
			// left in place (the apply path re-verifies, §2.5); the operator
			// hears about it.
			lg.Printf("node-plane: WARNING: staged capsule did not parse at boot: %v", err)
		}
		receiver := capsule.NewReceiver(capsule.NewReassembler(), stager)
		sink.Updates = receiver
		lg.Printf("node-plane: updates_enabled=ON (§9.4): capsule chunks accepted, staging to %s (arch gate %q, own release %d, apply stays the #22 operator path)",
			opts.updates.Dir, opts.updates.Arch, opts.updates.OwnRelease)
	}

	np := &nodePlane{
		pins:      pins,
		pinsPath:  opts.pinsPath,
		store:     store,
		engine:    engine,
		sink:      sink,
		cache:     cache,
		anchorPub: anchorPub,
		mgmt:      enforcer,
		wakeChs:   make(map[chan struct{}]struct{}),
	}
	if sink.Updates != nil {
		np.updates = sink.Updates
	}
	if enforcer != nil {
		enforcer.Inject = func(pdu []byte) error { return store.Accept(pdu) }
		sink.Mgmt = enforcer
		enforcer.Exec = &mgmt.Executors{
			Status:          planeStatusData(store, pins, enforcer),
			Janitor:         func() (int64, error) { return store.Janitor() },
			SyncNow:         np.wakeDialLoops,
			SetStoreCap:     func(bundles uint64) error { return store.SetCap(int(bundles)) },
			SetBudgets:      func(mib uint64) error { enforcer.Policy.SetContactBudgetMiB(mib); return nil },
			SetDialInterval: func(sec uint64) error { enforcer.Policy.SetDialIntervalSec(sec); return nil },
			SetFederation:   func(on bool) error { enforcer.Policy.SetFederation(on); return nil },
			FactoryReset: func() error {
				// FACTORY RESET, node plane only (docs/node-network.md §8.1):
				// bundle store + learned TOFU peer pins. NEVER the user-plane
				// mail (a different database file, never opened here), never
				// the pinned anchor or the node identity (provisioning
				// ceremony state — a re-install, not a runtime command).
				lg.Printf("node-plane: FACTORY RESET commanded (L3): wiping the bundle store and learned peer pins " +
					"(user-plane mail untouched; the pinned anchor and node identity survive)")
				deleted, derr := store.DeleteAll()
				if derr != nil {
					return derr
				}
				pins.ResetPeerPins()
				lg.Printf("node-plane: factory reset deleted %d bundle(s)", deleted)
				return nil
			},
		}
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
					logCounters(lg, store, engine, np.updates)
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
// engine sync counters, updates counters — one honest log line each.
func logCounters(lg *log.Logger, store *forward.Store, engine *forward.Engine, updates *capsule.Receiver) {
	n, err := store.Count()
	if err == nil {
		lg.Printf("node-plane: store %d bundle(s) (cap %d), admission %+v", n, store.Cap(), store.CountersSnapshot())
	}
	lg.Printf("node-plane: sync %+v", engine.CountersSnapshot())
	if updates != nil {
		lg.Printf("node-plane: updates %+v (reassembly %+v)", updates.CountersSnapshot(), updates.Reasm.Counters())
	}
}

// loadAnchorPub reads a 32-byte hex anchor public key (the §2.6 anchor.pub
// file format).
func loadAnchorPub(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	hx := strings.TrimSpace(string(raw))
	if len(hx) != 2*nodeid.KeyLen {
		return nil, fmt.Errorf("%s: want %d hex chars (a %d-byte key), got %d chars", path, 2*nodeid.KeyLen, nodeid.KeyLen, len(hx))
	}
	pub, err := hex.DecodeString(hx)
	if err != nil {
		return nil, fmt.Errorf("%s: not hex: %w", path, err)
	}
	return pub, nil
}

// seedOwnCert loads the §2.6 provisioned role certificate into the §2.5
// cache (the "cert provisioned at boot" path — issuance itself stays an
// offline anchor ceremony; the file was verified by capsuletool at
// provision time and is verified again here against the pinned anchor).
// Any failure is LOUD and leaves the node uncertified: mail works,
// management authority does not (§2.6's absent-kit stance, daemon side).
func seedOwnCert(cache *nodeid.Cache, anchorPub []byte, path string, lg *log.Logger) {
	cose, err := os.ReadFile(path)
	if err != nil {
		lg.Printf("node-plane: WARNING: cannot read the provisioned role cert %s: %v (booting uncertified)", path, err)
		return
	}
	st := cache.Merge(cose, anchorPub, time.Now().Unix())
	if st.Outcome != nodeid.OutcomeReplaced {
		lg.Printf("node-plane: WARNING: the provisioned role cert %s did not install (outcome %s) — booting uncertified", path, st.Outcome)
		return
	}
	cert, state := cache.Effective(cacheEIDOf(cose, anchorPub), time.Now().Unix())
	if cert == nil || state != nodeid.StateAuthority {
		lg.Printf("node-plane: WARNING: the provisioned role cert %s is not effective (state %s)", path, state)
		return
	}
	lg.Printf("node-plane: role certificate provisioned: %s (level %d, seq %d)", cert.EID, cert.Level, cert.Seq)
}

// cacheEIDOf re-derives the EID of a just-merged cert (the merge outcome
// carries no EID; the node's own EID is the only lookup this needs and it is
// already known to the caller — this helper keeps seedOwnCert honest by
// deriving, never assuming).
func cacheEIDOf(cose, anchorPub []byte) string {
	c, err := nodeid.VerifyCert(cose, anchorPub, time.Now().Unix())
	if err != nil {
		return ""
	}
	return c.EID
}

// planeStatusData is the get_status executor's data source: aggregates only
// (§10.7): this node's provisioned role/level, the bundle store fill/cap and
// the peer count. No EIDs, no fingerprints, no per-user anything.
func planeStatusData(store *forward.Store, pins *nodeid.PinStore, enforcer *mgmt.Enforcer) func() map[string]mgmt.Arg {
	return func() map[string]mgmt.Arg {
		data := map[string]mgmt.Arg{}
		if cert, state := enforcer.OwnCertState(); cert != nil && state == nodeid.StateAuthority && len(cert.Roles) > 0 {
			data["role"] = mgmt.Arg{Kind: mgmt.ArgTstr, Str: cert.Roles[0]}
			data["level"] = mgmt.Arg{Kind: mgmt.ArgUint, Uint: cert.Level}
		} else {
			data["role"] = mgmt.Arg{Kind: mgmt.ArgTstr, Str: "uncertified"}
			data["level"] = mgmt.Arg{Kind: mgmt.ArgUint, Uint: 0}
		}
		if n, err := store.Count(); err == nil {
			data["store_fill"] = mgmt.Arg{Kind: mgmt.ArgUint, Uint: uint64(n)}
		}
		data["store_cap"] = mgmt.Arg{Kind: mgmt.ArgUint, Uint: uint64(store.Cap())}
		data["peer_count"] = mgmt.Arg{Kind: mgmt.ArgUint, Uint: uint64(pins.PeerCount())}
		return data
	}
}

// wakeDialLoops is the L1 trigger_sync executor: one non-blocking token per
// live dial loop (a full inbox is dropped — the next interval dials anyway).
func (np *nodePlane) wakeDialLoops() {
	np.wakeMu.Lock()
	defer np.wakeMu.Unlock()
	for ch := range np.wakeChs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// registerWake adds this dial loop's wake channel (removed on exit).
func (np *nodePlane) registerWake(ch chan struct{}) {
	np.wakeMu.Lock()
	np.wakeChs[ch] = struct{}{}
	np.wakeMu.Unlock()
}

func (np *nodePlane) unregisterWake(ch chan struct{}) {
	np.wakeMu.Lock()
	delete(np.wakeChs, ch)
	np.wakeMu.Unlock()
}

// dialIntervalOf computes this iteration's wait: the L2 policy value when
// set (set_dial_interval), else the flag default — with the ±25 % jitter.
func (np *nodePlane) dialIntervalOf(base time.Duration) time.Duration {
	if np.mgmt != nil {
		if sec := np.mgmt.Policy.DialIntervalSec(); sec > 0 {
			base = time.Duration(sec) * time.Second
		}
	}
	j := base + time.Duration(rand.Int63n(int64(base/2))) - base/4 //nolint:gosec // de-synchronization jitter, not security
	if j < time.Second {
		j = time.Second
	}
	return j
}

// dialLoop keeps one outbound contact cadence alive: dial, hold the
// session for the §7.1 contact window, terminate (§6.1 graceful), then
// wait the configured interval with ±25 % jitter (a fleet of nodes must
// not sync in lockstep). The L1 trigger_sync command wakes the loop early
// and the L2 set_dial_interval / set_budgets policies are re-read every
// iteration (a new contact opens with the current policy). Config.
// ExpectedPeer is deliberately NOT set: the TOFU pin (first contact
// records, change fails loudly) is the v1 trust anchor.
func (np *nodePlane) dialLoop(ctx context.Context, peer string, interval time.Duration, lg *log.Logger) {
	defer np.wg.Done()
	wake := make(chan struct{}, 1)
	np.registerWake(wake)
	defer np.unregisterWake(wake)
	for {
		if ctx.Err() != nil {
			return
		}
		cfg := np.cfg
		if np.mgmt != nil {
			if mib := np.mgmt.Policy.ContactBudgetMiB(); mib > 0 {
				cfg.ContactBudget = int64(mib) << 20 // applies from this contact on
			}
		}
		dialCtx, cancel := context.WithTimeout(ctx, tcpcl.HandshakeTimeout)
		sess, err := tcpcl.Dial(dialCtx, "tcp", peer, cfg)
		cancel()
		if err != nil {
			lg.Printf("node-plane: dial %s failed (%v); retry in ~%s", peer, err, interval)
			if !np.sleepDial(ctx, np.dialIntervalOf(interval), wake) {
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
		if !np.sleepDial(ctx, np.dialIntervalOf(interval), wake) {
			return
		}
	}
}

// sleepDial waits the interval, interruptibly by ctx or a trigger_sync
// wake token; false when the context ended first.
func (np *nodePlane) sleepDial(ctx context.Context, d time.Duration, wake chan struct{}) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	case <-wake:
		return true // trigger_sync: dial again immediately
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

// NodePlaneSnapshot implements api.NodePlaneSource: one plain read of the
// plane's operational state for the §10.7 diagnostics member. Aggregates
// only (no EIDs, no fingerprints, no addresses — the reasoning lives in
// internal/api/nodeplane.go). Safe on a nil plane and on a plane whose
// management half is off (no pinned anchor): the caller renders null/0s.
func (np *nodePlane) NodePlaneSnapshot() api.NodePlaneSnapshot {
	snap := api.NodePlaneSnapshot{}
	if np == nil {
		return snap
	}
	if n, err := np.store.Count(); err == nil {
		snap.StoreFill = int64(n)
	}
	snap.StoreCap = np.store.Cap()
	snap.PeerCount = np.pins.PeerCount()
	snap.ActiveSess = np.ln.ActiveSessions()
	if np.mgmt != nil {
		c := np.mgmt.CountersSnapshot()
		snap.Mgmt = api.NodePlaneSnapshotMgmt{
			Accepted:        c.Accepted,
			DroppedShape:    c.DroppedShape,
			DroppedSig:      c.DroppedSig,
			DroppedTarget:   c.DroppedTarget,
			DroppedUnknown:  c.DroppedUnknown,
			DroppedByLevel:  c.DroppedByLevel,
			DroppedSeq:      c.DroppedSeq,
			DroppedExpired:  c.DroppedExpired,
			RepliesSent:     c.RepliesSent,
			RepliesReceived: c.RepliesReceived,
			ExecErrors:      c.ExecErrors,
		}
		snap.CertStaleDropped, snap.CertConflicts = np.mgmt.CertCountersSnapshot()
		if cert, state := np.mgmt.OwnCertState(); cert != nil && state == nodeid.StateAuthority && len(cert.Roles) > 0 {
			snap.HasCert = true
			snap.Role = cert.Roles[0]
			snap.Level = cert.Level
		}
	}
	return snap
}

// buildTCPCLOptions maps the flags (kept here so main stays readable).
func buildTCPCLOptions(enabled bool, addr, peers, nodeSeed, pins, mtls string, budgetMiB, keepaliveSec int,
	storePath string, storeCap, dialIntervalSec int, debug bool, nodeCert, anchorPub string,
	updates tcpclUpdatesOptions) tcpclOptions {
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
		nodeCertPath:    nodeCert,
		anchorPubPath:   anchorPub,
		updates:         updates,
	}
}
