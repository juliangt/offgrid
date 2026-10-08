package main

// nodeplane.go — the P3.4 daemon wiring of the TCPCLv4 listener + dialer
// (docs/node-network.md §6.2 item 4, §7.4; issue #33). Everything here is
// config-gated: with no -tcpcl flag the daemon behaves EXACTLY as before
// (the whole existing suite stays green with the listener OFF).
//
// Honesty note (P3.4 scope): the receiving sink is a STUB — it validates
// and counts, and says so in every log line. The real bundle store and
// the epidemic forwarding engine are P3.5; until then nothing received
// over the node plane is forwarded anywhere.

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"offgrid/dtn-node/internal/bundle"
	"offgrid/dtn-node/internal/nodeid"
	"offgrid/dtn-node/internal/tcpcl"
)

// tcpclOptions is the parsed -tcpcl-* flag set (built by main, consumed by
// startNodePlane so tests can drive the wiring without flag parsing).
type tcpclOptions struct {
	enabled      bool
	addr         string
	peers        []string
	nodeSeedPath string
	pinsPath     string
	mtls         string
	budgetMiB    int
	keepaliveSec int
}

// nodePlane owns the running TCPCL endpoints of this daemon.
type nodePlane struct {
	cfg      tcpcl.Config
	ln       *tcpcl.Listener // always present while the plane runs
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	pinsPath string
	stopOnce sync.Once

	sink *forwardingSink
	pins *nodeid.PinStore
}

// forwardingSink is the P3.4 seam: the session layer hands every fully
// received, profile-valid bundle here. The stub re-validates (fail-closed
// defense in depth), counts, and logs the truth: nothing is forwarded
// until P3.5 lands the bundle store.
type forwardingSink struct {
	log      *log.Logger
	accepted atomic.Uint64
	bytes    atomic.Uint64
}

// Accept implements tcpcl.BundleSink.
func (s *forwardingSink) Accept(pdu []byte) error {
	if _, err := bundle.Parse(pdu, time.Now()); err != nil {
		// The session layer already refused unparseable PDUs; reaching here
		// would be a contract break — refuse loudly rather than count.
		return fmt.Errorf("stub sink re-validation failed: %w", err)
	}
	s.accepted.Add(1)
	s.bytes.Add(uint64(len(pdu)))
	s.log.Printf("node-plane: bundle accepted (%d bytes, %d this boot) — forwarding pending until P3.5 (no store yet)", len(pdu), s.accepted.Load())
	return nil
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

// startNodePlane boots the node plane: identity → certificate → pin store
// → listener (+ peer dial loop). ctx cancellation shuts everything down
// gracefully (§6.1 SESS_TERM exchange per session, via Listener.Close).
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

	np := &nodePlane{
		sink:     &forwardingSink{log: lg},
		pins:     pins,
		pinsPath: opts.pinsPath,
	}
	np.cfg = tcpcl.Config{
		EID:           eid,
		Identity:      cert,
		Pins:          pins,
		MTLS:          mtls,
		Keepalive:     keepalive,
		ContactBudget: budget,
		Sink:          np.sink,
		Log:           lg,
	}

	// Own context: the plane outlives this function, dies with ctx.
	planeCtx, cancel := context.WithCancel(context.Background())
	np.cancel = cancel

	ln, err := tcpcl.Listen("tcp", opts.addr, np.cfg)
	if err != nil {
		cancel()
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
	lg.Printf("node-plane: TCPCLv4 (RFC 9174 subset, node-network §6.3) listening on %s — eid=%s mtls=%s budget=%dMiB keepalive=%s pins=%s",
		ln.Addr(), eid, mtls, opts.budgetMiB, keepalive, opts.pinsPath)
	lg.Printf("node-plane: receiving counts toward the P3.5 store, not yet the mail path — forwarding pending until P3.5")

	// Periodic pin-store checkpoint (TOFU pins learned mid-flight survive
	// an unclean restart; a crash still re-TOFUs anything after the last
	// checkpoint — stated honestly here and in the spec).
	np.wg.Add(1)
	go func() {
		defer np.wg.Done()
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-planeCtx.Done():
				return
			case <-t.C:
				if err := writePinStore(opts.pinsPath, pins); err != nil {
					lg.Printf("node-plane: pin store checkpoint failed: %v", err)
				}
			}
		}
	}()

	// Opportunistic dial loop per configured peer (§2.7 contact model:
	// nodes are convergence-layer peers; with nothing to exchange yet the
	// sessions carry keepalives and INBOUND bundles only — honest).
	for _, peer := range opts.peers {
		peer := strings.TrimSpace(peer)
		if peer == "" {
			continue
		}
		np.wg.Add(1)
		go np.dialLoop(planeCtx, peer, lg)
	}

	// Tie the plane's lifetime to the caller's ctx.
	go func() {
		<-ctx.Done()
		np.stop()
	}()
	return np, nil
}

// dialLoop keeps one outbound contact alive, retrying with a fixed
// backoff. Config.ExpectedPeer is deliberately NOT set: the TOFU pin
// (first contact records, change fails loudly) is the v1 trust anchor.
func (np *nodePlane) dialLoop(ctx context.Context, peer string, lg *log.Logger) {
	defer np.wg.Done()
	const backoff = 30 * time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		dialCtx, cancel := context.WithTimeout(ctx, tcpcl.HandshakeTimeout)
		sess, err := tcpcl.Dial(dialCtx, "tcp", peer, np.cfg)
		cancel()
		if err != nil {
			lg.Printf("node-plane: dial %s failed (%v); retry in %s", peer, err, backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
				continue
			}
		}
		lg.Printf("node-plane: outbound session with %s (%s) established", peer, sess.PeerEID())
		select {
		case <-ctx.Done():
			_ = sess.Terminate(tcpcl.TermUnknown)
			return
		case <-sess.Done():
			lg.Printf("node-plane: outbound session with %s ended (%v)", peer, sess.Err())
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
		}
	}
}

// stop shuts the plane down: graceful SESS_TERM per live session (via
// Listener.Close), the dial loops, and ONE final pin-store checkpoint.
// Exactly-once: main's shutdown path and the ctx watcher may both call
// it; a second call finds everything already closed (and must not write
// again — the trust state on disk is frozen at the first stop).
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
func buildTCPCLOptions(enabled bool, addr, peers, nodeSeed, pins, mtls string, budgetMiB, keepaliveSec int) tcpclOptions {
	var peerList []string
	if peers != "" {
		peerList = strings.Split(peers, ",")
	}
	return tcpclOptions{
		enabled:      enabled,
		addr:         addr,
		peers:        peerList,
		nodeSeedPath: nodeSeed,
		pinsPath:     pins,
		mtls:         mtls,
		budgetMiB:    budgetMiB,
		keepaliveSec: keepaliveSec,
	}
}
