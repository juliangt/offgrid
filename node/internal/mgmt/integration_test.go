package mgmt

// integration_test.go — the §11 row-i and row-l gates (issue #33 P3.6):
//
// TestL3LifecycleIslandWide: the FULL L3 ceremony on a three-node island
// (real SQLite stores, real TCPCLv4 sessions over 127.0.0.1 loopback, the
// REAL capsuletool binary driving the offline anchor ceremony) — with NO
// online server anywhere:
//
//	anchor (offline, capsuletool) issues the managers' certs → provisioned at
//	boot → mgr1's get_status crosses the island and every node replies →
//	mgr1 distributes an operator cert via install_cert (the §2.5 seq merge
//	rules admit it everywhere) → the NEW manager (mgr2) operates its L1/L3
//	authority → the anchor REVOKES mgr1 (revocation cert, seq bump) → mgr2
//	installs the revocation island-wide → mgr1's next command is dropped and
//	counted on every node, with no reply anywhere.
//
// TestPassiveCaptureRevealsNoPlaintext: a full management exchange over real
// TLS-wrapped TCPCL sessions, captured byte-for-byte at a raw TCP proxy —
// the capture contains no command names, no marker plaintext (the third AC
// checkbox of §4).
//
// Hermetic: 127.0.0.1, ephemeral ports, no external network, no HTTP.

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"offgrid/dtn-node/internal/bundle"
	"offgrid/dtn-node/internal/forward"
	"offgrid/dtn-node/internal/nodeid"
	"offgrid/dtn-node/internal/tcpcl"
)

// ---------------------------------------------------------------------------
// The capsuletool ceremony (the real binary — the same tool an operator runs).
// ---------------------------------------------------------------------------

var (
	ctOnce   sync.Once
	ctBinary string
	ctErr    error
)

// capsuletoolPath builds the REAL capsuletool binary once per test process
// (the offline ceremony tool of docs/node-network.md §2.6/§8; the suite must
// prove the ceremony works through the operator's interface, not a parallel
// library shortcut).
func capsuletoolPath(t *testing.T) string {
	t.Helper()
	ctOnce.Do(func() {
		_, thisFile, _, _ := runtime.Caller(0)
		// integration_test.go → mgmt → internal → the node module root.
		nodeDir := filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
		dir, err := os.MkdirTemp("", "capsuletool-build")
		if err != nil {
			ctErr = err
			return
		}
		bin := filepath.Join(dir, "capsuletool")
		cmd := exec.Command("go", "build", "-o", bin, "./cmd/capsuletool")
		cmd.Dir = nodeDir
		if out, err := cmd.CombinedOutput(); err != nil {
			ctErr = fmt.Errorf("build capsuletool: %v: %s", err, out)
			return
		}
		ctBinary = bin
	})
	if ctErr != nil {
		t.Fatal(ctErr)
	}
	return ctBinary
}

// ctRun runs one capsuletool command; fatals on a nonzero exit.
func ctRun(t *testing.T, bin string, args ...string) string {
	t.Helper()
	cmd := exec.Command(bin, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("capsuletool %s: %v: %s", args[0]+" "+args[1], err, out)
	}
	return string(out)
}

// ceremonyResult holds the ceremony's artifacts (files under a temp kit dir).
type ceremonyResult struct {
	dir       string
	anchorPub []byte
	mgr1EID   string
	mgr2EID   string
	opEID     string
	mgr1Seed  string // paths
	mgr2Seed  string
	certOf    map[string]string // role → cert file path
}

// runCeremony plays the §2.6/§8 offline ceremony with the real CLI: anchor
// keygen → node keygens → anchor signs the role certs (deterministic
// defaults; the wall clock is real, the certs are long-lived).
func runCeremony(t *testing.T) *ceremonyResult {
	t.Helper()
	bin := capsuletoolPath(t)
	dir := t.TempDir()
	c := &ceremonyResult{dir: dir, certOf: map[string]string{}}

	ctRun(t, bin, "anchor", "keygen", "--out", filepath.Join(dir, "anchor"))
	pub, err := os.ReadFile(filepath.Join(dir, "anchor", "anchor.pub"))
	if err != nil {
		t.Fatal(err)
	}
	c.anchorPub, err = hex.DecodeString(string(bytes.TrimSpace(pub)))
	if err != nil {
		t.Fatal(err)
	}

	keygen := func(name string) string {
		t.Helper()
		ctRun(t, bin, "rolecert", "keygen", "--out", filepath.Join(dir, name))
		return filepath.Join(dir, name, "node.seed")
	}
	c.mgr1Seed = keygen("mgr1")
	c.mgr2Seed = keygen("mgr2")
	keygen("op")

	seedPub := func(name string) string {
		t.Helper()
		return filepath.Join(dir, name, "node.pub")
	}
	sign := func(name, roles string, level, seq int) string {
		t.Helper()
		out := filepath.Join(dir, name+"_cert.cbor")
		ctRun(t, bin, "rolecert", "sign",
			"--anchor-seed", filepath.Join(dir, "anchor", "anchor.seed"),
			"--node-pub", seedPub(name),
			"--roles", roles, "--level", fmt.Sprint(level), "--seq", fmt.Sprint(seq),
			"--issued-ts", fmt.Sprint(time.Now().Unix()-60),
			"--expires-ts", fmt.Sprint(time.Now().Unix()+24*3600),
			"--out", out)
		c.certOf[name] = out
		return out
	}
	sign("mgr1", "manager", 3, 1)
	sign("mgr2", "manager", 3, 1)
	sign("op", "edge", 2, 1)

	eidOf := func(name string) string {
		t.Helper()
		out := ctRun(t, bin, "rolecert", "id", "--seed", filepath.Join(dir, name, "node.seed"))
		var eid string
		if _, err := fmt.Sscanf(out, "eid=%s", &eid); err != nil {
			t.Fatalf("rolecert id %s: %q", name, out)
		}
		return eid
	}
	c.mgr1EID = eidOf("mgr1")
	c.mgr2EID = eidOf("mgr2")
	c.opEID = eidOf("op")
	return c
}

// adminSign wraps `capsuletool admin sign` and returns the command object.
func adminSign(t *testing.T, c *ceremonyResult, seedPath, cmdName, args, target, cert, seq string) []byte {
	t.Helper()
	bin := capsuletoolPath(t)
	out := filepath.Join(t.TempDir(), "cmd.cose")
	argv := []string{"admin", "sign", "--seed", seedPath, "--cmd", cmdName, "--seq", seq, "--out", out}
	if args != "" {
		argv = append(argv, "--args", args)
	}
	if target != "" {
		argv = append(argv, "--target", target)
	}
	if cert != "" {
		argv = append(argv, "--cert", cert)
	}
	ctRun(t, bin, argv...)
	cose, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return cose
}

// ---------------------------------------------------------------------------
// The island stacks (the forward package's wiring, plus the P3.6 enforcer).
// ---------------------------------------------------------------------------

type mgmtStack struct {
	t       *testing.T
	name    string
	dir     string
	store   *forward.Store
	engine  *forward.Engine
	sink    *forward.Sink
	kp      nodeid.KeyPair
	eid     string
	pins    *nodeid.PinStore
	cache   *nodeid.Cache
	enf     *Enforcer
	cfg     tcpcl.Config
	ln      *tcpcl.Listener
	replies []Reply // guarded by mu (OnReply fires from the read loop)
	mu      sync.Mutex

	live *tcpcl.Session // the capture test's single live session
}

// newMgmtStack boots one island node. seed (when non-nil) is the §2.6
// node.seed — the MANAGER nodes boot from the ceremony's seeds, because the
// manager IS a node role (docs/node-network.md §2.3: its commands are signed
// by its node key and its telemetry replies are addressed to its EID).
func newMgmtStack(t *testing.T, name string, anchorPub, seed, ownCert []byte) *mgmtStack {
	t.Helper()
	dir := t.TempDir()
	store, err := forward.Open(forward.Config{Path: filepath.Join(dir, "bundles.db"), Log: quietLogger()})
	if err != nil {
		t.Fatalf("%s: store: %v", name, err)
	}
	t.Cleanup(func() { _ = store.Close() })

	kp := nodeid.KeyPair{}
	if seed != nil {
		kp, err = nodeid.NewKeyPairFromSeed(seed)
	} else {
		kp, err = nodeid.GenerateKeyPair()
	}
	if err != nil {
		t.Fatal(err)
	}
	eid, err := nodeid.EIDFromPub(kp.Public)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := nodeid.SelfSignedX509(kp, eid, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pins := nodeid.NewPinStore()
	cache := nodeid.NewCache()
	enf := NewEnforcer(cache, anchorPub, eid, kp)
	enf.Exec = &Executors{
		Status: func() map[string]Arg {
			data := map[string]Arg{
				"role":       {Kind: ArgTstr, Str: "edge"},
				"level":      {Kind: ArgUint, Uint: 1},
				"store_cap":  {Kind: ArgUint, Uint: uint64(store.Cap())},
				"peer_count": {Kind: ArgUint, Uint: uint64(pins.PeerCount())},
			}
			if n, err := store.Count(); err == nil {
				data["store_fill"] = Arg{Kind: ArgUint, Uint: uint64(n)}
			}
			return data
		},
		Janitor:         func() (int64, error) { return store.Janitor() },
		SetStoreCap:     func(b uint64) error { return store.SetCap(int(b)) },
		SetBudgets:      func(mib uint64) error { enf.Policy.SetContactBudgetMiB(mib); return nil },
		SetDialInterval: func(sec uint64) error { enf.Policy.SetDialIntervalSec(sec); return nil },
		SetFederation:   func(on bool) error { enf.Policy.SetFederation(on); return nil },
		FactoryReset: func() error {
			_, err := store.DeleteAll()
			pins.ResetPeerPins()
			return err
		},
	}
	// Provisioning: the own cert (when issued) and the anchor are the §2.6
	// kit; everything else arrives over the plane.
	if ownCert != nil {
		if st := cache.Merge(ownCert, anchorPub, time.Now().Unix()); st.Outcome != nodeid.OutcomeReplaced {
			t.Fatalf("%s: own cert did not provision: %s", name, st.Outcome)
		}
	}

	s := &mgmtStack{t: t, name: name, dir: dir, store: store, kp: kp, eid: eid,
		pins: pins, cache: cache, enf: enf}
	var lg *log.Logger
	if os.Getenv("MGMT_DEBUG") != "" {
		lg = log.New(os.Stderr, name+" ", 0)
	} else {
		lg = quietLogger()
	}
	s.engine = forward.NewEngine(store, eid, lg)
	s.engine.SummaryWait = 2 * time.Second
	s.sink = &forward.Sink{Store: store, Engine: s.engine, LocalEID: eid, Mgmt: enf}
	enf.Inject = func(pdu []byte) error { return store.Accept(pdu) }
	enf.OnReply = func(r Reply) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.replies = append(s.replies, r)
	}
	s.cfg = tcpcl.Config{
		EID:           eid,
		Identity:      cert,
		Pins:          pins,
		MTLS:          tcpcl.MTLSRequired,
		Keepalive:     -1,
		Sink:          s.sink,
		Counters:      &tcpcl.Counters{},
		TermLinger:    2 * time.Second,
		OnEstablished: s.engine.HandleSession,
		Log:           lg,
	}
	s.ln, err = tcpcl.Listen("tcp", "127.0.0.1:0", s.cfg)
	if err != nil {
		t.Fatalf("%s: listen: %v", name, err)
	}
	t.Cleanup(func() { _ = s.ln.Close() })
	go func() { _ = s.ln.Serve() }()
	return s
}

func quietLogger() *log.Logger { return log.New(&discardWriter{}, "", 0) }

type discardWriter struct{}

func (*discardWriter) Write(p []byte) (int, error) { return len(p), nil }

func (s *mgmtStack) dialTo(other *mgmtStack) *tcpcl.Session {
	s.t.Helper()
	if err := other.pins.PinPeer(s.eid, s.kp.Public); err != nil {
		s.t.Fatalf("pin %s at %s: %v", s.eid, other.name, err)
	}
	if err := s.pins.PinPeer(other.eid, other.kp.Public); err != nil {
		s.t.Fatalf("pin %s at %s: %v", other.eid, s.name, err)
	}
	cfg := s.cfg
	cfg.ExpectedPeer = other.eid
	sess, err := tcpcl.Dial(context.Background(), "tcp", other.ln.Addr().String(), cfg)
	if err != nil {
		s.t.Fatalf("%s dial %s: %v", s.name, other.name, err)
	}
	return sess
}

func (s *mgmtStack) counters() CountersSnapshot { return s.enf.CountersSnapshot() }

func (s *mgmtStack) replyCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.replies)
}

func (s *mgmtStack) certState(eid string) nodeid.CertState {
	_, state := s.cache.Effective(eid, time.Now().Unix())
	return state
}

// injectCommand is the manager's send path: the signed command rides the
// identified admin bundle, is CONSUMED LOCALLY (an og-admin broadcast
// includes the issuing node — its own host applies it through the exact
// sink path a receiver runs), and is admitted into the store so the
// §7.1 epidemic sync carries it to every peer.
func (s *mgmtStack) injectCommand(signerEID string, cose []byte) {
	s.t.Helper()
	b, err := bundle.NewManagement(signerEID, AdminEID, time.Now().UnixMilli(), 6*3600, 1, cose)
	if err != nil {
		s.t.Fatal(err)
	}
	pdu, err := bundle.Encode(b)
	if err != nil {
		s.t.Fatal(err)
	}
	if !s.enf.Consume(b) {
		s.t.Fatalf("a command payload must be consumed at the injection point (%s)", s.name)
	}
	if err := s.store.Accept(pdu); err != nil {
		s.t.Fatalf("inject command at %s: %v", s.name, err)
	}
}

// meshRound runs one full round of contacts over the triangle (each ordered
// pair once) — the epidemic exchange of §7.1 across the whole island.
func meshRound(t *testing.T, a, b, c *mgmtStack) {
	t.Helper()
	for _, pair := range [][2]*mgmtStack{{a, b}, {a, c}, {b, a}, {b, c}, {c, a}, {c, b}} {
		sess := pair[0].dialTo(pair[1])
		time.Sleep(60 * time.Millisecond) // summary + diff pump settle
		_ = sess.Terminate(tcpcl.TermUnknown)
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

// ---------------------------------------------------------------------------
// The L3 ceremony, island-wide, with no online server.
// ---------------------------------------------------------------------------

func TestL3LifecycleIslandWide(t *testing.T) {
	c := runCeremony(t)
	readFile := func(path string) []byte {
		t.Helper()
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	// The island: three nodes; mgr1 rides n1, mgr2 rides n3. Provisioned at
	// boot (the §2.6 kit): the MGR1 cert on every node (a manager is a
	// provisioning fact). mgr2's cert and the operator cert exist ONLY at
	// the anchor — the plane must distribute them.
	mgr1Cert := readFile(c.certOf["mgr1"])
	mgr2Cert := readFile(c.certOf["mgr2"])
	seedOf := func(name string) []byte {
		raw, err := os.ReadFile(filepath.Join(c.dir, name, "node.seed"))
		if err != nil {
			t.Fatal(err)
		}
		return mustHex(t, string(bytes.TrimSpace(raw)))
	}
	// n1 IS the mgr1 node; n3 IS the mgr2 node (the manager is a node role).
	// Every node boots with mgr1's cert (a manager is a provisioning fact);
	// n3's kit also carries its own mgr2 cert. mgr2's cert for the OTHERS
	// rides the plane via install_cert (step 2).
	n1 := newMgmtStack(t, "n1", c.anchorPub, seedOf("mgr1"), mgr1Cert)
	n2 := newMgmtStack(t, "n2", c.anchorPub, nil, mgr1Cert)
	n3 := newMgmtStack(t, "n3", c.anchorPub, seedOf("mgr2"), mgr2Cert)
	// n3's kit provisions BOTH managers (it must enforce mgr1 until revoked).
	if st := n3.cache.Merge(mgr1Cert, c.anchorPub, time.Now().Unix()); st.Outcome != nodeid.OutcomeReplaced {
		t.Fatalf("n3: mgr1 cert provisioning: %s", st.Outcome)
	}

	// -- 1. ISSUE → OPERATE: mgr1's get_status broadcast crosses the island;
	// every og-admin subscriber executes it and answers.
	n1.injectCommand(c.mgr1EID, adminSign(t, c, c.mgr1Seed, CmdGetStatus, "", "", "", "1"))
	meshRound(t, n1, n2, n3)
	waitFor(t, "every node to execute get_status", func() bool {
		return n1.counters().Accepted >= 1 && n2.counters().Accepted >= 1 && n3.counters().Accepted >= 1
	})
	waitFor(t, "mgr1 to receive the island's replies", func() bool {
		return n1.replyCount() >= 2 // n2's and n3's (n1's own reply is its own telemetry)
	})
	for _, s := range []*mgmtStack{n1, n2, n3} {
		if got := s.counters(); got.DroppedSig != 0 || got.DroppedByLevel != 0 {
			t.Fatalf("%s: clean get_status must not drop: %+v", s.name, got)
		}
	}

	// -- 2. ISSUE (the L3 power): mgr1 distributes a NEW operator cert, then
	// the new manager's cert, via install_cert — ONE COMMAND IN FLIGHT AT A
	// TIME (the §8.2 seq gate is per-signer strictly monotonic and epidemic
	// sync delivers WITHOUT ordering: an operator who overlaps two commands
	// correctly watches the stale one refused island-wide).
	n1.injectCommand(c.mgr1EID, adminSign(t, c, c.mgr1Seed, CmdInstallCert, "", "", c.certOf["op"], "2"))
	meshRound(t, n1, n2, n3)
	waitFor(t, "the operator cert to reach every cache", func() bool {
		return n1.certState(c.opEID) == nodeid.StateAuthority &&
			n2.certState(c.opEID) == nodeid.StateAuthority &&
			n3.certState(c.opEID) == nodeid.StateAuthority
	})
	n1.injectCommand(c.mgr1EID, adminSign(t, c, c.mgr1Seed, CmdInstallCert, "", "", c.certOf["mgr2"], "3"))
	meshRound(t, n1, n2, n3)
	waitFor(t, "the new manager's cert to reach the caches that lacked it", func() bool {
		return n1.certState(c.mgr2EID) == nodeid.StateAuthority &&
			n2.certState(c.mgr2EID) == nodeid.StateAuthority
	})
	if c1, c2, c3 := n1.cache.Conflicts, n2.cache.Conflicts, n3.cache.Conflicts; c1+c2+c3 != 0 {
		t.Fatalf("the cert distribution raised conflict signals: %d/%d/%d", c1, c2, c3)
	}

	// -- 3. The NEW manager operates: mgr2 (distributed in step 2 by the
	// same mechanism — proven again here with its own L1 command) executes
	// island-wide.
	n3.injectCommand(c.mgr2EID, adminSign(t, c, c.mgr2Seed, CmdSetDialInterval, `{"seconds": 42}`, "", "", "1"))
	meshRound(t, n1, n2, n3)
	waitFor(t, "mgr2's policy to be accepted everywhere", func() bool {
		return n1.counters().Accepted >= 2 && n2.counters().Accepted >= 2 && n3.counters().Accepted >= 2
	})
	for _, s := range []*mgmtStack{n1, n2, n3} {
		if sec := s.enf.Policy.DialIntervalSec(); sec != 42 {
			t.Fatalf("%s: dial interval = %d, want 42 (mgr2's L2 policy)", s.name, sec)
		}
	}

	// -- 4. REVOKE: the offline anchor revokes mgr1 (a higher-seq cert with
	// roles cleared — an offline ceremony, capsuletool), mgr2 installs it
	// island-wide via install_cert.
	bin := capsuletoolPath(t)
	revoked := filepath.Join(t.TempDir(), "mgr1_revoked.cbor")
	ctRun(t, bin, "rolecert", "sign",
		"--anchor-seed", filepath.Join(c.dir, "anchor", "anchor.seed"),
		"--node-pub", filepath.Join(c.dir, "mgr1", "node.pub"),
		"--roles", "none", "--level", "0", "--seq", "2",
		"--issued-ts", fmt.Sprint(time.Now().Unix()-1),
		"--expires-ts", fmt.Sprint(time.Now().Unix()+24*3600),
		"--out", revoked)
	n3.injectCommand(c.mgr2EID, adminSign(t, c, c.mgr2Seed, CmdInstallCert, "", "", revoked, "2"))
	meshRound(t, n1, n2, n3)
	waitFor(t, "the revocation to be observed island-wide (seq bump)", func() bool {
		return n1.certState(c.mgr1EID) == nodeid.StateRevoked &&
			n2.certState(c.mgr1EID) == nodeid.StateRevoked &&
			n3.certState(c.mgr1EID) == nodeid.StateRevoked
	})

	// -- 5. The revoked manager's next command: dropped + counted EVERYWHERE,
	// with no reply reaching anyone (the AC's final beat). Snapshot the
	// reply counters after a settling round (earlier commands' replies are
	// still converging as store cargo), then compare.
	meshRound(t, n1, n2, n3)
	time.Sleep(300 * time.Millisecond)
	before := [3]int{n1.replyCount(), n2.replyCount(), n3.replyCount()}
	n1.injectCommand(c.mgr1EID, adminSign(t, c, c.mgr1Seed, CmdGetStatus, "", "", "", "2"))
	meshRound(t, n1, n2, n3)
	waitFor(t, "every node to drop the revoked manager's command", func() bool {
		return n1.counters().DroppedSig >= 1 && n2.counters().DroppedSig >= 1 && n3.counters().DroppedSig >= 1
	})
	meshRound(t, n1, n2, n3) // any illegal reply would need a contact to travel
	after := [3]int{n1.replyCount(), n2.replyCount(), n3.replyCount()}
	for i, name := range []string{"n1", "n2", "n3"} {
		if after[i] != before[i] {
			t.Fatalf("%s observed %d new reply/replies for the revoked manager's command", name, after[i]-before[i])
		}
	}

	// Every session ran TLS 1.3 with pinned identities; no HTTP server, no
	// online directory, no CRL — the whole lifecycle rode the bundle plane.
}

// ---------------------------------------------------------------------------
// Row l: the passive capture.
// ---------------------------------------------------------------------------

// TestPassiveCaptureRevealsNoPlaintext captures the RAW TCP stream of a
// management exchange (a recording proxy between the two TCPCL endpoints)
// and asserts the command names and a marker arg never appear in plaintext —
// TLS wraps the session (§6.2 item 4), so the §4 AC holds on the wire.
func TestPassiveCaptureRevealsNoPlaintext(t *testing.T) {
	c := runCeremony(t)

	target := newMgmtStack(t, "target", c.anchorPub, nil, readFileT(t, c.certOf["mgr1"]))
	manager := newMgmtStack(t, "manager", c.anchorPub,
		readSeedT(t, c.mgr1Seed), readFileT(t, c.certOf["mgr1"]))

	// The recorder: a TCP proxy that copies every byte both directions.
	var capMu sync.Mutex
	var captured []byte
	proxy, err := listenRecordingProxy(&captured, &capMu, target.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proxy.Close() })

	// The manager dials THROUGH the proxy (ExpectedPeer still asserts the
	// true identity — the proxy sees only ciphertext).
	if err := target.pins.PinPeer(manager.eid, manager.kp.Public); err != nil {
		t.Fatal(err)
	}
	if err := manager.pins.PinPeer(target.eid, target.kp.Public); err != nil {
		t.Fatal(err)
	}
	cfg := manager.cfg
	cfg.ExpectedPeer = target.eid
	sess, err := tcpcl.Dial(context.Background(), "tcp", proxy.Addr().String(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	manager.live = sess
	defer func() { _ = sess.Terminate(tcpcl.TermUnknown) }()

	// A get_status with an unmistakable marker, plus an install_cert — the
	// two management exchanges of the AC.
	const marker = "MGMTCAPTURE-marker-9f2e-PLAINTEXT"
	mgrSeed, err := os.ReadFile(c.mgr1Seed)
	if err != nil {
		t.Fatal(err)
	}
	kp, err := nodeid.NewKeyPairFromSeed(mustHex(t, string(bytes.TrimSpace(mgrSeed))))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cose, err := SignCommand(kp, CmdGetStatus, map[string]Arg{"note": {Kind: ArgTstr, Str: marker}}, "", now.Unix()-10, now.Unix()+1800, 21)
	if err != nil {
		t.Fatal(err)
	}
	sendLive(t, manager, cose)

	opCert := readFileT(t, c.certOf["op"])
	cose, err = SignCommand(kp, CmdInstallCert, map[string]Arg{"cert": {Kind: ArgBstr, Bytes: opCert}}, "", now.Unix()-10, now.Unix()+1800, 22)
	if err != nil {
		t.Fatal(err)
	}
	sendLive(t, manager, cose)

	if got := target.counters(); got.Accepted != 2 {
		t.Fatalf("the target executed %d commands, want 2 (the exchange really happened)", got.Accepted)
	}
	_ = sess.Terminate(tcpcl.TermUnknown)
	time.Sleep(200 * time.Millisecond) // drain the proxy pumps

	capMu.Lock()
	defer capMu.Unlock()
	for _, secret := range []string{marker, CmdGetStatus, CmdInstallCert, "install_cert", "target_node"} {
		if bytes.Contains(captured, []byte(secret)) {
			t.Fatalf("the passive capture contains plaintext %q (%d bytes captured)", secret, len(captured))
		}
	}
	if len(captured) == 0 {
		t.Fatal("the proxy captured nothing — the test proved nothing")
	}
}

// sendLive transfers one command bundle over the stack's LIVE session (the
// sink consumes and executes it synchronously before the END segment's ACK
// returns — so the call returning proves the exchange completed).
func sendLive(t *testing.T, from *mgmtStack, cose []byte) {
	t.Helper()
	b, err := bundle.NewManagement(from.eid, AdminEID, time.Now().UnixMilli(), 3600, 1, cose)
	if err != nil {
		t.Fatal(err)
	}
	pdu, err := bundle.Encode(b)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if from.live == nil {
		t.Fatal("no live session")
	}
	if err := from.live.SendBundle(ctx, pdu); err != nil {
		t.Fatalf("send: %v", err)
	}
}

// mustHex parses a hex seed file's content.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex seed: %v", err)
	}
	if len(b) != nodeid.SeedLen {
		t.Fatalf("seed length %d, want %d", len(b), nodeid.SeedLen)
	}
	return b
}

func readFileT(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// readSeedT reads a capsuletool node.seed file (64 hex chars) as raw bytes.
func readSeedT(t *testing.T, path string) []byte {
	t.Helper()
	raw := readFileT(t, path)
	return mustHex(t, string(bytes.TrimSpace(raw)))
}
