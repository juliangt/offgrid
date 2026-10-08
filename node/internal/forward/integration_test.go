package forward

// integration_test.go — the §11 row-g gate (issue #33 P3.5): three FULL
// node-plane stacks A → B → C on loopback, each with its own real SQLite
// store, sync engine and TCPCL endpoint, proving the acceptance criteria
// end to end:
//
//   - a bundle injected at A reaches C through B byte-unmodified (same
//     bundle_id, envelope bytes at payload offset 1 untouched, creation and
//     lifetime identical — no life extension), the hop octet advanced 0→2;
//   - dup injection at B is deduped (P-7);
//   - an A↔C↔A loop terminates (dedup + hop), and a converged re-contact
//     transfers nothing;
//   - the §3.1 hop ceiling drops a hop-6 bundle's forwarding at B;
//   - a hostile peer flooding beyond the §7.4 contact budget is refused
//     ("No Resources") and the session stays alive.
//
// Hermetic: 127.0.0.1, ephemeral ports, no external network.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"offgrid/dtn-node/internal/bundle"
	"offgrid/dtn-node/internal/nodeid"
	"offgrid/dtn-node/internal/tcpcl"
)

// stack is one full node-plane node: store + engine + sink + TCPCL
// listener, exactly the wiring nodeplane.go assembles for the daemon.
type stack struct {
	t      *testing.T
	name   string
	dir    string
	store  *Store
	engine *Engine
	sink   *Sink
	kp     nodeid.KeyPair
	eid    string
	pins   *nodeid.PinStore
	cfg    tcpcl.Config
	ln     *tcpcl.Listener
}

var stackSeq atomic.Int32

func newStack(t *testing.T, budget int64) *stack {
	t.Helper()
	s := &stack{t: t, name: fmt.Sprintf("n%d", stackSeq.Add(1)), dir: t.TempDir()}
	var err error
	s.store, err = Open(Config{Path: filepath.Join(s.dir, "bundles.db"), Now: time.Now})
	if err != nil {
		t.Fatalf("%s: store: %v", s.name, err)
	}
	t.Cleanup(func() { _ = s.store.Close() })

	s.kp, err = nodeid.GenerateKeyPair()
	if err != nil {
		t.Fatalf("%s: keygen: %v", s.name, err)
	}
	s.eid, err = nodeid.EIDFromPub(s.kp.Public)
	if err != nil {
		t.Fatalf("%s: eid: %v", s.name, err)
	}
	cert, err := nodeid.SelfSignedX509(s.kp, s.eid, time.Hour)
	if err != nil {
		t.Fatalf("%s: cert: %v", s.name, err)
	}
	s.pins = nodeid.NewPinStore()
	s.engine = NewEngine(s.store, s.eid, quietLogger())
	s.engine.SummaryWait = 2 * time.Second
	s.sink = &Sink{Store: s.store, Engine: s.engine, LocalEID: s.eid}
	s.cfg = tcpcl.Config{
		EID:           s.eid,
		Identity:      cert,
		Pins:          s.pins,
		MTLS:          tcpcl.MTLSRequired,
		Keepalive:     -1, // tests stay short; no idle termination
		ContactBudget: budget,
		Sink:          s.sink,
		Counters:      &tcpcl.Counters{},
		TermLinger:    2 * time.Second,
		OnEstablished: s.engine.HandleSession,
		Log:           quietLogger(),
	}
	s.ln, err = tcpcl.Listen("tcp", "127.0.0.1:0", s.cfg)
	if err != nil {
		t.Fatalf("%s: listen: %v", s.name, err)
	}
	t.Cleanup(func() { _ = s.ln.Close() })
	go func() { _ = s.ln.Serve() }()
	return s
}

func quietLogger() *log.Logger { return log.New(&discardWriter{}, "", 0) }

type discardWriter struct{}

func (*discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// dialTo makes from dial to (cross-pinned, identities asserted), the full
// §6.1/§6.3 establishment.
func (s *stack) dialTo(other *stack) *tcpcl.Session {
	s.t.Helper()
	pub := s.kp.Public
	if err := other.pins.PinPeer(s.eid, pub); err != nil {
		s.t.Fatalf("pin %s at %s: %v", s.eid, other.eid, err)
	}
	if err := s.pins.PinPeer(other.eid, other.kp.Public); err != nil {
		s.t.Fatalf("pin %s at %s: %v", other.eid, s.eid, err)
	}
	s.cfg.ExpectedPeer = other.eid
	sess, err := tcpcl.Dial(context.Background(), "tcp", other.ln.Addr().String(), s.cfg)
	if err != nil {
		s.t.Fatalf("%s dial %s: %v", s.name, other.name, err)
	}
	return sess
}

// count returns the store's row count.
func (s *stack) count() int {
	s.t.Helper()
	n, err := s.store.Count()
	if err != nil {
		s.t.Fatalf("count: %v", err)
	}
	return n
}

// waitFor polls cond up to 10 s.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

// transferSnapshot pins the engine transfer counters (for the loop
// termination proof).
func (s *stack) transferSnapshot() uint64 { return s.engine.counters.Transferred.Load() }

// TestMultiHopDelivery is the AC scenario: A → B → C byte-unmodified,
// hop 0→2, dup dedup, A↔C↔A loop termination, hop ceiling, budget bound.
func TestMultiHopDelivery(t *testing.T) {
	a := newStack(t, tcpcl.DefaultContactBudget)
	b := newStack(t, tcpcl.DefaultContactBudget)
	c := newStack(t, tcpcl.DefaultContactBudget)

	// The §14.2-shaped cargo: an arbitrary (opaque to this plane) envelope.
	envelope := bytes.Repeat([]byte("OG-MAIL-PAYLOAD;"), 16) // 240 B
	created := time.Now()
	ttl := uint64(7 * 24 * 3600)
	pduA := mkBundle(t, envelope, created, ttl, 0, "mail")
	id := idOf(t, pduA)

	// Inject at A, then contact A→B: the sync diff must carry it across.
	if err := a.store.Accept(pduA); err != nil {
		t.Fatalf("inject at A: %v", err)
	}
	sessAB := a.dialTo(b)
	waitFor(t, "the bundle at B", func() bool { return b.count() == 1 })

	// --- the 2-hop leg: B → C.
	sessBC := b.dialTo(c)
	waitFor(t, "the bundle at C", func() bool { return c.count() == 1 })

	// Byte-unmodified at C: same id, envelope bytes at offset 1 untouched,
	// creation + lifetime identical (no life extension), hop advanced 0→2.
	pduC, ok, err := c.store.Get(id)
	if err != nil || !ok {
		t.Fatalf("bundle missing at C: ok=%v err=%v", ok, err)
	}
	bC, err := bundle.Parse(pduC, time.Now())
	if err != nil {
		t.Fatalf("parse at C: %v", err)
	}
	bA, err := bundle.Parse(pduA, time.Now())
	if err != nil {
		t.Fatalf("parse at A: %v", err)
	}
	if bC.Hop != 2 {
		t.Fatalf("hop octet at C = %d, want 2 (0 → 2 across the two relay sends)", bC.Hop)
	}
	if !bytes.Equal(bC.Payload, envelope) {
		t.Fatalf("envelope bytes modified in transit")
	}
	if bC.CreationDTNms != bA.CreationDTNms || bC.Lifetime != bA.Lifetime {
		t.Fatalf("life extension detected: creation %d vs %d, lifetime %d vs %d",
			bC.CreationDTNms, bA.CreationDTNms, bC.Lifetime, bA.Lifetime)
	}
	if !bytes.Equal(pduC[:bC.ContentOff], pduA[:bA.ContentOff]) {
		t.Fatalf("primary block bytes differ between A and C")
	}
	if got := c.store.CountersSnapshot().Accepted; got != 1 {
		t.Fatalf("C accepted %d bundles, want 1", got)
	}

	// --- dup safety at B: the identical bundle injected again absorbs.
	if err := b.store.Accept(pduA); err != nil {
		t.Fatalf("dup injection at B: %v", err)
	}
	if got := b.store.CountersSnapshot().Dup; got != 1 {
		t.Fatalf("B dup counter = %d, want 1", got)
	}
	if b.count() != 1 {
		t.Fatalf("B must hold exactly one copy")
	}

	// --- loop safety A↔C↔A: close the triangle; everything converges to
	// one copy everywhere, and a SECOND round of contacts transfers
	// nothing (epidemic terminates: dedup + empty diffs).
	summariesA := a.engine.counters.SummariesIn.Load()
	sessCA := c.dialTo(a)
	waitFor(t, "A to receive C's summary (the loop contact completes)",
		func() bool { return a.engine.counters.SummariesIn.Load() > summariesA })

	beforeA, beforeB, beforeC := a.transferSnapshot(), b.transferSnapshot(), c.transferSnapshot()

	// Second contact round on fresh sessions.
	sessAB2 := a.dialTo(b)
	sessBC2 := b.dialTo(c)
	sessCA2 := c.dialTo(a)
	time.Sleep(1500 * time.Millisecond) // let both contacts run to quiescence
	if got := a.transferSnapshot() - beforeA; got != 0 {
		t.Fatalf("converged re-contact transferred %d bundle(s) out of A", got)
	}
	if got := b.transferSnapshot() - beforeB; got != 0 {
		t.Fatalf("converged re-contact transferred %d bundle(s) out of B", got)
	}
	if got := c.transferSnapshot() - beforeC; got != 0 {
		t.Fatalf("converged re-contact transferred %d bundle(s) out of C", got)
	}
	if a.count() != 1 || b.count() != 1 || c.count() != 1 {
		t.Fatalf("loop inflated the stores: A=%d B=%d C=%d, want 1 each", a.count(), b.count(), c.count())
	}
	for _, sess := range []*tcpcl.Session{sessAB, sessBC, sessCA, sessAB2, sessBC2, sessCA2} {
		_ = sess.Terminate(tcpcl.TermUnknown)
	}

	// --- hop ceiling: a hop-6 bundle at A must reach the wire at hop 7 and
	// be DROPPED at B (honored and capped, §3.1).
	edge := mkBundle(t, []byte("one-hop-from-the-ceiling"), time.Now(), 3600, 6, "mail")
	if err := a.store.Accept(edge); err != nil {
		t.Fatalf("inject edge bundle: %v", err)
	}
	edgeID := idOf(t, edge)
	sessAB3 := a.dialTo(b)
	waitFor(t, "B to process the hop-7 drop", func() bool {
		return b.store.CountersSnapshot().HopCapped >= 1
	})
	if _, ok, _ := b.store.Get(edgeID); ok {
		t.Fatalf("a hop-7 bundle must never be stored at the receiver")
	}
	_ = sessAB3.Terminate(tcpcl.TermUnknown)
}

// sessAlive asserts a session is still established (used as a sanity probe).
func sessAlive(t *testing.T, s *tcpcl.Session) bool {
	t.Helper()
	select {
	case <-s.Done():
		return false
	default:
		return true
	}
}

// TestContactBudgetBindsHostilePeer: a peer offering more than the
// per-contact budget gets refused ("No Resources") and the session stays
// alive — the §7.4 bound of the AC.
func TestContactBudgetBindsHostilePeer(t *testing.T) {
	victim := newStack(t, 2048) // a 2 KiB contact budget

	// The hostile peer is a REAL tcpcl node (identity + pins) with a huge
	// egress budget, pointed at the victim's tiny ingress budget.
	hostile := newStack(t, 64<<20)
	hostile.cfg.Sink = &swallowSink{}

	sess := hostile.dialTo(victim)

	refused := 0
	sent := 0
	var refusedDetail *tcpcl.ErrTransferRefusedDetail
	for i := 0; i < 64; i++ {
		pdu := mkBundle(t, bytes.Repeat([]byte("flood;"), 128), time.Now(), 3600, 0, "mail")
		err := sess.SendBundle(context.Background(), pdu)
		switch {
		case err == nil:
			sent++
		case errors.As(err, &refusedDetail) && refusedDetail.Reason == tcpcl.RefuseNoResources:
			refused++
		case errors.Is(err, tcpcl.ErrBudgetDeferred):
			refused++ // the hostile side's own egress gate (symmetric budget)
		default:
			t.Fatalf("unexpected flood error after %d accepted: %v", sent, err)
		}
		if refused > 0 {
			// The budget bit; the bound held.
			break
		}
	}
	if refused == 0 {
		t.Fatalf("the hostile flood was never bounded (sent %d)", sent)
	}

	// The victim's store took only what fit the budget (a handful of
	// ~250-byte PDUs under 2 KiB — the store bound is the proof the flood
	// stopped; the hostile peer's own summary bundle rode the same budget).
	if n := victim.count(); n > 16 {
		t.Fatalf("the victim stored %d flood bundles; the budget did not bind", n)
	}

	// The session STAYS ALIVE: no termination, and a graceful §6.1
	// farewell still completes cleanly.
	if !sessAlive(t, sess) {
		t.Fatalf("the victim must refuse, not terminate, an over-budget peer")
	}
	if err := sess.Terminate(tcpcl.TermBusy); err != nil {
		t.Fatalf("graceful terminate after refusals: %v", err)
	}
	if victim.cfg.Counters.Snapshot().BudgetRefusalsIn == 0 {
		t.Fatalf("the victim must count the budget refusal")
	}
}

// swallowSink absorbs everything (the hostile peer does not keep cargo).
type swallowSink struct{}

func (*swallowSink) Accept([]byte) error { return nil }
