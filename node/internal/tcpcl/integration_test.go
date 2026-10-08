package tcpcl

// integration_test.go — the §11 row-h gate: two complete TCPCLv4 stacks
// (listener + dialer, both with node certificates and pin stores) over
// loopback, running the full contact: TLS establishment, several bundles
// in both directions (one malformed → refused), budget exhaustion
// mid-contact, a parallel second session, and the graceful §6.1 farewell.
// Hermetic: 127.0.0.1, ephemeral ports, no external network.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"offgrid/dtn-node/internal/nodeid"
)

// TestIntegrationFullContact is the P3.4 exit gate as one scenario.
func TestIntegrationFullContact(t *testing.T) {
	before := runtime.NumGoroutine()

	// --- nodes: A serves, B dials; budgets small enough to exhaust.
	aSink := &collectSink{}
	bSink := &collectSink{}
	aCfg, _, aEID := testNode(t, "A", aSink)
	bCfg, _, _ := testNode(t, "B", bSink)
	aCfg.Keepalive = time.Second // live keepalives during the contact
	bCfg.Keepalive = time.Second
	aCfg.ContactBudget = 4096 // §7.4 per-contact, ingress side
	bCfg.ContactBudget = 4096
	bCfg.MaxSegment = 96 // small segments → multi-segment transfers
	// Cross-pinning (the provisioning pattern; TOFU-first-contact is
	// covered by TestFirstContactTofuPin).
	aPub := mustPub(t, aCfg)
	bPub := mustPub(t, bCfg)
	if err := aCfg.Pins.PinPeer(bCfg.EID, bPub); err != nil {
		t.Fatalf("pin B: %v", err)
	}
	if err := bCfg.Pins.PinPeer(aCfg.EID, aPub); err != nil {
		t.Fatalf("pin A: %v", err)
	}
	aCfg.ExpectedPeer = bCfg.EID
	bCfg.ExpectedPeer = aEID

	ln, err := Listen("tcp", "127.0.0.1:0", aCfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		_ = ln.Serve()
	}()
	defer func() {
		_ = ln.Close()
		<-serveDone
	}()

	b, err := Dial(context.Background(), "tcp", ln.Addr().String(), bCfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if got := b.PeerEID(); got != aEID {
		t.Fatalf("B must see A's certified EID, got %q", got)
	}

	// --- phase 1: three valid bundles B→A (one of them multi-segment).
	var sent [][]byte
	for i := 0; i < 3; i++ {
		payload := bytes.Repeat([]byte(fmt.Sprintf("mail-%d;", i)), i+6)
		pdu := testBundle(t, payload)
		if err := b.SendBundle(context.Background(), pdu); err != nil {
			t.Fatalf("valid bundle %d: %v", i, err)
		}
		sent = append(sent, pdu)
	}
	waitSink(t, aSink, 3)
	for i, pdu := range sent {
		if !bytes.Equal(aSink.pdus[i], pdu) {
			t.Fatalf("bundle %d arrived corrupted at A", i)
		}
	}

	// --- phase 2: one malformed transfer → refused, session survives.
	err = b.SendBundle(context.Background(), []byte("deliberately not a bundle"))
	var refused *ErrTransferRefusedDetail
	if !errors.As(err, &refused) || refused.Reason != RefuseNotAcceptable {
		t.Fatalf("malformed bundle must draw Not Acceptable, got %v", err)
	}
	if got := aSink.len(); got != 3 {
		t.Fatalf("the malformed transfer must not reach A's sink, sink=%d", got)
	}

	// --- phase 3: budget exhaustion mid-contact. A ingested ~3 PDUs; keep
	// pushing until the §7.4 gate refuses (No Resources) — the contact's
	// budget is spent.
	exhausted := false
	for i := 0; i < 64 && !exhausted; i++ {
		pdu := testBundle(t, bytes.Repeat([]byte("z"), 400))
		err := b.SendBundle(context.Background(), pdu)
		var refused *ErrTransferRefusedDetail
		switch {
		case err == nil:
			sent = append(sent, pdu)
		case errors.As(err, &refused) && refused.Reason == RefuseNoResources:
			exhausted = true
		case errors.Is(err, ErrBudgetDeferred):
			exhausted = true // B's own egress gate fires symmetrically
		default:
			t.Fatalf("unexpected error while exhausting the budget: %v", err)
		}
	}
	if !exhausted {
		t.Fatalf("the contact budget never exhausted across 64 transfers")
	}

	// --- phase 4: A→B in the same contact (bidirectional plane).
	pdu := testBundle(t, []byte("reply from A"))
	// A's egress budget was never touched; the transfer rides the same
	// session (full duplex, RFC 9174 §3.1).
	a, ok := inboundSession(t, ln)
	if !ok {
		t.Fatalf("no inbound A-side session handle")
	}
	if err := a.SendBundle(context.Background(), pdu); err != nil {
		t.Fatalf("A→B transfer: %v", err)
	}
	waitSink(t, bSink, 1)
	if !bytes.Equal(bSink.last(), pdu) {
		t.Fatalf("A→B bundle corrupted")
	}

	// --- phase 5: counters tell the truth on both sides.
	aSnap := aCfg.Counters.Snapshot()
	bSnap := bCfg.Counters.Snapshot()
	if aSnap.BundlesIn != uint64(len(aSink.pdus)) || aSnap.BundlesIn < 3 {
		t.Fatalf("A counters: %+v", aSnap)
	}
	if aSnap.RefusalsIn < 1 { // the malformed bundle, at least
		t.Fatalf("A must count the malformed refusal: %+v", aSnap)
	}
	if bSnap.BundlesOut != uint64(len(sent)) || bSnap.RefusalsOut < 1 {
		t.Fatalf("B counters: %+v", bSnap)
	}
	// The §7.4 gate fired somewhere: A refused on ingress or B deferred on
	// egress (whichever side's 4096 bytes ran out first).
	if aSnap.BudgetRefusalsIn == 0 && bSnap.BudgetDeferralsOut == 0 {
		t.Fatalf("the contact budget never bit: A %+v / B %+v", aSnap, bSnap)
	}
	if bSnap.BundlesIn != 1 {
		t.Fatalf("B must have ingested exactly A's bundle: %+v", bSnap)
	}

	// --- phase 6: the graceful §6.1 farewell (A terminates).
	if err := a.Terminate(TermBusy); err != nil {
		t.Fatalf("A Terminate: %v", err)
	}
	if a.Err() != nil {
		t.Fatalf("the clean §6.1 exchange must not record an error: %v", a.Err())
	}
	select {
	case <-b.Done():
	case <-time.After(5 * time.Second):
		t.Fatalf("B must observe the end of the session")
	}

	waitGoroutines(t, before)
}

// TestIntegrationParallelSessions: §5.2.2 forbids interleaving segments
// WITHIN one session, so simultaneous transfers use multiple sessions —
// two B→A sessions run concurrently, each delivering its own bundles
// intact.
func TestIntegrationParallelSessions(t *testing.T) {
	aSink := &collectSink{}
	aCfg, _, _ := testNode(t, "A", aSink)
	ln, err := Listen("tcp", "127.0.0.1:0", aCfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = ln.Serve() }()
	defer func() { _ = ln.Close() }()

	const sessions = 2
	var wg sync.WaitGroup
	for s := 0; s < sessions; s++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			sSink := &collectSink{}
			cfg, _, _ := testNode(t, fmt.Sprintf("B%d", n), sSink)
			sess, err := Dial(context.Background(), "tcp", ln.Addr().String(), cfg)
			if err != nil {
				t.Errorf("session %d dial: %v", n, err)
				return
			}
			for i := 0; i < 3; i++ {
				pdu := testBundle(t, []byte(fmt.Sprintf("s%d-bundle-%d", n, i)))
				if err := sess.SendBundle(context.Background(), pdu); err != nil {
					t.Errorf("session %d send %d: %v", n, i, err)
					return
				}
			}
			_ = sess.Terminate(TermUnknown)
		}(s)
	}
	wg.Wait()

	waitSink(t, aSink, sessions*3)
	// Every PDU arrived exactly once (dedup is P3.5's job; the sink just
	// proves both sessions' streams stayed intact).
	if len(aSink.pdus) != sessions*3 {
		t.Fatalf("want %d bundles at A, got %d", sessions*3, len(aSink.pdus))
	}
}

// inboundSession retrieves the established inbound session of a listener
// (the A-side handle for the bidirectional phase). It polls because the
// listener registers sessions from its accept goroutine.
func inboundSession(t *testing.T, ln *Listener) (*Session, bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		ln.mu.Lock()
		for s := range ln.active {
			ln.mu.Unlock()
			return s, true
		}
		ln.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	return nil, false
}

func mustPub(t *testing.T, cfg Config) []byte {
	t.Helper()
	if cfg.Identity.Leaf == nil {
		t.Fatalf("the config certificate carries no parsed leaf")
	}
	pub, err := nodeid.CertNodeKey(cfg.Identity.Leaf)
	if err != nil {
		t.Fatalf("node key: %v", err)
	}
	return pub
}

func waitSink(t *testing.T, s *collectSink, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if s.len() >= n {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("sink never reached %d bundles (has %d)", n, s.len())
}
