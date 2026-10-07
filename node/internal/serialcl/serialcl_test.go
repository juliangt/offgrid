package serialcl

// Tests over net.Pipe/bytes.Pipe: prefix round-trips, the fail-closed
// bound, and the full §3 bridge round trip — a Go bridge and a fake radio
// head (whose C behavior is mirrored by the shared link vectors) complete
// a link handshake, then exchange a bundle-frag window through a LOSSY
// pipe (whole frames dropped at the serial-radio boundary; window
// reassembly recovers exactly as over the air).

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"offgrid/dtn-node/internal/link"
	"offgrid/dtn-node/internal/nodeid"
)

func seedKeyPair(t *testing.T, seed []byte) nodeid.KeyPair {
	t.Helper()
	kp, err := nodeid.NewKeyPairFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

func patternKeys(t *testing.T, prefix byte) nodeid.KeyPair {
	t.Helper()
	seed := make([]byte, nodeid.SeedLen)
	for i := range seed {
		seed[i] = prefix + byte(i)
	}
	return seedKeyPair(t, seed)
}

func eidOf(t *testing.T, kp nodeid.KeyPair) string {
	t.Helper()
	eid, err := nodeid.EIDFromPub(kp.Public)
	if err != nil {
		t.Fatal(err)
	}
	return eid
}

func peerKeys(t *testing.T, peers ...nodeid.KeyPair) *link.PeerKeys {
	t.Helper()
	keys := link.NewPeerKeys(nodeid.NewPinStore())
	for _, p := range peers {
		if err := keys.AddCert(p.Public); err != nil {
			t.Fatal(err)
		}
	}
	return keys
}

func TestPrefixRoundTrip(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	a := NewTransport(c1)
	b := NewTransport(c2)

	frame := bytes_RRepeat(239)
	go func() {
		if err := a.WriteFrame(frame); err != nil {
			t.Errorf("write: %v", err)
		}
	}()
	got, err := b.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, frame) {
		t.Fatal("frame mismatch")
	}
	// Multiple frames stay framed (the write mutex serializes).
	go func() {
		for i := 0; i < 10; i++ {
			if err := a.WriteFrame([]byte{byte(i), 0xFF}); err != nil {
				t.Errorf("write %d: %v", i, err)
			}
		}
	}()
	for i := 0; i < 10; i++ {
		got, err := b.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 || got[0] != byte(i) {
			t.Fatalf("frame %d = % X", i, got)
		}
	}
}

func bytes_RRepeat(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = 0xC3
	}
	return b
}

func TestPrefixFailClosed(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	a := NewTransport(c1)
	if err := a.WriteFrame(nil); err == nil {
		t.Fatal("empty frame accepted")
	}
	if err := a.WriteFrame(make([]byte, MaxFrameLen+1)); err == nil {
		t.Fatal("oversize frame accepted")
	}
	// A hostile prefix above the bound fails closed on the read side.
	go func() {
		_, _ = c2.Write([]byte{0xFF, 0xFF})
	}()
	if _, err := NewTransport(c1).ReadFrame(); err != ErrTooLarge {
		t.Fatalf("hostile prefix: %v", err)
	}
	// A truncated stream fails with ErrTruncated. (net.Pipe matches
	// reads and writes size-for-size, so the prefix goes in its own
	// write — exactly what a partial real-serial flush looks like.)
	halfA, halfB := net.Pipe()
	go func() {
		if _, err := halfB.Write([]byte{0x00, 0x05}); err != nil {
			t.Errorf("prefix write: %v", err)
		}
		if _, err := halfB.Write([]byte{0x01}); err != nil {
			t.Errorf("frame write: %v", err)
		}
		halfB.Close()
	}()
	if _, err := NewTransport(halfA).ReadFrame(); err != ErrTruncated {
		t.Fatalf("truncated: %v", err)
	}
}

// droppingConn wraps one end of a pipe and silently drops WHOLE
// length-prefixed frames per a 1-based script — the lossy radio boundary.
// Reads pass through untouched (only the bridge→head direction loses).
type droppingConn struct {
	io.ReadWriteCloser
	drop    map[int]bool
	seen    int
	dropped int
	pending []byte
	mu      sync.Mutex
}

func (d *droppingConn) Write(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pending = append(d.pending, p...)
	for {
		if len(d.pending) < PrefixLen {
			break
		}
		n := int(binary.BigEndian.Uint16(d.pending[:PrefixLen]))
		if n == 0 || n > MaxFrameLen {
			return 0, ErrTooLarge
		}
		if len(d.pending) < PrefixLen+n {
			break
		}
		frame := append([]byte(nil), d.pending[PrefixLen:PrefixLen+n]...)
		d.pending = d.pending[PrefixLen+n:]
		d.seen++
		if d.drop[d.seen] {
			d.dropped++
			continue // silently lost at the radio boundary
		}
		var prefix [PrefixLen]byte
		binary.BigEndian.PutUint16(prefix[:], uint16(n))
		if _, err := d.ReadWriteCloser.Write(append(prefix[:], frame...)); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func TestBridgeRoundTripWithHandshakeAndLoss(t *testing.T) {
	// The §3 bridge leg end-to-end over ONE pipe: bridge (initiator) ↔
	// fake radio head (responder, the C side's behavior mirrored by the
	// shared link vectors). Phase 1: the §6.1 handshake. Phase 2: a 500 B
	// bundle window as session-protected bundle-frag frames, each sent
	// with redundancy 2, through the LOSSY pipe — one copy of one frame
	// is dropped whole; the window still reassembles byte-exact.
	aKp := patternKeys(t, 0xA0)
	bKp := patternKeys(t, 0xB0)
	keys := peerKeys(t, aKp, bKp)

	scalarI := make([]byte, 32)
	scalarR := make([]byte, 32)
	for i := range scalarI {
		scalarI[i] = byte(0x11 + i)
		scalarR[i] = byte(0x22 + i)
	}
	cfgI := link.Config{Local: aKp, Keys: keys, ExpectedPeer: eidOf(t, bKp)}
	cfgI.EphemeralScalar = func() ([]byte, error) { return scalarI, nil }
	cfgR := link.Config{Local: bKp, Keys: keys, ExpectedPeer: eidOf(t, aKp)}
	cfgR.EphemeralScalar = func() ([]byte, error) { return scalarR, nil }

	ini, msg1, err := link.NewInitiator(cfgI)
	if err != nil {
		t.Fatal(err)
	}
	res, err := link.NewResponder(cfgR)
	if err != nil {
		t.Fatal(err)
	}

	// Bridge→head direction crosses the dropping middleware; the script
	// names bridge→head frames by 1-based order: #1 msg1, #2 msg3, #3..
	// the six window frames. Dropping #5 kills ONE copy of the window's
	// idx-1 frame.
	dropConn := &droppingConn{drop: map[int]bool{5: true}}
	bridgeRaw, headRaw := net.Pipe()
	dropConn.ReadWriteCloser = bridgeRaw
	bridgeT := NewTransport(dropConn)
	headT := NewTransport(headRaw)
	var shutdown atomicBool

	// The head's read loop as a small state machine: handshake first
	// (raw CBOR frames), then the session phase (link frames).
	type completion struct {
		content []byte
	}
	completions := make(chan completion, 4)
	headErr := make(chan error, 1)
	go func() {
		if err := <-headErr; err != nil && !shutdown.load() {
			fmt.Fprintln(os.Stderr, "HEAD ERROR:", err)
			t.Errorf("radio head failed: %v", err)
		}
	}()
	go func() {
		headFail := func(err error) {
			fmt.Fprintln(os.Stderr, "HEAD ERROR:", err)
			headErr <- err
		}
		frame, err := headT.ReadFrame()
		if err != nil {
			headFail(err)
			return
		}
		if !bytes.Equal(frame, msg1) {
			headErr <- ErrTooLarge
			return
		}
		if err := res.Read1(frame); err != nil {
			headFail(err)
			return
		}
		msg2, err := res.Write2()
		if err != nil {
			headFail(err)
			return
		}
		if err := headT.WriteFrame(msg2); err != nil {
			headFail(err)
			return
		}
		frame, err = headT.ReadFrame()
		if err != nil {
			headFail(err)
			return
		}
		if err := res.Read3(frame); err != nil {
			headFail(err)
			return
		}
		// Session phase: every further frame is a §5.4 link frame.
		clock := func() time.Time { return time.Unix(1791072000, 0) }
		reasm := link.NewReassembler(time.Hour, clock)
		for {
			wire, err := headT.ReadFrame()
			if err != nil {
				headFail(err)
				return
			}
			typ, pt, err := link.OpenFrame(res.Session(), wire)
			if err != nil {
				headFail(err)
				return
			}
			if typ != link.TypeBundleFrag {
				headErr <- ErrTooLarge
				return
			}
			content, done, err := reasm.Push(pt)
			if err != nil {
				headFail(err)
				return
			}
			if done {
				completions <- completion{content: content}
			}
		}
	}()

	if err := bridgeT.WriteFrame(msg1); err != nil {
		t.Fatal(err)
	}
	wire2, err := bridgeT.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if err := ini.Read2(wire2); err != nil {
		t.Fatal(err)
	}
	msg3, err := ini.Write3()
	if err != nil {
		t.Fatal(err)
	}
	if err := bridgeT.WriteFrame(msg3); err != nil {
		t.Fatal(err)
	}
	sess := ini.Session()
	if sess == nil {
		t.Fatal("no initiator session")
	}
	content := make([]byte, 500)
	for i := range content {
		content[i] = byte(0xA0 + i%16)
	}
	frames, err := link.SplitWindow(7, content)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 3 {
		t.Fatalf("window split = %d frames", len(frames))
	}
	for copy := 0; copy < 2; copy++ { // redundancy 2
		for _, f := range frames {
			wire, err := link.SealFrame(sess, link.TypeBundleFrag, f)
			if err != nil {
				t.Fatal(err)
			}
			if err := bridgeT.WriteFrame(wire); err != nil {
				t.Fatal(err)
			}
		}
	}
	select {
	case c := <-completions:
		if !bytes.Equal(c.content, content) {
			t.Fatal("window reassembled with corruption")
		}
	case err := <-headErr:
		t.Fatalf("radio head: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("window completion timeout")
	}
	if dropConn.dropped != 1 {
		t.Fatalf("the lossy pipe dropped %d frames, want exactly 1", dropConn.dropped)
	}
	// Orderly shutdown: the head's read loop ends with the pipe's close;
	// that error is expected, not a failure.
	shutdown.store(true)
	bridgeRaw.Close()
	headRaw.Close()
}

// atomicBool — a tiny flag for the test's shutdown ordering (sync/atomic
// Bool in disguise; kept local so the test reads plainly).
type atomicBool struct {
	mu sync.Mutex
	v  bool
}

func (a *atomicBool) store(v bool) { a.mu.Lock(); a.v = v; a.mu.Unlock() }
func (a *atomicBool) load() bool   { a.mu.Lock(); defer a.mu.Unlock(); return a.v }
