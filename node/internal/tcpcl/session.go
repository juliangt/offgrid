package tcpcl

// session.go — the TCPCL session engine: the §4 contact/TLS/SESS_INIT
// establishment ladder, the §5.1/§5.2 message loop (keepalives, transfers,
// refusals), the §7.4 per-contact byte budgets and the §6.1 termination
// paths. One Session owns exactly two goroutines (the read loop and, when
// keepalives are negotiated, the keepalive writer); both exit with the
// connection, so a closed session leaves nothing behind.

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"offgrid/dtn-node/internal/bundle"
	"offgrid/dtn-node/internal/nodeid"
)

// BundleSink receives a fully received, profile-validated bundle PDU (the
// bytes are exactly the two-block CBOR sequence of the Offgrid BPv7
// profile; Parse has already accepted them). Accept is called from the
// session's read goroutine: it must not block for long and MUST NOT call
// back into the same session (a SendBundle there would deadlock the read
// loop). P3.5 replaces the daemon's counting stub with the real store.
type BundleSink interface {
	Accept(pdu []byte) error
}

// MTLSMode is the §4.4.3 client-certificate policy. The RFC's own text has
// the active entity ALWAYS supply a certificate; "optional" is the
// profile's defined relaxation (node-network §6.2 item 4: "mTLS
// optional-but-defined"), shaped after §7.12.1: the server verifies the
// certificate WHEN PRESENTED and counts the session as unauthenticated
// otherwise.
type MTLSMode int

const (
	MTLSRequired MTLSMode = iota
	MTLSOptional
)

func (m MTLSMode) String() string {
	if m == MTLSOptional {
		return "optional"
	}
	return "required"
}

// Defaults (node-network §6.3 / §7.4).
const (
	DefaultKeepalive     = 30 * time.Second // RFC 9174 §5.1.1: ≥ 30 s recommended
	DefaultSegmentMRU    = 256 << 10        // received-segment cap we advertise
	DefaultTransferMRU   = 64 << 20         // received-transfer cap we advertise
	DefaultMaxSegment    = 64 << 10         // our sending chunk (§9.1: 64 KiB)
	DefaultContactBudget = 64 << 20         // §7.4: 64 MiB per contact
	HandshakeTimeout     = 10 * time.Second // contact + TLS + SESS_INIT window
	WriteTimeout         = 60 * time.Second // per-write cap (writes take no ctx)
	DefaultTermLinger    = 5 * time.Second  // graceful SESS_TERM reply wait
	readBufSize          = 16 << 10         // bufio: ≥ the MaxExtItems peeks
)

// Config is the session/endpoint configuration. EID, Identity, Pins and
// Sink are required; validate() enforces that loudly before any wire byte.
type Config struct {
	// EID is OUR node EID (the SESS_INIT node ID).
	EID string
	// Identity is our self-signed node certificate (nodeid.SelfSignedX509).
	Identity tls.Certificate
	// Pins is the shared TOFU pin store (nodeid.PinStore). First contact
	// pins the peer's node key; a change fails the handshake LOUDLY
	// (nodeid.ErrPeerKeyChanged, §6.1).
	Pins *nodeid.PinStore
	// ExpectedPeer, when non-empty, asserts the dial target: a peer whose
	// certified identity differs fails the handshake.
	ExpectedPeer string
	// MTLS selects the client-certificate policy (default required).
	MTLS MTLSMode
	// Keepalive is OUR advertised §5.1.1 interval; the session negotiates
	// the minimum. 0 → the default; negative → advertise 0 (keepalives
	// disabled, the §4.7 note).
	Keepalive time.Duration
	// SegmentMRU is the largest single segment we accept (advertised).
	SegmentMRU uint64
	// TransferMRU is the largest total transfer we accept (advertised).
	TransferMRU uint64
	// MaxSegment is the largest segment we SEND (clamped by the peer's
	// SegmentMRU on the wire, §5.2).
	MaxSegment uint64
	// ContactBudget is the §7.4 per-contact bundle-byte budget, enforced on
	// ingress (refuse) AND egress (defer). 0 → the default; negative →
	// unlimited (an explicit opt-out, never the fleet default).
	ContactBudget int64
	// TermLinger bounds the graceful SESS_TERM reply wait (§6.1).
	TermLinger time.Duration
	// Sink receives validated bundles (ingress). Required.
	Sink BundleSink
	// OnEstablished, when non-nil, runs ONCE per established session in its
	// own goroutine, on BOTH the active and passive side, after the session
	// loops started (SendBundle is safe from it). The P3.5 sync engine uses
	// it to run the §7.1 summary exchange; it is a pure local hook — no
	// wire byte, no RFC 9174 message, is added by it.
	OnEstablished func(*Session)
	// Counters is the shared, optional counter set (nil-safe).
	Counters *Counters
	// Log is optional (nil → discard).
	Log *log.Logger
	// Now pins the receiver clock for the bundle P-6 skew rule (tests).
	Now func() time.Time
}

func (c *Config) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Config) logf(format string, a ...any) {
	if c.Log != nil {
		c.Log.Printf("tcpcl: "+format, a...)
	}
}

func (c *Config) validate() error {
	if _, err := nodeid.ParseEID(c.EID); err != nil {
		return fmt.Errorf("tcpcl: config EID: %w", err)
	}
	if len(c.Identity.Certificate) == 0 {
		return fmt.Errorf("tcpcl: config needs a node certificate (nodeid.SelfSignedX509)")
	}
	if c.Pins == nil {
		return fmt.Errorf("tcpcl: config needs a pin store (TOFU, node-network §6.1)")
	}
	if c.Sink == nil {
		return fmt.Errorf("tcpcl: config needs a BundleSink (validated receive path)")
	}
	return nil
}

func (c *Config) segmentMRU() uint64 {
	if c.SegmentMRU > 0 {
		return c.SegmentMRU
	}
	return DefaultSegmentMRU
}

func (c *Config) transferMRU() uint64 {
	if c.TransferMRU > 0 {
		return c.TransferMRU
	}
	return DefaultTransferMRU
}

func (c *Config) maxSegment() uint64 {
	if c.MaxSegment > 0 {
		return c.MaxSegment
	}
	return DefaultMaxSegment
}

// keepalive: > 0 the value, < 0 disabled (advertise 0), 0 the default.
func (c *Config) keepalive() time.Duration {
	if c.Keepalive > 0 {
		return c.Keepalive
	}
	if c.Keepalive < 0 {
		return 0
	}
	return DefaultKeepalive
}

func (c *Config) budget() int64 {
	if c.ContactBudget > 0 {
		return c.ContactBudget
	}
	if c.ContactBudget < 0 {
		return -1 // explicitly unlimited
	}
	return DefaultContactBudget
}

func (c *Config) termLinger() time.Duration {
	if c.TermLinger > 0 {
		return c.TermLinger
	}
	return DefaultTermLinger
}

// sessionState is the §3.3 lifecycle (Established / Ending / Closed).
type sessionState int32

const (
	stateHandshake sessionState = iota
	stateEstablished
	stateEnding
	stateClosed
)

// Session is one established TCPCL session over a TLS connection.
type Session struct {
	cfg  Config
	conn net.Conn // the *tls.Conn after the §4.4.3 upgrade
	r    *bufio.Reader

	peerEID  string // the identity the TLS handshake certified ("" if none)
	peerInit SessInit

	keepalive time.Duration // negotiated: min of the two SESS_INIT values

	state     atomic.Int32
	closeOnce sync.Once
	doneOnce  sync.Once
	done      chan struct{} // closed exactly once, when the session dies
	termErr   atomic.Pointer[termError]

	wmu       sync.Mutex // serializes every write on the connection
	lastWrite atomic.Int64

	txMu     sync.Mutex
	nextTxID uint64
	txs      map[uint64]*txState

	// receiver state — owned by the read loop goroutine only
	rx         *rxTransfer
	rxRefused  uint64 // transfer currently refused (crossing segments)
	hasRefused bool
	ingress    int64 // §7.4 per-contact budget burn (bytes)

	egress int64 // §7.4 per-contact budget burn (bytes), atomic ops
}

// termError records why a session died (Session.Err surfaces it).
type termError struct{ err error }

// txState is one sender-side unacked transfer.
type txState struct {
	id    uint64
	total int
	done  chan struct{}
	// guarded by Session.txMu:
	acked   uint64
	refused bool
	reason  RefuseReason
}

// rxTransfer is the receiver's in-progress transfer (no interleaving:
// §5.2.2 allows exactly one per direction at a time).
type rxTransfer struct {
	id       uint64
	total    int64 // from the Transfer Length Extension; -1 when absent
	received int
	buf      []byte
}

// peerAuth carries the identity the TLS handshake certified out of the
// crypto/tls VerifyPeerCertificate callback (which runs inside the
// handshake) into the Session.
type peerAuth struct {
	mu  sync.Mutex
	eid string
}

func (p *peerAuth) set(eid string) {
	p.mu.Lock()
	p.eid = eid
	p.mu.Unlock()
}

func (p *peerAuth) get() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.eid
}

// Dial opens a TCP connection to addr and runs the ACTIVE side of the §4
// ladder: contact header first, TLS upgrade (client role, §4.4.3),
// SESS_INIT. The returned session is established and ready for SendBundle.
func Dial(ctx context.Context, network, addr string, cfg Config) (*Session, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("tcpcl: dial %s: %w", addr, err)
	}
	cfg.Counters.incSessionsOut()
	s, err := handshake(ctx, conn, cfg, true)
	if err != nil {
		_ = conn.Close()
		cfg.Counters.incHandshakeFailures()
		cfg.logf("outgoing handshake to %s failed: %v", addr, err)
		return nil, err
	}
	s.startLoops()
	return s, nil
}

// AcceptSession runs the PASSIVE side of the §4 ladder on an accepted
// connection and returns once the session is established. The caller
// serves it to its end with Wait (ServeSession is the one-call form).
func AcceptSession(ctx context.Context, conn net.Conn, cfg Config) (*Session, error) {
	if err := cfg.validate(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	cfg.Counters.incSessionsIn()
	s, err := handshake(ctx, conn, cfg, false)
	if err != nil {
		_ = conn.Close()
		cfg.Counters.incHandshakeFailures()
		cfg.logf("incoming handshake from %s failed: %v", conn.RemoteAddr(), err)
		return nil, err
	}
	s.startLoops()
	return s, nil
}

// Wait blocks until the session has ended and returns its terminal error.
func (s *Session) Wait() error {
	<-s.done
	return s.Err()
}

// ServeSession runs the PASSIVE side of the §4 ladder on an accepted
// connection and then serves the session until it ends. It blocks; run it
// in its own goroutine. The returned session (when err == nil) has ended.
func ServeSession(ctx context.Context, conn net.Conn, cfg Config) (*Session, error) {
	s, err := AcceptSession(ctx, conn, cfg)
	if err != nil {
		return nil, err
	}
	return s, s.Wait()
}

// handshake implements the §4 ladder. active = the TCP-initiating peer
// (the TLS client role, §4.4.3).
func handshake(ctx context.Context, conn net.Conn, cfg Config, active bool) (*Session, error) {
	s := &Session{
		cfg:  cfg,
		conn: conn,
		r:    bufio.NewReaderSize(conn, readBufSize),
		done: make(chan struct{}),
		txs:  make(map[uint64]*txState),
	}

	// Hard deadline over the whole contact phase (§4.4.3: the TLS
	// handshake "is considered to be part of the contact negotiation
	// before the TCPCL session itself is established").
	_ = conn.SetDeadline(time.Now().Add(HandshakeTimeout))

	auth := &peerAuth{}
	ours := ContactHeader{Version: ProtocolVersion, Flags: FlagCAN_TLS} // §4.2: the profile always enables TLS

	if active {
		if _, err := conn.Write(EncodeContactHeader(ours)); err != nil {
			return nil, fmt.Errorf("%w: write contact header: %w", ErrHandshake, err)
		}
	}
	hdr := make([]byte, 6)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, fmt.Errorf("%w: read contact header: %w", ErrHandshake, err)
	}
	theirs, err := ParseContactHeader(hdr)
	if err != nil && !errors.Is(err, ErrBadVersion) {
		// §4.3: an undecodable magic closes the TCP connection WITHOUT
		// any SESS_TERM (the inadvertent-protocol guard).
		return nil, fmt.Errorf("%w: %v", ErrHandshake, err)
	}
	if !active {
		if _, err := conn.Write(EncodeContactHeader(ours)); err != nil {
			return nil, fmt.Errorf("%w: write contact header: %w", ErrHandshake, err)
		}
	}
	if err != nil || theirs.Version != ProtocolVersion {
		// §4.3: the passive entity answers an unsupported version with its
		// own contact header (above) and SESS_TERM "Version mismatch"; the
		// active side just closes. (This profile speaks v4 only — no
		// fallback ladder.)
		if !active {
			_, _ = conn.Write(EncodeSESS_TERM(SessTerm{Reason: TermVersionMismatch}))
		}
		return nil, fmt.Errorf("%w: peer speaks version %d", ErrHandshake, theirs.Version)
	}

	// Enable TLS = logical AND of the two CAN_TLS flags (§4.3). Profile
	// policy: TLS REQUIRED — a peer that refuses is terminated with
	// "Contact Failure" (TLS stripping is not ours to tolerate,
	// node-network §6.2 item 4).
	if theirs.Flags&FlagCAN_TLS == 0 {
		_, _ = conn.Write(EncodeSESS_TERM(SessTerm{Reason: TermContactFailure}))
		cfg.logf("peer %s does not offer TLS; terminated with Contact Failure", conn.RemoteAddr())
		return nil, ErrTLSRequired
	}

	// The in-band TLS upgrade (§4.4.3): active peer = client role.
	tlsConn := tls.Server(conn, serverTLSConfig(&cfg, auth))
	if active {
		tlsConn = tls.Client(conn, clientTLSConfig(&cfg, auth))
	}
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		// §4.4.3: a failed TLS handshake closes the TCP connection; no
		// TCPCL session exists, so no SESS_TERM.
		return nil, fmt.Errorf("%w: TLS handshake: %w", ErrHandshake, err)
	}
	s.conn = tlsConn
	s.r = bufio.NewReaderSize(tlsConn, readBufSize)
	s.peerEID = auth.get()

	// SESS_INIT from BOTH entities (Figure 17), each write-then-read.
	init := SessInit{
		KeepaliveSec: uint16(keepaliveSeconds(cfg.keepalive())),
		SegmentMRU:   cfg.segmentMRU(),
		TransferMRU:  cfg.transferMRU(),
		NodeID:       cfg.EID,
		Extensions:   nil, // §6.3 decision: no session extension items
	}
	msg, err := EncodeSESS_INIT(init)
	if err != nil {
		return nil, err
	}
	if _, err := s.conn.Write(msg); err != nil {
		return nil, fmt.Errorf("%w: write SESS_INIT: %v", ErrHandshake, err)
	}
	h, body, err := readMessage(s.r, cfg.segmentMRU())
	if err != nil {
		return nil, fmt.Errorf("%w: read SESS_INIT: %w", ErrHandshake, err)
	}
	if h == MsgSESS_TERM {
		term, _ := ParseSESS_TERM(body)
		return nil, fmt.Errorf("%w: peer terminated contact: %s", ErrHandshake, term.Reason)
	}
	if h != MsgSESS_INIT {
		return nil, fmt.Errorf("%w: want SESS_INIT, got %s", ErrHandshake, msgName(h))
	}
	peerInit, err := ParseSESS_INIT(body)
	if err != nil {
		return nil, err
	}
	if err := s.validatePeerInit(peerInit); err != nil {
		_, _ = s.conn.Write(EncodeSESS_TERM(SessTerm{Reason: TermContactFailure}))
		return nil, err
	}

	s.peerInit = peerInit
	s.keepalive = negotiatedKeepalive(init, peerInit)
	s.state.Store(int32(stateEstablished))
	s.lastWrite.Store(time.Now().UnixNano())

	cfg.logf("session established with %s via %s (keepalive %s, segMRU %d, xferMRU %d, mtls %s, budget %s)",
		s.peerDesc(), conn.RemoteAddr(), s.keepalive, peerInit.SegmentMRU, peerInit.TransferMRU,
		cfg.MTLS, budgetString(cfg.budget()))
	return s, nil
}

// keepaliveSeconds converts the advertised interval into the SESS_INIT
// U16 field (capped; a negative duration already resolved to 0/disabled).
func keepaliveSeconds(d time.Duration) int64 {
	secs := int64(d / time.Second)
	if secs > 65535 {
		secs = 65535
	}
	return secs
}

// negotiatedKeepalive is §4.7: the minimum of the two announcements; zero
// disables keepalives (the §4.7 note).
func negotiatedKeepalive(ours, theirs SessInit) time.Duration {
	a := time.Duration(ours.KeepaliveSec) * time.Second
	b := time.Duration(theirs.KeepaliveSec) * time.Second
	if b < a {
		a = b
	}
	return a
}

// validatePeerInit applies the profile's §4.7 acceptability rules plus the
// identity binding: a non-empty SESS_INIT node ID MUST be a profile node
// EID and MUST equal the identity the TLS handshake certified (when it
// certified one — mTLS-optional without a client certificate).
func (s *Session) validatePeerInit(m SessInit) error {
	if m.SegmentMRU < 64 || m.TransferMRU < 64 {
		return fmt.Errorf("%w: peer MRUs unacceptable (seg %d, xfer %d)", ErrHandshake, m.SegmentMRU, m.TransferMRU)
	}
	if m.NodeID == "" {
		// §4.6: zero-length = the deliberate lack of a node ID. The
		// session continues; the peer is just unnamed (and its identity
		// counts as unauthenticated unless its certificate said otherwise).
		s.cfg.logf("peer %s sent no node ID (RFC 9174 §4.6); session continues", s.conn.RemoteAddr())
		return nil
	}
	if _, err := nodeid.ParseEID(m.NodeID); err != nil {
		return fmt.Errorf("%w: peer node ID %q is not a profile EID", ErrHandshake, m.NodeID)
	}
	if s.peerEID != "" && m.NodeID != s.peerEID {
		s.cfg.Counters.incPinRejections()
		return fmt.Errorf("%w: SESS_INIT node ID %s != TLS-certified %s", ErrPeerIdentity, m.NodeID, s.peerEID)
	}
	return nil
}

// peerDesc is the certified EID when one exists, else the honest
// asserted/unnamed placeholder.
func (s *Session) peerDesc() string {
	if s.peerEID != "" {
		return s.peerEID
	}
	if s.peerInit.NodeID != "" {
		return s.peerInit.NodeID + " (asserted, unauthenticated)"
	}
	return "(no node ID)"
}

// PeerEID returns the peer's certified EID ("" when none was certified —
// mTLS-optional without a client certificate).
func (s *Session) PeerEID() string { return s.peerEID }

// RemoteAddr returns the underlying connection address.
func (s *Session) RemoteAddr() net.Addr { return s.conn.RemoteAddr() }

// Err returns the terminal error of a finished session (nil while running,
// and nil for a cleanly exchanged §6.1 termination).
func (s *Session) Err() error {
	if te := s.termErr.Load(); te != nil {
		return te.err
	}
	return nil
}

// Done is closed when the session's read loop has exited (the session no
// longer exists).
func (s *Session) Done() <-chan struct{} { return s.done }

// startLoops launches the read loop and (when keepalives are negotiated)
// the keepalive writer, then the OnEstablished hook in its own goroutine.
// Exactly two goroutines in the no-hook case, both tied to s.done.
func (s *Session) startLoops() {
	go s.readLoop()
	if s.keepalive > 0 {
		go s.keepaliveLoop()
	}
	if h := s.cfg.OnEstablished; h != nil {
		go h(s)
	}
}

// ---------------------------------------------------------------------------
// Writes. Every write holds s.wmu, stamps lastWrite (the §5.1.1 "no
// transmission of any message" clock) and carries a deadline.
// ---------------------------------------------------------------------------

func (s *Session) writeRaw(msg []byte) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	return s.writeLocked(msg)
}

// writeMessageLocked writes header ‖ body in one call (the caller holds
// s.wmu — the keepalive loop's path, which must re-check its condition
// under the same lock it writes under).
func (s *Session) writeMessageLocked(hdr byte, body []byte) error {
	buf := make([]byte, 0, 1+len(body))
	buf = append(buf, hdr)
	buf = append(buf, body...)
	return s.writeLocked(buf)
}

func (s *Session) writeLocked(msg []byte) error {
	_ = s.conn.SetWriteDeadline(time.Now().Add(WriteTimeout))
	if _, err := s.conn.Write(msg); err != nil {
		return err
	}
	s.lastWrite.Store(time.Now().UnixNano())
	return nil
}

// keepaliveLoop is §5.1.1: send KEEPALIVE when the negotiated interval has
// elapsed with no transmission of ANY message. Idle termination is the
// reader's job. Exits with the session.
func (s *Session) keepaliveLoop() {
	tick := s.keepalive / 2
	if tick < 250*time.Millisecond {
		tick = 250 * time.Millisecond
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
			if time.Since(time.Unix(0, s.lastWrite.Load())) < s.keepalive {
				continue
			}
			s.wmu.Lock()
			// Re-check under the lock: a sender may have written meanwhile.
			if time.Since(time.Unix(0, s.lastWrite.Load())) < s.keepalive {
				s.wmu.Unlock()
				continue
			}
			if err := s.writeMessageLocked(MsgKEEPALIVE, nil); err != nil {
				s.wmu.Unlock()
				s.fail(fmt.Errorf("tcpcl: keepalive write: %w", err))
				return
			}
			s.wmu.Unlock()
		}
	}
}

// ---------------------------------------------------------------------------
// The read loop: message dispatch, §5.1.1 idle termination, the receiver
// side of transfers, budget enforcement.
// ---------------------------------------------------------------------------

func (s *Session) readLoop() {
	defer s.closeConn()
	for {
		// §5.1.1: nothing RECEIVED for (at least) 2× the keepalive interval
		// → SESS_TERM "Idle timeout" (exactly 2× here — the bound is not
		// operator-configurable in this profile). With keepalives disabled
		// there is no idle bound (the daemon's context still closes the
		// connection).
		if s.keepalive > 0 {
			_ = s.conn.SetReadDeadline(time.Now().Add(2 * s.keepalive))
		} else {
			_ = s.conn.SetReadDeadline(time.Time{})
		}
		hdr, body, err := readMessage(s.r, s.cfg.segmentMRU())
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() && s.keepalive > 0 {
				s.cfg.Counters.incKeepaliveTimeouts()
				s.terminateBestEffort(SessTerm{Reason: TermIdleTimeout})
				s.fail(ErrIdleTimeout)
				return
			}
			if isEOF(err) {
				// A §6.1-exchanged termination (we already sent ours) ends
				// CLEANLY at EOF; a silent peer drop does not.
				if sessionState(s.state.Load()) != stateEnding {
					s.fail(fmt.Errorf("tcpcl: connection closed by peer: %w", err))
				}
				return
			}
			s.fail(fmt.Errorf("tcpcl: read: %w", err))
			return
		}

		switch hdr {
		case MsgKEEPALIVE:
			// activity only; nothing to do

		case MsgSESS_TERM:
			term, perr := ParseSESS_TERM(body)
			if perr != nil {
				s.rejectAndDie(RejectUnsupported, perr, hdr)
				return
			}
			if !term.Reply && s.state.Load() != int32(stateEnding) {
				// Peer-initiated: §6.1 — reply with identical content and
				// the REPLY flag set, enter Ending (new transfers refused,
				// in-progress ones MAY finish), drain, close.
				s.state.Store(int32(stateEnding))
				_ = s.writeRaw(EncodeSESS_TERM(SessTerm{Reply: true, Reason: term.Reason}))
				s.cfg.Counters.incGracefulTerms()
				s.cfg.logf("peer %s terminated the session (%s); replying and draining", s.peerDesc(), term.Reason)
				_ = s.conn.SetReadDeadline(time.Now().Add(s.cfg.termLinger()))
				continue
			}
			// Our termination acknowledged: the §6.1 exchange is complete.
			// The TLS closure alert is the ORIGINAL terminator's duty —
			// that is the peer now; we simply close.
			s.state.Store(int32(stateEnding))
			return

		case MsgSESS_INIT:
			// §5.1.2: a SESS_INIT after establishment is state-incorrect.
			s.rejectAndDie(RejectUnexpected, fmt.Errorf("%w: SESS_INIT after establishment", ErrProtocol), hdr)
			return

		case MsgMSG_REJECT:
			rej, perr := ParseMSG_REJECT(body)
			if perr != nil {
				s.rejectAndDie(RejectUnsupported, perr, hdr)
				return
			}
			s.fail(fmt.Errorf("tcpcl: peer rejected our %s: %s", msgName(rej.Rejected), rej.Reason))
			return

		case MsgXFER_ACK:
			ack, perr := ParseXFER_ACK(body)
			if perr != nil {
				s.rejectAndDie(RejectUnsupported, perr, hdr)
				return
			}
			if !s.applyAck(ack) {
				// §5.1.2 names exactly this case: an XFER_ACK with an
				// unknown Transfer ID is "Message Unexpected".
				s.rejectAndDie(RejectUnexpected, fmt.Errorf("%w: XFER_ACK for unknown transfer %d", ErrProtocol, ack.TransferID), hdr)
				return
			}

		case MsgXFER_REFUSE:
			ref, perr := ParseXFER_REFUSE(body)
			if perr != nil {
				s.rejectAndDie(RejectUnsupported, perr, hdr)
				return
			}
			s.applyRefuse(ref)

		case MsgXFER_SEGMENT:
			seg, perr := ParseXFER_SEGMENT(body)
			if perr != nil {
				s.rejectAndDie(RejectUnsupported, perr, hdr)
				return
			}
			if done := s.handleSegment(seg); done {
				return
			}

		default:
			// §5.1.2: unknown message type → MSG_REJECT "Message Type
			// Unknown" and close the TCP connection.
			_ = s.writeRaw(EncodeMSG_REJECT(MsgReject{Reason: RejectTypeUnknown, Rejected: hdr}))
			s.cfg.Counters.incProtocolErrors()
			s.fail(fmt.Errorf("%w: unknown message type 0x%02x", ErrProtocol, hdr))
			return
		}
	}
}

func isEOF(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

// rejectAndDie sends MSG_REJECT and terminates the session fail-closed.
func (s *Session) rejectAndDie(reason RejectReason, err error, rejected byte) {
	_ = s.writeRaw(EncodeMSG_REJECT(MsgReject{Reason: reason, Rejected: rejected}))
	s.cfg.Counters.incProtocolErrors()
	s.terminateBestEffort(SessTerm{Reason: TermContactFailure})
	s.fail(err)
}

// handleSegment runs the receiver state machine. It returns true when the
// session must end.
func (s *Session) handleSegment(seg XferSegment) bool {
	// §6.1 Ending state: refuse any NEW incoming transfer.
	if s.state.Load() == int32(stateEnding) && seg.Start && (s.rx == nil || s.rx.id != seg.TransferID) {
		s.refuse(XferRefuse{Reason: RefuseSessionTerminating, TransferID: seg.TransferID})
		s.discardTransfer(seg)
		return false
	}

	if seg.Start {
		if s.rx != nil {
			// §5.2.2: no interleaving — a START while a transfer is in
			// progress is a sender violation (fail closed).
			s.rejectAndDie(RejectUnexpected, fmt.Errorf("%w: START of transfer %d interleaves transfer %d", ErrProtocol, seg.TransferID, s.rx.id), MsgXFER_SEGMENT)
			return true
		}
		return s.beginTransfer(seg)
	}

	// Continuation / END segment.
	if s.rx == nil {
		if s.hasRefused && s.rxRefused == seg.TransferID {
			// Refusal crossed on the wire: §5.2.4 — subsequent segments of
			// a refused transfer SHALL also be refused.
			s.refuse(XferRefuse{Reason: RefuseNoResources, TransferID: seg.TransferID})
			return false
		}
		s.rejectAndDie(RejectUnexpected, fmt.Errorf("%w: %s segment for transfer %d with no transfer in progress", ErrProtocol, segFlagName(seg), seg.TransferID), MsgXFER_SEGMENT)
		return true
	}
	if s.rx.id != seg.TransferID {
		// Impossible per the no-interleaving rule; fail closed anyway.
		s.rejectAndDie(RejectUnexpected, fmt.Errorf("%w: segment for transfer %d while %d is in progress", ErrProtocol, seg.TransferID, s.rx.id), MsgXFER_SEGMENT)
		return true
	}
	return s.continueTransfer(seg)
}

func segFlagName(seg XferSegment) string {
	switch {
	case seg.Start && seg.End:
		return "single-segment"
	case seg.End:
		return "END"
	default:
		return "continuation"
	}
}

// beginTransfer opens a new incoming transfer: extension handling and the
// MRU/budget gates first — refusing BEFORE the bytes arrive is the §5.2.4
// preemptive-refuse path.
func (s *Session) beginTransfer(seg XferSegment) bool {
	total := int64(-1)
	for _, it := range seg.Extensions {
		switch {
		case it.Type == ExtensionTransferLength:
			// §5.2.5.1: Total Length, authoritative.
			if len(it.Value) != 8 {
				s.cfg.Counters.incRefusalsIn()
				s.refuse(XferRefuse{Reason: RefuseExtensionFailure, TransferID: seg.TransferID})
				s.discardTransfer(seg)
				return false
			}
			total = int64(beUint64(it.Value))
		case it.Critical():
			// §5.2.5: unknown CRITICAL item → refuse "Extension Failure".
			s.cfg.Counters.incRefusalsIn()
			s.refuse(XferRefuse{Reason: RefuseExtensionFailure, TransferID: seg.TransferID})
			s.discardTransfer(seg)
			return false
		default:
			// §5.2.5: unknown non-critical item → skip and ignore.
		}
	}

	// Transfer MRU (§4.6: "largest allowable total-bundle data size").
	if total >= 0 && total > int64(s.cfg.transferMRU()) {
		s.cfg.Counters.incRefusalsIn()
		s.refuse(XferRefuse{Reason: RefuseNoResources, TransferID: seg.TransferID})
		s.discardTransfer(seg)
		return false
	}
	// §7.4 ingress budget: refuse BEFORE the bytes arrive when the sender
	// announced the size.
	if b := s.cfg.budget(); b >= 0 && total >= 0 && s.ingress+total > b {
		s.cfg.Counters.incBudgetRefusalsIn()
		s.refuse(XferRefuse{Reason: RefuseNoResources, TransferID: seg.TransferID})
		s.discardTransfer(seg)
		return false
	}

	s.rx = &rxTransfer{id: seg.TransferID, total: total}
	return s.continueTransfer(seg)
}

// continueTransfer appends a segment, ACKs it (§5.2.3: flags echo the
// segment being acknowledged, length is cumulative), and completes the
// transfer on END.
func (s *Session) continueTransfer(seg XferSegment) bool {
	rx := s.rx
	// Budget per received byte (for senders that announced nothing).
	if b := s.cfg.budget(); b >= 0 && s.ingress+int64(len(seg.Data)) > b {
		s.cfg.Counters.incBudgetRefusalsIn()
		s.refuse(XferRefuse{Reason: RefuseNoResources, TransferID: rx.id})
		s.discardTransfer(seg)
		return false
	}
	rx.received += len(seg.Data)
	rx.buf = append(rx.buf, seg.Data...)
	s.ingress += int64(len(seg.Data))

	if seg.End {
		return s.completeTransfer(seg)
	}
	if err := s.writeRaw(EncodeXFER_ACK(XferAck{
		Start:        seg.Start,
		TransferID:   rx.id,
		Acknowledged: uint64(rx.received),
	})); err != nil {
		s.fail(fmt.Errorf("tcpcl: write XFER_ACK: %w", err))
		return true
	}
	return false
}

// completeTransfer validates the assembled PDU and hands it to the sink.
// The §5.2.3 contract ("ACK after the segment has been fully processed")
// is honored strictly for the END segment: the final ACK is sent only
// when the bundle validated AND the sink took it — a sender therefore
// never observes a completed transfer that the receiver actually refused
// (§5.2.4: refuse instead of acknowledge).
func (s *Session) completeTransfer(seg XferSegment) bool {
	rx := s.rx
	s.rx = nil

	// §5.2.5.1: the Transfer Length Extension is authoritative — any
	// mismatch makes the data invalid ("Not Acceptable").
	if rx.total >= 0 && rx.total != int64(rx.received) {
		s.cfg.Counters.incRefusalsIn()
		s.refuse(XferRefuse{Reason: RefuseNotAcceptable, TransferID: rx.id})
		return false
	}

	// Fail-closed profile admission: the bytes MUST parse as a bundle
	// (node-network §3; the P-6 skew rule runs against OUR clock).
	if _, err := bundle.Parse(rx.buf, s.cfg.now()); err != nil {
		s.cfg.Counters.incMalformedBundles()
		s.cfg.Counters.incRefusalsIn()
		s.cfg.logf("refusing transfer %d from %s: not a profile bundle: %v", rx.id, s.peerDesc(), err)
		s.refuse(XferRefuse{Reason: RefuseNotAcceptable, TransferID: rx.id})
		return false
	}
	if err := s.cfg.Sink.Accept(rx.buf); err != nil {
		// The sink rejected (storage full, policy): Table 6's "the
		// receiver's resources are exhausted" is the honest code. The
		// bundle validated; this is a local-capacity verdict.
		s.cfg.Counters.incRefusalsIn()
		s.cfg.logf("sink refused transfer %d from %s: %v", rx.id, s.peerDesc(), err)
		s.refuse(XferRefuse{Reason: RefuseNoResources, TransferID: rx.id})
		return false
	}

	// The final cumulative ACK for the END segment (§5.2.3): everything
	// before it was acknowledged segment-by-segment; this one closes a
	// fully processed transfer.
	if err := s.writeRaw(EncodeXFER_ACK(XferAck{
		Start:        seg.Start,
		End:          true,
		TransferID:   rx.id,
		Acknowledged: uint64(rx.received),
	})); err != nil {
		s.fail(fmt.Errorf("tcpcl: write XFER_ACK: %w", err))
		return true
	}
	s.cfg.Counters.incBundlesIn(1)
	return false
}

// discardTransfer swallows the remainder of a refused transfer: the sender
// may still have segments in flight when our refusal crossed (§5.2.4).
func (s *Session) discardTransfer(seg XferSegment) {
	s.rx = nil
	if seg.Start {
		s.rxRefused = seg.TransferID
		s.hasRefused = true
	}
}

func (s *Session) refuse(m XferRefuse) {
	if err := s.writeRaw(EncodeXFER_REFUSE(m)); err != nil {
		s.fail(fmt.Errorf("tcpcl: write XFER_REFUSE: %w", err))
	}
}

// applyAck advances a sender-side transfer; false ⇒ unknown transfer ID.
func (s *Session) applyAck(ack XferAck) bool {
	s.txMu.Lock()
	defer s.txMu.Unlock()
	tx, ok := s.txs[ack.TransferID]
	if !ok {
		return false
	}
	if ack.Acknowledged > tx.acked {
		tx.acked = ack.Acknowledged
	}
	if tx.acked >= uint64(tx.total) {
		// §5.2.3: the cumulative acknowledged length reached the transfer
		// size — the transfer is complete.
		tx.refused = false
		delete(s.txs, tx.id)
		close(tx.done)
	}
	return true
}

// applyRefuse aborts a sender-side transfer (§5.2.4). A refusal for an
// unknown transfer ID is ignored quietly — §5.2.4 lets refusals cross with
// completion, so a late refusal for a finished transfer is legal.
func (s *Session) applyRefuse(ref XferRefuse) {
	s.txMu.Lock()
	tx, ok := s.txs[ref.TransferID]
	if ok {
		tx.refused = true
		tx.reason = ref.Reason
		delete(s.txs, tx.id)
		close(tx.done)
	}
	s.txMu.Unlock()
	if ok {
		s.cfg.Counters.incRefusalsOut()
		s.cfg.logf("transfer %d refused by %s: %s", ref.TransferID, s.peerDesc(), ref.Reason)
	}
}

// ---------------------------------------------------------------------------
// Sender side: SendBundle.
// ---------------------------------------------------------------------------

// ErrTransferRefusedDetail carries the peer's Table-6 reason on a refusal
// (Unwrap → ErrTransferRefused).
type ErrTransferRefusedDetail struct {
	Reason RefuseReason
}

func (e *ErrTransferRefusedDetail) Error() string {
	return "tcpcl: transfer refused by peer: " + e.Reason.String()
}

func (e *ErrTransferRefusedDetail) Unwrap() error { return ErrTransferRefused }

// SendBundle transfers one bundle PDU (a full `bundle.Encode` output) to
// the peer: §5.2 segmentation (no interleaving — the whole transfer runs to
// completion before the next begins), pipelined segments, START/END flags,
// the Transfer Length Extension on multi-segment transfers (§5.2.5.1).
// The §7.4 egress budget defers transfers that would not fit this contact.
// Returns when the peer has acknowledged every byte (or on refusal/error).
func (s *Session) SendBundle(ctx context.Context, pdu []byte) error {
	switch sessionState(s.state.Load()) {
	case stateEnding:
		return ErrSessionEnding
	case stateClosed:
		return ErrSessionClosed
	}
	if len(pdu) == 0 {
		return fmt.Errorf("tcpcl: empty bundle PDU")
	}
	if uint64(len(pdu)) > s.peerInit.TransferMRU {
		// Proactive fragmentation is the SENDER's job (§4.6); a bundle
		// larger than the peer's advertised transfer cap can never fit.
		// The profile carries whole bundles per transfer, so this is a
		// hard caller error.
		return fmt.Errorf("tcpcl: bundle of %d bytes exceeds the peer transfer MRU %d", len(pdu), s.peerInit.TransferMRU)
	}

	// §7.4 egress gate: defer what cannot fit this contact's budget.
	if b := s.cfg.budget(); b >= 0 {
		if atomic.AddInt64(&s.egress, int64(len(pdu))) > b {
			atomic.AddInt64(&s.egress, -int64(len(pdu)))
			s.cfg.Counters.incBudgetDeferralsOut()
			return ErrBudgetDeferred
		}
	}

	segSize := s.cfg.maxSegment()
	if s.peerInit.SegmentMRU > 0 && segSize > s.peerInit.SegmentMRU {
		segSize = s.peerInit.SegmentMRU // §5.2: never exceed the peer's Segment MRU
	}

	s.txMu.Lock()
	tx := &txState{
		id:    s.nextTxID, // §5.2.1: first 0, +1 each (the default algorithm)
		total: len(pdu),
		done:  make(chan struct{}),
	}
	s.nextTxID++
	s.txs[tx.id] = tx
	s.txMu.Unlock()

	multi := len(pdu) > int(segSize)
	// §5.2.5.1: the Transfer Length Extension SHOULD NOT be present on
	// single-segment transfers; multi-segment ones carry the total.
	var exts []ExtensionItem
	if multi {
		v := make([]byte, 8)
		putUint64(v, uint64(len(pdu)))
		exts = []ExtensionItem{{Type: ExtensionTransferLength, Value: v}}
	}

	var sendErr error
	for off := 0; off < len(pdu); off += int(segSize) {
		// A refusal may have crossed while earlier segments were in flight:
		// §5.2.4 — never commence further segments of a refused transfer.
		s.txMu.Lock()
		refused, reason := tx.refused, tx.reason
		s.txMu.Unlock()
		if refused {
			sendErr = &ErrTransferRefusedDetail{Reason: reason}
			break
		}
		end := off + int(segSize)
		if end > len(pdu) {
			end = len(pdu)
		}
		seg := XferSegment{
			Start:      off == 0,
			End:        end == len(pdu),
			TransferID: tx.id,
			Extensions: exts, // read on START segments only
			Data:       pdu[off:end],
		}
		if err := s.writeRaw(EncodeXFER_SEGMENT(seg)); err != nil {
			sendErr = err
			break
		}
		s.cfg.Counters.addBytesOut(uint64(end - off))
	}
	if sendErr != nil {
		// The stream state is uncertain after a failed write: the session
		// dies (fail-closed) and the transfer slot is released.
		s.fail(sendErr)
		return sendErr
	}

	// Pipelined: all segments are on the wire; wait for the cumulative ACK
	// (or refusal, or session death).
	select {
	case <-tx.done:
		if tx.refused {
			return &ErrTransferRefusedDetail{Reason: tx.reason}
		}
		s.cfg.Counters.incBundlesOut(1)
		return nil
	case <-s.done:
		return s.Err()
	case <-ctx.Done():
		// Segments already sent remain the peer's problem (TCP keeps the
		// stream consistent); the transfer is abandoned sender-side.
		return ctx.Err()
	}
}

// ---------------------------------------------------------------------------
// Termination (§6.1).
// ---------------------------------------------------------------------------

// Terminate runs the graceful §6.1 exchange: send SESS_TERM (REPLY=0),
// wait for the peer's acknowledging SESS_TERM (bounded by the linger),
// then close. The TLS closure alert rides on this close because the
// original SESS_TERM was ours (§4.4).
func (s *Session) Terminate(reason TermReason) error {
	if !s.state.CompareAndSwap(int32(stateEstablished), int32(stateEnding)) {
		if sessionState(s.state.Load()) == stateEnding {
			return nil // already terminating; the first Terminate owns it
		}
		return ErrSessionClosed
	}
	s.cfg.Counters.incGracefulTerms()
	if err := s.writeRaw(EncodeSESS_TERM(SessTerm{Reason: reason})); err != nil {
		s.fail(fmt.Errorf("tcpcl: write SESS_TERM: %w", err))
		return err
	}
	s.cfg.logf("terminating session with %s (%s)", s.peerDesc(), reason)
	select {
	case <-s.done:
		return s.Err()
	case <-time.After(s.cfg.termLinger()):
		s.fail(fmt.Errorf("tcpcl: SESS_TERM reply timed out after %s", s.cfg.termLinger()))
		return s.Err()
	}
}

// terminateBestEffort sends a SESS_TERM without state games (the idle
// timeout path — §5.1.1).
func (s *Session) terminateBestEffort(term SessTerm) {
	_ = s.writeRaw(EncodeSESS_TERM(term))
}

// Close performs the §6.1 unclean termination: a best-effort SESS_TERM
// followed by an immediate connection close. Safe from any state, any
// number of times (including after a failed handshake).
func (s *Session) Close() error {
	var err error
	s.closeOnce.Do(func() {
		if sessionState(s.state.Load()) == stateEstablished {
			s.state.Store(int32(stateEnding))
			_ = s.writeRaw(EncodeSESS_TERM(SessTerm{Reason: TermUnknown}))
		}
		s.state.Store(int32(stateClosed))
		err = s.conn.Close()
	})
	s.markDone()
	return err
}

// closeConn is the read loop's exit: mark closed, drop the connection,
// wake every waiter.
func (s *Session) closeConn() {
	s.closeOnce.Do(func() {
		s.state.Store(int32(stateClosed))
		_ = s.conn.Close()
	})
	s.markDone()
}

func (s *Session) markDone() {
	s.doneOnce.Do(func() { close(s.done) })
}

// fail records the terminal error once (first writer wins) and tears the
// connection down; waiters on s.done wake.
func (s *Session) fail(err error) {
	s.termErr.CompareAndSwap(nil, &termError{err: err})
	s.closeConn()
}

// budgetString renders a §7.4 budget for logs ("64 MiB" / "unlimited").
func budgetString(b int64) string {
	if b < 0 {
		return "unlimited"
	}
	return fmt.Sprintf("%d MiB", b>>20)
}
