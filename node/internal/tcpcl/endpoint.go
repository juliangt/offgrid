package tcpcl

// endpoint.go — the listener half of the Wi-Fi plane: an accept loop that
// turns inbound TCP connections into §4 handshakes and then served
// sessions. The dial half is Dial (session.go); the daemon owns its own
// opportunistic dial loop. The default port is the IANA TCPCL registration
// 4556 (RFC 9174 §4.1).

import (
	"context"
	"fmt"
	"net"
	"sync"
)

// DefaultPort is the IANA-assigned TCPCL port (§4.1).
const DefaultPort = 4556

// Listener serves the passive side of the TCPCL on one TCP address.
type Listener struct {
	cfg    Config
	ln     net.Listener
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu     sync.Mutex
	active map[*Session]struct{}
	closed bool
}

// Listen binds the TCPCL listener (it does NOT serve yet — call Serve).
func Listen(network, addr string, cfg Config) (*Listener, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	ln, err := net.Listen(network, addr)
	if err != nil {
		return nil, fmt.Errorf("tcpcl: listen %s: %w", addr, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Listener{
		cfg:    cfg,
		ln:     ln,
		ctx:    ctx,
		cancel: cancel,
		active: make(map[*Session]struct{}),
	}, nil
}

// Addr is the bound address (use :0 in tests to get an ephemeral port).
func (l *Listener) Addr() net.Addr { return l.ln.Addr() }

// Serve runs the accept loop until Close (or the listener fails). Each
// accepted connection gets its own goroutine running the passive §4
// ladder and then the session loop.
func (l *Listener) Serve() error {
	for {
		conn, err := l.ln.Accept()
		if err != nil {
			l.mu.Lock()
			closed := l.closed
			l.mu.Unlock()
			if closed {
				return nil
			}
			var ne net.Error
			if ok := asNetError(err, &ne); ok && ne.Timeout() {
				continue // transient; keep accepting
			}
			return fmt.Errorf("tcpcl: accept: %w", err)
		}
		l.wg.Add(1)
		go l.serveOne(conn)
	}
}

func asNetError(err error, target *net.Error) bool {
	ne, ok := err.(net.Error)
	if ok {
		*target = ne
	}
	return ok
}

func (l *Listener) serveOne(conn net.Conn) {
	defer l.wg.Done()
	sess, err := AcceptSession(l.ctx, conn, l.cfg)
	if err != nil {
		l.cfg.logf("inbound session from %s failed: %v", conn.RemoteAddr(), err)
		return
	}
	l.mu.Lock()
	if l.active == nil { // Close ran between accept and establish
		l.mu.Unlock()
		_ = sess.Terminate(TermUnknown)
		return
	}
	l.active[sess] = struct{}{}
	l.mu.Unlock()

	err = sess.Wait()

	l.mu.Lock()
	delete(l.active, sess)
	l.mu.Unlock()
	l.cfg.logf("inbound session with %s ended (%v)", sess.peerDesc(), err)
}

// Close stops the accept loop, gracefully terminates the active sessions
// and releases the goroutines. Idempotent.
func (l *Listener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	sessions := make([]*Session, 0, len(l.active))
	for s := range l.active {
		sessions = append(sessions, s)
	}
	l.active = nil
	l.mu.Unlock()

	l.cancel()
	_ = l.ln.Close()
	for _, s := range sessions {
		_ = s.Terminate(TermUnknown) // §6.1 graceful; bounded by the linger
	}
	l.wg.Wait()
	return nil
}

// ActiveSessions reports the number of currently established inbound
// sessions (operator honesty: a listener that accepted nobody says so).
func (l *Listener) ActiveSessions() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.active)
}
