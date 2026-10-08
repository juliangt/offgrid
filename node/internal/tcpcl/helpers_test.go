package tcpcl

// helpers_test.go — manual protocol peers for the cases where a full
// in-package Session would mask the behavior under test: a scripted
// ACTIVE peer (with or without a client certificate) driven byte by byte,
// plus tiny dial/read wrappers.

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"offgrid/dtn-node/internal/nodeid"
)

func netDial(addr string) (net.Conn, error) {
	return net.Dial("tcp", addr)
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	return io.ReadFull(conn, buf)
}

// bareTLSClient is a TLS 1.3 client with NO certificate (the §4.4.3
// violator for the mTLS-required test).
type bareTLSClient struct {
	t    *testing.T
	conn net.Conn
	tlsC *tls.Conn
}

func newBareTLSClient(addr string) (*bareTLSClient, error) {
	conn, err := netDial(addr)
	if err != nil {
		return nil, err
	}
	return &bareTLSClient{conn: conn, tlsC: tls.Client(conn, &tls.Config{
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, //nolint:gosec // the test asserts handshake failure
	})}, nil
}

func (b *bareTLSClient) handshake() error { return b.tlsC.Handshake() }

// manualPeer drives the ACTIVE side of the §4 ladder by hand: contact
// headers, TLS upgrade (with the given certificate, possibly nil for the
// §7.12.1 uncertified case), SESS_INIT — and then exposes raw message
// read/write for scripted behavior (silence, garbage, hostile messages).
type manualPeer struct {
	t    *testing.T
	conn net.Conn
	r    *bufio.Reader
	tlsC *tls.Conn
	eid  string
}

func manualActivePeer(t *testing.T, addr, nodeID string, cert *tls.Certificate) *manualPeer {
	t.Helper()
	conn, err := netDial(addr)
	if err != nil {
		t.Fatalf("manual peer dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	p := &manualPeer{t: t, conn: conn, eid: nodeID}

	if _, err := p.conn.Write(EncodeContactHeader(ContactHeader{Version: ProtocolVersion, Flags: FlagCAN_TLS})); err != nil {
		t.Fatalf("manual peer contact write: %v", err)
	}
	hdr := make([]byte, 6)
	if _, err := io.ReadFull(p.conn, hdr); err != nil {
		t.Fatalf("manual peer contact read: %v", err)
	}
	if _, err := ParseContactHeader(hdr); err != nil {
		t.Fatalf("manual peer contact header: %v", err)
	}
	tc := tls.Client(p.conn, &tls.Config{
		Certificates:       certCerts(cert),
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, //nolint:gosec // the test pins by construction
	})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("manual peer TLS handshake: %v", err)
	}
	p.tlsC = tc
	init := SessInit{
		KeepaliveSec: 1, // matches the keepalive test's interval
		SegmentMRU:   DefaultSegmentMRU,
		TransferMRU:  DefaultTransferMRU,
		NodeID:       nodeID,
	}
	msg, err := EncodeSESS_INIT(init)
	if err != nil {
		t.Fatalf("manual peer SESS_INIT: %v", err)
	}
	if _, err := tc.Write(msg); err != nil {
		t.Fatalf("manual peer SESS_INIT write: %v", err)
	}
	p.r = bufio.NewReaderSize(tc, readBufSize)
	h, body, err := readMessage(p.r, DefaultSegmentMRU)
	if err != nil {
		t.Fatalf("manual peer SESS_INIT read: %v", err)
	}
	if h != MsgSESS_INIT {
		t.Fatalf("manual peer want SESS_INIT, got %s (%x)", msgName(h), body)
	}
	return p
}

func certCerts(c *tls.Certificate) []tls.Certificate {
	if c == nil {
		return nil
	}
	return []tls.Certificate{*c}
}

// write sends one complete message.
func (p *manualPeer) write(hdr byte, body []byte) {
	p.t.Helper()
	if err := writeMessage(p.tlsC, hdr, body); err != nil {
		p.t.Fatalf("manual peer write %s: %v", msgName(hdr), err)
	}
}

// expectMessage reads messages until one of the wanted type arrives
// (skipping others), within the timeout.
func (p *manualPeer) expectMessage(want byte, timeout time.Duration) ([]byte, error) {
	deadline := time.Now().Add(timeout)
	_ = p.tlsC.SetReadDeadline(deadline)
	for {
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timeout waiting for %s", msgName(want))
		}
		h, body, err := readMessage(p.r, DefaultSegmentMRU)
		if err != nil {
			return nil, fmt.Errorf("read while waiting for %s: %w", msgName(want), err)
		}
		if h == want {
			return body, nil
		}
	}
}

// certFor builds a real node certificate for manual peers.
func certFor(t *testing.T) (*tls.Certificate, string) {
	t.Helper()
	kp, err := nodeid.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	eid, err := nodeid.EIDFromPub(kp.Public)
	if err != nil {
		t.Fatalf("eid: %v", err)
	}
	cert, err := nodeid.SelfSignedX509(kp, eid, time.Hour)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	return &cert, eid
}
