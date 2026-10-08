package tcpcl

// tls.go — the §4.4 session security for the Offgrid profile: TLS 1.3
// (RFC 8446, carried forward by RFC 9846) with the SAME node identity as
// the rest of the node plane (docs/node-network.md §6.2 item 4). Each side
// presents its self-signed Ed25519 node certificate; peer verification is
// the §6.1 TOFU pin over the LEAF CERTIFICATE'S PUBLIC KEY — which is the
// node key itself, so the pin store, the EIDs and the loud
// ErrPeerKeyChanged are shared verbatim with the LoRa plane. There is no
// CA on an island: crypto/tls's own chain verification is disabled
// (InsecureSkipVerify) and REPLACED by this pin check — nothing is trusted
// that the pin store has not seen.

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"offgrid/dtn-node/internal/nodeid"
)

// serverTLSConfig builds the §4.4.3 TLS-server side (the passive peer).
// auth receives the certified peer EID ("" when the client presented none
// — the MTLSOptional case, §7.12.1-shaped and counted).
func serverTLSConfig(cfg *Config, auth *peerAuth) *tls.Config {
	c := &tls.Config{
		Certificates: []tls.Certificate{cfg.Identity},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		// BCP 195 (RFC 7525, as §4.4.3 requires) is satisfied by TLS 1.3's
		// cipher suite policy; Go's defaults carry the rest.
		ClientAuth: tls.NoClientCert,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				if cfg.MTLS == MTLSRequired {
					// Unreachable via Go's own handshake state machine
					// (RequireAnyClientCert enforces presence), but the
					// policy stays explicit here: fail closed.
					return fmt.Errorf("tcpcl: mTLS required: client presented no certificate")
				}
				// Optional mode with no certificate: the §4.4.3 "Absent"
				// verdict. The session proceeds unauthenticated; the
				// counter makes that loud and honest (Go only calls this
				// callback when the client DID send a certificate, so this
				// branch is defense in depth).
				cfg.Counters.incUnauthenticatedPeers()
				return nil
			}
			eid, err := pinPeerCertificate(cfg, rawCerts[0])
			if err != nil {
				return err
			}
			auth.set(eid)
			return nil
		},
	}
	switch cfg.MTLS {
	case MTLSRequired:
		// §4.4.3: the active entity SHALL supply a certificate. Go demands
		// presence; the TOFU pin check above decides validity.
		c.ClientAuth = tls.RequireAnyClientCert
	case MTLSOptional:
		// The profile's defined relaxation: request, verify-if-present.
		c.ClientAuth = tls.RequestClientCert
	}
	return c
}

// clientTLSConfig builds the §4.4.3 TLS-client side (the active peer). The
// client ALWAYS presents its node certificate (§4.4.3 "Client
// Certificate: ... SHALL supply") and pins the server's.
func clientTLSConfig(cfg *Config, auth *peerAuth) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cfg.Identity},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		// The island has no web PKI: system chain verification is replaced
		// wholesale by the §6.1 pin check below (this is the one sanctioned
		// use of InsecureSkipVerify in the codebase — verification happens
		// in VerifyPeerCertificate, or not at all).
		InsecureSkipVerify: true, //nolint:gosec // replaced by the pin-verification callback
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				// §4.4.3: "The passive entity SHALL supply a certificate".
				return fmt.Errorf("tcpcl: server presented no certificate")
			}
			eid, err := pinPeerCertificate(cfg, rawCerts[0])
			if err != nil {
				return err
			}
			auth.set(eid)
			return nil
		},
	}
}

// pinPeerCertificate is the §6.1 gate, shared by both roles: the leaf must
// certify an Ed25519 node key whose self-derived EID it also carries (the
// RFC 9174 NODE-ID, §4.4.1), match any dial-time expectation, and pass the
// TOFU pin (first contact records; a change fails LOUDLY).
func pinPeerCertificate(cfg *Config, der []byte) (string, error) {
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		cfg.Counters.incPinRejections()
		return "", fmt.Errorf("tcpcl: peer leaf certificate: %w", err)
	}
	pub, err := nodeid.CertNodeKey(leaf)
	if err != nil {
		cfg.Counters.incPinRejections()
		return "", fmt.Errorf("tcpcl: %w", err)
	}
	eid, err := nodeid.EIDFromPub(pub)
	if err != nil {
		cfg.Counters.incPinRejections()
		return "", fmt.Errorf("tcpcl: %w", err)
	}
	if err := nodeid.CertCoversEID(leaf, eid); err != nil {
		cfg.Counters.incPinRejections()
		return "", fmt.Errorf("tcpcl: %w", err)
	}
	if cfg.ExpectedPeer != "" && eid != cfg.ExpectedPeer {
		cfg.Counters.incPinRejections()
		return "", fmt.Errorf("%w: dial target %s but the certificate certifies %s", ErrPeerIdentity, cfg.ExpectedPeer, eid)
	}
	if err := cfg.Pins.PinPeer(eid, pub); err != nil {
		cfg.Counters.incPinRejections()
		// nodeid.ErrPeerKeyChanged — the loud TOFU sentinel (§6.1). The
		// handshake dies here; the operator hears about it.
		return "", fmt.Errorf("tcpcl: pin check for %s: %w", eid, err)
	}
	return eid, nil
}
