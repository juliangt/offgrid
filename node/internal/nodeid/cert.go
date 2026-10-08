package nodeid

import (
	"crypto/ed25519"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/url"
	"time"
)

// The TCPCL (RFC 9174) node certificate: a self-signed X.509 v3 certificate
// binding the node's Ed25519 key (docs/node-network.md §6.2 item 4 — the IP
// plane's TLS 1.3 uses the SAME node identity as the LoRa plane). The EID
// travels as the subject CN and as a URI subjectAltName (the RFC's §4.4.2
// identity lives in the SAN; the CN is informational for operators). The
// certificate is self-signed because there is no online CA on an island —
// peer trust is the §6.1 TOFU pin, which here pins the leaf certificate's
// public key (exactly the node key), loud on change (ErrPeerKeyChanged).

// DefaultCertValidity is the self-signed certificate lifetime used by the
// provisioning ceremony when no explicit validity is given. Node-key
// rotation (a new identity, §2.5) is the honest revocation path; the
// validity only bounds a stale certificate's usability in TLS.
const DefaultCertValidity = 90 * 24 * time.Hour

// SelfSignedX509 builds the node's TCPCL/TLS certificate: X.509 v3,
// PureEd25519 signature, CN = EID, URI SAN = EID, keyUsage digitalSignature,
// EKU clientAuth + serverAuth (RFC 9174 §4.4.2: both, "for
// interoperability", since a TCPCL entity is client or server depending on
// which side dialed). Deterministic in every field except the clock: the
// serial number is derived from the key fingerprint, so the same seed
// regenerates the identical certificate within the same second.
func SelfSignedX509(key KeyPair, eid string, validity time.Duration) (tls.Certificate, error) {
	if validity <= 0 {
		validity = DefaultCertValidity
	}
	if err := ValidateBinding(key.Public, eid); err != nil {
		return tls.Certificate{}, err
	}
	// Serial: positive, derived, collision-free per key (SHA-256(pub)[0:16]
	// with the sign bit cleared — RFC 5280 wants a positive INTEGER).
	sum := sha256.Sum256(key.Public)
	serial := new(big.Int).SetBytes(sum[:16])
	serial.SetBit(serial, 127, 0)
	if serial.Sign() == 0 {
		serial.SetInt64(1) // degenerate but legal
	}
	now := time.Now()
	// The RFC 9174 NODE-ID: a subjectAltName URI whose value is the node
	// ID (§4.4.1). crypto/x509 has no BundleEID otherName form; the URI
	// SAN carries the EID verbatim and the verifier (CertNodeKey +
	// CertCoversEID) re-derives it from the key — the SAN check is then
	// exact-match. x509 marshals the SAN via url.URL.String.
	sanURI, err := url.Parse(eid)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("nodeid: EID %q is not a URI: %w", eid, err)
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   eid,
			Organization: []string{"offgrid node"},
		},
		NotBefore: now.Add(-time.Hour), // tolerate modest clock skew
		NotAfter:  now.Add(validity),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		DNSNames:              nil,
		URIs:                  []*url.URL{sanURI},
		SubjectKeyId:          subjectKeyId(key.Public),
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.PureEd25519,
	}
	der, err := x509.CreateCertificate(nil, tpl, tpl, key.Public, key.Private)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("nodeid: create certificate: %w", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("nodeid: parse own certificate: %w", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key.Private,
		Leaf:        parsed,
	}, nil
}

// subjectKeyId is RFC 5280's method 1 (SHA-1 of the public key) — the
// conventional SKI a TCPCL peer MAY use for chain assembly (§4.4.2: entities
// SHOULD NOT rely on it being present).
func subjectKeyId(pub []byte) []byte {
	s := sha1.Sum(pub) //nolint:gosec // RFC 5280 method 1 pins SHA-1 for SKI only
	return s[:]
}

// CertNodeKey extracts the Ed25519 node key a TCPCL certificate certifies.
// Anything but a 32-byte Ed25519 public key fails (the node plane has no
// other certificate kind).
func CertNodeKey(cert *x509.Certificate) ([]byte, error) {
	if cert == nil {
		return nil, fmt.Errorf("nodeid: nil certificate")
	}
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok || len(pub) != KeyLen {
		return nil, fmt.Errorf("nodeid: certificate public key is %T, want a 32-byte Ed25519 key", cert.PublicKey)
	}
	return pub, nil
}

// CertCoversEID is the §4.4.1 NODE-ID match, adapted to this profile: the
// certificate's URI SANs MUST contain exactly the EID the key derives. With
// the §2.1 binding already re-derived from the key, this closes the loop —
// the certificate authenticates the EID only when key, SAN and derivation
// agree. (The CN is not security-relevant; operators read it.)
func CertCoversEID(cert *x509.Certificate, eid string) error {
	for _, u := range cert.URIs {
		if u.Scheme != "dtn" {
			continue
		}
		if u.String() == eid {
			return nil
		}
	}
	return fmt.Errorf("nodeid: certificate SANs do not certify %s (found %d dtn URIs)", eid, countDTNURIs(cert))
}

func countDTNURIs(cert *x509.Certificate) int {
	n := 0
	for _, u := range cert.URIs {
		if u.Scheme == "dtn" {
			n++
		}
	}
	return n
}

// CertFingerprintHex is the operator-facing digest of a certificate (full
// SHA-256 over the DER, hex) — distinct from the node fingerprint, which is
// the first 8 bytes over the raw public key. Logs and the cert ceremony
// print this one; the PinStore pins the node fingerprint.
func CertFingerprintHex(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}
