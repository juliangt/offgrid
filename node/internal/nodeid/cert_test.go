package nodeid

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

// TestSelfSignedX509Binding pins the §6.2 item-4 certificate model: the
// self-signed X.509 binds the Ed25519 node key, carries the EID as CN and as
// the URI SAN (the RFC 9174 §4.4.1 NODE-ID position), is X.509 v3 with
// digitalSignature key usage and both clientAuth/serverAuth EKUs, and
// re-derives exactly the same identity the LoRa plane uses.
func TestSelfSignedX509Binding(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	eid, err := EIDFromPub(kp.Public)
	if err != nil {
		t.Fatalf("EIDFromPub: %v", err)
	}
	cert, err := SelfSignedX509(kp, eid, time.Hour)
	if err != nil {
		t.Fatalf("SelfSignedX509: %v", err)
	}
	if len(cert.Certificate) != 1 {
		t.Fatalf("want a single (self-signed, no chain) certificate, got %d", len(cert.Certificate))
	}
	parsed := cert.Leaf
	if parsed == nil {
		parsed, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatalf("parse DER: %v", err)
		}
	}
	if parsed.Version != 3 {
		t.Fatalf("TCPCL requires v3 certificates (RFC 9174 §4.4.2), got v%d", parsed.Version)
	}
	if parsed.Subject.CommonName != eid {
		t.Fatalf("CN = %q, want the EID %q", parsed.Subject.CommonName, eid)
	}
	if len(parsed.URIs) != 1 || parsed.URIs[0].String() != eid {
		t.Fatalf("URI SANs = %v, want exactly [%s]", parsed.URIs, eid)
	}
	if parsed.SignatureAlgorithm != x509.PureEd25519 {
		t.Fatalf("signature algorithm = %v, want PureEd25519", parsed.SignatureAlgorithm)
	}
	if parsed.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Fatalf("key usage must include digitalSignature (RFC 9174 §4.4.2)")
	}
	if len(parsed.ExtKeyUsage) != 2 ||
		parsed.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth ||
		parsed.ExtKeyUsage[1] != x509.ExtKeyUsageServerAuth {
		t.Fatalf("EKU must be exactly [clientAuth serverAuth] (a TCPCL entity is either, §4.4.2), got %v", parsed.ExtKeyUsage)
	}
	if !parsed.NotAfter.After(time.Now()) || parsed.NotBefore.After(time.Now()) {
		t.Fatalf("validity window must contain now: %v .. %v", parsed.NotBefore, parsed.NotAfter)
	}

	// The identity helpers must re-derive the node key and the EID.
	pub, err := CertNodeKey(parsed)
	if err != nil {
		t.Fatalf("CertNodeKey: %v", err)
	}
	if string(pub) != string(ed25519.PublicKey(kp.Public)) {
		t.Fatalf("certified key differs from the node key")
	}
	if err := ValidateBinding(pub, eid); err != nil {
		t.Fatalf("§2.1 binding must hold through the certificate: %v", err)
	}
	if err := CertCoversEID(parsed, eid); err != nil {
		t.Fatalf("CertCoversEID: %v", err)
	}
	other, _ := EIDFromPub(func() []byte { k, _ := GenerateKeyPair(); return k.Public }())
	if err := CertCoversEID(parsed, other); err == nil {
		t.Fatalf("a certificate must not cover a foreign EID")
	}

	// PEM round-trip (the capsuletool cert ceremony writes exactly this).
	block := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}
	re := pem.EncodeToMemory(block)
	reparsed, err := x509.ParseCertificate(block.Bytes)
	_ = re
	if err != nil {
		t.Fatalf("reparse PEM-embedded DER: %v", err)
	}
	if reparsed.Subject.CommonName != eid {
		t.Fatalf("PEM round-trip lost the CN")
	}
	if CertFingerprintHex(cert.Certificate[0]) == "" || len(CertFingerprintHex(cert.Certificate[0])) != 64 {
		t.Fatalf("certificate fingerprint must be 64 hex chars")
	}
}

// TestSelfSignedX509DeterministicAndRejects pins the ceremony honesty: the
// same seed + same wall-clock second regenerate the identical DER
// (deterministic serial from the key fingerprint), a validity ≤ 0 falls back
// to the documented default, and a mismatched EID/key pair is refused.
func TestSelfSignedX509DeterministicAndRejects(t *testing.T) {
	seed := make([]byte, SeedLen)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	kp, err := NewKeyPairFromSeed(seed)
	if err != nil {
		t.Fatalf("NewKeyPairFromSeed: %v", err)
	}
	eid, _ := EIDFromPub(kp.Public)

	a, err := SelfSignedX509(kp, eid, 0)
	if err != nil {
		t.Fatalf("SelfSignedX509(default validity): %v", err)
	}
	b, err := SelfSignedX509(kp, eid, DefaultCertValidity)
	if err != nil {
		t.Fatalf("SelfSignedX509: %v", err)
	}
	if string(a.Certificate[0]) != string(b.Certificate[0]) {
		t.Fatalf("the same seed must regenerate the identical certificate")
	}
	if a.Leaf.NotAfter.Sub(a.Leaf.NotBefore) != DefaultCertValidity+time.Hour {
		t.Fatalf("zero validity must fall back to %v, got %v", DefaultCertValidity, a.Leaf.NotAfter.Sub(a.Leaf.NotBefore))
	}

	foreign, _ := GenerateKeyPair()
	if _, err := SelfSignedX509(foreign, eid, time.Hour); err == nil {
		t.Fatalf("a key/EID mismatch must be refused (the §2.1 binding gate)")
	}
}
