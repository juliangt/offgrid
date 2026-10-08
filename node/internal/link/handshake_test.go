package link

// Handshake tests: the §6.1 happy path (both roles), the measured message
// sizes (38/134/91 — consistent with bundle/spike.go's HandshakeSizes),
// RFC 7748 §6.1 X25519, and the fail-closed set: bad signatures, transcript
// tampering, unknown peers, malformed ciphertexts, and the loud TOFU
// sentinel (nodeid.ErrPeerKeyChanged).

import (
	"bytes"
	"crypto/ecdh"
	"errors"
	"testing"

	"offgrid/dtn-node/internal/bundle"
	"offgrid/dtn-node/internal/nodeid"
)

// Deterministic test identities and X25519 scalars (byte patterns; the
// shared vectors carry the same shapes so Go and C produce identical
// transcripts).
func patternSeed(prefix byte) []byte {
	s := make([]byte, nodeid.SeedLen)
	for i := range s {
		s[i] = prefix + byte(i)
	}
	return s
}

func testKeyPair(t *testing.T, prefix byte) nodeid.KeyPair {
	t.Helper()
	kp, err := nodeid.NewKeyPairFromSeed(patternSeed(prefix))
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

// scalarX returns the fixed X25519 scalar generator for role x
// (0x11 = initiator, 0x22 = responder in these tests).
func scalarX(prefix byte) func() ([]byte, error) {
	return func() ([]byte, error) {
		s := make([]byte, 32)
		for i := range s {
			s[i] = prefix + byte(i)
		}
		return s, nil
	}
}

func mustEID(t *testing.T, kp nodeid.KeyPair) string {
	t.Helper()
	eid, err := nodeid.EIDFromPub(kp.Public)
	if err != nil {
		t.Fatal(err)
	}
	return eid
}

func testPeerKeys(t *testing.T, peers ...nodeid.KeyPair) *PeerKeys {
	t.Helper()
	pins := nodeid.NewPinStore()
	keys := NewPeerKeys(pins)
	for _, p := range peers {
		eid, err := nodeid.EIDFromPub(p.Public)
		if err != nil {
			t.Fatal(err)
		}
		if err := pins.PinPeer(eid, p.Public); err != nil {
			t.Fatal(err)
		}
		if err := keys.AddCert(p.Public); err != nil {
			t.Fatal(err)
		}
	}
	return keys
}

func fullCfgs(a, b nodeid.KeyPair, keysI, keysR *PeerKeys, expectI, expectR string) (Config, Config) {
	return Config{Local: a, Keys: keysI, ExpectedPeer: expectI, EphemeralScalar: scalarX(0x11)},
		Config{Local: b, Keys: keysR, ExpectedPeer: expectR, EphemeralScalar: scalarX(0x22)}
}

// runHandshakeOK drives a full exchange expecting success at every step.
func runHandshakeOK(t *testing.T, cfgI, cfgR Config) (msg1, msg2, msg3 []byte, ini *Initiator, res *Responder) {
	t.Helper()
	var err error
	if ini, msg1, err = NewInitiator(cfgI); err != nil {
		t.Fatalf("NewInitiator: %v", err)
	}
	if res, err = NewResponder(cfgR); err != nil {
		t.Fatal(err)
	}
	if err := res.Read1(msg1); err != nil {
		t.Fatalf("Read1: %v", err)
	}
	if msg2, err = res.Write2(); err != nil {
		t.Fatalf("Write2: %v", err)
	}
	if err := ini.Read2(msg2); err != nil {
		t.Fatalf("Read2: %v", err)
	}
	if msg3, err = ini.Write3(); err != nil {
		t.Fatalf("Write3: %v", err)
	}
	if err := res.Read3(msg3); err != nil {
		t.Fatalf("Read3: %v", err)
	}
	return msg1, msg2, msg3, ini, res
}

// runHandshakeFail drives the exchange expecting exactly ONE step to fail
// (the caller names it) and asserts no session survives.
func runHandshakeFail(t *testing.T, cfgI, cfgR Config, failingStep string) (ini *Initiator, res *Responder) {
	t.Helper()
	ini, msg1, err := NewInitiator(cfgI)
	if err != nil {
		t.Fatalf("NewInitiator: %v", err)
	}
	res, err = NewResponder(cfgR)
	if err != nil {
		t.Fatal(err)
	}
	if err := res.Read1(msg1); err != nil {
		if failingStep == "Read1" {
			return ini, res
		}
		t.Fatalf("failed early at Read1: %v", err)
	}
	msg2, err := res.Write2()
	if err != nil {
		if failingStep == "Write2" {
			return ini, res
		}
		t.Fatalf("failed early at Write2: %v", err)
	}
	if err := ini.Read2(msg2); err != nil {
		if failingStep == "Read2" {
			return ini, res
		}
		t.Fatalf("failed early at Read2: %v", err)
	}
	msg3, err := ini.Write3()
	if err != nil {
		if failingStep == "Write3" {
			return ini, res
		}
		t.Fatalf("failed early at Write3: %v", err)
	}
	if err := res.Read3(msg3); err != nil {
		if failingStep == "Read3" {
			return ini, res
		}
		t.Fatalf("failed at Read3: %v", err)
	}
	t.Fatalf("handshake unexpectedly succeeded (expected failure at %s)", failingStep)
	return nil, nil
}

func TestHandshakeHappyPath(t *testing.T) {
	a := testKeyPair(t, 0xA0)
	b := testKeyPair(t, 0xB0)
	cfgI, cfgR := fullCfgs(a, b, testPeerKeys(t, a, b), testPeerKeys(t, a, b), mustEID(t, b), mustEID(t, a))
	msg1, msg2, msg3, ini, res := runHandshakeOK(t, cfgI, cfgR)

	if got, want := len(msg1), 38; got != want {
		t.Fatalf("msg1 = %d B, want %d", got, want)
	}
	if got, want := len(msg2), 134; got != want {
		t.Fatalf("msg2 = %d B, want %d", got, want)
	}
	if got, want := len(msg3), 91; got != want {
		t.Fatalf("msg3 = %d B, want %d", got, want)
	}
	// The P3.0 spike sizer must agree with the real implementation.
	sz := bundle.HandshakeSizes()
	if sz.M1 != len(msg1) || sz.M2 != len(msg2) || sz.M3 != len(msg3) {
		t.Fatalf("spike sizes %+v disagree with the real messages %d/%d/%d", sz, len(msg1), len(msg2), len(msg3))
	}
	if ini.Session() == nil || res.Session() == nil {
		t.Fatal("handshake completed without sessions")
	}
	if ini.PeerEID() != mustEID(t, b) || res.PeerEID() != mustEID(t, a) {
		t.Fatalf("authenticated EIDs wrong: %s / %s", ini.PeerEID(), res.PeerEID())
	}

	// The two sessions interop: both directions, byte-exact roundtrip.
	payload := []byte("bundle bytes cross the link")
	for _, step := range []struct{ sender, receiver *Session }{{ini.Session(), res.Session()}, {res.Session(), ini.Session()}} {
		ct, err := step.sender.Seal([]byte{1}, payload)
		if err != nil {
			t.Fatal(err)
		}
		pt, err := step.receiver.Open([]byte{1}, ct)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(pt, payload) {
			t.Fatal("session roundtrip mismatch")
		}
		if _, err := step.receiver.Open([]byte{1}, ct); !errors.Is(err, ErrReplay) {
			t.Fatalf("replay accepted: %v", err)
		}
	}
}

func TestX25519RFC7748(t *testing.T) {
	// RFC 7748 §6.1 vectors (fetched from the RFC text, 2026-10-07).
	alicePriv := mustHex(t, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	alicePubWant := mustHex(t, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
	bobPriv := mustHex(t, "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
	bobPubWant := mustHex(t, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
	sharedWant := mustHex(t, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

	alice, err := ecdh.X25519().NewPrivateKey(alicePriv)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(alice.PublicKey().Bytes(), alicePubWant) {
		t.Fatalf("alice pub:\n got %X\nwant %X", alice.PublicKey().Bytes(), alicePubWant)
	}
	bob, err := ecdh.X25519().NewPrivateKey(bobPriv)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bob.PublicKey().Bytes(), bobPubWant) {
		t.Fatalf("bob pub:\n got %X\nwant %X", bob.PublicKey().Bytes(), bobPubWant)
	}
	shared, err := x25519Shared(alice, bob.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(shared, sharedWant) {
		t.Fatalf("shared:\n got %X\nwant %X", shared, sharedWant)
	}
}

func TestHandshakeFailClosed(t *testing.T) {
	a := testKeyPair(t, 0xA0)
	b := testKeyPair(t, 0xB0)
	rogue := testKeyPair(t, 0xC0)
	keys := func() (*PeerKeys, *PeerKeys) { return testPeerKeys(t, a, b), testPeerKeys(t, a, b) }

	t.Run("responder_signs_with_unresolvable_key", func(t *testing.T) {
		keysI, keysR := keys()
		cfgI, cfgR := fullCfgs(a, b, keysI, keysR, "", "")
		cfgR.Local = rogue // its fingerprint resolves to nothing on the initiator
		ini, _ := runHandshakeFail(t, cfgI, cfgR, "Read2")
		if ini.Session() != nil {
			t.Fatal("session survived a failed handshake")
		}
	})

	t.Run("initiator_signs_with_unresolvable_key", func(t *testing.T) {
		keysI, keysR := keys()
		cfgI, cfgR := fullCfgs(a, b, keysI, keysR, "", "")
		cfgI.Local = rogue
		_, res := runHandshakeFail(t, cfgI, cfgR, "Read3")
		if res.Session() != nil {
			t.Fatal("session survived a failed handshake")
		}
	})

	t.Run("msg1_tamper_breaks_ct2", func(t *testing.T) {
		keysI, keysR := keys()
		cfgI, cfgR := fullCfgs(a, b, keysI, keysR, "", "")
		ini, msg1, err := NewInitiator(cfgI)
		if err != nil {
			t.Fatal(err)
		}
		tampered := append([]byte(nil), msg1...)
		tampered[10] ^= 0x01 // a flipped bit inside g_x in flight
		res, err := NewResponder(cfgR)
		if err != nil {
			t.Fatal(err)
		}
		if err := res.Read1(tampered); err != nil {
			t.Fatalf("tampered msg1 still parses: %v", err)
		}
		msg2, err := res.Write2()
		if err != nil {
			t.Fatal(err)
		}
		// The initiator's th1/DH are over ITS msg1; the responder answered
		// the tampered one: ct2 must not open.
		if err := ini.Read2(msg2); err == nil {
			t.Fatal("handshake survived a tampered msg1")
		}
		if ini.Session() != nil {
			t.Fatal("session survived a tampered msg1")
		}
	})

	t.Run("ct2_tamper", func(t *testing.T) {
		keysI, keysR := keys()
		cfgI, cfgR := fullCfgs(a, b, keysI, keysR, "", "")
		_, msg2, _, ini, _ := runHandshakeOK(t, cfgI, cfgR)
		ini2, _, err := NewInitiator(cfgI) // fresh initiator, same inputs
		if err != nil {
			t.Fatal(err)
		}
		if err := ini2.Read2(msg2); err != nil {
			t.Fatalf("deterministic replay of msg2 must verify: %v", err)
		}
		bad := append([]byte(nil), msg2...)
		bad[len(bad)-1] ^= 0x01
		ini3, _, err := NewInitiator(cfgI)
		if err != nil {
			t.Fatal(err)
		}
		if err := ini3.Read2(bad); err == nil {
			t.Fatal("tampered ct2 accepted")
		}
		// ini completed its full exchange; ini2 verified msg2 but has not
		// run Write3 (no session yet by design); ini3's tampered ct2
		// killed its handshake.
		if ini.Session() == nil || ini2.Session() != nil || ini3.Session() != nil {
			t.Fatal("inconsistent session states after ct2 tamper set")
		}
	})

	t.Run("unknown_peer_fails_closed", func(t *testing.T) {
		// The initiator's store knows ONLY itself: the responder's
		// fingerprint resolves to nothing.
		cfgI, cfgR := fullCfgs(a, b, testPeerKeys(t, a), testPeerKeys(t, a, b), "", "")
		ini, res := runHandshakeFail(t, cfgI, cfgR, "Read2")
		if ini.Session() != nil || res.Session() != nil {
			t.Fatal("session survived an unknown peer")
		}
		// And the mirror: the responder does not know the initiator. The
		// initiator legitimately holds a session (it authenticated the
		// responder and cannot see the responder's msg3 rejection) — the
		// fail-closed property under test is that the RESPONDER (the node
		// that could not authenticate) has NO session.
		cfgI2, cfgR2 := fullCfgs(a, b, testPeerKeys(t, a, b), testPeerKeys(t, b), "", "")
		_, res2 := runHandshakeFail(t, cfgI2, cfgR2, "Read3")
		if res2.Session() != nil {
			t.Fatal("session survived an unknown initiator")
		}
	})

	t.Run("expected_peer_change_fails_loudly", func(t *testing.T) {
		// The pinned peer rotated its key with no higher-seq certificate:
		// the exchange is cryptographically valid, but the ExpectedPeer
		// gate fails the session LOUDLY with nodeid.ErrPeerKeyChanged.
		cfgI, cfgR := fullCfgs(a, b, testPeerKeys(t, a, b), testPeerKeys(t, a, b), mustEID(t, rogue), "")
		ini, msg1, err := NewInitiator(cfgI)
		if err != nil {
			t.Fatal(err)
		}
		res, err := NewResponder(cfgR)
		if err != nil {
			t.Fatal(err)
		}
		if err := res.Read1(msg1); err != nil {
			t.Fatal(err)
		}
		msg2, err := res.Write2()
		if err != nil {
			t.Fatal(err)
		}
		err = ini.Read2(msg2)
		if err == nil {
			t.Fatal("ExpectedPeer mismatch accepted")
		}
		if !errors.Is(err, nodeid.ErrPeerKeyChanged) {
			t.Fatalf("ExpectedPeer mismatch must wrap nodeid.ErrPeerKeyChanged, got: %v", err)
		}
		if ini.Session() != nil {
			t.Fatal("session survived the TOFU gate")
		}
	})

	t.Run("truncated_and_oversized_messages", func(t *testing.T) {
		keysI, keysR := keys()
		cfgI, cfgR := fullCfgs(a, b, keysI, keysR, "", "")
		ini, msg1, err := NewInitiator(cfgI)
		if err != nil {
			t.Fatal(err)
		}
		res, err := NewResponder(cfgR)
		if err != nil {
			t.Fatal(err)
		}
		if err := res.Read1(msg1[:20]); err == nil {
			t.Fatal("truncated msg1 accepted")
		}
		if err := res.Read1(append(msg1, 0x00)); err == nil {
			t.Fatal("trailing-byte msg1 accepted")
		}
		// Fail-closed: any malformed input kills THIS responder state
		// machine; a clean handshake needs a fresh one.
		res2, err := NewResponder(cfgR)
		if err != nil {
			t.Fatal(err)
		}
		if err := res2.Read1(msg1); err != nil {
			t.Fatalf("clean responder must accept a clean msg1: %v", err)
		}
		msg2, err := res2.Write2()
		if err != nil {
			t.Fatal(err)
		}
		if err := ini.Read2(msg2[:50]); err == nil {
			t.Fatal("truncated msg2 accepted")
		}
	})

	t.Run("wrong_state_transitions", func(t *testing.T) {
		keysI, keysR := keys()
		cfgI, cfgR := fullCfgs(a, b, keysI, keysR, "", "")
		ini, _, err := NewInitiator(cfgI)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ini.Write3(); err == nil {
			t.Fatal("Write3 before Read2 accepted")
		}
		res, err := NewResponder(cfgR)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := res.Write2(); err == nil {
			t.Fatal("Write2 before Read1 accepted")
		}
	})
}
