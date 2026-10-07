package link

// Session tests: the §6.2 replay window (accept/reject/counters), the
// persisted-checkpoint + unclean-restart scenario (sender resumes at
// last-persisted + 32, the receiver's window absorbs the gap), and the
// rekey trigger bounds.

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

// memStore is the in-memory StateStore (the RAM reference implementation).
type memStore struct {
	saved map[Direction]uint64
	saves int
}

func newMemStore() *memStore                         { return &memStore{saved: make(map[Direction]uint64)} }
func (m *memStore) Load(d Direction) (uint64, error) { return m.saved[d], nil }
func (m *memStore) Save(d Direction, seq uint64) error {
	m.saved[d] = seq
	m.saves++
	return nil
}

func TestSessionRoundtripAndReplay(t *testing.T) {
	a := testKeyPair(t, 0xA0)
	b := testKeyPair(t, 0xB0)
	keys := testPeerKeys(t, a, b)
	cfgI, cfgR := fullCfgs(a, b, keys, keys, mustEID(t, b), mustEID(t, a))
	_, _, _, ini, res := runHandshakeOK(t, cfgI, cfgR)
	si, sr := ini.Session(), res.Session()

	payload := []byte("replay-window test payload")
	for i := 0; i < 100; i++ {
		ct, err := si.Seal([]byte{byte(i)}, payload)
		if err != nil {
			t.Fatal(err)
		}
		pt, err := sr.Open([]byte{byte(i)}, ct)
		if err != nil {
			t.Fatalf("packet %d: %v", i, err)
		}
		if !bytes.Equal(pt, payload) {
			t.Fatalf("packet %d: mismatch", i)
		}
		// Replay of the just-accepted packet must be rejected.
		if _, err := sr.Open([]byte{byte(i)}, ct); !errors.Is(err, ErrReplay) {
			t.Fatalf("packet %d replay accepted", i)
		}
	}
	d := sr.DropCounters()
	if d.Replayed != 100 {
		t.Fatalf("Replayed = %d, want 100", d.Replayed)
	}

	// Out-of-order within the window must be accepted.
	ctNow, _ := si.Seal(nil, payload)
	ctNext, _ := si.Seal(nil, payload)
	if _, err := sr.Open(nil, ctNext); err != nil {
		t.Fatalf("in-window reorder rejected: %v", err)
	}
	if _, err := sr.Open(nil, ctNow); err != nil {
		t.Fatalf("in-window late packet rejected: %v", err)
	}

	// Too-far-ahead: jump far past the highest (flip the sequence's top
	// byte in the nonce).
	jump := append([]byte(nil), ctNext...)
	jump[NonceSaltLen] ^= 0xFF
	if _, err := sr.Open(nil, jump); !errors.Is(err, ErrReplay) {
		t.Fatalf("too-far-ahead accepted: %v", err)
	}
	if sr.DropCounters().TooFarAhead == 0 {
		t.Fatal("TooFarAhead not counted")
	}

	// A foreign session's salt must be rejected outright (wrong session).
	a2 := testKeyPair(t, 0xA1)
	b2 := testKeyPair(t, 0xB1)
	keys2 := testPeerKeys(t, a2, b2)
	cfgI2, cfgR2 := fullCfgs(a2, b2, keys2, keys2, mustEID(t, b2), mustEID(t, a2))
	_, _, _, ini2, _ := runHandshakeOK(t, cfgI2, cfgR2)
	other, _ := ini2.Session().Seal(nil, payload)
	if _, err := sr.Open(nil, other); !errors.Is(err, ErrReplay) {
		t.Fatalf("foreign-session frame accepted: %v", err)
	}
	if sr.DropCounters().RejectedSalt == 0 {
		t.Fatal("RejectedSalt not counted")
	}
}

func TestSessionTooOld(t *testing.T) {
	a := testKeyPair(t, 0xA0)
	b := testKeyPair(t, 0xB0)
	keys := testPeerKeys(t, a, b)
	cfgI, cfgR := fullCfgs(a, b, keys, keys, mustEID(t, b), mustEID(t, a))
	_, _, _, ini, res := runHandshakeOK(t, cfgI, cfgR)
	si, sr := ini.Session(), res.Session()

	// Advance the receiver's highest by 70 packets, then deliver packet 1
	// (kept from the start): it must fall below the window floor.
	old := make([][]byte, 0, 70)
	for i := 0; i < 70; i++ {
		ct, err := si.Seal(nil, []byte{byte(i)})
		if err != nil {
			t.Fatal(err)
		}
		old = append(old, ct)
	}
	for i, ct := range old {
		if _, err := sr.Open(nil, ct); err != nil {
			t.Fatalf("packet %d: %v", i, err)
		}
	}
	// old[0] is 70 below the highest (69): below the 64-wide floor.
	if _, err := sr.Open(nil, old[0]); !errors.Is(err, ErrReplay) {
		t.Fatal("below-floor packet accepted")
	}
	if sr.DropCounters().TooOld == 0 {
		t.Fatal("TooOld not counted")
	}
	// A packet held just inside the window's far edge is still acceptable:
	// seal it now, advance 63 (the window edge), then deliver it late.
	held, err := si.Seal(nil, []byte{0xEE})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 63; i++ {
		ct, err := si.Seal(nil, []byte{byte(i)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sr.Open(nil, ct); err != nil {
			t.Fatalf("advance packet %d: %v", i, err)
		}
	}
	if _, err := sr.Open(nil, held); err != nil {
		t.Fatalf("in-window late packet rejected: %v", err)
	}
	// But one MORE advance pushes it below the floor.
	ct, _ := si.Seal(nil, nil)
	if _, err := sr.Open(nil, ct); err != nil {
		t.Fatal(err)
	}
	if _, err := sr.Open(nil, held); !errors.Is(err, ErrReplay) {
		t.Fatal("below-floor late packet accepted")
	}
}

func TestSessionCheckpointAndRestart(t *testing.T) {
	// The exact §6.2 unclean-restart scenario: the sender checkpoints
	// every 32nd packet; it crashes after 40 un-persisted packets; the
	// fresh sender resumes at last-persisted (32) + 32 = 64; the
	// receiver's replay window absorbs the 24-packet gap; a replayed
	// pre-crash packet is still rejected.
	a := testKeyPair(t, 0xA0)
	b := testKeyPair(t, 0xB0)
	keys := testPeerKeys(t, a, b)
	cfgI, cfgR := fullCfgs(a, b, keys, keys, mustEID(t, b), mustEID(t, a))
	_, _, _, ini, res := runHandshakeOK(t, cfgI, cfgR)

	store := newMemStore()
	sendCrashed := NewSession(DirI2R, ini.Session().sendKey, ini.Session().recvKey,
		ini.Session().sendSalt, ini.Session().recvSalt, store, nil)
	recvLive := res.Session()

	// 40 packets: checkpoint fires exactly once, at packet 32 (seq 32).
	var lastCT []byte
	for i := 0; i < 40; i++ {
		ct, err := sendCrashed.Seal(nil, []byte{byte(i)})
		if err != nil {
			t.Fatal(err)
		}
		lastCT = ct
		if _, err := recvLive.Open(nil, ct); err != nil {
			t.Fatalf("packet %d: %v", i, err)
		}
	}
	if store.saved[DirI2R] != 32 {
		t.Fatalf("checkpoint = %d, want 32", store.saved[DirI2R])
	}
	if store.saves != 1 {
		t.Fatalf("saves = %d, want 1", store.saves)
	}

	// Unclean restart: the fresh sender loads the store and resumes at 32+32.
	sendFresh := NewSession(DirI2R, ini.Session().sendKey, ini.Session().recvKey,
		ini.Session().sendSalt, ini.Session().recvSalt, store, nil)
	if got, want := sendFresh.SendSeq(), uint64(64); got != want {
		t.Fatalf("restarted sender at seq %d, want %d", got, want)
	}
	ct64, err := sendFresh.Seal(nil, []byte{0x40})
	if err != nil {
		t.Fatal(err)
	}
	// The receiver saw up to 39; 64 is 25 ahead — inside the 64-wide window.
	if _, err := recvLive.Open(nil, ct64); err != nil {
		t.Fatalf("post-restart packet rejected (window did not absorb the gap): %v", err)
	}
	// And the pre-crash tail is still a replay.
	if _, err := recvLive.Open(nil, lastCT); !errors.Is(err, ErrReplay) {
		t.Fatal("pre-crash packet accepted after restart")
	}
}

func TestSessionNeedsRekey(t *testing.T) {
	a := testKeyPair(t, 0xA0)
	b := testKeyPair(t, 0xB0)
	keys := testPeerKeys(t, a, b)
	cfgI, cfgR := fullCfgs(a, b, keys, keys, mustEID(t, b), mustEID(t, a))
	_, _, _, ini, _ := runHandshakeOK(t, cfgI, cfgR)

	// Time bound: 24 h after establishment.
	now := time.Unix(1791072000, 0)
	clock := now
	sess := NewSession(DirI2R, ini.Session().sendKey, ini.Session().recvKey,
		ini.Session().sendSalt, ini.Session().recvSalt, nil, func() time.Time { return clock })
	if sess.NeedsRekey() {
		t.Fatal("rekey triggered before any bound")
	}
	clock = now.Add(RekeyInterval)
	if !sess.NeedsRekey() {
		t.Fatal("rekey not triggered at the 24 h bound")
	}

	// Packet bound: 2^20 packets.
	sess3 := NewSession(DirI2R, ini.Session().sendKey, ini.Session().recvKey,
		ini.Session().sendSalt, ini.Session().recvSalt, nil, func() time.Time { return now })
	for i := uint64(0); i < RekeyPackets; i++ {
		if _, err := sess3.Seal(nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	if !sess3.NeedsRekey() {
		t.Fatal("rekey not triggered at the 2^20 packet bound")
	}
}
