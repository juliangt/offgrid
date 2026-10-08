package link

// Frame-layer tests: the frozen 1-byte header layout (version 2 | type 3 |
// flags 3), fail-closed parsing, session-protected frames (header as AAD),
// and the fixed beacon content.

import (
	"bytes"
	"testing"
)

func TestFrameHeaderLayout(t *testing.T) {
	cases := []struct {
		typ  FrameType
		want byte
	}{
		{TypeBeacon, 0x40},     // version 01 << 6
		{TypeSession, 0x48},    // 01 << 6 | 1 << 3
		{TypeMailWin, 0x50},    // 01 << 6 | 2 << 3
		{TypeBundleFrag, 0x58}, // 01 << 6 | 3 << 3
	}
	for _, c := range cases {
		got := EncodeHeader(c.typ, 0)
		if got != c.want {
			t.Fatalf("%s header = 0x%02x, want 0x%02x", c.typ, got, c.want)
		}
		typ, flags, err := ParseHeader(got)
		if err != nil || typ != c.typ || flags != 0 {
			t.Fatalf("ParseHeader(0x%02x) = %d/%d/%v", got, typ, flags, err)
		}
	}
}

func TestFrameFailClosed(t *testing.T) {
	if _, _, err := ParseHeader(0x80 | 0x40); err == nil { // version 2
		t.Fatal("version 2 accepted")
	}
	if _, _, err := ParseHeader(0x40 | 4<<3); err == nil { // type 4
		t.Fatal("unknown type accepted")
	}
	if _, _, err := ParseHeader(0x40 | 1); err == nil { // flags 1
		t.Fatal("nonzero flags accepted")
	}
	if _, _, err := ParseFrame(nil); err == nil {
		t.Fatal("empty frame accepted")
	}
	big := make([]byte, FramePayloadMax+1)
	if _, err := EncodeFrame(TypeBeacon, big); err == nil {
		t.Fatal("oversize beacon payload accepted")
	}
	if _, _, err := ParseFrame(append([]byte{0x40}, big...)); err == nil {
		t.Fatal("oversize payload accepted")
	}
	// Encrypted frames below nonce+tag are truncated.
	if _, _, err := ParseFrame(append([]byte{0x48}, make([]byte, 10)...)); err == nil {
		t.Fatal("truncated session frame accepted")
	}
}

func TestFrameSealOpen(t *testing.T) {
	a := testKeyPair(t, 0xA0)
	b := testKeyPair(t, 0xB0)
	keys := testPeerKeys(t, a, b)
	cfgI, cfgR := fullCfgs(a, b, keys, keys, mustEID(t, b), mustEID(t, a))
	_, _, _, ini, res := runHandshakeOK(t, cfgI, cfgR)

	payload := bytes.Repeat([]byte{0x5A}, 200)
	for _, typ := range []FrameType{TypeSession, TypeMailWin, TypeBundleFrag} {
		frame, err := SealFrame(ini.Session(), typ, payload)
		if err != nil {
			t.Fatalf("%s: %v", typ, err)
		}
		if len(frame) != 1+NonceLen+len(payload)+TagLen {
			t.Fatalf("%s: frame is %d B", typ, len(frame))
		}
		gotTyp, pt, err := OpenFrame(res.Session(), frame)
		if err != nil {
			t.Fatalf("%s: %v", typ, err)
		}
		if gotTyp != typ || !bytes.Equal(pt, payload) {
			t.Fatalf("%s: roundtrip mismatch (typ %d)", typ, gotTyp)
		}
		// Replay via the frame layer must fail.
		if _, _, err := OpenFrame(res.Session(), frame); err == nil {
			t.Fatalf("%s: replayed frame accepted", typ)
		}
		// Tampering with the header (the AAD) must fail the tag.
		bad := append([]byte(nil), frame...)
		bad[0] ^= 0x08
		if _, _, err := OpenFrame(res.Session(), bad); err == nil {
			t.Fatalf("%s: header tamper accepted", typ)
		}
	}

	// Beacons: plaintext, fixed content, parse without a session, and the
	// frame layer refuses to seal them.
	fp := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	beacon, err := EncodeFrame(TypeBeacon, BeaconPayload(fp))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SealFrame(ini.Session(), TypeBeacon, nil); err == nil {
		t.Fatal("sealing a beacon accepted")
	}
	typ, payload2, err := ParseFrame(beacon)
	if err != nil || typ != TypeBeacon {
		t.Fatalf("beacon parse: %d/%v", typ, err)
	}
	gotFP, err := ParseBeacon(payload2)
	if err != nil || gotFP != fp {
		t.Fatalf("beacon content: %v/%v", gotFP, err)
	}
	if _, _, err := OpenFrame(ini.Session(), beacon); err == nil {
		t.Fatal("OpenFrame on a beacon accepted")
	}
	// Beacon content is fail-closed: wrong version, wrong length.
	if _, err := ParseBeacon([]byte{0x02, 1, 2, 3, 4, 5, 6, 7, 8}); err == nil {
		t.Fatal("beacon version 2 accepted")
	}
	if _, err := ParseBeacon([]byte{0x01, 1, 2, 3}); err == nil {
		t.Fatal("short beacon accepted")
	}
}
