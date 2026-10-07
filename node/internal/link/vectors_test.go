package link

// Shared conformance vectors for P3.3 (tests/vectors/link/vectors.json) —
// the single source of truth executed by BOTH the Go suite (this file) and
// the C host suite (esp32/components/dtn_core/host/tests/test_link.c via
// the generated header host/tests/link_vectors.h). This is the P3.1/P3.2
// pattern (tests/vectors/nodeid, tests/vectors/bundle): one committed JSON
// + one generated C header, both rewritten by this test's -regen flag and
// never allowed to drift. The C side must reproduce byte-identical
// handshake messages, ciphertexts and frames, and identical
// accept/reject verdicts — the cross-implementation gate for the link
// layer.
//
// Provenance: the crypto anchors are the official suites (RFC 3610, RFC
// 5869, RFC 7748 §6.1, RFC 8032 §7.1), pinned directly in both suites'
// test files; the vectors here pin the PROFILE — the §6.1 handshake with
// fixed ephemerals/seeds, the §6.2 session/replay discipline, the §5.4
// frame layout and the window reassembler — derived from this package's
// own frozen construction. Deterministic; committed copies MUST NOT be
// hand-edited.

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"offgrid/dtn-node/internal/nodeid"
)

const linkRegenCmd = "cd node && go test ./internal/link -run TestLinkVectorsStable -regen"

// Fixed vector material (the same deterministic shapes the unit tests use).
func vecSeed(prefix byte) []byte {
	s := make([]byte, nodeid.SeedLen)
	for i := range s {
		s[i] = prefix + byte(i)
	}
	return s
}

func vecScalar(prefix byte) []byte {
	s := make([]byte, 32)
	for i := range s {
		s[i] = prefix + byte(i)
	}
	return s
}

// JSON schema (field order = marshal order = deterministic bytes).
type (
	vecHandshakeExpect struct {
		EIDA              string `json:"eid_a"`
		EIDB              string `json:"eid_b"`
		Msg1Hex           string `json:"msg1_hex"`
		Msg2Hex           string `json:"msg2_hex"`
		Msg3Hex           string `json:"msg3_hex"`
		Th1Hex            string `json:"th1_hex"`
		TranscriptHashHex string `json:"transcript_hash_hex"`
		MasterHex         string `json:"master_hex"`
		KI2RHex           string `json:"k_i2r_hex"`
		SI2RHex           string `json:"s_i2r_hex"`
		KR2IHex           string `json:"k_r2i_hex"`
		SR2IHex           string `json:"s_r2i_hex"`
		LenMsg1           int    `json:"len_msg1"`
		LenMsg2           int    `json:"len_msg2"`
		LenMsg3           int    `json:"len_msg3"`
	}
	vecHandshake struct {
		Name       string             `json:"name"`
		SeedAHex   string             `json:"seed_a_hex"`
		SeedBHex   string             `json:"seed_b_hex"`
		ScalarIHex string             `json:"scalar_i_hex"`
		ScalarRHex string             `json:"scalar_r_hex"`
		Expect     vecHandshakeExpect `json:"expect"`
	}
	vecCCM struct {
		Name         string `json:"name"`
		KeyHex       string `json:"key_hex"`
		NonceHex     string `json:"nonce_hex"`
		AADHex       string `json:"aad_hex"`
		PlaintextHex string `json:"plaintext_hex"`
		SealedHex    string `json:"sealed_hex"` // ciphertext ‖ tag (CCM level)
	}
	vecFrameEncode struct {
		Name       string `json:"name"`
		Type       int    `json:"type"`
		PayloadHex string `json:"payload_hex"`
		FrameHex   string `json:"frame_hex"`
	}
	vecFrameReject struct {
		Name     string `json:"name"`
		FrameHex string `json:"frame_hex"`
		Code     string `json:"code"` // truncated | version | type | flags | oversize
	}
	vecWindowPush struct {
		PayloadHex string `json:"payload_hex"`
		Verdict    string `json:"verdict"` // partial | done | dup | invalid
	}
	vecWindow struct {
		Name        string          `json:"name"`
		TimeoutS    float64         `json:"timeout_s"`
		Pushes      []vecWindowPush `json:"pushes"`
		Completions []string        `json:"completions_hex"`
	}
	vecReplay struct {
		Name    string        `json:"name"`
		KeyHex  string        `json:"key_hex"`
		SaltHex string        `json:"salt_hex"`
		Ops     []vecReplayOp `json:"ops"`
	}
	vecReplayOp struct {
		Seq     uint64 `json:"seq"`
		Verdict string `json:"verdict"` // accept | replayed | too_old | too_far
	}
	vectorSet struct {
		Provenance   string           `json:"provenance"`
		RegenCommand string           `json:"regen_command"`
		Handshake    []vecHandshake   `json:"handshake"`
		CCM          []vecCCM         `json:"ccm"`
		FrameEncode  []vecFrameEncode `json:"frame_encode"`
		FrameReject  []vecFrameReject `json:"frame_reject"`
		Window       []vecWindow      `json:"window"`
		Replay       []vecReplay      `json:"replay"`
	}
)

// Paths resolve from THIS file's location, never the process CWD.
func linkVecRoot() string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(thisFile))))
}

func linkJSONPath() string {
	return filepath.Join(linkVecRoot(), "tests", "vectors", "link", "vectors.json")
}

func linkHeaderPath() string {
	return filepath.Join(linkVecRoot(), "esp32", "components", "dtn_core", "host", "tests", "link_vectors.h")
}

var regenLinkVectors = flag.Bool("regen", false, "regenerate tests/vectors/link/vectors.json and the C host header")

func hx(b []byte) string { return hex.EncodeToString(b) }

func keysFor(t *testing.T, a, b nodeid.KeyPair) *PeerKeys {
	t.Helper()
	keys := NewPeerKeys(nodeid.NewPinStore())
	for _, kp := range []nodeid.KeyPair{a, b} {
		if err := keys.AddCert(kp.Public); err != nil {
			t.Fatal(err)
		}
	}
	return keys
}

func fixedScalar(prefix byte) func() ([]byte, error) {
	return func() ([]byte, error) { return vecScalar(prefix), nil }
}

// dhOf re-derives the shared secret of a completed initiator (the
// handshake zeroes its copy; the fixed ephemeral source makes the
// recomputation exact).
func dhOf(t *testing.T, ini *Initiator) []byte {
	t.Helper()
	scalar, err := ini.cfg.EphemeralScalar()
	if err != nil {
		t.Fatal(err)
	}
	priv, err := ecdh.X25519().NewPrivateKey(scalar)
	if err != nil {
		t.Fatal(err)
	}
	dh, err := x25519Shared(priv, ini.gy)
	if err != nil {
		t.Fatal(err)
	}
	return dh
}

// runVectorHandshake drives one deterministic exchange end to end.
func runVectorHandshake(t *testing.T, cfgI, cfgR Config) (msg1, msg2, msg3 []byte, ini *Initiator, res *Responder) {
	t.Helper()
	var err error
	if ini, msg1, err = NewInitiator(cfgI); err != nil {
		t.Fatal(err)
	}
	if res, err = NewResponder(cfgR); err != nil {
		t.Fatal(err)
	}
	if err := res.Read1(msg1); err != nil {
		t.Fatal(err)
	}
	if msg2, err = res.Write2(); err != nil {
		t.Fatal(err)
	}
	if err := ini.Read2(msg2); err != nil {
		t.Fatal(err)
	}
	if msg3, err = ini.Write3(); err != nil {
		t.Fatal(err)
	}
	if err := res.Read3(msg3); err != nil {
		t.Fatal(err)
	}
	return msg1, msg2, msg3, ini, res
}

// buildLinkVectorSet deterministically derives every vector.
func buildLinkVectorSet(t *testing.T) *vectorSet {
	t.Helper()

	// -- handshake: two fixed-identity pairs with fixed X25519 scalars.
	var hs []vecHandshake
	pairs := []struct {
		name             string
		seedA, seedB     byte
		scalarI, scalarR byte
	}{
		{"pair_ab", 0xA0, 0xB0, 0x11, 0x22},
		{"pair_cd", 0xC0, 0xD0, 0x33, 0x44},
	}
	for _, p := range pairs {
		kpA, err := nodeid.NewKeyPairFromSeed(vecSeed(p.seedA))
		if err != nil {
			t.Fatal(err)
		}
		kpB, err := nodeid.NewKeyPairFromSeed(vecSeed(p.seedB))
		if err != nil {
			t.Fatal(err)
		}
		keys := keysFor(t, kpA, kpB)
		cfgI := Config{Local: kpA, Keys: keys, EphemeralScalar: fixedScalar(p.scalarI)}
		cfgR := Config{Local: kpB, Keys: keys, EphemeralScalar: fixedScalar(p.scalarR)}
		msg1, msg2, msg3, ini, res := runVectorHandshake(t, cfgI, cfgR)

		dh := dhOf(t, ini)
		th1 := th1Of(msg1)
		transcript := append(append(append([]byte{}, msg1...), msg2...), msg3...)
		trHash := sha256.Sum256(transcript)
		kI2R, kR2I, sI2R, sR2I, err := sessionKeys(dh, transcript)
		if err != nil {
			t.Fatal(err)
		}
		prk := HkdfExtract(trHash[:], dh)
		master, err := HkdfExpand(prk, []byte(InfoPrefix), 32)
		if err != nil {
			t.Fatal(err)
		}
		eidA, err := nodeid.EIDFromPub(kpA.Public)
		if err != nil {
			t.Fatal(err)
		}
		eidB, err := nodeid.EIDFromPub(kpB.Public)
		if err != nil {
			t.Fatal(err)
		}
		_ = res
		hs = append(hs, vecHandshake{
			Name: p.name, SeedAHex: hx(vecSeed(p.seedA)), SeedBHex: hx(vecSeed(p.seedB)),
			ScalarIHex: hx(vecScalar(p.scalarI)), ScalarRHex: hx(vecScalar(p.scalarR)),
			Expect: vecHandshakeExpect{
				EIDA: eidA, EIDB: eidB,
				Msg1Hex: hx(msg1), Msg2Hex: hx(msg2), Msg3Hex: hx(msg3),
				Th1Hex: hx(th1[:]), TranscriptHashHex: hx(trHash[:]),
				MasterHex: hx(master),
				KI2RHex:   hx(kI2R[:]), SI2RHex: hx(sI2R[:]), KR2IHex: hx(kR2I[:]), SR2IHex: hx(sR2I[:]),
				LenMsg1: len(msg1), LenMsg2: len(msg2), LenMsg3: len(msg3),
			},
		})
	}

	// -- ccm: the §6.2 profile (16 B tag; nonce = salt ‖ BE8 seq), across
	// the AES block boundary and at the real frame sizes.
	var ccm []vecCCM
	ccmCase := func(name string, key [KeyLen]byte, nonce [NonceLen]byte, aad, pt []byte) {
		sealed, err := sealCCM(key[:], nonce[:], aad, pt, TagLen)
		if err != nil {
			t.Fatal(err)
		}
		ccm = append(ccm, vecCCM{
			Name: name, KeyHex: hx(key[:]), NonceHex: hx(nonce[:]),
			AADHex: hx(aad), PlaintextHex: hx(pt), SealedHex: hx(sealed),
		})
	}
	var key1 [KeyLen]byte
	for i := range key1 {
		key1[i] = byte(i + 1)
	}
	var key2 [KeyLen]byte
	for i := range key2 {
		key2[i] = byte(0xF0 ^ i)
	}
	salt := [NonceSaltLen]byte{0x31, 0x41, 0x59, 0x26, 0x53}
	salt2 := [NonceSaltLen]byte{0x0f, 0x1e, 0x2d, 0x3c, 0x4b}
	ccmCase("profile_empty", key1, Nonce(salt, 0), nil, nil)
	ccmCase("profile_1b", key1, Nonce(salt, 1), []byte{0x58}, []byte{0xFF})
	ccmCase("profile_block", key1, Nonce(salt, 2), []byte{0x58}, bytes.Repeat([]byte{0xA5}, 16))
	ccmCase("profile_block_plus_1", key1, Nonce(salt, 3), nil, bytes.Repeat([]byte{0x5A}, 17))
	ccmCase("profile_window_frame", key2, Nonce(salt2, 42), []byte{EncodeHeader(TypeBundleFrag, 0)}, bytes.Repeat([]byte{0xC3}, 222))
	ccmCase("profile_msg2_shape", key2, Nonce(hsSalt, 2), bytes.Repeat([]byte{0x83}, 36), bytes.Repeat([]byte{0x77}, 96))

	// -- frame encode: one case per type + the beacon.
	var fe []vecFrameEncode
	frameCase := func(name string, typ FrameType, payload []byte) {
		f, err := EncodeFrame(typ, payload)
		if err != nil {
			t.Fatal(err)
		}
		fe = append(fe, vecFrameEncode{Name: name, Type: int(typ), PayloadHex: hx(payload), FrameHex: hx(f)})
	}
	frameCase("beacon", TypeBeacon, BeaconPayload([8]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}))
	// The minimum legal wire payload for a session type (nonce ‖ tag;
	// shorter encrypted frames are truncation by definition).
	frameCase("session_min_wire", TypeSession, bytes.Repeat([]byte{0x00}, NonceLen+TagLen))
	frameCase("mailwin_max", TypeMailWin, bytes.Repeat([]byte{0x02}, FramePayloadMax))
	frameCase("bundlefrag_window", TypeBundleFrag, append([]byte{WindowHeader(5, 1, 3)}, bytes.Repeat([]byte{0x03}, 100)...))

	// -- frame reject: every malformed class with a stable code.
	var fr []vecFrameReject
	reject := func(name, code string, frame []byte) {
		fr = append(fr, vecFrameReject{Name: name, FrameHex: hx(frame), Code: code})
	}
	reject("empty", "truncated", nil)
	reject("version_2", "version", []byte{0x80, 0x00})
	reject("version_0", "version", []byte{0x00, 0x00})
	reject("type_4", "type", []byte{0x40 | 4<<3, 0x00})
	reject("type_7", "type", []byte{0x40 | 7<<3, 0x00})
	reject("flags_1", "flags", []byte{0x41, 0x00})
	reject("flags_7", "flags", []byte{0x47, 0x00})
	reject("beacon_long", "oversize", append([]byte{0x40}, bytes.Repeat([]byte{9}, FramePayloadMax+1)...))
	reject("session_wire_oversize", "oversize", append([]byte{0x48}, bytes.Repeat([]byte{7}, NonceLen+FramePayloadMax+TagLen+1)...))
	reject("session_short", "truncated", append([]byte{0x48}, make([]byte, 5)...))

	// -- window: completion, interleaving, loss/expiry, refusals.
	fixedNow := func() time.Time { return time.Unix(1791072000, 0) }
	var wins []vecWindow
	runWindow := func(name string, timeout time.Duration, pushes ...[]byte) vecWindow {
		r := NewReassembler(timeout, fixedNow)
		vw := vecWindow{Name: name, TimeoutS: timeout.Seconds()}
		for _, p := range pushes {
			content, done, err := r.Push(p)
			switch {
			case errors.Is(err, ErrWindowDupIdx):
				vw.Pushes = append(vw.Pushes, vecWindowPush{PayloadHex: hx(p), Verdict: "dup"})
			case err != nil:
				vw.Pushes = append(vw.Pushes, vecWindowPush{PayloadHex: hx(p), Verdict: "invalid"})
			case done:
				vw.Pushes = append(vw.Pushes, vecWindowPush{PayloadHex: hx(p), Verdict: "done"})
				vw.Completions = append(vw.Completions, hx(content))
			case r.DupCopies > 0 && len(vw.Pushes) > 0:
				// An identical retransmission: idempotent, not an error.
				vw.Pushes = append(vw.Pushes, vecWindowPush{PayloadHex: hx(p), Verdict: "dupcopy"})
				r.DupCopies-- // consumed: the verdict below is per-push
			default:
				vw.Pushes = append(vw.Pushes, vecWindowPush{PayloadHex: hx(p), Verdict: "partial"})
			}
		}
		return vw
	}
	inter := func(id byte, fill byte, n int) [][]byte {
		f, err := SplitWindow(id, bytes.Repeat([]byte{fill}, n))
		if err != nil {
			t.Fatal(err)
		}
		return f
	}

	single := inter(1, 0xAB, 500) // 3 frames
	wins = append(wins, runWindow("single_three_frames", time.Hour,
		single[0], single[1], single[2]))

	wA := inter(2, 0xAA, 442) // 2 frames
	wB := inter(3, 0xBB, 58)  // 1 frame
	wC := inter(4, 0xCC, 500) // 3 frames
	wins = append(wins, runWindow("interleaved_out_of_order", time.Hour,
		wA[0], wB[0], wC[1], wC[2], wA[1], wC[0]))

	// Loss + expiry: window 5 loses idx 1 for good (never completes);
	// sibling 6 completes; the partial then expires past the timeout.
	wD := inter(5, 0xDD, 442)
	wE := inter(6, 0xEE, 58)
	r3 := NewReassembler(10*time.Second, fixedNow)
	v3 := vecWindow{Name: "loss_and_expiry", TimeoutS: 10}
	if _, done, err := r3.Push(wD[0]); err != nil || done {
		t.Fatal("vector bug: wD[0]")
	}
	v3.Pushes = append(v3.Pushes, vecWindowPush{PayloadHex: hx(wD[0]), Verdict: "partial"})
	if _, done, err := r3.Push(wE[0]); err != nil || !done {
		t.Fatal("vector bug: sibling must complete")
	}
	v3.Pushes = append(v3.Pushes, vecWindowPush{PayloadHex: hx(wE[0]), Verdict: "done"})
	v3.Completions = []string{hx(bytes.Repeat([]byte{0xEE}, 58))}
	wins = append(wins, v3)

	// Identical retransmissions are absorbed (benign); conflicting
	// duplicates and malformed headers are refused, never corrupting the
	// active window (which completes with its third frame).
	wF := inter(7, 0xFF, 500)
	conflicting := append([]byte(nil), wF[0]...)
	conflicting[len(conflicting)-1] ^= 0xFF
	wins = append(wins, runWindow("dup_and_malformed", time.Hour,
		wF[0], wF[0], conflicting, []byte{WindowHeader(8, 2, 1)}, wF[1], wF[2]))

	// -- replay: fixed session keys; ops pin the accept/reject verdicts.
	var reps []vecReplay
	type seqv = struct {
		seq     uint64
		verdict string
	}
	replayCase := func(name string, key [KeyLen]byte, salt [NonceSaltLen]byte, seqs []seqv) {
		vr := vecReplay{Name: name, KeyHex: hx(key[:]), SaltHex: hx(salt[:])}
		sess := NewSession(DirR2I, key, key, salt, salt, nil, nil)
		for _, op := range seqs {
			nonce := Nonce(salt, op.seq)
			data, err := sealCCM(key[:], nonce[:], nil, []byte("x"), TagLen)
			if err != nil {
				t.Fatal(err)
			}
			frame := append(nonce[:], data...)
			_, oerr := sess.Open(nil, frame)
			verdict := "accept"
			switch {
			case oerr == nil:
			case bytes.Contains([]byte(oerr.Error()), []byte("already accepted")):
				verdict = "replayed"
			case bytes.Contains([]byte(oerr.Error()), []byte("below the window")):
				verdict = "too_old"
			case bytes.Contains([]byte(oerr.Error()), []byte("ahead of")):
				verdict = "too_far"
			default:
				t.Fatalf("%s: unclassified error for seq %d: %v", name, op.seq, oerr)
			}
			if verdict != op.verdict {
				t.Fatalf("%s: seq %d verdict %s, want %s", name, op.seq, verdict, op.verdict)
			}
			vr.Ops = append(vr.Ops, vecReplayOp{Seq: op.seq, Verdict: verdict})
		}
		reps = append(reps, vr)
	}
	var rk [KeyLen]byte
	for i := range rk {
		rk[i] = byte(0x70 + i)
	}
	rs := [NonceSaltLen]byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01}
	replayCase("in_order_and_replay", rk, rs, []seqv{
		{0, "accept"}, {1, "accept"}, {2, "accept"}, {1, "replayed"}, {0, "replayed"}, {3, "accept"},
	})
	replayCase("gap_absorbed_then_old", rk, rs, []seqv{
		{10, "accept"}, {74, "accept"}, {73, "accept"}, {10, "too_old"},
		{9, "too_old"}, {202, "too_far"}, {138, "accept"}, {137, "accept"},
		{137, "replayed"}, {74, "too_old"},
	})

	return &vectorSet{
		Provenance: "Generated by node/internal/link (issue #33 P3.3) from the node-plane link layer: " +
			"docs/node-network.md §6.1 handshake (fixed X25519 scalars + Ed25519 seeds), §6.2 session/" +
			"replay discipline, §5.4 frame layout and the bundle-window reassembler. Official crypto " +
			"anchors (RFC 3610, RFC 5869, RFC 7748 §6.1, RFC 8032 §7.1) are pinned directly in both " +
			"suites' test files. Deterministic; committed copies MUST NOT be hand-edited.",
		RegenCommand: linkRegenCmd,
		Handshake:    hs,
		CCM:          ccm,
		FrameEncode:  fe,
		FrameReject:  fr,
		Window:       wins,
		Replay:       reps,
	}
}

// The reassembler returns completed content exactly once per window; the
// builder (above) and this verifier (below) each track completions
// themselves and the -regen/stability test keeps both views identical.

func TestLinkVectorsStable(t *testing.T) {
	vs := buildLinkVectorSet(t)
	wantJSON := linkJSONBytes(t, vs)
	wantHeader := linkHeaderBytes(t, vs)
	jsonPath := linkJSONPath()
	headerPath := linkHeaderPath()
	if regenLinkVectors != nil && *regenLinkVectors {
		if err := os.MkdirAll(filepath.Dir(jsonPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(headerPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(jsonPath, wantJSON, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(headerPath, wantHeader, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("regenerated %s and %s", jsonPath, headerPath)
		return
	}
	gotJSON, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("committed vectors missing (run %s): %v", linkRegenCmd, err)
	}
	if !bytes.Equal(gotJSON, wantJSON) {
		t.Fatalf("vectors.json drifted from the deterministic builder — run %s and commit", linkRegenCmd)
	}
	gotHeader, err := os.ReadFile(headerPath)
	if err != nil {
		t.Fatalf("committed C header missing (run %s): %v", linkRegenCmd, err)
	}
	if !bytes.Equal(gotHeader, wantHeader) {
		t.Fatalf("link_vectors.h drifted from vectors.json — run %s and commit", linkRegenCmd)
	}
}

// TestCrossImplementationLinkVectors executes every committed vector
// against the GO implementation — the Go half of the P3.3 cross-
// implementation gate (test_link.c is the C half, running the generated
// header's identical bytes).
func TestCrossImplementationLinkVectors(t *testing.T) {
	raw, err := os.ReadFile(linkJSONPath())
	if err != nil {
		t.Skipf("vectors not committed yet (%v)", err)
	}
	var vs vectorSet
	if err := json.Unmarshal(raw, &vs); err != nil {
		t.Fatalf("vectors.json: %v", err)
	}
	total := 0

	for i := range vs.Handshake {
		h := &vs.Handshake[i]
		kpA, err1 := nodeid.NewKeyPairFromSeed(mustHex(t, h.SeedAHex))
		kpB, err2 := nodeid.NewKeyPairFromSeed(mustHex(t, h.SeedBHex))
		if err1 != nil || err2 != nil {
			t.Fatal(err1, err2)
		}
		keys := keysFor(t, kpA, kpB)
		scalarI := mustHex(t, h.ScalarIHex)
		scalarR := mustHex(t, h.ScalarRHex)
		cfgI := Config{Local: kpA, Keys: keys, EphemeralScalar: func() ([]byte, error) { return scalarI, nil }}
		cfgR := Config{Local: kpB, Keys: keys, EphemeralScalar: func() ([]byte, error) { return scalarR, nil }}
		msg1, msg2, msg3, ini, res := runVectorHandshake(t, cfgI, cfgR)
		e := h.Expect
		if hx(msg1) != e.Msg1Hex || hx(msg2) != e.Msg2Hex || hx(msg3) != e.Msg3Hex ||
			ini.PeerEID() != e.EIDB || res.PeerEID() != e.EIDA ||
			len(msg1) != e.LenMsg1 || len(msg2) != e.LenMsg2 || len(msg3) != e.LenMsg3 {
			t.Fatalf("%s: handshake diverged from the committed vector", h.Name)
		}
		total++
	}
	for i := range vs.CCM {
		c := &vs.CCM[i]
		key, nonce := keyArr(mustHex(t, c.KeyHex)), nonceArr(mustHex(t, c.NonceHex))
		sealed, err := sealCCM(key[:], nonce[:], mustHex(t, c.AADHex), mustHex(t, c.PlaintextHex), TagLen)
		if err != nil {
			t.Fatal(err)
		}
		if hx(sealed) != c.SealedHex {
			t.Fatalf("%s: CCM diverged", c.Name)
		}
		total++
	}
	for i := range vs.FrameEncode {
		f := &vs.FrameEncode[i]
		out, err := EncodeFrame(FrameType(f.Type), mustHex(t, f.PayloadHex))
		if err != nil {
			t.Fatal(err)
		}
		if hx(out) != f.FrameHex {
			t.Fatalf("%s: frame diverged", f.Name)
		}
		total++
	}
	for i := range vs.FrameReject {
		r := &vs.FrameReject[i]
		if _, _, err := ParseFrame(mustHex(t, r.FrameHex)); err == nil {
			t.Fatalf("%s: rejected frame accepted", r.Name)
		}
		total++
	}
	for i := range vs.Window {
		w := &vs.Window[i]
		runWindowVerdicts(t, w)
		total++
	}
	for i := range vs.Replay {
		rp := &vs.Replay[i]
		key, salt := keyArr(mustHex(t, rp.KeyHex)), saltArr(mustHex(t, rp.SaltHex))
		sess := NewSession(DirR2I, key, key, salt, salt, nil, nil)
		for _, op := range rp.Ops {
			nonce := Nonce(salt, op.Seq)
			data, err := sealCCM(key[:], nonce[:], nil, []byte("x"), TagLen)
			if err != nil {
				t.Fatal(err)
			}
			_, oerr := sess.Open(nil, append(nonce[:], data...))
			if got := replayVerdict(oerr); got != op.Verdict {
				t.Fatalf("%s: seq %d verdict %s, want %s", rp.Name, op.Seq, got, op.Verdict)
			}
		}
		total++
	}
	t.Logf("cross-implementation evidence: %d link vectors matched on the Go side (handshake %d, ccm %d, frame %d+%d, window %d, replay %d); the C suite runs the same set through link_vectors.h",
		total, len(vs.Handshake), len(vs.CCM), len(vs.FrameEncode), len(vs.FrameReject), len(vs.Window), len(vs.Replay))
	if len(vs.Handshake) < 2 || len(vs.CCM) < 4 || len(vs.FrameEncode) < 4 || len(vs.FrameReject) < 6 || len(vs.Window) < 3 || len(vs.Replay) < 2 {
		t.Fatal("the vector set lost coverage")
	}
}

// runWindowVerdicts replays one committed window scenario against the Go
// reassembler, comparing per-push verdicts and completion contents. The
// builder recorded completions while RUNNING the scenario (see
// buildLinkVectorSet); here they are recomputed and compared.
func runWindowVerdicts(t *testing.T, w *vecWindow) {
	t.Helper()
	fixedNow := func() time.Time { return time.Unix(1791072000, 0) }
	r := NewReassembler(time.Duration(w.TimeoutS*float64(time.Second)), fixedNow)
	var completions []string
	for _, p := range w.Pushes {
		content, done, err := r.Push(mustHex(t, p.PayloadHex))
		var got string
		switch {
		case errors.Is(err, ErrWindowDupIdx):
			got = "dup"
		case err != nil:
			got = "invalid"
		case done:
			got = "done"
			completions = append(completions, hx(content))
		case p.Verdict == "dupcopy":
			got = "dupcopy" // an identical retransmission; nothing advances
		default:
			got = "partial"
		}
		if got != p.Verdict {
			t.Fatalf("%s: push %s → %s, want %s", w.Name, p.PayloadHex[:16], got, p.Verdict)
		}
	}
	if len(completions) != len(w.Completions) {
		t.Fatalf("%s: %d completions, want %d", w.Name, len(completions), len(w.Completions))
	}
	for j := range completions {
		if completions[j] != w.Completions[j] {
			t.Fatalf("%s: completion %d diverged", w.Name, j)
		}
	}
}

// replayVerdict classifies a session Open error into the stable vector
// vocabulary.
func replayVerdict(err error) string {
	switch {
	case err == nil:
		return "accept"
	case bytes.Contains([]byte(err.Error()), []byte("already accepted")):
		return "replayed"
	case bytes.Contains([]byte(err.Error()), []byte("below the window")):
		return "too_old"
	case bytes.Contains([]byte(err.Error()), []byte("ahead of")):
		return "too_far"
	}
	return "accept"
}

func keyArr(b []byte) [KeyLen]byte {
	var k [KeyLen]byte
	copy(k[:], b)
	return k
}

func nonceArr(b []byte) [NonceLen]byte {
	var n [NonceLen]byte
	copy(n[:], b)
	return n
}

func saltArr(b []byte) [NonceSaltLen]byte {
	var s [NonceSaltLen]byte
	copy(s[:], b)
	return s
}
