// P3.0 measurement spike tests (issue #33). These tests MEASURE the byte
// budgets the docs/node-network.md §4/§5/§6 tables quote; run with -v to
// dump the exact hex encodings the spec's byte tables are transcribed from:
//
//	go test ./internal/bundle -run TestSpikeDump -v
//
// The normative bounds asserted here come from the issue's exit criteria:
// mail-bundle overhead ≤ 80 B, a 399 B envelope fits ≤ 3 LoRa frames,
// handshake messages < 3 frames each. If a change to the profile builders
// breaks one of them, docs/node-network.md must be revised in the same PR.
package bundle

import (
	"bytes"
	"encoding/hex"
	"math"
	"testing"
	"time"
)

// testFP is a synthetic 16-lowercase-hex node fingerprint ("og." + fp = the
// §3.2 identified EID shape).
const testFP = "0123456789abcdef"

// testTTL is the §8.1 default envelope TTL (7 days).
const testTTL = 604800

// testCreated matches the §3.2 example envelope's created_at.
const testCreated = 1759500000

// synthetic envelope bytes at the §14.3 sizes (floor 244, max 399).
func envelopeOf(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(0xA5 ^ i) // deterministic, non-trivial filler
	}
	return b
}

// synthetic minimal COSE_Sign1 ([protBstr{1:-8}, {}, payload, sig(64)]) —
// the floor size of any management payload (role cert, admin command,
// capsule chunk header); real ones are strictly larger.
func minimalCOSESign1(payload []byte) []byte {
	e := &cbor{}
	e.array(4)
	prot := &cbor{}
	prot.mapHead(1)
	prot.uint(1)    // alg label 1
	prot.negint(-8) // EdDSA
	e.bstr(prot.b)
	e.mapHead(0) // unprotected
	e.bstr(payload)
	sig := make([]byte, 64)
	for i := range sig {
		sig[i] = byte(0x5A ^ i)
	}
	e.bstr(sig)
	return e.b
}

func TestSpikeCRC16X25(t *testing.T) {
	// CRC-16/X.25 catalogue check value.
	if got := crc16x25([]byte("123456789")); got != 0x906E {
		t.Fatalf("crc16x25(\"123456789\") = %#04x, want 0x906E", got)
	}
}

func TestSpikeMailBundleBudget(t *testing.T) {
	const maxEnvelope = 399 // §14.3: M=128, A=24
	const minEnvelope = 244 // §14.3: M=0, A=0

	maxB := MailBundle(envelopeOf(maxEnvelope), testCreated, testTTL, 0)
	overheadMax := len(maxB) - maxEnvelope
	framesMax, capMax, okMax := frameFit(len(maxB))
	t.Logf("mail bundle @ max envelope %d B: bundle %d B, overhead %d B (budget ≤ 80), frames %d (window capacity %d B, fits %v)",
		maxEnvelope, len(maxB), overheadMax, framesMax, capMax, okMax)
	if overheadMax > 80 {
		t.Fatalf("mail overhead %d B busts the ≤ 80 B budget", overheadMax)
	}
	if !okMax || framesMax > 3 {
		t.Fatalf("399 B envelope needs %d frames — busts the ≤ 3-frames exit criterion (capacity %d B)", framesMax, capMax)
	}
	if len(maxB) <= 2*frameWindowPayload {
		t.Fatalf("expected the measured math to show 2 frames insufficient for 399 B (bundle %d ≤ %d)", len(maxB), 2*frameWindowPayload)
	}

	minB := MailBundle(envelopeOf(minEnvelope), testCreated, testTTL, 0)
	overheadMin := len(minB) - minEnvelope
	framesMin, _, _ := frameFit(len(minB))
	t.Logf("mail bundle @ min envelope %d B: bundle %d B, overhead %d B, frames %d",
		minEnvelope, len(minB), overheadMin, framesMin)
	if framesMin != 2 {
		t.Fatalf("min mail bundle needs %d frames, want 2", framesMin)
	}

	// Bundle identity ignores the mutable hop octet: same PDU → same id.
	if !bytes.Equal(BundleID(envelopeOf(maxEnvelope)), BundleID(envelopeOf(maxEnvelope))) {
		t.Fatal("BundleID is not deterministic")
	}
	hopped := append([]byte{7}, envelopeOf(maxEnvelope)...)
	if !bytes.Equal(BundleID(hopped[1:]), BundleID(envelopeOf(maxEnvelope))) {
		t.Fatal("BundleID must be computed over the PDU (payload after the hop octet)")
	}
}

func TestSpikeManagementBundleBudget(t *testing.T) {
	cose := minimalCOSESign1(make([]byte, 20))
	mb := ManagementBundle(testFP, testFP, cose, testCreated, 1, testTTL, 0)
	fixedOverhead := len(mb) - len(cose)
	frames, _, ok := frameFit(len(mb))
	t.Logf("management bundle @ floor COSE_Sign1 %d B: bundle %d B, fixed overhead %d B, frames %d (fits %v)",
		len(cose), len(mb), fixedOverhead, frames, ok)
	if frames != 1 {
		t.Fatalf("floor management bundle needs %d frames, want 1", frames)
	}

	// A 200 B LoRa capsule chunk (docs/node-network.md §9) must fit 2 frames.
	chunk := ManagementBundle(testFP, testFP, make([]byte, 200), testCreated, 2, testTTL, 0)
	cf, _, cok := frameFit(len(chunk))
	t.Logf("capsule chunk bundle @ 200 B: bundle %d B, frames %d (fits %v)", len(chunk), cf, cok)
	if !cok || cf != 2 {
		t.Fatalf("200 B capsule chunk needs %d frames (fits %v), want 2", cf, cok)
	}

	// A worst-case 1024 B directory card exceeds the 4-frame window and must
	// be refused by the LoRa CL (honest bound recorded in §9).
	card := ManagementBundle(testFP, testFP, make([]byte, 1024), testCreated, 3, testTTL, 0)
	kf, _, kok := frameFit(len(card))
	t.Logf("max directory-card bundle @ 1024 B: bundle %d B, frames %d (fits %v) — LoRa CL must refuse", len(card), kf, kok)
	if kok {
		t.Fatalf("1024 B card unexpectedly fits the window (%d frames)", kf)
	}
}

func TestSpikeFrameFitBounds(t *testing.T) {
	cases := []struct {
		bytes  int
		frames int
		ok     bool
	}{
		{172, 1, true},  // floor management bundle
		{290, 2, true},  // min mail bundle
		{446, 3, true},  // max mail bundle
		{884, 4, true},  // full window
		{885, 5, false}, // over the window — LoRa CL refuses
	}
	for _, c := range cases {
		f, capacity, ok := frameFit(c.bytes)
		if f != c.frames || ok != c.ok {
			t.Fatalf("frameFit(%d) = %d frames (ok=%v), want %d (ok=%v)", c.bytes, f, ok, c.frames, c.ok)
		}
		if ok && capacity < c.bytes {
			t.Fatalf("frameFit(%d) capacity %d < %d", c.bytes, capacity, c.bytes)
		}
	}
}

func TestSpikeHandshakeSizes(t *testing.T) {
	s := HandshakeSizes()
	t.Logf("handshake message sizes: msg1 %d B, msg2 %d B, msg3 %d B (frame %d B, 3-frame bound %d B)",
		s.M1, s.M2, s.M3, frameWindowPayload, 3*frameWindowPayload)
	for name, sz := range map[string]int{"msg1": s.M1, "msg2": s.M2, "msg3": s.M3} {
		if sz >= 3*frameWindowPayload {
			t.Fatalf("%s = %d B busts the < 3-frames bound", name, sz)
		}
		if sz >= frameWindowPayload {
			t.Fatalf("%s = %d B lost its single-frame fit", name, sz)
		}
	}
}

func TestSpikeAirtimeTable(t *testing.T) {
	// The three §5 profiles at a 222 B frame (the §14.3 radio MTU), and the
	// airtime of the frame split a 200 B capsule-chunk bundle actually
	// transmits (279 B = 221 + 58).
	profiles := []struct {
		name   string
		sf, bw int
	}{
		{"SF7/BW125", 7, 125000},
		{"SF9/BW125", 9, 125000},
		{"SF11/BW250", 11, 250000},
	}
	for _, p := range profiles {
		t222, err := LoraAirtimeAutoDE(p.sf, p.bw, 222)
		if err != nil {
			t.Fatal(err)
		}
		t221, err := LoraAirtimeAutoDE(p.sf, p.bw, 221)
		if err != nil {
			t.Fatal(err)
		}
		t58, err := LoraAirtimeAutoDE(p.sf, p.bw, 58)
		if err != nil {
			t.Fatal(err)
		}
		chunk := t221 + t58 // one 279 B chunk bundle = 2 frames (221 + 58)
		full1500 := 7500 * chunk
		full11000 := 55000 * chunk
		t.Logf("%s: T222=%v T221=%v T58=%v | chunk-bundle(279 B, 2 fr)=%v | 1.5 MB (7500 chunks)=%v | 11 MB (55000 chunks)=%v",
			p.name, t222.Round(time.Millisecond), t221.Round(time.Millisecond), t58.Round(time.Millisecond),
			chunk.Round(time.Millisecond), full1500.Round(time.Second), full11000.Round(time.Second))
	}

	// Golden pins for the §5 table (standard formula, preamble 8, CR 4/5,
	// PHY CRC on, explicit header; DE per the 16 ms rule).
	golden := []struct {
		sf, bw, pl int
		want       time.Duration
	}{
		{7, 125000, 222, 348416 * time.Microsecond},
		{9, 125000, 222, 1106944 * time.Microsecond},
		{11, 250000, 222, 1845248 * time.Microsecond},
		{7, 125000, 58, 112896 * time.Microsecond},
		{9, 125000, 58, 369664 * time.Microsecond},
	}
	for _, g := range golden {
		got, err := LoraAirtimeAutoDE(g.sf, g.bw, g.pl)
		if err != nil {
			t.Fatal(err)
		}
		if got != g.want {
			t.Fatalf("airtime(sf=%d bw=%d pl=%d) = %v, want %v", g.sf, g.bw, g.pl, got, g.want)
		}
	}

	// The formula must scale the way LoRa does: higher SF = slower.
	slow, _ := LoraAirtimeAutoDE(9, 125000, 222)
	fast, _ := LoraAirtimeAutoDE(7, 125000, 222)
	if slow <= fast || math.IsNaN(slow.Seconds()) {
		t.Fatal("airtime must increase with SF")
	}
}

// TestSpikeDump is the reproducibility dump: run with -v and transcribe the
// hex into docs/node-network.md §4/§6 byte tables.
func TestSpikeDump(t *testing.T) {
	env := envelopeOf(399)
	mail := MailBundle(env, testCreated, testTTL, 0)

	primaryMail := primaryBlock(mailGroupEID, eidNone, eidNone, testCreated, 0, testTTL)
	if len(primaryMail) != 35 {
		t.Fatalf("mail primary block is %d B, want 35 (update the doc and this check)", len(primaryMail))
	}

	mb := ManagementBundle(testFP, testFP, minimalCOSESign1(make([]byte, 20)), testCreated, 1, testTTL, 0)
	primaryMgmt := primaryBlock(nodeEID(testFP), nodeEID(testFP), eidNone, testCreated, 1, testTTL)
	if len(primaryMgmt) != 68 {
		t.Fatalf("management primary block is %d B, want 68 (update the doc and this check)", len(primaryMgmt))
	}

	t.Logf("== primary block, anonymous mail (35 B) ==\n%s", hexDump(primaryMail))
	t.Logf("== primary block, identified management (68 B) ==\n%s", hexDump(primaryMgmt))
	t.Logf("== mail bundle, 399 B envelope, total %d B ==\n%s", len(mail), hexDump(mail))
	t.Logf("== management bundle, floor COSE_Sign1, total %d B ==\n%s", len(mb), hexDump(mb))
	t.Logf("== BundleID(mail PDU) (32 B) ==\n%s", hex.EncodeToString(BundleID(env)))
}

func hexDump(b []byte) string {
	const w = 32
	var out bytes.Buffer
	for i := 0; i < len(b); i += w {
		end := i + w
		if end > len(b) {
			end = len(b)
		}
		row := hex.EncodeToString(b[i:end])
		out.WriteString(row)
		if end-i == w {
			out.WriteString("  (+" + itoa(end) + ")")
		}
		out.WriteString("\n")
	}
	return out.String()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
