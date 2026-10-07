// P3.2 profile-codec tests (issue #33): the §3 rules P-1..P-7 as executable
// checks — round trips, the §3.1 envelope-verbatim and relay-replay pins,
// the §4 byte budgets as exact numbers, the EID shape rules, the P-6 skew
// boundary and the fail-closed malformed-input battery (including the
// truncation and single-bit-flip properties over whole PDUs). The shared
// Go↔C vector contract lives in vectors_test.go.
package bundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

// vecClock is the receivers' wall clock in these tests (the repo fixture
// time, same constant as nodeid's vector set).
var vecClock = time.Unix(1791072000, 0)

func mustMail(t *testing.T, n int, createdUnixMs int64, hop byte) (*Bundle, []byte) {
	t.Helper()
	b, err := NewMail(envelopeOf(n), createdUnixMs, testTTL)
	if err != nil {
		t.Fatal(err)
	}
	b.Hop = hop
	pdu, err := Encode(b)
	if err != nil {
		t.Fatal(err)
	}
	return b, pdu
}

func mustMgmt(t *testing.T, srcFP, dstFP string, createdUnixMs int64, hop byte) (*Bundle, []byte) {
	t.Helper()
	b, err := NewManagement("dtn://og."+srcFP+"/", "dtn://og."+dstFP+"/", createdUnixMs, testTTL, 1, minimalCOSESign1(make([]byte, 20)))
	if err != nil {
		t.Fatal(err)
	}
	b.Hop = hop
	pdu, err := Encode(b)
	if err != nil {
		t.Fatal(err)
	}
	return b, pdu
}

func TestCodecRoundTrip(t *testing.T) {
	createdMs := int64(vecClock.Unix()-3600) * 1000
	cases := []struct {
		name string
		b    *Bundle
	}{
		{"mail_hop0", func() *Bundle { b, _ := NewMail(envelopeOf(244), createdMs, testTTL); return b }()},
		{"mail_hop5", func() *Bundle { b, _ := NewMail(envelopeOf(64), createdMs, testTTL); b.Hop = 5; return b }()},
		{"mgmt_pair", func() *Bundle {
			b, _ := NewManagement("dtn://og."+testFP+"/", "dtn://og.dac073e0123bdea5/", createdMs, testTTL, 7, minimalCOSESign1([]byte("payload")))
			return b
		}()},
		{"mgmt_admin_group", func() *Bundle {
			b, err := NewManagement("dtn://og."+testFP+"/", "dtn://og-admin/", createdMs, testTTL, 1, []byte{1, 2, 3})
			if err != nil {
				t.Fatal(err)
			}
			return b
		}()},
	}
	for _, c := range cases {
		pdu, err := Encode(c.b)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got, err := Parse(pdu, vecClock)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got.Destination != c.b.Destination || got.Source != c.b.Source || got.ReportTo != c.b.ReportTo {
			t.Fatalf("%s: EIDs mismatch: %v/%v/%v", c.name, got.Destination, got.Source, got.ReportTo)
		}
		if got.CreationDTNms != c.b.CreationDTNms || got.Sequence != c.b.Sequence ||
			got.Lifetime != c.b.Lifetime || got.Hop != c.b.Hop {
			t.Fatalf("%s: fields mismatch: %+v", c.name, got)
		}
		if !bytes.Equal(got.Payload, c.b.Payload) {
			t.Fatalf("%s: payload mismatch (%d vs %d bytes)", c.name, len(got.Payload), len(c.b.Payload))
		}
		again, err := Encode(got)
		if err != nil {
			t.Fatalf("%s: re-encode: %v", c.name, err)
		}
		if !bytes.Equal(again, pdu) {
			t.Fatalf("%s: parse→encode is not the identity", c.name)
		}
	}
}

// TestEnvelopeVerbatimAtOffsetOne pins §3.1: the mail payload content is the
// hop octet followed by the §14.2 envelope verbatim — the envelope's bytes
// appear exactly once, at content offset 1, unmodified.
func TestEnvelopeVerbatimAtOffsetOne(t *testing.T) {
	env := envelopeOf(244)
	b, err := NewMail(env, int64(testCreated)*1000, testTTL)
	if err != nil {
		t.Fatal(err)
	}
	pdu, err := Encode(b)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(pdu, vecClock)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.ContentOff != parsed.PrimaryLen+5+2 {
		// array head (1) + type/number/flags/CRC-type (4) + bstr head (2 for
		// content 245 ≤ 255) — the §4.1 framing math.
		t.Fatalf("content offset %d, want %d", parsed.ContentOff, parsed.PrimaryLen+7)
	}
	if !bytes.Equal(pdu[parsed.ContentOff:parsed.ContentOff+1+len(env)], append([]byte{0}, env...)) {
		t.Fatal("content is not hop ‖ envelope verbatim")
	}
	if i := bytes.Index(pdu, env); i != parsed.ContentOff+1 {
		t.Fatalf("envelope bytes appear at offset %d, want exactly %d (never at 0, never rewritten)", i, parsed.ContentOff+1)
	}
}

// TestBudgetsPinned re-asserts §4's measured numbers as exact values of the
// formal codec (the spike's TestSpikeMailBundleBudget stays as the looser
// exit-criterion gate; this pins the same math through NewMail/Encode).
func TestBudgetsPinned(t *testing.T) {
	cases := []struct {
		name         string
		envelope     int
		wantBundle   int
		wantOverhead int
		wantFrames   int
	}{
		{"min envelope (§14.3 floor)", 244, 290, 46, 2},
		{"max envelope (§14.3 max)", 399, 446, 47, 3},
	}
	for _, c := range cases {
		_, pdu := mustMail(t, c.envelope, int64(testCreated)*1000, 0)
		if len(pdu) != c.wantBundle {
			t.Fatalf("%s: bundle %d B, want %d (update docs/node-network.md §4 with any change)", c.name, len(pdu), c.wantBundle)
		}
		if len(pdu)-c.envelope != c.wantOverhead {
			t.Fatalf("%s: overhead %d B, want %d", c.name, len(pdu)-c.envelope, c.wantOverhead)
		}
		if frames, _, ok := frameFit(len(pdu)); !ok || frames != c.wantFrames {
			t.Fatalf("%s: frames %d (fits %v), want %d", c.name, frames, ok, c.wantFrames)
		}
	}

	// The §4 primary-block hexes, transcribed: the anonymous mail primary
	// (35 B, created 1759500000, ttl 604800) and the identified management
	// primary (68 B, both EIDs og.0123456789abcdef, seq 1).
	_, mailPDU := mustMail(t, 16, int64(testCreated)*1000, 0)
	const mailPrimaryHex = "890700018260676f672d6d61696cf6f6821b000000bd3f8faf00001a00093a80" + "42912c"
	if !bytes.HasPrefix(mailPDU, mustHex(t, mailPrimaryHex)) {
		t.Fatalf("mail primary block diverges from the §4 hex:\n got %x\nwant %s", mailPDU[:35], mailPrimaryHex)
	}
	_, mgmtPDU := mustMgmt(t, testFP, testFP, int64(testCreated)*1000, 0)
	const mgmtPrimaryHex = "8907000182736f672e303132333435363738396162636465666082736f672e30" +
		"31323334353637383961626364656660f6821b000000bd3f8faf00011a00093a" + "80425019"
	if len(mgmtPDU) < 68 || !bytes.HasPrefix(mgmtPDU, mustHex(t, mgmtPrimaryHex)) {
		t.Fatalf("management primary block diverges from the §4 hex:\n got %x\nwant %s", mgmtPDU[:68], mgmtPrimaryHex)
	}

	// §4.1 row: the floor COSE_Sign1 management bundle is 172 B, 1 frame,
	// 79 B fixed overhead.
	cose := minimalCOSESign1(make([]byte, 20))
	if len(cose) != 93 {
		t.Fatalf("floor COSE_Sign1 is %d B, want 93", len(cose))
	}
	mb, err := NewManagement("dtn://og."+testFP+"/", "dtn://og."+testFP+"/", int64(testCreated)*1000, testTTL, 1, cose)
	if err != nil {
		t.Fatal(err)
	}
	mPDU, err := Encode(mb)
	if err != nil {
		t.Fatal(err)
	}
	if len(mPDU) != 172 {
		t.Fatalf("floor management bundle is %d B, want 172 (§4.1)", len(mPDU))
	}
	if frames, _, _ := frameFit(len(mPDU)); frames != 1 {
		t.Fatalf("floor management bundle needs %d frames, want 1", frames)
	}
}

// TestRewriteHopRelayOperation pins the §3.1 relay semantics: exactly three
// bytes change (the hop octet and the payload block's two CRC bytes), the
// primary block and envelope are untouched, identity is stable, and the
// limit is a hard stop.
func TestRewriteHopRelayOperation(t *testing.T) {
	_, pdu := mustMail(t, 64, int64(testCreated)*1000, 2)
	parsed, err := Parse(pdu, vecClock)
	if err != nil {
		t.Fatal(err)
	}
	out, err := RewriteHop(pdu)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != len(pdu) {
		t.Fatalf("rewrite changed the length: %d → %d", len(pdu), len(out))
	}
	var changed []int
	for i := range pdu {
		if pdu[i] != out[i] {
			changed = append(changed, i)
		}
	}
	if len(changed) != 3 || changed[0] != parsed.ContentOff ||
		changed[1] != len(pdu)-2 || changed[2] != len(pdu)-1 {
		t.Fatalf("rewrite touched %v, want exactly [hop, crcHi, crcLo] = [%d, %d, %d]",
			changed, parsed.ContentOff, len(pdu)-2, len(pdu)-1)
	}
	if !bytes.Equal(out[:parsed.PrimaryLen], pdu[:parsed.PrimaryLen]) {
		t.Fatal("rewrite touched the primary block")
	}
	re, err := Parse(out, vecClock)
	if err != nil {
		t.Fatalf("rewritten PDU does not parse: %v", err)
	}
	if re.Hop != 3 {
		t.Fatalf("rewritten hop = %d, want 3", re.Hop)
	}
	if !bytes.Equal(re.Payload, parsed.Payload) {
		t.Fatal("rewrite disturbed the payload bytes")
	}
	idBefore, err := BundleIDOf(pdu)
	if err != nil {
		t.Fatal(err)
	}
	idAfter, err := BundleIDOf(out)
	if err != nil {
		t.Fatal(err)
	}
	if idBefore != idAfter {
		t.Fatal("bundle identity changed across a hop rewrite (P-7 says it must not)")
	}

	// hop == 7: the drop semantics — a relay must refuse, not wrap.
	_, pdu7 := mustMail(t, 64, int64(testCreated)*1000, 7)
	if _, err := RewriteHop(pdu7); ErrorCode(err) != CodeHop {
		t.Fatalf("RewriteHop at hop 7 = %v, want code %s", err, CodeHop)
	}
	// hop == 7 still parses (it may be delivered locally); hop == 8 never.
	if b, err := Parse(pdu7, vecClock); err != nil || b.Hop != 7 {
		t.Fatalf("Parse at hop 7 = (%v, %v), want hop 7 accepted", b, err)
	}
	if _, err := Parse(mustHop8(t), vecClock); ErrorCode(err) != CodeHop {
		t.Fatalf("Parse at hop 8 = %v, want code %s", err, CodeHop)
	}
}

// mustHop8 builds a structurally valid bundle whose hop octet is 8 (CRC
// recomputed, so the hop rule is the only thing under test).
func mustHop8(t *testing.T) []byte {
	t.Helper()
	_, pdu := mustMail(t, 32, int64(testCreated)*1000, 0)
	parsed, err := Parse(pdu, vecClock)
	if err != nil {
		t.Fatal(err)
	}
	out := bytes.Clone(pdu)
	out[parsed.ContentOff] = 8
	patchPayloadCRC(t, out, parsed.PrimaryLen)
	return out
}

// patchPayloadCRC recomputes and rewrites the payload block's CRC after a
// mutation (for malformed classes whose failure must NOT be the CRC). The
// CRC covers the block up to (not including) its 0x42 CRC-bstr head.
func patchPayloadCRC(t *testing.T, pdu []byte, primaryLen int) {
	t.Helper()
	crcHead := len(pdu) - 3
	c := crc16x25(pdu[primaryLen:crcHead])
	pdu[crcHead+1] = byte(c >> 8)
	pdu[crcHead+2] = byte(c)
}

func TestBundleIDOfDigest(t *testing.T) {
	env := envelopeOf(100)
	b, err := NewMail(env, int64(testCreated)*1000, testTTL)
	if err != nil {
		t.Fatal(err)
	}
	pdu, err := Encode(b)
	if err != nil {
		t.Fatal(err)
	}
	id, err := BundleIDOf(pdu)
	if err != nil {
		t.Fatal(err)
	}
	if want := sha256.Sum256(env); id != want {
		t.Fatal("BundleIDOf(mail) != SHA-256(envelope verbatim)")
	}
	if !bytes.Equal(id[:], BundleID(env)) {
		t.Fatal("BundleIDOf disagrees with spike.BundleID over the same PDU")
	}
	if _, err := BundleIDOf([]byte{0x01}); err == nil {
		t.Fatal("BundleIDOf accepted garbage")
	}
}

func TestFutureSkewBoundary(t *testing.T) {
	_, pdu := mustMail(t, 32, int64(testCreated)*1000, 0)
	// created_at is 300 s ahead of this clock: the boundary accepts.
	if _, err := Parse(pdu, time.Unix(testCreated-300, 0)); err != nil {
		t.Fatalf("creation exactly 300 s ahead must be accepted, got %v", err)
	}
	if _, err := Parse(pdu, time.Unix(testCreated-301, 0)); ErrorCode(err) != CodeSkew {
		t.Fatalf("creation 301 s ahead = %v, want code %s", err, CodeSkew)
	}
	// Arbitrary age is fine — expiry is the store's job, not the codec's.
	if _, err := Parse(pdu, time.Unix(testCreated+86400, 0)); err != nil {
		t.Fatalf("old bundle rejected: %v", err)
	}
}

func TestEIDShapes(t *testing.T) {
	round := []struct {
		uri  string
		want EID
	}{
		{"dtn:none", eidNone},
		{"dtn:og-mail", eid{local: "og-mail"}},
		{"dtn://og-admin/", eid{authority: "og-admin"}},
		{"dtn://og." + testFP + "/", nodeEID(testFP)},
	}
	for _, c := range round {
		got, err := ParseEID(c.uri)
		if err != nil {
			t.Fatalf("ParseEID(%q): %v", c.uri, err)
		}
		if got != c.want || got.String() != c.uri {
			t.Fatalf("ParseEID(%q) = %q round-trip failed", c.uri, got.String())
		}
	}
	for _, bad := range []string{
		"", "dtn:", "dtn:none/", "dtn://", "dtn://og." + testFP, // no trailing slash
		"dtn://og." + testFP + "//", "dtn://OG.0123456789ABCDEF/", // uppercase
		"dtn://og.0123/", // short fingerprint
		"dtn://og.zzzz/", // not hex
		"dtn:OG-MAIL",    // uppercase token
		"dtn:-og-mail",   // must start alphanumeric
		"dtn:og.mail",    // dot is node-authority-only
		"dtn:" + string(bytes.Repeat([]byte("a"), 64)), // over the token bound
		"http://og." + testFP + "/", "ipn:1.1",
	} {
		if _, err := ParseEID(bad); err == nil {
			t.Fatalf("ParseEID(%q) accepted", bad)
		}
	}
}

// TestEncodeRejectsInvalid: Encode is the last gate before the wire.
func TestEncodeRejectsInvalid(t *testing.T) {
	valid := func(b *Bundle) *Bundle { return b }
	cases := []struct {
		name string
		b    *Bundle
		code string
	}{
		{"nil", nil, CodeArgument},
		{"empty payload", valid(&Bundle{Destination: mailGroupEID, Source: eidNone, ReportTo: eidNone, Lifetime: testTTL}), CodeEmptyPayload},
		{"lifetime 0", valid(&Bundle{Destination: mailGroupEID, Source: eidNone, ReportTo: eidNone, Lifetime: 0, Payload: []byte{1}}), CodeLifetime},
		{"hop 8", valid(&Bundle{Destination: mailGroupEID, Source: eidNone, ReportTo: eidNone, Lifetime: testTTL, Hop: 8, Payload: []byte{1}}), CodeHop},
		{"anonymous destination", valid(&Bundle{Destination: eidNone, Source: eidNone, ReportTo: eidNone, Lifetime: testTTL, Payload: []byte{1}}), CodeEID},
		{"group source", valid(&Bundle{Destination: mailGroupEID, Source: mailGroupEID, ReportTo: eidNone, Lifetime: testTTL, Payload: []byte{1}}), CodeEID},
		{"report-to set", valid(&Bundle{Destination: mailGroupEID, Source: eidNone, ReportTo: nodeEID(testFP), Lifetime: testTTL, Payload: []byte{1}}), CodeEID},
		{"malformed source eid", valid(&Bundle{Destination: mailGroupEID, Source: eid{authority: "og.zzz"}, ReportTo: eidNone, Lifetime: testTTL, Payload: []byte{1}}), CodeEID},
	}
	for _, c := range cases {
		if _, err := Encode(c.b); ErrorCode(err) != c.code {
			t.Fatalf("%s: Encode = %v, want code %s", c.name, err, c.code)
		}
	}
	if _, err := NewMail(nil, 0, testTTL); ErrorCode(err) != CodeEmptyPayload {
		t.Fatalf("NewMail(empty) = %v, want %s", err, CodeEmptyPayload)
	}
	if _, err := NewManagement("dtn:og-mail", "dtn:og-mail", int64(testCreated)*1000, testTTL, 1, []byte{1}); ErrorCode(err) != CodeEID {
		t.Fatalf("NewManagement(group source) = %v, want %s", err, CodeEID)
	}
	if _, err := NewManagement("dtn://og."+testFP+"/", "dtn:none", int64(testCreated)*1000, testTTL, 1, []byte{1}); ErrorCode(err) != CodeEID {
		t.Fatalf("NewManagement(anonymous destination) = %v, want %s", err, CodeEID)
	}
	if _, err := NewMail(envelopeOf(8), 100, testTTL); ErrorCode(err) != CodeArgument {
		t.Fatalf("NewMail(pre-epoch) = %v, want %s", err, CodeArgument)
	}
}

// TestMalformedFailClosed is the hand-built half of the rejection table (the
// shared-vector half lives in vectors_test.go): truncation at EVERY byte
// position, a single-bit flip at EVERY byte position, non-shortest heads,
// indefinite lengths, foreign containers, extra blocks.
func TestMalformedFailClosed(t *testing.T) {
	_, mailPDU := mustMail(t, 32, int64(testCreated)*1000, 0)
	_, mgmtPDU := mustMgmt(t, testFP, "dac073e0123bdea5", int64(testCreated)*1000, 0)

	// Truncation: every proper prefix of a canonical bundle is rejected.
	for _, pdu := range [][]byte{mailPDU, mgmtPDU} {
		for i := 0; i < len(pdu); i++ {
			if _, err := Parse(pdu[:i], vecClock); err == nil {
				t.Fatalf("prefix of %d bytes accepted (%d-byte PDU)", i, len(pdu))
			}
		}
	}

	// Single-bit flips: every bit of every byte position is rejected (the
	// block CRCs make this a hard property, and everything a flip can break
	// — heads, types, lengths, CRC bytes — fails closed somewhere).
	parsed, err := Parse(mailPDU, vecClock)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(mailPDU); i++ {
		for bit := 0; bit < 8; bit++ {
			mut := bytes.Clone(mailPDU)
			mut[i] ^= 1 << bit
			if _, err := Parse(mut, vecClock); err == nil {
				t.Fatalf("bit %d of byte %d flipped → accepted", bit, i)
			}
		}
	}
	_ = parsed

	// Non-shortest head (version encoded 0x18 0x07): CRC recomputed so the
	// canonicality rule is the only thing under test.
	d, err := decode(mailPDU)
	if err != nil {
		t.Fatal(err)
	}
	nonShortest := append(bytes.Clone(mailPDU[:2]), append([]byte{0x18}, mailPDU[2:]...)...)
	crcHead := d.primaryLen + 1 - 3 // the primary CRC bstr head, shifted by the insert
	c := crc16x25(nonShortest[:crcHead])
	nonShortest[crcHead+1] = byte(c >> 8)
	nonShortest[crcHead+2] = byte(c)
	if _, err := Parse(nonShortest, vecClock); ErrorCode(err) != CodeNonCanonical {
		t.Fatalf("non-shortest head = %v, want code %s", err, CodeNonCanonical)
	}

	// Indefinite-length array head for the primary block.
	indef := bytes.Clone(mailPDU)
	indef[0] = 0x9f
	if _, err := Parse(indef, vecClock); ErrorCode(err) != CodeNonCanonical {
		t.Fatalf("indefinite head = %v, want code %s", err, CodeNonCanonical)
	}

	// A CBOR map where the primary block belongs (the profile has no maps;
	// duplicate keys are unreachable by construction).
	mapHead := append([]byte{0xa1, 0x01, 0x02}, mailPDU...)
	if _, err := Parse(mapHead, vecClock); ErrorCode(err) != CodeStructure {
		t.Fatalf("map head = %v, want code %s", err, CodeStructure)
	}

	// Three blocks: a valid bundle plus a whole second payload block.
	three := append(bytes.Clone(mailPDU), payloadBlock([]byte{0, 1})...)
	if _, err := Parse(three, vecClock); ErrorCode(err) != CodeBlockCount {
		t.Fatalf("three blocks = %v, want code %s", err, CodeBlockCount)
	}

	// Payload block type 2 (an extension block — P-2 closes the surface).
	type2 := bytes.Clone(mailPDU)
	type2[parsed.PrimaryLen+1] = 2
	if _, err := Parse(type2, vecClock); ErrorCode(err) != CodeBlockType {
		t.Fatalf("block type 2 = %v, want code %s", err, CodeBlockType)
	}

	// CRC type ≠ 1 on either block.
	crc0 := bytes.Clone(mailPDU)
	crc0[3] = 0
	if _, err := Parse(crc0, vecClock); ErrorCode(err) != CodeStructure {
		t.Fatalf("primary CRC type 0 = %v, want code %s", err, CodeStructure)
	}

	// Empty and hop-only payload content.
	empty := bundle(primaryBlockDTNms(mailGroupEID, eidNone, eidNone, d.creationDTNms, 0, testTTL), payloadBlock(nil))
	if _, err := Parse(empty, vecClock); ErrorCode(err) != CodeEmptyPayload {
		t.Fatalf("empty content = %v, want code %s", err, CodeEmptyPayload)
	}
	hopOnly := bundle(primaryBlockDTNms(mailGroupEID, eidNone, eidNone, d.creationDTNms, 0, testTTL), payloadBlock([]byte{0}))
	if _, err := Parse(hopOnly, vecClock); ErrorCode(err) != CodeEmptyPayload {
		t.Fatalf("hop-only content = %v, want code %s", err, CodeEmptyPayload)
	}

	// EID anomalies, wired through the real parser with valid CRCs.
	content := append([]byte{0}, envelopeOf(16)...)
	cases := []struct {
		name string
		dest EID
		src  EID
		rpt  EID
	}{
		{"anonymous destination", eidNone, eidNone, eidNone},
		{"group source", mailGroupEID, mailGroupEID, eidNone},
		{"node report-to", mailGroupEID, eidNone, nodeEID(testFP)},
		{"uppercase fp source", mailGroupEID, nodeEID("0123456789ABCDEF"), eidNone},
		{"short fp source", mailGroupEID, nodeEID("01234567"), eidNone},
		{"empty eid source", mailGroupEID, eid{}, eidNone},
		{"both parts source", mailGroupEID, eid{authority: "og." + testFP, local: "x"}, eidNone},
	}
	for _, c := range cases {
		pdu := bundle(primaryBlockDTNms(c.dest, c.src, c.rpt, d.creationDTNms, 0, testTTL), payloadBlock(content))
		if _, err := Parse(pdu, vecClock); ErrorCode(err) != CodeEID {
			t.Fatalf("%s = %v, want code %s", c.name, err, CodeEID)
		}
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex constant: %v", err)
	}
	return b
}
