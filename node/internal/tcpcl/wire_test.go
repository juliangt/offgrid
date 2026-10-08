package tcpcl

// wire_test.go — golden bytes for every message codec (the §11 row-h
// codec pins) and the fail-closed caps. The goldens are hand-derived from
// RFC 9174 Figures 16/19/21/22/23/24/27: a regression that shifts one byte
// must fail here, not interop.

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatalf("test golden hex: %v", err)
	}
	return b
}

// TestGoldenContactHeader pins the §4.2 six bytes: "dtn!" + version 4 +
// CAN_TLS.
func TestGoldenContactHeader(t *testing.T) {
	got := EncodeContactHeader(ContactHeader{Version: 4, Flags: FlagCAN_TLS})
	want := mustHex(t, "64746e21 0401")
	if !bytes.Equal(got, want) {
		t.Fatalf("contact header: got %x, want %x", got, want)
	}
	h, err := ParseContactHeader(got)
	if err != nil || h.Version != 4 || h.Flags&FlagCAN_TLS == 0 {
		t.Fatalf("round-trip: %+v err=%v", h, err)
	}
	// Reserved flag bits are ignored (§4.2).
	h, err = ParseContactHeader(mustHex(t, "64746e21 04f1"))
	if err != nil || h.Flags&FlagCAN_TLS == 0 {
		t.Fatalf("reserved bits must be ignored, got %+v err=%v", h, err)
	}
	// Bad magic and wrong version fail closed.
	for _, bad := range []string{"64746e20 0401", "64746e21 0301", "64746e21 04"} {
		if _, err := ParseContactHeader(mustHex(t, bad)); err == nil {
			t.Fatalf("contact header %s must be rejected", bad)
		}
	}
}

// TestGoldenSESS_INIT pins Figure 19: keepalive U16, segment MRU U64,
// transfer MRU U64, node ID U16+data, session extension items U32.
func TestGoldenSESS_INIT(t *testing.T) {
	m := SessInit{
		KeepaliveSec: 30,
		SegmentMRU:   65536,
		TransferMRU:  134217728,
		NodeID:       "dtn://og.0123456789abcdef/",
		Extensions:   nil, // the profile's empty list
	}
	got, err := EncodeSESS_INIT(m)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	want := mustHex(t, "07"+
		"001e"+
		"0000000000010000"+
		"0000000008000000"+
		"001a"+
		"64746e3a2f2f6f672e303132333435363738396162636465662f"+
		"00000000")
	if !bytes.Equal(got, want) {
		t.Fatalf("SESS_INIT: got %x, want %x", got, want)
	}
	back, err := ParseSESS_INIT(got[1:])
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if back.KeepaliveSec != 30 || back.SegmentMRU != 65536 || back.TransferMRU != 134217728 || back.NodeID != m.NodeID {
		t.Fatalf("round-trip mismatch: %+v", back)
	}
	if back.Extensions != nil {
		t.Fatalf("empty extension list must parse to nil, got %+v", back.Extensions)
	}
}

// TestGoldenXFER_SEGMENT pins Figure 22 for the two shapes the sender
// emits: a single-segment transfer (START|END, empty extension list —
// §5.2.5.1 "SHOULD NOT be present") and a multi-segment START carrying the
// Transfer Length Extension (item type 0x0001, U64 total).
func TestGoldenXFER_SEGMENT(t *testing.T) {
	single := EncodeXFER_SEGMENT(XferSegment{
		Start: true, End: true, TransferID: 0, Extensions: nil,
		Data: []byte("abc"),
	})
	wantSingle := mustHex(t, "01"+
		"03"+
		"0000000000000000"+
		"00000000"+
		"0000000000000003"+
		"616263")
	if !bytes.Equal(single, wantSingle) {
		t.Fatalf("single-segment: got %x, want %x", single, wantSingle)
	}

	multi := EncodeXFER_SEGMENT(XferSegment{
		Start: true, End: false, TransferID: 7,
		Extensions: []ExtensionItem{{Type: ExtensionTransferLength, Value: mustHex(t, "0000000000001234")}},
		Data:       []byte("hi"),
	})
	wantMulti := mustHex(t, "01"+
		"02"+
		"0000000000000007"+
		"0000000d"+ // one item: 1 flags + 2 type + 2 len + 8 value
		"00 0001 0008 0000000000001234"+
		"0000000000000002"+
		"6869")
	if !bytes.Equal(multi, wantMulti) {
		t.Fatalf("multi START: got %x, want %x", multi, wantMulti)
	}

	cont := EncodeXFER_SEGMENT(XferSegment{TransferID: 7, Data: []byte("!")})
	wantCont := mustHex(t, "01"+"00"+"0000000000000007"+"0000000000000001"+"21")
	if !bytes.Equal(cont, wantCont) {
		t.Fatalf("continuation: got %x, want %x", cont, wantCont)
	}

	back, err := ParseXFER_SEGMENT(wantMulti[1:])
	if err != nil {
		t.Fatalf("parse multi: %v", err)
	}
	if !back.Start || back.End || back.TransferID != 7 || len(back.Extensions) != 1 ||
		back.Extensions[0].Type != ExtensionTransferLength || back.Extensions[0].Critical() {
		t.Fatalf("round-trip mismatch: %+v", back)
	}
	if !bytes.Equal(back.Extensions[0].Value, mustHex(t, "0000000000001234")) {
		t.Fatalf("length extension value: %x", back.Extensions[0].Value)
	}
	if !bytes.Equal(back.Data, []byte("hi")) {
		t.Fatalf("data: %q", back.Data)
	}
}

// TestGoldenSmallMessages pins XFER_ACK (Figure 23), XFER_REFUSE
// (Figure 24), SESS_TERM (Figure 27), MSG_REJECT (Figure 21) and
// KEEPALIVE (§5.1.1).
func TestGoldenSmallMessages(t *testing.T) {
	ack := EncodeXFER_ACK(XferAck{Start: true, TransferID: 5, Acknowledged: 100})
	if want := mustHex(t, "02 02 0000000000000005 0000000000000064"); !bytes.Equal(ack, want) {
		t.Fatalf("XFER_ACK: got %x, want %x", ack, want)
	}
	back, err := ParseXFER_ACK(ack[1:])
	if err != nil || !back.Start || back.TransferID != 5 || back.Acknowledged != 100 {
		t.Fatalf("XFER_ACK round-trip: %+v err=%v", back, err)
	}

	ref := EncodeXFER_REFUSE(XferRefuse{Reason: RefuseNoResources, TransferID: 5})
	if want := mustHex(t, "03 02 0000000000000005"); !bytes.Equal(ref, want) {
		t.Fatalf("XFER_REFUSE: got %x, want %x", ref, want)
	}
	backRef, err := ParseXFER_REFUSE(ref[1:])
	if err != nil || backRef.Reason != RefuseNoResources || backRef.TransferID != 5 {
		t.Fatalf("XFER_REFUSE round-trip: %+v err=%v", backRef, err)
	}

	term := EncodeSESS_TERM(SessTerm{Reason: TermBusy})
	if want := mustHex(t, "05 00 03"); !bytes.Equal(term, want) {
		t.Fatalf("SESS_TERM: got %x, want %x", term, want)
	}
	reply := EncodeSESS_TERM(SessTerm{Reply: true, Reason: TermBusy})
	if want := mustHex(t, "05 01 03"); !bytes.Equal(reply, want) {
		t.Fatalf("SESS_TERM reply: got %x, want %x", reply, want)
	}

	rej := EncodeMSG_REJECT(MsgReject{Reason: RejectUnexpected, Rejected: 0x03})
	if want := mustHex(t, "06 03 03"); !bytes.Equal(rej, want) {
		t.Fatalf("MSG_REJECT: got %x, want %x", rej, want)
	}

	if EncodeKEEPALIVE != 0x04 {
		t.Fatalf("KEEPALIVE must be the single octet 0x04, got 0x%02x", EncodeKEEPALIVE)
	}
}

// TestFailClosedCaps proves the reader never trusts a peer length: node
// IDs, extension blobs and segment data beyond the caps are protocol
// errors, not allocations.
func TestFailClosedCaps(t *testing.T) {
	// SESS_INIT with a node ID length over the cap.
	big := make([]byte, 1+2+8+8+2+4)
	big[0] = MsgSESS_INIT
	big[19] = 0x10 // node ID length high byte: 0x1000 > MaxNodeIDLen
	if _, err := ParseSESS_INIT(big[1:]); err == nil || !strings.Contains(err.Error(), "cap") {
		t.Fatalf("oversize node ID must be rejected with the cap error, got %v", err)
	}
	// SESS_INIT whose extension list does not fit the message.
	evil := append([]byte{}, mustHex(t, "07 001e 0000000000010000 0000000008000000 0000 00000001")...)
	if _, err := ParseSESS_INIT(evil[1:]); err == nil {
		t.Fatalf("extension list must fit the message exactly")
	}
	// XFER_SEGMENT data length over the framing cap (the reader's maxData).
	tricky := append([]byte{}, mustHex(t, "01 00 0000000000000000")...)
	tricky = append(tricky, mustHex(t, "ffffffffffffffff")...)
	if _, err := ParseXFER_SEGMENT(tricky[1:]); err == nil {
		t.Fatalf("data length beyond the message must be rejected")
	}
	// The framing reader rejects an oversized segment before allocation.
	r := bufio.NewReaderSize(bytes.NewReader(tricky), readBufSize)
	if _, _, err := readMessage(r, 64); err == nil || !strings.Contains(err.Error(), "segment MRU") {
		t.Fatalf("framing must enforce the segment MRU, got %v", err)
	}
	// START segment whose extension items length exceeds the cap.
	evilExt := append([]byte{}, mustHex(t, "01 02 0000000000000000")...)
	evilExt = append(evilExt, mustHex(t, "00010000")...) // 65536 > MaxExtItems
	evilExt = append(evilExt, make([]byte, 8)...)
	r2 := bufio.NewReaderSize(bytes.NewReader(evilExt), readBufSize)
	if _, _, err := readMessage(r2, 1024); err == nil || !strings.Contains(err.Error(), "cap") {
		t.Fatalf("framing must enforce the extension cap, got %v", err)
	}
	// A truncated extension item list fails the whole message.
	if _, err := ParseExtItems([]byte{0x00, 0x00, 0x01}); err == nil {
		t.Fatalf("truncated extension item must fail")
	}
	// An unknown message type surfaces to the caller unfired (its body
	// length is unknowable): the §5.1.2 verdict — MSG_REJECT + close — is
	// the read loop's, not the framing reader's.
	r3 := bufio.NewReaderSize(bytes.NewReader([]byte{0x42}), readBufSize)
	hdr, body, err := readMessage(r3, 1024)
	if err != nil || hdr != 0x42 || body != nil {
		t.Fatalf("unknown message type must surface as (hdr, nil, nil), got (%d, %x, %v)", hdr, body, err)
	}
}

// TestExtItemCriticalFlag pins the §5.2.5 CRITICAL bit semantics on the
// item container itself.
func TestExtItemCriticalFlag(t *testing.T) {
	items := []ExtensionItem{{Flags: FlagItemCRITICAL, Type: 0x8001, Value: []byte{1}}}
	raw := EncodeExtItems(items)
	if want := mustHex(t, "00000006 01 8001 0001 01"); !bytes.Equal(raw, want) {
		t.Fatalf("ext items: got %x, want %x", raw, want)
	}
	back, err := ParseExtItems(raw[4:])
	if err != nil || len(back) != 1 || !back[0].Critical() || back[0].Type != 0x8001 {
		t.Fatalf("round-trip: %+v err=%v", back, err)
	}
}
