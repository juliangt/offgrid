package tcpcl

// wire.go — the byte level of the RFC 9174 subset: the §4.2 contact header,
// the one-octet message header with the per-message bodies (§4.5–§6.1), and
// the extension-item TLV container (§4.8/§5.2.5). Every multi-octet integer
// is big-endian with the RFC's exact width (U16/U32/U64). Readers are
// fail-closed: every length is checked against a hard cap BEFORE any
// allocation, so a hostile peer cannot buy memory with a length field.

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
)

// Hard caps for peer-controlled length fields (fail-closed DoS bounds;
// legitimate peers stay far below — a profile bundle is ≤ a few KiB and the
// node EID is exactly 26 bytes). Exceeding a cap is a protocol violation.
const (
	// MaxNodeIDLen bounds the SESS_INIT node ID string (§4.6). The profile
	// EID is 26 bytes; 1024 leaves room for RFC-conforming URIs.
	MaxNodeIDLen = 1024
	// MaxExtItems bounds the extension-item blob of ONE message (session or
	// transfer). This profile sends none; peers that send critical unknown
	// items are refused, non-critical ones skipped — within this cap.
	MaxExtItems = 4096
	// maxInitBody bounds the whole SESS_INIT body read.
	maxInitBody = 2 + 8 + 8 + 2 + MaxNodeIDLen + 4 + MaxExtItems
)

// ContactHeader is the §4.2 exchange opener: magic "dtn!" + version 4 +
// flags (only CAN_TLS is defined).
type ContactHeader struct {
	Version byte
	Flags   byte
}

// EncodeContactHeader renders the 6-byte §4.2 contact header.
func EncodeContactHeader(h ContactHeader) []byte {
	b := make([]byte, 0, 6)
	b = append(b, ContactMagic...)
	b = append(b, h.Version, h.Flags)
	return b
}

// ParseContactHeader decodes the 6-byte contact header. The reserved flag
// bits are ignored per §4.2 ("All reserved header flag bits SHALL be
// ignored by the receiver") — only CAN_TLS is read.
func ParseContactHeader(b []byte) (ContactHeader, error) {
	if len(b) != 6 || string(b[:4]) != ContactMagic {
		return ContactHeader{}, ErrBadMagic
	}
	if b[4] != ProtocolVersion {
		return ContactHeader{}, fmt.Errorf("%w: got %d", ErrBadVersion, b[4])
	}
	return ContactHeader{Version: b[4], Flags: b[5]}, nil
}

// ExtensionItem is one §4.8/§5.2.5 TLV container element.
type ExtensionItem struct {
	Flags byte // bit 0 = CRITICAL
	Type  uint16
	Value []byte
}

// Critical reports the CRITICAL flag (the receiver MUST understand it).
func (it ExtensionItem) Critical() bool { return it.Flags&FlagItemCRITICAL != 0 }

// EncodeExtItems renders an extension-item list: the U32 total length
// followed by the concatenated TLVs. This profile always renders the empty
// list; the encoder exists to parse peers faithfully and to emit the
// Transfer Length Extension.
func EncodeExtItems(items []ExtensionItem) []byte {
	total := 0
	for _, it := range items {
		total += 1 + 2 + 2 + len(it.Value)
	}
	b := make([]byte, 4, 4+total)
	binary.BigEndian.PutUint32(b, uint32(total))
	for _, it := range items {
		b = append(b, it.Flags)
		var t [2]byte
		binary.BigEndian.PutUint16(t[:], it.Type)
		b = append(b, t[:]...)
		var l [2]byte
		binary.BigEndian.PutUint16(l[:], uint16(len(it.Value)))
		b = append(b, l[:]...)
		b = append(b, it.Value...)
	}
	return b
}

// ParseExtItems reads an extension-item list (the caller supplies exactly
// the `length` announced bytes). A list whose items overrun their own
// announced length fails the whole message (§4.6/§5.2.2: "the reception ...
// is considered to have failed").
func ParseExtItems(b []byte) ([]ExtensionItem, error) {
	var items []ExtensionItem
	for len(b) > 0 {
		if len(b) < 5 {
			return nil, fmt.Errorf("%w: truncated extension item header", ErrProtocol)
		}
		it := ExtensionItem{Flags: b[0], Type: binary.BigEndian.Uint16(b[1:3])}
		vl := int(binary.BigEndian.Uint16(b[3:5]))
		b = b[5:]
		if vl > len(b) {
			return nil, fmt.Errorf("%w: extension item value overruns the announced list length", ErrProtocol)
		}
		it.Value = b[:vl]
		b = b[vl:]
		items = append(items, it)
	}
	return items, nil
}

// SessInit is the §4.6 session parameter announcement.
type SessInit struct {
	KeepaliveSec uint16
	SegmentMRU   uint64
	TransferMRU  uint64
	NodeID       string // zero-length = the RFC's "lack of a node ID"
	Extensions   []ExtensionItem
}

// EncodeSESS_INIT renders the full §4.6 message (header included).
func EncodeSESS_INIT(m SessInit) ([]byte, error) {
	if len(m.NodeID) > MaxNodeIDLen {
		return nil, fmt.Errorf("%w: node ID of %d bytes exceeds the cap", ErrProtocol, len(m.NodeID))
	}
	ext := EncodeExtItems(m.Extensions)
	if len(ext)-4 > MaxExtItems {
		return nil, fmt.Errorf("%w: %d bytes of session extension items exceed the cap", ErrProtocol, len(ext)-4)
	}
	b := make([]byte, 0, 1+2+8+8+2+len(m.NodeID)+len(ext))
	b = append(b, MsgSESS_INIT)
	var u16 [2]byte
	var u64 [8]byte
	binary.BigEndian.PutUint16(u16[:], m.KeepaliveSec)
	b = append(b, u16[:]...)
	binary.BigEndian.PutUint64(u64[:], m.SegmentMRU)
	b = append(b, u64[:]...)
	binary.BigEndian.PutUint64(u64[:], m.TransferMRU)
	b = append(b, u64[:]...)
	binary.BigEndian.PutUint16(u16[:], uint16(len(m.NodeID)))
	b = append(b, u16[:]...)
	b = append(b, m.NodeID...)
	b = append(b, ext...)
	return b, nil
}

// ParseSESS_INIT decodes a SESS_INIT body (after the 1-byte message header).
func ParseSESS_INIT(body []byte) (SessInit, error) {
	m := SessInit{}
	if len(body) < 2+8+8+2+4 {
		return m, fmt.Errorf("%w: SESS_INIT truncated", ErrProtocol)
	}
	m.KeepaliveSec = binary.BigEndian.Uint16(body[0:2])
	m.SegmentMRU = binary.BigEndian.Uint64(body[2:10])
	m.TransferMRU = binary.BigEndian.Uint64(body[10:18])
	nidLen := int(binary.BigEndian.Uint16(body[18:20]))
	if nidLen > MaxNodeIDLen {
		return m, fmt.Errorf("%w: node ID length %d exceeds the cap", ErrProtocol, nidLen)
	}
	if 20+nidLen+4 > len(body) {
		return m, fmt.Errorf("%w: SESS_INIT truncated in the node ID", ErrProtocol)
	}
	m.NodeID = string(body[20 : 20+nidLen])
	extLen := int(binary.BigEndian.Uint32(body[20+nidLen : 24+nidLen]))
	if extLen > MaxExtItems {
		return m, fmt.Errorf("%w: session extension items length %d exceeds the cap", ErrProtocol, extLen)
	}
	if 24+nidLen+extLen != len(body) {
		return m, fmt.Errorf("%w: SESS_INIT extension list does not fit the message", ErrProtocol)
	}
	ext, err := ParseExtItems(body[24+nidLen:])
	if err != nil {
		return m, err
	}
	m.Extensions = ext
	return m, nil
}

// SessTerm is the §6.1 termination message.
type SessTerm struct {
	Reply  bool // the REPLY flag: acknowledgment of the peer's SESS_TERM
	Reason TermReason
}

// EncodeSESS_TERM renders header + flags + reason (Figure 27).
func EncodeSESS_TERM(m SessTerm) []byte {
	flags := byte(0)
	if m.Reply {
		flags = FlagTERM_REPLY
	}
	return []byte{MsgSESS_TERM, flags, byte(m.Reason)}
}

// ParseSESS_TERM decodes the 2-byte body.
func ParseSESS_TERM(body []byte) (SessTerm, error) {
	if len(body) != 2 {
		return SessTerm{}, fmt.Errorf("%w: SESS_TERM body must be exactly 2 bytes, got %d", ErrProtocol, len(body))
	}
	return SessTerm{Reply: body[0]&FlagTERM_REPLY != 0, Reason: TermReason(body[1])}, nil
}

// XferSegment is the §5.2.2 transmission message. Extensions is carried
// (and parsed) only when Start is set, per the RFC's conditional field.
type XferSegment struct {
	Start      bool
	End        bool
	TransferID uint64
	Extensions []ExtensionItem // present only on START segments
	Data       []byte
}

// EncodeXFER_SEGMENT renders header, flags, transfer ID, the START-only
// extension fields, the data length and the data (Figure 22).
func EncodeXFER_SEGMENT(m XferSegment) []byte {
	flags := byte(0)
	if m.End {
		flags |= FlagXFER_END
	}
	if m.Start {
		flags |= FlagXFER_START
	}
	b := make([]byte, 0, 1+1+8+4+8+len(m.Data))
	b = append(b, MsgXFER_SEGMENT, flags)
	var u64 [8]byte
	binary.BigEndian.PutUint64(u64[:], m.TransferID)
	b = append(b, u64[:]...)
	if m.Start {
		b = append(b, EncodeExtItems(m.Extensions)...)
	}
	binary.BigEndian.PutUint64(u64[:], uint64(len(m.Data)))
	b = append(b, u64[:]...)
	b = append(b, m.Data...)
	return b
}

// ParseXFER_SEGMENT decodes the message body after the 1-byte header.
// `trailing` returns the data view (the caller must not retain it without
// copying).
func ParseXFER_SEGMENT(body []byte) (XferSegment, error) {
	m := XferSegment{}
	if len(body) < 1+8 {
		return m, fmt.Errorf("%w: XFER_SEGMENT truncated before the data length", ErrProtocol)
	}
	flags := body[0]
	// §5.2.2: all reserved flag bits SHALL be ignored by the receiver — only
	// END (0x01) and START (0x02) are read, whatever else the peer set.
	m.End = flags&FlagXFER_END != 0
	m.Start = flags&FlagXFER_START != 0
	m.TransferID = binary.BigEndian.Uint64(body[1:9])
	off := 9
	if m.Start {
		if len(body) < off+4 {
			return m, fmt.Errorf("%w: START segment truncated before the extension length", ErrProtocol)
		}
		extLen := int(binary.BigEndian.Uint32(body[off : off+4]))
		if extLen > MaxExtItems {
			return m, fmt.Errorf("%w: transfer extension items length %d exceeds the cap", ErrProtocol, extLen)
		}
		off += 4
		if len(body) < off+extLen {
			return m, fmt.Errorf("%w: START segment truncated in the extension list", ErrProtocol)
		}
		ext, err := ParseExtItems(body[off : off+extLen])
		if err != nil {
			return m, err
		}
		m.Extensions = ext
		off += extLen
	}
	if len(body) < off+8 {
		return m, fmt.Errorf("%w: XFER_SEGMENT truncated before the data", ErrProtocol)
	}
	dataLen := binary.BigEndian.Uint64(body[off : off+8])
	if dataLen > uint64(len(body)-off-8) {
		return m, fmt.Errorf("%w: XFER_SEGMENT data length %d exceeds the message", ErrProtocol, dataLen)
	}
	m.Data = body[off+8 : off+8+int(dataLen)]
	return m, nil
}

// XferAck is the §5.2.3 acknowledgment: the flags echo the acknowledged
// segment's flags; the length is cumulative over the transfer.
type XferAck struct {
	Start, End   bool
	TransferID   uint64
	Acknowledged uint64
}

// EncodeXFER_ACK renders Figure 23.
func EncodeXFER_ACK(m XferAck) []byte {
	flags := byte(0)
	if m.End {
		flags |= FlagXFER_END
	}
	if m.Start {
		flags |= FlagXFER_START
	}
	b := make([]byte, 0, 1+1+8+8)
	b = append(b, MsgXFER_ACK, flags)
	var u64 [8]byte
	binary.BigEndian.PutUint64(u64[:], m.TransferID)
	b = append(b, u64[:]...)
	binary.BigEndian.PutUint64(u64[:], m.Acknowledged)
	b = append(b, u64[:]...)
	return b
}

// ParseXFER_ACK decodes the 17-byte body.
func ParseXFER_ACK(body []byte) (XferAck, error) {
	m := XferAck{}
	if len(body) != 1+8+8 {
		return m, fmt.Errorf("%w: XFER_ACK body must be exactly 17 bytes, got %d", ErrProtocol, len(body))
	}
	m.End = body[0]&FlagXFER_END != 0
	m.Start = body[0]&FlagXFER_START != 0
	m.TransferID = binary.BigEndian.Uint64(body[1:9])
	m.Acknowledged = binary.BigEndian.Uint64(body[9:17])
	return m, nil
}

// XferRefuse is the §5.2.4 refusal: reason + transfer ID (Figure 24).
type XferRefuse struct {
	Reason     RefuseReason
	TransferID uint64
}

// EncodeXFER_REFUSE renders Figure 24.
func EncodeXFER_REFUSE(m XferRefuse) []byte {
	b := make([]byte, 0, 1+1+8)
	b = append(b, MsgXFER_REFUSE, byte(m.Reason))
	var u64 [8]byte
	binary.BigEndian.PutUint64(u64[:], m.TransferID)
	return append(b, u64[:]...)
}

// ParseXFER_REFUSE decodes the 9-byte body.
func ParseXFER_REFUSE(body []byte) (XferRefuse, error) {
	m := XferRefuse{}
	if len(body) != 1+8 {
		return m, fmt.Errorf("%w: XFER_REFUSE body must be exactly 9 bytes, got %d", ErrProtocol, len(body))
	}
	m.Reason = RefuseReason(body[0])
	m.TransferID = binary.BigEndian.Uint64(body[1:9])
	return m, nil
}

// MsgReject is the §5.1.2 rejection: reason + a copy of the rejected
// message header.
type MsgReject struct {
	Reason   RejectReason
	Rejected byte
}

// EncodeMSG_REJECT renders Figure 21.
func EncodeMSG_REJECT(m MsgReject) []byte {
	return []byte{MsgMSG_REJECT, byte(m.Reason), m.Rejected}
}

// ParseMSG_REJECT decodes the 2-byte body.
func ParseMSG_REJECT(body []byte) (MsgReject, error) {
	m := MsgReject{}
	if len(body) != 2 {
		return m, fmt.Errorf("%w: MSG_REJECT body must be exactly 2 bytes, got %d", ErrProtocol, len(body))
	}
	m.Reason = RejectReason(body[0])
	m.Rejected = body[1]
	return m, nil
}

// Keepalive is the §5.1.1 single-octet message.
const EncodeKEEPALIVE = MsgKEEPALIVE

// beUint64/putUint64: big-endian U64 (the RFC's integer width everywhere).
func beUint64(b []byte) uint64 { return binary.BigEndian.Uint64(b) }

func putUint64(b []byte, v uint64) { binary.BigEndian.PutUint64(b, v) }

// ---------------------------------------------------------------------------
// The framing reader/writer. Every message is contiguous on the stream and
// self-delimiting; the reader applies the caps BEFORE trusting lengths.
// ---------------------------------------------------------------------------

// readMessage reads one message: the 1-byte header, then the body with the
// per-type size resolution. The `maxData` function supplies the caller's
// bound for XFER_SEGMENT data lengths (the receiver's advertised Segment
// MRU); a violating segment is a protocol error, never a big allocation.
// An UNKNOWN message type is returned as (hdr, nil, nil) — its body length
// is unknowable by definition, so the caller owns the §5.1.2 verdict
// (MSG_REJECT "Message Type Unknown" + close).
func readMessage(r *bufio.Reader, maxData uint64) (byte, []byte, error) {
	hdr, err := r.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	switch hdr {
	case MsgKEEPALIVE, MsgXFER_SEGMENT, MsgXFER_ACK, MsgXFER_REFUSE, MsgSESS_TERM, MsgMSG_REJECT:
		// fixed-size bodies resolved below
	case MsgSESS_INIT:
		// bounded below by maxInitBody
	default:
		return hdr, nil, nil // §5.1.2: the caller rejects and closes
	}

	var bodyLen int
	switch hdr {
	case MsgKEEPALIVE:
		bodyLen = 0
	case MsgSESS_TERM:
		bodyLen = 2
	case MsgMSG_REJECT:
		bodyLen = 2
	case MsgXFER_REFUSE:
		bodyLen = 9
	case MsgXFER_ACK:
		bodyLen = 17
	case MsgSESS_INIT:
		// The peek is side-effect free (bufio), so computing the body size
		// from the fixed prefix twice is one code path.
		n, err := sessInitBodyLen(r)
		if err != nil {
			return hdr, nil, err
		}
		bodyLen = n
	case MsgXFER_SEGMENT:
		n, err := peekSegmentLen(r, maxData)
		if err != nil {
			return hdr, nil, err
		}
		bodyLen = n
	}
	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return hdr, nil, fmt.Errorf("tcpcl: read %s body: %w", msgName(hdr), err)
	}
	return hdr, body, nil
}

// peekSegmentLen resolves the full XFER_SEGMENT body size from the stream
// without consuming it (bufio Peeks), validating the data length against
// maxData first. BODY coordinates (the message header is already
// consumed): [0] flags, [1..8] transfer ID, then (START only) the U32
// extension-items length, then the U64 data length.
func peekSegmentLen(r *bufio.Reader, maxData uint64) (int, error) {
	head, err := r.Peek(1 + 8)
	if err != nil {
		return 0, fmt.Errorf("tcpcl: read XFER_SEGMENT header: %w", err)
	}
	start := head[0]&FlagXFER_START != 0
	off := 1 + 8 // flags + transfer ID
	extLen := 0
	if start {
		extHead, err := r.Peek(off + 4)
		if err != nil {
			return 0, fmt.Errorf("tcpcl: read XFER_SEGMENT extension length: %w", err)
		}
		extLen = int(binary.BigEndian.Uint32(extHead[off : off+4]))
		if extLen > MaxExtItems {
			return 0, fmt.Errorf("%w: transfer extension items length %d exceeds the cap", ErrProtocol, extLen)
		}
		off += 4 + extLen // the length field itself, then the items
	}
	dataHead, err := r.Peek(off + 8)
	if err != nil {
		return 0, fmt.Errorf("tcpcl: read XFER_SEGMENT data length: %w", err)
	}
	dataLen := binary.BigEndian.Uint64(dataHead[off : off+8])
	if dataLen > maxData {
		return 0, fmt.Errorf("%w: XFER_SEGMENT data length %d exceeds the negotiated segment MRU %d", ErrProtocol, dataLen, maxData)
	}
	return off + 8 + int(dataLen), nil
}

// peekSessInitLen validates the SESS_INIT shape without consuming. BODY
// coordinates: [0..1] keepalive, [2..9] segment MRU, [10..17] transfer
// MRU, [18..19] node ID length, then the node ID, then the U32 extension
// items length (behind the variable node ID, so two peeks).
func peekSessInitLen(r *bufio.Reader) (int, error) {
	fixed, err := r.Peek(2 + 8 + 8 + 2)
	if err != nil {
		return 0, fmt.Errorf("tcpcl: read SESS_INIT fixed fields: %w", err)
	}
	nidLen := int(binary.BigEndian.Uint16(fixed[18:20]))
	if nidLen > MaxNodeIDLen {
		return 0, fmt.Errorf("%w: node ID length %d exceeds the cap", ErrProtocol, nidLen)
	}
	tail, err := r.Peek(20 + nidLen + 4)
	if err != nil {
		return 0, fmt.Errorf("tcpcl: read SESS_INIT node ID/extension length: %w", err)
	}
	extLen := int(binary.BigEndian.Uint32(tail[20+nidLen : 24+nidLen]))
	if extLen > MaxExtItems {
		return 0, fmt.Errorf("%w: session extension items length %d exceeds the cap", ErrProtocol, extLen)
	}
	return 2 + 8 + 8 + 2 + nidLen + 4 + extLen, nil
}

// sessInitBodyLen is peekSessInitLen for the body size (the peek is
// side-effect free, so calling it twice is fine and keeps one code path).
func sessInitBodyLen(r *bufio.Reader) (int, error) {
	return peekSessInitLen(r)
}

func msgName(hdr byte) string {
	switch hdr {
	case MsgXFER_SEGMENT:
		return "XFER_SEGMENT"
	case MsgXFER_ACK:
		return "XFER_ACK"
	case MsgXFER_REFUSE:
		return "XFER_REFUSE"
	case MsgKEEPALIVE:
		return "KEEPALIVE"
	case MsgSESS_TERM:
		return "SESS_TERM"
	case MsgMSG_REJECT:
		return "MSG_REJECT"
	case MsgSESS_INIT:
		return "SESS_INIT"
	}
	return fmt.Sprintf("type-0x%02x", hdr)
}

// writeMessage writes a complete message (header + body) in one call. The
// caller holds the write lock and sets the deadline.
func writeMessage(w io.Writer, hdr byte, body []byte) error {
	buf := make([]byte, 0, 1+len(body))
	buf = append(buf, hdr)
	buf = append(buf, body...)
	_, err := w.Write(buf)
	return err
}
