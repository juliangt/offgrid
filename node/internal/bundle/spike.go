// Package bundle hosts the P3.0 measurement spike for the Offgrid BPv7
// profile (issue #33). It is deliberately minimal and dependency-free:
// the canonical CBOR encoder subset, the frozen profile's block builders,
// the §14.3-derived frame-fit math and the standard SX126x LoRa airtime
// formula — exactly enough to MEASURE the byte budgets that
// docs/node-network.md §4/§5 quote. Since P3.2 this package also hosts the
// formal profile codec (bundle.go: Parse/Encode/RewriteHop with
// validate/fail-closed, from the shared vectors) and the promoted CBOR
// reader (reader.go) — the spike's builders above remain their single
// encoding core. The numbers in the spec are transcribed from this code's output:
//
//	go test ./internal/bundle -run TestSpikeDump -v
package bundle

import (
	"crypto/sha256"
	"fmt"
	"time"
)

// ---------------------------------------------------------------------------
// Minimal canonical CBOR encoder (RFC 8949 preferred serialization subset).
// Major types 0/1 (ints), 2 (bstr), 3 (tstr), 4 (array), 5 (map) and 7
// (simple values: false, true, null). No floats, no tags, no indefinite
// lengths, no 64-bit heads for the sizes this profile produces — preferred
// serialization is the rule: every head is the shortest encoding of its
// value, map keys are emitted in ascending encoded order (callers use small
// ascending integer keys, which is automatically canonical).
// ---------------------------------------------------------------------------

type cbor struct{ b []byte }

func (e *cbor) head(major byte, val uint64) {
	switch {
	case val < 24:
		e.b = append(e.b, major<<5|byte(val))
	case val <= 0xff:
		e.b = append(e.b, major<<5|24, byte(val))
	case val <= 0xffff:
		e.b = append(e.b, major<<5|25, byte(val>>8), byte(val))
	case val <= 0xffffffff:
		e.b = append(e.b, major<<5|26, byte(val>>24), byte(val>>16), byte(val>>8), byte(val))
	default:
		e.b = append(e.b, major<<5|27,
			byte(val>>56), byte(val>>48), byte(val>>40), byte(val>>32),
			byte(val>>24), byte(val>>16), byte(val>>8), byte(val))
	}
}

func (e *cbor) uint(v uint64)  { e.head(0, v) }
func (e *cbor) negint(v int64) { e.head(1, uint64(-1-v)) } // v < 0
func (e *cbor) bstr(b []byte)  { e.head(2, uint64(len(b))); e.b = append(e.b, b...) }
func (e *cbor) tstr(s string)  { e.head(3, uint64(len(s))); e.b = append(e.b, s...) }
func (e *cbor) array(n int)    { e.head(4, uint64(n)) }
func (e *cbor) mapHead(n int)  { e.head(5, uint64(n)) }
func (e *cbor) bFalse()        { e.b = append(e.b, 0xf4) }
func (e *cbor) bTrue()         { e.b = append(e.b, 0xf5) }
func (e *cbor) null()          { e.b = append(e.b, 0xf6) }

// Cbor is the canonical CBOR encoder above, exported as a type alias so the
// sibling node-plane packages encode from this ONE implementation instead of
// growing a second one (issue #33 P3.1: the role certificates of
// internal/nodeid; P3.2: the profile codec). An alias — not a wrapper — so
// existing *cbor call sites keep working unchanged.
type Cbor = cbor

// EncodeCbor builds a canonical CBOR byte string with the encoder above:
// build writes exactly one top-level value (the encoder is never reused
// across values). It is the shared entry point for the node-plane packages;
// the spike's own builders below keep calling the type directly.
func EncodeCbor(build func(e *Cbor)) []byte {
	e := &cbor{}
	build(e)
	return e.b
}

// Exported forwarding methods so sibling packages can drive the encoder
// through the Cbor alias from EncodeCbor closures (the unexported names
// above remain the spike's own vocabulary). Pure delegation — no behavior
// of the encoder changes.
func (e *Cbor) Uint(v uint64)  { e.uint(v) }
func (e *Cbor) Negint(v int64) { e.negint(v) }
func (e *Cbor) Bstr(b []byte)  { e.bstr(b) }
func (e *Cbor) Tstr(s string)  { e.tstr(s) }
func (e *Cbor) Array(n int)    { e.array(n) }
func (e *Cbor) MapHead(n int)  { e.mapHead(n) }

// ---------------------------------------------------------------------------
// CRC-16/X.25 — RFC 9171 CRC type code 1 (reflected poly 0x8408, init
// 0xFFFF, xorout 0xFFFF). Check value over the ASCII string "123456789"
// is 0x906E (pinned in spike_test.go).
// ---------------------------------------------------------------------------

func crc16x25(b []byte) uint16 {
	crc := uint16(0xFFFF)
	for _, by := range b {
		crc ^= uint16(by)
		for i := 0; i < 8; i++ {
			if crc&1 != 0 {
				crc = (crc >> 1) ^ 0x8408
			} else {
				crc >>= 1
			}
		}
	}
	return ^crc
}

// appendCRC finishes a block: appends the CRC byte string (bstr of 2 bytes,
// CRC-16/X.25) computed over everything encoded so far (the array head and
// every field before the CRC value — RFC 9171 §4.3.1).
func (e *cbor) appendCRC() {
	c := crc16x25(e.b)
	e.bstr([]byte{byte(c >> 8), byte(c)})
}

// ---------------------------------------------------------------------------
// EIDs (docs/node-network.md §3.2). The profile uses exactly three forms:
//
//	dtn:none          -> CBOR null
//	dtn:og-mail       -> ["", "og-mail"]        (the mail group EID, no authority)
//	dtn://og.<fp>/    -> ["og.<fp>", ""]        (identified node, fp = 16 lowercase hex)
// ---------------------------------------------------------------------------

type eid struct {
	authority string // dtn URI authority ("og.<fp>"); empty for the group form
	local     string // node-specific part ("og-mail") when authority is empty
	none      bool   // dtn:none
}

// eidNone is BPv7's anonymous EID dtn:none.
var eidNone = eid{none: true}

// mailGroupEID is the destination group EID of every mail bundle.
var mailGroupEID = eid{local: "og-mail"}

// nodeEID builds dtn://og.<fp>/ from a 16-lowercase-hex fingerprint
// (first 8 bytes of SHA-256 of the node's Ed25519 key).
func nodeEID(fp string) eid { return eid{authority: "og." + fp} }

func (e *cbor) eid(x eid) {
	if x.none {
		e.null()
		return
	}
	e.array(2)
	if x.authority != "" {
		e.tstr(x.authority)
	} else {
		e.tstr("")
	}
	if x.local != "" {
		e.tstr(x.local)
	} else {
		e.tstr("")
	}
}

// dtnEpochUnix is 2000-01-01T00:00:00Z, the BPv7 DTN time epoch.
const dtnEpochUnix = 946684800

// DTNEpochUnixS is the exported form of the DTN epoch (2000-01-01Z, unix
// seconds): the conversion anchor consumers need to turn a parsed bundle's
// CreationDTNms back into wall-clock time (e.g. the P-6 local expiry of the
// forwarding store, docs/node-network.md §7.5).
const DTNEpochUnixS = int64(dtnEpochUnix)

// dtnTime converts unix seconds to DTN time (milliseconds since the DTN
// epoch, RFC 9171 §4.2.9) as used in the creation timestamp.
func dtnTime(unixSec int64) uint64 { return uint64((unixSec - dtnEpochUnix) * 1000) }

// ---------------------------------------------------------------------------
// Profile block builders (docs/node-network.md §3).
// ---------------------------------------------------------------------------

// hopOctetLimit is the frozen hop limit of the profile (docs/node-network.md
// §3.4): a relay drops a bundle whose hop octet reaches 7. Same bound as the
// §14.1 rule-4 reserved envelope hop_count, so the two planes share the
// semantics even though the node plane carries its own copy (outside the
// envelope bytes — an envelope is never mutated in transit).
const hopOctetLimit = 7

// primaryBlock builds the frozen minimal primary block:
//
//	[7, flags=0, crcType=1, destination, source, reportTo,
//	 [dtnTimeMs, sequence], lifetime] ‖ CRC-16
//
// flags = 0 for every v1 bundle (no fragment, no administrative-record bit —
// management payloads are COSE objects, deliberately not BP admin records).
func primaryBlock(dest, src, reportTo eid, createdUnix int64, sequence, lifetime uint64) []byte {
	return primaryBlockDTNms(dest, src, reportTo, dtnTime(createdUnix), sequence, lifetime)
}

// primaryBlockDTNms is primaryBlock at the DTN-millisecond level: the P3.2
// codec (bundle.go) carries the creation timestamp in DTN time directly, so
// its builder needs the ms form without a unix-seconds round trip. The spike
// builders keep their unix-seconds signature and delegate here — one code
// path, no duplicated block math.
func primaryBlockDTNms(dest, src, reportTo eid, creationDTNms uint64, sequence, lifetime uint64) []byte {
	e := &cbor{}
	e.array(9) // 8 fields + the CRC value
	e.uint(7)  // BPv7 version
	e.uint(0)  // processing control flags
	e.uint(1)  // CRC type: CRC-16/X.25
	e.eid(dest)
	e.eid(src)
	e.eid(reportTo)
	e.array(2)
	e.uint(creationDTNms)
	e.uint(sequence)
	e.uint(lifetime)
	e.appendCRC()
	return e.b
}

// payloadBlock wraps content (the hop octet ‖ PDU) with the canonical
// payload block [1, 0, 0, 1, bstr(content)] ‖ CRC-16.
func payloadBlock(content []byte) []byte {
	e := &cbor{}
	e.array(6) // 5 fields + the CRC value
	e.uint(1)  // block type: payload
	e.uint(0)  // block number: 0 (mandatory, payload only)
	e.uint(0)  // block control flags
	e.uint(1)  // CRC type
	e.bstr(content)
	e.appendCRC()
	return e.b
}

// bundle assembles a complete bundle: primary ‖ payload.
func bundle(primary, payload []byte) []byte {
	out := make([]byte, 0, len(primary)+len(payload))
	out = append(out, primary...)
	out = append(out, payload...)
	return out
}

// MailBundle builds the anonymous mail bundle (docs/node-network.md §3.3):
// destination = dtn:og-mail, source = report-to = dtn:none, payload =
// hop octet ‖ one §14.2 CBOR envelope verbatim. The envelope bytes are
// never parsed, padded or mutated.
func MailBundle(envelope []byte, createdUnix int64, ttl uint64, hop byte) []byte {
	content := make([]byte, 0, 1+len(envelope))
	content = append(content, hop)
	content = append(content, envelope...)
	return bundle(
		primaryBlock(mailGroupEID, eidNone, eidNone, createdUnix, 0, ttl),
		payloadBlock(content),
	)
}

// ManagementBundle builds an identified bundle (role certificates, admin
// commands, capsule chunks, directory records): destination = target node
// EID (or the well-known admin/group EID), source = the issuing node's EID,
// report-to = dtn:none, payload = hop octet ‖ COSE_Sign1 (or the raw signed
// record for self-signed directory cards).
func ManagementBundle(destFP, srcFP string, pdu []byte, createdUnix int64, sequence, ttl uint64, hop byte) []byte {
	content := make([]byte, 0, 1+len(pdu))
	content = append(content, hop)
	content = append(content, pdu...)
	return bundle(
		primaryBlock(nodeEID(destFP), nodeEID(srcFP), eidNone, createdUnix, sequence, ttl),
		payloadBlock(content),
	)
}

// BundleID is the profile's dedup key: SHA-256 over the PDU (the payload
// content AFTER the hop octet). The hop octet is mutable (relays increment
// it), so it is excluded from identity; for mail bundles the PDU is the
// §14.2 envelope verbatim, so bundle identity is 1:1 with envelope identity
// across planes without ever recomputing the user-plane `id`.
func BundleID(pdu []byte) []byte { // returns 32 raw bytes
	sum := sha256.Sum256(pdu)
	return sum[:]
}

// ---------------------------------------------------------------------------
// Frame fit (docs/node-network.md §4): the node-plane window header is the
// §14.3(a) grammar — 1 byte, win_id(4)|idx(2)|total(2) — carrying at most
// 221 B of bundle bytes per frame, at most 4 frames per window.
// ---------------------------------------------------------------------------

const (
	frameWindowPayload = 221 // 222 B frame - 1 B window header
	frameWindowMax     = 4   // total ≤ 4 (2 bits)
	frameWindowCap     = frameWindowPayload * frameWindowMax
)

// frameFit returns the number of node-plane frames a byte string needs.
func frameFit(total int) (frames, capacity int, ok bool) {
	frames = (total + frameWindowPayload - 1) / frameWindowPayload
	return frames, frames * frameWindowPayload, frames <= frameWindowMax
}

// ---------------------------------------------------------------------------
// Handshake message sizing (docs/node-network.md §6). The EDHOC-shaped
// session exchange with fixed-width fields:
//
//	msg1 = [1(suite), 1(curve), g_x(32), 0(c_i)]                    = 38 B
//	msg2 = [g_y(32), 1(c_r), ct2]                                   = 134 B
//	       ct2 = AEAD(K2, th1(8) ‖ id_cred_r(8) ‖ sig_r(64)) = 96 B
//	msg3 = [ct3]                                                    = 91 B
//	       ct3 = AEAD(K3, id_cred_i(8) ‖ sig_i(64))          = 88 B
//
// All three are single-frame at the §14.3 window (221 B) — far under the
// < 3-frames bound the phase requires.
// ---------------------------------------------------------------------------

type handshakeSizes struct{ M1, M2, M3 int }

// HandshakeSizes returns the exact wire lengths of the three session
// messages with the synthetic 64-byte signatures the vectors use.
func HandshakeSizes() handshakeSizes {
	msg1 := func() []byte {
		e := &cbor{}
		e.array(4)
		e.uint(1) // method/suite
		e.uint(1) // curve: X25519
		e.bstr(make([]byte, 32))
		e.uint(0) // c_i
		return e.b
	}()
	// The synthetic 64-byte signatures live inside the ct2/ct3 lengths
	// below (th1 8 + id_cred 8 + sig 64 + tag 16); content is never encoded.
	ct2 := make([]byte, 8+8+64+16) // th1 + id_cred_r + sig_r + AEAD tag
	msg2 := func() []byte {
		e := &cbor{}
		e.array(3)
		e.bstr(make([]byte, 32))
		e.uint(1)
		e.bstr(ct2)
		return e.b
	}()
	ct3 := make([]byte, 8+64+16)
	msg3 := func() []byte {
		e := &cbor{}
		e.array(1)
		e.bstr(ct3)
		return e.b
	}()
	return handshakeSizes{M1: len(msg1), M2: len(msg2), M3: len(msg3)}
}

// ---------------------------------------------------------------------------
// LoRa airtime — the standard SX126x/LoRa formula (Semtech SX126x datasheet
// / AN1200.13), pure math:
//
//	Tsym            = 2^SF / BW
//	Tpreamble       = (n_preamble + 4.25) * Tsym
//	Npayload        = 8 + max(ceil((8*PL - 4*SF + 28 + 16*CRC - 20*IH)
//	                          / (4*(SF - 2*DE))), 0) * (CR + 4)
//	Tair            = Tpreamble + Npayload * Tsym
//
// with PL the payload length in bytes, CR ∈ {1..4} for 4/5..4/8, CRC the
// LoRa PHY payload-CRC flag (1 = present, the profile's default) and IH the
// implicit-header flag (0 = explicit header, the default). DE (low data rate
// optimization) is a parameter; LoraAirtimeAutoDE sets it by the standard
// 16 ms symbol-time rule.
// ---------------------------------------------------------------------------

// LoraAirtime computes time-on-air for explicit-header LoRa.
func LoraAirtime(sf, bwHz, pl, preamble, cr, crc, ih, de int) (time.Duration, error) {
	if sf < 5 || sf > 12 || bwHz <= 0 || pl < 0 || cr < 1 || cr > 4 {
		return 0, fmt.Errorf("lora: invalid parameters sf=%d bw=%d pl=%d cr=%d", sf, bwHz, pl, cr)
	}
	tsymNs := float64(uint64(1)<<uint(sf)) * 1e9 / float64(bwHz)
	denom := 4 * (sf - 2*de)
	if denom <= 0 {
		return 0, fmt.Errorf("lora: degenerate sf=%d de=%d", sf, de)
	}
	num := 8*pl - 4*sf + 28 + 16*crc - 20*ih
	extra := 0
	if num > 0 {
		extra = (num + denom - 1) / denom // integer ceil
	}
	symbols := 8 + extra*(cr+4)
	ns := (float64(preamble)+4.25)*tsymNs + float64(symbols)*tsymNs
	return time.Duration(ns).Round(time.Microsecond), nil
}

// LoraAirtimeAutoDE is LoraAirtime with DE set by the standard rule
// (DE = 1 when the symbol time exceeds 16 ms — SF11/SF12 at BW125).
func LoraAirtimeAutoDE(sf, bwHz, pl int) (time.Duration, error) {
	de := 0
	if float64(uint64(1)<<uint(sf))/float64(bwHz) > 0.016 {
		de = 1
	}
	return LoraAirtime(sf, bwHz, pl, 8, 1, 1, 0, de)
}
