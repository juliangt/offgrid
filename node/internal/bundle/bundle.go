package bundle

// The Offgrid BPv7 profile codec (issue #33 P3.2) — docs/node-network.md §3
// rules P-1..P-7 formalized over this package's spike primitives. Encode and
// Parse are strict at both ends of the same frozen shape:
//
//   - P-1: a CBOR sequence of exactly two blocks, canonical CBOR (shortest
//     heads, definite lengths), CRC-16/X.25 (type code 1) over each block;
//   - P-3: primary `[7, 0, 1, destination, source, report-to,
//     [creationDTNms, sequence], lifetime]` + CRC;
//   - P-4/P-5: EIDs per profile — `dtn:none` → null, group `dtn:og-mail` →
//     `["", "og-mail"]`, node `dtn://og.<fp>/` → `["og.<fp>", ""]`;
//   - §3.4: payload content = `hop(1 B) ‖ PDU`, the hop octet capped at 7;
//   - P-6: lifetime > 0 and the ≤ 300 s creation-skew rule at the receiver;
//   - P-7: bundle identity = SHA-256 over the payload content AFTER the hop
//     octet.
//
// Parse validates by re-encoding what it read: a bundle is accepted only
// when its own bytes are the canonical encoding of its parsed fields, so
// non-shortest heads, wrong CRC types and any other byte-level deviation are
// rejected fail-closed (the profile has no CBOR maps, so duplicate map keys
// cannot occur on the wire). The C counterpart (dtn_core's dtn_bundle.c)
// implements the same rejection table and is pinned to this one through the
// shared vectors of tests/vectors/bundle/vectors.json.

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"
)

// MaxFutureSkew is the P-6 admission skew: a bundle whose creation timestamp
// is more than 300 s ahead of the receiver MUST be dropped.
const MaxFutureSkew = 300 * time.Second

const maxFutureSkewMs = uint64(MaxFutureSkew / time.Millisecond)

// Stable failure codes — the shared vocabulary of the Go and C rejection
// tables and of the vectors' expect_code fields. They are part of the
// cross-implementation contract: NEVER rename a code without regenerating
// the vectors and the C side in the same change.
const (
	CodeTruncated    = "truncated"     // the PDU ends mid-value
	CodeStructure    = "bad_structure" // right idea, wrong shape/type/length
	CodeVersion      = "bad_version"   // version ≠ 7 (P-3; RFC 5050 stays out)
	CodeFlags        = "bad_flags"     // processing-control flags ≠ 0 on either block
	CodeCRC          = "bad_crc"       // a block's CRC-16 does not match
	CodeBlockCount   = "block_count"   // not exactly two blocks / trailing bytes
	CodeBlockType    = "unknown_block" // a block this profile does not define
	CodeNonCanonical = "non_canonical" // not the canonical encoding (P-1)
	CodeEID          = "bad_eid"       // an EID outside the §3 profile shapes
	CodeHop          = "hop_limit"     // hop octet > 7, or rewrite at 7 (§3.1)
	CodeSkew         = "future_skew"   // creation > now + 300 s (P-6)
	CodeLifetime     = "bad_lifetime"  // lifetime = 0 (P-6)
	CodeEmptyPayload = "empty_payload" // content is not hop ‖ non-empty PDU
	CodeArgument     = "bad_argument"  // constructor/Encode argument error
)

// ParseError is every rejection this codec produces; Code carries the stable
// code above (ErrorCode extracts it), Off the byte offset when meaningful.
type ParseError struct {
	Code string
	Off  int
	msg  string
}

func (e *ParseError) Error() string { return e.msg }

func errAt(code string, off int, format string, a ...any) error {
	return &ParseError{Code: code, Off: off, msg: fmt.Sprintf(format, a...)}
}

// ErrorCode maps an error to its stable code ("" when err is nil; for any
// non-nil error this package produced, the code is one of the Code*
// constants).
func ErrorCode(err error) string {
	var pe *ParseError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

// ---------------------------------------------------------------------------
// EIDs (docs/node-network.md §3 P-4/P-5). The spike's eid struct, exported
// as an alias: EID values compare with == and render through String.
// ---------------------------------------------------------------------------

// EID is a profile endpoint identifier. The zero value is not valid; use
// ParseEID, the constructors, or the package forms.
type EID = eid

// FingerprintHexLen is the hex length of the node fingerprint inside a node
// EID authority ("og." + 16 lowercase hex, docs/node-network.md §2.1).
const FingerprintHexLen = 16

// eidTokenMax bounds a group/admin token (dtn:og-mail, dtn://og-admin/).
const eidTokenMax = 63

// String renders the dtn URI form: dtn:none, dtn:og-mail, dtn://og.<fp>/.
func (e EID) String() string {
	if e.none {
		return "dtn:none"
	}
	if e.authority != "" {
		return "dtn://" + e.authority + "/"
	}
	return "dtn:" + e.local
}

// IsNone reports the anonymous form (BPv7 dtn:none, CBOR null).
func (e EID) IsNone() bool { return e.none }

// ParseEID parses the three profile URI shapes (and rejects everything
// else): "dtn:none", "dtn:<token>" (group), "dtn://<authority>/" (node,
// admin). Round-trips with EID.String.
func ParseEID(s string) (EID, error) {
	bad := func() (EID, error) {
		return EID{}, errAt(CodeEID, 0, "EID %q is not a profile URI (dtn:none, dtn:<token>, dtn://<authority>/)", s)
	}
	switch {
	case s == "dtn:none":
		return eidNone, nil
	case strings.HasPrefix(s, "dtn://"):
		rest := strings.TrimPrefix(s, "dtn://")
		if !strings.HasSuffix(rest, "/") {
			return bad()
		}
		auth := strings.TrimSuffix(rest, "/")
		if !validEIDToken(auth) && !isNodeAuthority(auth) {
			return bad()
		}
		return eid{authority: auth}, nil
	case strings.HasPrefix(s, "dtn:"):
		ssp := strings.TrimPrefix(s, "dtn:")
		if !validEIDToken(ssp) {
			return bad()
		}
		return eid{local: ssp}, nil
	default:
		return bad()
	}
}

// validEIDToken accepts the profile's endpoint tokens: 1..63 chars of
// [a-z0-9-] starting alphanumeric (og-mail, og-admin). Node authorities
// ("og.<fp>") carry a dot and are validated by isNodeAuthority instead.
func validEIDToken(s string) bool {
	if len(s) == 0 || len(s) > eidTokenMax {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
		default:
			return false
		}
	}
	return s[0] >= 'a' && s[0] <= 'z' || s[0] >= '0' && s[0] <= '9'
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' && c < 'a' || c > 'f' {
			return false
		}
	}
	return len(s) > 0
}

// isNodeAuthority matches the self-certifying node EID authority:
// "og." + 16 lowercase hex (docs/node-network.md §2.1).
func isNodeAuthority(a string) bool {
	if len(a) != 3+FingerprintHexLen || !strings.HasPrefix(a, "og.") {
		return false
	}
	return isLowerHex(a[3:])
}

// validProfileEID: well-formed per profile — none, or exactly one of
// authority/ssp set, each a valid node authority or token.
func validProfileEID(e EID) bool {
	if e.none {
		return true
	}
	if (e.authority == "") == (e.local == "") { // both or neither set
		return false
	}
	if e.authority != "" {
		return isNodeAuthority(e.authority) || validEIDToken(e.authority)
	}
	return validEIDToken(e.local)
}

// validSourceEID: P-4/P-5 — anonymous (null) or an identified node.
func validSourceEID(e EID) bool {
	return e.none || (e.local == "" && isNodeAuthority(e.authority))
}

// validDestinationEID: P-4/P-5 — a group EID, a node EID or the well-known
// admin EID; never anonymous (a bundle to nobody has no plane to ride).
func validDestinationEID(e EID) bool {
	return !e.none && validProfileEID(e)
}

// validReportToEID: the profile pins report-to = dtn:none on both bundle
// classes (P-4/P-5); status-report-style replies are §8.3 application
// objects, not BP administrative records.
func validReportToEID(e EID) bool { return e.none }

// ---------------------------------------------------------------------------
// The Bundle value and the constructors.
// ---------------------------------------------------------------------------

// Bundle is a parsed (or to-be-encoded) profile bundle. Payload is the
// profile ADU after the hop octet — for a parsed bundle it is a VIEW into
// the Parse input; the constructors copy.
type Bundle struct {
	Destination   EID
	Source        EID
	ReportTo      EID
	CreationDTNms uint64 // DTN time, ms since 2000-01-01Z (RFC 9171 §4.2.9)
	Sequence      uint64 // 0 for mail, per-source counter for identified
	Lifetime      uint64 // seconds (P-6: the envelope TTL)
	Hop           byte   // the hop octet, 0..7 (§3.1)
	Payload       []byte // PDU after the hop octet (envelope verbatim for mail)

	// PrimaryLen / ContentOff locate the wire positions of a parsed bundle:
	// the payload block starts at PrimaryLen and the hop octet sits at
	// ContentOff (so the envelope-in-the-verbatim pin of §3.1 is
	// pdu[ContentOff+1 : ContentOff+1+len(Payload)]). Zero for constructed
	// (not yet encoded) bundles.
	PrimaryLen int
	ContentOff int
}

// dtnEpochUnixMs is 2000-01-01T00:00:00Z in unix milliseconds.
const dtnEpochUnixMs = dtnEpochUnix * 1000

func dtnMsOf(unixMs int64) (uint64, error) {
	if unixMs < dtnEpochUnixMs {
		return 0, errAt(CodeArgument, 0, "creation timestamp %d ms precedes the DTN epoch", unixMs)
	}
	return uint64(unixMs - dtnEpochUnixMs), nil
}

// dtnMsOfTime maps a receiver clock reading to DTN ms (clamped at the epoch:
// a pre-2000 clock rejects everything, honestly).
func dtnMsOfTime(now time.Time) uint64 {
	ms := now.UnixMilli() - dtnEpochUnixMs
	if ms < 0 {
		return 0
	}
	return uint64(ms)
}

// NewMail builds the anonymous mail bundle (P-4): destination dtn:og-mail,
// source and report-to dtn:none, sequence 0, lifetime = the envelope TTL,
// payload = the §14.2 envelope bytes (carried verbatim behind the hop octet).
func NewMail(envelope []byte, createdAtUnixMs int64, ttlSec uint64) (*Bundle, error) {
	if len(envelope) == 0 {
		return nil, errAt(CodeEmptyPayload, 0, "mail bundle needs a non-empty envelope")
	}
	ms, err := dtnMsOf(createdAtUnixMs)
	if err != nil {
		return nil, err
	}
	return &Bundle{
		Destination:   mailGroupEID,
		Source:        eidNone,
		ReportTo:      eidNone,
		CreationDTNms: ms,
		Lifetime:      ttlSec,
		Payload:       bytes.Clone(envelope),
	}, nil
}

// NewManagement builds an identified bundle (P-5): source = the issuing
// node's EID (dtn://og.<fp>/), destination = the target node EID or a
// well-known group/admin EID (dtn://og-admin/), report-to = dtn:none,
// payload = the inner PDU (COSE_Sign1, directory card, capsule chunk) behind
// the hop octet. Hop starts at 0; a relaying node owns the increments.
func NewManagement(srcEID, dstEID string, createdAtUnixMs int64, lifetimeSec, seq uint64, inner []byte) (*Bundle, error) {
	src, err := ParseEID(srcEID)
	if err != nil {
		return nil, err
	}
	dst, err := ParseEID(dstEID)
	if err != nil {
		return nil, err
	}
	if !validSourceEID(src) {
		return nil, errAt(CodeEID, 0, "management source must be a node EID dtn://og.<fp>/, got %s", srcEID)
	}
	if !validDestinationEID(dst) {
		return nil, errAt(CodeEID, 0, "management destination must not be anonymous, got %s", dstEID)
	}
	if len(inner) == 0 {
		return nil, errAt(CodeEmptyPayload, 0, "management bundle needs a non-empty inner PDU")
	}
	ms, err := dtnMsOf(createdAtUnixMs)
	if err != nil {
		return nil, err
	}
	return &Bundle{
		Destination:   dst,
		Source:        src,
		ReportTo:      eidNone,
		CreationDTNms: ms,
		Sequence:      seq,
		Lifetime:      lifetimeSec,
		Payload:       bytes.Clone(inner),
	}, nil
}

// Encode serializes b into the canonical two-block PDU. It re-validates the
// bundle so an invalid value can never reach the wire (Encode is the last
// line of defense before admission, not a pretty-printer).
func Encode(b *Bundle) ([]byte, error) {
	if b == nil {
		return nil, errAt(CodeArgument, 0, "nil bundle")
	}
	if !validDestinationEID(b.Destination) {
		return nil, errAt(CodeEID, 0, "destination %q is not a valid profile EID", b.Destination.String())
	}
	if !validSourceEID(b.Source) {
		return nil, errAt(CodeEID, 0, "source %q must be dtn:none or a node EID", b.Source.String())
	}
	if !validReportToEID(b.ReportTo) {
		return nil, errAt(CodeEID, 0, "report-to must be dtn:none in this profile, got %q", b.ReportTo.String())
	}
	if b.Lifetime == 0 {
		return nil, errAt(CodeLifetime, 0, "lifetime must be > 0 (P-6)")
	}
	if b.Hop > hopOctetLimit {
		return nil, errAt(CodeHop, 0, "hop octet %d exceeds the limit %d", b.Hop, hopOctetLimit)
	}
	if len(b.Payload) == 0 {
		return nil, errAt(CodeEmptyPayload, 0, "payload PDU must be non-empty")
	}
	content := make([]byte, 0, 1+len(b.Payload))
	content = append(content, b.Hop)
	content = append(content, b.Payload...)
	return bundle(
		primaryBlockDTNms(b.Destination, b.Source, b.ReportTo, b.CreationDTNms, b.Sequence, b.Lifetime),
		payloadBlock(content),
	), nil
}

// ---------------------------------------------------------------------------
// Parse / RewriteHop / BundleIDOf.
// ---------------------------------------------------------------------------

// decoded is the full structural read of a PDU, before profile-level field
// validation. Offsets locate the relay's touch points (§3.1).
type decoded struct {
	dest, src, rpt EID
	creationDTNms  uint64
	sequence       uint64
	lifetime       uint64
	content        []byte // view: hop octet ‖ PDU
	primaryLen     int    // payload block starts here
	contentOff     int    // hop octet position in the PDU
}

// readerCode maps a CBOR reader failure to the stable codec vocabulary.
// Both sides (Go and C) apply the identical mapping so the shared vectors
// fail identically — including the array/map fit guard, which dtn_cbor.c's
// enter() reports as TRUNCATED.
func readerCode(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "truncated"), strings.Contains(msg, "cannot fit the buffer"):
		return CodeTruncated
	case strings.Contains(msg, "indefinite length"), strings.Contains(msg, "reserved additional info"),
		strings.Contains(msg, "nesting depth"):
		return CodeNonCanonical // definite-length canonical CBOR only (P-1)
	default: // wrong major type, non-UTF-8 tstr, tags/simples
		return CodeStructure
	}
}

// decode performs the structural walk of §3 P-1/P-3: two canonical blocks,
// version 7, flags 0, CRC type 1, both CRCs verified, nothing trailing.
// Profile-field validation (EID shapes, hop, lifetime, skew, content) stays
// with the callers so RewriteHop can skip the receiver-only skew check.
func decode(pdu []byte) (*decoded, error) {
	r := newCborReader(pdu)
	fail := func(err error) (*decoded, error) {
		off := r.Pos()
		var pe *ParseError
		if errors.As(err, &pe) {
			off = pe.Off
		}
		return nil, errAt(readerCode(err), off, "%s", err.Error())
	}

	// ---- primary block: array(9) = 8 fields + the CRC value.
	n, err := r.Array()
	if err != nil {
		return fail(err)
	}
	if n != 9 {
		return nil, errAt(CodeStructure, r.Pos(), "primary block must be array(9) (8 fields + CRC), got array(%d)", n)
	}
	version, err := r.Uint()
	if err != nil {
		return fail(err)
	}
	if version != 7 {
		return nil, errAt(CodeVersion, r.Pos(), "bundle version %d is not 7 (P-3; RFC 5050 is out of profile)", version)
	}
	flags, err := r.Uint()
	if err != nil {
		return fail(err)
	}
	if flags != 0 {
		return nil, errAt(CodeFlags, r.Pos(), "primary processing-control flags must be 0 in v1, got %d", flags)
	}
	crcType, err := r.Uint()
	if err != nil {
		return fail(err)
	}
	if crcType != 1 {
		return nil, errAt(CodeStructure, r.Pos(), "CRC type must be 1 (CRC-16/X.25), got %d", crcType)
	}
	d := &decoded{}
	if d.dest, d.src, d.rpt, err = readEIDs(r); err != nil {
		return nil, err
	}
	creation, err := readCreation(r)
	if err != nil {
		return nil, err
	}
	d.creationDTNms, d.sequence = creation[0], creation[1]
	if d.lifetime, err = r.Uint(); err != nil {
		return fail(err)
	}
	// The primary CRC covers the block bytes up to (not including) the CRC
	// value (RFC 9171 §4.3.1, erratum 8043: only the value bytes are zeroed
	// for computation — here, simply excluded).
	crcOff := r.Pos()
	stored, err := r.Bstr()
	if err != nil {
		return fail(err)
	}
	if len(stored) != 2 {
		return nil, errAt(CodeStructure, crcOff, "primary CRC must be a 2-byte bstr (type code 1), got %d bytes", len(stored))
	}
	if crc16x25(pdu[:crcOff]) != uint16(stored[0])<<8|uint16(stored[1]) {
		return nil, errAt(CodeCRC, crcOff, "primary block CRC mismatch")
	}
	d.primaryLen = r.Pos()
	if r.Done() {
		return nil, errAt(CodeBlockCount, d.primaryLen, "a bundle is exactly two blocks; the payload block is missing")
	}

	// ---- payload block: array(6) = [1, 0, 0, 1, bstr(content), CRC].
	m, err := r.Array()
	if err != nil {
		return fail(err)
	}
	if m != 6 {
		return nil, errAt(CodeStructure, r.Pos(), "payload block must be array(6) (5 fields + CRC), got array(%d)", m)
	}
	blockType, err := r.Uint()
	if err != nil {
		return fail(err)
	}
	if blockType != 1 {
		return nil, errAt(CodeBlockType, r.Pos(), "block type %d is outside this profile (P-2: payload only, no extension blocks)", blockType)
	}
	blockNumber, err := r.Uint()
	if err != nil {
		return fail(err)
	}
	if blockNumber != 0 {
		return nil, errAt(CodeStructure, r.Pos(), "payload block number must be 0, got %d", blockNumber)
	}
	blockFlags, err := r.Uint()
	if err != nil {
		return fail(err)
	}
	if blockFlags != 0 {
		return nil, errAt(CodeFlags, r.Pos(), "payload block control flags must be 0 in v1, got %d", blockFlags)
	}
	payloadCRCType, err := r.Uint()
	if err != nil {
		return fail(err)
	}
	if payloadCRCType != 1 {
		return nil, errAt(CodeStructure, r.Pos(), "payload CRC type must be 1 (CRC-16/X.25), got %d", payloadCRCType)
	}
	content, err := r.Bstr()
	if err != nil {
		return fail(err)
	}
	d.content = content
	// The hop octet sits at the content's own start (after the bstr head),
	// not at the head's start — §3.1's "payload content offset 0".
	d.contentOff = r.Pos() - len(content)
	payloadCRCOff := r.Pos()
	stored, err = r.Bstr()
	if err != nil {
		return fail(err)
	}
	if len(stored) != 2 {
		return nil, errAt(CodeStructure, payloadCRCOff, "payload CRC must be a 2-byte bstr (type code 1), got %d bytes", len(stored))
	}
	if crc16x25(pdu[d.primaryLen:payloadCRCOff]) != uint16(stored[0])<<8|uint16(stored[1]) {
		return nil, errAt(CodeCRC, payloadCRCOff, "payload block CRC mismatch")
	}
	if !r.Done() {
		return nil, errAt(CodeBlockCount, r.Pos(), "a bundle is exactly two blocks; %d trailing bytes", len(pdu)-r.Pos())
	}

	// ---- canonicality (P-1): the input must BE the canonical encoding of
	// what was just read. Re-encoding is the honest check — it catches
	// non-shortest heads and any other preferred-serialization deviation
	// without a hand-rolled head audit. (The profile has no CBOR maps, so
	// duplicate keys cannot occur on the wire.)
	canon := bundle(
		primaryBlockDTNms(d.dest, d.src, d.rpt, d.creationDTNms, d.sequence, d.lifetime),
		payloadBlock(d.content),
	)
	if !bytes.Equal(canon, pdu) {
		return nil, errAt(CodeNonCanonical, 0, "PDU is not the canonical CBOR encoding of its fields (P-1: shortest heads, definite lengths)")
	}
	return d, nil
}

// readEIDs reads destination, source and report-to: each null or the
// two-tstr EID form. Wrong CBOR types are structure errors.
func readEIDs(r *cborReader) (dest, src, rpt EID, err error) {
	readOne := func() (EID, error) {
		if err := r.Null(); err == nil {
			return eidNone, nil
		} else if !isTypeError(err) {
			return EID{}, errAt(readerCode(err), r.Pos(), "%s", err.Error())
		}
		n, err := r.Array()
		if err != nil {
			return EID{}, errAt(readerCode(err), r.Pos(), "%s", err.Error())
		}
		if n != 2 {
			return EID{}, errAt(CodeStructure, r.Pos(), "EID must be null or [authority, ssp], got array(%d)", n)
		}
		auth, err := r.Tstr()
		if err != nil {
			return EID{}, errAt(readerCode(err), r.Pos(), "%s", err.Error())
		}
		ssp, err := r.Tstr()
		if err != nil {
			return EID{}, errAt(readerCode(err), r.Pos(), "%s", err.Error())
		}
		return eid{authority: auth, local: ssp}, nil
	}
	// wrap keeps the inner error's stable code (a truncation inside the EID
	// region must stay "truncated", not become a shape error).
	wrap := func(stage string, err error) error {
		code := ErrorCode(err)
		if code == "" {
			code = CodeStructure
		}
		return errAt(code, r.Pos(), "%s: %s", stage, err.Error())
	}
	if dest, err = readOne(); err != nil {
		return dest, src, rpt, wrap("destination", err)
	}
	if src, err = readOne(); err != nil {
		return dest, src, rpt, wrap("source", err)
	}
	if rpt, err = readOne(); err != nil {
		return dest, src, rpt, wrap("report-to", err)
	}
	return dest, src, rpt, nil
}

func isTypeError(err error) bool {
	// The reader's wrong-value-at-null message ("... expected null (0x..),
	// got 0x..") — as opposed to "truncated (expected null)".
	return strings.Contains(err.Error(), "expected null (")
}

// readCreation reads the [creationDTNms, sequence] pair.
func readCreation(r *cborReader) ([2]uint64, error) {
	var out [2]uint64
	n, err := r.Array()
	if err != nil {
		return out, errAt(readerCode(err), r.Pos(), "creation timestamp: %s", err.Error())
	}
	if n != 2 {
		return out, errAt(CodeStructure, r.Pos(), "creation timestamp must be [dtnMs, sequence], got array(%d)", n)
	}
	if out[0], err = r.Uint(); err != nil {
		return out, errAt(readerCode(err), r.Pos(), "creation ms: %s", err.Error())
	}
	if out[1], err = r.Uint(); err != nil {
		return out, errAt(readerCode(err), r.Pos(), "sequence: %s", err.Error())
	}
	return out, nil
}

// validateProfile applies the P-4..P-6 field rules on top of a structural
// decode. checkSkew is false for relay-side operations (the skew rule is
// admission's, evaluated once at reception — P-6).
func (d *decoded) validateProfile(checkSkew bool, nowDTNms uint64) error {
	if !validDestinationEID(d.dest) {
		return errAt(CodeEID, 0, "destination %q is not a valid profile EID (or is anonymous)", d.dest.String())
	}
	if !validSourceEID(d.src) {
		return errAt(CodeEID, 0, "source %q must be dtn:none or a node EID dtn://og.<fp>/", d.src.String())
	}
	if !validReportToEID(d.rpt) {
		return errAt(CodeEID, 0, "report-to must be dtn:none in this profile, got %q", d.rpt.String())
	}
	if len(d.content) < 2 {
		// content = hop octet ‖ PDU; a missing hop octet or an empty PDU is
		// not a profile bundle (mail: envelope verbatim; mgmt: COSE/card/
		// chunk — never empty).
		return errAt(CodeEmptyPayload, 0, "payload content must be hop octet ‖ non-empty PDU, got %d bytes", len(d.content))
	}
	if d.content[0] > hopOctetLimit {
		return errAt(CodeHop, 0, "hop octet %d exceeds the limit %d (§3.1)", d.content[0], hopOctetLimit)
	}
	if d.lifetime == 0 {
		return errAt(CodeLifetime, 0, "lifetime must be > 0 (P-6)")
	}
	if checkSkew && d.creationDTNms > nowDTNms+maxFutureSkewMs {
		return errAt(CodeSkew, 0, "creation timestamp %d is more than %s ahead of the receiver (%d) — drop (P-6)",
			d.creationDTNms, MaxFutureSkew, nowDTNms)
	}
	return nil
}

// Parse decodes and fully validates a PDU against the profile, `now` being
// the receiver's clock for the P-6 skew rule. On success the returned
// Bundle's Payload (and its PrimaryLen/ContentOff locations) view the input
// bytes; copy if the PDU's lifetime outlives the call.
func Parse(pdu []byte, now time.Time) (*Bundle, error) {
	d, err := decode(pdu)
	if err != nil {
		return nil, err
	}
	if err := d.validateProfile(true, dtnMsOfTime(now)); err != nil {
		return nil, err
	}
	return d.bundle(pdu), nil
}

func (d *decoded) bundle(pdu []byte) *Bundle {
	return &Bundle{
		Destination:   d.dest,
		Source:        d.src,
		ReportTo:      d.rpt,
		CreationDTNms: d.creationDTNms,
		Sequence:      d.sequence,
		Lifetime:      d.lifetime,
		Hop:           d.content[0],
		Payload:       pdu[d.contentOff+1 : d.contentOff+len(d.content)],
		PrimaryLen:    d.primaryLen,
		ContentOff:    d.contentOff,
	}
}

// RewriteHop is the §3.1 relay operation: increment the hop octet in place
// and recompute ONLY the payload block's CRC — the primary block and the
// envelope bytes at offset 1 are never touched. A bundle at the hop limit is
// rejected (the drop semantics); so is anything that does not fully parse.
func RewriteHop(pdu []byte) ([]byte, error) {
	d, err := decode(pdu)
	if err != nil {
		return nil, err
	}
	// Full profile validation except the receiver-only skew rule: a relay
	// rewrites only bundles it would have admitted.
	if err := d.validateProfile(false, 0); err != nil {
		return nil, err
	}
	if d.content[0] >= hopOctetLimit {
		return nil, errAt(CodeHop, d.contentOff, "hop octet reached %d — the bundle is dropped, not forwarded (§3.1)", d.content[0])
	}
	out := bytes.Clone(pdu)
	out[d.contentOff]++
	// The payload block's CRC covers pdu[primaryLen : payloadCRCOff]; only
	// the hop byte inside that range changed, so patch the two CRC bytes.
	crcHeadOff := d.contentOff + len(d.content) // the payload CRC bstr head (0x42)
	c := crc16x25(out[d.primaryLen:crcHeadOff])
	out[crcHeadOff+1] = byte(c >> 8)
	out[crcHeadOff+2] = byte(c)
	return out, nil
}

// BundleIDOf returns the P-7 dedup key of an encoded bundle: SHA-256 over
// the payload content AFTER the hop octet (the mutable byte is excluded, so
// hop rewrites never change a bundle's identity). The input must parse.
// (spike.BundleID is the same digest over already-extracted PDU content.)
func BundleIDOf(pdu []byte) ([32]byte, error) {
	d, err := decode(pdu)
	if err != nil {
		return [32]byte{}, err
	}
	if err := d.validateProfile(false, 0); err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(d.content[1:]), nil
}
