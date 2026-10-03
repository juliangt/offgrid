// Package envelope defines the DTN envelope wire format (Phase 1, JSON) and
// its server-side validation rules.
//
// The format is normatively specified in docs/protocolo.md §3 (fields),
// §8.2 (payload size bounds) and §10.5 (push-path validation). The node is a
// blind intermediary: it validates structure only — it MUST NOT decrypt
// payloads, verify signatures, or require id recomputation (§6.2).
package envelope

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
)

// Envelope is the atomic transport unit of the off-grid DTN: one encrypted
// message plus routing metadata. It is immutable once created. The JSON tags
// are exactly the six field names of the Phase 1 wire format (§3.1) and their
// declaration order here matches the fixed canonical member order used for
// hashing the envelope id (§5.2) — never serialize this struct's fields
// through a map (map keys are sorted alphabetically and would produce the
// wrong hashed byte string).
//
// # Phase 2/3 evolution mapping (Module D, part 1 — spec §14)
//
// The semantic fields below are FROZEN across all three phases: no field is
// ever repurposed (§14.1). Sign-then-encrypt is invariant: the sender's
// Ed25519 signature and alias always travel inside the ciphertext. What
// changes per phase is only the transport encoding.
//
//	Phase 1 (this struct, JSON over HTTP/Wi-Fi):
//	  v, id, dest_hint, created_at, ttl, payload — hex ids and Base64 payload
//	  as text. hop_count is always ABSENT (absent == 0); it never appears in
//	  Phase 1 code paths.
//
//	Phase 2 — BLE L2CAP CoC (bitchat alignment, §14.2):
//	  Transport: Bluetooth LE Credit-Based Flow Control over a
//	  Connection-Oriented Channel (one CoC per peer, fixed dynamic PSM
//	  advertised out-of-band). Frame layout: length(2 bytes, big-endian) ||
//	  CBOR envelope; the L2CAP layer segments/reassembles, one envelope = one
//	  SDU; negotiated MTU >= 512 B, so the max binary envelope (399 B, §14.3)
//	  plus the 2-byte length prefix fits a single SDU.
//	  JSON → CBOR mapping (canonical CBOR, RFC 8949 preferred serialization,
//	  integer map keys ascending):
//
//	    CBOR key   JSON field    CBOR type       Notes
//	    0          v             uint            constant 1
//	    1          id            bstr (32 B)     SHA-256 bytes (hex decoded)
//	    2          dest_hint     bstr (8 B)      raw 8 bytes (hex decoded)
//	    3          created_at    uint            unix seconds
//	    4          ttl           uint            seconds
//	    5          payload       bstr            eph_pub || nonce || box
//	    6          hop_count     uint (0–7)      optional; absent == 0
//
//	  hop_count semantics (reserved, §14.1): number of peer-to-peer relays,
//	  incremented by each relaying phone, envelope dropped at 7. Constant 0
//	  (absent) in Phase 1.
//
//	Phase 3 — LoRa P2P SX1262 at 915 MHz (§14.3):
//	  Radio frames carry at most 222 bytes. The binary envelope is the Phase 2
//	  CBOR map. Size math with M = |m|, A = |a|, h(n) = 0 if n < 24 else 1:
//
//	    inner_cbor  = 111 + M + A + h(M) + h(A)
//	    L (payload) = 32 (eph) + 24 (nonce) + (inner_cbor + 16 MAC)
//	    envelope    = 59 + (2 if L <= 255 else 3) + L
//	    floor (M=0, A=0): 244 B; max (M=128, A=24): 399 B
//
//	  222 B can never carry the general envelope, so Phase 3 fragments it into
//	  2 radio frames, each prefixed with a 1-byte fragment header followed by
//	  up to 221 bytes of envelope bytes (2 x 221 = 442 >= 399, so every
//	  Phase 1-legal message fits 2 frames):
//
//	    bit 7..4   bit 3..2   bit 1..0
//	    win_id(4)  idx(2)     total(2)
//
//	  win_id is a random per-message window tag; idx is the zero-based fragment
//	  index; total the fragment count (1–4). Reassembly concatenates by idx
//	  within (win_id, total). A "short message" single-frame mode (M <= 48,
//	  no id/dest_hint/alias) also exists; see spec §14.3(b).
//
//	  In both phases the id is either transported raw (bstr, the hex decoded)
//	  or recomputed from frame bytes (short mode); dest_hint derivation is
//	  stable through Phase 3 (rotating-hint HKDF is a Phase 2 privacy upgrade
//	  that swaps only the derivation, §13.3).
type Envelope struct {
	V         int64  `json:"v"`          // format version, MUST be 1
	ID        string `json:"id"`         // 64 lowercase hex; client-computed SHA-256 of the §5.2 canonical subset (opaque dedup key to the node)
	DestHint  string `json:"dest_hint"`  // 16 lowercase hex; first 8 bytes of SHA-256(recipient X25519 public key) (§6.1)
	CreatedAt int64  `json:"created_at"` // unix seconds (UTC); > 0 and <= now + 300 at ingestion (§10.5)
	TTL       int64  `json:"ttl"`        // seconds; within [3600, 2592000] (§8.1)
	Payload   string `json:"payload"`    // Base64 (RFC 4648 standard alphabet, with padding) of eph_pub(32) || nonce(24) || box(...); decoded length within [248, 400] (§8.2)
}

const (
	// MinTTL and MaxTTL bound the envelope time-to-live in seconds
	// (1 hour to 30 days, §8.1).
	MinTTL = 3600
	MaxTTL = 2592000

	// ClockSkewSeconds is how far into the future created_at may be at
	// ingestion time and still be accepted (§3.1, §10.5).
	ClockSkewSeconds = 300

	// MinPayloadLen / MaxPayloadLen bound the DECODED payload size in bytes
	// (§8.2): payload = eph_pub(32) + nonce(24) + box, where box is
	// inner_json (>= 176 B) + 16-byte Poly1305 MAC -> floor 248 B, and
	// inner_json <= 128 (m) + 24 (a) fixed-part bytes -> max 400 B.
	MinPayloadLen = 248
	MaxPayloadLen = 400
)

var (
	idRe       = regexp.MustCompile(`^[0-9a-f]{64}$`)
	destHintRe = regexp.MustCompile(`^[0-9a-f]{16}$`)
	// AliasRe is the binding alias pattern of §4.1/§8.1, enforced by the node
	// on directory writes (and by the client on registration).
	AliasRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,24}$`)
)

// ValidAlias reports whether s is a well-formed user alias
// (^[A-Za-z0-9_.-]{1,24}$). Shared by the API layer for directory
// sanitization.
func ValidAlias(s string) bool {
	return AliasRe.MatchString(s)
}

// validPayload checks that p is valid RFC 4648 standard-alphabet Base64 with
// canonical padding (no whitespace, no URL-safe characters, zero trailing
// padding bits) and that its decoded length lies within the normative bounds
// of §8.2.
func validPayload(p string) error {
	if p == "" {
		return fmt.Errorf("payload is empty")
	}
	// encoding/base64 ignores \r and \n even in Strict mode; the wire format
	// forbids them, so reject them before decoding.
	if strings.ContainsAny(p, "\r\n") {
		return fmt.Errorf("payload contains newline characters")
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(p)
	if err != nil {
		return fmt.Errorf("payload is not valid padded standard Base64: %w", err)
	}
	if n := len(decoded); n < MinPayloadLen || n > MaxPayloadLen {
		return fmt.Errorf("payload decoded length %d is outside [%d, %d]", n, MinPayloadLen, MaxPayloadLen)
	}
	return nil
}

// Validate checks the envelope against every server-side rule of §10.5:
// v == 1; id matches ^[0-9a-f]{64}$; dest_hint matches ^[0-9a-f]{16}$;
// created_at is > 0 and <= now+300; ttl is within [3600, 2592000]; payload is
// valid padded standard Base64 whose decoded length is within [248, 400].
//
// now is the server's current unix time in seconds. The node never inspects
// the encrypted inner payload and never recomputes id (§6.2).
func (e Envelope) Validate(now int64) error {
	if e.V != 1 {
		return fmt.Errorf("unsupported version %d (must be 1)", e.V)
	}
	if !idRe.MatchString(e.ID) {
		return fmt.Errorf("id must be 64 lowercase hex characters")
	}
	if !destHintRe.MatchString(e.DestHint) {
		return fmt.Errorf("dest_hint must be 16 lowercase hex characters")
	}
	if e.CreatedAt <= 0 {
		return fmt.Errorf("created_at must be a positive unix timestamp")
	}
	if maxCreated := now + ClockSkewSeconds; e.CreatedAt > maxCreated {
		return fmt.Errorf("created_at %d is more than %d s in the future", e.CreatedAt, ClockSkewSeconds)
	}
	if e.TTL < MinTTL || e.TTL > MaxTTL {
		return fmt.Errorf("ttl %d is outside [%d, %d]", e.TTL, MinTTL, MaxTTL)
	}
	if err := validPayload(e.Payload); err != nil {
		return err
	}
	return nil
}
