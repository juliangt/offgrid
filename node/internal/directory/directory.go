// Package directory implements the node-plane leg of directory federation
// (docs/node-network.md §9.3, issue #33 P3.8): the signed identity card of
// docs/offline-maintenance.md §3.1 as a bundle payload between nodes, and
// the §3.4 merge/eviction rules VERBATIM, landing in the EXISTING user-plane
// directory storage (the same rows POST /api/v1/directory produces — which
// is what makes the SPA continuity warnings behave identically for a
// federated row and a registered one).
//
// THE SPLIT WITH #37 (stated once, honestly): offline-maintenance §3's CODE
// does not exist — only its design record. This package implements the
// node-to-node path: cards ride the bundle plane (§9.3), the merge rules of
// §3.4 run at every receiving node, and the emission hook is §3.2's
// registration card (wire-compatible, blind-validated at the HTTP door).
// §3.3's mule ferry, its HTTP delta/federate endpoints and the SPA ferry UI
// remain #37's work; both paths converge on the same signed-card semantics.
//
// THE CARD IS §3.1's CARD, BYTE FOR BYTE: the payload a card bundle carries
// is the complete canonical-JSON card of §3.1.1 — the fixed-member object
// with the detached Ed25519 self-signature — exactly what the §3.3 mule
// path and the §3.2 HTTP door mint. One serialization, two transports: a
// node-plane card and a mule-carried card for the same identity at the same
// seq are byte-equal (so §3.4's rule-4 byte comparison means what it says),
// and the §3.1.2 worked vector is a vector here as-is.
package directory

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"

	"offgrid/dtn-node/internal/envelope"
	"offgrid/dtn-node/internal/nodeid"
)

// DirEID is the well-known directory group of §9.3 (dtn://og-dir/): the
// destination every federated card carries. Kept as an alias of
// forward.DirEID's literal so the two can never diverge — directory must
// not import forward (the forward sink consumes THIS package through an
// interface, the §8.5 pattern).
const DirEID = "dtn://og-dir/"

// Bounds of the v1 card (frozen in §9.3 from offline-maintenance §3.1):
const (
	// CardMaxBytes is §3.1's whole-card admission cap: the serialized card
	// MUST be ≤ 1024 bytes at every admission point (the maxPrekeysBytes
	// pattern; the realistic card is ≈ 370 bytes).
	CardMaxBytes = 1024
	// MaxCreatedSkew is the §4.3 skew rule applied to created_ts (§3.1:
	// "≤ merge time + 300"): a receiver drops cards created more than
	// 300 s into its future.
	MaxCreatedSkew = int64(300)
	// SeqMin is the lowest valid issue sequence (§3.1: integer ≥ 1). A
	// card-less directory row has the implied sequence 0 (§3.4 rule 2).
	SeqMin = 1
	// CardBundleLifetime is the bundle lifetime of an emitted card (§3 P-6):
	// 7 days — a card must survive several episodic contacts to cross a
	// partitioned island, and it is refreshed on every republication (§3.2:
	// the client re-publishes on every upsert). Expiry is local, like mail.
	CardBundleLifetime uint64 = 604800
)

// CardSchemaVersion is the card schema version (§3.1: v MUST be 1; an
// unknown v makes the card invalid — the §15-style versioned convention).
const CardSchemaVersion = 1

// Card is a parsed identity card (offline-maintenance §3.1): the field list
// is EXACTLY §3.1's — v, alias, ed, x, ts, seq — with §3.1's own semantics
// per field. §3.1 defines no prev_hash member and none exists here.
//
// The card is SELF-SIGNED: the signature is made and verified with the
// card's own Ed25519 key (ed), so a card is authentic iff it carries a
// valid signature under its own identity — no anchor, no cert, no node
// trust involved (the identity vouches for itself, §3.1.1).
type Card struct {
	V         int
	Alias     string
	Ed25519   []byte // 32 bytes — the §3.1 `ed` identity key (the merge key)
	X25519    []byte // 32 bytes — the §3.1 `x` encryption key (carried data)
	CreatedTS int64  // unix seconds — the §3.1 `ts`
	Seq       uint64 // ≥ 1 — the §3.4 merge ordering key
}

// PubkeyB64 is the card's identity key in the directory's canonical Base64
// (the exact string the directory table keys on — §3.4 rule 1 dedups by
// pubkey).
func (c *Card) PubkeyB64() string {
	return base64.StdEncoding.EncodeToString(c.Ed25519)
}

// X25519B64 is the card's encryption key in the directory's canonical Base64
// (the string an HTTP-registered row stores in x25519).
func (c *Card) X25519B64() string {
	return base64.StdEncoding.EncodeToString(c.X25519)
}

// cardSignedString renders §3.1.1's signed byte string — the exact canonical
// JSON of the six unsigned members in fixed order:
//
//	{"v":1,"alias":<alias>,"ed":<ed>,"x":<x>,"ts":<ts>,"seq":<seq>}
//
// Every variable part is §8.1-ASCII (the alias regex) or standard Base64, so
// no JSON escaping can ever fire and plain concatenation IS the canonical
// form (§3.1.1's own argument).
func cardSignedString(c *Card) []byte {
	b := make([]byte, 0, 200)
	b = append(b, `{"v":1,"alias":"`...)
	b = append(b, c.Alias...)
	b = append(b, `","ed":"`...)
	b = base64.StdEncoding.AppendEncode(b, c.Ed25519)
	b = append(b, `","x":"`...)
	b = base64.StdEncoding.AppendEncode(b, c.X25519)
	b = append(b, `","ts":`...)
	b = strconv.AppendInt(b, c.CreatedTS, 10)
	b = append(b, `,"seq":`...)
	b = strconv.AppendUint(b, c.Seq, 10)
	b = append(b, '}')
	return b
}

// scanCard parses the complete §3.1.1 card — the canonical object with the
// detached signature as the seventh member — enforcing canonicality by
// construction: fixed member order, no whitespace, no escapes (the value
// alphabets are ASCII/Base64), canonical integers (no leading zeros). It
// returns the parsed card, the decoded signature, and signedLen = the length
// of the §3.1.1 signed byte string prefix (the card bytes before `,"sig"`).
func scanCard(card []byte) (*Card, []byte, int, error) {
	bad := func(format string, a ...any) (*Card, []byte, int, error) {
		return nil, nil, 0, fmt.Errorf("directory: card shape: "+format, a...)
	}
	if len(card) == 0 || len(card) > CardMaxBytes {
		return bad("length %d outside [1, %d]", len(card), CardMaxBytes)
	}
	c := &Card{}
	i := 0
	lit := func(s string) error {
		if !bytesHasPrefixAt(card, i, s) {
			return fmt.Errorf("expected %s at offset %d", s, i)
		}
		i += len(s)
		return nil
	}
	b64field := func(name, prefix string, want int) ([]byte, error) {
		if err := lit(prefix); err != nil {
			return nil, err
		}
		start := i
		for i < len(card) && card[i] != '"' {
			i++
		}
		if i >= len(card) {
			return nil, fmt.Errorf("unterminated %s string", name)
		}
		raw := card[start:i]
		// Exactly-want-bytes check, padding-aware: EncodedLen pins the
		// character count, and the decoded length — count the pad
		// characters, DecodedLen alone is only a maximum — pins the size. A
		// 31-byte key encodes to the same 44 characters as a 32-byte one
		// with two pads instead of one, and Decode alone would silently
		// fill only 31 of the 32 output bytes.
		pad := 0
		if len(raw) > 0 && raw[len(raw)-1] == '=' {
			pad = 1
			if len(raw) > 1 && raw[len(raw)-2] == '=' {
				pad = 2
			}
		}
		if len(raw) != base64.StdEncoding.EncodedLen(want) || len(raw)/4*3-pad != want || !isStdB64(raw) {
			return nil, fmt.Errorf("%s must be %d standard-Base64 chars for exactly %d bytes, got %d chars at offset %d", name, base64.StdEncoding.EncodedLen(want), want, len(raw), start)
		}
		out := make([]byte, want)
		if _, err := base64.StdEncoding.Decode(out, raw); err != nil {
			return nil, fmt.Errorf("%s: %v", name, err)
		}
		i++ // the closing quote
		return out, nil
	}
	uintfield := func(name string) (uint64, error) {
		start := i
		for i < len(card) && card[i] >= '0' && card[i] <= '9' {
			i++
		}
		digits := card[start:i]
		if len(digits) == 0 {
			return 0, fmt.Errorf("%s: not a canonical integer at offset %d", name, start)
		}
		if len(digits) > 1 && digits[0] == '0' {
			return 0, fmt.Errorf("%s: leading zero at offset %d (canonical JSON)", name, start)
		}
		v, err := strconv.ParseUint(string(digits), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("%s: %v", name, err)
		}
		return v, nil
	}

	if err := lit(`{"v":1,"alias":"`); err != nil {
		return bad("%v", err)
	}
	c.V = CardSchemaVersion // pinned by the consumed literal itself
	{
		start := i
		for i < len(card) && card[i] != '"' {
			i++
		}
		if i >= len(card) {
			return bad("unterminated alias")
		}
		c.Alias = string(card[start:i])
		if !envelope.ValidAlias(c.Alias) {
			return bad("alias %q does not match the §8.1 alias regex", c.Alias)
		}
		i++ // the closing quote
	}
	var err error
	if c.Ed25519, err = b64field("ed", `,"ed":"`, nodeid.KeyLen); err != nil {
		return bad("%v", err)
	}
	if c.X25519, err = b64field("x", `,"x":"`, nodeid.KeyLen); err != nil {
		return bad("%v", err)
	}
	if err := lit(`,"ts":`); err != nil {
		return bad("%v", err)
	}
	ts, err := uintfield("ts")
	if err != nil {
		return bad("%v", err)
	}
	if ts == 0 {
		return bad("ts must be > 0")
	}
	c.CreatedTS = int64(ts)
	if err := lit(`,"seq":`); err != nil {
		return bad("%v", err)
	}
	if c.Seq, err = uintfield("seq"); err != nil {
		return bad("%v", err)
	}
	if c.Seq < SeqMin {
		return bad("seq must be ≥ %d, got %d", SeqMin, c.Seq)
	}
	signedLen := i // the signed string = card[:i] + the closing brace — in
	// the complete card that brace was replaced by `,"sig":…` (SignCard), so
	// §3.1.1's 153-byte signed string is the prefix PLUS the rebuilt `}`.
	sig, err := b64field("sig", `,"sig":"`, ed25519.SignatureSize)
	if err != nil {
		return bad("%v", err)
	}
	if err := lit(`}`); err != nil {
		return bad("%v", err)
	}
	if i != len(card) {
		return bad("%d trailing bytes after the sig member", len(card)-i)
	}
	return c, sig, signedLen, nil
}

// SignCard mints and signs a card (the §3.1 issuer is the USER's own
// client; the node never signs — it only relays and merges). alias must
// match the §8.1 alias regex, x25519 must be 32 bytes, createdTS > 0 and
// seq ≥ SeqMin — the constructor enforces exactly what a verifier would
// reject outright. Returns the complete §3.1.1 card: the signed string with
// the detached Base64 signature appended as the seventh member.
func SignCard(user nodeid.KeyPair, alias string, x25519 []byte, createdTS int64, seq uint64) ([]byte, error) {
	if len(user.Public) != nodeid.KeyLen {
		return nil, fmt.Errorf("directory: the issuer key must be %d bytes", nodeid.KeyLen)
	}
	if !envelope.ValidAlias(alias) {
		return nil, fmt.Errorf("directory: alias %q is not a valid §8.1 alias", alias)
	}
	if len(x25519) != nodeid.KeyLen {
		return nil, fmt.Errorf("directory: x25519 must be %d bytes, got %d", nodeid.KeyLen, len(x25519))
	}
	if createdTS <= 0 {
		return nil, fmt.Errorf("directory: created_ts must be > 0")
	}
	if seq < SeqMin {
		return nil, fmt.Errorf("directory: seq must be ≥ %d", SeqMin)
	}
	c := &Card{V: CardSchemaVersion, Alias: alias, Ed25519: user.Public, X25519: x25519, CreatedTS: createdTS, Seq: seq}
	signed := cardSignedString(c)
	sig := ed25519.Sign(user.Private, signed)
	card := make([]byte, 0, len(signed)+len(`,"sig":"`)+base64.StdEncoding.EncodedLen(len(sig))+len(`"`)+1)
	card = append(card, signed[:len(signed)-1]...) // strip the closing brace
	card = append(card, `,"sig":"`...)
	card = base64.StdEncoding.AppendEncode(card, sig)
	card = append(card, `"}`...)
	if len(card) > CardMaxBytes {
		return nil, fmt.Errorf("directory: signed card is %d bytes, over the %d-byte cap", len(card), CardMaxBytes)
	}
	return card, nil
}

// ParseCard parses a card's SHAPE (offline-maintenance §3.2's blind
// validation — the HTTP registration door and the stored-card reads use
// this; NO signature verification happens here). Every structural rule of
// §3.1 is enforced by the canonical scan: exact member set and order
// (v, alias, ed, x, ts, seq, sig), v == 1, the alias regex, 32-byte keys,
// sig length 64, created_ts > 0, seq ≥ 1, canonical integers, no
// whitespace, the whole card ≤ CardMaxBytes.
func ParseCard(card []byte) (*Card, error) {
	c, _, _, err := scanCard(card)
	return c, err
}

// VerifyCard verifies a card FOR MERGE (§3.4: "each card verified FIRST
// with its own ed key"; the one trust step the federation input gets):
// ParseCard's shape rules, then the Ed25519 detached self-signature over
// §3.1.1's signed byte string with the card's OWN key, then the §3.1
// created_ts skew rule (ts ≤ now + 300 — a receiver's clock is the
// reference, never the issuer's claim about the future).
func VerifyCard(card []byte, now int64) (*Card, error) {
	c, sig, signedLen, err := scanCard(card)
	if err != nil {
		return nil, err
	}
	// The signed byte string is the unsigned members' prefix with the
	// closing brace rebuilt (§3.1.1); the complete card replaced that brace
	// with the sig member.
	signed := make([]byte, 0, signedLen+1)
	signed = append(signed, card[:signedLen]...)
	signed = append(signed, '}')
	if !ed25519.Verify(c.Ed25519, signed, sig) {
		return nil, errors.New("directory: card verify: signature check failed")
	}
	if c.CreatedTS > now+MaxCreatedSkew {
		return nil, fmt.Errorf("directory: card verify: created_ts %d is more than %d s ahead of the receiver (%d)", c.CreatedTS, MaxCreatedSkew, now)
	}
	return c, nil
}

// CanonicalB64 renders the canonical Base64 text of a card's bytes — the
// exact string the directory table stores in its card column (TEXT, the
// §3.2 storage shape) and the form byte-comparisons decode from.
func CanonicalB64(card []byte) string {
	return base64.StdEncoding.EncodeToString(card)
}

// bytesHasPrefixAt is bytes.HasPrefix at an offset.
func bytesHasPrefixAt(b []byte, at int, prefix string) bool {
	if at+len(prefix) > len(b) {
		return false
	}
	return string(b[at:at+len(prefix)]) == prefix
}

// isStdB64 reports whether every byte is in the standard-Base64 alphabet
// (the padding '=' included — Decode still validates placement).
func isStdB64(b []byte) bool {
	for _, c := range b {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '+', c == '/', c == '=':
		default:
			return false
		}
	}
	return true
}
