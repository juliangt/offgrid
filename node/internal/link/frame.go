// frame.go — the §5.4 node-plane link frame: a 1-byte header
// [version(2) | type(3) | flags(3)] ‖ payload (≤ 222 B) ‖ [16 B AEAD tag
// for session-protected types]. The exact byte layout is frozen here and
// in the spec's 1.3.0 precision note:
//
//	bit 7..6  version   (1)
//	bit 5..3  type      (0 = beacon, 1 = session, 2 = mail-win, 3 = bundle-frag)
//	bit 2..0  flags     (0 in v1; nonzero fails closed)
//
// Encrypted types protect the payload with the §6.2 session AEAD, the
// header byte as AAD; beacons are plaintext with fixed content (§6.1:
// links without a verified session carry nothing but beacons). The C
// mirror is dtn_frame.c; the shared "frame" vectors pin both sides.
package link

import (
	"fmt"

	"offgrid/dtn-node/internal/nodeid"
)

// Frame layer constants (§5.4, frozen; 1.3.0 precision note).
const (
	FrameVersion = 1
	// FramePayloadMax is the PLAINTEXT budget per frame: the bundle-frag
	// window needs 1 B window header + 221 B window content (§4.1's
	// 221 B/frame, which the §4.1 capacity table freezes). §5.4's "≤ 220 B"
	// predates that arithmetic and is corrected to 222 in the changelog.
	FramePayloadMax = 222
	// FrameOnAirMax is the on-air size bound for session types:
	// 1 B header ‖ 13 B nonce ‖ ≤ 222 B ciphertext ‖ 16 B tag = 252 ≤ the
	// SX126x 255-byte radio limit (beacons: 1 + 9).
	FrameOnAirMax = 1 + NonceLen + FramePayloadMax + TagLen
)

// FrameType is the 3-bit type field.
type FrameType byte

const (
	TypeBeacon     FrameType = 0 // plaintext, fixed content, no session
	TypeSession    FrameType = 1 // session-protected control plane
	TypeMailWin    FrameType = 2 // session-protected mail window frames
	TypeBundleFrag FrameType = 3 // session-protected bundle chunk windows
)

// frameTypeEncrypted reports whether the type carries a session AEAD tag.
func (t FrameType) encrypted() bool { return t != TypeBeacon }

func (t FrameType) String() string {
	switch t {
	case TypeBeacon:
		return "beacon"
	case TypeSession:
		return "session"
	case TypeMailWin:
		return "mail-win"
	case TypeBundleFrag:
		return "bundle-frag"
	}
	return fmt.Sprintf("frame-type(%d)", byte(t))
}

// Frame errors (stable code strings double as the shared-vector verdicts).
var (
	ErrFrameTruncated = fmt.Errorf("link: frame truncated")
	ErrFrameVersion   = fmt.Errorf("link: frame version not 1")
	ErrFrameType      = fmt.Errorf("link: frame type unknown")
	ErrFrameFlags     = fmt.Errorf("link: frame flags nonzero in v1")
	ErrFrameOversize  = fmt.Errorf("link: frame payload exceeds 222 B")
	ErrFrameAuth      = fmt.Errorf("link: frame AEAD open failed")
)

// EncodeHeader builds the 1-byte header.
func EncodeHeader(typ FrameType, flags byte) byte {
	return FrameVersion<<6 | byte(typ)<<3 | flags&0x07
}

// ParseHeader splits the 1-byte header, fail-closed on every reserved or
// unknown value.
func ParseHeader(h byte) (typ FrameType, flags byte, err error) {
	if v := h >> 6; v != FrameVersion {
		return 0, 0, fmt.Errorf("%w: 0x%02x carries version %d", ErrFrameVersion, h, v)
	}
	typ = FrameType((h >> 3) & 0x07)
	if typ > TypeBundleFrag {
		return 0, 0, fmt.Errorf("%w: type %d", ErrFrameType, typ)
	}
	flags = h & 0x07
	if flags != 0 {
		return 0, 0, fmt.Errorf("%w: flags 0x%02x", ErrFrameFlags, flags)
	}
	return typ, flags, nil
}

// EncodeFrame builds header ‖ payload (plaintext types) — for encrypted
// types use SealFrame.
func EncodeFrame(typ FrameType, payload []byte) ([]byte, error) {
	if len(payload) > FramePayloadMax {
		return nil, fmt.Errorf("%w: %d B %s payload", ErrFrameOversize, len(payload), typ)
	}
	out := make([]byte, 0, 1+len(payload))
	out = append(out, EncodeHeader(typ, 0))
	return append(out, payload...), nil
}

// ParseFrame splits header ‖ payload without authenticating (beacons use
// this; session types go through OpenFrame).
func ParseFrame(b []byte) (typ FrameType, payload []byte, err error) {
	if len(b) < 1 {
		return 0, nil, fmt.Errorf("%w: no header byte", ErrFrameTruncated)
	}
	typ, _, err = ParseHeader(b[0])
	if err != nil {
		return 0, nil, err
	}
	payload = b[1:]
	// The WIRE payload of session types is nonce ‖ ciphertext ‖ tag; the
	// plaintext budget applies to the ciphertext only.
	if wireMax := FramePayloadMax; !typ.encrypted() {
		if len(payload) > wireMax {
			return 0, nil, fmt.Errorf("%w: %d B payload", ErrFrameOversize, len(payload))
		}
	} else {
		if len(payload) > NonceLen+FramePayloadMax+TagLen {
			return 0, nil, fmt.Errorf("%w: %d B %s wire payload", ErrFrameOversize, len(payload), typ)
		}
		if len(payload) < NonceLen+TagLen {
			return 0, nil, fmt.Errorf("%w: %s frame carries %d B, want ≥ %d", ErrFrameTruncated, typ, len(payload), NonceLen+TagLen)
		}
	}
	return typ, payload, nil
}

// SealFrame protects one outgoing frame: the session seals the payload
// (nonce ‖ ciphertext ‖ tag) with the header byte as AAD; the frame is
// header ‖ sealed. The plaintext budget is FramePayloadMax.
func SealFrame(s *Session, typ FrameType, payload []byte) ([]byte, error) {
	if !typ.encrypted() {
		return nil, fmt.Errorf("link: %s frames are plaintext by definition", typ)
	}
	if len(payload) > FramePayloadMax {
		return nil, fmt.Errorf("%w: %d B plaintext payload", ErrFrameOversize, len(payload))
	}
	head := EncodeHeader(typ, 0)
	sealed, err := s.Seal([]byte{head}, payload)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 1+len(sealed))
	out = append(out, head)
	return append(out, sealed...), nil
}

// OpenFrame authenticates and opens one incoming frame. Beacons parse
// directly (ParseFrame); everything else must carry a valid session AEAD.
// The wire payload (nonce ‖ ciphertext ‖ tag) goes straight to the
// session, which owns the sequence/replay discipline.
func OpenFrame(s *Session, b []byte) (typ FrameType, payload []byte, err error) {
	typ, payload, err = ParseFrame(b)
	if err != nil {
		return 0, nil, err
	}
	if !typ.encrypted() {
		return 0, nil, fmt.Errorf("link: %s frames are plaintext — use ParseFrame", typ)
	}
	pt, err := s.Open([]byte{b[0]}, payload)
	if err != nil {
		return 0, nil, fmt.Errorf("%w: %v", ErrFrameAuth, err)
	}
	return typ, pt, nil
}

// BeaconVersion is the beacon payload's first byte (fail-closed forward
// compatibility: an unknown beacon version is rejected, not guessed).
const BeaconVersion = 1

// BeaconPayload is the fixed plaintext beacon content: version ‖ the 8-byte
// node fingerprint (the §6.1 "nothing but beacons" minimum: enough for a
// peer to learn WHICH node is awake, nothing else).
func BeaconPayload(fp [nodeid.FingerprintLen]byte) []byte {
	b := make([]byte, 0, 1+nodeid.FingerprintLen)
	b = append(b, BeaconVersion)
	return append(b, fp[:]...)
}

// ParseBeacon validates fixed beacon content and returns the fingerprint.
func ParseBeacon(payload []byte) ([nodeid.FingerprintLen]byte, error) {
	var fp [nodeid.FingerprintLen]byte
	if len(payload) != 1+nodeid.FingerprintLen {
		return fp, fmt.Errorf("link: beacon payload is %d B, want %d", len(payload), 1+nodeid.FingerprintLen)
	}
	if payload[0] != BeaconVersion {
		return fp, fmt.Errorf("link: beacon version %d, want %d", payload[0], BeaconVersion)
	}
	copy(fp[:], payload[1:])
	return fp, nil
}
