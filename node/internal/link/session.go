// session.go — the §6.2 link session: per-direction AES-CCM-128 traffic
// keys, the 13-byte nonce (5-byte session salt ‖ 8-byte big-endian
// per-direction sequence), a monotonic outgoing sequence with a persisted
// checkpoint every 32nd packet, a sliding replay window (≥ 32, implemented
// as 64) on the incoming direction, drop counters, and the rekey bounds
// (2^20 packets / 24 h). The C mirror is dtn_session.c; the shared replay
// vectors (tests/vectors/link, "replay" group) pin both sides to identical
// accept/reject verdicts.
package link

import (
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"time"
)

// Sequence/rekey parameters, frozen by §6.2.
const (
	// CheckpointInterval is the §6.2 writer cadence: the sender persists
	// its counter every 32nd packet.
	CheckpointInterval = 32
	// ResumeSkip is the unclean-restart rule: the sender resumes at
	// last-persisted + 32; the receiver's replay window absorbs the gap.
	ResumeSkip = 32
	// ReplayWindow is the receiver's sliding window (§6.2 requires ≥ 32;
	// 64 doubles the headroom so the ResumeSkip gap never reaches the
	// too-far-ahead bound).
	ReplayWindow = 64
	// RekeyPackets is the §6.2 packet-count rekey bound (2^20).
	RekeyPackets = 1 << 20
	// RekeyInterval is the §6.2 time rekey bound (24 h).
	RekeyInterval = 24 * time.Hour
)

// Direction labels a session's two half-channels (§6.2 per-direction keys
// and sequences). The initiator owns I2R's sender side and R2I's receiver.
type Direction int

const (
	DirI2R Direction = iota // initiator → responder
	DirR2I                  // responder → initiator
)

func (d Direction) String() string {
	if d == DirR2I {
		return "r2i"
	}
	return "i2r"
}

// StateStore is the persisted-counter seam (§6.2 "sequence state persists,
// flash on ESP32"): the writer's per-direction send counter is loaded at
// session open and saved every CheckpointInterval packets. Implementations
// persist exactly two counters per session (the keys themselves are session
// state, not store state — a new session comes from a new handshake).
type StateStore interface {
	// Load returns the last persisted send counter for dir; 0 = none.
	Load(dir Direction) (uint64, error)
	// Save persists the send counter for dir (called every
	// CheckpointInterval packets).
	Save(dir Direction, seq uint64) error
}

// Drops counts the §6.2 "replayed or reordered-beyond-window frames are
// dropped and counted" rule, split by cause. Counters are monotonic.
type Drops struct {
	Replayed     uint64 // sequence already seen inside the window
	TooOld       uint64 // sequence below the window floor
	TooFarAhead  uint64 // sequence beyond the window ceiling
	RejectedSalt uint64 // nonce salt prefix does not match this session
}

// Session is one established link session's crypto state. It is not safe
// for concurrent use (a link serves one peer at a time); the serial CL
// serializes its own writes.
type Session struct {
	dir Direction // the LOCAL sender direction

	sendKey, recvKey   [KeyLen]byte
	sendSalt, recvSalt [NonceSaltLen]byte

	sendSeq     uint64 // next outgoing sequence (monotonic)
	recvHighest uint64 // highest accepted incoming sequence
	recvSeen    []byte // ReplayWindow/8-byte bitmap of recvHighest-.. window

	store StateStore
	est   time.Time // establishment time (rekey time bound)
	now   func() time.Time

	drops Drops
}

// NonceSaltLen is the salt prefix of the 13-byte §6.2 nonce.
const NonceSaltLen = 5

// Handshake-derived errors. Failed handshakes return these before any
// Session exists; a Session is only constructed by a completed handshake.
var (
	ErrHandshake     = fmt.Errorf("link: handshake failed")
	ErrReplay        = fmt.Errorf("link: replayed or out-of-window frame")
	ErrSessionSealed = fmt.Errorf("link: session is not established")
)

// NewSession builds the session half for direction dir (the local sender
// side). store may be nil (host tests without persistence); now may be nil
// (time.Now). The sender resumes at last-persisted + ResumeSkip (§6.2's
// unclean-restart rule) whenever a store supplies a counter.
func NewSession(dir Direction, sendKey, recvKey [KeyLen]byte, sendSalt, recvSalt [NonceSaltLen]byte, store StateStore, now func() time.Time) *Session {
	if now == nil {
		now = time.Now
	}
	s := &Session{
		dir:      dir,
		sendKey:  sendKey,
		recvKey:  recvKey,
		sendSalt: sendSalt,
		recvSalt: recvSalt,
		recvSeen: make([]byte, ReplayWindow/8),
		store:    store,
		est:      now(),
		now:      now,
	}
	if store != nil {
		if persisted, err := store.Load(dir); err == nil && persisted > 0 {
			s.sendSeq = persisted + ResumeSkip
		}
	}
	return s
}

// Nonce builds the §6.2 13-byte nonce: salt ‖ 8-byte BE sequence.
func Nonce(salt [NonceSaltLen]byte, seq uint64) [NonceLen]byte {
	var n [NonceLen]byte
	copy(n[:], salt[:])
	binary.BigEndian.PutUint64(n[NonceSaltLen:], seq)
	return n
}

// Seal protects one outgoing payload: encrypts under the sender's key and
// the CURRENT sequence's nonce, then advances the sequence. Returns
// nonce ‖ ciphertext ‖ tag (the §6.2 wire shape — the receiver reads the
// sequence from the nonce itself). Every CheckpointInterval packets the
// counter is persisted through the store (§6.2 checkpoint-every-32).
func (s *Session) Seal(aad, plaintext []byte) ([]byte, error) {
	seq := s.sendSeq
	ct, err := Seal(s.sendKey, Nonce(s.sendSalt, seq), aad, plaintext)
	if err != nil {
		return nil, err
	}
	s.sendSeq = seq + 1
	if s.store != nil && s.sendSeq%CheckpointInterval == 0 {
		// Checkpoint AFTER the 32nd packet: the persisted value is the
		// next-unsent sequence; the restart rule adds ResumeSkip on top.
		if err := s.store.Save(s.dir, s.sendSeq); err != nil {
			return nil, fmt.Errorf("link: persisting sequence checkpoint: %w", err)
		}
	}
	out := make([]byte, 0, NonceLen+len(ct))
	nonce := Nonce(s.sendSalt, seq)
	out = append(out, nonce[:]...)
	return append(out, ct...), nil
}

// Open verifies and decrypts one incoming ciphertext ‖ tag. The sequence
// is taken from the nonce itself (§6.2); replayed, too-old and too-far-
// ahead frames are rejected with ErrReplay and counted. A frame whose salt
// prefix does not match this session is rejected outright.
func (s *Session) Open(aad, data []byte) ([]byte, error) {
	if len(data) < NonceLen+TagLen {
		return nil, fmt.Errorf("%w: frame shorter than nonce+tag", ErrReplay)
	}
	var nonce [NonceLen]byte
	copy(nonce[:], data[:NonceLen])
	if subtle.ConstantTimeCompare(nonce[:NonceSaltLen], s.recvSalt[:]) != 1 {
		s.drops.RejectedSalt++
		return nil, fmt.Errorf("%w: salt prefix mismatch (not this session)", ErrReplay)
	}
	seq := binary.BigEndian.Uint64(nonce[NonceSaltLen:])
	switch {
	case seq > s.recvHighest+ReplayWindow:
		s.drops.TooFarAhead++
		return nil, fmt.Errorf("%w: sequence %d is more than %d ahead of %d", ErrReplay, seq, ReplayWindow, s.recvHighest)
	case seq+ReplayWindow <= s.recvHighest:
		s.drops.TooOld++
		return nil, fmt.Errorf("%w: sequence %d is below the window floor of %d", ErrReplay, seq, s.recvHighest)
	case seq <= s.recvHighest && s.bit(int(s.recvHighest-seq)):
		s.drops.Replayed++
		return nil, fmt.Errorf("%w: sequence %d was already accepted", ErrReplay, seq)
	}
	pt, err := Open(s.recvKey, nonce, aad, data[NonceLen:])
	if err != nil {
		return nil, err // tag mismatch: nothing is marked seen
	}
	// Distance-based bitmap: bit d = "recvHighest − d was accepted"; the
	// window advances by shifting on every new high-water mark (RFC 6479
	// style). Sequences are unique, so a bit never lies about its
	// sequence.
	if seq > s.recvHighest {
		s.shiftWindow(seq - s.recvHighest)
		s.recvHighest = seq
		s.setBit(0)
	} else {
		s.setBit(int(s.recvHighest - seq))
	}
	return pt, nil
}

// shiftWindow slides the bitmap up by delta (a new high-water mark delta
// above the old one): bit d moves to d+delta, bits past the window fall
// off, the new top bits clear.
func (s *Session) shiftWindow(delta uint64) {
	if delta >= ReplayWindow {
		s.recvSeen = make([]byte, ReplayWindow/8)
		return
	}
	for d := int(ReplayWindow) - 1; d >= 0; d-- {
		if d >= int(delta) && s.bit(d-int(delta)) {
			s.recvSeen[d/8] |= 1 << (d % 8)
		} else {
			s.recvSeen[d/8] &^= 1 << (d % 8)
		}
	}
}

// bit reports whether distance-d slot is marked.
func (s *Session) bit(d int) bool {
	return s.recvSeen[d/8]&(1<<(d%8)) != 0
}

// setBit marks distance-d slot.
func (s *Session) setBit(d int) {
	s.recvSeen[d/8] |= 1 << (d % 8)
}

// DropCounters returns a copy of the drop counters.
func (s *Session) DropCounters() Drops { return s.drops }

// SendSeq returns the next outgoing sequence number.
func (s *Session) SendSeq() uint64 { return s.sendSeq }

// EstablishedAt returns the session's establishment time.
func (s *Session) EstablishedAt() time.Time { return s.est }

// NeedsRekey reports whether either §6.2 rekey bound has fired: the sender
// reached RekeyPackets packets or RekeyInterval elapsed since
// establishment. The actual rekey is a NEW handshake (§6.2); this check
// only gates the trigger.
func (s *Session) NeedsRekey() bool {
	return s.sendSeq >= RekeyPackets || s.now().Sub(s.est) >= RekeyInterval
}
