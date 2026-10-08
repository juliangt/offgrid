// window.go — the node-plane bundle window (§5.4): bundle chunks ride as
// bundle-frag payloads behind a 1-byte window header of the §14.3(a)
// grammar, mirrored as this plane's own format (the user-plane bytes are
// untouched). Frozen encoding (1.3.0 precision note):
//
//	bit 7..4   win_id(4)   window tag (0–15)
//	bit 3..2   idx(2)      zero-based fragment index (0–3)
//	bit 1..0   total(2)    fragment count MINUS ONE (0–3 ⇔ counts 1–4)
//
// (the §14.3(a) text says "total: fragment count (1–4)" without pinning
// the encoding; the 2-bit field stores total−1 so counts 1..4 fit — the
// same resolution the user-plane readers will need when the §14.3 radio
// path is implemented; it is pinned here and in the doc's changelog).
//
// Reassembly: the Reassembler accepts interleaved windows keyed by win_id,
// completes in-order or out-of-order, refuses duplicate indices, and
// expires partial windows after the caller's timeout (the bundle's TTL —
// §5.4 "partial windows expire with the bundle's TTL"). A lost frame never
// corrupts sibling windows. The C mirror is dtn_frame.c's reassembler;
// the shared "window" vectors pin both sides.
package link

import (
	"bytes"
	"fmt"
	"time"
)

// Window constants (§4.1/§5.4, frozen; identical to bundle/spike.go's
// frame-fit math).
const (
	WinPayloadPerFrame = 221 // bundle bytes per frame (222 B budget − 1 B window header)
	WinMaxTotal        = 4   // total ≤ 4 (2-bit field)
	WinMaxBytes        = WinPayloadPerFrame * WinMaxTotal
	// WinMaxActive bounds the reassembler's concurrent windows (memory
	// honesty on the ESP32; 16 ≥ the 16 win_id values).
	WinMaxActive = 16
)

// Window errors (stable code strings double as the shared-vector verdicts).
var (
	ErrWindowTooLarge = fmt.Errorf("link: window content exceeds %d B (%d frames)", WinMaxBytes, WinMaxTotal)
	ErrWindowHeader   = fmt.Errorf("link: window header invalid")
	ErrWindowDupIdx   = fmt.Errorf("link: duplicate window index")
	ErrWindowFull     = fmt.Errorf("link: too many concurrent windows")
)

// WindowHeader encodes the 1-byte window header (total−1 encoding, above).
func WindowHeader(winID, idx, total byte) byte {
	return winID<<4 | idx<<2 | (total - 1)
}

// ParseWindowHeader splits the 1-byte window header, fail-closed.
func ParseWindowHeader(h byte) (winID, idx, total byte, err error) {
	winID = h >> 4
	idx = (h >> 2) & 0x03
	total = (h & 0x03) + 1
	if idx >= total {
		return 0, 0, 0, fmt.Errorf("%w: idx %d ≥ total %d", ErrWindowHeader, idx, total)
	}
	return winID, idx, total, nil
}

// SplitWindow chunks content into bundle-frag payloads (window header ‖
// ≤ 221 B), refusing content that needs more than 4 frames (§4.1: the LoRa
// CL refuses rather than grow the window).
func SplitWindow(winID byte, content []byte) ([][]byte, error) {
	frames := (len(content) + WinPayloadPerFrame - 1) / WinPayloadPerFrame
	if frames < 1 {
		frames = 1 // an empty content still occupies a well-formed 1-frame window
	}
	if frames > WinMaxTotal {
		return nil, fmt.Errorf("%w: %d B needs %d frames", ErrWindowTooLarge, len(content), frames)
	}
	out := make([][]byte, frames)
	for idx := 0; idx < frames; idx++ {
		start := idx * WinPayloadPerFrame
		end := start + WinPayloadPerFrame
		if end > len(content) {
			end = len(content)
		}
		chunk := content[start:end]
		f := make([]byte, 0, 1+len(chunk))
		f = append(f, WindowHeader(winID, byte(idx), byte(frames)))
		out[idx] = append(f, chunk...)
	}
	return out, nil
}

type winState struct {
	total   byte
	seen    [WinMaxTotal]bool
	parts   [WinMaxTotal][]byte
	got     int
	created time.Time
}

// Reassembler reassembles interleaved bundle windows.
type Reassembler struct {
	timeout   time.Duration
	now       func() time.Time
	windows   map[byte]*winState
	Expired   uint64 // partial windows pruned by timeout
	Rejected  uint64 // malformed or conflicting-duplicate frames dropped
	DupCopies uint64 // identical retransmissions absorbed (redundancy)
}

// NewReassembler builds a reassembler whose partial windows expire after
// timeout (the caller passes the bundle's TTL per §5.4). now may be nil
// (time.Now).
func NewReassembler(timeout time.Duration, now func() time.Time) *Reassembler {
	if now == nil {
		now = time.Now
	}
	return &Reassembler{timeout: timeout, now: now, windows: make(map[byte]*winState)}
}

// Push feeds one bundle-frag payload (window header ‖ data). When the push
// completes a window it returns the byte-exact content and done = true.
// A CONFLICTING duplicate (an index already seen with DIFFERENT bytes) is
// corruption and is refused; an IDENTICAL retransmission (the redundancy
// mechanism — the radio may deliver the same window frame twice) is
// idempotent: ignored, counted in DupCopies, never an error. Malformed
// headers and overfull sets are rejected with an error — never corrupting
// sibling windows.
func (r *Reassembler) Push(payload []byte) (content []byte, done bool, err error) {
	r.Expire()
	if len(payload) < 1 {
		r.Rejected++
		return nil, false, fmt.Errorf("%w: empty payload", ErrWindowHeader)
	}
	winID, idx, total, err := ParseWindowHeader(payload[0])
	if err != nil {
		r.Rejected++
		return nil, false, err
	}
	data := payload[1:]
	w, ok := r.windows[winID]
	if !ok {
		if len(r.windows) >= WinMaxActive {
			r.Rejected++
			return nil, false, fmt.Errorf("%w: %d active windows", ErrWindowFull, len(r.windows))
		}
		w = &winState{total: total, created: r.now()}
		r.windows[winID] = w
	}
	if total != w.total {
		// A window header whose total disagrees with the window's other
		// frames is corruption, not a sibling: refuse the frame.
		r.Rejected++
		return nil, false, fmt.Errorf("%w: win_id %d got total %d, window has %d", ErrWindowHeader, winID, total, w.total)
	}
	if len(data) > WinPayloadPerFrame {
		r.Rejected++
		return nil, false, fmt.Errorf("%w: win_id %d chunk %d B", ErrWindowHeader, winID, len(data))
	}
	if w.seen[idx] {
		if !bytes.Equal(data, w.parts[idx]) {
			r.Rejected++
			return nil, false, fmt.Errorf("%w: win_id %d idx %d carries conflicting bytes", ErrWindowDupIdx, winID, idx)
		}
		// Identical retransmission: idempotent, counted, not an error.
		r.DupCopies++
		return nil, false, nil
	}
	w.seen[idx] = true
	w.parts[idx] = append([]byte(nil), data...)
	w.got++
	if w.got < int(w.total) {
		return nil, false, nil
	}
	// Complete: concatenate by idx order, byte-exact.
	size := 0
	for _, p := range w.parts {
		size += len(p)
	}
	out := make([]byte, 0, size)
	for _, p := range w.parts {
		out = append(out, p...)
	}
	delete(r.windows, winID)
	return out, true, nil
}

// Expire prunes partial windows older than the timeout (§5.4: partial
// windows expire with the bundle's TTL). Completed windows never linger —
// they are removed at completion.
func (r *Reassembler) Expire() int {
	removed := 0
	for id, w := range r.windows {
		if r.now().Sub(w.created) > r.timeout {
			delete(r.windows, id)
			removed++
			r.Expired++
		}
	}
	return removed
}

// Active reports how many partial windows are pending.
func (r *Reassembler) Active() int { return len(r.windows) }
