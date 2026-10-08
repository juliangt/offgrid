package link

// Window reassembly tests: interleaved windows complete in-order or
// out-of-order, a lost frame never corrupts sibling windows, duplicates
// and malformed headers are refused, partial windows expire with their
// timeout, and >4-frame content is refused.

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func windowTestClock() (func() time.Time, *time.Time) {
	base := time.Unix(1791072000, 0)
	cur := base
	return func() time.Time { return cur }, &cur
}

func TestWindowSplitJoin(t *testing.T) {
	content := bytes.Repeat([]byte{0xC3}, 500) // 3 frames (221+221+58)
	frames, err := SplitWindow(0x07, content)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 3 {
		t.Fatalf("SplitWindow produced %d frames, want 3", len(frames))
	}
	r := NewReassembler(time.Hour, nil)
	var got []byte
	done := false
	for i, f := range frames { // in order
		c, d, err := r.Push(f)
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if d {
			got, done = c, true
		} else if r.Active() != 1 {
			t.Fatalf("frame %d: window lost", i)
		}
	}
	if !done || !bytes.Equal(got, content) {
		t.Fatalf("reassembled %d B (done=%v), want byte-exact %d B", len(got), done, len(content))
	}
	if r.Active() != 0 {
		t.Fatal("completed window not removed")
	}
}

func TestWindowInterleavedWithLoss(t *testing.T) {
	// Three interleaved windows; frames drop from each. A lost frame
	// NEVER corrupts the others: the windows that eventually receive
	// every frame complete byte-exact; incomplete ones just expire.
	clock, _ := windowTestClock()
	r := NewReassembler(10*time.Second, clock)

	content := func(n int, fill byte) []byte { return bytes.Repeat([]byte{fill}, n) }
	wA, err := SplitWindow(1, content(442, 0xAA)) // 2 frames
	if err != nil {
		t.Fatal(err)
	}
	wB, err := SplitWindow(2, content(58, 0xBB)) // 1 frame
	if err != nil {
		t.Fatal(err)
	}
	wC, err := SplitWindow(3, content(500, 0xCC)) // 3 frames
	if err != nil {
		t.Fatal(err)
	}
	// Interleave with scripted loss: C loses idx 0 but it is re-delivered
	// after C[1]/C[2]; every window that eventually sees all frames
	// completes byte-exact regardless of arrival order.
	delivered := [][]byte{wA[0], wB[0], wC[1], wC[2], wA[1], wC[0]}
	var completions int
	var gotA, gotB, gotC bool
	for i, f := range delivered {
		c, done, err := r.Push(f)
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if !done {
			continue
		}
		completions++
		switch {
		case bytes.Equal(c, content(442, 0xAA)):
			gotA = true
		case bytes.Equal(c, content(58, 0xBB)):
			gotB = true
		case bytes.Equal(c, content(500, 0xCC)):
			gotC = true
		default:
			t.Fatalf("unexpected completion %d B", len(c))
		}
	}
	if completions != 3 || !gotA || !gotB || !gotC {
		t.Fatalf("%d windows completed (A=%v B=%v C=%v), want all three byte-exact", completions, gotA, gotB, gotC)
	}
	if r.Active() != 0 {
		t.Fatalf("%d windows still active", r.Active())
	}

	// Now a genuinely incomplete window: A loses idx 1 for good.
	clock2, cur2 := windowTestClock()
	r2 := NewReassembler(10*time.Second, clock2)
	w, err := SplitWindow(4, content(442, 0xDD))
	if err != nil {
		t.Fatal(err)
	}
	sibling, err := SplitWindow(5, content(58, 0xEE))
	if err != nil {
		t.Fatal(err)
	}
	if _, done, err := r2.Push(w[0]); err != nil || done {
		t.Fatalf("A[0]: %v/%v", err, done)
	}
	if _, done, err := r2.Push(sibling[0]); err != nil || !done {
		t.Fatalf("sibling: %v/%v", err, done)
	}
	if r2.Active() != 1 {
		t.Fatal("partial window missing")
	}
	*cur2 = clock2().Add(11 * time.Second)
	if n := r2.Expire(); n != 1 {
		t.Fatalf("expired %d windows, want 1", n)
	}
	if r2.Active() != 0 || r2.Expired != 1 {
		t.Fatal("partial window did not expire")
	}
}

func TestWindowRefusals(t *testing.T) {
	clock, _ := windowTestClock()
	r := NewReassembler(time.Hour, clock)

	// An IDENTICAL retransmission (redundancy) is idempotent — ignored,
	// counted, not an error; a CONFLICTING duplicate (different bytes for
	// a seen idx) is corruption and is refused.
	frames, err := SplitWindow(9, bytes.Repeat([]byte{1}, 300))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Push(frames[0]); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Push(frames[0]); err != nil {
		t.Fatalf("identical retransmission rejected: %v", err)
	}
	if r.DupCopies != 1 {
		t.Fatalf("DupCopies = %d, want 1", r.DupCopies)
	}
	conflict := append([]byte(nil), frames[0]...)
	conflict[len(conflict)-1] ^= 0xFF
	if _, _, err := r.Push(conflict); !errors.Is(err, ErrWindowDupIdx) {
		t.Fatalf("conflicting duplicate accepted: %v", err)
	}
	if r.Rejected != 1 {
		t.Fatalf("Rejected = %d, want 1", r.Rejected)
	}

	// total disagreement within one win_id refused.
	bad := []byte{WindowHeader(9, 1, 3)} // window 9 was created with total 2
	if _, _, err := r.Push(bad); err == nil {
		t.Fatal("total disagreement accepted")
	}

	// idx >= total refused.
	if _, _, err := r.Push([]byte{WindowHeader(10, 2, 2), 0x00}); err == nil {
		t.Fatal("idx ≥ total accepted")
	}
	// Empty payload refused.
	if _, _, err := r.Push(nil); err == nil {
		t.Fatal("empty payload accepted")
	}

	// > 4 frames refused at split time.
	if _, err := SplitWindow(11, bytes.Repeat([]byte{2}, WinMaxBytes+1)); !errors.Is(err, ErrWindowTooLarge) {
		t.Fatalf("oversize window accepted: %v", err)
	}
	// Exactly the window capacity splits into 4.
	frames4, err := SplitWindow(11, bytes.Repeat([]byte{3}, WinMaxBytes))
	if err != nil || len(frames4) != 4 {
		t.Fatalf("capacity window: %d frames, err %v", len(frames4), err)
	}

	// Window-header encoding roundtrip and total−1 field encoding.
	for _, c := range []struct{ id, idx, total byte }{{0, 0, 1}, {15, 3, 4}, {7, 1, 2}} {
		h := WindowHeader(c.id, c.idx, c.total)
		id, idx, total, err := ParseWindowHeader(h)
		if err != nil || id != c.id || idx != c.idx || total != c.total {
			t.Fatalf("header 0x%02x → %d/%d/%d/%v", h, id, idx, total, err)
		}
	}
	// The total−1 encoding is pinned: total 4 ↔ field 3.
	if h := WindowHeader(0, 0, 4); h&0x03 != 3 {
		t.Fatalf("total-4 field = %d, want 3", h&0x03)
	}
}
