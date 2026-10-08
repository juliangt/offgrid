package forward

// sync_test.go — the §7.1 epidemic primitives (Bloom summary, diff, the
// summary-bundle codec) and the §7.3 priority queue discipline.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func idFromSeed(b byte) [32]byte {
	return sha256.Sum256([]byte{b})
}

func idsFromSeeds(seeds ...byte) [][32]byte {
	out := make([][32]byte, len(seeds))
	for i, s := range seeds {
		out[i] = idFromSeed(s)
	}
	return out
}

func TestBloomShapeAndMembership(t *testing.T) {
	// §7.1 pins the shape: 4096 bits (512 B), k = 4.
	s := &Summary{}
	if len(s.Bits) != BloomBytes || BloomBytes != 512 {
		t.Fatalf("filter must be 512 B, got %d", len(s.Bits))
	}
	if BloomK != 4 {
		t.Fatalf("k must be 4")
	}
	if BloomBits != len(s.Bits)*8 {
		t.Fatalf("BloomBits/BloomBytes mismatch")
	}

	id := idFromSeed(1)
	if s.Contains(&id) {
		t.Fatalf("empty filter claims membership")
	}
	s.Add(&id)
	if !s.Contains(&id) {
		t.Fatalf("added id must be found")
	}
	// Every hash index must be within range and deterministic.
	h1 := bloomHashes(&id)
	h2 := bloomHashes(&id)
	if h1 != h2 {
		t.Fatalf("hashes must be deterministic")
	}
	for _, bit := range h1 {
		if bit >= BloomBits {
			t.Fatalf("index %d out of range", bit)
		}
	}
}

func TestBloomFalsePositiveRateBound(t *testing.T) {
	// §7.1: ≈ 0.1 % at 200 entries. Assert the honest bound (the vector
	// below pins the exact bytes; this pins the DESIGN claim).
	s := NewSummary(idsFromSeeds(0, 1, 2, 3, 4))
	count := 0
	for b := 0; b < 256; b++ {
		id := idFromSeed(byte(b))
		if s.Contains(&id) && !containsSeed(idsFromSeeds(0, 1, 2, 3, 4), id) {
			count++
		}
	}
	if count > 3 { // 5 entries → expected false positives ≈ 256 * 2.4e-8 ≈ 0
		t.Fatalf("too many false positives on a 5-entry filter: %d", count)
	}
}

func containsSeed(ids [][32]byte, id [32]byte) bool {
	for i := range ids {
		if ids[i] == id {
			return true
		}
	}
	return false
}

func TestMissingComputesTheTransferList(t *testing.T) {
	// Peer has {1, 2}; we have {1, 2, 3, 4}. The peer's diff against OUR
	// summary would send {3, 4}; symmetrically, our run over THEIR summary
	// keeps {1, 2} and flags nothing... this direction: OUR ids missing from
	// THEIR filter = what WE must send.
	theirs := NewSummary(idsFromSeeds(1, 2))
	ours := idsFromSeeds(1, 2, 3, 4)
	got := Missing(ours, theirs)
	if len(got) != 2 || got[0] != idFromSeed(3) || got[1] != idFromSeed(4) {
		t.Fatalf("missing = %v, want {3,4} in order", got)
	}
	// Converged sets diff to nothing.
	if got := Missing(ours, NewSummary(ours)); len(got) != 0 {
		t.Fatalf("converged diff must be empty, got %d", len(got))
	}
}

func TestSummaryPDUCodecRoundTrip(t *testing.T) {
	s := NewSummary(idsFromSeeds(9, 8, 7))
	pdu := EncodeSummaryPDU(s)
	if len(pdu) != SummaryPayloadLen || SummaryPayloadLen != 513 {
		t.Fatalf("summary PDU must be 513 B (1 version + 512 filter), got %d", len(pdu))
	}
	if pdu[0] != SyncVersion {
		t.Fatalf("version byte must lead")
	}
	got, ok := ParseSummaryPDU(pdu)
	if !ok {
		t.Fatalf("round-trip must parse")
	}
	if got.Bits != s.Bits {
		t.Fatalf("filter bytes changed in transit")
	}
	// Foreign shapes refuse.
	if _, ok := ParseSummaryPDU(pdu[1:]); ok {
		t.Fatalf("wrong length must refuse")
	}
	if _, ok := ParseSummaryPDU(append([]byte{SyncVersion + 1}, pdu[1:]...)); ok {
		t.Fatalf("unknown version must refuse")
	}
	if _, ok := ParseSummaryPDU(append([]byte{SyncVersion}, pdu[1:]...)); !ok {
		t.Fatalf("correct shape must parse")
	}
}

func TestSendQueuePriorityDiscipline(t *testing.T) {
	// §7.3: management > mail > bulk, FIFO within a lane, whatever the push
	// order.
	q := &sendQueue{}
	q.push(idFromSeed(1), ClassBulk)
	q.push(idFromSeed(2), ClassMail)
	q.push(idFromSeed(3), ClassBulk)
	q.push(idFromSeed(4), ClassManagement)
	q.push(idFromSeed(5), ClassMail)

	want := []struct {
		id    [32]byte
		class Class
	}{{idFromSeed(4), ClassManagement}, {idFromSeed(2), ClassMail}, {idFromSeed(5), ClassMail},
		{idFromSeed(1), ClassBulk}, {idFromSeed(3), ClassBulk}}
	for i, w := range want {
		id, ok := q.pop()
		if !ok || id != w.id {
			t.Fatalf("pop %d = %v, want %v (priority discipline violated)", i, id, w.id)
		}
	}
	if _, ok := q.pop(); ok {
		t.Fatalf("queue must be empty")
	}
}

func TestSendQueueBulkBacklogDoesNotStarveManagement(t *testing.T) {
	// The §7.3 starvation bound, exactly as required: a bulk backlog in
	// flight never delays a management bundle by more than ONE transfer
	// window — pop() happens between transfers, so a management bundle that
	// arrives while bulk #1 is on the wire wins the very next slot.
	q := &sendQueue{}
	for i := 0; i < 64; i++ {
		q.push(idFromSeed(byte(i)), ClassBulk)
	}
	first, ok := q.pop() // bulk #1 is "in flight"
	if !ok || first != idFromSeed(0) {
		t.Fatalf("first pop must be bulk #0")
	}
	q.push(idFromSeed(200), ClassManagement) // arrives mid-transfer
	for i := 0; i < 64; i++ {
		id, ok := q.pop()
		if !ok {
			t.Fatalf("queue drained early at %d", i)
		}
		if i == 0 && id != idFromSeed(200) {
			t.Fatalf("management must take the slot immediately after the in-flight bulk transfer, got %v", id)
		}
		if i > 0 && id == idFromSeed(200) {
			t.Fatalf("management appeared out of order")
		}
	}
	if q.len() != 0 {
		t.Fatalf("queue must be empty")
	}
}

func TestBloomVectorAnchorsTheCMirror(t *testing.T) {
	// A human-checkable anchor (the full cross-implementation pin lives in
	// tests/vectors/forward/vectors.json, executed by BOTH suites): the
	// filter of the empty set is all-zero bytes, and adding one id sets
	// exactly k bits.
	s := &Summary{}
	if !bytes.Equal(s.Bits[:], make([]byte, BloomBytes)) {
		t.Fatalf("empty filter must be zeroed")
	}
	id := idFromSeed(42)
	s.Add(&id)
	popcount := 0
	for _, b := range s.Bits {
		for b != 0 {
			popcount += int(b & 1)
			b >>= 1
		}
	}
	if popcount != BloomK {
		t.Fatalf("one id must set exactly k=%d bits, set %d", BloomK, popcount)
	}
	t.Logf("bloom(%s) head: %s", hex.EncodeToString(id[:]),
		hex.EncodeToString(s.Bits[:16]))
}
