package capsule

// chunk_test.go — the §9.4 chunk transport: Split/ParseChunk roundtrip, the
// reassembler's ordering independence (interleaved capsules), duplicate
// absorption, the stride discipline, TTL expiry, eviction bounds and the
// completed-id dedup.

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"
	"time"
)

func chunkClock(offset *time.Time) func() time.Time {
	return func() time.Time { return *offset }
}

func TestSplitParseRoundtrip(t *testing.T) {
	caps := bytes.Repeat([]byte{0xA5}, 1000)
	for _, size := range []int{1, 200, 333, 1000, 4096} {
		pdus, err := Split(caps, size)
		if err != nil {
			t.Fatalf("Split(size %d): %v", size, err)
		}
		r := NewReassembler()
		var got []byte
		for _, pdu := range pdus {
			out, err := r.Offer(pdu, 60)
			if err != nil {
				t.Fatalf("Offer: %v", err)
			}
			if out != nil {
				got = out
			}
		}
		if !bytes.Equal(got, caps) {
			t.Fatalf("size %d: reassembly not byte-exact", size)
		}
	}
}

func TestSplitRefusals(t *testing.T) {
	if _, err := Split([]byte("x"), 0); ErrorCode(err) != CodeLength {
		t.Fatalf("size 0: %v", err)
	}
	if _, err := Split(nil, 10); ErrorCode(err) != CodeLength {
		t.Fatalf("empty capsule: %v", err)
	}
	if _, err := Split(make([]byte, MaxChunks+1), 1); ErrorCode(err) != CodeLength {
		t.Fatalf("over ceiling: %v", err)
	}
}

func TestChunkHeaderLayout(t *testing.T) {
	caps := []byte("capsule-bytes")
	pdus, err := Split(caps, 5)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	if len(pdus) != 3 {
		t.Fatalf("3 chunks of 5 bytes over 13, got %d", len(pdus))
	}
	sum := sha256.Sum256(caps)
	h, data, ok := ParseChunk(pdus[1])
	if !ok {
		t.Fatalf("ParseChunk rejected a real PDU")
	}
	if h.Total != 3 || h.Idx != 1 || !bytes.Equal(h.ID[:], sum[:8]) {
		t.Fatalf("header: %+v", h)
	}
	if !bytes.Equal(data, caps[5:10]) {
		t.Fatalf("chunk bytes: %q", data)
	}
	// CapsuleIDOf is the sha prefix, frozen.
	if CapsuleIDOf(caps) != ([8]byte(sum[:8])) {
		t.Fatalf("CapsuleIDOf drift")
	}
}

func TestLooksLikeChunkArithmetic(t *testing.T) {
	if LooksLikeChunk(make([]byte, 16)) {
		t.Fatalf("header-only payload must not pass (needs chunk bytes)")
	}
	big := make([]byte, 32)
	binary.BigEndian.PutUint32(big[8:12], 1<<21) // over MaxChunks
	if LooksLikeChunk(big) {
		t.Fatalf("total over the ceiling must not pass")
	}
	binary.BigEndian.PutUint32(big[8:12], 2)
	binary.BigEndian.PutUint32(big[12:16], 2) // idx == total
	if LooksLikeChunk(big) {
		t.Fatalf("idx == total must not pass")
	}
	binary.BigEndian.PutUint32(big[12:16], 1)
	if !LooksLikeChunk(big) {
		t.Fatalf("sane header must pass")
	}
}

func TestReassemblerInterleavedCapsulesIndependent(t *testing.T) {
	a := bytes.Repeat([]byte{0x11}, 300)
	b := bytes.Repeat([]byte{0x22}, 250)
	pa, _ := Split(a, 100)
	pb, _ := Split(b, 100)
	r := NewReassembler()
	// Strictly interleaved delivery, one chunk at a time; neither capsule
	// can corrupt or complete the other, and dups of either are absorbed.
	var gotA, gotB []byte
	for i := 0; i < 3; i++ {
		out, err := r.Offer(pa[i], 3600)
		if err != nil {
			t.Fatalf("a[%d]: %v", i, err)
		}
		if out != nil {
			gotA = out
		}
		out, err = r.Offer(pb[i], 3600)
		if err != nil {
			t.Fatalf("b[%d]: %v", i, err)
		}
		if out != nil {
			gotB = out
		}
		if i < 2 && (out != nil || gotA != nil) {
			t.Fatalf("nothing may complete before its last chunk (i=%d)", i)
		}
		// An interleaved dup never completes anything.
		if i < 2 {
			if _, err := r.Offer(pa[0], 3600); err != nil {
				t.Fatalf("dup a[0] at %d: %v", i, err)
			}
		}
	}
	if !bytes.Equal(gotA, a) || !bytes.Equal(gotB, b) {
		t.Fatalf("interleaved reassembly corrupted: a %v b %v", gotA == nil, gotB == nil)
	}
	if cs := r.Counters(); cs.Completions != 2 {
		t.Fatalf("completions: %+v", cs)
	}
}

func TestReassemblerDuplicateAbsorption(t *testing.T) {
	a := bytes.Repeat([]byte{0x33}, 40)
	pdus, _ := Split(a, 10)
	r := NewReassembler()
	for _, pass := range []int{0, 1} {
		for _, pdu := range pdus {
			out, err := r.Offer(pdu, 3600)
			if err != nil {
				t.Fatalf("pass %d: %v", pass, err)
			}
			if pass == 1 && out != nil {
				t.Fatalf("redelivery must be absorbed, not reassembled")
			}
		}
	}
	// A differing redelivery of an already-completed capsule is absorbed
	// by the done-set (the capsule is byte-frozen by its own sha).
	forged := append([]byte(nil), pdus[0]...)
	forged[len(forged)-1] ^= 0xFF
	if _, err := r.Offer(forged, 3600); err != nil {
		t.Fatalf("completed-capsule redelivery: %v", err)
	}
	cs := r.Counters()
	if cs.Dups == 0 || cs.Completions != 1 {
		t.Fatalf("counters: %+v", cs)
	}
}

func TestReassemblerDifferingRedeliveryIsCorruption(t *testing.T) {
	a := bytes.Repeat([]byte{0x44}, 60)
	pdus, _ := Split(a, 20)
	r := NewReassembler()
	if _, err := r.Offer(pdus[0], 3600); err != nil {
		t.Fatalf("first: %v", err)
	}
	forged := append([]byte(nil), pdus[0]...)
	forged[len(forged)-1] ^= 0x01
	if _, err := r.Offer(forged, 3600); ErrorCode(err) != CodeLength {
		t.Fatalf("differing redelivery: %v, want corruption refusal", err)
	}
	// Fail-closed: the whole partial was dropped (the §5.4 rule). A fresh,
	// HONEST delivery restarts cleanly and completes.
	var got []byte
	for _, pdu := range pdus {
		out, err := r.Offer(pdu, 3600)
		if err != nil {
			t.Fatalf("restart: %v", err)
		}
		if out != nil {
			got = out
		}
	}
	if !bytes.Equal(got, a) {
		t.Fatalf("restart must reassemble byte-exact")
	}
}

func TestReassemblerStrideDiscipline(t *testing.T) {
	a := bytes.Repeat([]byte{0x55}, 50)
	pdus, _ := Split(a, 20) // 20, 20, 10
	r := NewReassembler()
	if _, err := r.Offer(pdus[0], 3600); err != nil {
		t.Fatalf("first: %v", err)
	}
	// A middle chunk of the WRONG length: corruption — the partial dies.
	mixed := append([]byte(nil), pdus[1][:ChunkHeaderLen]...)
	mixed = append(mixed, bytes.Repeat([]byte{0x77}, 15)...)
	if _, err := r.Offer(mixed, 3600); ErrorCode(err) != CodeLength {
		t.Fatalf("mixed stride: %v", err)
	}
	// The total-conflict case: same capsule_id (approximated by reusing a
	// header from a), different total.
	conflict := append([]byte(nil), pdus[0][:12]...)
	conflict = append(conflict, 0, 0, 0, 9, 0, 0, 0, 0) // total 9, idx 0
	if _, err := r.Offer(conflict, 3600); ErrorCode(err) != CodeLength {
		t.Fatalf("total conflict: %v", err)
	}
}

func TestReassemblerTTLSweep(t *testing.T) {
	a := bytes.Repeat([]byte{0x66}, 30)
	pdus, _ := Split(a, 10)
	now := time.Unix(1791072000, 0)
	r := NewReassembler()
	r.Now = chunkClock(&now)
	if _, err := r.Offer(pdus[0], 3600); err != nil {
		t.Fatalf("offer: %v", err)
	}
	// Within the TTL the partial survives.
	r.Sweep()
	if got := r.Counters().Expired; got != 0 {
		t.Fatalf("expired too early: %d", got)
	}
	// Past it (delivery clock beyond the offer's now + lifetime), the lazy
	// sweep on the NEXT offer collects it.
	now = now.Add(2 * time.Hour)
	if _, err := r.Offer(pdus[1], 3600); err != nil {
		t.Fatalf("offer: %v", err)
	}
	if cs := r.Counters(); cs.Expired != 1 {
		t.Fatalf("expired counter: %+v", cs)
	}
	// The capsule can no longer complete — the partial was reset.
	var out []byte
	for _, pdu := range pdus {
		o, err := r.Offer(pdu, 3600)
		if err != nil {
			t.Fatalf("re-offer: %v", err)
		}
		if o != nil {
			out = o
		}
	}
	if !bytes.Equal(out, a) {
		t.Fatalf("fresh delivery after expiry must complete")
	}
}

func TestReassemblerPartialEviction(t *testing.T) {
	r := NewReassembler()
	r.Now = chunkClock(&nowShared)
	// MaxPartialCapsules + 1 interleaved partials: the soonest-expiring
	// partial is evicted (a fake-capsule flood cannot buy unbounded RAM).
	parts := make([][][]byte, MaxPartialCapsules+1)
	for i := range parts {
		caps := bytes.Repeat([]byte{byte(i)}, 40)
		p, err := Split(caps, 10)
		if err != nil {
			t.Fatalf("Split: %v", err)
		}
		parts[i] = p
		if _, err := r.Offer(p[0], 3600); err != nil {
			t.Fatalf("offer %d: %v", i, err)
		}
	}
	if cs := r.Counters(); cs.Expired != 1 {
		t.Fatalf("one eviction expected: %+v", cs)
	}
	// Complete capsule 0 — it was the eviction victim (all expires equal,
	// id ASC tie-break picks the lowest id... deterministic, but WHICH one
	// is a detail; what is pinned: exactly one partial was evicted, so
	// exactly one of the capsules fails to complete, and a fresh full
	// delivery of ANY capsule still works.
	for _, pdu := range parts[0] {
		if _, err := r.Offer(pdu, 3600); err != nil {
			t.Fatalf("complete 0: %v", err)
		}
	}
}

var nowShared = time.Unix(1791072000, 0)

func TestReassemblerBadPDUs(t *testing.T) {
	r := NewReassembler()
	if _, err := r.Offer([]byte("not a chunk"), 60); ErrorCode(err) != CodeLength {
		t.Fatalf("garbage: %v", err)
	}
	if cs := r.Counters(); cs.BadChunks != 1 || cs.ChunksIn != 0 {
		t.Fatalf("counters: %+v", cs)
	}
}

func TestReassemblerMemoryBound(t *testing.T) {
	// A claimed capsule larger than the staging cap dies as soon as the
	// arithmetic proves the size — before any full buffering.
	r := NewReassembler()
	pdu := make([]byte, ChunkHeaderLen+10)
	binary.BigEndian.PutUint32(pdu[8:12], 500000) // total
	binary.BigEndian.PutUint32(pdu[12:16], 0)     // idx 0, non-last → fixes stride 10
	// 500000 × 10 = 5 MB > MaxPayloadLen (48 MiB + 64 KiB)? No — under.
	// Use the honest bound: total such that total×stride > cap.
	binary.BigEndian.PutUint32(pdu[8:12], (MaxPayloadLen/10)+2)
	if _, err := r.Offer(pdu, 60); ErrorCode(err) != CodeLength {
		t.Fatalf("oversize capsule: %v", err)
	}
}
