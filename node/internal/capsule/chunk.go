// chunk.go — the node-plane capsule chunk transport (docs/node-network.md
// §9.4, frozen in P3.7): a capsule crosses the plane as N identified bulk
// bundles whose payload is a small chunk header followed by the capsule's
// bytes at a fixed stride.
//
//	Chunk PDU layout (frozen, §9.4):
//	offset  size  field
//	0       8     capsule_id — SHA-256(capsule bytes)[0:8]
//	8       4     total      — big-endian uint32, the chunk count N ≥ 1
//	12      4     idx        — big-endian uint32, 0-based index, < total
//	16      ...   chunk bytes — capsule[idx·stride : ...]
//
// Chunk sizes are per-transfer constants (§9.1): 64 KiB on the TCPCL
// (Wi-Fi/IP) plane, ≈ 200 B on LoRa (a 279 B, 2-frame bundle per chunk —
// loss of one window wastes ≤ 2 frames of airtime). The receiver derives
// the stride from the wire and validates it structurally (every non-last
// chunk of one capsule_id must carry the SAME length; the last carries
// the remainder) — a capsule keeps ONE stride for its whole crossing, so
// reassembly is exact and a mixed-size delivery is corruption, caught
// before any bytes are trusted.
//
// The reassembler is keyed by capsule_id, absorbs duplicates
// idempotently (the epidemic plane WILL redeliver), expires partials with
// the chunk bundles' lifetime (a partial window expires with its TTL —
// the §14.3 rule generalized), keeps interleaved capsules independent,
// and hands the byte-exact capsule to the Stager. Verification and
// anti-rollback happen ONCE, at completion, against the pinned release
// key — the §9.1 zero-new-trust-surface sentence: the network is one more
// entry point beside the operator laptop and the mule.

package capsule

import (
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"time"
)

// Frozen §9.4 constants.
const (
	// ChunkHeaderLen is the fixed chunk header size (8 + 4 + 4).
	ChunkHeaderLen = 16
	// ChunkSizeTCPCL is the 64 KiB chunk of the Wi-Fi/IP plane (§9.1).
	ChunkSizeTCPCL = 64 << 10
	// ChunkSizeLoRa is the ≈ 200 B chunk of the LoRa plane (§9.1); the
	// LoRa leg itself is hardware bring-up (P3.3+) — the constant and the
	// format exist now so both planes speak one grammar.
	ChunkSizeLoRa = 200
	// MaxChunks bounds `total` (a 48 MiB capsule at the 200 B LoRa stride
	// is ≈ 252 000 chunks; the bound is the format's sanity ceiling, not
	// a promise any node will buffer that).
	MaxChunks = 1 << 20
	// ChunkLifetime is the chunk bundles' lifetime (§3 P-6): chunked
	// ESP32-class capsules take hours over LoRa (§9.2) and must survive
	// store-and-forward across many episodic contacts; a week covers the
	// slowest honest crossing and bounds partial residence.
	ChunkLifetime = 7 * 24 * 3600
	// MaxPartialCapsules bounds concurrent partial reassemblies (RAM
	// honesty: each partial holds up to MaxCapsuleBytes of chunks; four
	// is generous for an island and bounds a hostile flood).
	MaxPartialCapsules = 4
	// doneCap bounds the completed-capsule id memory (dedup of
	// redelivered chunks after staging), FIFO.
	doneCap = 16
)

// CapsuleIDOf returns the chunk header's capsule_id: the first 8 bytes of
// SHA-256 over the capsule bytes.
func CapsuleIDOf(capsule []byte) [8]byte {
	sum := sha256.Sum256(capsule)
	var id [8]byte
	copy(id[:], sum[:8])
	return id
}

// ChunkHeader is the parsed fixed header of one chunk PDU.
type ChunkHeader struct {
	ID    [8]byte
	Total uint32
	Idx   uint32
}

// LooksLikeChunk is the cheap classification peek (§9.4): the payload
// COULD be a chunk PDU. It is deliberately arithmetic-only — total within
// [1, MaxChunks] and idx < total — so the store's admission path can run
// it without allocation. False positives (a COSE object whose bytes 8-15
// happen to parse as a sane header) cost nothing: the real dispatch runs
// on full validation, and the classification rule this feeds ("payload
// starts with the chunk header AND destination is identified → bulk")
// only overrides management-class EID routing when the arithmetic holds.
func LooksLikeChunk(payload []byte) bool {
	if len(payload) <= ChunkHeaderLen {
		return false
	}
	total := binary.BigEndian.Uint32(payload[8:12])
	idx := binary.BigEndian.Uint32(payload[12:16])
	return total >= 1 && total <= MaxChunks && idx < total
}

// ParseChunk splits a chunk PDU into its header and chunk bytes (views —
// copy what outlives the call). ok is false for anything the header
// arithmetic rejects; deeper consistency (stride, completion) is the
// Reassembler's.
func ParseChunk(payload []byte) (ChunkHeader, []byte, bool) {
	if !LooksLikeChunk(payload) {
		return ChunkHeader{}, nil, false
	}
	var h ChunkHeader
	copy(h.ID[:], payload[:8])
	h.Total = binary.BigEndian.Uint32(payload[8:12])
	h.Idx = binary.BigEndian.Uint32(payload[12:16])
	return h, payload[ChunkHeaderLen:], true
}

// Split chunks a capsule into the N chunk PDUs (each allocated fresh) at
// the given stride — the sender side of §9.4. chunkSize must be ≥ 1; the
// last chunk carries the remainder (it may equal the stride).
func Split(capsule []byte, chunkSize int) ([][]byte, error) {
	if chunkSize < 1 {
		return nil, errf(CodeLength, "chunk size must be ≥ 1, got %d", chunkSize)
	}
	if len(capsule) == 0 {
		return nil, errf(CodeLength, "cannot chunk an empty capsule")
	}
	total := (len(capsule) + chunkSize - 1) / chunkSize
	if total > MaxChunks {
		return nil, errf(CodeLength, "capsule needs %d chunks at stride %d — above the format ceiling %d", total, chunkSize, MaxChunks)
	}
	id := CapsuleIDOf(capsule)
	out := make([][]byte, total)
	for i := 0; i < total; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > len(capsule) {
			end = len(capsule)
		}
		pdu := make([]byte, ChunkHeaderLen, ChunkHeaderLen+end-start)
		copy(pdu, id[:])
		binary.BigEndian.PutUint32(pdu[8:12], uint32(total))
		binary.BigEndian.PutUint32(pdu[12:16], uint32(i))
		out[i] = append(pdu, capsule[start:end]...)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// The reassembler.
// ---------------------------------------------------------------------------

// partial is one capsule's in-flight chunk set.
type partial struct {
	total    uint32
	stride   int // the validated common length of the non-last chunks (0 = not yet fixed)
	chunks   map[uint32][]byte
	received int
	expires  time.Time // sliding: now + the chunk bundle's lifetime
}

// Reassembler reassembles chunked capsules, keyed by capsule_id. Safe for
// concurrent use (sessions deliver from multiple goroutines). Zero value
// is NOT ready — construct with NewReassembler.
type Reassembler struct {
	Now func() time.Time

	mu       sync.Mutex
	partials map[[8]byte]*partial
	done     [][8]byte // FIFO of completed capsule ids (dedup of redelivery)
	doneSet  map[[8]byte]bool

	// counters (RAM-only, the §10.7 discipline)
	chunksIn    uint64
	dups        uint64
	badChunks   uint64 // arithmetic violations, stride conflicts, overflows
	completions uint64
	expired     uint64
}

// NewReassembler builds an empty reassembler.
func NewReassembler() *Reassembler {
	return &Reassembler{
		Now:      time.Now,
		partials: make(map[[8]byte]*partial),
		doneSet:  make(map[[8]byte]bool),
	}
}

// CountersSnapshot is a plain read of the reassembly counters.
type ReasmCounters struct {
	ChunksIn    uint64
	Dups        uint64
	BadChunks   uint64
	Completions uint64
	Expired     uint64
}

// Counters returns the current counter values.
func (r *Reassembler) Counters() ReasmCounters {
	r.mu.Lock()
	defer r.mu.Unlock()
	return ReasmCounters{
		ChunksIn:    r.chunksIn,
		Dups:        r.dups,
		BadChunks:   r.badChunks,
		Completions: r.completions,
		Expired:     r.expired,
	}
}

// Offer feeds one chunk PDU (the full payload after the hop octet) and,
// when it completes a capsule, returns the byte-exact reassembled bytes.
// The lifetime extends the partial's TTL (the bundle-lifetime rule of
// §9.4) on every delivery — a capsule still crossing the plane never
// expires mid-flight.
func (r *Reassembler) Offer(chunkPDU []byte, lifetimeSec uint64) (assembled []byte, err error) {
	h, data, ok := ParseChunk(chunkPDU)
	if !ok {
		r.mu.Lock()
		r.badChunks++
		r.mu.Unlock()
		return nil, errf(CodeLength, "not a chunk PDU (header arithmetic)")
	}
	now := r.now()
	expires := now.Add(time.Duration(lifetimeSec) * time.Second)

	r.mu.Lock()
	defer r.mu.Unlock()
	r.chunksIn++
	r.sweepLocked(now)

	if r.doneSet[h.ID] {
		// A capsule this node already completed and staged: redelivered
		// chunks are absorbed idempotently (the anti-rollback rule makes
		// a second stage a refusal anyway; absorbing here keeps the
		// counters honest about WHY nothing happens).
		r.dups++
		return nil, nil
	}

	p := r.partials[h.ID]
	if p == nil {
		if len(r.partials) >= MaxPartialCapsules {
			// Evict the soonest-expiring partial (the §7.5 eviction
			// shape, applied to reassembly state): a flood of fake
			// capsule ids cannot buy unbounded memory.
			r.evictOneLocked(now)
		}
		p = &partial{total: h.Total, chunks: make(map[uint32][]byte)}
		r.partials[h.ID] = p
	}
	if p.total != h.Total {
		// Two different totals for one capsule_id: a corrupted or forged
		// header. Fail the whole partial (fail-closed).
		r.dropLocked(h.ID)
		r.badChunks++
		return nil, errf(CodeLength, "chunk claims total %d for a capsule tracked as %d — corruption", h.Total, p.total)
	}
	if prev, have := p.chunks[h.Idx]; have {
		if string(prev) == string(data) {
			r.dups++
			return nil, nil // identical redelivery absorbed (§5.4 discipline)
		}
		r.dropLocked(h.ID)
		r.badChunks++
		return nil, errf(CodeLength, "chunk %d redelivered with DIFFERING bytes — corruption (the §5.4 rule)", h.Idx)
	}
	// Stride discipline: every NON-last chunk carries the same length;
	// the last carries the remainder (may be shorter, never longer).
	isLast := h.Idx == h.Total-1
	if p.stride == 0 && !isLast {
		p.stride = len(data)
	}
	if !isLast {
		if len(data) != p.stride {
			r.dropLocked(h.ID)
			r.badChunks++
			return nil, errf(CodeLength, "chunk %d is %d bytes; capsule stride is %d — mixed chunk sizes are corruption (§9.4)", h.Idx, len(data), p.stride)
		}
	} else if p.stride != 0 && len(data) > p.stride {
		r.dropLocked(h.ID)
		r.badChunks++
		return nil, errf(CodeLength, "the last chunk is %d bytes, longer than the stride %d", len(data), p.stride)
	}
	// Memory honesty: total × stride (plus the remainder) is the capsule
	// size — it must fit the §2.4.2 body cap before any full buffering.
	if size := capsuleSizeLocked(p, len(data), isLast); size > MaxPayloadLen {
		r.dropLocked(h.ID)
		r.badChunks++
		return nil, errf(CodeLength, "capsule size %d exceeds the staging cap %d", size, MaxPayloadLen)
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	p.chunks[h.Idx] = cp
	p.received++
	p.expires = expires

	if int(p.received) < int(p.total) {
		return nil, nil
	}
	// Complete: concat in index order. The stride discipline plus the
	// idx < total guarantee make this exact.
	size := capsuleSizeLocked(p, len(p.chunks[p.total-1]), true)
	out := make([]byte, 0, size)
	for i := uint32(0); i < p.total; i++ {
		out = append(out, p.chunks[i]...)
	}
	r.dropLocked(h.ID)
	r.completions++
	r.rememberDoneLocked(h.ID)
	return out, nil
}

// capsuleSizeLocked computes the implied capsule size from what is known.
func capsuleSizeLocked(p *partial, lastLen int, haveLast bool) int {
	// total−1 stride-sized chunks + the remainder (bounded by stride when
	// the last chunk has not arrived yet).
	tail := lastLen
	if !haveLast && p.stride > 0 {
		tail = p.stride
	}
	middles := int(p.total) - 1
	if middles < 0 {
		middles = 0
	}
	if p.stride == 0 {
		// Only the last chunk so far (total == 1, or nothing to derive).
		return tail
	}
	return middles*p.stride + tail
}

func (r *Reassembler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Reassembler) dropLocked(id [8]byte) {
	if p, ok := r.partials[id]; ok {
		delete(r.partials, id)
		p.chunks = nil
	}
}

// evictOneLocked drops the soonest-expiring partial (deterministic:
// expires ASC, then id ASC — the §7.5 tie-break discipline).
func (r *Reassembler) evictOneLocked(now time.Time) {
	var victim [8]byte
	var when time.Time
	found := false
	for id, p := range r.partials {
		if !found || p.expires.Before(when) || (p.expires.Equal(when) && idLess(id, victim)) {
			victim, when, found = id, p.expires, true
		}
	}
	if found {
		r.dropLocked(victim)
		r.expired++
	}
}

func idLess(a, b [8]byte) bool {
	for i := 0; i < 8; i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// sweepLocked expires partials past their TTL (lazy — no goroutine; the
// daemon's bundle janitor calls Sweep on the same cadence) and bounds the
// completed-id memory with the FIFO cap.
func (r *Reassembler) sweepLocked(now time.Time) {
	for id, p := range r.partials {
		if now.After(p.expires) {
			r.dropLocked(id)
			r.expired++
		}
	}
	if len(r.done) > doneCap {
		cut := len(r.done) - doneCap
		for _, id := range r.done[:cut] {
			delete(r.doneSet, id)
		}
		r.done = append([][8]byte(nil), r.done[cut:]...)
	}
}

func (r *Reassembler) rememberDoneLocked(id [8]byte) {
	if !r.doneSet[id] {
		r.doneSet[id] = true
		r.done = append(r.done, id)
	}
}

// Sweep expires partials whose chunk bundles' lifetime has passed (the
// daemon's janitor calls this on the §10.6 cadence).
func (r *Reassembler) Sweep() {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sweepLocked(now)
}
