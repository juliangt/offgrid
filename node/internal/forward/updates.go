package forward

// updates.go — the P3.7 updates-over-the-plane integration (docs/
// node-network.md §9): the sender side (a capsule becomes N identified
// bulk-class chunk bundles) and the receiving dispatch in the Sink (chunk
// cargo addressed to this node feeds the capsule.Receiver BEFORE the store,
// then re-admits like §8.5 does for consumed management copies).
//
// Trust stance (§9.1, verbatim from offline-maintenance §2.3): the network
// is one more entry point beside the operator laptop and the mule — the
// receiving node verifies signature, arch and anti-rollback at STAGING
// (internal/capsule.Stager), exactly as the future #37 HTTP endpoint will.
// Nothing here trusts a chunk, a sender EID, or an authenticated session.

import (
	"fmt"

	"offgrid/dtn-node/internal/bundle"
	"offgrid/dtn-node/internal/capsule"
)

// ChunkCapsule is the §9.4 sender: it splits capsule bytes into chunk PDUs
// at the given stride (§9.1 pins 64 KiB for TCPCL transfers, capsule.
// ChunkSizeLoRa for the LoRa leg) and wraps each as a §3 P-5 IDENTIFIED
// bundle — source = the sending node's EID, destination = the target node
// EID or the dtn://og-admin/ group, lifetime = capsule.ChunkLifetime (§9.4:
// ESP32-class capsules cross LoRa over hours, through many episodic
// contacts), hop 0, one transfer sequence per chunk (P-3). The bundles
// classify BULK (§7.5 + the §9.4 chunk peek), so the §7.3 queue discipline
// and the §7.4 budgets bind them like any bulk cargo.
//
// The receiver derives delivery order from the chunk header — the bundles
// MAY cross any number of relays and contacts in any order.
func ChunkCapsule(srcEID, dstEID string, createdAtUnixMs int64, capsuleBytes []byte, chunkSize int, nextSeq func() uint64) ([][]byte, error) {
	if nextSeq == nil {
		return nil, fmt.Errorf("forward: chunk capsule: nextSeq is required (P-3 per-source sequence)")
	}
	pdus, err := capsule.Split(capsuleBytes, chunkSize)
	if err != nil {
		return nil, err
	}
	out := make([][]byte, len(pdus))
	for i, pdu := range pdus {
		b, err := bundle.NewManagement(srcEID, dstEID, createdAtUnixMs, capsule.ChunkLifetime, nextSeq(), pdu)
		if err != nil {
			return nil, fmt.Errorf("forward: chunk bundle %d/%d: %w", i+1, len(pdus), err)
		}
		wire, err := bundle.Encode(b)
		if err != nil {
			return nil, fmt.Errorf("forward: encode chunk bundle %d/%d: %w", i+1, len(pdus), err)
		}
		out[i] = wire
	}
	return out, nil
}

// dispatchUpdates routes one parsed, profile-valid bundle through the §9.4
// updates seam. It reports whether the payload WAS chunk cargo addressed to
// this node (or the og-admin group) — the caller has already fed it to the
// Receiver and must now RE-ADMIT it into the store (the §8.5 convergence
// rule: a consumed copy must enter OUR store, or the peers that hold it
// re-deliver it until its TTL dies).
func (s *Sink) dispatchUpdates(b *bundle.Bundle) bool {
	if s.Updates == nil || b.Source.IsNone() {
		return false // updates off (no receiver), or an anonymous shape (§3 P-4/P-5: chunk cargo is identified)
	}
	switch b.Destination.String() {
	case s.LocalEID, AdminEID:
	default:
		return false // transit cargo for another node: the store relays it (bulk)
	}
	// The summary bundle (§7.1: version byte 0x01 ‖ 512 B, EXACT length) is
	// dispatched before this peek precisely so a filter whose bytes 8..16
	// parse as a header can never be mistaken for a chunk; the reverse
	// ambiguity (a real chunk PDU of exactly 513 B whose capsule_id starts
	// 0x01) is unreachable at the pinned §9.1 chunk sizes.
	if !capsule.LooksLikeChunk(b.Payload) {
		return false
	}
	// Reassembly is this node's DELIVERY of the capsule: verify signature,
	// arch and anti-rollback at completion (the Receiver's staging order)
	// — never per chunk, never per relay hop.
	s.Updates.OfferChunk(b.Payload, b.Lifetime)
	return true
}
