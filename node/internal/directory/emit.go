package directory

// emit.go — the sending half of §9.3: a published card becomes ONE
// identified bundle (§3 P-5) to the well-known directory group. The payload
// is the card's COSE bytes VERBATIM behind the hop octet (the P3.0 freeze:
// "hop octet ‖ raw self-signed record bytes") — the node never re-signs a
// card (it cannot: the signature is the user's own, §3.1.1).

import (
	"fmt"

	"offgrid/dtn-node/internal/bundle"
)

// EmitCardBundle wraps one card as the §9.3 emission: source = the emitting
// node's EID, destination = dtn://og-dir/ (the group every federation peer
// consumes), lifetime = CardBundleLifetime, hop 0, seq = the per-source
// monotonic bundle sequence (§3 P-3; wire hygiene only — dedup is P-7).
// The bundle classifies BULK (§7.3: cards are not management, and §3.4's
// eviction operates on the directory table, not the bundle store — the
// decision is frozen in §9.3).
func EmitCardBundle(srcEID string, cardCose []byte, createdAtUnixMs int64, seq uint64) ([]byte, error) {
	if len(cardCose) == 0 || len(cardCose) > CardMaxBytes {
		return nil, fmt.Errorf("directory: emit: card length %d outside [1, %d]", len(cardCose), CardMaxBytes)
	}
	b, err := bundle.NewManagement(srcEID, DirEID, createdAtUnixMs, CardBundleLifetime, seq, cardCose)
	if err != nil {
		return nil, fmt.Errorf("directory: emit: %w", err)
	}
	pdu, err := bundle.Encode(b)
	if err != nil {
		return nil, fmt.Errorf("directory: emit: encode: %w", err)
	}
	return pdu, nil
}
