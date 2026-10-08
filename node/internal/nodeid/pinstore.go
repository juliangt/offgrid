package nodeid

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
)

// The pin store: anchor trust roots + TOFU peer pins (docs/node-network.md
// §6.1 — offline-maintenance §3.5's first-contact pattern applied to node
// keys). A node verifies role certs ONLY against PINNED anchor public keys
// (§2.2) and opens link sessions with peers whose key matches the cached
// role cert or the first-contact pin. A key change with no higher-seq cert
// fails LOUDLY — a sentinel error, never a silent overwrite.

// ErrAnchorPinConflict fires when a DIFFERENT public key is offered under a
// fingerprint that is already pinned. The fingerprint is SHA-256-derived, so
// this is a collision-class event: fail loudly, never overwrite.
var ErrAnchorPinConflict = fmt.Errorf("nodeid: a different anchor key was offered under a pinned fingerprint")

// ErrPeerKeyChanged is the loud TOFU sentinel of §6.1: a peer EID presented
// a different node key than the one pinned at first contact, with no
// higher-seq role certificate to explain the change.
var ErrPeerKeyChanged = fmt.Errorf("nodeid: pinned peer key changed with no higher-seq certificate (TOFU)")

// PinStore is the in-memory pin set. Zero value is ready to use. It is
// SAFE FOR CONCURRENT USE: several TCPCL/link sessions share one store and
// a first contact can TOFU-pin while another session reads (1.4.0 — the
// pin checks run inside concurrent TLS handshakes).
type PinStore struct {
	mu      sync.Mutex
	anchors map[[FingerprintLen]byte][KeyLen]byte // anchor fp -> anchor pub
	peers   map[string][KeyLen]byte               // peer EID -> node key
}

// NewPinStore returns an empty store.
func NewPinStore() *PinStore {
	return &PinStore{
		anchors: make(map[[FingerprintLen]byte][KeyLen]byte),
		peers:   make(map[string][KeyLen]byte),
	}
}

// lock returns the maps with the mutex held (internal helper discipline:
// public methods lock exactly once, the lock* helpers never re-lock).
func (p *PinStore) lock() func() {
	p.mu.Lock()
	return p.mu.Unlock
}

// PinAnchor pins an anchor public key (TOFU: first sight records it, the
// same key again is a no-op, a different key under the same 8-byte
// fingerprint fails with ErrAnchorPinConflict). Multiple anchors coexist
// (each is keyed by its own fingerprint) — anchor rotation is a fresh pin,
// never an overwrite (§2.2: kid selects among pinned anchors).
func (p *PinStore) PinAnchor(pub []byte) error {
	if len(pub) != KeyLen {
		return fmt.Errorf("nodeid: anchor public key must be %d bytes, got %d", KeyLen, len(pub))
	}
	fp := Fingerprint(pub)
	var key [KeyLen]byte
	copy(key[:], pub)
	defer p.lock()()
	if cur, ok := p.anchors[fp]; ok {
		if cur != key {
			return fmt.Errorf("%w: fingerprint %s", ErrAnchorPinConflict, hex.EncodeToString(fp[:]))
		}
		return nil
	}
	p.anchors[fp] = key
	return nil
}

// Anchor returns the pinned public key for a fingerprint.
func (p *PinStore) Anchor(fp [FingerprintLen]byte) ([]byte, bool) {
	defer p.lock()()
	if key, ok := p.anchors[fp]; ok {
		return append([]byte(nil), key[:]...), true
	}
	return nil, false
}

// AnchorCount is the number of pinned anchors.
func (p *PinStore) AnchorCount() int {
	defer p.lock()()
	return len(p.anchors)
}

// PinPeer records a peer's node key for its EID (TOFU first contact).
// Same key again: no-op. Different key: ErrPeerKeyChanged — the loud
// warning; the caller drops the session (fail-closed, §6.1).
func (p *PinStore) PinPeer(eid string, nodeKey []byte) error {
	if _, err := ParseEID(eid); err != nil {
		return err
	}
	if len(nodeKey) != KeyLen {
		return fmt.Errorf("nodeid: node key must be %d bytes, got %d", KeyLen, len(nodeKey))
	}
	var key [KeyLen]byte
	copy(key[:], nodeKey)
	defer p.lock()()
	if cur, ok := p.peers[eid]; ok {
		if cur != key {
			return fmt.Errorf("%w: %s", ErrPeerKeyChanged, eid)
		}
		return nil
	}
	p.peers[eid] = key
	return nil
}

// Peer returns the pinned node key for an EID.
func (p *PinStore) Peer(eid string) ([]byte, bool) {
	defer p.lock()()
	if key, ok := p.peers[eid]; ok {
		return append([]byte(nil), key[:]...), true
	}
	return nil, false
}

// PeerCount is the number of pinned peers.
func (p *PinStore) PeerCount() int {
	defer p.lock()()
	return len(p.peers)
}

// ResolvePeer is the §6.1 session gate: a peer presenting nodeKey for eid
// passes when the key matches its cached role certificate (the cert is the
// authority), else the TOFU pin, else it becomes the first-contact pin.
// Order matters: the cert wins over an older pin (a higher-seq cert is the
// only honest way a key changes).
func (p *PinStore) ResolvePeer(eid string, nodeKey []byte, cert *Cert) error {
	if cert != nil {
		if !bytes.Equal(cert.NodeKey, nodeKey) {
			return fmt.Errorf("%w: %s presents a key its role certificate does not certify", ErrPeerKeyChanged, eid)
		}
		return p.PinPeer(eid, nodeKey) // refresh/adopt the certified key
	}
	return p.PinPeer(eid, nodeKey)
}

// --- persistence -----------------------------------------------------------
//
// Marshal format (documented, stable, deterministic): JSON object
//
//	{"v":1,"anchors":[{"fp":"<16hex>","pub":"<64hex>"}...],
//	 "peers":[{"eid":"dtn://og.<fp>/","key":"<64hex>"}...]}
//
// members in this exact order; anchors sorted by fingerprint, peers by EID.
// An unknown v fails Unmarshal (fail-closed forward compatibility: a newer
// store must not be silently truncated to v1).

type pinRecord struct {
	FP  string `json:"fp"`
	Pub string `json:"pub"`
}

type peerRecord struct {
	EID string `json:"eid"`
	Key string `json:"key"`
}

type pinStoreDoc struct {
	V       int          `json:"v"`
	Anchors []pinRecord  `json:"anchors,omitempty"`
	Peers   []peerRecord `json:"peers,omitempty"`
}

// Marshal renders the store in the documented format.
func (p *PinStore) Marshal() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	doc := pinStoreDoc{V: 1}
	fps := make([][FingerprintLen]byte, 0, len(p.anchors))
	for fp := range p.anchors {
		fps = append(fps, fp)
	}
	sort.Slice(fps, func(i, j int) bool {
		return bytes.Compare(fps[i][:], fps[j][:]) < 0
	})
	for _, fp := range fps {
		key := p.anchors[fp]
		doc.Anchors = append(doc.Anchors, pinRecord{
			FP:  hex.EncodeToString(fp[:]),
			Pub: hex.EncodeToString(key[:]),
		})
	}
	eids := make([]string, 0, len(p.peers))
	for eid := range p.peers {
		eids = append(eids, eid)
	}
	sort.Strings(eids)
	for _, eid := range eids {
		key := p.peers[eid]
		doc.Peers = append(doc.Peers, peerRecord{
			EID: eid,
			Key: hex.EncodeToString(key[:]),
		})
	}
	return json.MarshalIndent(doc, "", "  ")
}

// UnmarshalPinStore parses the Marshal format (with a trailing newline
// tolerated).
func UnmarshalPinStore(b []byte) (*PinStore, error) {
	var doc pinStoreDoc
	if err := json.Unmarshal(bytes.TrimSpace(b), &doc); err != nil {
		return nil, fmt.Errorf("nodeid: pin store: %w", err)
	}
	if doc.V != 1 {
		return nil, fmt.Errorf("nodeid: pin store v must be 1, got %d", doc.V)
	}
	p := NewPinStore()
	for _, a := range doc.Anchors {
		pub, err := hex.DecodeString(a.Pub)
		if err != nil || len(pub) != KeyLen {
			return nil, fmt.Errorf("nodeid: pin store anchor %s: pub must be 64 hex chars of the key", a.FP)
		}
		raw, err := hex.DecodeString(a.FP)
		if err != nil || len(raw) != FingerprintLen {
			return nil, fmt.Errorf("nodeid: pin store anchor: fp must be 16 hex chars")
		}
		var fp [FingerprintLen]byte
		copy(fp[:], raw)
		if Fingerprint(pub) != fp {
			return nil, fmt.Errorf("nodeid: pin store anchor %s: fp does not match pub (corrupt store)", a.FP)
		}
		if err := p.PinAnchor(pub); err != nil {
			return nil, err
		}
	}
	for _, pr := range doc.Peers {
		key, err := hex.DecodeString(pr.Key)
		if err != nil || len(key) != KeyLen {
			return nil, fmt.Errorf("nodeid: pin store peer %s: key must be 64 hex chars", pr.EID)
		}
		if err := p.PinPeer(pr.EID, key); err != nil {
			return nil, err
		}
	}
	return p, nil
}
