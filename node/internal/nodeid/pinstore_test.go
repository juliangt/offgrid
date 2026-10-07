package nodeid

// The TOFU pin store (§6.1 / offline-maintenance §3.5): first-contact
// pinning, loud key-change detection, and the Marshal/Unmarshal round trip
// later phases will use to persist it.

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func TestPinAnchorTOFU(t *testing.T) {
	anchor, _, other := testKeypairs(t)
	p := NewPinStore()
	if err := p.PinAnchor(anchor.Public); err != nil {
		t.Fatal(err)
	}
	// Same key again: idempotent.
	if err := p.PinAnchor(anchor.Public); err != nil {
		t.Fatal(err)
	}
	// The pinned key is retrievable by fingerprint.
	fp := Fingerprint(anchor.Public)
	got, ok := p.Anchor(fp)
	if !ok || !bytes.Equal(got, anchor.Public) {
		t.Fatal("pinned anchor not retrievable")
	}
	// A different key under the same fingerprint: the loud sentinel. (Needs
	// a SHA-256 collision in reality — exactly why it must never be silent.)
	forged := append([]byte(nil), anchor.Public...)
	forged[0] ^= 0x01 // fp will differ; simulate the collision directly below
	_ = forged
	if err := p.PinAnchor(other.Public); err != nil {
		// different fp -> a second anchor, allowed (kid selects among pins)
		t.Fatalf("second anchor rejected: %v", err)
	}
	if p.AnchorCount() != 2 {
		t.Fatalf("anchor count %d", p.AnchorCount())
	}
	// Direct collision simulation: pin fp with a mutated key.
	q := NewPinStore()
	q.PinAnchor(anchor.Public)
	var collided [KeyLen]byte
	copy(collided[:], anchor.Public)
	collided[31] ^= 0x80 // same check path as a same-fp different-key event
	q.anchors[Fingerprint(anchor.Public)] = collided
	if err := q.PinAnchor(anchor.Public); !errors.Is(err, ErrAnchorPinConflict) {
		t.Fatalf("collision: %v (want ErrAnchorPinConflict)", err)
	}
	if err := p.PinAnchor(anchor.Public[:31]); err == nil {
		t.Fatal("short key accepted")
	}
}

func TestPinPeerTOFU(t *testing.T) {
	_, node, node2 := testKeypairs(t)
	eid := EID(Fingerprint(node.Public))
	p := NewPinStore()
	if err := p.PinPeer(eid, node.Public); err != nil {
		t.Fatal(err)
	}
	if err := p.PinPeer(eid, node.Public); err != nil {
		t.Fatal(err)
	}
	got, ok := p.Peer(eid)
	if !ok || !bytes.Equal(got, node.Public) {
		t.Fatal("pin not retrievable")
	}
	// The §6.1 loud failure: same EID, different key, no higher-seq cert.
	if err := p.PinPeer(eid, node2.Public); !errors.Is(err, ErrPeerKeyChanged) {
		t.Fatalf("key change: %v (want ErrPeerKeyChanged)", err)
	}
	if got2, _ := p.Peer(eid); !bytes.Equal(got2, node.Public) {
		t.Fatal("failed pin mutated the store")
	}
	// A different EID is a different peer.
	if err := p.PinPeer(EID(Fingerprint(node2.Public)), node2.Public); err != nil {
		t.Fatalf("second peer: %v", err)
	}
	if p.PeerCount() != 2 {
		t.Fatalf("peer count %d", p.PeerCount())
	}
	if err := p.PinPeer("not-an-eid", node.Public); err == nil {
		t.Fatal("malformed EID accepted")
	}
}

func TestResolvePeer(t *testing.T) {
	anchor, node, node2 := testKeypairs(t)
	now := vecNow
	eid := EID(Fingerprint(node.Public))
	certCose, err := SignCert(anchor, node.Public, eid, []string{RoleEdge}, 1, now-100, now+1000, 1, now)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := VerifyCert(certCose, anchor.Public, now)
	if err != nil {
		t.Fatal(err)
	}
	p := NewPinStore()
	// First contact, no cert: pins.
	if err := p.ResolvePeer(eid, node.Public, nil); err != nil {
		t.Fatalf("first contact: %v", err)
	}
	// Same key again: fine.
	if err := p.ResolvePeer(eid, node.Public, nil); err != nil {
		t.Fatalf("same key: %v", err)
	}
	// Certified key beats/reconciles the pin (rotation path).
	if err := p.ResolvePeer(eid, node.Public, cert); err != nil {
		t.Fatalf("certified key: %v", err)
	}
	// A key the cert does NOT certify: loud, even though the pin matches
	// would-be node2 — the cert is the authority when present.
	if err := p.ResolvePeer(eid, node2.Public, cert); !errors.Is(err, ErrPeerKeyChanged) {
		t.Fatalf("uncertified key: %v", err)
	}
}

func TestPinStoreMarshalRoundTrip(t *testing.T) {
	anchor, node, node2 := testKeypairs(t)
	p := NewPinStore()
	if err := p.PinAnchor(anchor.Public); err != nil {
		t.Fatal(err)
	}
	eid := EID(Fingerprint(node.Public))
	if err := p.PinPeer(eid, node.Public); err != nil {
		t.Fatal(err)
	}
	b, err := p.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	// Documented format: v first, deterministic member order.
	head := string(b[:min(len(b), 64)])
	if !strings.Contains(head, `"v": 1`) || !strings.Contains(head, `"anchors"`) {
		t.Fatalf("format head: %s", head)
	}
	q, err := UnmarshalPinStore(b)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if q.AnchorCount() != 1 || q.PeerCount() != 1 {
		t.Fatalf("counts %d/%d", q.AnchorCount(), q.PeerCount())
	}
	got, _ := q.Anchor(Fingerprint(anchor.Public))
	if !bytes.Equal(got, anchor.Public) {
		t.Fatal("anchor round-trip")
	}
	gotPeer, _ := q.Peer(eid)
	if !bytes.Equal(gotPeer, node.Public) {
		t.Fatal("peer round-trip")
	}
	// Marshal(Unmarshal(Marshal)) is byte-stable (deterministic order).
	b2, err := q.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, b2) {
		t.Fatal("marshal is not deterministic")
	}
	// A tampered store fails loudly (fp/pub cross-check).
	bad := bytes.Replace(b, []byte(hex.EncodeToString(anchor.Public)[:2]), []byte("zz"), 1)
	if _, err := UnmarshalPinStore(bad); err == nil {
		t.Fatal("tampered store accepted")
	}
	// Unknown version fails closed.
	if _, err := UnmarshalPinStore([]byte(`{"v":2}`)); err == nil {
		t.Fatal("unknown v accepted")
	}
	_ = node2
}
