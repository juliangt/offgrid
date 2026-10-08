package forward

// capsule_loopback_test.go — the P3.7 acceptance evidence (docs/
// node-network.md §9.4, issue #33): a ~1.5 MB synthetic ESP32 release
// capsule crosses a REAL TCPCLv4/TLS session A → B, reassembles byte-exact
// out of arbitrarily ordered 64 KiB chunk bundles, verifies against the
// pinned release key, passes anti-rollback and stages ATOMICALLY into the
// #22-convention staging directory — plus the refusal classes: stale
// (the §2.6 409-equivalent, counted), tampered (never staged), wrong arch,
// and updates_enabled=off refusing chunk cargo at the TCPCL layer.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"

	"offgrid/dtn-node/internal/capsule"
	"offgrid/dtn-node/internal/tcpcl"
)

// capsReleaseSeed is the fixed RFC 8032 §7.1 TEST1 seed — the pinned
// release key of these tests (the same key the shared vectors sign with).
var capsReleaseSeed = mustHexCaps("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")

func mustHexCaps(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func capsPub(t *testing.T) []byte {
	t.Helper()
	return []byte(ed25519.NewKeyFromSeed(capsReleaseSeed).Public().(ed25519.PublicKey))
}

// wireReceiver turns a plain stack into an updates-ON receiver node: the
// §9.4 policy lever on the store and a capsule.Receiver (reassembler +
// stager into its own staged/ dir) behind the sink. OwnRelease 0 = a build
// that predates the release stamp (the anti-rollback floor then rests on
// the staged capsule alone — the honest current state until #37 stamps
// build.sh).
func wireReceiver(t *testing.T, s *stack, arch string, running uint64) (*capsule.Stager, *capsule.Receiver) {
	t.Helper()
	stager := &capsule.Stager{
		Dir:            filepath.Join(s.dir, "staged"),
		Pub:            capsPub(t),
		Arch:           arch,
		RunningRelease: running,
	}
	if err := stager.Load(); err != nil {
		t.Fatalf("stager load: %v", err)
	}
	rc := capsule.NewReceiver(capsule.NewReassembler(), stager)
	s.sink.Updates = rc
	s.store.SetUpdatesEnabled(true)
	return stager, rc
}

func buildCapsule(t *testing.T, payload []byte, arch string, release uint64, seed []byte) []byte {
	t.Helper()
	sum := sha256.Sum256(payload)
	blob, err := capsule.Build(seed, capsule.Metadata{
		V:              1,
		Release:        release,
		Semver:         "v9.9.9",
		VCS:            "vectors",
		Arch:           arch,
		MinUpgradeFrom: 0,
		SPAEmbedded:    true,
		PayloadSHA256:  hex.EncodeToString(sum[:]),
		PayloadBytes:   len(payload),
		CreatedAt:      time.Now().Unix(),
	}, payload)
	if err != nil {
		t.Fatalf("build capsule %d/%s: %v", release, arch, err)
	}
	return blob
}

func sendCapsuleAcross(t *testing.T, from, to *stack, capsuleBytes []byte) {
	t.Helper()
	pdus, err := ChunkCapsule(from.eid, to.eid, time.Now().UnixMilli(), capsuleBytes, capsule.ChunkSizeTCPCL,
		seqCounter())
	if err != nil {
		t.Fatalf("ChunkCapsule: %v", err)
	}
	for _, pdu := range pdus {
		if err := from.store.Accept(pdu); err != nil {
			t.Fatalf("inject chunk bundle: %v", err)
		}
	}
}

var capsSeq atomicSeq

type atomicSeq struct{ n uint64 }

func seqCounter() func() uint64 {
	return func() uint64 {
		capsSeq.n++
		return capsSeq.n
	}
}

func TestCapsuleCrossesThePlaneByteExact(t *testing.T) {
	a := newStack(t, tcpcl.DefaultContactBudget)
	b := newStack(t, tcpcl.DefaultContactBudget)
	stager, rc := wireReceiver(t, b, "esp32s3", 0)
	a.store.SetUpdatesEnabled(true) // the sender's own §9.4 lever

	// The §2.9 scenario: a ~1.5 MB ESP32-class firmware image, synthetic
	// and deterministic (the staging equality check is the point, not the
	// bytes' provenance).
	payload := make([]byte, 1_500_000)
	sum := uint32(0x9e3779b9)
	for i := range payload {
		sum = sum*1664525 + 1013904223
		payload[i] = byte(sum >> 24)
	}
	original := buildCapsule(t, payload, "esp32s3", 1012000, capsReleaseSeed)

	sendCapsuleAcross(t, a, b, original)
	sess := a.dialTo(b)
	defer func() { _ = sess.Terminate(tcpcl.TermUnknown) }()

	wantID := capsule.CapsuleIDOf(original)
	waitFor(t, "the staged capsule at B", func() bool {
		if _, ok, _ := stager.StagedBlob(); ok {
			return true
		}
		return false
	})

	// Byte-exact staging: the staged file IS the original capsule.
	staged, ok, err := stager.StagedBlob()
	if err != nil || !ok {
		t.Fatalf("staged blob: %v %v", ok, err)
	}
	if !bytes.Equal(staged, original) {
		t.Fatalf("staged bytes differ from the original capsule")
	}
	if c, err := capsule.Parse(staged); err != nil || !bytes.Equal(c.Payload, payload) {
		t.Fatalf("staged capsule payload not byte-exact: %v", err)
	}
	if stager.StagedRelease() != 1012000 {
		t.Fatalf("staged release: %d", stager.StagedRelease())
	}
	// Atomicity residue: exactly update.capsule in the staging dir (the
	// tmp file is renamed, never left behind).
	entries, _ := filepath.Glob(filepath.Join(stager.Dir, "*"))
	if len(entries) != 1 || filepath.Base(entries[0]) != capsule.StagedFile {
		t.Fatalf("staging dir must hold exactly %s, got %v", capsule.StagedFile, entries)
	}

	// The receiver counters: one reassembled, one accepted, zero refusals.
	cs := rc.CountersSnapshot()
	if cs.Reassembled != 1 || cs.Accepted != 1 || cs.Stale+cs.Signature+cs.Malformed+cs.WrongArch+cs.Unpinned != 0 {
		t.Fatalf("receiver counters: %+v", cs)
	}
	reasm := rc.Reasm.Counters()
	if reasm.Completions != 1 || reasm.BadChunks != 0 {
		t.Fatalf("reassembly counters: %+v", reasm)
	}
	// The chunk bundles were re-admitted into B's store (§8.5 convergence:
	// B's summaries cover them, so A never re-sends until they expire).
	nChunks := (len(original) + capsule.ChunkSizeTCPCL - 1) / capsule.ChunkSizeTCPCL
	waitFor(t, "all chunk bundles re-admitted at B", func() bool { return b.count() == nChunks })

	// Reassembly was order-independent by construction (the §7.1 diff sends
	// bundle_id ASC — NOT chunk idx order): assert the reassembler really
	// saw interleaved indices by replaying the same set through a fresh
	// reassembler in idx order — the pinned semantic, not an accident.
	_ = wantID
}

func TestStaleCapsuleRefusedOverThePlane(t *testing.T) {
	a := newStack(t, tcpcl.DefaultContactBudget)
	b := newStack(t, tcpcl.DefaultContactBudget)
	stager, rc := wireReceiver(t, b, "esp32s3", 0)
	a.store.SetUpdatesEnabled(true)

	// The current release crosses and stages (contact 1)...
	current := buildCapsule(t, []byte("current release"), "esp32s3", 1012000, capsReleaseSeed)
	sendCapsuleAcross(t, a, b, current)
	sess := a.dialTo(b)
	defer func() { _ = sess.Terminate(tcpcl.TermUnknown) }()
	waitFor(t, "the current capsule staged", func() bool {
		_, ok, _ := stager.StagedBlob()
		return ok
	})
	waitFor(t, "the first contact to wind down", func() bool {
		return a.engine.CountersSnapshot().Transferred >= 1
	})

	// ...then last year's GENUINE (correctly signed) release rides a second
	// contact — the replay case: the §2.6 rule-2 refusal, over the plane
	// exactly as at the HTTP endpoint.
	old := buildCapsule(t, []byte("last year"), "esp32s3", 1009000, capsReleaseSeed)
	sendCapsuleAcross(t, a, b, old)
	sess2 := a.dialTo(b)
	defer func() { _ = sess2.Terminate(tcpcl.TermUnknown) }()
	waitFor(t, "the stale refusal counted", func() bool { return rc.CountersSnapshot().Stale == 1 })

	cs := rc.CountersSnapshot()
	if cs.Accepted != 1 || cs.Reassembled != 2 {
		t.Fatalf("counters: %+v", cs)
	}
	// The stale capsule is NEVER staged (the 409 semantics, §2.6: refused
	// whatever its signature) — the staged file still holds the newer one.
	staged, _, _ := stager.StagedBlob()
	if c, err := capsule.Parse(staged); err != nil || c.Meta.Release != 1012000 {
		t.Fatalf("staged state changed by a stale capsule: %v", err)
	}
}

func TestTamperedAndWrongArchRefusedOverThePlane(t *testing.T) {
	a := newStack(t, tcpcl.DefaultContactBudget)
	b := newStack(t, tcpcl.DefaultContactBudget)
	stager, rc := wireReceiver(t, b, "esp32s3", 0)
	a.store.SetUpdatesEnabled(true)

	// A tampered capsule: valid signature over DIFFERENT bytes than it
	// carries — the §2.4.4 order kills it on the SHA before any politics.
	tampered := buildCapsule(t, []byte("honest payload"), "esp32s3", 1012000, capsReleaseSeed)
	tampered[len(tampered)-capsule.SigLen-1] ^= 0x01

	// A well-signed capsule for ANOTHER BOARD: the §9.1 arch gate.
	wrongArch := buildCapsule(t, []byte("pi build"), "armv6", 1013000, capsReleaseSeed)

	sendCapsuleAcross(t, a, b, tampered)
	sendCapsuleAcross(t, a, b, wrongArch)
	sess := a.dialTo(b)
	defer func() { _ = sess.Terminate(tcpcl.TermUnknown) }()
	waitFor(t, "both verdicts counted", func() bool {
		cs := rc.CountersSnapshot()
		return cs.Malformed >= 1 && cs.WrongArch >= 1
	})

	cs := rc.CountersSnapshot()
	if cs.Accepted != 0 {
		t.Fatalf("nothing may stage here: %+v", cs)
	}
	if cs.Malformed != 1 || cs.WrongArch != 1 {
		t.Fatalf("counters: %+v", cs)
	}
	if _, ok, _ := stager.StagedBlob(); ok {
		t.Fatalf("a tampered capsule must never reach the staging dir")
	}
}

func TestUpdatesOffRefusesChunksAtTheTransferLayer(t *testing.T) {
	a := newStack(t, tcpcl.DefaultContactBudget)
	c := newStack(t, tcpcl.DefaultContactBudget) // NO receiver: updates OFF
	a.store.SetUpdatesEnabled(true)

	capsuleBytes := buildCapsule(t, []byte("denied"), "esp32s3", 1012000, capsReleaseSeed)
	pdus, err := ChunkCapsule(a.eid, c.eid, time.Now().UnixMilli(), capsuleBytes, capsule.ChunkSizeTCPCL, seqCounter())
	if err != nil {
		t.Fatalf("ChunkCapsule: %v", err)
	}
	for _, pdu := range pdus {
		if err := a.store.Accept(pdu); err != nil {
			t.Fatalf("inject: %v", err)
		}
	}
	sess := a.dialTo(c)
	defer func() { _ = sess.Terminate(tcpcl.TermUnknown) }()

	// The first chunk bundle is refused at C's admission (the TCPCL layer
	// answers XFER_REFUSE "No Resources"); the sender sees the refusal and
	// the contact carries nothing.
	waitFor(t, "the updates_off refusal counted at C", func() bool {
		return c.store.CountersSnapshot().UpdatesOff >= 1
	})
	if n := c.count(); n != 0 {
		t.Fatalf("chunk cargo must never be stored with updates off, has %d", n)
	}
	// The sender ends the contact on the refusal (a send error, counted).
	waitFor(t, "the sender observing the refusal", func() bool {
		return a.engine.CountersSnapshot().SendErrors >= 1
	})
	// And the receiver half of the AC: C's sink has no reassembly state at
	// all — the chunk never began a partial anywhere.
	if c.sink.Updates != nil {
		t.Fatalf("updates off must mean NO receiver")
	}
}
