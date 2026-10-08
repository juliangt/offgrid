package forward

// updates_test.go — the P3.7 updates seam (docs/node-network.md §9.4):
//
//   - the §9.4 admission policy: updates_enabled OFF refuses chunk cargo at
//     admission (counted) — and never touches anonymous (user-plane) shapes
//     whose bytes merely pass the arithmetic peek;
//   - the classification: chunk cargo is BULK even addressed to og-admin;
//   - the §7.4-row-2 priority AC (the TCPCL equivalent of the LoRa rule
//     "bulk only while the mail queue is empty"): a mail bundle queued
//     behind bulk capsule chunks leaves within ONE transfer window under a
//     tight contact budget, and bulk resumes on the next contact.

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"offgrid/dtn-node/internal/bundle"
	"offgrid/dtn-node/internal/capsule"
	"offgrid/dtn-node/internal/tcpcl"
)

func chunkBundleFor(t *testing.T, src, dst string, capsuleBytes []byte, idx int, created time.Time, seq uint64) []byte {
	t.Helper()
	pdus, err := capsule.Split(capsuleBytes, 1000)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	b, err := bundle.NewManagement(src, dst, created.UnixMilli(), capsule.ChunkLifetime, seq, pdus[idx])
	if err != nil {
		t.Fatalf("chunk bundle: %v", err)
	}
	pdu, err := bundle.Encode(b)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return pdu
}

func TestUpdatesOffRefusesChunkCargoAtAdmission(t *testing.T) {
	clock := &testClock{t: time.Unix(1791072000, 0)}
	st := openTestStore(t, 100, clock)
	src := "dtn://og.0123456789abcdef/"
	dst := "dtn://og.dac073e0123bdea5/"

	chunk := chunkBundleFor(t, src, dst, bytes.Repeat([]byte{0x42}, 2500), 0, clock.t, 1)

	// Default (updates OFF — the pinned default): refused at admission,
	// counted, never stored.
	if _, err := st.accept(chunk); !errors.Is(err, ErrUpdatesDisabled) {
		t.Fatalf("chunk with updates off: %v, want ErrUpdatesDisabled", err)
	}
	if cs := st.CountersSnapshot(); cs.UpdatesOff != 1 {
		t.Fatalf("updates_off counter: %+v", cs)
	}
	if n, _ := st.Count(); n != 0 {
		t.Fatalf("refused chunk cargo must never be stored")
	}

	// An ANONYMOUS bundle whose bytes pass the peek is never touched — the
	// user plane cannot care whether updates are on.
	anonPayload := make([]byte, 51)
	anonPayload[11] = 1 // total = 1 at bytes 8..11 → the arithmetic peek passes
	for i := 16; i < len(anonPayload); i++ {
		anonPayload[i] = 0x42
	}
	anon, err := bundle.NewManagement("dtn:none", "dtn:og-updates", clock.t.UnixMilli(), 3600, 1, anonPayload)
	if err != nil {
		t.Fatalf("anon bundle: %v", err)
	}
	anon.Hop = 0
	anonPdu, err := bundle.Encode(anon)
	if err != nil {
		t.Fatalf("encode anon: %v", err)
	}
	if _, err := bundle.Parse(anonPdu, clock.t); err != nil {
		t.Fatalf("anon shape: %v", err)
	}
	if v, aerr := st.accept(anonPdu); v != VerdictAccepted || aerr != nil {
		t.Fatalf("anonymous chunk-shaped bundle must pass admission untouched: %v %v", v, aerr)
	}

	// Policy on: the same chunk is admitted, classified BULK (never
	// management, even though the store rules would call an identified
	// bundle to a plain EID bulk anyway — the og-admin case is the pin).
	st.SetUpdatesEnabled(true)
	chunkAdmin := chunkBundleFor(t, src, "dtn://og-admin/", bytes.Repeat([]byte{0x42}, 2500), 0, clock.t, 2)
	if v, aerr := st.accept(chunkAdmin); v != VerdictAccepted || aerr != nil {
		t.Fatalf("chunk with updates on: %v %v", v, aerr)
	}
	id := idOf(t, chunkAdmin)
	stored, ok, err := st.Get(id)
	if err != nil || !ok {
		t.Fatalf("stored: %v %v", ok, err)
	}
	b, err := bundle.Parse(stored, clock.t)
	if err != nil {
		t.Fatalf("reparse: %v", err)
	}
	if got := Classify(b.Destination, b.Source, b.Payload); got != ClassBulk {
		t.Fatalf("chunk cargo to og-admin classified %s, want bulk", got)
	}
}

func TestMailQueuedBehindBulkLeadsWithinOneWindow(t *testing.T) {
	// The §7.4-row-2 TCPCL equivalent: under a contact budget that fits the
	// summary plus exactly one bundle, a mail bundle queued BEHIND six bulk
	// capsule chunks goes out in this window — not after all bulk — and the
	// chunks defer to the next contact. Bulk resumes once the mail lane is
	// empty.
	a := newStack(t, tcpcl.DefaultContactBudget)
	b := newStack(t, tcpcl.DefaultContactBudget)
	created := time.Now()

	capsuleBytes := bytes.Repeat([]byte{0xC7}, 6000) // six 1000 B chunks
	// The SENDER carries updates enabled (its own §9.4 policy lever — the
	// receiver-side lever is what stays off in the admission test above).
	a.store.SetUpdatesEnabled(true)
	var chunkPDUs [][]byte
	for i := 0; i < 6; i++ {
		chunkPDUs = append(chunkPDUs, chunkBundleFor(t, a.eid, b.eid, capsuleBytes, i, created, uint64(i+1)))
	}
	mailPDU := mkBundle(t, bytes.Repeat([]byte("M"), 64), created, 3600, 0, "mail")

	// Inject chunks FIRST (the mail is queued behind them), then the mail.
	for _, pdu := range chunkPDUs {
		if err := a.store.Accept(pdu); err != nil {
			t.Fatalf("inject chunk: %v", err)
		}
	}
	if err := a.store.Accept(mailPDU); err != nil {
		t.Fatalf("inject mail: %v", err)
	}
	mailID := idOf(t, mailPDU)

	// Sanity: the classification put the chunks in bulk, the mail in mail.
	var bulkN, mailN int
	entries, err := a.store.Entries()
	if err != nil {
		t.Fatalf("entries: %v", err)
	}
	for _, en := range entries {
		switch en.Class {
		case ClassBulk:
			bulkN++
		case ClassMail:
			mailN++
		}
	}
	if bulkN != 6 || mailN != 1 {
		t.Fatalf("classification at A: bulk %d mail %d, want 6/1", bulkN, mailN)
	}

	// The contact budget: the summary bundle + the mail PDU, exactly —
	// the first chunk would not fit. Compute the summary length with the
	// engine's own builder (tests are in-package).
	summaryPDU, err := a.engine.summaryBundle(b.eid, &Summary{})
	if err != nil {
		t.Fatalf("summary builder: %v", err)
	}
	budget := int64(len(summaryPDU) + len(mailPDU))
	a.cfg.ContactBudget = budget
	b.cfg.ContactBudget = budget

	sess := a.dialTo(b)
	defer func() { _ = sess.Terminate(tcpcl.TermUnknown) }()
	waitFor(t, "the mail at B", func() bool {
		_, ok, _ := b.store.Get(mailID)
		return ok
	})
	// The AC, precisely: mail left within THIS window while all six chunks
	// deferred — not after them.
	if got := a.engine.counters.Transferred.Load(); got != 1 {
		t.Fatalf("transferred %d bundles, want exactly the mail", got)
	}
	if got := a.engine.counters.DeferredOut.Load(); got < 6 {
		t.Fatalf("deferred %d, want all six chunks", got)
	}
	if b.count() != 1 {
		t.Fatalf("B must hold exactly the mail bundle, has %d", b.count())
	}

	// The next contact (§7.4: deferrals retry) carries the chunks: bulk
	// flows once the mail queue is empty. B's own updates policy lever is
	// on here (the chunks relay through its store as bulk — B has no
	// Receiver, so no reassembly, just §7.5 cargo).
	b.store.SetUpdatesEnabled(true)
	a.cfg.ContactBudget = tcpcl.DefaultContactBudget
	b.cfg.ContactBudget = tcpcl.DefaultContactBudget
	waitFor(t, "the engine to wind the first contact down", func() bool { return true })
	sess2 := a.dialTo(b)
	defer func() { _ = sess2.Terminate(tcpcl.TermUnknown) }()
	waitFor(t, "the chunks at B", func() bool { return b.count() == 7 })
}
