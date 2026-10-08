package storage

// directory_merge_test.go — the §3.4 merge rules and eviction policy at the
// STORAGE level (docs/node-network.md §9.3, offline-maintenance §3.4
// verbatim): MergeFederatedCard against a real SQLite store, the same store
// the HTTP register path writes (which is the property that makes a
// federated row indistinguishable from a registered one for the SPA).
//
// The signing-side rules live in internal/directory; here the merge is
// driven through directory.CardMerge values built from REAL signed cards
// (the stored-card sequence must parse out of the card column exactly as
// the merge will in production).

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"offgrid/dtn-node/internal/directory"
	"offgrid/dtn-node/internal/nodeid"
)

func mustSignerOf(t *testing.T, label string) nodeid.KeyPair {
	t.Helper()
	s := sha256.Sum256([]byte(label))
	kp, err := nodeid.NewKeyPairFromSeed(s[:])
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

func mustXOf(t *testing.T, label string) []byte {
	t.Helper()
	s := sha256.Sum256([]byte(label))
	return s[:]
}

func mustSignedCard(t *testing.T, user nodeid.KeyPair, alias string, x []byte, ts int64, seq uint64) []byte {
	t.Helper()
	cose, err := directory.SignCard(user, alias, x, ts, seq)
	if err != nil {
		t.Fatal(err)
	}
	return cose
}

func mergeReq(cose []byte, ts int64) directory.CardMerge {
	card, err := directory.ParseCard(cose)
	if err != nil {
		panic(err)
	}
	return directory.CardMerge{
		CardB64:  directory.CanonicalB64(cose),
		Raw:      cose,
		Pubkey:   card.PubkeyB64(),
		X25519:   card.X25519B64(),
		Alias:    card.Alias,
		Seq:      card.Seq,
		LastSeen: ts,
	}
}

func openMergeStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "merge.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func rowOrFail(t *testing.T, s *Store, pubkey string) *DirectoryRow {
	t.Helper()
	r, err := s.DirectoryRowOf(pubkey)
	if err != nil {
		t.Fatal(err)
	}
	if r == nil {
		t.Fatalf("no directory row for %s", pubkey)
	}
	return r
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func TestFederatedMergeRulesVerbatim(t *testing.T) {
	s := openMergeStore(t)
	user := mustSignerOf(t, "offgrid-storage-merge-test-user")
	pubkey := b64(user.Public)
	x1 := mustXOf(t, "merge-x1")
	x2 := mustXOf(t, "merge-x2")
	merger := func(cose []byte, lastSeen int64) directory.MergeResult {
		res, err := s.MergeFederatedCard(mergeReq(cose, lastSeen))
		if err != nil {
			t.Fatal(err)
		}
		return res
	}

	// Rule 1: absent pubkey → INSERT (alias/x25519/card from the card,
	// server-set last_seen/epoch, source = 1).
	c1 := mustSignedCard(t, user, "alice_77", x1, 1791072000, 1)
	if res := merger(c1, 1791072000); res.Outcome != directory.MergeInsert || res.Evictions != 0 {
		t.Fatalf("rule 1: %+v", res)
	}
	r := rowOrFail(t, s, pubkey)
	if r.Source != 1 || r.Alias != "alice_77" || r.X25519 != b64(x1) {
		t.Fatalf("rule 1 row: %+v", r)
	}
	if r.Card.String != directory.CanonicalB64(c1) {
		t.Fatal("rule 1: the card is not stored verbatim")
	}
	if r.Epoch != 1791072000/HintEpochSeconds {
		t.Fatalf("rule 1 epoch %d", r.Epoch)
	}

	// Rule 2: higher seq replaces alias/x25519/card and refreshes
	// last_seen/epoch. THE key rotation — the only way a served X25519 key
	// ever changes: across a HIGHER-SEQUENCE SIGNED record.
	c2 := mustSignedCard(t, user, "alice_prime", x2, 1791073000, 2)
	if res := merger(c2, 1791073000); res.Outcome != directory.MergeReplace {
		t.Fatalf("rule 2: %+v", res)
	}
	r = rowOrFail(t, s, pubkey)
	if r.Source != 1 || r.Alias != "alice_prime" || r.X25519 != b64(x2) {
		t.Fatalf("rule 2 row: %+v", r)
	}
	if r.LastSeen != 1791073000 || r.Epoch != 1791073000/HintEpochSeconds {
		t.Fatalf("rule 2 liveness: last_seen %d epoch %d", r.LastSeen, r.Epoch)
	}

	// Rule 3: a LOWER-seq card (the seq-1 card again, after seq 2 is stored)
	// is stale — the row is untouched, not even its last_seen (a stale card
	// must not refresh liveness).
	if res := merger(c1, 1791076000); res.Outcome != directory.MergeStale {
		t.Fatalf("rule 3: %+v", res)
	}
	if r2 := rowOrFail(t, s, pubkey); r2.Alias != "alice_prime" || r2.LastSeen != 1791073000 {
		t.Fatalf("rule 3 mutated the row: %+v", r2)
	}

	// Rule 4a: byte-equal at equal seq → duplicate, no-op.
	if res := merger(c2, 1791077000); res.Outcome != directory.MergeDuplicate {
		t.Fatalf("rule 4a: %+v", res)
	}
	if r2 := rowOrFail(t, s, pubkey); r2.LastSeen != 1791073000 {
		t.Fatalf("rule 4a refreshed last_seen: %+v", r2)
	}

	// Rule 4b: equal seq, differing content → CONFLICT: keep the existing
	// row (alias AND x25519 — the SPA continuity path stays consistent: the
	// row keeps its OLD key). This is the attack-signal case.
	c3 := mustSignedCard(t, user, "mallipe", x1, 1791072000, 2) // same seq 2, different alias+x
	if res := merger(c3, 1791078000); res.Outcome != directory.MergeConflict {
		t.Fatalf("rule 4b: %+v", res)
	}
	r = rowOrFail(t, s, pubkey)
	if r.Alias != "alice_prime" || r.X25519 != b64(x2) {
		t.Fatalf("rule 4b: the tie overwrote the row: %+v", r)
	}

	// Rule 5, both directions:
	// (a) a LOCAL upsert on a federated row promotes it to source 0;
	if err := s.UpsertDirectory(pubkey, b64(x2), "alice_local", 1791079000, 1791079000/HintEpochSeconds, nil, ""); err != nil {
		t.Fatal(err)
	}
	if r = rowOrFail(t, s, pubkey); r.Source != 0 {
		t.Fatalf("rule 5a: source %d after a local visit", r.Source)
	}
	// (b) a federated replace on the now-local row still applies (rules 2-4
	// do not care about source) and KEEPS source = 0 — presence at this node
	// is a local fact, key truth is a sequence fact.
	c4 := mustSignedCard(t, user, "alice_seq4", x1, 1791079500, 4)
	if res := merger(c4, 1791079500); res.Outcome != directory.MergeReplace {
		t.Fatalf("rule 5b: %+v", res)
	}
	if r = rowOrFail(t, s, pubkey); r.Source != 0 || r.Alias != "alice_seq4" {
		t.Fatalf("rule 5b row: %+v", r)
	}

	// A card-less row has the implied sequence 0 (rule 2's own words): a
	// seq-1 card replaces it even though the row predates the card — and
	// the row STAYS local.
	s2 := openMergeStore(t)
	if err := s2.UpsertDirectory(pubkey, b64(x1), "alice_legacy", 1791070000, 1791070000/HintEpochSeconds, nil, ""); err != nil {
		t.Fatal(err)
	}
	if res, err := s2.MergeFederatedCard(mergeReq(c1, 1791072000)); err != nil || res.Outcome != directory.MergeReplace {
		t.Fatalf("implied seq 0: %+v (%v)", res, err)
	}
	if r = rowOrFail(t, s2, pubkey); r.Source != 0 || r.Alias != "alice_77" {
		t.Fatalf("implied seq 0 row: %+v", r)
	}

	// A stored card whose text is corrupt reads as implied sequence 0 (the
	// corruption guard, never a validation path).
	if got := storedSeqOf(sql.NullString{String: "not base64!!", Valid: true}); got != 0 {
		t.Fatalf("corrupt stored card seq = %d, want 0", got)
	}
}

// TestFederatedMergeEviction pins the §3.4 eviction under the hard table
// cap: federated rows evict oldest-last_seen-first, locals are NEVER
// evicted, a full locals-only table drops the card, and the HTTP path's
// ErrCapacity behavior is untouched.
func TestFederatedMergeEviction(t *testing.T) {
	oldCap := maxDirectoryEntries
	maxDirectoryEntries = 6
	t.Cleanup(func() { maxDirectoryEntries = oldCap })

	s := openMergeStore(t)
	aliasOf := func(i int) string { return fmt.Sprintf("user_%02d", i) }
	signerOf := func(i int) nodeid.KeyPair {
		return mustSignerOf(t, "offgrid-eviction-user-"+aliasOf(i))
	}
	cardFor := func(i int, ts int64) []byte {
		return mustSignedCard(t, signerOf(i), aliasOf(i), mustXOf(t, "evict-x-"+aliasOf(i)), ts, 1)
	}
	merger := func(cose []byte, lastSeen int64) directory.MergeResult {
		res, err := s.MergeFederatedCard(mergeReq(cose, lastSeen))
		if err != nil {
			t.Fatal(err)
		}
		return res
	}

	// Fill the table with 6 federated rows, oldest first (six DIFFERENT
	// identities — the merge dedup key is the pubkey).
	for i := 0; i < 6; i++ {
		c := cardFor(i, int64(1791070000+i))
		if res := merger(c, int64(1791070000+i)); res.Outcome != directory.MergeInsert {
			t.Fatalf("seed %d: %+v", i, res)
		}
	}
	if n, err := s.DirectoryCount(); err != nil || n != 6 {
		t.Fatalf("seed count %d (%v)", n, err)
	}

	// One more card at the cap: the OLDEST federated row (user_00) is
	// evicted, the newcomer lands, the cap holds.
	oldest := b64(signerOf(0).Public)
	newest := cardFor(6, 1791070100)
	res := merger(newest, 1791070100)
	if res.Outcome != directory.MergeInsert || res.Evictions != 1 {
		t.Fatalf("evicting insert: %+v", res)
	}
	if n, _ := s.DirectoryCount(); n != 6 {
		t.Fatalf("count after eviction %d, want 6 (the cap holds)", n)
	}
	if r, _ := s.DirectoryRowOf(oldest); r != nil {
		t.Fatal("the oldest federated row survived the eviction")
	}
	if r, _ := s.DirectoryRowOf(b64(signerOf(6).Public)); r == nil {
		t.Fatal("the newcomer did not land")
	}

	// A flood respects the cap: 20 more cards, one eviction each, never a
	// row beyond the cap, and only federated rows ever disappear.
	for i := 0; i < 20; i++ {
		c := cardFor(7+i, int64(1791070200+i))
		if res := merger(c, int64(1791070200+i)); res.Outcome != directory.MergeInsert || res.Evictions != 1 {
			t.Fatalf("flood %d: %+v", i, res)
		}
		if n, _ := s.DirectoryCount(); n != 6 {
			t.Fatalf("flood %d: count %d", i, n)
		}
	}

	// Locals are NEVER auto-evicted: promote an existing federated row to
	// local (an EXISTING row's upsert always refreshes — the cap never
	// blocks a republication), then churn six more federated cards past it.
	// The target is the NEWEST flood row: every older federated row is
	// evicted by the churn, so survival proves the source = 0 protection.
	localTarget := b64(signerOf(7 + 19).Public)
	if err := s.UpsertDirectory(localTarget, localTarget, "local_survivor", 1791070000, 1791070000/HintEpochSeconds, nil, ""); err != nil {
		t.Fatal(err)
	}
	if r, _ := s.DirectoryRowOf(localTarget); r == nil || r.Source != 0 {
		t.Fatalf("local promotion: %+v", r)
	}
	for i := 0; i < 6; i++ {
		c := cardFor(30+i, int64(1791070400+i))
		if res := merger(c, int64(1791070400+i)); res.Outcome != directory.MergeInsert {
			t.Fatalf("churn %d: %+v", i, res)
		}
	}
	if r, _ := s.DirectoryRowOf(localTarget); r == nil {
		t.Fatal("a LOCAL row was evicted — §3.4 forbids this unconditionally")
	}

	// A full table of locals: the card is DROPPED (MergeDroppedAtCap — the
	// recorded deviation; the cap holds, the local rows are untouched).
	localsOnly := openMergeStore(t)
	for i := 0; i < 6; i++ {
		key := b64(mustXOf(t, "local-key-"+aliasOf(i)))
		if err := localsOnly.UpsertDirectory(key, key, aliasOf(i), 100, 0, nil, ""); err != nil {
			t.Fatal(err)
		}
	}
	c := cardFor(50, 1791070500)
	if res, err := localsOnly.MergeFederatedCard(mergeReq(c, 1791070500)); err != nil || res.Outcome != directory.MergeDroppedAtCap {
		t.Fatalf("dropped at cap: %+v (%v)", res, err)
	}
	if n, _ := localsOnly.DirectoryCount(); n != 6 {
		t.Fatalf("dropped-at-cap count %d", n)
	}

	// The HTTP path is untouched: a NEW local registration at the cap still
	// sheds with ErrCapacity, and an EXISTING row still refreshes.
	newKey := b64(mustXOf(t, "over-the-cap"))
	if err := s.UpsertDirectory(newKey, newKey, "over", 100, 0, nil, ""); !errors.Is(err, ErrCapacity) {
		t.Fatalf("local at cap: %v, want ErrCapacity", err)
	}
	if err := s.UpsertDirectory(localTarget, localTarget, "refreshed", 200, 0, nil, ""); err != nil {
		t.Fatalf("local refresh at cap: %v", err)
	}
}
