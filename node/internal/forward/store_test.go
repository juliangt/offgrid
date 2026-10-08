package forward

// store_test.go — the §7.5 bundle store: admission pipeline (parse/skew,
// hop ceiling, dedup, classification, local expiry), the cap with
// priority-aware eviction, WAL persistence across reopen, and the janitor.

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"offgrid/dtn-node/internal/bundle"
)

// testClock is a mutable test clock.
type testClock struct{ t time.Time }

func (c *testClock) Now() time.Time { return c.t }

func mkBundle(t *testing.T, payload []byte, created time.Time, ttl uint64, hop byte, kind string) []byte {
	t.Helper()
	var b *bundle.Bundle
	var err error
	switch kind {
	case "mgmt":
		b, err = bundle.NewManagement("dtn://og.0123456789abcdef/", AdminEID, created.UnixMilli(), ttl, 1, payload)
	case "mail":
		b, err = bundle.NewMail(payload, created.UnixMilli(), ttl)
	case "p2p": // identified point-to-point: bulk per Classify
		b, err = bundle.NewManagement("dtn://og.0123456789abcdef/", "dtn://og.dac073e0123bdea5/", created.UnixMilli(), ttl, 1, payload)
	default:
		t.Fatalf("unknown kind %q", kind)
	}
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	b.Hop = hop
	pdu, err := bundle.Encode(b)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return pdu
}

func openTestStore(t *testing.T, cap int, clock *testClock) *Store {
	t.Helper()
	st, err := Open(Config{Path: filepath.Join(t.TempDir(), "bundles.db"), Cap: cap, Now: clock.Now})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func mustVerdict(t *testing.T, st *Store, pdu []byte) Verdict {
	t.Helper()
	v, err := st.accept(pdu)
	if err != nil && !errors.Is(err, ErrCapacity) {
		t.Fatalf("accept: %v", err)
	}
	return v
}

func TestClassifyPinsTheEIDRules(t *testing.T) {
	none, _ := bundle.ParseEID("dtn:none")
	mail, _ := bundle.ParseEID(MailGroupEID)
	admin, _ := bundle.ParseEID(AdminEID)
	node, _ := bundle.ParseEID("dtn://og.0123456789abcdef/")
	other, _ := bundle.ParseEID("dtn:og-updates")

	// A payload whose first 16 bytes pass the §9.4 chunk-header arithmetic
	// (a fake capsule chunk): total=1 (bytes 8..11), idx=0 (bytes 12..15).
	chunk := make([]byte, 40)
	chunk[11] = 1    // total = 1
	chunk[16] = 0xEE // chunk bytes

	cases := []struct {
		dest, src bundle.EID
		payload   []byte
		want      Class
	}{
		{mail, none, []byte("envelope"), ClassMail},
		{mail, node, []byte("envelope"), ClassBulk}, // identified source is NOT mail (P-4 is anonymous)
		{admin, node, []byte("cose"), ClassManagement},
		{admin, none, []byte("cose"), ClassManagement}, // the dest decides management
		{node, node, []byte("p2p"), ClassBulk},         // identified point-to-point: bulk in v1 (P3.6 extends)
		{other, none, []byte("x"), ClassBulk},
		// §9.4 (P3.7): chunk cargo is BULK even when addressed to the admin
		// group — update cargo never rides the management class (a bulk
		// bundle can never evict mail or management, §7.5; letting a chunk
		// pose as management would buy exactly that).
		{node, node, chunk, ClassBulk},
		{admin, node, chunk, ClassBulk},
		// An anonymous bundle whose bytes happen to pass the arithmetic is
		// classified by the EID rules as before (the chunk peek never
		// overrides the anonymous shapes — the user plane is never touched).
		{other, none, chunk, ClassBulk},
	}
	for _, tc := range cases {
		if got := Classify(tc.dest, tc.src, tc.payload); got != tc.want {
			t.Fatalf("Classify(%s, %s, %x…) = %s, want %s", tc.dest, tc.src, tc.payload[:8], got, tc.want)
		}
	}
}

func TestStoreAdmissionPipeline(t *testing.T) {
	clock := &testClock{t: time.Unix(1791072000, 0)}
	st := openTestStore(t, 100, clock)

	mail := mkBundle(t, []byte("envelope-bytes"), clock.t, 3600, 0, "mail")

	// 1. Fresh admission.
	if v := mustVerdict(t, st, mail); v != VerdictAccepted {
		t.Fatalf("first admit = %s, want accepted", v)
	}
	// 2. Dedup: the identical PDU absorbs.
	if v := mustVerdict(t, st, mail); v != VerdictDup {
		t.Fatalf("re-admit = %s, want dup", v)
	}
	// 3. The hop-rewritten copy dedups too (P-7 excludes the hop octet) —
	// and being identical-after-hop it MUST NOT store a second row.
	rew, err := bundle.RewriteHop(mail)
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if v := mustVerdict(t, st, rew); v != VerdictDup {
		t.Fatalf("hop-rewritten re-admit = %s, want dup", v)
	}
	// 4. Hop ceiling: hop 7 is dead cargo — dropped, acknowledged, unstored.
	capped := mkBundle(t, []byte("dead"), clock.t, 3600, 7, "mail")
	if v := mustVerdict(t, st, capped); v != VerdictHopCapped {
		t.Fatalf("hop-7 = %s, want hop_capped", v)
	}
	if _, ok, _ := st.Get(idOf(t, capped)); ok {
		t.Fatalf("a hop-capped bundle must never be stored")
	}
	// 5. Expired at admission (creation + lifetime already past the clock).
	stale := mkBundle(t, []byte("stale"), clock.t.Add(-2*time.Hour), 3600, 0, "mail")
	if v := mustVerdict(t, st, stale); v != VerdictExpired {
		t.Fatalf("stale = %s, want expired", v)
	}
	// 6. Malformed PDUs refuse with ErrMalformed.
	if _, err := st.accept([]byte("garbage")); !errors.Is(err, ErrMalformed) {
		t.Fatalf("garbage = %v, want ErrMalformed", err)
	}

	if n, _ := st.Count(); n != 1 {
		t.Fatalf("store must hold exactly the one mail bundle, has %d", n)
	}
	cs := st.CountersSnapshot()
	if cs.Accepted != 1 || cs.Dup != 2 || cs.HopCapped != 1 || cs.Expired != 1 {
		t.Fatalf("counters: %+v", cs)
	}
}

func idOf(t *testing.T, pdu []byte) [32]byte {
	t.Helper()
	id, err := bundle.BundleIDOf(pdu)
	if err != nil {
		t.Fatalf("bundle id: %v", err)
	}
	return id
}

func TestStoreExpiryAndJanitor(t *testing.T) {
	clock := &testClock{t: time.Unix(1791072000, 0)}
	st := openTestStore(t, 100, clock)

	// Two bundles: one dies in an hour, one in a week.
	short := mkBundle(t, []byte("short-ttl"), clock.t, 3600, 0, "mail")
	long := mkBundle(t, []byte("long-ttl"), clock.t, 7*24*3600, 0, "mail")
	if v := mustVerdict(t, st, short); v != VerdictAccepted {
		t.Fatalf("short: %s", v)
	}
	if v := mustVerdict(t, st, long); v != VerdictAccepted {
		t.Fatalf("long: %v", v)
	}

	// The janitor boundary matches the envelope store: exclusive
	// (expires_at < now); at exactly expires_at the bundle is still live.
	clock.t = clock.t.Add(3600 * time.Second)
	if n, _ := st.Count(); n != 2 {
		t.Fatalf("at exactly expires_at the bundle is still live (have %d)", n)
	}
	clock.t = clock.t.Add(time.Second)
	deleted, err := st.Janitor()
	if err != nil {
		t.Fatalf("janitor: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("janitor deleted %d, want 1", deleted)
	}
	if n, _ := st.Count(); n != 1 {
		t.Fatalf("janitor left %d rows, want 1", n)
	}
	// The expired bundle is no longer listed as live (never re-transferred).
	entries, _ := st.Entries()
	if len(entries) != 1 || entries[0].ID != idOf(t, long) {
		t.Fatalf("live entries: %+v", entries)
	}
}

func TestStorePriorityAwareEviction(t *testing.T) {
	clock := &testClock{t: time.Unix(1791072000, 0)}
	st := openTestStore(t, 3, clock)

	// Fill the cap: 1 management (expires last), 1 mail, 1 bulk
	// (expires first among evictable-for-bulk).
	mgmt := mkBundle(t, []byte("mgmt"), clock.t, 7*24*3600, 0, "mgmt")
	mail := mkBundle(t, []byte("mail"), clock.t, 2*24*3600, 0, "mail")
	bulk := mkBundle(t, []byte("bulk"), clock.t, 1*24*3600, 0, "p2p")
	for i, pdu := range [][]byte{mgmt, mail, bulk} {
		if v := mustVerdict(t, st, pdu); v != VerdictAccepted {
			t.Fatalf("fill %d: %s", i, v)
		}
	}

	// A bulk arrival at cap: evicts the BULK bundle (lowest priority, and
	// the mail/management rows are protected from a bulk newcomer) — even
	// though the bulk row is NOT the globally soonest-expiring one... it is
	// here, but the pin is the class rule: the ONLY evictable class for a
	// bulk arrival is bulk.
	bulk2 := mkBundle(t, []byte("bulk2"), clock.t, 3*24*3600, 0, "p2p")
	if v := mustVerdict(t, st, bulk2); v != VerdictAccepted {
		t.Fatalf("bulk at cap must evict the bulk row: %s", v)
	}
	if _, ok, _ := st.Get(idOf(t, bulk)); ok {
		t.Fatalf("the bulk row must have been evicted")
	}
	if _, ok, _ := st.Get(idOf(t, mail)); !ok {
		t.Fatalf("the mail row must survive a bulk eviction")
	}
	if got := st.CountersSnapshot().Evicted; got != 1 {
		t.Fatalf("evicted counter: %d", got)
	}

	// A mail arrival at cap: evicts from bulk first (bulk2, even though
	// mgmt expires later... bulk is the lower priority class — the
	// §7.3 discipline, not the expiry, picks the class).
	mail2 := mkBundle(t, []byte("mail2"), clock.t, 8*24*3600, 0, "mail")
	if v := mustVerdict(t, st, mail2); v != VerdictAccepted {
		t.Fatalf("mail at cap: %s", v)
	}
	if _, ok, _ := st.Get(idOf(t, bulk2)); ok {
		t.Fatalf("bulk2 must have been evicted for the mail arrival")
	}

	// A management arrival at cap: the lowest-priority class first (mail —
	// the bulk lane is empty), and within that class the SOONEST-expiring
	// row: `mail` (2 d) goes, `mail2` (8 d) stays.
	mgmt2 := mkBundle(t, []byte("mgmt2"), clock.t, 9*24*3600, 0, "mgmt")
	if v := mustVerdict(t, st, mgmt2); v != VerdictAccepted {
		t.Fatalf("mgmt at cap: %s", v)
	}
	if _, ok, _ := st.Get(idOf(t, mail)); ok {
		t.Fatalf("the soonest-expiring mail row must have been evicted for the management arrival")
	}
	if _, ok, _ := st.Get(idOf(t, mail2)); !ok {
		t.Fatalf("the later-expiring mail row must survive")
	}

	// At cap with ONLY management rows left: a bulk arrival is REFUSED
	// (refuse-newest — nothing evictable for bulk), never trades down.
	bulk3 := mkBundle(t, []byte("bulk3"), clock.t, 3600, 0, "p2p")
	v, err := st.accept(bulk3)
	if !errors.Is(err, ErrCapacity) || v != VerdictAtCap {
		t.Fatalf("bulk into a management-only full store: verdict %s err %v, want at_cap/ErrCapacity", v, err)
	}
	if n, _ := st.Count(); n != 3 {
		t.Fatalf("a refused arrival must not change the store (has %d)", n)
	}
	if got := st.CountersSnapshot().AtCapRejected; got != 1 {
		t.Fatalf("at_cap counter: %d", got)
	}
}

func TestStoreEvictionWithinClassIsSoonestExpiring(t *testing.T) {
	clock := &testClock{t: time.Unix(1791072000, 0)}
	st := openTestStore(t, 2, clock)

	// Two mail rows: the second expires SOONER than the first.
	first := mkBundle(t, []byte("first"), clock.t, 10*24*3600, 0, "mail")
	second := mkBundle(t, []byte("second"), clock.t, 1*24*3600, 0, "mail")
	mustVerdict(t, st, first)
	mustVerdict(t, st, second)

	third := mkBundle(t, []byte("third"), clock.t, 10*24*3600, 0, "mail")
	if v := mustVerdict(t, st, third); v != VerdictAccepted {
		t.Fatalf("third: %s", v)
	}
	if _, ok, _ := st.Get(idOf(t, second)); ok {
		t.Fatalf("the soonest-expiring row must be evicted first")
	}
	if _, ok, _ := st.Get(idOf(t, first)); !ok {
		t.Fatalf("the later-expiring row must survive")
	}
}

func TestStorePersistAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bundles.db")
	clock := &testClock{t: time.Unix(1791072000, 0)}

	st, err := Open(Config{Path: path, Cap: 10, Now: clock.Now})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	pdu := mkBundle(t, []byte("persist-me"), clock.t, 24*3600, 0, "mail")
	if err := st.Accept(pdu); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	st2, err := Open(Config{Path: path, Cap: 10, Now: clock.Now})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer st2.Close()
	if n, _ := st2.Count(); n != 1 {
		t.Fatalf("reopened store has %d rows, want 1", n)
	}
	pdu2, ok, err := st2.Get(idOf(t, pdu))
	if err != nil || !ok {
		t.Fatalf("get after reopen: ok=%v err=%v", ok, err)
	}
	if string(pdu2) != string(pdu) {
		t.Fatalf("stored PDU must be byte-exact across reopen")
	}
	// And dedup still holds after the reopen (the P-7 key is on disk).
	if v := mustVerdict(t, st2, pdu); v != VerdictDup {
		t.Fatalf("re-admit after reopen = %s, want dup", v)
	}
}

func TestStoreRefusesNewerSchema(t *testing.T) {
	// The §15.3 downgrade stance applied to the node-plane namespace: a
	// database stamped by a newer binary is refused, untouched.
	path := filepath.Join(t.TempDir(), "bundles.db")
	st, err := Open(Config{Path: path, Cap: 10})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	if _, err := db.Exec("PRAGMA user_version = 99"); err != nil {
		t.Fatalf("stamp: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("raw close: %v", err)
	}
	if _, err := Open(Config{Path: path, Cap: 10}); err == nil {
		t.Fatalf("a newer-schema bundle store must be refused")
	}
}

func TestStoreEntriesAndClassRoundTrip(t *testing.T) {
	clock := &testClock{t: time.Unix(1791072000, 0)}
	st := openTestStore(t, 100, clock)
	mk := map[string][]byte{
		"mgmt": mkBundle(t, []byte("m"), clock.t, 3600, 0, "mgmt"),
		"mail": mkBundle(t, []byte("e"), clock.t, 3600, 0, "mail"),
		"bulk": mkBundle(t, []byte("b"), clock.t, 3600, 0, "p2p"),
	}
	for _, pdu := range mk {
		if v := mustVerdict(t, st, pdu); v != VerdictAccepted {
			t.Fatalf("admit: %s", v)
		}
	}
	entries, err := st.Entries()
	if err != nil {
		t.Fatalf("entries: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("want 3 entries, got %d", len(entries))
	}
	got := map[[32]byte]Class{}
	for _, en := range entries {
		got[en.ID] = en.Class
	}
	if got[idOf(t, mk["mgmt"])] != ClassManagement ||
		got[idOf(t, mk["mail"])] != ClassMail ||
		got[idOf(t, mk["bulk"])] != ClassBulk {
		t.Fatalf("classes did not round-trip: %+v", got)
	}
}

func TestStoreCapIsReportedHonestly(t *testing.T) {
	st := openTestStore(t, 7, &testClock{t: time.Unix(1791072000, 0)})
	if st.Cap() != 7 {
		t.Fatalf("Cap() = %d, want 7 (the enforced cap is the reported one, §7.5)", st.Cap())
	}
	def, err := Open(Config{Path: filepath.Join(t.TempDir(), "b.db")})
	if err != nil {
		t.Fatalf("open default: %v", err)
	}
	defer def.Close()
	if def.Cap() != DefaultCap {
		t.Fatalf("default cap = %d, want %d", def.Cap(), DefaultCap)
	}
}
