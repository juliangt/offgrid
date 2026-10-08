package directory_test

// integration_test.go — the §11 row-k gate and the issue #33 §4 acceptance
// case (P3.8): registration on node A becomes COMPOSABLE from node C
// through the node plane, with no mule anywhere.
//
// TestRegistrationOnAComposableFromC: three FULL stacks over real TCPCLv4
// sessions on 127.0.0.1 — each with its own user-plane SQLite directory
// (the SAME storage the HTTP API serves) and its own §7.5 bundle store.
// The user registers on A through the REAL HTTP API (the §3.2 card hook);
// the daemon emits the card as an og-dir bundle; the §7.1 epidemic sync
// carries it A → B → C; C's directory lists the user with identical keys,
// in a row the SPA cannot distinguish from a locally-registered one.
//
// TestFederationOffGatesEmissionAndAbsorption: the §9.3 gate — one flag
// gates emission AND absorption; a policy-off node relays og-dir cargo as
// ordinary bulk transit but never emits and never merges.
//
// Hermetic: 127.0.0.1, ephemeral ports, no external network.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"testing/fstest"
	"time"

	"offgrid/dtn-node/internal/api"
	"offgrid/dtn-node/internal/directory"
	"offgrid/dtn-node/internal/forward"
	"offgrid/dtn-node/internal/health"
	"offgrid/dtn-node/internal/nodeid"
	"offgrid/dtn-node/internal/storage"
	"offgrid/dtn-node/internal/tcpcl"
)

// minWebFS is the embedded-web-root stand-in (the API construction requires
// every walked tree to exist — loadStaticAssets fails startup otherwise).
var minWebFS = fstest.MapFS{
	"web/index.html":         &fstest.MapFile{Data: []byte("<!DOCTYPE html><html><body>dtntest</body></html>")},
	"web/guide.html":         &fstest.MapFile{Data: []byte("<!DOCTYPE html><html><body>guide</body></html>")},
	"web/manifest.json":      &fstest.MapFile{Data: []byte(`{"name":"t"}`)},
	"web/css/app.css":        &fstest.MapFile{Data: []byte("body{}")},
	"web/js/app.js":          &fstest.MapFile{Data: []byte("var x=1;")},
	"web/icons/icon-192.png": &fstest.MapFile{Data: []byte("png")},
	"web/img/guide/x.png":    &fstest.MapFile{Data: []byte("png")},
}

// dirStack is one island node: user-plane directory store (the HTTP API's
// own storage), §7.5 bundle store, epidemic engine, the §9.3 federator and
// the REAL HTTP API handler with the §3.2 emission hook.
type dirStack struct {
	t         *testing.T
	name      string
	dir       string
	userStore *storage.Store
	fwd       *forward.Store
	engine    *forward.Engine
	sink      *forward.Sink
	fed       *directory.Federator
	api       http.Handler
	apiSrv    *httptest.Server
	kp        nodeid.KeyPair
	eid       string
	cert      tls.Certificate
	pins      *nodeid.PinStore
	ln        *tcpcl.Listener
	emitSeq   int
	fedOn     bool
}

func newDirStack(t *testing.T, name string, fedOn bool) *dirStack {
	t.Helper()
	dir := t.TempDir()
	userStore, err := storage.Open(filepath.Join(dir, "node_storage.db"))
	if err != nil {
		t.Fatalf("%s: user store: %v", name, err)
	}
	t.Cleanup(func() { _ = userStore.Close() })
	fwd, err := forward.Open(forward.Config{Path: filepath.Join(dir, "bundles.db"), Log: quietLogger()})
	if err != nil {
		t.Fatalf("%s: forward store: %v", name, err)
	}
	t.Cleanup(func() { _ = fwd.Close() })

	kp, err := nodeid.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	eid, err := nodeid.EIDFromPub(kp.Public)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := nodeid.SelfSignedX509(kp, eid, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	s := &dirStack{t: t, name: name, dir: dir, userStore: userStore, fwd: fwd, kp: kp, eid: eid, cert: cert, fedOn: fedOn}
	s.pins = nodeid.NewPinStore()
	s.engine = forward.NewEngine(fwd, eid, quietLogger())
	s.engine.SummaryWait = 2 * time.Second
	s.fed = &directory.Federator{
		Store:   userStore,
		Enabled: func() bool { return s.fedOn },
		Inject:  func(pdu []byte) error { return fwd.Accept(pdu) },
	}
	s.sink = &forward.Sink{Store: fwd, Engine: s.engine, LocalEID: eid, Directory: s.fed}

	// The REAL API handler (the same constructor main uses) with the §3.2
	// emission hook — emitCard mirrors node/nodeplane.go's emitCard: the
	// policy gate, one identified bundle per card, admitted into the local
	// forward store for epidemic propagation.
	handler, err := api.NewWithCounters(userStore, health.NewCounters(), "dirtest", minWebFS,
		api.WithDirectoryCard(s.emitCard))
	if err != nil {
		t.Fatalf("%s: api: %v", name, err)
	}
	s.api = handler
	s.apiSrv = httptest.NewServer(handler)
	t.Cleanup(s.apiSrv.Close)

	cfg := tcpcl.Config{
		EID:           eid,
		Identity:      cert,
		Pins:          s.pins,
		MTLS:          tcpcl.MTLSRequired,
		Keepalive:     -1,
		Sink:          s.sink,
		Counters:      &tcpcl.Counters{},
		TermLinger:    2 * time.Second,
		OnEstablished: s.engine.HandleSession,
		Log:           quietLogger(),
	}
	s.ln, err = tcpcl.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("%s: listen: %v", name, err)
	}
	t.Cleanup(func() { _ = s.ln.Close() })
	go func() { _ = s.ln.Serve() }()
	return s
}

func quietLogger() *log.Logger { return log.New(io.Discard, "", 0) }

// emitCard is the daemon's §9.3 emission closure (node/nodeplane.go's
// emitCard, verbatim semantics).
func (s *dirStack) emitCard(cardCose []byte) {
	if !s.fedOn || len(cardCose) == 0 {
		return
	}
	s.emitSeq++
	pdu, err := directory.EmitCardBundle(s.eid, cardCose, time.Now().UnixMilli(), uint64(s.emitSeq))
	if err != nil {
		s.t.Fatalf("%s: emit: %v", s.name, err)
	}
	if err := s.fwd.Accept(pdu); err != nil {
		s.t.Fatalf("%s: card admission: %v", s.name, err)
	}
}

// dialTo opens one §7.1 contact (pinned both ways), holds it for the
// summary/diff exchange, and terminates gracefully.
func (s *dirStack) dialTo(other *dirStack) {
	s.t.Helper()
	if err := other.pins.PinPeer(s.eid, s.kp.Public); err != nil {
		s.t.Fatal(err)
	}
	if err := s.pins.PinPeer(other.eid, other.kp.Public); err != nil {
		s.t.Fatal(err)
	}
	cfg := tcpcl.Config{
		EID: s.eid, Identity: s.cert, Pins: s.pins,
		MTLS: tcpcl.MTLSRequired, Keepalive: -1, Sink: s.sink,
		Counters: &tcpcl.Counters{}, TermLinger: 2 * time.Second,
		OnEstablished: s.engine.HandleSession, Log: quietLogger(),
		ExpectedPeer: other.eid,
	}
	sess, err := tcpcl.Dial(context.Background(), "tcp", other.ln.Addr().String(), cfg)
	if err != nil {
		s.t.Fatalf("%s dial %s: %v", s.name, other.name, err)
	}
	time.Sleep(150 * time.Millisecond) // summary + diff pump settle
	_ = sess.Terminate(tcpcl.TermUnknown)
}

// postToAPI issues one HTTP request against a stack's REAL API with the
// canonical Host header (the canonical-host middleware redirects any other
// origin — §10.2).
func (s *dirStack) postToAPI(t *testing.T, path, body string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, s.apiSrv.URL+path, bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = api.CanonicalHost
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp, raw
}

// registerUser POSTs a registration (with card) to a stack's REAL API and
// fails the test on anything but 200 ok.
func (s *dirStack) registerUser(t *testing.T, alias string, user nodeid.KeyPair, x []byte, cardB64 string) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{
		"alias":  alias,
		"pubkey": base64.StdEncoding.EncodeToString(user.Public),
		"x25519": base64.StdEncoding.EncodeToString(x),
		"card":   cardB64,
	})
	resp, raw := s.postToAPI(t, "/api/v1/directory", string(body))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s: register %s: %d %s", s.name, alias, resp.StatusCode, raw)
	}
	if !bytes.Contains(raw, []byte(`"ok"`)) {
		t.Fatalf("%s: register %s: %s", s.name, alias, raw)
	}
}

// getDirectory fetches the served directory JSON of a stack's REAL API.
func (s *dirStack) getDirectory(t *testing.T) []map[string]any {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, s.apiSrv.URL+"/api/v1/directory", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = api.CanonicalHost
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s: directory GET: %d %s", s.name, resp.StatusCode, raw)
	}
	var out []map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("%s: directory GET: %v (%s)", s.name, err, raw)
	}
	return out
}

func (s *dirStack) rowCount(t *testing.T) int64 {
	t.Helper()
	n, err := s.userStore.DirectoryCount()
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func (s *dirStack) rowOf(t *testing.T, pubkey string) *storage.DirectoryRow {
	t.Helper()
	r, err := s.userStore.DirectoryRowOf(pubkey)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (s *dirStack) bundleCount(t *testing.T) int {
	t.Helper()
	n, err := s.fwd.Count()
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func waitForDir(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

// fixedUser derives one deterministic user key pair (cards and rows are
// pinned by name in the assertions).
func fixedUser(t *testing.T, label string) (nodeid.KeyPair, []byte, string) {
	t.Helper()
	s := sha256.Sum256([]byte("offgrid-dirtest-user-" + label))
	kp, err := nodeid.NewKeyPairFromSeed(s[:])
	if err != nil {
		t.Fatal(err)
	}
	x := sha256.Sum256([]byte("offgrid-dirtest-x-" + label))
	return kp, x[:], base64.StdEncoding.EncodeToString(kp.Public)
}

// TestRegistrationOnAComposableFromC is THE acceptance case: a user
// registered only on node A becomes composable from node C via node-plane
// directory federation (issue #33 §4, checkbox 5) — and the row C serves is
// field-identical in shape to an HTTP-registered one.
func TestRegistrationOnAComposableFromC(t *testing.T) {
	a := newDirStack(t, "a", true)
	b := newDirStack(t, "b", true)
	c := newDirStack(t, "c", true)

	user, x, pubkeyB64 := fixedUser(t, "alice")
	card, err := directory.SignCard(user, "alice_77", x, time.Now().Unix()-5, 1)
	if err != nil {
		t.Fatal(err)
	}
	cardB64 := directory.CanonicalB64(card)

	// 1. Registration on A through the REAL HTTP API (§3.2's hook).
	a.registerUser(t, "alice_77", user, x, cardB64)
	if r := a.rowOf(t, pubkeyB64); r == nil || r.Source != 0 || r.Card.String != cardB64 {
		t.Fatalf("A's local row: %+v", r)
	}
	if n := a.bundleCount(t); n != 1 {
		t.Fatalf("A's forward store holds %d bundles, want 1 (the emitted card)", n)
	}

	// 2. A → B: the §7.1 epidemic sync carries the card; B verifies it and
	// merges it into its own user-plane directory.
	a.dialTo(b)
	waitForDir(t, "B to merge the card", func() bool {
		r := b.rowOf(t, pubkeyB64)
		return r != nil && r.Source == 1 && r.Alias == "alice_77"
	})
	if got := b.fed.CountersSnapshot(); got.Accepted != 1 {
		t.Fatalf("B's federation counters: %+v", got)
	}
	if n := b.bundleCount(t); n != 1 {
		t.Fatalf("B's forward store holds %d bundles, want 1 (the re-admitted card)", n)
	}

	// 3. B → C: the multi-hop leg — registration on A reached C through B
	// WITHOUT any mule.
	b.dialTo(c)
	waitForDir(t, "C to merge the card", func() bool {
		r := c.rowOf(t, pubkeyB64)
		return r != nil && r.Source == 1 && r.Alias == "alice_77"
	})
	if got := c.fed.CountersSnapshot(); got.Accepted != 1 {
		t.Fatalf("C's federation counters: %+v", got)
	}

	// 4. COMPOSABLE: C's REAL API serves the user with identical keys.
	entries := c.getDirectory(t)
	var served map[string]any
	for _, e := range entries {
		if e["pubkey"] == pubkeyB64 {
			served = e
			break
		}
	}
	if served == nil {
		t.Fatalf("C's directory does not list the user: %v", entries)
	}
	if served["alias"] != "alice_77" || served["x25519"] != base64.StdEncoding.EncodeToString(x) {
		t.Fatalf("C serves different identity data: %v", served)
	}

	// 5. SPA INDISTINGUISHABILITY: register a second user LOCALLY on C and
	// compare the served JSON member sets — a federated row and a
	// registered row must be the same shape (the continuity-warning path
	// sees one kind of row).
	user2, x2, pubkey2 := fixedUser(t, "bob")
	c.registerUser(t, "bob_1", user2, x2, "") // legacy client: no card member
	entries = c.getDirectory(t)
	if len(entries) != 2 {
		t.Fatalf("C serves %d entries, want 2", len(entries))
	}
	memberSet := func(e map[string]any) string {
		keys := make([]string, 0, len(e))
		for k := range e {
			keys = append(keys, k)
		}
		sortStrings(keys)
		return fmt.Sprintf("%v", keys)
	}
	var fedEntry, localEntry map[string]any
	for _, e := range entries {
		switch e["pubkey"] {
		case pubkeyB64:
			fedEntry = e
		case pubkey2:
			localEntry = e
		}
	}
	if fedEntry == nil || localEntry == nil {
		t.Fatalf("entries missing: %v", entries)
	}
	if memberSet(fedEntry) != memberSet(localEntry) {
		t.Fatalf("the SPA can tell a federated row from a registered one: %v vs %v", memberSet(fedEntry), memberSet(localEntry))
	}
	// The stored rows carry the same served fields too (the internal
	// card/source columns never surface).
	if fedEntry["alias"] != localEntry["alias"] && fedEntry["alias"] != "alice_77" {
		t.Fatalf("federated alias drifted: %v", fedEntry)
	}
	if _, has := fedEntry["card"]; has {
		t.Fatal("the internal card column leaked into the served JSON")
	}
	if _, has := fedEntry["source"]; has {
		t.Fatal("the internal source column leaked into the served JSON")
	}

	// 6. CONVERGENCE, not flooding: a re-contact re-diffs to nothing new —
	// the duplicate absorption is the §3.4 counter's job, the store's is
	// P-7 dedup.
	before := c.bundleCount(t)
	c.dialTo(b)
	waitForDir(t, "the re-contact to settle", func() bool { return true })
	if n := c.bundleCount(t); n != before {
		t.Fatalf("C's forward store grew from %d to %d on a converged re-contact", before, n)
	}
	if got := c.fed.CountersSnapshot(); got.Conflicts != 0 || got.StaleDropped != 0 {
		t.Fatalf("a clean island raised attack signals: %+v", got)
	}
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// TestFederationOffGatesEmissionAndAbsorption pins the §9.3 gate semantics:
// one flag gates emission AND absorption; a policy-off node still RELAYS
// og-dir cargo as ordinary bulk transit (unconditional DTN duty) but never
// emits a card and never merges one into its directory.
func TestFederationOffGatesEmissionAndAbsorption(t *testing.T) {
	a := newDirStack(t, "a", false) // federation OFF at A
	b := newDirStack(t, "b", true)
	c := newDirStack(t, "c", true)

	user, x, pubkeyB64 := fixedUser(t, "carol")
	card, err := directory.SignCard(user, "carol_9", x, time.Now().Unix()-5, 1)
	if err != nil {
		t.Fatal(err)
	}

	// Registration WITH a card on a policy-off node: stored verbatim (the
	// row is local truth), but NOTHING is emitted.
	a.registerUser(t, "carol_9", user, x, directory.CanonicalB64(card))
	if r := a.rowOf(t, pubkeyB64); r == nil || r.Card.String == "" {
		t.Fatalf("A's row: %+v", r)
	}
	if n := a.bundleCount(t); n != 0 {
		t.Fatalf("a federation-off node emitted %d bundle(s)", n)
	}

	// No card, no propagation: after the full line contacts, B and C never
	// hear about the user.
	a.dialTo(b)
	b.dialTo(c)
	time.Sleep(300 * time.Millisecond)
	for _, s := range []*dirStack{b, c} {
		if r := s.rowOf(t, pubkeyB64); r != nil {
			t.Fatalf("%s merged a card that was never emitted", s.name)
		}
		if n := s.bundleCount(t); n != 0 {
			t.Fatalf("%s holds %d bundles", s.name, n)
		}
	}

	// Absorption is gated too: an og-dir bundle handed to A's sink is
	// DECLINED (the federator returns false) and lands in the forward store
	// as ordinary bulk transit — relayed, never merged.
	pdu, err := directory.EmitCardBundle(b.eid, card, time.Now().UnixMilli(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.sink.Accept(pdu); err != nil {
		t.Fatalf("transit card refused: %v", err)
	}
	if n := a.bundleCount(t); n != 1 {
		t.Fatalf("A's store holds %d bundles, want 1 (transit relay)", n)
	}
	if r := a.rowOf(t, pubkeyB64); r == nil || r.Source != 0 || r.Alias != "carol_9" {
		t.Fatalf("the transit card leaked into A's merge path: %+v", r)
	}

	// The same bundle at a federation-on node IS directory business: merged
	// AND re-admitted for propagation.
	if err := b.sink.Accept(pdu); err != nil {
		t.Fatal(err)
	}
	if r := b.rowOf(t, pubkeyB64); r == nil || r.Source != 1 {
		t.Fatalf("B did not merge the card: %+v", r)
	}
	if n := b.bundleCount(t); n != 1 {
		t.Fatalf("B's store holds %d bundles, want 1 (re-admitted)", n)
	}
}

// TestSinkDropsInvalidDirCards pins the og-door discipline: an og-dir bundle
// whose payload fails VerifyCard is consumed (never relayed, never stored,
// never merged) and counted.
func TestSinkDropsInvalidDirCards(t *testing.T) {
	s := newDirStack(t, "n", true)
	user, x, pubkeyB64 := fixedUser(t, "eve")
	card, err := directory.SignCard(user, "eve_1", x, time.Now().Unix()-5, 1)
	if err != nil {
		t.Fatal(err)
	}
	card[len(card)-1] ^= 0x01 // one flipped bit: a forged card
	pdu, err := directory.EmitCardBundle(s.eid, card, time.Now().UnixMilli(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.sink.Accept(pdu); err != nil {
		t.Fatalf("a refused card must still ACK the transfer: %v", err)
	}
	if r := s.rowOf(t, pubkeyB64); r != nil {
		t.Fatal("a forged card was merged")
	}
	if n := s.bundleCount(t); n != 0 {
		t.Fatalf("a forged card became store cargo (%d bundles)", n)
	}
	if got := s.fed.CountersSnapshot(); got.Rejected != 1 {
		t.Fatalf("rejected counter: %+v", got)
	}
}

// compile-time assertion: the Federator satisfies the forward sink seam.
var _ forward.DirectoryConsumer = (*directory.Federator)(nil)
