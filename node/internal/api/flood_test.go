package api

// flood_test.go — CI-safe daemon-side flood/sabotage tests for issue #16
// Phase 2, Track 2. Each test models one row of the issue's flood list
// against the plain httptest recorder (no network, no timing asserts): the
// property under test is always FUNCTIONAL — who still gets served, what the
// store holds — never latency.
//
// All admission-control knobs go through overrideAdmissionLimits (the
// maxEnvelopes-style hook of ratelimit.go), so every test runs against the
// shipped request/envelope budget semantics with test-scaled magnitudes.

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"offgrid/dtn-node/internal/envelope"
	"offgrid/dtn-node/internal/storage"
)

// junkIP / muleIP are the source IPs the flood tests impersonate via
// RemoteAddr: attackerStation is the saboteur, honestMule the legitimate
// client whose service must never degrade while the attacker is flooding.
const (
	attackerStation = "203.0.113.9"
	honestMule      = "198.51.100.7"
)

// doFrom is do() with a forced source IP (httptest.NewRequest defaults every
// request to 192.0.2.1, which would put attacker and mule in one bucket).
func doFrom(t *testing.T, h http.Handler, ip, method, target string, body []byte, contentType string) *httptest.ResponseRecorder {
	t.Helper()
	var rd *strings.Reader
	if body == nil {
		rd = strings.NewReader("")
	} else {
		rd = strings.NewReader(string(body))
	}
	req := httptest.NewRequest(method, target, rd)
	req.RemoteAddr = net.JoinHostPort(ip, "47111")
	req.Host = CanonicalHost
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// syncBodyFrom marshals a §10.4 body and posts it from ip.
func syncBodyFrom(t *testing.T, h http.Handler, ip string, knownIDs []string, envs []envelope.Envelope) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]any{"known_ids": knownIDs, "push_envelopes": envs})
	if err != nil {
		t.Fatalf("marshal sync body: %v", err)
	}
	return doFrom(t, h, ip, http.MethodPost, "/api/v1/sync", body, "application/json")
}

// storedCount pages through the whole store by accumulating known_ids (pull
// is capped by limit, so one pull cannot count a store bigger than 200).
func storedCount(t *testing.T, s *storage.Store, now int64) int {
	t.Helper()
	total := 0
	var known []string
	for {
		pulled, err := s.PullEnvelopes(known, 200, now)
		if err != nil {
			t.Fatalf("count store: %v", err)
		}
		total += len(pulled)
		if len(pulled) == 0 {
			return total
		}
		for _, e := range pulled {
			known = append(known, e.ID)
		}
		if len(known) > 100000 {
			t.Fatalf("store count did not converge (bug in the paging loop)")
		}
	}
}

// errBodyOf decodes a {"status":"error","error":"<code>"} body.
func errBodyOf(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response must carry a JSON error body, got %q", rec.Body.String())
	}
	if body["status"] != "error" {
		t.Fatalf("response must carry status=error, got %q", rec.Body.String())
	}
	return body["error"]
}

// TestFloodJunkEnvelopesStoreCapHolds pushes 10000 junk envelopes from one
// hostile station against a node already at its §8.1 cap: invalid-envelope
// batches must all fail closed with 400, oversized bodies with 413, and
// well-formed pushes with 429 node_full — while an honest mule on another IP
// keeps pulling mid-flood and after it. The cap must hold exactly: nothing
// the attacker pushed may be stored (reject newest, keep oldest).
func TestFloodJunkEnvelopesStoreCapHolds(t *testing.T) {
	// This test isolates the §8.1 global cap, so the per-IP budgets are
	// widened out of the way (their own behavior has dedicated tests below).
	restore := overrideAdmissionLimits(1_000_000, time.Second, 1_000_000, 600, bucketEvictionFloor, bucketIdleTTL)
	defer restore()

	h, store := newTestHandler(t)
	now := time.Now().Unix()

	// Fill the store to the 5000-envelope cap directly (the API path to do
	// so is what the flood pretends to continue).
	fill := make([]envelope.Envelope, 0, 5000)
	for i := 0; i < 5000; i++ {
		fill = append(fill, validEnv(hexID(i), now))
	}
	if inserted, err := store.InsertEnvelopes(fill); err != nil || inserted != 5000 {
		t.Fatalf("fill store to cap: got %d inserted, err=%v", inserted, err)
	}
	seedIDs := make([]string, 0, len(fill))
	for _, e := range fill {
		seedIDs = append(seedIDs, e.ID)
	}

	// 250 batches × 40 envelopes = 10000 junk envelopes, three sabotage
	// flavors interleaved: oversized bodies, malformed envelopes, and
	// well-formed (but unwanted) mail.
	const (
		junkBatches  = 250
		junkPerBatch = 40
	)
	sawNodeFull, sawBodyTooLarge, sawInvalid := false, false, false
	for batch := 0; batch < junkBatches; batch++ {
		switch batch % 5 {
		case 0: // oversized body: >1 MiB of hex ids (§8.1 → 413 before any parse)
			known := make([]string, 0, 20000)
			for i := 0; i < 20000; i++ {
				known = append(known, hexID(batch*100000+i))
			}
			body, _ := json.Marshal(map[string]any{"known_ids": known})
			if len(body) <= MaxBodyBytes {
				t.Fatalf("fixture body must exceed the cap, is %d", len(body))
			}
			rec := doFrom(t, h, attackerStation, http.MethodPost, "/api/v1/sync", body, "application/json")
			if rec.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("oversized flood batch %d: got %d, want 413", batch, rec.Code)
			}
			sawBodyTooLarge = true
		case 1, 3: // malformed envelopes: §10.5 rejects the whole batch with 400
			envs := make([]envelope.Envelope, 0, junkPerBatch)
			for i := 0; i < junkPerBatch; i++ {
				e := validEnv(hexID(1000000+batch*junkPerBatch+i), now)
				e.Payload = "!!!" // not Base64 — invalid
				envs = append(envs, e)
			}
			rec := syncBodyFrom(t, h, attackerStation, nil, envs)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("invalid flood batch %d: got %d, want 400 (body: %s)", batch, rec.Code, rec.Body.String())
			}
			sawInvalid = true
		default: // well-formed mail the full node cannot want: 429 node_full
			envs := make([]envelope.Envelope, 0, junkPerBatch)
			for i := 0; i < junkPerBatch; i++ {
				envs = append(envs, validEnv(hexID(2000000+batch*junkPerBatch+i), now))
			}
			rec := syncBodyFrom(t, h, attackerStation, nil, envs)
			if rec.Code != http.StatusTooManyRequests {
				t.Fatalf("flood batch %d at capacity: got %d, want 429 node_full", batch, rec.Code)
			}
			if code := errBodyOf(t, rec); code != "node_full" {
				t.Fatalf("flood batch %d must carry node_full, got %q", batch, code)
			}
			sawNodeFull = true
		}

		// Mid-flood responsiveness (functional, not timing): the honest mule
		// on another IP keeps pulling mail from the full node.
		if batch == junkBatches/2 {
			rec := syncBodyFrom(t, h, honestMule, seedIDs[:100], nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("honest mule mid-flood pull: got %d (body: %s)", rec.Code, rec.Body.String())
			}
		}
	}
	if !sawNodeFull || !sawBodyTooLarge || !sawInvalid {
		t.Fatalf("flood must have exercised all three sabotage flavors (node_full=%v 413=%v 400=%v)",
			sawNodeFull, sawBodyTooLarge, sawInvalid)
	}

	// Cap held exactly: the honest mule still pulls (the §8.1 known_ids cap
	// binds a single pull to 500 ids), the store holds exactly the 5000
	// seeded envelopes, and a fresh push is still node_full.
	rec := syncBodyFrom(t, h, honestMule, seedIDs[:500], nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("honest mule pull after flood: got %d (body: %s)", rec.Code, rec.Body.String())
	}
	if got := storedCount(t, store, now); got != 5000 {
		t.Fatalf("store cap must hold at 5000 seeded envelopes, got %d", got)
	}
	if _, err := store.InsertEnvelopes([]envelope.Envelope{validEnv(hexID(999999), now)}); !errors.Is(err, storage.ErrCapacity) {
		t.Fatalf("node must still be at capacity after the flood, got err=%v", err)
	}
}

// TestFloodSyncStormSingleStationIsolated hammers POST /api/v1/sync from one
// station past its request budget: the storm gets 429 rate_limited with a
// Retry-After hint while the honest mule on another IP keeps syncing
// untouched (the isolation property). Bucket maps must not grow unbounded,
// which the eviction unit test below pins.
func TestFloodSyncStormSingleStationIsolated(t *testing.T) {
	// Burst 7, no refill during the test: the attacker's 5-per-round storm
	// exhausts it in round 1, while the mule's 6 syncs stay inside the same
	// budget on its own bucket.
	restore := overrideAdmissionLimits(7, time.Hour, syncEnvelopeBurst, syncEnvelopeRefillPerHour, bucketEvictionFloor, bucketIdleTTL)
	defer restore()

	h, _ := newTestHandler(t)

	muleEnvelope := validEnv(hexID(31337), time.Now().Unix())
	muleSync := func() *httptest.ResponseRecorder {
		return syncBodyFrom(t, h, honestMule, nil, []envelope.Envelope{muleEnvelope})
	}

	var gotLimited *httptest.ResponseRecorder
	for round := 0; round < 6; round++ {
		// The storm: repeated sync bursts from the attacker station.
		for i := 0; i < 5; i++ {
			rec := syncBodyFrom(t, h, attackerStation, nil, nil)
			switch {
			case rec.Code == http.StatusOK:
				// inside the burst budget
			case rec.Code == http.StatusTooManyRequests:
				if gotLimited == nil {
					recCopy := *rec
					gotLimited = &recCopy
				}
			default:
				t.Fatalf("storm round %d: unexpected status %d (body: %s)", round, rec.Code, rec.Body.String())
			}
		}
		// Isolation: the mule's sync succeeds every round, storm or not.
		if rec := muleSync(); rec.Code != http.StatusOK {
			t.Fatalf("honest mule must keep syncing during the storm, got %d (body: %s)", rec.Code, rec.Body.String())
		}
	}
	if gotLimited == nil {
		t.Fatalf("storm never exhausted the request budget — fixture is wrong")
	}
	if code := errBodyOf(t, gotLimited); code != "rate_limited" {
		t.Fatalf("storm must be shed with rate_limited, got %q", code)
	}
	retryAfter := gotLimited.Header().Get("Retry-After")
	seconds, err := strconv.Atoi(retryAfter)
	if err != nil || seconds < 1 {
		t.Fatalf("Retry-After must be a sane positive integer, got %q", retryAfter)
	}
	// Still exhausted (refill is an hour away), the mule still fine.
	if rec := syncBodyFrom(t, h, attackerStation, nil, nil); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("attacker must stay shed until refill, got %d", rec.Code)
	}
	if rec := muleSync(); rec.Code != http.StatusOK {
		t.Fatalf("honest mule must keep syncing after the storm, got %d", rec.Code)
	}
}

// TestFloodPerIPEnvelopeQuotaIsolation pins the store-side quota: one
// station's pushes stop at its own 600-envelope budget (the 7th full batch
// is refused whole, storing nothing), while another IP keeps full push
// service afterwards — one hog cannot own the 5000-envelope node.
func TestFloodPerIPEnvelopeQuotaIsolation(t *testing.T) {
	// Shipped burst (600), but zero refill so the exhaustion is permanent and
	// the assertions deterministic.
	restore := overrideAdmissionLimits(postRequestBurst, postRequestRefillInterval, 600, 0, bucketEvictionFloor, bucketIdleTTL)
	defer restore()

	h, store := newTestHandler(t)
	now := time.Now().Unix()

	batch := func(seed int) []envelope.Envelope {
		envs := make([]envelope.Envelope, 0, 100)
		for i := 0; i < 100; i++ {
			envs = append(envs, validEnv(hexID(seed+i), now))
		}
		return envs
	}

	// Six full batches fill the attacker's budget exactly (6 × 100 = 600).
	for b := 0; b < 6; b++ {
		rec := syncBodyFrom(t, h, attackerStation, nil, batch(b*100))
		if rec.Code != http.StatusOK {
			t.Fatalf("attacker batch %d within budget: got %d (body: %s)", b, rec.Code, rec.Body.String())
		}
	}

	// The seventh batch is refused whole, BEFORE storage validation: 429
	// rate_limited with Retry-After, nothing of it stored.
	over := batch(1000)
	rec := syncBodyFrom(t, h, attackerStation, nil, over)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("batch past the budget: got %d, want 429 (body: %s)", rec.Code, rec.Body.String())
	}
	if code := errBodyOf(t, rec); code != "rate_limited" {
		t.Fatalf("quota exhaustion must carry rate_limited, got %q", code)
	}
	if ra := rec.Header().Get("Retry-After"); ra == "" {
		t.Fatalf("quota 429 must carry Retry-After")
	}

	// Other IPs keep full service — and their envelopes land.
	for b := 0; b < 2; b++ {
		rec := syncBodyFrom(t, h, honestMule, nil, batch(5000+b*100))
		if rec.Code != http.StatusOK {
			t.Fatalf("honest mule push after attacker exhaustion: got %d (body: %s)", rec.Code, rec.Body.String())
		}
	}

	// The attacker is still shed (no refill), the mule still fine.
	if rec := syncBodyFrom(t, h, attackerStation, nil, batch(9000)); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("attacker must stay shed without refill, got %d", rec.Code)
	}
	if rec := syncBodyFrom(t, h, honestMule, nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("honest mule pull must stay fine, got %d", rec.Code)
	}

	// Store accounting: exactly the 600 attacker + 200 mule envelopes — the
	// rejected 100-envelope batch contributed nothing (fail closed).
	if got := storedCount(t, store, now); got != 800 {
		t.Fatalf("store must hold exactly 600 attacker + 200 mule envelopes, got %d", got)
	}
}

// brokenStore is an injected failing Store: write/read calls return the
// configured error (the api.Store interface exists precisely so handlers
// never touch SQL — here it lets a test simulate a full disk / dead SD card).
// The health stat methods fail the same way: the diagnostics surface sheds
// with 507 when it cannot truthfully read the store (issue #31).
type brokenStore struct {
	err error
}

func (b *brokenStore) InsertEnvelopes(envs []envelope.Envelope) (int, error) {
	return 0, b.err
}
func (b *brokenStore) PullEnvelopes(knownIDs []string, limit int, now int64) ([]envelope.Envelope, error) {
	return nil, b.err
}
func (b *brokenStore) UpsertDirectory(pubkey, x25519, alias string, lastSeen int64, epoch int64, prekeys []byte) error {
	return b.err
}
func (b *brokenStore) GetDirectory(limit int) ([]storage.DirectoryEntry, error) {
	return nil, b.err
}
func (b *brokenStore) EnvelopeCount() (int64, error)  { return 0, b.err }
func (b *brokenStore) DirectoryCount() (int64, error) { return 0, b.err }
func (b *brokenStore) DBSizeBytes() (int64, error)    { return 0, b.err }

// TestFloodStorageUnavailableMapsTo507 forces storage write failures: the
// sync handler must translate them into a clean 507 storage_unavailable in
// the §10.1 error shape (never a 500 or a panic), the daemon must stay
// alive, and the ErrCapacity → 429 node_full mapping must stay untouched.
func TestFloodStorageUnavailableMapsTo507(t *testing.T) {
	h, err := New(&brokenStore{err: errors.New("storage: insert envelope: disk I/O error (SQLITE_IOERR_WRITE)")}, testBuild, testWebFS)
	if err != nil {
		t.Fatalf("build handler: %v", err)
	}

	rec := syncBodyFrom(t, h, honestMule, nil, []envelope.Envelope{validEnv(hexID(1), time.Now().Unix())})
	if rec.Code != http.StatusInsufficientStorage {
		t.Fatalf("storage failure: got %d, want 507 (body: %s)", rec.Code, rec.Body.String())
	}
	if code := errBodyOf(t, rec); code != "storage_unavailable" {
		t.Fatalf("507 must carry storage_unavailable, got %q", code)
	}

	// Pulls fail the same clean way when the storage engine is unhappy.
	rec = syncBodyFrom(t, h, honestMule, nil, nil)
	if rec.Code != http.StatusInsufficientStorage || errBodyOf(t, rec) != "storage_unavailable" {
		t.Fatalf("pull under storage failure: got %d / %q, want 507 storage_unavailable", rec.Code, errBodyOf(t, rec))
	}

	// The daemon is alive: reads that bypass the broken engine still answer.
	rec = do(t, h, http.MethodGet, "/api/v1/capabilities", CanonicalHost, nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("daemon must stay alive after storage failure, got %d", rec.Code)
	}

	// ErrCapacity keeps its dedicated 429 node_full mapping (§8.1).
	hCap, err := New(&brokenStore{err: storage.ErrCapacity}, testBuild, testWebFS)
	if err != nil {
		t.Fatalf("build handler: %v", err)
	}
	rec = syncBodyFrom(t, hCap, honestMule, nil, []envelope.Envelope{validEnv(hexID(2), time.Now().Unix())})
	if rec.Code != http.StatusTooManyRequests || errBodyOf(t, rec) != "node_full" {
		t.Fatalf("capacity failure must stay 429 node_full, got %d / %q", rec.Code, errBodyOf(t, rec))
	}
}

// TestFloodOversizedRequestHeaderServerSurvives fires a request with a
// multi-megabyte header at a REAL net/http server (header limits live in the
// server read loop, not in handlers): net/http answers 431 and the node must
// answer the next, normal request — the server survives header abuse.
func TestFloodOversizedRequestHeaderServerSurvives(t *testing.T) {
	h, _ := newTestHandler(t)
	srv := httptest.NewServer(h)
	defer srv.Close()

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	// ~2 MiB of junk header, well past net/http's default 1 MiB
	// MaxHeaderBytes. The request line and Host are canonical so the only
	// thing under test is the header size itself.
	junk := strings.Repeat("A", 2<<20)
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nX-Junk: %s\r\n\r\n", CanonicalHost, junk)

	status, err := bufio.NewReader(conn).ReadString('\n')
	conn.Close()
	if err != nil && status == "" {
		t.Fatalf("no response to oversized header: %v", err)
	}
	if !strings.Contains(status, "431") {
		t.Fatalf("oversized header: got status line %q, want 431", status)
	}

	// Survival: the next ordinary request is answered normally.
	client := new(http.Client)
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/capabilities", nil)
	req.Host = CanonicalHost
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("server did not survive header abuse: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("post-abuse capabilities request: got %d, want 200", resp.StatusCode)
	}
}

// TestRateLimiterTokenBucketMath pins the bucket arithmetic: burst is
// consumable immediately, refill is continuous and capped, withdrawals are
// all-or-nothing, zero-cost probes mint no bucket, and costs larger than the
// burst are admitted only from a full bucket.
func TestRateLimiterTokenBucketMath(t *testing.T) {
	t0 := time.Unix(1700000000, 0)
	l := newRateLimiter(3, time.Second) // burst 3, refill 1 token/s
	clock := t0
	l.now = func() time.Time { return clock }

	// Burst is immediately consumable, exactly burst times.
	for i := 0; i < 3; i++ {
		if ok, wait := l.allow("k", 1); !ok || wait != 0 {
			t.Fatalf("consume %d/3 from full burst: ok=%v wait=%v", i+1, ok, wait)
		}
	}
	// Fourth withdrawal must wait one full refill interval.
	if ok, wait := l.allow("k", 1); ok || wait != time.Second {
		t.Fatalf("empty bucket: ok=%v wait=%v, want false/1s", ok, wait)
	}
	// Half a second later there is not enough yet — and Retry-After reports
	// the missing half second.
	clock = t0.Add(500 * time.Millisecond)
	if ok, wait := l.allow("k", 1); ok || wait != 500*time.Millisecond {
		t.Fatalf("half-refilled bucket: ok=%v wait=%v, want false/500ms", ok, wait)
	}
	// One second later exactly one token has refilled.
	clock = t0.Add(1 * time.Second)
	if ok, _ := l.allow("k", 1); !ok {
		t.Fatalf("one refilled token must admit one withdrawal")
	}
	if ok, wait := l.allow("k", 1); ok || wait != time.Second {
		t.Fatalf("overdraw past refill: ok=%v wait=%v", ok, wait)
	}

	// Refill caps at the burst: waiting an hour never yields more than 3.
	clock = t0.Add(time.Hour)
	for i := 0; i < 3; i++ {
		if ok, _ := l.allow("k", 1); !ok {
			t.Fatalf("idle bucket must be full again (withdrawal %d/3)", i+1)
		}
	}
	if ok, _ := l.allow("k", 1); ok {
		t.Fatalf("refill must cap at the burst")
	}

	// All-or-nothing: a cost of 3 is admitted from full, a cost of 3 with 2
	// tokens is refused without spending the 2.
	clock = t0.Add(2 * time.Hour)
	if ok, _ := l.allow("bulk", 3); !ok {
		t.Fatalf("full-bucket bulk withdrawal must pass")
	}
	if ok, _ := l.allow("bulk", 2); ok {
		t.Fatalf("bulk withdrawal past the remaining balance must fail")
	}
	if ok, _ := l.allow("bulk", 2); ok {
		t.Fatalf("failed bulk withdrawal must not have spent tokens")
	}

	// Cost larger than the burst: admitted once from a FULL bucket only.
	l2 := newRateLimiter(2, 0) // burst-only, never refills
	l2.now = func() time.Time { return t0 }
	if ok, _ := l2.allow("x", 5); !ok {
		t.Fatalf("oversized cost from a full bucket must be admitted once")
	}
	if ok, _ := l2.allow("x", 1); ok {
		t.Fatalf("after the oversized withdrawal the bucket must be spent")
	}

	// Zero-cost probes never mint buckets (pull-only syncs must not grow the
	// map).
	if ok, _ := l2.allow("ghost", 0); !ok {
		t.Fatalf("zero-cost probe must always pass")
	}
	if len(l2.buckets) != 1 {
		t.Fatalf("zero-cost probe must not mint a bucket, map: %v", l2.buckets)
	}
}

// TestRateLimiterRetryAfterHeaderSane checks the Retry-After rendering: ceil
// to whole seconds, never zero, never negative — and the burst-only budget's
// "not now" fallback.
func TestRateLimiterRetryAfterHeaderSane(t *testing.T) {
	cases := []struct {
		wait time.Duration
		want string
	}{
		{-time.Second, "1"},
		{0, "1"},
		{1 * time.Millisecond, "1"},
		{999 * time.Millisecond, "1"},
		{1001 * time.Millisecond, "2"},
		{2 * time.Second, "2"},
		{time.Hour, "3600"},
	}
	for _, tc := range cases {
		if got := strconv.FormatInt(retryAfterSeconds(tc.wait), 10); got != tc.want {
			t.Fatalf("retryAfterSeconds(%v) = %s, want %s", tc.wait, got, tc.want)
		}
	}

	// Burst-only limiter (refill disabled) must not produce an infinite or
	// zero Retry-After on exhaustion.
	l := newRateLimiter(1, 0)
	l.now = func() time.Time { return time.Unix(1700000000, 0) }
	if ok, _ := l.allow("k", 1); !ok {
		t.Fatalf("first withdrawal must pass")
	}
	ok, wait := l.allow("k", 1)
	if ok || wait <= 0 || wait > time.Hour {
		t.Fatalf("burst-only exhaustion: ok=%v wait=%v, want false with a bounded hint", ok, wait)
	}
}

// TestRateLimiterIgnoresForwardedFor proves the bucket key is derived from
// the network-layer RemoteAddr ONLY: a spoofed X-Forwarded-For must neither
// change the key nor mint fresh buckets for an exhausted client.
func TestRateLimiterIgnoresForwardedFor(t *testing.T) {
	// Unit level: identical keys with, without, and despite differing XFF.
	build := func(xff string) *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/sync", nil)
		req.RemoteAddr = "9.9.9.9:55555"
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		return req
	}
	base := clientKey(build(""))
	if base != "9.9.9.9" {
		t.Fatalf("clientKey must be the bare source IP, got %q", base)
	}
	if clientKey(build("1.1.1.1")) != base || clientKey(build("2.2.2.2, 3.3.3.3")) != base {
		t.Fatalf("X-Forwarded-For must not influence the bucket key")
	}

	// Behavioral level: with a burst of 1, the second request from the same
	// socket is shed EVEN IF it rotates the spoofed header (which, if
	// trusted, would have bought it a fresh bucket).
	restore := overrideAdmissionLimits(1, time.Hour, syncEnvelopeBurst, syncEnvelopeRefillPerHour, bucketEvictionFloor, bucketIdleTTL)
	defer restore()
	h, _ := newTestHandler(t)

	syncWithXFF := func(xff string, srcPort int) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/sync", strings.NewReader("{}"))
		req.RemoteAddr = net.JoinHostPort(attackerStation, fmt.Sprint(srcPort))
		req.Host = CanonicalHost
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", xff)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	recA := syncWithXFF("6.6.6.6", 40000)
	recB := syncWithXFF("7.7.7.7", 40001)

	if recA.Code != http.StatusOK {
		t.Fatalf("first request must pass, got %d", recA.Code)
	}
	if recB.Code != http.StatusTooManyRequests || errBodyOf(t, recB) != "rate_limited" {
		t.Fatalf("rotated X-Forwarded-For must not mint a fresh bucket, got %d / %s", recB.Code, recB.Body.String())
	}
}

// TestRateLimiterIdleBucketEviction pins the unbounded-growth guard: buckets
// idle past bucketIdleTTL are swept (directly and via the lazy floor
// trigger), so a flood of unique source IPs cannot grow the map forever.
func TestRateLimiterIdleBucketEviction(t *testing.T) {
	restore := overrideAdmissionLimits(postRequestBurst, postRequestRefillInterval, syncEnvelopeBurst, syncEnvelopeRefillPerHour, 4, time.Minute)
	defer restore()

	t0 := time.Unix(1700000000, 0)
	clock := t0
	l := newRateLimiter(10, time.Second)
	l.now = func() time.Time { return clock }

	// 20 distinct stations mint 20 buckets (floor is 4 but nothing is idle
	// yet — the sweep must not evict live buckets).
	for i := 0; i < 20; i++ {
		if ok, _ := l.allow(fmt.Sprintf("10.66.0.%d", i), 1); !ok {
			t.Fatalf("station %d must be admitted", i)
		}
	}
	if len(l.buckets) != 20 {
		t.Fatalf("20 live buckets expected, got %d", len(l.buckets))
	}

	// Direct sweep at idleTTL + 1s: everything goes.
	clock = t0.Add(bucketIdleTTL + time.Second)
	if n := l.sweepIdle(clock); n != 20 {
		t.Fatalf("sweep must evict all 20 idle buckets, evicted %d", n)
	}
	if len(l.buckets) != 0 {
		t.Fatalf("map must be empty after the sweep, got %d", len(l.buckets))
	}

	// Lazy trigger: refill 10 buckets, let them go idle, then one new
	// request trips the sweep inside allow() and the map collapses to 1.
	clock = t0.Add(2 * bucketIdleTTL)
	for i := 0; i < 10; i++ {
		l.allow(fmt.Sprintf("10.77.0.%d", i), 1)
	}
	clock = clock.Add(bucketIdleTTL + time.Second)
	if ok, _ := l.allow("10.88.0.1", 1); !ok {
		t.Fatalf("fresh station must be admitted")
	}
	if len(l.buckets) != 1 {
		t.Fatalf("lazy sweep on the floor must collapse the map to the one live bucket, got %d", len(l.buckets))
	}
}
