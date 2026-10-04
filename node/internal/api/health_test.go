package api

// health_test.go — the diagnostics surface of issue #31 (docs/protocol.md
// §10.7): document shape, truthful aggregates against a seeded store, the
// 1-second snapshot cache, the per-IP health budget, wrong-method handling,
// canonical-host middleware, and the privacy assertion (no user-identifying
// datum anywhere in the raw bodies).

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"offgrid/dtn-node/internal/envelope"
	"offgrid/dtn-node/internal/health"
	"offgrid/dtn-node/internal/storage"
)

// healthMembers is the exact §10.7 top-level member set of the health
// document; countersMembers and rejectionMembers the nested sets.
var (
	healthMembers = []string{
		"status", "api", "build", "envelope_versions", "schema_version",
		"uptime_seconds", "envelopes", "envelope_capacity", "directory_entries",
		"db_size_bytes", "last_cleanup_unix", "last_cleanup_envelopes_deleted",
		"counters",
	}
	countersMembers = []string{
		"pushes_accepted", "pushes_rejected", "pushes_rejected_by_class",
		"dedup_hits", "ttl_sweeps", "ttl_swept_envelopes",
	}
	rejectionMembers = []string{
		"invalid", "rate_limited", "node_full", "storage_unavailable", "too_large",
	}
)

// getHealth GETs a diagnostics path (JSON or HTML) with the canonical Host.
func getHealth(t *testing.T, h http.Handler, path string) (int, http.Header, string) {
	t.Helper()
	rec := do(t, h, http.MethodGet, path, CanonicalHost, nil, "")
	return rec.Code, rec.Header(), rec.Body.String()
}

// decodeHealthBody decodes a 200 health document into the response struct.
func decodeHealthBody(t *testing.T, body string) healthResponse {
	t.Helper()
	var doc healthResponse
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("decode health document: %v (body: %s)", err, body)
	}
	return doc
}

// overrideHealthNow swaps the snapshot-cache clock (the healthNow test hook)
// and returns the restore func (defer it).
func overrideHealthNow(now func() time.Time) (restore func()) {
	old := healthNow
	healthNow = now
	return func() { healthNow = old }
}

// envWithHint is validEnv with a per-envelope dest_hint, so the privacy test
// can seed several distinct hints.
func envWithHint(id string, createdAt int64, hint string) envelope.Envelope {
	e := validEnv(id, createdAt)
	e.DestHint = hint
	return e
}

// TestHealthEndpointDocument verifies the §10.7 document shape on a fresh
// node: exactly the thirteen members, the nested counter sets, the identity
// members wired to the same sources as §15.5, and truthful zero values.
func TestHealthEndpointDocument(t *testing.T) {
	h, _ := newTestHandler(t)

	code, header, body := getHealth(t, h, "/api/v1/health")
	if code != http.StatusOK {
		t.Fatalf("got %d, want 200 (body: %s)", code, body)
	}
	if ct := header.Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Fatalf("Content-Type: got %q, want application/json; charset=utf-8", ct)
	}

	var doc map[string]any
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("decode health document: %v", err)
	}
	if len(doc) != len(healthMembers) {
		t.Fatalf("health must carry exactly the %d §10.7 members, got %d: %v", len(healthMembers), len(doc), doc)
	}
	for _, m := range healthMembers {
		if _, ok := doc[m]; !ok {
			t.Errorf("health document is missing member %q", m)
		}
	}
	counters, ok := doc["counters"].(map[string]any)
	if !ok || len(counters) != len(countersMembers) {
		t.Fatalf("counters must carry exactly %d members, got %v", len(countersMembers), counters)
	}
	for _, m := range countersMembers {
		if _, ok := counters[m]; !ok {
			t.Errorf("counters is missing member %q", m)
		}
	}
	classes, ok := counters["pushes_rejected_by_class"].(map[string]any)
	if !ok || len(classes) != len(rejectionMembers) {
		t.Fatalf("pushes_rejected_by_class must carry exactly %d members, got %v", len(rejectionMembers), classes)
	}
	for _, m := range rejectionMembers {
		if _, ok := classes[m]; !ok {
			t.Errorf("pushes_rejected_by_class is missing member %q", m)
		}
	}

	hr := decodeHealthBody(t, body)
	if hr.Status != "ok" {
		t.Fatalf("status must be \"ok\" (liveness, §10.7), got %q", hr.Status)
	}
	if hr.API != "v1" {
		t.Fatalf("api must be \"v1\", got %q", hr.API)
	}
	if hr.Build != testBuild {
		t.Fatalf("build must surface the identifier wired through New, got %q want %q", hr.Build, testBuild)
	}
	if len(hr.EnvelopeVersions) != 2 || hr.EnvelopeVersions[0] != 1 || hr.EnvelopeVersions[1] != 2 {
		t.Fatalf("envelope_versions must be [1, 2] (§15.3), got %v", hr.EnvelopeVersions)
	}
	if hr.SchemaVersion != storage.SchemaVersion {
		t.Fatalf("schema_version must be storage.SchemaVersion (%d), got %d", storage.SchemaVersion, hr.SchemaVersion)
	}
	if hr.UptimeSeconds < 0 {
		t.Fatalf("uptime_seconds must never be negative, got %d", hr.UptimeSeconds)
	}
	// A fresh node: empty store, no janitor running in-process, no requests.
	if hr.Envelopes != 0 || hr.DirectoryEntries != 0 {
		t.Fatalf("fresh node must report empty aggregates, got envelopes=%d directory=%d", hr.Envelopes, hr.DirectoryEntries)
	}
	if hr.EnvelopeCapacity != storage.MaxEnvelopes() || hr.EnvelopeCapacity != 5000 {
		t.Fatalf("envelope_capacity must be the §8.1 cap (5000), got %d", hr.EnvelopeCapacity)
	}
	if hr.DBSizeBytes <= 0 {
		t.Fatalf("db_size_bytes must be positive once the schema exists, got %d", hr.DBSizeBytes)
	}
	if hr.LastCleanupUnix != 0 || hr.LastCleanupEnvelopesDeleted != 0 {
		t.Fatalf("no janitor has run in-process: last cleanup must read 0, got %+v", hr)
	}
	if hr.Counters.PushesAccepted != 0 || hr.Counters.PushesRejected != 0 || hr.Counters.DedupHits != 0 ||
		hr.Counters.TTLSweeps != 0 || hr.Counters.TTLSweptEnvelopes != 0 {
		t.Fatalf("fresh counters must be zero, got %+v", hr.Counters)
	}
}

// TestHealthTruthfulAggregates drives real traffic (pushes, a re-push, an
// invalid push, directory upserts) and asserts the snapshot matches the store
// and the counters exactly — the "truthful aggregates" acceptance criterion.
func TestHealthTruthfulAggregates(t *testing.T) {
	h, store := newTestHandler(t)
	now := time.Now().Unix()

	e1 := validEnv(hexID(21), now)
	e2 := validEnv(hexID(22), now+10)

	// 1. accepted push (2 envelopes, own ids in known_ids).
	rec := postJSON(t, h, "/api/v1/sync", map[string]any{
		"known_ids": []string{e1.ID, e2.ID}, "push_envelopes": []envelope.Envelope{e1, e2},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("push: got %d (body: %s)", rec.Code, rec.Body.String())
	}
	// 2. re-push of e1 alone: accepted, one dedup hit.
	rec = postJSON(t, h, "/api/v1/sync", map[string]any{
		"push_envelopes": []envelope.Envelope{e1},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("re-push: got %d (body: %s)", rec.Code, rec.Body.String())
	}
	// 3. invalid push: rejected (class invalid), stores nothing.
	bad := validEnv(hexID(23), now)
	bad.Payload = "!!!"
	rec = postJSON(t, h, "/api/v1/sync", map[string]any{"push_envelopes": []envelope.Envelope{bad}})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid push: got %d, want 400", rec.Code)
	}
	// 4. pull-only sync: neither accepted nor rejected (nothing pushed).
	rec = postJSON(t, h, "/api/v1/sync", map[string]any{})
	if rec.Code != http.StatusOK {
		t.Fatalf("pull-only sync: got %d", rec.Code)
	}
	// 5. two directory entries.
	for _, seed := range []byte{1, 3} {
		rec = postJSON(t, h, "/api/v1/directory", map[string]string{
			"alias": fmt.Sprintf("user_%d", seed), "pubkey": keyB64(seed), "x25519": keyB64(seed + 1),
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("directory upsert: got %d", rec.Code)
		}
	}

	code, _, body := getHealth(t, h, "/api/v1/health")
	if code != http.StatusOK {
		t.Fatalf("health: got %d (body: %s)", code, body)
	}
	hr := decodeHealthBody(t, body)

	// Store figures must match the seeded store exactly.
	pulled, err := store.PullEnvelopes(nil, 200, now)
	if err != nil {
		t.Fatalf("pull store: %v", err)
	}
	if hr.Envelopes != int64(len(pulled)) || len(pulled) != 2 {
		t.Fatalf("envelopes must match the store (%d), got %d", len(pulled), hr.Envelopes)
	}
	if hr.DirectoryEntries != 2 {
		t.Fatalf("directory_entries: got %d, want 2", hr.DirectoryEntries)
	}

	// Counters must match the traffic above exactly.
	c := hr.Counters
	if c.PushesAccepted != 2 {
		t.Fatalf("pushes_accepted: got %d, want 2", c.PushesAccepted)
	}
	if c.PushesRejected != 1 {
		t.Fatalf("pushes_rejected: got %d, want 1", c.PushesRejected)
	}
	if c.PushesRejectedByClass.Invalid != 1 {
		t.Fatalf("rejected invalid: got %d, want 1", c.PushesRejectedByClass.Invalid)
	}
	if c.PushesRejectedByClass.RateLimited != 0 || c.PushesRejectedByClass.NodeFull != 0 ||
		c.PushesRejectedByClass.StorageUnavailable != 0 || c.PushesRejectedByClass.TooLarge != 0 {
		t.Fatalf("other rejection classes must be zero, got %+v", c.PushesRejectedByClass)
	}
	if c.DedupHits != 1 {
		t.Fatalf("dedup_hits: got %d, want 1 (the re-pushed e1)", c.DedupHits)
	}
	if c.TTLSweeps != 0 || c.TTLSweptEnvelopes != 0 {
		t.Fatalf("no janitor runs in-process: ttl counters must be zero, got %+v", c)
	}
}

// TestHealthRejectionClasses exercises every rejection class end to end and
// asserts the class bucket matches the error code the client actually saw.
func TestHealthRejectionClasses(t *testing.T) {
	now := time.Now().Unix()

	t.Run("invalid (400)", func(t *testing.T) {
		h, _ := newTestHandler(t)
		bad := validEnv(hexID(31), now)
		bad.DestHint = "abc"
		if rec := postJSON(t, h, "/api/v1/sync", map[string]any{"push_envelopes": []envelope.Envelope{bad}}); rec.Code != http.StatusBadRequest {
			t.Fatalf("got %d, want 400", rec.Code)
		}
		assertRejectionClass(t, h, 1, 0, 0, 0, 0)
	})

	t.Run("rate_limited (429 request budget)", func(t *testing.T) {
		// Burst 1, no refill: the second sync from the same IP is shed at the
		// middleware boundary, before the body is read.
		restore := overrideAdmissionLimits(1, time.Hour, syncEnvelopeBurst, syncEnvelopeRefillPerHour, bucketEvictionFloor, bucketIdleTTL)
		defer restore()
		h, _ := newTestHandler(t)
		if rec := syncBodyFrom(t, h, honestMule, nil, nil); rec.Code != http.StatusOK {
			t.Fatalf("first sync: got %d", rec.Code)
		}
		if rec := syncBodyFrom(t, h, honestMule, nil, nil); rec.Code != http.StatusTooManyRequests {
			t.Fatalf("second sync: got %d, want 429", rec.Code)
		}
		assertRejectionClass(t, h, 0, 1, 0, 0, 0)
	})

	t.Run("node_full (429 capacity)", func(t *testing.T) {
		h, store := newTestHandler(t)
		fill := make([]envelope.Envelope, 0, 5000)
		for i := 0; i < 5000; i++ {
			fill = append(fill, validEnv(hexID(i), now))
		}
		if inserted, err := store.InsertEnvelopes(fill); err != nil || inserted != 5000 {
			t.Fatalf("fill store to cap: got %d inserted, err=%v", inserted, err)
		}
		rec := postJSON(t, h, "/api/v1/sync", map[string]any{
			"push_envelopes": []envelope.Envelope{validEnv(hexID(99999), now)},
		})
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("got %d, want 429 node_full", rec.Code)
		}
		assertRejectionClass(t, h, 0, 0, 1, 0, 0)
	})

	t.Run("too_large (413)", func(t *testing.T) {
		h, _ := newTestHandler(t)
		known := make([]string, 0, 20000)
		for i := 0; i < 20000; i++ {
			known = append(known, hexID(i))
		}
		body, _ := json.Marshal(map[string]any{"known_ids": known})
		if len(body) <= MaxBodyBytes {
			t.Fatalf("fixture must exceed the body cap, is %d bytes", len(body))
		}
		if rec := do(t, h, http.MethodPost, "/api/v1/sync", CanonicalHost, body, "application/json"); rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("got %d, want 413", rec.Code)
		}
		assertRejectionClass(t, h, 0, 0, 0, 0, 1)
	})

	t.Run("storage_unavailable (507)", func(t *testing.T) {
		// The store is broken, so the snapshot itself cannot be served —
		// assert the counters through the shared instance instead (the same
		// wiring the daemon's main uses between API and janitor).
		counters := health.NewCounters()
		h, err := NewWithCounters(&brokenStore{err: errors.New("storage: insert envelope: disk I/O error")}, counters, testBuild, testWebFS)
		if err != nil {
			t.Fatalf("build handler: %v", err)
		}
		rec := syncBodyFrom(t, h, honestMule, nil, []envelope.Envelope{validEnv(hexID(41), now)})
		if rec.Code != http.StatusInsufficientStorage {
			t.Fatalf("got %d, want 507", rec.Code)
		}
		totals := counters.Totals()
		if totals.PushesRejected != 1 || totals.RejectedStorageUnavailable != 1 {
			t.Fatalf("507 must be counted as storage_unavailable, got %+v", totals)
		}
	})
}

// assertRejectionClass fetches the health document and asserts the exact
// per-class rejection bucket (invalid, rate_limited, node_full,
// storage_unavailable, too_large).
func assertRejectionClass(t *testing.T, h http.Handler, invalid, rateLimited, nodeFull, storageUnavailable, tooLarge int64) {
	t.Helper()
	code, _, body := getHealth(t, h, "/api/v1/health")
	if code != http.StatusOK {
		t.Fatalf("health: got %d (body: %s)", code, body)
	}
	classes := decodeHealthBody(t, body).Counters.PushesRejectedByClass
	want := healthRejectionClassesJSON{
		Invalid: invalid, RateLimited: rateLimited, NodeFull: nodeFull,
		StorageUnavailable: storageUnavailable, TooLarge: tooLarge,
	}
	if classes != want {
		t.Fatalf("rejection classes: got %+v, want %+v", classes, want)
	}
}

// TestHealthCacheWithinSecond pins the 1-second snapshot cache: within the
// TTL a change in the store is NOT reflected (the flood cannot hammer
// SQLite), after it the next request refreshes. The cache clock is injected
// (healthNow), so the test is deterministic with no sleeping.
func TestHealthCacheWithinSecond(t *testing.T) {
	h, store := newTestHandler(t)
	now := time.Now().Unix()

	t0 := time.Unix(1700000000, 0)
	clock := t0
	defer overrideHealthNow(func() time.Time { return clock })()

	// First request refreshes (empty cache): zero envelopes.
	code, _, body := getHealth(t, h, "/api/v1/health")
	if code != http.StatusOK {
		t.Fatalf("got %d (body: %s)", code, body)
	}
	if got := decodeHealthBody(t, body).Envelopes; got != 0 {
		t.Fatalf("fresh store must report 0 envelopes, got %d", got)
	}

	// Change the store BEHIND the cache and ask again within the TTL: the
	// cached snapshot is served untouched.
	if _, err := store.InsertEnvelopes([]envelope.Envelope{validEnv(hexID(51), now)}); err != nil {
		t.Fatalf("seed store: %v", err)
	}
	_, _, body = getHealth(t, h, "/api/v1/health")
	if got := decodeHealthBody(t, body).Envelopes; got != 0 {
		t.Fatalf("within the cache TTL the snapshot must not re-read the store, got envelopes=%d", got)
	}

	// Past the TTL the next request refreshes and sees the truth.
	clock = t0.Add(2 * healthCacheTTL)
	_, _, body = getHealth(t, h, "/api/v1/health")
	if got := decodeHealthBody(t, body).Envelopes; got != 1 {
		t.Fatalf("after the cache TTL the snapshot must refresh, got envelopes=%d", got)
	}
}

// TestHealthAndStatusMethodNotAllowed verifies the §10.1 405 behavior for the
// diagnostics paths, and (§10.2) that the canonical-host redirect covers them.
func TestHealthAndStatusMethodNotAllowed(t *testing.T) {
	h, _ := newTestHandler(t)

	for _, path := range []string{"/api/v1/health", "/status"} {
		for _, method := range []string{http.MethodPost, http.MethodDelete, http.MethodPut} {
			rec := do(t, h, method, path, CanonicalHost, nil, "")
			if rec.Code != http.StatusMethodNotAllowed {
				t.Fatalf("%s %s: got %d, want 405 (body: %s)", method, path, rec.Code, rec.Body.String())
			}
			if got := rec.Header().Get("Allow"); got != "GET" {
				t.Fatalf("%s %s Allow: got %q, want GET", method, path, got)
			}
		}
		// §10.2: same middleware as every route — non-canonical Host → 301
		// with path and query preserved, never an answer.
		rec := do(t, h, http.MethodGet, path, "10.42.0.1:8080", nil, "")
		if rec.Code != http.StatusMovedPermanently {
			t.Fatalf("non-canonical host %s: got %d, want 301", path, rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "http://"+CanonicalHost+path {
			t.Fatalf("non-canonical host Location for %s: got %q", path, loc)
		}
	}
}

// TestHealthBudget429 exhausts the diagnostics budget from one source IP
// (burst 60, refill 1/s): the 61st GET answers 429 rate_limited with a sane
// Retry-After, /status shares the same budget, and another IP keeps full
// service.
func TestHealthBudget429(t *testing.T) {
	h, _ := newTestHandler(t)

	for i := 0; i < healthRequestBurst; i++ {
		if rec := doFrom(t, h, attackerStation, http.MethodGet, "/api/v1/health", nil, ""); rec.Code != http.StatusOK {
			t.Fatalf("request %d inside the burst: got %d", i+1, rec.Code)
		}
	}
	rec := doFrom(t, h, attackerStation, http.MethodGet, "/api/v1/health", nil, "")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("past the burst: got %d, want 429 (body: %s)", rec.Code, rec.Body.String())
	}
	if code := errBodyOf(t, rec); code != "rate_limited" {
		t.Fatalf("429 must carry rate_limited, got %q", code)
	}
	seconds, err := strconv.Atoi(rec.Header().Get("Retry-After"))
	if err != nil || seconds < 1 {
		t.Fatalf("Retry-After must be a positive integer, got %q", rec.Header().Get("Retry-After"))
	}

	// /status sits behind the same budget: the exhausted client is shed there
	// too, and a fresh IP is served untouched.
	if rec := doFrom(t, h, attackerStation, http.MethodGet, "/status", nil, ""); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status for the exhausted client: got %d, want 429", rec.Code)
	}
	if rec := doFrom(t, h, honestMule, http.MethodGet, "/api/v1/health", nil, ""); rec.Code != http.StatusOK {
		t.Fatalf("another IP must keep service: got %d (body: %s)", rec.Code, rec.Body.String())
	}
	if rec := doFrom(t, h, honestMule, http.MethodGet, "/status", nil, ""); rec.Code != http.StatusOK {
		t.Fatalf("status for another IP: got %d", rec.Code)
	}
}

// TestHealthPrivacy is the §13 review of this endpoint, as a test: real mail
// with distinct ids, hints and payloads plus registered aliases and keys go
// through the node, and NONE of it may appear anywhere in the raw health or
// status bodies (aggregate counters only, §10.7).
func TestHealthPrivacy(t *testing.T) {
	h, _ := newTestHandler(t)
	now := time.Now().Unix()

	// Registered identities: aliases and public keys that must never surface.
	aliased := []struct{ alias, pubkey, x25519 string }{
		{"alice_priv", keyB64(1), keyB64(2)},
		{"bob_priv", keyB64(3), keyB64(4)},
	}
	for _, u := range aliased {
		if rec := postJSON(t, h, "/api/v1/directory", map[string]string{
			"alias": u.alias, "pubkey": u.pubkey, "x25519": u.x25519,
		}); rec.Code != http.StatusOK {
			t.Fatalf("directory upsert: got %d", rec.Code)
		}
	}

	// Three envelopes with distinct ids, hints and payloads.
	envs := make([]envelope.Envelope, 0, 3)
	secrets := []string{aliased[0].alias, aliased[1].alias}
	for i := 0; i < 3; i++ {
		e := envWithHint(hexID(61+i), now+int64(i), fmt.Sprintf("%016x", 0xBEEF00+i))
		envs = append(envs, e)
		secrets = append(secrets, e.ID, e.DestHint, e.Payload)
	}
	rec := postJSON(t, h, "/api/v1/sync", map[string]any{"push_envelopes": envs})
	if rec.Code != http.StatusOK {
		t.Fatalf("push: got %d (body: %s)", rec.Code, rec.Body.String())
	}

	// Sanity: the fixtures DO surface on the endpoints that are allowed to
	// carry them — the assertions below are meaningful only then.
	rec = do(t, h, http.MethodGet, "/api/v1/directory", CanonicalHost, nil, "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "alice_priv") {
		t.Fatalf("fixture sanity failed: directory must list the aliases")
	}

	for _, path := range []string{"/api/v1/health", "/status"} {
		code, _, body := getHealth(t, h, path)
		if code != http.StatusOK {
			t.Fatalf("%s: got %d (body: %s)", path, code, body)
		}
		for _, s := range secrets {
			if strings.Contains(body, s) {
				t.Fatalf("%s: raw body leaks a user-identifying datum (%.24s…)", path, s)
			}
		}
	}
}

// TestStatusPage verifies the operator status view: HTML from the same cached
// snapshot, no JavaScript, and the aggregate numbers visible.
func TestStatusPage(t *testing.T) {
	h, _ := newTestHandler(t)

	code, header, body := getHealth(t, h, "/status")
	if code != http.StatusOK {
		t.Fatalf("got %d (body: %s)", code, body)
	}
	if ct := header.Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Fatalf("Content-Type: got %q, want text/html; charset=utf-8", ct)
	}
	for _, want := range []string{
		"Node status",             // the page's own heading
		testBuild,                 // identity, same source as the JSON document
		"5000",                    // envelope capacity
		"Content-Security-Policy", // same closed CSP shape as the portal
	} {
		if !strings.Contains(body, want) {
			t.Errorf("status page must contain %q", want)
		}
	}
	if strings.Contains(body, "<script") {
		t.Errorf("status page must require no JavaScript")
	}

	// The JSON twin and the page must agree (same snapshot, one source).
	_, _, jsonBody := getHealth(t, h, "/api/v1/health")
	hr := decodeHealthBody(t, jsonBody)
	for _, want := range []string{hr.Build, fmt.Sprint(hr.EnvelopeCapacity), fmt.Sprint(hr.SchemaVersion)} {
		if !strings.Contains(body, want) {
			t.Errorf("status page must show %q like the JSON document", want)
		}
	}
}

// TestHealthMatchesCapabilities pins the §10.7 schema-sharing decision: the
// four identity members are identical in both documents because they come
// from the same sources in code.
func TestHealthMatchesCapabilities(t *testing.T) {
	h, _ := newTestHandler(t)

	_, _, healthBody := getHealth(t, h, "/api/v1/health")
	rec := do(t, h, http.MethodGet, "/api/v1/capabilities", CanonicalHost, nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("capabilities: got %d", rec.Code)
	}
	var caps map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &caps); err != nil {
		t.Fatalf("decode capabilities: %v", err)
	}
	hr := decodeHealthBody(t, healthBody)

	if hr.API != caps["api"] {
		t.Fatalf("api member diverges: health %v vs capabilities %v", hr.API, caps["api"])
	}
	if hr.Build != caps["build"] {
		t.Fatalf("build member diverges: health %q vs capabilities %q", hr.Build, caps["build"])
	}
	if hr.SchemaVersion != int(caps["schema_version"].(float64)) {
		t.Fatalf("schema_version diverges: health %d vs capabilities %v", hr.SchemaVersion, caps["schema_version"])
	}
	if len(hr.EnvelopeVersions) != len(caps["envelope_versions"].([]any)) {
		t.Fatalf("envelope_versions diverge: health %v vs capabilities %v", hr.EnvelopeVersions, caps["envelope_versions"])
	}
	for i, v := range caps["envelope_versions"].([]any) {
		if hr.EnvelopeVersions[i] != int64(v.(float64)) {
			t.Fatalf("envelope_versions[%d] diverges: %d vs %v", i, hr.EnvelopeVersions[i], v)
		}
	}
}

// TestHealthStorageUnavailableSheds507 verifies the diagnostics surface never
// fabricates numbers: when the store cannot be read (dead SD card simulated
// by brokenStore) both endpoints shed with 507 storage_unavailable instead of
// answering zeros.
func TestHealthStorageUnavailableSheds507(t *testing.T) {
	h, err := New(&brokenStore{err: errors.New("storage: stat: input/output error")}, testBuild, testWebFS)
	if err != nil {
		t.Fatalf("build handler: %v", err)
	}
	for _, path := range []string{"/api/v1/health", "/status"} {
		rec := doFrom(t, h, honestMule, http.MethodGet, path, nil, "")
		if rec.Code != http.StatusInsufficientStorage {
			t.Fatalf("%s: got %d, want 507 (body: %s)", path, rec.Code, rec.Body.String())
		}
		if code := errBodyOf(t, rec); code != "storage_unavailable" {
			t.Fatalf("%s: 507 must carry storage_unavailable, got %q", path, code)
		}
	}
}

// TestStatusRenderers pins the operator-page formatting helpers.
func TestStatusRenderers(t *testing.T) {
	cases := []struct {
		seconds int64
		want    string
	}{
		{0, "00:00:00"},
		{59, "00:00:59"},
		{3600, "01:00:00"},
		{90061, "1d 01:01:01"},
		{172800, "2d 00:00:00"},
	}
	for _, tc := range cases {
		if got := formatUptime(tc.seconds); got != tc.want {
			t.Errorf("formatUptime(%d) = %q, want %q", tc.seconds, got, tc.want)
		}
	}

	byteCases := []struct {
		n    int64
		want string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1536, "1.5 KiB"},
		{2048, "2 KiB"},
		{3 << 20, "3 MiB"},
		{5 * 1024 * 1024 * 1024, "5 GiB"},
	}
	for _, tc := range byteCases {
		if got := formatBytes(tc.n); got != tc.want {
			t.Errorf("formatBytes(%d) = %q, want %q", tc.n, got, tc.want)
		}
	}

	if got := joinInt64s([]int64{1, 2}); got != "1, 2" {
		t.Errorf("joinInt64s = %q, want \"1, 2\"", got)
	}
	if got := joinInt64s(nil); got != "" {
		t.Errorf("joinInt64s(nil) = %q, want \"\"", got)
	}
}

// compile-time interface checks: the health stat methods are part of the
// Store contract (issue #31) and both production stores must satisfy it.
var (
	_ Store = (*storage.Store)(nil)
	_ Store = (*brokenStore)(nil)
)
