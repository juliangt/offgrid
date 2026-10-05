package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"offgrid/dtn-node/internal/envelope"
	"offgrid/dtn-node/internal/storage"
)

// testIndexHTML is the portal page fixture: it carries the CSP that the UI
// contract depends on (no inline script/style; everything same-origin).
const testIndexHTML = `<!DOCTYPE html><html><head><title>DTN Node</title>` +
	`<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self'; style-src 'self'">` +
	`</head><body><script src="/js/app.js"></script></body></html>`

// testWebFS stands in for the go:embed'ed web root of the main package.
var testWebFS = fstest.MapFS{
	"web/index.html":     &fstest.MapFile{Data: []byte(testIndexHTML)},
	"web/css/app.css":    &fstest.MapFile{Data: []byte("body { color: rebeccapurple; }")},
	"web/js/app.js":      &fstest.MapFile{Data: []byte("var x = 1;")},
	"web/js/vendor/x.js": &fstest.MapFile{Data: []byte("var y = 2;")},
}

// testBuild is the build identifier threaded through New in every test here;
// the capabilities test asserts it surfaces verbatim in the §15.5 document.
const testBuild = "test-build-1.2.3"

// newTestHandler builds a handler backed by a real SQLite store in a temp dir.
func newTestHandler(t *testing.T) (http.Handler, *storage.Store) {
	t.Helper()
	s, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	h, err := New(s, testBuild, testWebFS)
	if err != nil {
		t.Fatalf("build handler: %v", err)
	}
	return h, s
}

// do runs a request against the handler with full control over the Host
// header, which the canonical-host middleware depends on.
func do(t *testing.T, h http.Handler, method, target, host string, body []byte, contentType string) *httptest.ResponseRecorder {
	t.Helper()
	var rd *strings.Reader
	if body == nil {
		rd = strings.NewReader("")
	} else {
		rd = strings.NewReader(string(body))
	}
	req := httptest.NewRequest(method, target, rd)
	if host != "" {
		req.Host = host
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// hexID renders n as a deterministic 64-char lowercase hex id.
func hexID(n int) string {
	return fmt.Sprintf("%064x", n)
}

// keyB64 returns the Base64 of 32 deterministic key bytes (directory keys).
func keyB64(seed byte) string {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = seed + byte(i)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// validEnv builds an envelope that passes Validate at time now.
func validEnv(id string, createdAt int64) envelope.Envelope {
	raw := make([]byte, 248)
	for i := range raw {
		raw[i] = byte(id[len(id)-1]) ^ byte(i)
	}
	return envelope.Envelope{
		V:         1,
		ID:        id,
		DestHint:  "9f3ab02c1d77e4c1",
		CreatedAt: createdAt,
		TTL:       3600,
		Payload:   base64.StdEncoding.EncodeToString(raw),
	}
}

// postJSON posts v as JSON with the right Content-Type and returns the recorder.
func postJSON(t *testing.T, h http.Handler, target string, v any) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	return do(t, h, http.MethodPost, target, CanonicalHost, body, "application/json")
}

// TestCanonicalHostRedirect verifies §10.2: any non-canonical Host gets a 301
// to the canonical origin with the original path and query; the canonical host
// (case-insensitive) and a bare canonical host without port behave as
// specified.
func TestCanonicalHostRedirect(t *testing.T) {
	h, _ := newTestHandler(t)

	cases := []struct {
		name     string
		host     string
		target   string
		wantCode int
		wantLoc  string
	}{
		{"ip host redirects", "10.42.0.1:8080", "/", http.StatusMovedPermanently, "http://offgrid.local:8080/"},
		{"path and query preserved", "evil.example.com", "/foo?bar=1", http.StatusMovedPermanently, "http://offgrid.local:8080/foo?bar=1"},
		{"bare host without port redirects", "offgrid.local", "/", http.StatusMovedPermanently, "http://offgrid.local:8080/"},
		{"canonical host passes", "offgrid.local:8080", "/", http.StatusOK, ""},
		{"canonical host is case-insensitive", "OFFGRID.LOCAL:8080", "/", http.StatusOK, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := do(t, h, http.MethodGet, tc.target, tc.host, nil, "")
			if rec.Code != tc.wantCode {
				t.Fatalf("got %d, want %d (body: %s)", rec.Code, tc.wantCode, rec.Body.String())
			}
			if got := rec.Header().Get("Location"); got != tc.wantLoc {
				t.Fatalf("Location: got %q, want %q", got, tc.wantLoc)
			}
		})
	}
}

// TestCaptiveProbesExemptFromCanonicalRedirect verifies §10.2: the OS probe
// endpoints answer 302 to the canonical portal with ANY Host (spoofed
// wildcard-DNS hosts included), are never redirected to the canonical host
// first, and never answer 204.
func TestCaptiveProbesExemptFromCanonicalRedirect(t *testing.T) {
	h, _ := newTestHandler(t)

	for _, path := range []string{"/generate_204", "/hotspot-detect.html"} {
		for _, host := range []string{"connectivitycheck.gstatic.com", "captive.apple.com", CanonicalHost} {
			name := path + " with Host " + host
			t.Run(name, func(t *testing.T) {
				rec := do(t, h, http.MethodGet, path, host, nil, "")
				if rec.Code != http.StatusFound {
					t.Fatalf("got %d, want 302 (body: %s)", rec.Code, rec.Body.String())
				}
				if rec.Code == http.StatusNoContent {
					t.Fatalf("probe must never answer 204")
				}
				if got := rec.Header().Get("Location"); got != "http://"+CanonicalHost+"/" {
					t.Fatalf("Location: got %q, want canonical portal", got)
				}
			})
		}
	}
}

// TestIndexServed verifies GET / serves the embedded HTML with the §10.1
// content type, and that unknown paths are JSON 404 (no SPA fallback).
func TestIndexServed(t *testing.T) {
	h, _ := newTestHandler(t)

	rec := do(t, h, http.MethodGet, "/", CanonicalHost, nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Fatalf("Content-Type: got %q", ct)
	}
	if !strings.Contains(rec.Body.String(), "<title>DTN Node</title>") {
		t.Fatalf("index.html not served, body: %s", rec.Body.String())
	}

	rec = do(t, h, http.MethodGet, "/nope", CanonicalHost, nil, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown path: got %d, want 404", rec.Code)
	}
	var errBody map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &errBody); err != nil || errBody["status"] != "error" {
		t.Fatalf("404 must carry a JSON error body, got %q", rec.Body.String())
	}
}

// TestStaticAssets verifies the same-origin asset routes: exact-path serving
// with the §10.1 content types, revalidation on every load, JSON 404 for
// unknown assets (no SPA fallback) and JSON 405 + Allow for wrong methods.
func TestStaticAssets(t *testing.T) {
	h, _ := newTestHandler(t)

	cases := []struct {
		path     string
		wantBody string
		wantCT   string
	}{
		{"/css/app.css", "body { color: rebeccapurple; }", "text/css; charset=utf-8"},
		{"/js/app.js", "var x = 1;", "text/javascript; charset=utf-8"},
		{"/js/vendor/x.js", "var y = 2;", "text/javascript; charset=utf-8"},
	}
	for _, tc := range cases {
		t.Run("GET "+tc.path, func(t *testing.T) {
			rec := do(t, h, http.MethodGet, tc.path, CanonicalHost, nil, "")
			if rec.Code != http.StatusOK {
				t.Fatalf("got %d, want 200 (body: %s)", rec.Code, rec.Body.String())
			}
			if ct := rec.Header().Get("Content-Type"); ct != tc.wantCT {
				t.Fatalf("Content-Type: got %q, want %q", ct, tc.wantCT)
			}
			if rec.Header().Get("Cache-Control") != "no-cache" {
				t.Fatalf("assets must be revalidated on every load (Cache-Control: no-cache)")
			}
			if rec.Body.String() != tc.wantBody {
				t.Fatalf("body: got %q, want %q", rec.Body.String(), tc.wantBody)
			}
		})
	}

	// Unknown asset: JSON 404, exactly like any other unknown path (§10.1).
	rec := do(t, h, http.MethodGet, "/js/nope.js", CanonicalHost, nil, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown asset: got %d, want 404", rec.Code)
	}
	var errBody map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &errBody); err != nil || errBody["error"] != "not_found" {
		t.Fatalf("unknown asset must carry the JSON 404 body, got %q", rec.Body.String())
	}

	// Nothing outside css/ and js/ is ever exposed (only index.html is HTML).
	rec = do(t, h, http.MethodGet, "/index.html", CanonicalHost, nil, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("/index.html must not be served directly, got %d", rec.Code)
	}

	// Wrong method: JSON 405 with Allow: GET.
	for _, path := range []string{"/css/app.css", "/js/app.js"} {
		rec := do(t, h, http.MethodPost, path, CanonicalHost, nil, "application/json")
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("POST %s: got %d, want 405", path, rec.Code)
		}
		if got := rec.Header().Get("Allow"); got != "GET" {
			t.Fatalf("POST %s Allow: got %q, want GET", path, got)
		}
	}
}

// TestNewFailsClosed verifies that a broken embed (missing page or an
// unsupported file in the served trees) refuses to start the node instead of
// serving a half-shipped UI.
func TestNewFailsClosed(t *testing.T) {
	s, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	if _, err := New(s, testBuild, fstest.MapFS{}); err == nil {
		t.Fatalf("missing web/index.html must fail startup")
	}
	broken := fstest.MapFS{
		"web/index.html":  &fstest.MapFile{Data: []byte(testIndexHTML)},
		"web/css/app.css": &fstest.MapFile{Data: []byte("/* ok */")},
		"web/js/evil.exe": &fstest.MapFile{Data: []byte("MZ")},
	}
	if _, err := New(s, testBuild, broken); err == nil || !strings.Contains(err.Error(), "unsupported extension") {
		t.Fatalf("unsupported asset extension must fail startup, got: %v", err)
	}
}

// TestMethodNotAllowed verifies the §10.1 405 behavior with Allow headers.
func TestMethodNotAllowed(t *testing.T) {
	h, _ := newTestHandler(t)

	cases := []struct {
		method, target string
		wantAllow      string
	}{
		{http.MethodDelete, "/api/v1/directory", "GET, POST"},
		{http.MethodGet, "/api/v1/sync", "POST"},
		{http.MethodPut, "/api/v1/sync", "POST"},
		{http.MethodPost, "/", "GET"},
		{http.MethodPost, "/generate_204", "GET"},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.target, func(t *testing.T) {
			rec := do(t, h, tc.method, tc.target, CanonicalHost, nil, "")
			if rec.Code != http.StatusMethodNotAllowed {
				t.Fatalf("got %d, want 405 (body: %s)", rec.Code, rec.Body.String())
			}
			if got := rec.Header().Get("Allow"); got != tc.wantAllow {
				t.Fatalf("Allow: got %q, want %q", got, tc.wantAllow)
			}
		})
	}
}

// TestDirectoryPostAndGet covers the §10.3 directory endpoints: upsert
// validation and persistence, then the ordered GET.
func TestDirectoryPostAndGet(t *testing.T) {
	h, _ := newTestHandler(t)

	// §6.1 (issue #26): pin the node clock so the server-set epoch is exact.
	// 1791072000 sits mid-epoch 20730 (2026-10-04T04:26:40Z).
	restore := stubTimeNow(t, time.Unix(1791072000, 0))
	defer restore()

	// Valid upsert.
	rec := postJSON(t, h, "/api/v1/directory", map[string]string{
		"alias": "alice_77", "pubkey": keyB64(1), "x25519": keyB64(2),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("valid upsert: got %d (body: %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"status":"ok"`) {
		t.Fatalf("upsert must answer {\"status\":\"ok\"}, got %s", rec.Body.String())
	}

	// Second identity for ordering.
	rec = postJSON(t, h, "/api/v1/directory", map[string]string{
		"alias": "bob", "pubkey": keyB64(3), "x25519": keyB64(4),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("second upsert: got %d", rec.Code)
	}

	rec = do(t, h, http.MethodGet, "/api/v1/directory", CanonicalHost, nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET directory: got %d", rec.Code)
	}
	var entries []storage.DirectoryEntry
	if err := json.Unmarshal(rec.Body.Bytes(), &entries); err != nil {
		t.Fatalf("GET directory must return a JSON array: %v", err)
	}
	if len(entries) != 2 || entries[0].Pubkey != keyB64(1) || entries[0].Alias != "alice_77" {
		t.Fatalf("unexpected directory entries: %+v", entries)
	}
	if entries[0].LastSeen == 0 {
		t.Fatalf("last_seen must be set by the node")
	}
	// §6.1 (issue #26): every entry carries the server-set hint epoch —
	// floor(node now / 86400), set at upsert and additive in this response.
	if entries[0].LastSeen != 1791072000 {
		t.Fatalf("last_seen must come from the node clock, got %d", entries[0].LastSeen)
	}
	if entries[0].Epoch != 1791072000/storage.HintEpochSeconds {
		t.Fatalf("epoch must be floor(node now / HintEpochSeconds), got %d want %d",
			entries[0].Epoch, 1791072000/storage.HintEpochSeconds)
	}

	// Validation failures -> 400.
	badCases := []struct {
		name string
		body map[string]string
	}{
		{"bad alias", map[string]string{"alias": "bad alias!", "pubkey": keyB64(1), "x25519": keyB64(2)}},
		{"alias too long", map[string]string{"alias": strings.Repeat("a", 25), "pubkey": keyB64(1), "x25519": keyB64(2)}},
		{"missing alias", map[string]string{"pubkey": keyB64(1), "x25519": keyB64(2)}},
		{"pubkey 31 bytes", map[string]string{"alias": "ok", "pubkey": base64.StdEncoding.EncodeToString(make([]byte, 31)), "x25519": keyB64(2)}},
		{"pubkey not base64", map[string]string{"alias": "ok", "pubkey": "!!not-base64!!", "x25519": keyB64(2)}},
		{"x25519 33 bytes", map[string]string{"alias": "ok", "pubkey": keyB64(1), "x25519": base64.StdEncoding.EncodeToString(make([]byte, 33))}},
		{"missing x25519", map[string]string{"alias": "ok", "pubkey": keyB64(1)}},
	}
	for _, tc := range badCases {
		t.Run(tc.name, func(t *testing.T) {
			rec := postJSON(t, h, "/api/v1/directory", tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("got %d, want 400 (body: %s)", rec.Code, rec.Body.String())
			}
		})
	}

	// Missing/wrong Content-Type -> 400 (§10.1).
	rec = do(t, h, http.MethodPost, "/api/v1/directory", CanonicalHost,
		[]byte(`{"alias":"ok","pubkey":"x","x25519":"y"}`), "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing content type: got %d, want 400", rec.Code)
	}

	// Malformed JSON -> 400.
	rec = do(t, h, http.MethodPost, "/api/v1/directory", CanonicalHost,
		[]byte(`{"alias":`), "application/json")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed json: got %d, want 400", rec.Code)
	}

	// Upsert refresh: same pubkey updates alias and last_seen.
	rec = postJSON(t, h, "/api/v1/directory", map[string]string{
		"alias": "alice_prime", "pubkey": keyB64(1), "x25519": keyB64(2),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("refresh upsert: got %d", rec.Code)
	}
	rec = do(t, h, http.MethodGet, "/api/v1/directory", CanonicalHost, nil, "")
	var after []storage.DirectoryEntry
	_ = json.Unmarshal(rec.Body.Bytes(), &after)
	if len(after) != 2 {
		t.Fatalf("upsert must not duplicate entries, got %d", len(after))
	}
	if after[0].Alias != "alice_prime" {
		t.Fatalf("refreshed entry must surface the new alias first, got %+v", after[0])
	}
}

// TestSyncPushPullDedup exercises the full §10.4 cycle: pushed envelopes are
// stored, excluded when listed in known_ids, served when unknown, and
// duplicated pushes are ignored.
func TestSyncPushPullDedup(t *testing.T) {
	h, _ := newTestHandler(t)
	now := time.Now().Unix()

	e1 := validEnv(hexID(1), now)
	e2 := validEnv(hexID(2), now+10)

	// Push with own ids in known_ids -> stored but not pulled back (§10.4: a
	// client includes its own pushes in known_ids).
	rec := postJSON(t, h, "/api/v1/sync", map[string]any{
		"known_ids":      []string{e1.ID, e2.ID},
		"push_envelopes": []envelope.Envelope{e1, e2},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("push: got %d (body: %s)", rec.Code, rec.Body.String())
	}
	var resp struct {
		Status        string              `json:"status"`
		PullEnvelopes []envelope.Envelope `json:"pull_envelopes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Status != "ok" || len(resp.PullEnvelopes) != 0 {
		t.Fatalf("own pushes must not be pulled back, got %+v", resp)
	}

	// Empty known_ids -> both envelopes come back, newest first.
	rec = postJSON(t, h, "/api/v1/sync", map[string]any{})
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.PullEnvelopes) != 2 || resp.PullEnvelopes[0].ID != e2.ID || resp.PullEnvelopes[1].ID != e1.ID {
		t.Fatalf("pull must return both envelopes newest-first, got %+v", resp.PullEnvelopes)
	}
	// Every stored envelope is v=1 by push validation (§10.5); the pull
	// reconstruction must surface that version (§3.1), not a zero value.
	for _, p := range resp.PullEnvelopes {
		if p.V != 1 {
			t.Fatalf("pulled envelope must report v=1, got %+v", p)
		}
	}
	// The pulled payload must round-trip identically.
	if resp.PullEnvelopes[0].Payload != e2.Payload {
		t.Fatalf("payload must round-trip byte-for-byte")
	}

	// Re-pushing e1 is a no-op (INSERT OR IGNORE) and it is served once.
	rec = postJSON(t, h, "/api/v1/sync", map[string]any{
		"push_envelopes": []envelope.Envelope{e1},
	})
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	count := 0
	for _, e := range resp.PullEnvelopes {
		if e.ID == e1.ID {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("dedup must keep exactly one copy, found %d", count)
	}

	// known_ids exclusion after storage.
	rec = postJSON(t, h, "/api/v1/sync", map[string]any{
		"known_ids": []string{e2.ID},
	})
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.PullEnvelopes) != 1 || resp.PullEnvelopes[0].ID != e1.ID {
		t.Fatalf("known id e2 must be excluded, got %+v", resp.PullEnvelopes)
	}
}

// TestSyncDefaultsAndLimits verifies the §8.1 request limits: default limit
// 50, [1,200] range (outside -> 400), push cap 100, known_ids cap 500.
func TestSyncDefaultsAndLimits(t *testing.T) {
	h, store := newTestHandler(t)
	now := time.Now().Unix()

	// Seed 60 envelopes directly so the default-50 behavior is observable.
	seed := make([]envelope.Envelope, 0, 60)
	for i := 0; i < 60; i++ {
		seed = append(seed, validEnv(hexID(1000+i), now+int64(i)))
	}
	if _, err := store.InsertEnvelopes(seed); err != nil {
		t.Fatalf("seed: %v", err)
	}

	rec := postJSON(t, h, "/api/v1/sync", map[string]any{})
	var resp struct {
		PullEnvelopes []envelope.Envelope `json:"pull_envelopes"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.PullEnvelopes) != 50 {
		t.Fatalf("absent limit must default to 50, got %d", len(resp.PullEnvelopes))
	}

	rec = postJSON(t, h, "/api/v1/sync", map[string]any{"limit": 200})
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.PullEnvelopes) != 60 {
		t.Fatalf("limit 200 must return all 60, got %d", len(resp.PullEnvelopes))
	}

	for _, bad := range []int{0, -1, 201} {
		rec := postJSON(t, h, "/api/v1/sync", map[string]any{"limit": bad})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("limit %d must be rejected with 400, got %d", bad, rec.Code)
		}
	}

	// limit of 1 returns exactly one (the newest).
	rec = postJSON(t, h, "/api/v1/sync", map[string]any{"limit": 1})
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.PullEnvelopes) != 1 || resp.PullEnvelopes[0].ID != hexID(1059) {
		t.Fatalf("limit 1 must return the newest envelope, got %+v", resp.PullEnvelopes)
	}

	// Push cap: 101 envelopes -> 400, nothing stored.
	oversized := make([]envelope.Envelope, 0, 101)
	for i := 0; i < 101; i++ {
		oversized = append(oversized, validEnv(hexID(5000+i), now))
	}
	rec = postJSON(t, h, "/api/v1/sync", map[string]any{"push_envelopes": oversized})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("101 pushed envelopes must be rejected with 400, got %d", rec.Code)
	}
	// Fail closed: nothing beyond the 60 seeded envelopes may exist. Query the
	// store directly, excluding the seeds — a stored rejected envelope would
	// show up here.
	seedIDs := make([]string, 0, len(seed))
	for _, e := range seed {
		seedIDs = append(seedIDs, e.ID)
	}
	leftover, err := store.PullEnvelopes(seedIDs, 200, now)
	if err != nil {
		t.Fatalf("verify store: %v", err)
	}
	if len(leftover) != 0 {
		t.Fatalf("rejected push must store nothing, got %+v", leftover)
	}

	// known_ids cap: 501 entries -> 400.
	known := make([]string, 0, 501)
	for i := 0; i < 501; i++ {
		known = append(known, hexID(9000+i))
	}
	rec = postJSON(t, h, "/api/v1/sync", map[string]any{"known_ids": known})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("501 known_ids must be rejected with 400, got %d", rec.Code)
	}

	// known_ids entries must be 64-char lowercase hex.
	rec = postJSON(t, h, "/api/v1/sync", map[string]any{"known_ids": []string{"NOT-HEX"}})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed known_id must be rejected with 400, got %d", rec.Code)
	}
}

// TestSyncNodeFullReturns429 verifies the per-node envelope cap of §8.1
// (anti-abuse hardening, plan §7): a store filled to the 5000-envelope cap
// rejects further pushes with 429 and the node_full error code, while pulls
// keep serving.
func TestSyncNodeFullReturns429(t *testing.T) {
	h, store := newTestHandler(t)
	now := time.Now().Unix()

	fill := make([]envelope.Envelope, 0, 5000)
	for i := 0; i < 5000; i++ {
		fill = append(fill, validEnv(hexID(i), now))
	}
	if inserted, err := store.InsertEnvelopes(fill); err != nil || inserted != 5000 {
		t.Fatalf("fill store to cap: got %d inserted, err=%v", inserted, err)
	}

	// One more envelope over the API: 429 with the node_full code.
	rec := postJSON(t, h, "/api/v1/sync", map[string]any{
		"push_envelopes": []envelope.Envelope{validEnv(hexID(99999), now)},
	})
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("push at node capacity: got %d, want 429 (body: %s)", rec.Code, rec.Body.String())
	}
	var errBody map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &errBody); err != nil || errBody["error"] != "node_full" {
		t.Fatalf("429 must carry the node_full code, got %s", rec.Body.String())
	}

	// The rejected envelope must not have been stored (fail closed).
	ids := make([]string, 0, 5000)
	for _, e := range fill {
		ids = append(ids, e.ID)
	}
	leftover, err := store.PullEnvelopes(ids, 200, now)
	if err != nil || len(leftover) != 0 {
		t.Fatalf("rejected push must store nothing, got %+v err=%v", leftover, err)
	}

	// Pulls keep working on the full node.
	rec = postJSON(t, h, "/api/v1/sync", map[string]any{})
	var resp struct {
		Status        string              `json:"status"`
		PullEnvelopes []envelope.Envelope `json:"pull_envelopes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if rec.Code != http.StatusOK || resp.Status != "ok" || len(resp.PullEnvelopes) != 50 {
		t.Fatalf("pull on a full node must still work, got %d / %+v", rec.Code, resp)
	}
}

// TestSyncInvalidEnvelopes verifies the §10.5 push-path validation: any
// invalid envelope rejects the whole request (fail closed) and stores nothing.
func TestSyncInvalidEnvelopes(t *testing.T) {
	h, _ := newTestHandler(t)
	now := time.Now().Unix()

	bad := []struct {
		name string
		mut  func(*envelope.Envelope)
	}{
		{"v=3 rejected", func(e *envelope.Envelope) { e.V = 3 }},
		{"v1 carrying meta", func(e *envelope.Envelope) { e.Meta = json.RawMessage(`{}`) }},
		{"v2 with meta.orig_v 2", func(e *envelope.Envelope) { e.V = 2; e.Meta = json.RawMessage(`{"orig_v":2}`) }},
		{"v2 with meta as string", func(e *envelope.Envelope) { e.V = 2; e.Meta = json.RawMessage(`"x"`) }},
		{"uppercase hex id", func(e *envelope.Envelope) { e.ID = strings.ToUpper(e.ID) }},
		{"short dest_hint", func(e *envelope.Envelope) { e.DestHint = "abc" }},
		{"future created_at", func(e *envelope.Envelope) { e.CreatedAt = now + 301 }},
		{"ttl below range", func(e *envelope.Envelope) { e.TTL = 3599 }},
		{"ttl above range", func(e *envelope.Envelope) { e.TTL = 2592001 }},
		{"payload not base64", func(e *envelope.Envelope) { e.Payload = "!!!" }},
		{"payload too short", func(e *envelope.Envelope) { e.Payload = base64.StdEncoding.EncodeToString(make([]byte, 247)) }},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			e := validEnv(hexID(77), now)
			tc.mut(&e)
			rec := postJSON(t, h, "/api/v1/sync", map[string]any{"push_envelopes": []envelope.Envelope{e}})
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("got %d, want 400 (body: %s)", rec.Code, rec.Body.String())
			}
			// Fail closed: nothing stored.
			rec = postJSON(t, h, "/api/v1/sync", map[string]any{})
			var resp struct {
				PullEnvelopes []envelope.Envelope `json:"pull_envelopes"`
			}
			_ = json.Unmarshal(rec.Body.Bytes(), &resp)
			if len(resp.PullEnvelopes) != 0 {
				t.Fatalf("invalid envelope must not be stored, got %+v", resp.PullEnvelopes)
			}
		})
	}

	// A float limit is not a JSON integer -> rejected (§3.3 numbers rule).
	rec := do(t, h, http.MethodPost, "/api/v1/sync", CanonicalHost,
		[]byte(`{"limit": 1.5}`), "application/json")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("float limit: got %d, want 400", rec.Code)
	}
}

// TestSyncBodyTooLarge verifies the §8.1 1 MiB body cap surfaces as 413.
func TestSyncBodyTooLarge(t *testing.T) {
	h, _ := newTestHandler(t)

	// A syntactically valid request whose body exceeds 1 MiB: ~20000 hex ids
	// is ~1.3 MB of JSON.
	known := make([]string, 0, 20000)
	for i := 0; i < 20000; i++ {
		known = append(known, hexID(i))
	}
	body, _ := json.Marshal(map[string]any{"known_ids": known})
	if len(body) <= MaxBodyBytes {
		t.Fatalf("fixture must exceed the body cap, is %d bytes", len(body))
	}

	rec := do(t, h, http.MethodPost, "/api/v1/sync", CanonicalHost, body, "application/json")
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("got %d, want 413 (body: %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "body_too_large") {
		t.Fatalf("413 must carry the body_too_large code, got %s", rec.Body.String())
	}
}

// TestSyncLimitTypeNoise verifies a string limit is rejected.
func TestSyncLimitTypeNoise(t *testing.T) {
	h, _ := newTestHandler(t)
	rec := do(t, h, http.MethodPost, "/api/v1/sync", CanonicalHost,
		[]byte(`{"limit": "50"}`), "application/json")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("string limit: got %d, want 400", rec.Code)
	}
}

// v2Form returns the §15.1 v1→v2 conversion of e — set v = 2, set
// meta.orig_v = 1, leave every other member (id included) untouched.
func v2Form(e envelope.Envelope) envelope.Envelope {
	e.V = 2
	e.Meta = json.RawMessage(`{"orig_v":1}`)
	return e
}

// TestCapabilitiesEndpoint verifies the §15.5 version-advertisement document:
// exactly the six §15.5 members plus the two additive §6.1 members (issue
// #26: hint_epoch_seconds, hint_epoch_current), envelope_versions ascending
// [1, 2], the derived invariants (min = first, max = last), schema_version
// wired to storage.SchemaVersion, a non-empty build identifier, JSON 405 for
// wrong methods, and the same middleware as every other API route (§10.2:
// the canonical-host redirect applies here too).
func TestCapabilitiesEndpoint(t *testing.T) {
	h, _ := newTestHandler(t)

	rec := do(t, h, http.MethodGet, "/api/v1/capabilities", CanonicalHost, nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Fatalf("Content-Type: got %q, want application/json; charset=utf-8", ct)
	}

	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode capabilities document: %v", err)
	}

	// §15.5 + §6.1 (issue #26): the member set is exactly these eight —
	// the six §15.5 members plus the additive hint-epoch pair.
	wantMembers := []string{
		"api", "envelope_versions", "min_envelope_version",
		"max_envelope_version", "schema_version", "build",
		"hint_epoch_seconds", "hint_epoch_current",
	}
	if len(doc) != len(wantMembers) {
		t.Fatalf("capabilities must carry exactly the eight §15.5+§6.1 members, got %d: %v", len(doc), doc)
	}
	for _, m := range wantMembers {
		if _, ok := doc[m]; !ok {
			t.Errorf("capabilities document is missing member %q", m)
		}
	}

	if doc["api"] != "v1" {
		t.Fatalf("api member must be \"v1\", got %v", doc["api"])
	}

	versions, ok := doc["envelope_versions"].([]any)
	if !ok || len(versions) != 2 || versions[0] != float64(1) || versions[1] != float64(2) {
		t.Fatalf("envelope_versions must be [1, 2] ascending, got %v", doc["envelope_versions"])
	}
	minV, ok := doc["min_envelope_version"].(float64)
	if !ok {
		t.Fatalf("min_envelope_version must be an integer, got %T", doc["min_envelope_version"])
	}
	maxV, ok := doc["max_envelope_version"].(float64)
	if !ok {
		t.Fatalf("max_envelope_version must be an integer, got %T", doc["max_envelope_version"])
	}
	if minV != versions[0] || maxV != versions[len(versions)-1] {
		t.Fatalf("derived members must match envelope_versions (min = first, max = last, §15.5): got min=%v max=%v", minV, maxV)
	}

	schemaV, ok := doc["schema_version"].(float64)
	if !ok || schemaV != float64(storage.SchemaVersion) {
		t.Fatalf("schema_version must be storage.SchemaVersion (%d), got %v", storage.SchemaVersion, doc["schema_version"])
	}

	build, ok := doc["build"].(string)
	if !ok || build == "" {
		t.Fatalf("build must be a non-empty string (§15.5), got %v", doc["build"])
	}
	if build != testBuild {
		t.Fatalf("build must surface the identifier wired through New, got %q want %q", build, testBuild)
	}

	// §6.1 additive members: the epoch length is the binding constant, and
	// the current epoch derives from the node clock (injected for the pin).
	if doc["hint_epoch_seconds"] != float64(storage.HintEpochSeconds) {
		t.Fatalf("hint_epoch_seconds must be storage.HintEpochSeconds (%d), got %v", storage.HintEpochSeconds, doc["hint_epoch_seconds"])
	}
	fixedCaps := time.Unix(1791072000, 0) // 2026-10-04T04:26:40Z, mid-epoch 20730
	restore := stubTimeNow(t, fixedCaps)
	rec = do(t, h, http.MethodGet, "/api/v1/capabilities", CanonicalHost, nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("injected-clock capabilities: got %d", rec.Code)
	}
	var doc2 map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc2); err != nil {
		t.Fatalf("decode injected capabilities: %v", err)
	}
	if got := doc2["hint_epoch_current"]; got != float64(1791072000/storage.HintEpochSeconds) {
		t.Fatalf("hint_epoch_current must be floor(now / HintEpochSeconds) on the node clock, got %v", got)
	}
	restore()

	// Wrong methods: JSON 405 with Allow: GET, like every read-only route.
	for _, method := range []string{http.MethodPost, http.MethodDelete} {
		rec := do(t, h, method, "/api/v1/capabilities", CanonicalHost, nil, "")
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s capabilities: got %d, want 405 (body: %s)", method, rec.Code, rec.Body.String())
		}
		if got := rec.Header().Get("Allow"); got != "GET" {
			t.Fatalf("%s capabilities Allow: got %q, want GET", method, got)
		}
	}

	// Same middleware as the rest of the API (§15.5 via §10.2): a
	// non-canonical Host gets the canonical redirect, not an answer.
	rec = do(t, h, http.MethodGet, "/api/v1/capabilities", "10.42.0.1:8080", nil, "")
	if rec.Code != http.StatusMovedPermanently {
		t.Fatalf("non-canonical host: got %d, want 301", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "http://"+CanonicalHost+"/api/v1/capabilities" {
		t.Fatalf("non-canonical host Location: got %q", loc)
	}
}

// stubTimeNow pins the api package's directory/capabilities clock (§10.3,
// §6.1 — the node clock is the shared epoch reference) and returns the
// restore function. Tests must call restore (defer or explicit).
func stubTimeNow(t *testing.T, at time.Time) func() {
	t.Helper()
	previous := timeNow
	timeNow = func() time.Time { return at }
	return func() { timeNow = previous }
}

// TestSyncV2AdmissionDedupAndServing covers the node-side rows of the §15.7
// matrix: a v2 envelope is admitted by the supported set {1, 2} (§15.3);
// re-pushing its v1 original (same id) is absorbed — dedup is by id alone and
// version-agnostic (§15.1, matrix §15.7c); and the pull path serves the
// stored version (v: 2) with no meta member at all (§15.3).
func TestSyncV2AdmissionDedupAndServing(t *testing.T) {
	h, store := newTestHandler(t)
	now := time.Now().Unix()

	v1 := validEnv(hexID(11), now)
	v2 := v2Form(v1)

	// The converted form is admitted and stored as v2.
	rec := postJSON(t, h, "/api/v1/sync", map[string]any{"push_envelopes": []envelope.Envelope{v2}})
	if rec.Code != http.StatusOK {
		t.Fatalf("v2 push: got %d (body: %s)", rec.Code, rec.Body.String())
	}

	// Re-pushing the v1 original is absorbed: same id, INSERT OR IGNORE.
	rec = postJSON(t, h, "/api/v1/sync", map[string]any{"push_envelopes": []envelope.Envelope{v1}})
	if rec.Code != http.StatusOK {
		t.Fatalf("v1 re-push: got %d (body: %s)", rec.Code, rec.Body.String())
	}

	pulled, err := store.PullEnvelopes(nil, 200, now)
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	if len(pulled) != 1 || pulled[0].ID != v1.ID {
		t.Fatalf("v2 push + v1 re-push must leave exactly one stored envelope, got %+v", pulled)
	}
	if pulled[0].V != 2 {
		t.Fatalf("INSERT OR IGNORE keeps the first row: stored version must be 2, got %d", pulled[0].V)
	}
	if len(pulled[0].Meta) != 0 {
		t.Fatalf("stored envelope must not carry meta (§15.3), got %s", pulled[0].Meta)
	}

	// The pull path serves the stored version and NEVER a meta member
	// (§15.3): clients must not rely on meta surviving a node round-trip.
	rec = postJSON(t, h, "/api/v1/sync", map[string]any{})
	var raw struct {
		Status        string           `json:"status"`
		PullEnvelopes []map[string]any `json:"pull_envelopes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode sync response: %v", err)
	}
	if raw.Status != "ok" || len(raw.PullEnvelopes) != 1 {
		t.Fatalf("pull must serve the single stored envelope, got %+v", raw)
	}
	served := raw.PullEnvelopes[0]
	if served["v"] != float64(2) {
		t.Fatalf("served envelope must carry its stored v=2, got %v", served["v"])
	}
	if _, hasMeta := served["meta"]; hasMeta {
		t.Fatalf("served envelope must not carry a meta member (§15.3), got %v", served)
	}
	// Everything else survives the round-trip untouched (§15.1 invariants).
	if served["id"] != v1.ID || served["payload"] != v1.Payload || served["dest_hint"] != v1.DestHint {
		t.Fatalf("served core members must be byte-identical to the pushed ones, got %v", served)
	}
}

// TestSyncDedupAbsorbsV2AfterV1 is the mirror order of matrix §15.7c: v1
// first, then its v2 conversion with the same id — absorbed as well, and the
// stored (first) row keeps serving as v1.
func TestSyncDedupAbsorbsV2AfterV1(t *testing.T) {
	h, store := newTestHandler(t)
	now := time.Now().Unix()

	v1 := validEnv(hexID(12), now)
	v2 := v2Form(v1)

	rec := postJSON(t, h, "/api/v1/sync", map[string]any{"push_envelopes": []envelope.Envelope{v1}})
	if rec.Code != http.StatusOK {
		t.Fatalf("v1 push: got %d (body: %s)", rec.Code, rec.Body.String())
	}
	rec = postJSON(t, h, "/api/v1/sync", map[string]any{"push_envelopes": []envelope.Envelope{v2}})
	if rec.Code != http.StatusOK {
		t.Fatalf("v2 re-push: got %d (body: %s)", rec.Code, rec.Body.String())
	}

	pulled, err := store.PullEnvelopes(nil, 200, now)
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	if len(pulled) != 1 || pulled[0].ID != v1.ID {
		t.Fatalf("v1 push + v2 re-push must leave exactly one stored envelope, got %+v", pulled)
	}
	if pulled[0].V != 1 || len(pulled[0].Meta) != 0 {
		t.Fatalf("first stored row wins: must serve v=1 without meta, got %+v", pulled[0])
	}
}
