package api

// security_headers_test.go — regression test for audit finding NODE-03
// (issue #14): the baseline X-Content-Type-Options / X-Frame-Options /
// Referrer-Policy headers must ride EVERY response — HTML, JSON, errors and
// both redirect flavors (the §10.2 301 and the §10.2 probe 302) — because
// the secureHeaders middleware sits outermost, before canonicalHost.

import (
	"net/http"
	"testing"
)

// TestSecurityHeadersOnEveryResponse verifies the NODE-03 fix: every answer
// of the daemon carries the three baseline security headers, whatever the
// status class (200 HTML, 200 JSON, 404, 405, the §10.2 301 and the
// captive-probe 302).
func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	h, _ := newTestHandler(t)

	cases := []struct {
		name   string
		method string
		target string
		host   string
		body   []byte
		ct     string
	}{
		{"portal HTML 200", http.MethodGet, "/", CanonicalHost, nil, ""},
		{"capabilities JSON 200", http.MethodGet, "/api/v1/capabilities", CanonicalHost, nil, ""},
		{"static asset 200", http.MethodGet, "/css/app.css", CanonicalHost, nil, ""},
		{"unknown path 404", http.MethodGet, "/nope", CanonicalHost, nil, ""},
		{"wrong method 405", http.MethodPost, "/api/v1/sync", CanonicalHost, nil, ""},
		{"canonical-host 301", http.MethodGet, "/", "10.42.0.1:8080", nil, ""},
		{"captive-probe 302", http.MethodGet, "/generate_204", "captive.apple.com", nil, ""},
		{"sync 400 error shape", http.MethodPost, "/api/v1/sync", CanonicalHost, []byte(`{}`), "application/json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := do(t, h, tc.method, tc.target, tc.host, tc.body, tc.ct)
			if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
				t.Fatalf("status %d: X-Content-Type-Options: got %q, want nosniff", rec.Code, got)
			}
			if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
				t.Fatalf("status %d: X-Frame-Options: got %q, want DENY", rec.Code, got)
			}
			if got := rec.Header().Get("Referrer-Policy"); got != "no-referrer" {
				t.Fatalf("status %d: Referrer-Policy: got %q, want no-referrer", rec.Code, got)
			}
		})
	}
}
