// Package api exposes the node's HTTP surface: the exact endpoint set of
// docs/protocol.md §10, the canonical-host middleware with its captive-probe
// exemption (§10.2), and the per-request limits of §8.1.
package api

import (
	"net/http"
	"strings"
)

// CanonicalHost is the one web origin shared by every node in the network
// (scheme + host + port). All nodes are indistinguishable in origin so a
// mule's IndexedDB storage never fragments between nodes (§12).
const CanonicalHost = "portal.red.local:8080"

// MaxBodyBytes is the POST body limit: 1 MiB (1,048,576 bytes); larger
// bodies are rejected with 413 (§8.1, §10.1).
const MaxBodyBytes = 1 << 20

// captiveProbePaths are the OS captive-portal detection endpoints. They are
// exempt from the canonical-host redirect: the OS probes arrive with spoofed
// Hosts (connectivitycheck.gstatic.com, captive.apple.com, ...) resolved by
// the node's wildcard DNS, and they MUST reach the 302 answer directly or the
// captive-portal detection fails (§10.2).
var captiveProbePaths = map[string]bool{
	"/generate_204":        true,
	"/hotspot-detect.html": true,
}

// canonicalHost redirects every request whose Host header is not exactly
// CanonicalHost (case-insensitive) to the same path and query on the
// canonical origin, so the browser always ends on the one true origin
// (§10.2). Captive-probe paths short-circuit before this redirect.
func canonicalHost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !captiveProbePaths[r.URL.Path] && !strings.EqualFold(r.Host, CanonicalHost) {
			target := "http://" + CanonicalHost + r.URL.RequestURI()
			http.Redirect(w, r, target, http.StatusMovedPermanently)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// limitBody caps every request body at MaxBodyBytes by wrapping it in an
// http.MaxBytesReader (§10.1). Handlers that read the body translate the
// resulting *http.MaxBytesError into a 413 response. Requests without a body
// (the GET endpoints) are unaffected.
func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
		}
		next.ServeHTTP(w, r)
	})
}
