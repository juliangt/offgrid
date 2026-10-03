package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"offgrid/dtn-node/internal/envelope"
	"offgrid/dtn-node/internal/storage"
)

// Sync limits of §8.1 (binding):
//   - sync limit param: default 50, must be within [1, 200] (outside → 400);
//   - push_envelopes: at most 100 per request (more → 400);
//   - known_ids: at most 500 entries (more → 400);
//   - body size: capped by the limitBody middleware (1 MiB → 413).
const (
	defaultSyncLimit  = 50
	maxSyncLimit      = 200
	maxPushEnvelopes  = 100
	maxKnownIDs       = 500
	directoryMaxLimit = 500
)

// Store is the persistence surface the API needs. It is satisfied by
// *storage.Store and kept as an interface so handlers never touch SQL.
type Store interface {
	InsertEnvelopes(envs []envelope.Envelope) (int, error)
	PullEnvelopes(knownIDs []string, limit int, now int64) ([]envelope.Envelope, error)
	UpsertDirectory(pubkey, x25519, alias string, lastSeen int64) error
	GetDirectory(limit int) ([]storage.DirectoryEntry, error)
}

// server carries the handler dependencies.
type server struct {
	store     Store
	indexHTML []byte
}

// New wires the exact endpoint surface of §10.3 into a single handler:
//
//	GET  /                      embedded index.html (text/html; charset=utf-8)
//	GET  /generate_204          302 → canonical portal (Android probe; never 204)
//	GET  /hotspot-detect.html   302 → canonical portal (iOS probe)
//	GET  /api/v1/directory      JSON array of directory entries
//	POST /api/v1/directory      directory upsert
//	POST /api/v1/sync           envelope push + pull
//
// indexHTML is the embedded web/index.html supplied by the main package
// (go:embed cannot cross package directories). Unknown paths yield a JSON 404
// and wrong methods a JSON 405 with an Allow header (§10.1). The whole mux is
// wrapped with the canonical-host redirect and the body-size limiter.
func New(store Store, indexHTML []byte) http.Handler {
	s := &server{store: store, indexHTML: indexHTML}
	mux := http.NewServeMux()

	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("GET /generate_204", s.handleProbe)
	mux.HandleFunc("GET /hotspot-detect.html", s.handleProbe)
	mux.HandleFunc("GET /api/v1/directory", s.handleGetDirectory)
	mux.HandleFunc("POST /api/v1/directory", s.handlePostDirectory)
	mux.HandleFunc("POST /api/v1/sync", s.handleSync)

	// Method-specific fallbacks: same paths, wrong method → JSON 405 + Allow.
	mux.HandleFunc("/{$}", methodNotAllowed("GET"))
	mux.HandleFunc("/generate_204", methodNotAllowed("GET"))
	mux.HandleFunc("/hotspot-detect.html", methodNotAllowed("GET"))
	mux.HandleFunc("/api/v1/directory", methodNotAllowed("GET, POST"))
	mux.HandleFunc("/api/v1/sync", methodNotAllowed("POST"))
	// Everything else → JSON 404 (no SPA fallback; only GET / serves HTML).
	mux.HandleFunc("/", handleNotFound)

	return canonicalHost(limitBody(mux))
}

// error short codes used in the {"status":"error","error":"<code>"} bodies
// of §10.1.
const (
	codeInvalidJSON      = "invalid_json"
	codeBodyTooLarge     = "body_too_large"
	codeContentType      = "content_type"
	codeInvalidEnvelope  = "invalid_envelope"
	codeTooManyPush      = "too_many_envelopes"
	codeTooManyKnownIDs  = "too_many_known_ids"
	codeInvalidKnownID   = "invalid_known_id"
	codeInvalidLimit     = "invalid_limit"
	codeInvalidAlias     = "invalid_alias"
	codeInvalidPubkey    = "invalid_pubkey"
	codeInvalidX25519    = "invalid_x25519"
	codeNotFound         = "not_found"
	codeMethodNotAllowed = "method_not_allowed"
	codeInternal         = "internal"
)

// writeJSON emits v with the API-wide JSON content type of §10.1.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

// writeError emits the error body shape of §10.1.
func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"status": "error", "error": code})
}

// handleNotFound answers unknown paths (§10.1: no SPA fallback).
func handleNotFound(w http.ResponseWriter, _ *http.Request) {
	writeError(w, http.StatusNotFound, codeNotFound)
}

// methodNotAllowed answers a known path hit with the wrong verb (§10.1).
func methodNotAllowed(allow string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Allow", allow)
		writeError(w, http.StatusMethodNotAllowed, codeMethodNotAllowed)
	}
}

// handleIndex serves the embedded single-file SPA (Sprint 2 replaces the
// placeholder content; the endpoint never changes).
func (s *server) handleIndex(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(s.indexHTML)
}

// handleProbe answers the OS captive-portal detection probes (§10.2). It must
// always answer 302 to the canonical portal URL regardless of the Host header,
// and must never answer 204: a 204 tells Android/iOS that there is no captive
// portal, which would strand the device.
func (s *server) handleProbe(w http.ResponseWriter, r *http.Request) {
	// The target is an absolute URL: it is served identically whatever Host
	// the probe arrived with.
	http.Redirect(w, r, "http://"+CanonicalHost+"/", http.StatusFound)
}

// decodeJSON parses the request body into dst, enforcing the §10.1
// conventions: Content-Type must be application/json (400 otherwise) and an
// oversized body surfaces the limitBody middleware's *http.MaxBytesError as
// 413. It writes the error response itself and returns false on failure.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	ct := r.Header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil || mediaType != "application/json" {
		writeError(w, http.StatusBadRequest, codeContentType)
		return false
	}
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeError(w, http.StatusRequestEntityTooLarge, codeBodyTooLarge)
			return false
		}
		writeError(w, http.StatusBadRequest, codeInvalidJSON)
		return false
	}
	return true
}

// decodeBase64Key validates a directory public key: standard-alphabet padded
// Base64 (§3.3) decoding to exactly 32 bytes (§10.3).
func decodeBase64Key(s string) ([]byte, error) {
	if strings.ContainsAny(s, "\r\n") {
		return nil, errors.New("key contains newline characters")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(raw) != 32 {
		return nil, errors.New("key must decode to exactly 32 bytes")
	}
	return raw, nil
}

// handleGetDirectory serves the public directory (§10.3): at most 500 entries,
// most recently seen first (last_seen DESC, pubkey ASC tie-break). The
// optional limit query parameter is clamped into [1, 500]; the default is 500.
func (s *server) handleGetDirectory(w http.ResponseWriter, r *http.Request) {
	limit := directoryMaxLimit
	if q := r.URL.Query().Get("limit"); q != "" {
		n, err := strconv.Atoi(q)
		if err != nil {
			writeError(w, http.StatusBadRequest, codeInvalidLimit)
			return
		}
		limit = n
	}
	if limit < 1 {
		limit = 1
	}
	if limit > directoryMaxLimit {
		limit = directoryMaxLimit
	}

	entries, err := s.store.GetDirectory(limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal)
		return
	}
	writeJSON(w, http.StatusOK, entries)
}

// directoryRequest is the POST /api/v1/directory body (§10.3).
type directoryRequest struct {
	Alias  string `json:"alias"`
	Pubkey string `json:"pubkey"`
	X25519 string `json:"x25519"`
}

// handlePostDirectory upserts a directory entry keyed by the Ed25519 public
// key with last_seen = now (§10.3). Invalid alias or keys → 400.
func (s *server) handlePostDirectory(w http.ResponseWriter, r *http.Request) {
	var req directoryRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !envelope.ValidAlias(req.Alias) {
		writeError(w, http.StatusBadRequest, codeInvalidAlias)
		return
	}
	if _, err := decodeBase64Key(req.Pubkey); err != nil {
		writeError(w, http.StatusBadRequest, codeInvalidPubkey)
		return
	}
	if _, err := decodeBase64Key(req.X25519); err != nil {
		writeError(w, http.StatusBadRequest, codeInvalidX25519)
		return
	}
	if err := s.store.UpsertDirectory(req.Pubkey, req.X25519, req.Alias, time.Now().Unix()); err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// syncRequest is the POST /api/v1/sync body (§10.4). Limit is a pointer so an
// absent field can default to 50 instead of 0.
type syncRequest struct {
	KnownIDs      []string            `json:"known_ids"`
	PushEnvelopes []envelope.Envelope `json:"push_envelopes"`
	Limit         *int                `json:"limit"`
}

// syncResponse is the POST /api/v1/sync reply (§10.4 step 4).
type syncResponse struct {
	Status        string              `json:"status"`
	PullEnvelopes []envelope.Envelope `json:"pull_envelopes"`
}

// handleSync implements the exact push+pull behavior of §10.4, failing closed:
// any request-level violation rejects the whole request with 400 before a
// single envelope is stored.
func (s *server) handleSync(w http.ResponseWriter, r *http.Request) {
	var req syncRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	limit := defaultSyncLimit
	if req.Limit != nil {
		limit = *req.Limit
	}
	if limit < 1 || limit > maxSyncLimit {
		writeError(w, http.StatusBadRequest, codeInvalidLimit)
		return
	}
	if len(req.KnownIDs) > maxKnownIDs {
		writeError(w, http.StatusBadRequest, codeTooManyKnownIDs)
		return
	}
	for _, id := range req.KnownIDs {
		if !isHex64(id) {
			writeError(w, http.StatusBadRequest, codeInvalidKnownID)
			return
		}
	}
	if len(req.PushEnvelopes) > maxPushEnvelopes {
		writeError(w, http.StatusBadRequest, codeTooManyPush)
		return
	}
	now := time.Now().Unix()
	for _, e := range req.PushEnvelopes {
		if err := e.Validate(now); err != nil {
			writeError(w, http.StatusBadRequest, codeInvalidEnvelope)
			return
		}
	}

	if _, err := s.store.InsertEnvelopes(req.PushEnvelopes); err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal)
		return
	}
	pulled, err := s.store.PullEnvelopes(req.KnownIDs, limit, now)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal)
		return
	}
	writeJSON(w, http.StatusOK, syncResponse{Status: "ok", PullEnvelopes: pulled})
}

// isHex64 reports whether s matches ^[0-9a-f]{64}$ (§10.4 known_ids entries).
func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
