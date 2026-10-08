package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"mime"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"offgrid/dtn-node/internal/envelope"
	"offgrid/dtn-node/internal/health"
	"offgrid/dtn-node/internal/status"
	"offgrid/dtn-node/internal/storage"
)

// Sync limits of §8.1 (binding):
//   - sync limit param: default 50, must be within [1, 200] (outside → 400);
//   - push_envelopes: at most 100 per request (more → 400);
//   - known_ids: at most 500 entries (more → 400);
//   - body size: capped by the limitBody middleware (1 MiB → 413);
//   - per-node envelope cap: storage.maxEnvelopes (5000) — at or over the
//     cap the whole push is rejected with 429 node_full (anti-abuse guard,
//     plan §7 risk "Llenado del nodo por abuso").
const (
	defaultSyncLimit  = 50
	maxSyncLimit      = 200
	maxPushEnvelopes  = 100
	maxKnownIDs       = 500
	directoryMaxLimit = 500
)

// Store is the persistence surface the API needs. It is satisfied by
// *storage.Store and kept as an interface so handlers never touch SQL. The
// stat methods feed the health snapshot (issues #31 and #36): they are
// pure COUNT/size/pragma queries that never inspect or return row content.
type Store interface {
	InsertEnvelopes(envs []envelope.Envelope) (int, error)
	PullEnvelopes(knownIDs []string, limit int, now int64) ([]envelope.Envelope, error)
	UpsertDirectory(pubkey, x25519, alias string, lastSeen int64, epoch int64, prekeys []byte) error
	GetDirectory(limit int) ([]storage.DirectoryEntry, error)
	EnvelopeCount() (int64, error)
	DirectoryCount() (int64, error)
	DBSizeBytes() (int64, error)
	ExpiringCounts(now int64) (storage.ExpCounts, error)
	SchemaVersionOnDisk() (int, error)
}

// timeNow is the clock the directory upsert path (§10.3 last_seen) and the
// §6.1 epoch stamping + capabilities advertisement read. Var purely as a
// test hook (the §6.1 epoch is floor(now / storage.HintEpochSeconds), which
// only an injected clock can pin exactly around a real midnight);
// production code must never reassign it.
var timeNow = time.Now

// server carries the handler dependencies. postBudget and pushQuota are the
// per-client admission-control limiters of ratelimit.go (issue #16 Phase 2):
// a POST request budget shared by the two write endpoints and a per-IP
// pushed-envelope budget, both RAM-only and keyed by source IP. healthBudget
// is the diagnostics budget of health.go (issue #31). counters is the shared
// RAM-only aggregate set the health document serves (internal/health);
// healthMu/healthCache/healthCachedAt implement the 1-second snapshot cache.
// status is the optional field-status sampler engine of issue #36 (nil on
// servers built without WithStatusEngine — every status member then renders
// N/A); when wired, the budget wrappers also feed it client activity for
// the aggregate-only active-clients count (internal/status/activity.go).
type server struct {
	store      Store
	build      string
	indexHTML  []byte
	guideHTML  []byte
	assets     map[string]staticAsset
	postBudget *rateLimiter
	pushQuota  *rateLimiter

	counters       *health.Counters
	healthBudget   *rateLimiter
	started        time.Time
	healthMu       sync.Mutex
	healthCache    *healthResponse
	healthCachedAt time.Time

	status *status.Engine

	// nodePlane is the optional P3.6 node-plane status source (nil on
	// servers built without WithNodePlane — the node_plane member then
	// renders null, the §10.7 N/A convention).
	nodePlane NodePlaneSource
}

// Option customizes a server built by New/NewWithCounters.
type Option func(*server)

// WithStatusEngine attaches the field-status sampler engine of issue #36:
// the RAM-only background sampler whose Snapshot() the diagnostics surface
// renders, and the aggregate-only active-client tracker the budget wrappers
// feed. Passing nil (or not passing this option) leaves every new member at
// null — the documented §10.7 N/A convention.
func WithStatusEngine(e *status.Engine) Option {
	return func(s *server) { s.status = e }
}

// noteClientActivity feeds the active-clients aggregate (issue #36). It is
// called only from the budget wrappers, at the exact points where
// clientKey(r) is already computed for admission control — so no identity
// is retained beyond what rate limiting already keeps. The key never
// leaves the tracker (internal/status/activity.go); only the count is
// ever served.
func (s *server) noteClientActivity(key string) {
	if s.status != nil {
		s.status.NoteClientActivity(key)
	}
}

// staticAsset is one embedded same-origin web file (stylesheet, script,
// §12.1 manifest or PNG icon) held in memory, ready to serve.
type staticAsset struct {
	body        []byte
	contentType string
}

// staticContentTypes lists the only file extensions the portal ever serves,
// with their exact §10.1 content types. Anything else found in the embedded
// css/, js/ or icons/ trees fails startup (fail closed: a half-shipped UI
// must not serve stale assets).
var staticContentTypes = map[string]string{
	".css": "text/css; charset=utf-8",
	".js":  "text/javascript; charset=utf-8",
	".png": "image/png",
}

// manifestContentType is the §12.1 web app manifest's media type. Chrome
// matches the bare media type (parameters are fine), and the W3C manifest
// spec prescribes application/manifest+json — preferred here over plain
// application/json so the document is unambiguous to every conforming UA.
const manifestContentType = "application/manifest+json; charset=utf-8"

// New wires the exact endpoint surface of §10.3 (plus the §15.5 capabilities
// document and the §10.7 diagnostics surface) into a single handler:
//
//	GET  /                      embedded index.html (text/html; charset=utf-8)
//	GET  /guide                 embedded end-user quick-start guide (issue #23)
//	GET  /css/…, GET /js/…      embedded same-origin static assets
//	GET  /img/…                 embedded guide screenshots (issue #23, PNG)
//	GET  /manifest.json         embedded web app manifest (§12.1)
//	GET  /icons/…               embedded PNG icons (§12.1)
//	GET  /generate_204          302 → canonical portal (Android probe; never 204)
//	GET  /hotspot-detect.html   302 → canonical portal (iOS probe)
//	GET  /api/v1/directory      JSON array of directory entries
//	POST /api/v1/directory      directory upsert
//	POST /api/v1/sync           envelope push + pull
//	GET  /api/v1/capabilities   version-advertisement document (§15.5)
//	GET  /api/v1/health         aggregate health snapshot (§10.7, budgeted)
//	GET  /status                operator status view, not linked from the
//	                            portal (§10.7, budgeted)
//
// build is the node build identifier advertised by the capabilities document
// (§15.5) and the health snapshot (§10.7); the main package threads its
// ldflags-stamped value through. An empty build falls back to "dev" so the
// §15.5 non-empty invariant holds even for a mis-stamped binary. webAssets is
// the embedded web root supplied by the main package (go:embed cannot cross
// package directories); its index.html, guide.html (issue #23), manifest.json
// and every .css/.js file under css/ and js/ plus every .png under icons/
// and img/ are read once at
// startup. Unknown paths yield a JSON 404 and wrong
// methods a JSON 405 with an Allow header (§10.1). The whole mux is wrapped
// with the baseline security headers, the canonical-host redirect and the
// body-size limiter; the two POST
// endpoints additionally sit behind the per-IP admission-control budgets of
// ratelimit.go (issue #16 Phase 2): exhaustion answers 429 rate_limited with
// a Retry-After header before the body is read. GET endpoints stay unlimited
// EXCEPT the diagnostics surface (§10.7), which carries its own small per-IP
// budget — the health snapshot must not become the DoS surface it reports on;
// the outer firewall rate limits remain the abuse brake for the other reads.
func New(store Store, build string, webAssets fs.FS) (http.Handler, error) {
	// Fresh RAM-only counters: binaries that do not need to share them with
	// the cleanup janitor (tests, and main uses NewWithCounters instead).
	return NewWithCounters(store, health.NewCounters(), build, webAssets)
}

// NewWithCounters is New with an explicit shared counter set: the daemon's
// main passes the same *health.Counters to the cleanup-recording janitor and
// to the API server, so TTL sweeps recorded by the janitor are exactly the
// ones the health document reports (issue #31). A nil counters is replaced by
// a fresh set. Options customize the server (WithStatusEngine, issue #36).
func NewWithCounters(store Store, counters *health.Counters, build string, webAssets fs.FS, opts ...Option) (http.Handler, error) {
	if build == "" {
		build = "dev"
	}
	if counters == nil {
		counters = health.NewCounters()
	}
	webRoot, err := fs.Sub(webAssets, "web")
	if err != nil {
		return nil, fmt.Errorf("locate web root in embedded assets: %w", err)
	}
	indexHTML, err := fs.ReadFile(webRoot, "index.html")
	if err != nil {
		return nil, fmt.Errorf("embedded web/index.html is missing: %w", err)
	}
	// The /guide page (issue #23) is embedded the same way as index.html and
	// must fail startup when missing — a half-shipped node must not serve a
	// portal whose only visible link (the "Guide" footer) is dead.
	guideHTML, err := fs.ReadFile(webRoot, "guide.html")
	if err != nil {
		return nil, fmt.Errorf("embedded web/guide.html is missing: %w", err)
	}
	assets, err := loadStaticAssets(webRoot)
	if err != nil {
		return nil, err
	}

	postBudget, pushQuota := newAdmissionControl()
	s := &server{
		store:        store,
		build:        build,
		indexHTML:    indexHTML,
		guideHTML:    guideHTML,
		assets:       assets,
		postBudget:   postBudget,
		pushQuota:    pushQuota,
		counters:     counters,
		healthBudget: newRateLimiter(healthRequestBurst, healthRequestRefillInterval),
		started:      time.Now(),
	}
	for _, opt := range opts {
		opt(s)
	}
	mux := http.NewServeMux()

	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("GET /guide", s.handleGuide)
	mux.HandleFunc("GET /css/", s.handleStatic)
	mux.HandleFunc("GET /js/", s.handleStatic)
	mux.HandleFunc("GET /img/", s.handleStatic)
	mux.HandleFunc("GET /manifest.json", s.handleStatic)
	mux.HandleFunc("GET /icons/", s.handleStatic)
	mux.HandleFunc("GET /generate_204", s.handleProbe)
	mux.HandleFunc("GET /hotspot-detect.html", s.handleProbe)
	mux.HandleFunc("GET /api/v1/directory", s.handleGetDirectory)
	// The two write endpoints sit behind the per-IP request budget (§ above);
	// the GET read path stays unlimited. The sync variant counts a shed at
	// this boundary as a rejected push (issue #31 counters).
	mux.HandleFunc("POST /api/v1/directory", s.withRequestBudget(s.handlePostDirectory))
	mux.HandleFunc("POST /api/v1/sync", s.withSyncRequestBudget(s.handleSync))
	mux.HandleFunc("GET /api/v1/capabilities", s.handleCapabilities)
	// Diagnostics surface (§10.7): snapshot + operator page behind one small
	// per-IP budget.
	mux.HandleFunc("GET /api/v1/health", s.withHealthBudget(s.handleHealth))
	mux.HandleFunc("GET /status", s.withHealthBudget(s.handleStatus))

	// Method-specific fallbacks: same paths, wrong method → JSON 405 + Allow.
	mux.HandleFunc("/{$}", methodNotAllowed("GET"))
	mux.HandleFunc("/guide", methodNotAllowed("GET"))
	mux.HandleFunc("/css/", methodNotAllowed("GET"))
	mux.HandleFunc("/js/", methodNotAllowed("GET"))
	mux.HandleFunc("/img/", methodNotAllowed("GET"))
	mux.HandleFunc("/manifest.json", methodNotAllowed("GET"))
	mux.HandleFunc("/icons/", methodNotAllowed("GET"))
	mux.HandleFunc("/generate_204", methodNotAllowed("GET"))
	mux.HandleFunc("/hotspot-detect.html", methodNotAllowed("GET"))
	mux.HandleFunc("/api/v1/directory", methodNotAllowed("GET, POST"))
	mux.HandleFunc("/api/v1/sync", methodNotAllowed("POST"))
	mux.HandleFunc("/api/v1/capabilities", methodNotAllowed("GET"))
	mux.HandleFunc("/api/v1/health", methodNotAllowed("GET"))
	mux.HandleFunc("/status", methodNotAllowed("GET"))
	// Everything else → JSON 404 (no SPA fallback; only GET / serves HTML).
	mux.HandleFunc("/", handleNotFound)

	// secureHeaders outermost: even the 301 canonical redirect and the 302
	// captive-probe answer carry the baseline security headers (issue #14,
	// NODE-03); then the canonical-host redirect, then the body cap.
	return secureHeaders(canonicalHost(limitBody(mux))), nil
}

// loadStaticAssets reads every .css/.js file under css/ and js/ plus every
// .png under icons/ and img/ of the embedded web root into memory, keyed by
// its exact URL path ("/js/ui.js", "/icons/icon-192.png",
// "/img/guide/composer.png"). The allow-list is derived from the embed
// itself: nothing outside those trees is ever served (no directory listing,
// no traversal — requests are matched by exact path after the mux's path
// cleaning). The img/ tree carries the guide screenshots (issue #23); the
// §12.1 web app manifest lives at the web root (outside every walked tree)
// and is read explicitly; a missing manifest or icons tree fails startup —
// a manifest the browser cannot resolve is a half-shipped UI.
func loadStaticAssets(webRoot fs.FS) (map[string]staticAsset, error) {
	assets := make(map[string]staticAsset)
	for _, dir := range []string{"css", "js", "icons", "img"} {
		err := fs.WalkDir(webRoot, dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			ct, ok := staticContentTypes[strings.ToLower(filepath.Ext(path))]
			if !ok {
				return fmt.Errorf("embedded web asset %s has an unsupported extension", path)
			}
			body, err := fs.ReadFile(webRoot, path)
			if err != nil {
				return fmt.Errorf("read embedded web asset %s: %w", path, err)
			}
			assets["/"+filepath.ToSlash(path)] = staticAsset{body: body, contentType: ct}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("scan embedded web/%s assets: %w", dir, err)
		}
	}
	manifest, err := fs.ReadFile(webRoot, "manifest.json")
	if err != nil {
		return nil, fmt.Errorf("embedded web/manifest.json is missing: %w", err)
	}
	assets["/manifest.json"] = staticAsset{body: manifest, contentType: manifestContentType}
	return assets, nil
}

// error short codes used in the {"status":"error","error":"<code>"} bodies
// of §10.1.
const (
	codeInvalidJSON        = "invalid_json"
	codeBodyTooLarge       = "body_too_large"
	codeContentType        = "content_type"
	codeInvalidEnvelope    = "invalid_envelope"
	codeTooManyPush        = "too_many_envelopes"
	codeTooManyKnownIDs    = "too_many_known_ids"
	codeInvalidKnownID     = "invalid_known_id"
	codeInvalidLimit       = "invalid_limit"
	codeInvalidAlias       = "invalid_alias"
	codeInvalidPubkey      = "invalid_pubkey"
	codeInvalidX25519      = "invalid_x25519"
	codeInvalidPrekeys     = "invalid_prekeys"
	codeNodeFull           = "node_full"
	codeRateLimited        = "rate_limited"
	codeStorageUnavailable = "storage_unavailable"
	codeNotFound           = "not_found"
	codeMethodNotAllowed   = "method_not_allowed"
	codeInternal           = "internal"
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

// handleIndex serves the embedded portal page (the §10.1 entry point).
func (s *server) handleIndex(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(s.indexHTML)
}

// handleGuide serves the embedded end-user quick-start guide (issue #23): a
// script-free HTML page (own stylesheet /css/guide.css, print layout for a
// one-sheet core flow) rendering the same text as docs/quick-start.md, with
// the real SPA screenshots under /img/guide/. It is PUBLIC and linked from
// the portal footer ("Guide") — the one portal-visible addition of the
// guide work; the operator view /status (§10.7) stays linked from nowhere.
// no-cache like the other embedded assets: a node is updated as a whole
// binary and captive clients must pick up the new guide immediately.
func (s *server) handleGuide(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(s.guideHTML)
}

// handleStatic serves one embedded same-origin asset (css/js/manifest/icons)
// by its exact URL path (§10.1: no SPA fallback, no directory listing).
// Responses are revalidated on every load (no-cache): a node is updated as a
// whole binary, and captive clients must pick up the new UI immediately.
func (s *server) handleStatic(w http.ResponseWriter, r *http.Request) {
	asset, ok := s.assets[r.URL.Path]
	if !ok {
		handleNotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", asset.contentType)
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(asset.body)
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
// 413. It writes the error response itself and returns the short code it
// answered plus false on failure (the sync handler classifies the failure
// into its rejection counters, issue #31; other callers ignore the code).
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) (string, bool) {
	ct := r.Header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil || mediaType != "application/json" {
		writeError(w, http.StatusBadRequest, codeContentType)
		return codeContentType, false
	}
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeError(w, http.StatusRequestEntityTooLarge, codeBodyTooLarge)
			return codeBodyTooLarge, false
		}
		writeError(w, http.StatusBadRequest, codeInvalidJSON)
		return codeInvalidJSON, false
	}
	return "", true
}

// decodeBase64Key validates a directory public key: standard-alphabet padded
// Base64 (§3.3) decoding to exactly 32 bytes (§10.3).
func decodeBase64Key(s string) ([]byte, error) {
	return decodeBase64OfLen(s, 32)
}

// decodeBase64OfLen validates standard-alphabet padded Base64 (§3.3)
// decoding to exactly want bytes — the shared check behind the directory
// keys (32 B, §10.3) and the §4.6 prekey bundle members (32 B keys, 64 B
// signature).
func decodeBase64OfLen(s string, want int) ([]byte, error) {
	if strings.ContainsAny(s, "\r\n") {
		return nil, errors.New("key contains newline characters")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(raw) != want {
		return nil, fmt.Errorf("key must decode to exactly %d bytes", want)
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

// directoryRequest is the POST /api/v1/directory body (§10.3). Prekeys is
// the OPTIONAL §4.6 bundle (issue #27, additive since 1.7.0): captured as a
// RawMessage so the exact published bytes are blind-validated and stored
// verbatim; an absent member or an explicit null stores NULL (which clears
// any previously stored bundle — the documented downgrade self-heal, §9).
type directoryRequest struct {
	Alias   string          `json:"alias"`
	Pubkey  string          `json:"pubkey"`
	X25519  string          `json:"x25519"`
	Prekeys json.RawMessage `json:"prekeys,omitempty"`
}

// §4.6 prekey-bundle admission bounds (blind shape only — the node NEVER
// verifies the bundle's Ed25519 signature, §1/§10.3; clients verify):
//   - the whole serialized member is at most maxPrekeysBytes (2048 bytes;
//     the §4.6 worst case is ≈ 938 B at the 16-OPK maximum, so the cap has
//     comfortable headroom while bounding the directory GET, §8.1 NOTE);
//   - v is exactly 1 (the §15-style bundle schema version; a future version
//     arrives with a new spec revision);
//   - spk decodes to 32 bytes, spk_sig to 64 bytes, every opks entry to
//     32 bytes (padded standard Base64, §3.3);
//   - ts is an integer > 0 (the SPK TTL anchor);
//   - opks holds between prekeyOPKMin (8) and prekeyOPKMax (16) entries.
//     Unknown members inside prekeys are ignored (§15.4 additive policy).
const (
	maxPrekeysBytes = 2048
	prekeyOPKMin    = 8
	prekeyOPKMax    = 16
)

// prekeyBundle is the blind shape of the §4.6 prekeys member (§10.3).
type prekeyBundle struct {
	V      int64    `json:"v"`
	SPK    string   `json:"spk"`
	SPKSig string   `json:"spk_sig"`
	TS     int64    `json:"ts"`
	OPKs   []string `json:"opks"`
}

// validatePrekeysBundle blind-validates the optional §4.6 prekeys member of
// a directory POST (§10.3): nil (absent) and explicit JSON null both store
// NULL; anything present must be the exact bundle shape above and within
// the size cap. Returns the bytes to store verbatim. The node does not
// parse the signature beyond its length and does not verify it (§1).
func validatePrekeysBundle(raw json.RawMessage) ([]byte, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return nil, nil
	}
	if len(raw) > maxPrekeysBytes {
		return nil, fmt.Errorf("prekeys bundle is %d bytes, over the %d-byte cap", len(raw), maxPrekeysBytes)
	}
	var b prekeyBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("prekeys must be a bundle object: %w", err)
	}
	if b.V != 1 {
		return nil, fmt.Errorf("prekeys.v must be 1, got %d", b.V)
	}
	if _, err := decodeBase64OfLen(b.SPK, 32); err != nil {
		return nil, fmt.Errorf("prekeys.spk: %w", err)
	}
	if _, err := decodeBase64OfLen(b.SPKSig, 64); err != nil {
		return nil, fmt.Errorf("prekeys.spk_sig: %w", err)
	}
	if b.TS <= 0 {
		return nil, fmt.Errorf("prekeys.ts must be > 0, got %d", b.TS)
	}
	if len(b.OPKs) < prekeyOPKMin || len(b.OPKs) > prekeyOPKMax {
		return nil, fmt.Errorf("prekeys.opks must hold %d..%d entries, got %d", prekeyOPKMin, prekeyOPKMax, len(b.OPKs))
	}
	for _, opk := range b.OPKs {
		if _, err := decodeBase64OfLen(opk, 32); err != nil {
			return nil, fmt.Errorf("prekeys.opks entry: %w", err)
		}
	}
	return raw, nil
}

// handlePostDirectory upserts a directory entry keyed by the Ed25519 public
// key with last_seen = now and epoch = floor(now / HintEpochSeconds) — both
// set from the NODE clock (§10.3, §6.1: the server, never the client, owns
// the time reference). Invalid alias or keys → 400; an invalid §4.6 prekeys
// member → 400 invalid_prekeys (blind shape validation only — the node
// never verifies the bundle signature, §1/§4.6). At the storage layer's
// directory cap (storage.MaxDirectoryEntries, issue #14 NODE-01) a NEW
// pubkey is shed with 429 node_full — the same capacity class the sync
// endpoint answers at envelope capacity, and a status this endpoint already
// answers under the §10.1 request budget — while a refresh of an entry
// already present always succeeds (issue #14: a full directory must never
// lock existing users out of republication). The POST body shape is
// otherwise unchanged since pre-1.6 builds (epoch is additive in the GET
// response only, §15.4; prekeys is additive since 1.7.0 and its absence
// clears any stored bundle, §9).
func (s *server) handlePostDirectory(w http.ResponseWriter, r *http.Request) {
	var req directoryRequest
	if _, ok := decodeJSON(w, r, &req); !ok {
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
	prekeys, err := validatePrekeysBundle(req.Prekeys)
	if err != nil {
		writeError(w, http.StatusBadRequest, codeInvalidPrekeys)
		return
	}
	now := timeNow().Unix()
	if err := s.store.UpsertDirectory(req.Pubkey, req.X25519, req.Alias, now, now/storage.HintEpochSeconds, prekeys); err != nil {
		if errors.Is(err, storage.ErrCapacity) {
			writeError(w, http.StatusTooManyRequests, codeNodeFull)
			return
		}
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
// single envelope is stored. Admission per envelope uses the §15.3 widened
// validation: v in the supported set {1, 2} plus the per-version meta rules,
// every other §10.5 check version-invariant.
//
// Issue #16 Phase 2 additions, in path order:
//   - the outer withSyncRequestBudget wrapper has already spent this client's
//     per-IP request token before the body was read;
//   - after the §8.1 shape checks but BEFORE per-envelope validation and any
//     storage work, the batch cost (its envelope count) is checked against
//     the client's per-IP envelope budget; an exhausted budget rejects the
//     whole batch with 429 rate_limited while other IPs keep full service.
//
// Issue #31 additions: every request outcome is classified once into the
// RAM-only push counters (internal/health) — accepted on a 200 that stored a
// batch, rejected under its error-code class otherwise. The counters carry no
// identity: they are aggregates only (§10.7, §13).
func (s *server) handleSync(w http.ResponseWriter, r *http.Request) {
	var req syncRequest
	if code, ok := decodeJSON(w, r, &req); !ok {
		// decodeJSON already wrote the error body; classify it only.
		s.recordSyncRejection(code)
		return
	}

	limit := defaultSyncLimit
	if req.Limit != nil {
		limit = *req.Limit
	}
	if limit < 1 || limit > maxSyncLimit {
		s.syncError(w, http.StatusBadRequest, codeInvalidLimit)
		return
	}
	if len(req.KnownIDs) > maxKnownIDs {
		s.syncError(w, http.StatusBadRequest, codeTooManyKnownIDs)
		return
	}
	for _, id := range req.KnownIDs {
		if !isHex64(id) {
			s.syncError(w, http.StatusBadRequest, codeInvalidKnownID)
			return
		}
	}
	if len(req.PushEnvelopes) > maxPushEnvelopes {
		s.syncError(w, http.StatusBadRequest, codeTooManyPush)
		return
	}
	// Per-IP envelope budget (issue #16 Phase 2; complements the global §8.1
	// cap so ONE station cannot fill the whole store). The full batch cost is
	// withdrawn atomically before any validation/insert work: a batch that
	// does not fit the remaining budget is refused whole — nothing is stored
	// and no token is half-spent (fail closed, same as invalid envelopes).
	// Pull-only syncs (no push_envelopes) cost nothing and mint no bucket.
	// Counters are RAM-only and die on restart — that is acceptable graceful
	// degradation, and the node never persists or attributes this per
	// envelope (docs/protocol.md §13: no user-identifying data on disk).
	if len(req.PushEnvelopes) > 0 {
		if ok, wait := s.pushQuota.allow(clientKey(r), float64(len(req.PushEnvelopes))); !ok {
			s.counters.RecordPushRejected(health.ClassRateLimited)
			writeRateLimited(w, wait)
			return
		}
	}
	now := time.Now().Unix()
	for _, e := range req.PushEnvelopes {
		if err := e.Validate(now); err != nil {
			s.syncError(w, http.StatusBadRequest, codeInvalidEnvelope)
			return
		}
	}

	inserted, err := s.store.InsertEnvelopes(req.PushEnvelopes)
	if err != nil {
		// The per-node envelope cap (§8.1, plan §7 anti-abuse risk): the node
		// is full, so pushes are shed with 429 instead of 500 — a capacity
		// condition is expected behavior, not an internal error. The policy
		// is deliberately "reject newest, keep oldest": nothing is ever
		// evicted to admit new mail (eviction belongs exclusively to the
		// §10.6 TTL janitor), so when the store is full the NEWEST writers —
		// the flood, almost by definition — are the ones refused, and the
		// oldest legitimate mail keeps being served until it expires.
		if errors.Is(err, storage.ErrCapacity) {
			s.syncError(w, http.StatusTooManyRequests, codeNodeFull)
			return
		}
		// Full disk / I/O failure under fire (issue #16 Phase 2): translate
		// unexpected storage errors into a clean 507 with the standard error
		// shape instead of 500-chaos. A solar-powered node with a saturated
		// SD card must answer legibly and stay up, not spew internal errors.
		s.syncError(w, http.StatusInsufficientStorage, codeStorageUnavailable)
		return
	}
	// The push landed: count absorbed duplicates (batch ids the store already
	// held — the §10.4 INSERT OR IGNORE dedup at work) and, since the batch
	// was non-empty by the budget guard above, one accepted push request.
	// Envelope-granular dedup, request-granular acceptance (§10.7).
	if absorbed := len(req.PushEnvelopes) - inserted; absorbed > 0 {
		s.counters.RecordDedupHits(absorbed)
	}
	if len(req.PushEnvelopes) > 0 {
		s.counters.RecordPushAccepted()
	}
	pulled, err := s.store.PullEnvelopes(req.KnownIDs, limit, now)
	if err != nil {
		// Reads fail the same clean way when the storage engine is unhappy
		// (e.g. WAL writes on a full disk surface even on selects). Counted
		// by final outcome: the request failed 507 (the pushed envelopes did
		// land, but the aggregate counters are request-level — §10.7).
		s.syncError(w, http.StatusInsufficientStorage, codeStorageUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, syncResponse{Status: "ok", PullEnvelopes: pulled})
}

// syncError classifies one rejected POST /api/v1/sync request into the
// RAM-only rejection counters (issue #31) and writes the §10.1 error body.
// The class derives from the short error code alone, so the counter can never
// disagree with what the client actually saw.
func (s *server) syncError(w http.ResponseWriter, status int, code string) {
	s.recordSyncRejection(code)
	writeError(w, status, code)
}

// recordSyncRejection is the record-only half of syncError, for the decodeJSON
// failure path (that helper writes its own response body).
func (s *server) recordSyncRejection(code string) {
	s.counters.RecordPushRejected(rejectionClass(code))
}

// rejectionClass maps a sync error short code to its counter class (§10.7):
// the two 429 shapes, the 413 body cap and the 507 shed have their own class;
// every 400 shape (bad envelope, bad limit, bad JSON, ...) is "invalid".
func rejectionClass(code string) health.RejectionClass {
	switch code {
	case codeRateLimited:
		return health.ClassRateLimited
	case codeNodeFull:
		return health.ClassNodeFull
	case codeStorageUnavailable:
		return health.ClassStorageUnavailable
	case codeBodyTooLarge:
		return health.ClassTooLarge
	default:
		return health.ClassInvalid
	}
}

// capabilitiesResponse is the version-advertisement document served by
// GET /api/v1/capabilities (§15.5). The member set on this build is exactly
// these eight: the six §15.5 identity/negotiation members plus the two
// §6.1 additive members (issue #26 — hint_epoch_seconds, hint_epoch_current)
// that let clients derive rotating dest_hints from NODE time. New members
// may only be added additively (§15.4) and MUST be ignored by clients. The
// three derived members stay consistent with envelope_versions (min = first,
// max = last, §15.5).
type capabilitiesResponse struct {
	API                string  `json:"api"`
	EnvelopeVersions   []int64 `json:"envelope_versions"`
	MinEnvelopeVersion int64   `json:"min_envelope_version"`
	MaxEnvelopeVersion int64   `json:"max_envelope_version"`
	SchemaVersion      int     `json:"schema_version"`
	Build              string  `json:"build"`
	HintEpochSeconds   int64   `json:"hint_epoch_seconds"`
	HintEpochCurrent   int64   `json:"hint_epoch_current"`
}

// handleCapabilities advertises the version facts clients negotiate on
// (§15.5): the API generation, the supported envelope-version set (§15.3),
// the storage schema version (wired to storage.SchemaVersion, never a
// hardcoded copy) and the build identifier — plus the §6.1 additive members
// (issue #26): the epoch length and the node's current hint epoch
// (floor(now / HintEpochSeconds), the same server clock that stamps
// directory entries). Read-only, behind the same middleware as every other
// API route (§10.2).
func (s *server) handleCapabilities(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, capabilitiesResponse{
		API:                "v1",
		EnvelopeVersions:   envelope.SupportedVersions,
		MinEnvelopeVersion: envelope.SupportedVersions[0],
		MaxEnvelopeVersion: envelope.MaxSupportedVersion,
		SchemaVersion:      storage.SchemaVersion,
		Build:              s.build,
		HintEpochSeconds:   storage.HintEpochSeconds,
		HintEpochCurrent:   timeNow().Unix() / storage.HintEpochSeconds,
	})
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
