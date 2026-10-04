// health.go — the diagnostics surface of issue #31: GET /api/v1/health (the
// machine-readable snapshot of docs/protocol.md §10.7) and GET /status (the
// human-readable operator view of the same data).
//
// Two properties are binding:
//
//   - Privacy (§13): the response is aggregate integers only — no envelope
//     id, no dest_hint, no alias, no key, no payload fragment, no source
//     address. The counters come from internal/health (RAM-only, never
//     persisted, never logged per request), the store figures come from
//     COUNT(*)-class queries that never inspect row content. This is reviewed
//     and asserted by TestHealthPrivacy.
//   - Boundedness: both endpoints answer from a snapshot cached in RAM for
//     healthCacheTTL, so a flood of GETs cannot turn the diagnostics surface
//     into the storage-DoS surface it reports on (at most one store refresh
//     per interval, whatever the request rate), and each client additionally
//     sits behind a small per-IP token budget (429 rate_limited + Retry-After
//     on exhaustion, same shape as the write paths). The document itself is a
//     fixed member set — no query parameters, no way to inflate the answer.
//
// Liveness alignment: "status":"ok" means exactly one thing — the daemon
// process that systemd's sd_notify watchdog keeps alive (Type=notify,
// raspberry/systemd/dtn-node.service) is up and answering on this socket.
// No further health judgment is invented: a node has no TLS and no uplink BY
// DESIGN, and the sdnotify implementation holds no queryable runtime state
// (it sends fire-and-forget datagrams), so no watchdog detail is fabricated
// into the response.

package api

import (
	"fmt"
	"html/template"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"offgrid/dtn-node/internal/envelope"
	"offgrid/dtn-node/internal/storage"
)

// healthCacheTTL bounds how often the snapshot is refreshed from SQLite. One
// second: fresh enough to be operationally truthful (and well inside the
// < 50 ms budget, since serving is a mutex check plus a marshaled copy),
// coarse enough that even a request flood costs the store nothing.
const healthCacheTTL = time.Second

// healthNow is the clock the snapshot cache reads. Package var purely as a
// test hook (the maxEnvelopes pattern of the storage package); production
// code must never reassign it.
var healthNow = time.Now

// healthResponse is the GET /api/v1/health document (§10.7). The member set
// is exactly these thirteen top-level members; new members may only be added
// additively (§15.4) and MUST be ignored by clients. The four identity
// members (api, build, envelope_versions, schema_version) are filled from the
// very same sources as the §15.5 capabilities document — they can never
// diverge between the two endpoints because there is one source in code.
type healthResponse struct {
	Status                      string             `json:"status"`
	API                         string             `json:"api"`
	Build                       string             `json:"build"`
	EnvelopeVersions            []int64            `json:"envelope_versions"`
	SchemaVersion               int                `json:"schema_version"`
	UptimeSeconds               int64              `json:"uptime_seconds"`
	Envelopes                   int64              `json:"envelopes"`
	EnvelopeCapacity            int                `json:"envelope_capacity"`
	DirectoryEntries            int64              `json:"directory_entries"`
	DBSizeBytes                 int64              `json:"db_size_bytes"`
	LastCleanupUnix             int64              `json:"last_cleanup_unix"`
	LastCleanupEnvelopesDeleted int64              `json:"last_cleanup_envelopes_deleted"`
	Counters                    healthCountersJSON `json:"counters"`
}

// healthCountersJSON is the "counters" member of the health document: the
// process-lifetime aggregates of internal/health. All RAM-only; every value
// resets to zero on restart by design (documented in §10.7).
type healthCountersJSON struct {
	PushesAccepted        int64                      `json:"pushes_accepted"`
	PushesRejected        int64                      `json:"pushes_rejected"`
	PushesRejectedByClass healthRejectionClassesJSON `json:"pushes_rejected_by_class"`
	DedupHits             int64                      `json:"dedup_hits"`
	TTLSweeps             int64                      `json:"ttl_sweeps"`
	TTLSweptEnvelopes     int64                      `json:"ttl_swept_envelopes"`
}

// healthRejectionClassesJSON breaks pushes_rejected down by the error code
// the sync endpoint answered (§10.1): invalid = any 400 shape, too_large =
// 413, rate_limited/node_full = the two 429 shapes, storage_unavailable = 507.
type healthRejectionClassesJSON struct {
	Invalid            int64 `json:"invalid"`
	RateLimited        int64 `json:"rate_limited"`
	NodeFull           int64 `json:"node_full"`
	StorageUnavailable int64 `json:"storage_unavailable"`
	TooLarge           int64 `json:"too_large"`
}

// statusTemplate is the operator status view (GET /status): server-rendered
// from the same cached snapshot as /api/v1/health, plain HTML, zero
// JavaScript (it must render on the cheap captive-portal browser of any
// phone a field operator carries). The look is the portal's own stylesheet;
// the CSP keeps the same closed shape as index.html (no inline anything).
// The page deliberately carries NO link to or from the portal: the portal
// index never mentions /status, so ordinary visitors are never shown
// operational detail (§10.7).
var statusTemplate = template.Must(template.New("status").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="referrer" content="no-referrer">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'self'">
  <title>Node status — offgrid</title>
  <link rel="stylesheet" href="/css/app.css">
</head>
<body>
<main>
  <h1>Node status</h1>
  <p class="hint">Operator view — not linked from the public portal. Machine-readable twin:
  <code>/api/v1/health</code>. Aggregates only: this page holds nothing about individual
  messages, senders, recipients or devices.</p>
  <div class="card">
    <h2>Node</h2>
    <dl>
      <dt>Status</dt><dd>{{.Snap.Status}}</dd>
      <dt>Build</dt><dd><code>{{.Snap.Build}}</code></dd>
      <dt>API</dt><dd>{{.Snap.API}} — envelope versions {{.VersionsText}}</dd>
      <dt>Storage schema version</dt><dd>{{.Snap.SchemaVersion}}</dd>
      <dt>Uptime</dt><dd>{{.UptimeText}} ({{.Snap.UptimeSeconds}} s)</dd>
    </dl>
  </div>
  <div class="card">
    <h2>Store</h2>
    <dl>
      <dt>Envelopes held</dt><dd>{{.Snap.Envelopes}} / capacity {{.Snap.EnvelopeCapacity}}</dd>
      <dt>Directory entries</dt><dd>{{.Snap.DirectoryEntries}}</dd>
      <dt>Database size on disk</dt><dd>{{.DBSizeText}} ({{.Snap.DBSizeBytes}} bytes)</dd>
      <dt>Last cleanup</dt><dd>{{if .Snap.LastCleanupUnix}}{{.Snap.LastCleanupUnix}} (deleted {{.Snap.LastCleanupEnvelopesDeleted}}){{else}}none recorded since start{{end}}</dd>
    </dl>
  </div>
  <div class="card">
    <h2>Counters (since process start)</h2>
    <dl>
      <dt>Pushes accepted</dt><dd>{{.Snap.Counters.PushesAccepted}}</dd>
      <dt>Pushes rejected</dt><dd>{{.Snap.Counters.PushesRejected}} (invalid {{.Snap.Counters.PushesRejectedByClass.Invalid}}, rate-limited {{.Snap.Counters.PushesRejectedByClass.RateLimited}}, node full {{.Snap.Counters.PushesRejectedByClass.NodeFull}}, storage unavailable {{.Snap.Counters.PushesRejectedByClass.StorageUnavailable}}, too large {{.Snap.Counters.PushesRejectedByClass.TooLarge}})</dd>
      <dt>Dedup hits</dt><dd>{{.Snap.Counters.DedupHits}}</dd>
      <dt>TTL sweeps</dt><dd>{{.Snap.Counters.TTLSweeps}} ({{.Snap.Counters.TTLSweptEnvelopes}} envelopes swept)</dd>
    </dl>
  </div>
</main>
</body>
</html>
`))

// statusView is the data the status template renders: the snapshot plus a few
// operator-friendly renderings computed once per request.
type statusView struct {
	Snap         *healthResponse
	VersionsText string
	UptimeText   string
	DBSizeText   string
}

// snapshot returns the cached health document, refreshing it from the store
// at most once per healthCacheTTL. On a store read failure the error is
// surfaced (507, the §10.1 clean shed): a stale snapshot silently freezing
// the numbers would lie to the operator diagnosing exactly that storage —
// truthful beats available here, and the endpoint stays cheap either way.
func (s *server) snapshot() (*healthResponse, error) {
	s.healthMu.Lock()
	defer s.healthMu.Unlock()
	now := healthNow()
	if s.healthCache != nil && now.Sub(s.healthCachedAt) < healthCacheTTL {
		return s.healthCache, nil
	}
	envelopes, err := s.store.EnvelopeCount()
	if err != nil {
		return nil, err
	}
	directory, err := s.store.DirectoryCount()
	if err != nil {
		return nil, err
	}
	dbSize, err := s.store.DBSizeBytes()
	if err != nil {
		return nil, err
	}
	totals := s.counters.Totals()
	snap := &healthResponse{
		// "ok" is a liveness statement, not a health judgment: the node
		// answering IS the alive signal (§10.7). No TLS, no uplink, no
		// watchdog state is invented around it.
		Status:                      "ok",
		API:                         "v1",
		Build:                       s.build,
		EnvelopeVersions:            envelope.SupportedVersions,
		SchemaVersion:               storage.SchemaVersion,
		UptimeSeconds:               int64(time.Since(s.started).Seconds()),
		Envelopes:                   envelopes,
		EnvelopeCapacity:            storage.MaxEnvelopes(),
		DirectoryEntries:            directory,
		DBSizeBytes:                 dbSize,
		LastCleanupUnix:             totals.LastCleanupUnix,
		LastCleanupEnvelopesDeleted: totals.LastCleanupEnvelopesDeleted,
		Counters: healthCountersJSON{
			PushesAccepted: totals.PushesAccepted,
			PushesRejected: totals.PushesRejected,
			PushesRejectedByClass: healthRejectionClassesJSON{
				Invalid:            totals.RejectedInvalid,
				RateLimited:        totals.RejectedRateLimited,
				NodeFull:           totals.RejectedNodeFull,
				StorageUnavailable: totals.RejectedStorageUnavailable,
				TooLarge:           totals.RejectedTooLarge,
			},
			DedupHits:         totals.DedupHits,
			TTLSweeps:         totals.TTLSweeps,
			TTLSweptEnvelopes: totals.TTLSweptEnvelopes,
		},
	}
	s.healthCache = snap
	s.healthCachedAt = now
	return snap, nil
}

// withHealthBudget wraps both diagnostics handlers in the per-IP health
// budget (burst 60, refill 1 request/second — generous for an operator
// polling from a phone, exhausting under any scripted flood). Exhaustion
// answers 429 rate_limited with Retry-After, exactly like the write paths.
// One budget covers both endpoints: they are one diagnostics surface.
func (s *server) withHealthBudget(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if ok, wait := s.healthBudget.allow(clientKey(r), 1); !ok {
			writeRateLimited(w, wait)
			return
		}
		next(w, r)
	}
}

// handleHealth serves the machine-readable snapshot (§10.7).
func (s *server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	snap, err := s.snapshot()
	if err != nil {
		writeError(w, http.StatusInsufficientStorage, codeStorageUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, snap)
}

// handleStatus serves the operator status view (§10.7): the same cached
// snapshot, server-rendered as static HTML. An unavailable store answers the
// same 507 shed as the JSON endpoint.
func (s *server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	snap, err := s.snapshot()
	if err != nil {
		writeError(w, http.StatusInsufficientStorage, codeStorageUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	view := statusView{
		Snap:         snap,
		VersionsText: joinInt64s(snap.EnvelopeVersions),
		UptimeText:   formatUptime(snap.UptimeSeconds),
		DBSizeText:   formatBytes(snap.DBSizeBytes),
	}
	_ = statusTemplate.Execute(w, view) // fixed-shape data; cannot fail mid-body in practice
}

// joinInt64s renders a version slice as "1, 2" for the status page.
func joinInt64s(xs []int64) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = strconv.FormatInt(x, 10)
	}
	return strings.Join(parts, ", ")
}

// formatUptime renders seconds as "Nd HH:MM:SS" (or "HH:MM:SS" under a day)
// for the status page.
func formatUptime(seconds int64) string {
	d := seconds / 86400
	rem := seconds % 86400
	h, m, sec := rem/3600, (rem%3600)/60, rem%60
	body := fmt.Sprintf("%02d:%02d:%02d", h, m, sec)
	if d > 0 {
		return fmt.Sprintf("%dd %s", d, body)
	}
	return body
}

// formatBytes renders a byte count in binary units (B / KiB / MiB / GiB) for
// the status page.
func formatBytes(n int64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	v := float64(n)
	i := 0
	for v >= 1024 && i < len(units)-1 {
		v /= 1024
		i++
	}
	if i == 0 {
		return strconv.FormatInt(n, 10) + " B"
	}
	if v == math.Trunc(v) {
		return strconv.FormatInt(int64(v), 10) + " " + units[i]
	}
	return fmt.Sprintf("%.1f", v) + " " + units[i]
}
