package api

// nodeplane_test.go — the P3.6 additive member of the diagnostics surface
// (docs/node-network.md §8 via protocol.md §10.7's additive-only rule): the
// `node_plane` member on GET /api/v1/health, the matching operator card on
// GET /status, and the §10.7 privacy shape of both.

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"offgrid/dtn-node/internal/health"
	"offgrid/dtn-node/internal/storage"
)

// fakeNodePlane is a plain NodePlaneSource (the daemon's nodePlane maps its
// live values into the same struct — the api package never touches engines).
type fakeNodePlane struct{ snap NodePlaneSnapshot }

func (f fakeNodePlane) NodePlaneSnapshot() NodePlaneSnapshot { return f.snap }

// planeTestHandler builds a server WITH a node-plane source over a real
// SQLite store, exactly the wiring main() uses.
func planeTestHandler(t *testing.T, snap NodePlaneSnapshot) http.Handler {
	t.Helper()
	s, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	h, err := NewWithCounters(s, health.NewCounters(), testBuild, testWebFS, WithNodePlane(fakeNodePlane{snap}))
	if err != nil {
		t.Fatalf("build handler: %v", err)
	}
	return h
}

// TestNodePlaneMemberNullWhenPlaneOff pins the N/A convention: a server
// built without WithNodePlane carries the member (fixed member set) but
// NULL — never zeros.
func TestNodePlaneMemberNullWhenPlaneOff(t *testing.T) {
	h, _ := newTestHandler(t)
	code, _, body := getHealth(t, h, "/api/v1/health")
	if code != http.StatusOK {
		t.Fatalf("got %d", code)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatal(err)
	}
	member, ok := doc["node_plane"]
	if !ok {
		t.Fatal("node_plane must be present at all times (fixed member set, §10.7)")
	}
	if member != nil {
		t.Fatalf("node_plane must be null without a source, got %v", member)
	}
	// The operator page says the same thing honestly.
	_, _, page := getHealth(t, h, "/status")
	if !strings.Contains(page, "Node plane") {
		t.Fatal("the status page must carry the node-plane card even when the plane is off")
	}
	if !strings.Contains(page, "N/A") {
		t.Fatal("a plane-less node renders N/A, not zeros")
	}
}

// TestNodePlaneMemberServedWithSource drives the full mapping: counters,
// role/level, store fill/cap, peer count — and the privacy shape (no EIDs,
// no fingerprints, no addresses anywhere in the document or the page).
func TestNodePlaneMemberServedWithSource(t *testing.T) {
	snap := NodePlaneSnapshot{
		Role:             "manager",
		Level:            3,
		HasCert:          true,
		StoreFill:        7,
		StoreCap:         5000,
		PeerCount:        3,
		ActiveSess:       1,
		CertStaleDropped: 1,
		Mgmt: NodePlaneSnapshotMgmt{
			Accepted:        12,
			DroppedByLevel:  4,
			DroppedSeq:      2,
			DroppedSig:      1,
			DroppedExpired:  1,
			RepliesSent:     11,
			RepliesReceived: 9,
		},
	}
	h := planeTestHandler(t, snap)
	code, _, body := getHealth(t, h, "/api/v1/health")
	if code != http.StatusOK {
		t.Fatalf("got %d (body: %s)", code, body)
	}
	var doc struct {
		NodePlane *struct {
			Role           *string `json:"role"`
			Level          *uint64 `json:"level"`
			StoreFill      int64   `json:"store_fill"`
			StoreCap       int     `json:"store_cap"`
			PeerCount      int     `json:"peer_count"`
			ActiveSessions int     `json:"active_sessions"`
			Mgmt           struct {
				CommandsAccepted uint64 `json:"commands_accepted"`
				DroppedByLevel   uint64 `json:"dropped_bylevel"`
				DroppedSeq       uint64 `json:"dropped_seq"`
				DroppedSig       uint64 `json:"dropped_sig"`
				DroppedExpired   uint64 `json:"dropped_expired"`
				RepliesSent      uint64 `json:"replies_sent"`
				RepliesReceived  uint64 `json:"replies_received"`
			} `json:"mgmt"`
			CertStaleDropped uint64 `json:"cert_stale_dropped"`
			CertConflicts    uint64 `json:"cert_conflicts"`
		} `json:"node_plane"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatal(err)
	}
	np := doc.NodePlane
	if np == nil {
		t.Fatal("node_plane must be served when a source is wired")
	}
	if np.Role == nil || *np.Role != "manager" || np.Level == nil || *np.Level != 3 {
		t.Fatalf("role/level: %+v", np)
	}
	if np.StoreFill != 7 || np.StoreCap != 5000 || np.PeerCount != 3 || np.ActiveSessions != 1 {
		t.Fatalf("store/peers/sessions: %+v", np)
	}
	m := np.Mgmt
	if m.CommandsAccepted != 12 || m.DroppedByLevel != 4 || m.DroppedSeq != 2 ||
		m.DroppedSig != 1 || m.DroppedExpired != 1 || m.RepliesSent != 11 || m.RepliesReceived != 9 {
		t.Fatalf("mgmt counters: %+v", m)
	}
	if np.CertStaleDropped != 1 || np.CertConflicts != 0 {
		t.Fatalf("cert counters: %+v", np)
	}
	// The §10.7 privacy shape: no node pseudonym, no fingerprint, no
	// address anywhere in the served document.
	for _, forbidden := range []string{"dtn://og.", "eid", "fingerprint", "addr"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("the health document carries %q — the node_plane member is aggregates only", forbidden)
		}
	}

	// The operator page renders the same numbers with the aggregates-only
	// hint, and the cert-conflict warning.
	_, _, page := getHealth(t, h, "/status")
	if !strings.Contains(page, "manager / L3") {
		t.Fatal("the page must render the provisioned role and level")
	}
	if !strings.Contains(page, "7 / 5000") || !strings.Contains(page, "no identities") {
		t.Fatal("the page must render the store fill/cap and the no-identities stance")
	}
	if !strings.Contains(page, "Cert conflicts") {
		t.Fatal("the page must surface the cert merge counters (the §2.5 attack signal)")
	}
}
