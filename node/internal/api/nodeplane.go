package api

// nodeplane.go — the P3.6 additive member of the diagnostics surface
// (docs/node-network.md §8.6 via protocol.md §10.7's additive-only rule):
// the `node_plane` member of GET /api/v1/health and the matching operator
// card on GET /status.
//
// Privacy reasoning (the §10.7 rules, applied to the node plane — reviewed
// against the status engine's contract in internal/status):
//
//   - Everything exposed is an AGGREGATE integer or the node's own
//     provisioned role/level: command counters (the same class the §10.7
//     push counters established), the §2.5 cert merge counters, the bundle
//     store fill/cap and the peer count. None of it can link envelopes to
//     users — management traffic is node-to-node, and the counters carry no
//     per-user datum by construction.
//   - Deliberately ABSENT (less is more, §10.7): our own EID and any peer
//     EID or fingerprint (they are rotatable pseudonyms, but they are still
//     stable identifiers an unauthenticated page has no reason to publish —
//     the operator works with the COUNT), any peer address, any command
//     name, any target, any timestamp.
//   - The member follows the binding N/A convention: when the daemon runs
//     with the node plane off (or built without a source), the whole member
//     is null — never zeros. It rides the existing diagnostics budget and
//     cache; the member set is fixed and carries no query parameters.

// NodePlaneSnapshot is one plain read of the node plane's operational state.
// Plain data — the api package never imports the node-plane engines; the
// daemon maps its live values into this struct (node/nodeplane.go).
type NodePlaneSnapshot struct {
	// Role/Level come from this node's provisioned role certificate (§2.5
	// effective state). HasCert=false renders both null (an uncertified
	// node has no management authority — the page says so honestly).
	Role    string
	Level   uint64
	HasCert bool

	StoreFill  int64 // live rows in the §7.5 bundle store
	StoreCap   int   // the enforced cap (§7.5 honesty: the enforced number)
	PeerCount  int   // TOFU-pinned peers (the count only — no fingerprints)
	ActiveSess int   // currently established sessions

	Mgmt mgmtCountersSnapshot
	// CertStaleDropped / CertConflicts are the §2.5 merge counters;
	// conflicts nonzero is the loud attack signal (§2.5 rule 3).
	CertStaleDropped uint64
	CertConflicts    uint64
}

// mgmtCountersSnapshot mirrors the §8.2 pipeline counters (plain values).
// The alias exports it to the daemon's nodePlane without renaming every
// field use inside this package.
type mgmtCountersSnapshot struct {
	Accepted        uint64
	DroppedShape    uint64
	DroppedSig      uint64
	DroppedTarget   uint64
	DroppedUnknown  uint64
	DroppedByLevel  uint64
	DroppedSeq      uint64
	DroppedExpired  uint64
	RepliesSent     uint64
	RepliesDropped  uint64
	RepliesReceived uint64
	ExecErrors      uint64
}

// NodePlaneSnapshotMgmt is the exported name of the pipeline-counter mirror
// (the daemon's nodePlane fills it; the api package maps it to JSON).
type NodePlaneSnapshotMgmt = mgmtCountersSnapshot

// NodePlaneSource is the daemon-side provider (the main package's nodePlane
// implements it). Nil-safe: WithNodePlane(nil) behaves like no plane.
type NodePlaneSource interface {
	NodePlaneSnapshot() NodePlaneSnapshot
}

// WithNodePlane attaches the node-plane status source (P3.6). Passing nil
// (or not passing this option) leaves the node_plane member null — the
// documented §10.7 N/A convention for a plane that is OFF by default.
func WithNodePlane(src NodePlaneSource) Option {
	return func(s *server) { s.nodePlane = src }
}

// nodePlaneJSON is the `node_plane` member of the health document. Present
// at all times when a source is wired (null otherwise); every value is an
// aggregate or the node's own provisioned role/level.
type nodePlaneJSON struct {
	Role             *string          `json:"role"`
	Level            *uint64          `json:"level"`
	StoreFill        int64            `json:"store_fill"`
	StoreCap         int              `json:"store_cap"`
	PeerCount        int              `json:"peer_count"`
	ActiveSessions   int              `json:"active_sessions"`
	Mgmt             mgmtCountersJSON `json:"mgmt"`
	CertStaleDropped uint64           `json:"cert_stale_dropped"`
	CertConflicts    uint64           `json:"cert_conflicts"`
}

type mgmtCountersJSON struct {
	CommandsAccepted uint64 `json:"commands_accepted"`
	DroppedByLevel   uint64 `json:"dropped_bylevel"`
	DroppedSeq       uint64 `json:"dropped_seq"`
	DroppedSig       uint64 `json:"dropped_sig"`
	DroppedExpired   uint64 `json:"dropped_expired"`
	DroppedShape     uint64 `json:"dropped_shape"`
	DroppedTarget    uint64 `json:"dropped_target"`
	DroppedUnknown   uint64 `json:"dropped_unknown"`
	RepliesSent      uint64 `json:"replies_sent"`
	RepliesReceived  uint64 `json:"replies_received"`
	ExecErrors       uint64 `json:"exec_errors"`
}

// nodePlaneFromSnapshot maps the plain snapshot into the JSON member (pure;
// reviewed against the §10.7 privacy rules above).
func nodePlaneFromSnapshot(np NodePlaneSnapshot) *nodePlaneJSON {
	out := &nodePlaneJSON{
		StoreFill:      np.StoreFill,
		StoreCap:       np.StoreCap,
		PeerCount:      np.PeerCount,
		ActiveSessions: np.ActiveSess,
		Mgmt: mgmtCountersJSON{
			CommandsAccepted: np.Mgmt.Accepted,
			DroppedByLevel:   np.Mgmt.DroppedByLevel,
			DroppedSeq:       np.Mgmt.DroppedSeq,
			DroppedSig:       np.Mgmt.DroppedSig,
			DroppedExpired:   np.Mgmt.DroppedExpired,
			DroppedShape:     np.Mgmt.DroppedShape,
			DroppedTarget:    np.Mgmt.DroppedTarget,
			DroppedUnknown:   np.Mgmt.DroppedUnknown,
			RepliesSent:      np.Mgmt.RepliesSent,
			RepliesReceived:  np.Mgmt.RepliesReceived,
			ExecErrors:       np.Mgmt.ExecErrors,
		},
		CertStaleDropped: np.CertStaleDropped,
		CertConflicts:    np.CertConflicts,
	}
	if np.HasCert {
		role := np.Role
		level := np.Level
		out.Role = &role
		out.Level = &level
	}
	return out
}
