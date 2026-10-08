package nodeid

import "errors"

// The merge rules of docs/node-network.md §2.5 — offline-maintenance §3.4
// applied to role certificates, verbatim in structure: there is NO online
// CRL; revocation and rollback resistance are pure seq-merge rules applied
// identically to certs received by any path (direct contact, epidemic sync,
// provisioning).

// Outcome classifies one Merge call.
type Outcome int

const (
	// OutcomeReplaced: a verified cert with a higher seq than the cached
	// one replaced it (§2.5 rule 1).
	OutcomeReplaced Outcome = iota
	// OutcomeStaleDropped: seq lower than cached — stale, dropped silently
	// and counted (rule 2, counter StaleDropped).
	OutcomeStaleDropped
	// OutcomeConflictKept: equal seq, DIFFERING bytes — the existing cert
	// stays, the attempt is counted as an attack signal (rule 3, counter
	// Conflicts). Equal-sequence ties NEVER overwrite: first verified claim
	// wins; no honest anchor issues two different certs at one sequence.
	OutcomeConflictKept
	// OutcomeUnchanged: equal seq, byte-identical — the same verified cert
	// delivered again (epidemic sync redelivers); nothing changes, no
	// counter moves. Not a conflict: identical bytes have one author.
	OutcomeUnchanged
	// OutcomeExpiredDropped: the new cert is validly signed but expired —
	// §2.5 rule 5 treats it as absent: not stored, nothing replaced.
	OutcomeExpiredDropped
	// OutcomeInvalid: verification failed (bad signature, wrong anchor,
	// schema violation); nothing stored. Reason carries the stable code.
	OutcomeInvalid
)

func (o Outcome) String() string {
	switch o {
	case OutcomeReplaced:
		return "replace"
	case OutcomeStaleDropped:
		return "stale_drop"
	case OutcomeConflictKept:
		return "conflict_keep"
	case OutcomeUnchanged:
		return "unchanged"
	case OutcomeExpiredDropped:
		return "expired_drop"
	default:
		return "invalid"
	}
}

// Status is the per-merge result.
type Status struct {
	Outcome Outcome
	// Reason is the stable VerifyError code for OutcomeInvalid ("" otherwise).
	Reason string
	// Revoked: after this merge the effective cert for the EID is a
	// revocation record (roles cleared) — management authority is blocked,
	// mail receivability stays (§2.5 rule 4).
	Revoked bool
}

// CertState is what a cached cert is worth at a wall clock (§2.5 rules 4-5).
type CertState int

const (
	// StateAbsent: nothing cached for the EID.
	StateAbsent CertState = iota
	// StateAuthority: live cert with roles — full authority per its level.
	StateAuthority
	// StateRevoked: a revocation record is cached — MUST NOT open management
	// sessions nor honor commands; mail remains receivable (opaque, §3.3).
	StateRevoked
	// StateExpired: the cached cert lapsed — no authority, no management
	// session; the node itself MAY keep forwarding mail (rule 5).
	StateExpired
)

func (s CertState) String() string {
	switch s {
	case StateAuthority:
		return "authority"
	case StateRevoked:
		return "revoked"
	case StateExpired:
		return "expired"
	default:
		return "absent"
	}
}

// Cache is the per-node_eid role-cert cache with the §2.5 merge rules.
// RAM-only, deterministic, no I/O — the C side (dtn_rolecert.c) implements
// the identical state machine over the same vectors.
type Cache struct {
	byEID map[string]*Cert
	// StaleDropped counts rule-2 drops (stale seq) — RAM-only, resets on
	// restart, surfaced on the node's counters the §10.7 way.
	StaleDropped uint64
	// Conflicts counts rule-3 equal-seq conflicting certs — the ATTACK
	// signal. Any nonzero value means two byte-different certs at one
	// sequence: an anchor honesty failure or a forgery attempt.
	Conflicts uint64
}

// NewCache returns an empty cache.
func NewCache() *Cache { return &Cache{byEID: make(map[string]*Cert)} }

// Len is the number of cached node EIDs.
func (c *Cache) Len() int { return len(c.byEID) }

// Cached returns the raw stored cert for an EID (no expiry/revocation
// interpretation), or nil.
func (c *Cache) Cached(eid string) *Cert { return c.byEID[eid] }

// Merge verifies cose against anchorPub at wall clock now and applies the
// §2.5 rules for its node_eid. Never panics on hostile bytes; every path
// returns a Status.
func (c *Cache) Merge(cose, anchorPub []byte, now int64) Status {
	cert, err := VerifyCert(cose, anchorPub, now)
	if err != nil {
		// Expired-but-genuine certs are treated as absent (rule 5): a
		// distinct outcome, not an error signal — they are NOT stored (a
		// lapsed cert must not raise the seq floor behind the anchor's
		// back, and must not resurrect authority either).
		if errors.Is(err, ErrExpired) {
			return Status{Outcome: OutcomeExpiredDropped}
		}
		return Status{Outcome: OutcomeInvalid, Reason: ErrorCode(err)}
	}
	cur := c.byEID[cert.EID]
	if cur == nil || cert.Seq > cur.Seq {
		c.byEID[cert.EID] = cert
		return Status{Outcome: OutcomeReplaced, Revoked: cert.Revocation()}
	}
	switch {
	case cert.Seq < cur.Seq:
		c.StaleDropped++
		return Status{Outcome: OutcomeStaleDropped}
	case bytesEqual(cert.raw, cur.raw):
		return Status{Outcome: OutcomeUnchanged}
	default:
		// Equal seq, differing bytes: keep the existing cert, count the
		// attack signal. The first verified claim wins — this is the
		// offline-island substitute for a CRL conflict policy.
		c.Conflicts++
		return Status{Outcome: OutcomeConflictKept, Revoked: cur.Revocation()}
	}
}

// Effective interprets the cached cert at wall clock now (§2.5 rules 4-5):
// authority only while the cert is live and carries roles.
func (c *Cache) Effective(eid string, now int64) (*Cert, CertState) {
	cert := c.byEID[eid]
	if cert == nil {
		return nil, StateAbsent
	}
	if cert.Expired(now) {
		return cert, StateExpired
	}
	if cert.Revocation() {
		return cert, StateRevoked
	}
	return cert, StateAuthority
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
