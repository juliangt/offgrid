package nodeid

// The §2.5 merge state machine beyond the shared vectors: expiry as absence,
// revocation semantics, the unchanged (idempotent redelivery) case, and the
// counter discipline the §10.7-style surfacing relies on.

import (
	"testing"
)

func mergeCert(t *testing.T, anchor KeyPair, node KeyPair, seq uint64, roles []string, level uint64, iss, exp, now int64) []byte {
	t.Helper()
	eid := EID(Fingerprint(node.Public))
	cose, err := SignCert(anchor, node.Public, eid, roles, level, iss, exp, seq, now)
	if err != nil {
		t.Fatal(err)
	}
	return cose
}

func TestMergeLifecycle(t *testing.T) {
	anchor, node, _ := testKeypairs(t)
	now := vecNow
	eid := EID(Fingerprint(node.Public))
	live := func(seq uint64) []byte {
		return mergeCert(t, anchor, node, seq, []string{RoleManager}, 2, now-100, now+1000, now)
	}
	revokedAt := func(seq uint64) []byte {
		return mergeCert(t, anchor, node, seq, nil, 0, now-100, now+1000, now)
	}

	cache := NewCache()

	// First sight of an EID installs (rule 1 against an empty slot).
	if st := cache.Merge(live(1), anchor.Public, now); st.Outcome != OutcomeReplaced || st.Revoked {
		t.Fatalf("install: %+v", st)
	}
	if _, state := cache.Effective(eid, now); state != StateAuthority {
		t.Fatalf("state after install: %s", state)
	}

	// Idempotent redelivery of the identical bytes: no change, no counters.
	if st := cache.Merge(cache.Cached(eid).Raw(), anchor.Public, now); st.Outcome != OutcomeUnchanged {
		t.Fatalf("redelivery: %+v", st)
	}
	if cache.Conflicts != 0 || cache.StaleDropped != 0 {
		t.Fatal("redelivery moved counters")
	}

	// Rollback attempts against a fresh cache holding seq 3.
	cache2 := NewCache()
	cache2.Merge(live(3), anchor.Public, now)
	if st := cache2.Merge(live(2), anchor.Public, now); st.Outcome != OutcomeStaleDropped {
		t.Fatalf("stale: %+v", st)
	}
	if cache2.StaleDropped != 1 || cache2.Conflicts != 0 {
		t.Fatalf("stale counters: %d/%d", cache2.StaleDropped, cache2.Conflicts)
	}

	// Revocation: higher-seq empty-roles cert installs and flips the state;
	// the cert itself remains (it is the proof the EID was revoked).
	if st := cache2.Merge(revokedAt(4), anchor.Public, now); !st.Revoked || st.Outcome != OutcomeReplaced {
		t.Fatalf("revocation: %+v", st)
	}
	if c, state := cache2.Effective(eid, now); state != StateRevoked || !c.Revocation() {
		t.Fatalf("post-revocation state: %s", state)
	}
	// A revoked node cannot regain authority by replaying its OLD live cert.
	if st := cache2.Merge(live(3), anchor.Public, now); st.Outcome != OutcomeStaleDropped {
		t.Fatalf("replay under revocation: %+v", st)
	}
	if _, state := cache2.Effective(eid, now); state != StateRevoked {
		t.Fatalf("replay lifted revocation: %s", state)
	}

	// A genuinely newer cert (seq 5) supersedes the revocation — the L3
	// re-issue path.
	if st := cache2.Merge(live(5), anchor.Public, now); st.Outcome != OutcomeReplaced || st.Revoked {
		t.Fatalf("re-issue: %+v", st)
	}
	if _, state := cache2.Effective(eid, now); state != StateAuthority {
		t.Fatalf("post-reissue state: %s", state)
	}
}

func TestMergeExpiryIsAbsence(t *testing.T) {
	anchor, node, _ := testKeypairs(t)
	now := vecNow
	eid := EID(Fingerprint(node.Public))
	// A cert that is already expired at `now`: validly signed, expired.
	expired := mergeCert(t, anchor, node, 9, []string{RoleEdge}, 1, now-2000, now-1000, now)
	cache := NewCache()
	if st := cache.Merge(expired, anchor.Public, now); st.Outcome != OutcomeExpiredDropped {
		t.Fatalf("expired merge: %+v", st)
	}
	if cache.Len() != 0 {
		t.Fatal("expired cert was stored")
	}
	if _, state := cache.Effective(eid, now); state != StateAbsent {
		t.Fatalf("expired state: %s (want absent — §2.5 rule 5)", state)
	}
	// It must not raise the seq floor: a genuine seq-1 issue still installs.
	live := mergeCert(t, anchor, node, 1, []string{RoleEdge}, 1, now-100, now+1000, now)
	if st := cache.Merge(live, anchor.Public, now); st.Outcome != OutcomeReplaced {
		t.Fatalf("install under expired junk: %+v", st)
	}
	// Time passing makes the cached cert expire WITHOUT any new merge:
	// Effective interprets, it does not mutate.
	if _, state := cache.Effective(eid, now+2000); state != StateExpired {
		t.Fatalf("lapsed state: %s", state)
	}
	if _, state := cache.Effective(eid, now); state != StateAuthority {
		t.Fatalf("still-live state: %s", state)
	}
}

func TestMergeInvalidNeverTouchesState(t *testing.T) {
	anchor, node, node2 := testKeypairs(t)
	now := vecNow
	eid := EID(Fingerprint(node.Public))
	cache := NewCache()
	cache.Merge(mergeCert(t, anchor, node, 1, []string{RoleEdge}, 1, now-100, now+1000, now), anchor.Public, now)
	before := cache.Cached(eid).Raw()

	// Cert signed by a NON-pinned key: invalid, nothing changes.
	other := EID(Fingerprint(node2.Public))
	forgedOther, err := SignCert(node2, node2.Public, other, []string{RoleManager}, 3, now-1, now+100, 2, now)
	if err != nil {
		t.Fatal(err)
	}
	if st := cache.Merge(forgedOther, anchor.Public, now); st.Outcome != OutcomeInvalid || st.Reason != CodeWrongAnchorFP {
		t.Fatalf("forged: %+v", st)
	}
	// Schema garbage signed by the REAL anchor (the C side runs the same
	// case from the vectors): invalid, cached bytes untouched.
	if st := cache.Merge([]byte{0x84, 0x00}, anchor.Public, now); st.Outcome != OutcomeInvalid {
		t.Fatalf("garbage: %+v", st)
	}
	if string(cache.Cached(eid).Raw()) != string(before) {
		t.Fatal("failed merges mutated the cache")
	}
	if cache.Conflicts != 0 || cache.StaleDropped != 0 {
		t.Fatal("failed merges moved counters")
	}
}

func TestMergePerEIDIsolation(t *testing.T) {
	anchor, node, node2 := testKeypairs(t)
	now := vecNow
	cache := NewCache()
	eidA := EID(Fingerprint(node.Public))
	eidB := EID(Fingerprint(node2.Public))
	cache.Merge(mergeCert(t, anchor, node, 5, []string{RoleEdge}, 1, now-100, now+1000, now), anchor.Public, now)
	cache.Merge(mergeCert(t, anchor, node2, 1, []string{RoleBridge}, 1, now-100, now+1000, now), anchor.Public, now)
	// B's seq-1 does not clash with A's seq-5: different node_eid slots.
	if st := cache.Merge(mergeCert(t, anchor, node2, 1, []string{RoleEdge}, 1, now-90, now+1000, now), anchor.Public, now); st.Outcome != OutcomeConflictKept {
		t.Fatalf("B conflict: %+v", st)
	}
	if st := cache.Merge(mergeCert(t, anchor, node, 4, []string{RoleEdge}, 1, now-90, now+1000, now), anchor.Public, now); st.Outcome != OutcomeStaleDropped {
		t.Fatalf("A stale: %+v", st)
	}
	if cache.Len() != 2 {
		t.Fatalf("cache size %d", cache.Len())
	}
	if _, s := cache.Effective(eidA, now); s != StateAuthority {
		t.Fatalf("A state %s", s)
	}
	if _, s := cache.Effective(eidB, now); s != StateAuthority {
		t.Fatalf("B state %s", s)
	}
}
