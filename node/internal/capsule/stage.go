// stage.go — the §2.4.4 staging semantics as a library, the
// entry-point-agnostic core offline-maintenance §2.3 predicted ("format
// and verification are entry-point-agnostic by construction"). Both
// future entry points call THIS code:
//
//   - the #37 HTTP endpoint (POST /api/v1/update/stage, §2.4) — lands with
//     #37; the endpoint wraps Stage and maps Error.Code to its §2.4.2
//     status codes;
//   - the node-plane reassembler (§9.4 of docs/node-network.md) — landed
//     here in P3.7; it feeds the reassembled bytes straight into Stage.
//
// The binding staging order (§2.4.4) and the §2.6 anti-rollback policy:
//
//	1. Parse (shape, lengths, coherence)          → invalid/corrupted class
//	2. Verify (payload SHA-256, then signature)   → corrupted / bad signature
//	3. arch gate (§9.1, node-plane)               → wrong_arch
//	4. anti-rollback vs max(running, staged)      → stale (§2.6 rule 2)
//	5. min_upgrade_from floor                     → too_old (§2.6 rule 3)
//	6. created_at sanity against the local clock  → created_at_skew
//	7. ATOMIC write (tmp + fsync + rename + dir fsync, §2.4.4 step 4)
//
// NOTHING here applies a capsule. Apply is #22's machinery
// (raspberry/upgrade.sh: probe → backup → swap → health gate → auto
// rollback), triggered at boot or by explicit operator command (§2.5) —
// deliberately not in v1 over the node plane either: an island-wide bad
// update needs the operator's explicit gate, consistent with §2.4's
// operator-visible staging. The #22 counters, functions and
// tests/upgrade_e2e.sh outcomes are untouched by this package.

package capsule

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// StagedFile is the §2.4.4 staging target name (ONE capsule staged at a
// time; a strictly newer one replaces it — step 4 of the rule makes
// replacements monotone).
const (
	StagedFile = "update.capsule"
	stagedTmp  = "update.capsule.tmp"
	// MaxCreatedSkew is the §2.1.2 created_at rule (the §4.3 skew rule):
	// a capsule created more than 300 s into the node's future is refused
	// at staging.
	MaxCreatedSkew = 300 * time.Second
)

// Stager holds the staging state of one node: the staging directory (the
// #22 convention: /var/lib/dtn-node/staged/ on a provisioned Pi; tests
// point it at a temp dir), the pinned release public key, the node's own
// arch (the §9.1 gate) and its running release (the §2.4.3 ldflags
// stamp — 0 on builds that predate capsules, which is every build until
// #37 lands the stamp; the anti-rollback rule then rests on the staged
// capsule alone).
type Stager struct {
	// Dir is the staging directory (created on demand, mode 0750 — the
	// same class as the data directory).
	Dir string
	// Pub is the pinned release public key (32 bytes). Nil = unpinned:
	// staging is UNAVAILABLE (§2.4.1), never misbehaving — Stage answers
	// unpinned and writes nothing.
	Pub []byte
	// Arch is this node's arch (the §9.1 enum value matching the board).
	// Empty disables the arch gate (the #37 Pi endpoint is per-arch by
	// artifact naming and passes "" today; the node plane passes its
	// provisioned arch).
	Arch string
	// RunningRelease is this build's own release integer (§2.4.3). 0 =
	// a build that predates capsules (unknown); the anti-rollback floor
	// then uses max(staged) only, and the min_upgrade_from gate refuses
	// capsules whose floor exceeds the (unknown) running release — a
	// node that cannot prove its release does not blind-stage across a
	// migration gap.
	RunningRelease uint64

	mu      sync.Mutex
	stagedR uint64 // the staged capsule's release; 0 = none staged

	// Now pins the clock (tests).
	Now func() time.Time
}

// StageResult reports one Stage call.
type StageResult struct {
	Release  uint64 // the staged capsule's release (== the accepted capsule's)
	Replaced bool   // true when a previous staged capsule was replaced
}

// StagedRelease reports the release currently staged (0 = none).
func (s *Stager) StagedRelease() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stagedR
}

// Load reads an existing staged capsule (boot path: the daemon learns
// what a previous life staged). A capsule that no longer parses is left
// in place but NOT counted as staged state — it will fail Verify at
// apply time (§2.5's fresh-eyes re-check); the operator's apply path is
// the arbiter, not the loader.
func (s *Stager) Load() error {
	blob, err := os.ReadFile(filepath.Join(s.Dir, StagedFile))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("capsule: read staged capsule: %w", err)
	}
	c, err := Parse(blob)
	if err != nil {
		return fmt.Errorf("capsule: staged capsule does not parse: %w", err)
	}
	s.mu.Lock()
	s.stagedR = c.Meta.Release
	s.mu.Unlock()
	return nil
}

// Stage runs the binding §2.4.4 order over blob and, on success, writes
// the capsule bytes atomically to Dir/StagedFile. The returned error is
// always an *Error — callers map ErrorCode to their surface's vocabulary
// (the §2.4.2 HTTP classes; the §9.4 counters).
//
// The WHOLE ladder runs under the staging lock: the §2.6 rule-2 check
// (monotonic against max(running, staged)) and the atomic write must not
// interleave — two concurrent staging attempts would otherwise both pass
// the same floor and land out of order (an epidemic sink delivers from
// several sessions at once). Staging is rare; holding a mutex across the
// file write costs nothing that matters.
func (s *Stager) Stage(blob []byte) (StageResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	meta, err := s.check(blob, s.stagedR)
	if err != nil {
		return StageResult{}, err
	}
	// The atomic stage (§2.4.4 step 4) — write the tmp file in the SAME
	// directory, fsync it, rename over the target, fsync the directory. A
	// power cut mid-staging leaves either the old or the new capsule,
	// never a half file.
	if err := s.writeAtomic(blob); err != nil {
		return StageResult{}, err
	}
	replaced := s.stagedR != 0
	s.stagedR = meta.Release
	return StageResult{Release: meta.Release, Replaced: replaced}, nil
}

// Check is the §2.4.4 decision ladder WITHOUT the write — parse, verify,
// the arch gate and the version rules against (running, staged) and the
// local clock. The shared vectors drive this function (the C mirror
// decides identically). Note it snapshots stagedR WITHOUT the staging
// lock: use it when the state is yours (tests, a single-threaded caller);
// Stage is the concurrency-safe path.
func (s *Stager) Check(blob []byte) (Metadata, error) {
	return s.check(blob, s.stagedR)
}

// check is the ladder against an explicit staged floor.
func (s *Stager) check(blob []byte, staged uint64) (Metadata, error) {
	now := s.Now
	if now == nil {
		now = time.Now
	}
	// §2.4.1: an unpinned key means staging is unavailable — fail closed
	// BEFORE doing any work with the bytes.
	if len(s.Pub) != 32 {
		return Metadata{}, errf(CodeUnpinned, "no release key pinned (§2.4.1): staging unavailable, not misbehaving")
	}
	// Step 1: parse (shape, lengths, coherence).
	c, err := Parse(blob)
	if err != nil {
		return Metadata{}, err
	}
	// Step 2: integrity first (cheap SHA), then the signature.
	if err := c.Verify(s.Pub); err != nil {
		return Metadata{}, err
	}
	// Step 3 (node-plane arch gate, §9.1): a capsule for another board is
	// refused BEFORE the version rules — arch and version are independent
	// facts, and the arch message is the actionable one.
	if s.Arch != "" && c.Meta.Arch != s.Arch {
		return Metadata{}, errf(CodeWrongArch, "capsule arch %q does not match this node (%s)", c.Meta.Arch, s.Arch)
	}
	// Step 4 (§2.6 rule 2): monotonic at staging against max(running,
	// staged). Genuine-old capsules are refused exactly like forged ones;
	// replaying last year's release never winds a node back.
	floor := staged
	if s.RunningRelease > floor {
		floor = s.RunningRelease
	}
	if c.Meta.Release <= floor {
		return Metadata{}, errf(CodeStale, "capsule release %d ≤ max(running %d, staged %d) — anti-rollback (§2.6 rule 2)", c.Meta.Release, s.RunningRelease, staged)
	}
	// Step 5 (§2.6 rule 3): the min_upgrade_from floor. A running release
	// of 0 (unknown — pre-capsule build) cannot prove it is above any
	// nonzero floor, so it refuses them: the migration chain is not to be
	// trusted blind.
	if c.Meta.MinUpgradeFrom > s.RunningRelease {
		return Metadata{}, errf(CodeTooOld, "running release %d < min_upgrade_from %d — the reflash path (§4.6) is the only route across a gap this wide", s.RunningRelease, c.Meta.MinUpgradeFrom)
	}
	// Step 6: created_at sanity against the LOCAL clock (§2.1.2 member
	// 10: ≤ now + 300).
	if c.Meta.CreatedAt > now().Add(MaxCreatedSkew).Unix() {
		return Metadata{}, errf(CodeCreatedAt, "created_at %d is more than %s ahead of this node", c.Meta.CreatedAt, MaxCreatedSkew)
	}
	return c.Meta, nil
}

// writeAtomic is §2.4.4 step 4, verbatim.
func (s *Stager) writeAtomic(blob []byte) error {
	if err := os.MkdirAll(s.Dir, 0o750); err != nil {
		return fmt.Errorf("capsule: create staging dir: %w", err)
	}
	tmp := filepath.Join(s.Dir, stagedTmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("capsule: open tmp: %w", err)
	}
	if _, err := f.Write(blob); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("capsule: write tmp: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("capsule: fsync tmp: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("capsule: close tmp: %w", err)
	}
	if err := os.Rename(tmp, filepath.Join(s.Dir, StagedFile)); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("capsule: rename over target: %w", err)
	}
	d, err := os.Open(s.Dir)
	if err != nil {
		return fmt.Errorf("capsule: reopen staging dir for fsync: %w", err)
	}
	if err := d.Sync(); err != nil {
		d.Close()
		return fmt.Errorf("capsule: fsync staging dir: %w", err)
	}
	return d.Close()
}

// StagedBlob reads the staged capsule bytes (apply-side fresh eyes; the
// #22 apply path re-verifies before anything is touched, §2.5 row 1).
func (s *Stager) StagedBlob() ([]byte, bool, error) {
	blob, err := os.ReadFile(filepath.Join(s.Dir, StagedFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("capsule: read staged capsule: %w", err)
	}
	return blob, true, nil
}

// FingerprintHex is the SHA-256 of a capsule blob, hexed — the release
// note bookkeeping of §2.2.2 ("record the capsule fingerprints").
func FingerprintHex(blob []byte) string {
	sum := sha256.Sum256(blob)
	return hex.EncodeToString(sum[:])
}
