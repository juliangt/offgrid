package capsule

// stage_test.go — the §2.4.4 binding staging order as a library: the refusal
// ladder (unpinned → parse → integrity → arch → anti-rollback → floor →
// skew), the ATOMIC write (staged bytes byte-exact, tmp cleaned up, a
// strictly newer capsule replaces), boot Load, and the concurrency
// guarantee (two racers can never land out of order).

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func newStager(t *testing.T) *Stager {
	t.Helper()
	return &Stager{
		Dir:  filepath.Join(t.TempDir(), "staged"),
		Pub:  ed25519PubOf(t, testSeed),
		Arch: "esp32s3",
		Now:  func() time.Time { return time.Unix(1791072000, 0) },
	}
}

func ed25519PubOf(t *testing.T, seed []byte) []byte {
	t.Helper()
	return []byte(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
}

func stageOK(t *testing.T, s *Stager, payload []byte, release uint64) StageResult {
	t.Helper()
	blob := buildOK(t, testSeed, payload, func(m *Metadata) {
		m.Release = release
		m.MinUpgradeFrom = 0
	})
	res, err := s.Stage(blob)
	if err != nil {
		t.Fatalf("Stage release %d: %v", release, err)
	}
	return res
}

func TestStageHappyPathAtomic(t *testing.T) {
	s := newStager(t)
	payload := bytesRepeata(1000)
	res := stageOK(t, s, payload, 1012000)
	if res.Release != 1012000 || res.Replaced {
		t.Fatalf("result: %+v", res)
	}
	// Staged bytes == the original capsule, byte-exact.
	blob, ok, err := s.StagedBlob()
	if err != nil || !ok {
		t.Fatalf("StagedBlob: %v %v", ok, err)
	}
	c, err := Parse(blob)
	if err != nil {
		t.Fatalf("staged capsule does not parse: %v", err)
	}
	if !bytesEqualStr(c.Payload, payload) {
		t.Fatalf("staged payload not byte-exact")
	}
	// §2.4.4: the tmp file is GONE — only update.capsule exists.
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != StagedFile {
		for _, e := range entries {
			t.Logf("entry: %s", e.Name())
		}
		t.Fatalf("staging dir must hold exactly %s (no tmp residue)", StagedFile)
	}
	if s.StagedRelease() != 1012000 {
		t.Fatalf("StagedRelease: %d", s.StagedRelease())
	}
}

func TestStageRefusalLadder(t *testing.T) {
	payload := []byte("payload")
	t.Run("unpinned", func(t *testing.T) {
		s := newStager(t)
		s.Pub = nil
		blob := buildOK(t, testSeed, payload, nil)
		if _, err := s.Stage(blob); ErrorCode(err) != CodeUnpinned {
			t.Fatalf("unpinned: %v", err)
		}
		// Nothing written.
		if _, ok, _ := s.StagedBlob(); ok {
			t.Fatalf("unpinned staging must write nothing")
		}
	})
	t.Run("wrong arch", func(t *testing.T) {
		s := newStager(t)
		blob := buildOK(t, testSeed, payload, func(m *Metadata) { m.Arch = "arm64" })
		if _, err := s.Stage(blob); ErrorCode(err) != CodeWrongArch {
			t.Fatalf("wrong arch: %v", err)
		}
	})
	t.Run("arch gate accepts own arch", func(t *testing.T) {
		s := newStager(t)
		blob := buildOK(t, testSeed, payload, func(m *Metadata) { m.MinUpgradeFrom = 0 }) // esp32s3 == the node's arch
		if _, err := s.Stage(blob); err != nil {
			t.Fatalf("own arch: %v", err)
		}
	})
	t.Run("stale vs staged", func(t *testing.T) {
		s := newStager(t)
		stageOK(t, s, payload, 1012000)
		blob := buildOK(t, testSeed, payload, func(m *Metadata) { m.Release = 1011000; m.MinUpgradeFrom = 0 })
		if _, err := s.Stage(blob); ErrorCode(err) != CodeStale {
			t.Fatalf("older than staged: %v", err)
		}
		// Equal release is stale too (monotonic, not ≥).
		blob = buildOK(t, testSeed, payload, func(m *Metadata) { m.Release = 1012000; m.MinUpgradeFrom = 0 })
		if _, err := s.Stage(blob); ErrorCode(err) != CodeStale {
			t.Fatalf("equal release: %v", err)
		}
		// The staged capsule survives every refusal untouched.
		if s.StagedRelease() != 1012000 {
			t.Fatalf("a refusal must not touch the staged state")
		}
	})
	t.Run("stale vs running", func(t *testing.T) {
		s := newStager(t)
		s.RunningRelease = 1012000
		blob := buildOK(t, testSeed, payload, func(m *Metadata) { m.Release = 1011999; m.MinUpgradeFrom = 0 })
		if _, err := s.Stage(blob); ErrorCode(err) != CodeStale {
			t.Fatalf("older than running: %v", err)
		}
	})
	t.Run("too old floor", func(t *testing.T) {
		s := newStager(t)
		s.RunningRelease = 1000000
		blob := buildOK(t, testSeed, payload, func(m *Metadata) { m.Release = 1012000; m.MinUpgradeFrom = 1009000 })
		if _, err := s.Stage(blob); ErrorCode(err) != CodeTooOld {
			t.Fatalf("min_upgrade_from: %v", err)
		}
	})
	t.Run("created_at skew", func(t *testing.T) {
		s := newStager(t)
		blob := buildOK(t, testSeed, payload, func(m *Metadata) { m.CreatedAt = 1791072000 + 3600; m.MinUpgradeFrom = 0 })
		if _, err := s.Stage(blob); ErrorCode(err) != CodeCreatedAt {
			t.Fatalf("future created_at: %v", err)
		}
	})
	t.Run("tampered", func(t *testing.T) {
		s := newStager(t)
		blob := buildOK(t, testSeed, payload, nil)
		blob[HeaderLen+5] ^= 0x20
		if _, err := s.Stage(blob); ErrorCode(err) != CodeSHA && ErrorCode(err) != CodeMetadata && ErrorCode(err) != CodeSignature {
			t.Fatalf("tampered: %v", err)
		}
	})
	t.Run("unknown arch string is a node-plane refusal", func(t *testing.T) {
		// Consumers MUST ignore unknown arch values at the FORMAT level
		// (§9.1): Parse accepts, the node's arch GATE refuses — so the
		// refusal needs a genuinely well-signed foreign-arch capsule.
		s := newStager(t)
		blob := handSignedCapsule(t, canonMeta(t, payload, "riscv", 1012000), payload)
		if _, err := s.Stage(blob); ErrorCode(err) != CodeWrongArch {
			t.Fatalf("unknown arch: %v", err)
		}
	})
}

func TestStageReplaceMonotone(t *testing.T) {
	s := newStager(t)
	stageOK(t, s, []byte("one"), 1012000)
	res := stageOK(t, s, []byte("two"), 1015000)
	if !res.Replaced {
		t.Fatalf("a strictly newer capsule must replace")
	}
	blob, ok, _ := s.StagedBlob()
	if !ok {
		t.Fatalf("staged blob vanished")
	}
	c, _ := Parse(blob)
	if c.Meta.Release != 1015000 {
		t.Fatalf("staged release %d, want 1015000", c.Meta.Release)
	}
}

func TestStageLoad(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "staged")
	s1 := &Stager{Dir: dir, Pub: ed25519PubOf(t, testSeed), Arch: "esp32s3"}
	if err := s1.Load(); err != nil {
		t.Fatalf("empty load: %v", err)
	}
	if s1.StagedRelease() != 0 {
		t.Fatalf("empty load must leave the state at 0")
	}
	payload := []byte("boot-loader-capsule")
	blob := buildOK(t, testSeed, payload, func(m *Metadata) { m.MinUpgradeFrom = 0 })
	if _, err := s1.Stage(blob); err != nil {
		t.Fatalf("stage: %v", err)
	}
	// A fresh process loads the staged release (the boot path).
	s2 := &Stager{Dir: dir, Pub: ed25519PubOf(t, testSeed), Arch: "esp32s3"}
	if err := s2.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	if s2.StagedRelease() != 1012000 {
		t.Fatalf("loaded release %d", s2.StagedRelease())
	}
	// Anti-rollback against a LOADED staged release: the pre-restart replay
	// is refused exactly like a live one.
	replay := buildOK(t, testSeed, payload, func(m *Metadata) { m.Release = 1000000; m.MinUpgradeFrom = 0 })
	if _, err := s2.Stage(replay); ErrorCode(err) != CodeStale {
		t.Fatalf("replay after boot: %v", err)
	}
}

func TestStageConcurrentNeverOutOfOrder(t *testing.T) {
	s := newStager(t)
	var wg sync.WaitGroup
	accepted := make([]uint64, 0, 8)
	var mu sync.Mutex
	for _, rel := range []uint64{1012000, 1013000, 1014000, 1015000, 1016000, 1017000, 1018000, 1019000} {
		rel := rel
		wg.Add(1)
		go func() {
			defer wg.Done()
			payload := []byte{byte(rel), byte(rel >> 8)}
			blob := buildOK(t, testSeed, payload, func(m *Metadata) { m.Release = rel; m.MinUpgradeFrom = 0 })
			res, err := s.Stage(blob)
			if err == nil {
				mu.Lock()
				accepted = append(accepted, res.Release)
				mu.Unlock()
			} else if ErrorCode(err) != CodeStale {
				t.Errorf("unexpected error for %d: %v", rel, err)
			}
		}()
	}
	wg.Wait()
	// Whatever the interleaving, the FINAL staged release must be the
	// maximum — a stale stage can never overwrite a newer one.
	if got := s.StagedRelease(); got != 1019000 {
		t.Fatalf("final staged release %d, want the max 1019000 (accepted: %v)", got, accepted)
	}
}

func TestFingerprintHex(t *testing.T) {
	blob := buildOK(t, testSeed, []byte("payload"), nil)
	sum := sha256.Sum256(blob)
	if FingerprintHex(blob) != hex.EncodeToString(sum[:]) {
		t.Fatalf("FingerprintHex drift")
	}
}

// --- tiny local helpers (the test files above define bytes helpers) --------

func bytesRepeata(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte('A' + i%26)
	}
	return out
}

func bytesEqualStr(a []byte, b []byte) bool {
	return string(a) == string(b)
}
