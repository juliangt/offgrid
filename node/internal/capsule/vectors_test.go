package capsule

// Shared conformance vectors for P3.7 (tests/vectors/capsule/vectors.json) —
// the single source of truth executed by BOTH the Go suite (this file) and
// the C host suite (esp32/components/dtn_core/host/tests/test_capsule.c via
// the generated header host/tests/capsule_vectors.h).
//
// The vectors pin capsule format v1 (offline-maintenance §2.1) end to end
// on the SAME bytes: Go-SIGNED capsules whose staging verdict (the §2.4.4
// ladder of Stager.Check) must be reached identically by dtn_capsule.c, and
// chunk-transport scenarios (§9.4) whose per-step reassembly verdicts and
// final assembled SHA-256 must match byte for byte.
//
// Regeneration is deterministic (fixed RFC 8032 seed, fixed wall clock):
//   cd node && go test ./internal/capsule -run TestVectorsStable -regen
// rewrites BOTH files; the committed copies must never drift.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Fixed material — the RFC 8032 §7.1 TEST1 seed signs everything; a
// key derived from a fixed label is the WRONG key; vecNow is the shared
// wall clock.
const (
	vecSeedHex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
	vecNow     = int64(1791072000)
)

var regen = flag.Bool("regen", false, "rewrite the shared capsule vectors (Go + C header)")

// JSON schema (field order = marshal order = deterministic bytes).
type (
	vecBlob struct {
		Hex     string `json:"hex"`
		Release uint64 `json:"release"`
		Arch    string `json:"arch"`
		Why     string `json:"why"`
	}
	vecVerdict struct {
		Name          string `json:"name"`
		Blob          string `json:"blob"`
		Pub           string `json:"pub"`            // "release" | "other" | "none"
		Arch          string `json:"arch"`           // the node's arch ("" = gate off)
		Running       uint64 `json:"running"`        // the node's release stamp
		Staged        uint64 `json:"staged"`         // pre-staged release
		Expect        string `json:"expect"`         // the stable §2.4.4 code ("ok" = accept)
		ExpectRelease uint64 `json:"expect_release"` // when expect == "ok"
	}
	// vecStep is one reassembly offer: a named capsule's chunk index, or a
	// raw PDU (the corruption variants). Resolved to concrete bytes at
	// generation time — the C header embeds the step PDUs directly.
	vecStep struct {
		C   string `json:"c,omitempty"`
		I   uint32 `json:"i,omitempty"`
		PDU string `json:"pdu,omitempty"`
	}
	vecScenario struct {
		Name         string            `json:"name"`
		ChunkSize    int               `json:"chunk_size"`
		Capsules     map[string]string `json:"capsules"` // key → full capsule hex
		Steps        []vecStep         `json:"steps"`
		ExpectSteps  []string          `json:"expect_steps"` // stored|dup|complete|refused, one per step
		CompleteAt   map[string]int    `json:"complete_at"`  // capsule key → step index
		AssembledSHA map[string]string `json:"assembled_sha256"`
		Why          string            `json:"why"`
	}
	capsuleVectorSet struct {
		Provenance     string             `json:"provenance"`
		RegenCommand   string             `json:"regen_command"`
		Now            int64              `json:"now"`
		ReleaseSeedHex string             `json:"release_seed_hex"`
		ReleasePubHex  string             `json:"release_pub_hex"`
		OtherPubHex    string             `json:"other_pub_hex"`
		Blobs          map[string]vecBlob `json:"blobs"`
		Verdicts       []vecVerdict       `json:"verdicts"`
		Scenarios      []vecScenario      `json:"chunk_scenarios"`
	}
)

func vecSeed() []byte {
	b, _ := hex.DecodeString(vecSeedHex)
	return b
}

func vecPubOf(seed []byte) string {
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	return hex.EncodeToString(pub)
}

// detPayload is the deterministic synthetic payload (the §2.1.4 "synthetic
// 1 KB payload" class): xorshift fill, fixed for all regenerations.
func detPayload(n int, salt byte) []byte {
	out := make([]byte, n)
	var x uint32 = 0x9e3779b9 ^ uint32(salt)<<24
	for i := range out {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		out[i] = byte(x)
	}
	return out
}

func vecBuild(t *testing.T, payload []byte, arch string, release, minUpgrade uint64, createdAt int64) []byte {
	t.Helper()
	sum := sha256.Sum256(payload)
	blob, err := Build(vecSeed(), Metadata{
		V: 1, Release: release,
		Semver: fmt.Sprintf("v%d.%d.%d", release/1_000_000, release/1_000%1_000, release%1_000),
		VCS:    "vectors", Arch: arch, MinUpgradeFrom: minUpgrade, SPAEmbedded: true,
		PayloadSHA256: hex.EncodeToString(sum[:]), PayloadBytes: len(payload), CreatedAt: createdAt,
	}, payload)
	if err != nil {
		t.Fatalf("vector build: %v", err)
	}
	return blob
}

// vecHandSigned signs a RAW metadata string (for shapes Build refuses:
// metadata v=2) — a well-formed forgery tool for the fail-closed vectors.
func vecHandSigned(t *testing.T, meta string, payload []byte) []byte {
	t.Helper()
	blob := make([]byte, 0, HeaderLen+len(meta)+len(payload)+SigLen)
	blob = append(blob, Magic...)
	blob = append(blob, 0, 1)
	mlen := len(meta)
	blob = append(blob, byte(mlen>>24), byte(mlen>>16), byte(mlen>>8), byte(mlen))
	blob = append(blob, meta...)
	blob = append(blob, payload...)
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(vecSeed()), blob[HeaderLen:HeaderLen+mlen+len(payload)])
	return append(blob, sig...)
}

func vecCanonMeta(t *testing.T, payload []byte, v int, arch string, release, minUpgrade uint64, createdAt int64) string {
	t.Helper()
	sum := sha256.Sum256(payload)
	u := func(x uint64) string { return fmt.Sprintf("%d", x) }
	return `{"v":` + u(uint64(v)) + `,"release":` + u(release) +
		`,"semver":"v1.12.0","vcs":"vectors","arch":"` + arch +
		`","min_upgrade_from":` + u(minUpgrade) +
		`,"spa_embedded":true,"payload_sha256":"` + hex.EncodeToString(sum[:]) +
		`","payload_bytes":` + u(uint64(len(payload))) +
		`,"created_at":` + u(uint64(createdAt)) + `}`
}

func shaOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func metaLenOf(blob []byte) int {
	return int(blob[10])<<24 | int(blob[11])<<16 | int(blob[12])<<8 | int(blob[13])
}

// buildVectorSet assembles the whole set deterministically.
func buildVectorSet(t *testing.T) capsuleVectorSet {
	t.Helper()
	otherSeed := sha256.Sum256([]byte("offgrid-capsule-vector-other-key"))
	otherPub := vecPubOf(otherSeed[:])

	goodPayload := detPayload(1000, 0x01)
	good := vecBuild(t, goodPayload, "esp32s3", 1012000, 0, vecNow)

	foreign := vecBuild(t, detPayload(300, 0x02), "armv6", 1013000, 0, vecNow)

	tamperedPayload := vecBuild(t, goodPayload, "esp32s3", 1012000, 0, vecNow)
	tamperedPayload[len(tamperedPayload)-SigLen-1] ^= 0x01 // one payload byte: dies on the SHA

	tamperedMeta := vecBuild(t, detPayload(300, 0x03), "esp32s3", 1014000, 0, vecNow)
	// Flip the LAST created_at digit (canonical shape intact, signature
	// broken — the bad_signature class, not bad_metadata).
	tamperedMeta[HeaderLen+metaLenOf(tamperedMeta)-2] ^= 0x01

	badMagic := append([]byte(nil), good...)
	badMagic[3] = 'X' // "OFGRIDUP" → "OFXRIDUP"

	badFormat := append([]byte(nil), good...)
	badFormat[9] = 2

	truncated := good[:len(good)-10]

	hugeMlen := append([]byte(nil), good[:HeaderLen]...)
	hugeMlen[10], hugeMlen[11], hugeMlen[12], hugeMlen[13] = 0, 0, 0x10, 0x00 // 4096 > the M budget
	hugeMlen = append(hugeMlen, good[HeaderLen:]...)

	floored := vecBuild(t, detPayload(200, 0x04), "esp32s3", 1012000, 1009000, vecNow)

	futureCreated := vecBuild(t, detPayload(200, 0x05), "esp32s3", 1015000, 0, vecNow+3600)

	v2Payload := detPayload(100, 0x06)
	v2 := vecHandSigned(t, vecCanonMeta(t, v2Payload, 2, "esp32s3", 1016000, 0, vecNow), v2Payload)

	small := vecBuild(t, detPayload(64, 0x07), "esp32s3", 1017000, 0, vecNow) // 2 chunks @ 200 B
	mid := vecBuild(t, detPayload(256, 0x08), "esp32s3", 1018000, 0, vecNow)  // 3 chunks @ 200 B

	blobs := map[string]vecBlob{
		"good":              {hex.EncodeToString(good), 1012000, "esp32s3", "the accept reference (the §2.1 layout with a real signature)"},
		"foreign_arch":      {hex.EncodeToString(foreign), 1013000, "armv6", "well-signed capsule for another board (the §9.1 arch gate)"},
		"tampered_payload":  {hex.EncodeToString(tamperedPayload), 1012000, "esp32s3", "one flipped payload byte: the SHA kills it before any politics"},
		"tampered_metadata": {hex.EncodeToString(tamperedMeta), 1014000, "esp32s3", "one flipped created_at digit: canonical shape, dead signature"},
		"bad_magic":         {hex.EncodeToString(badMagic), 1012000, "esp32s3", "corrupted prologue"},
		"bad_format":        {hex.EncodeToString(badFormat), 1012000, "esp32s3", "format version 2 does not exist"},
		"truncated":         {hex.EncodeToString(truncated), 1012000, "esp32s3", "ten bytes short: length-coherence catches it"},
		"huge_mlen":         {hex.EncodeToString(hugeMlen), 1012000, "esp32s3", "metadata length over the §2.1.2 budget"},
		"floored":           {hex.EncodeToString(floored), 1012000, "esp32s3", "min_upgrade_from above the running release (§2.6 rule 3)"},
		"future_created":    {hex.EncodeToString(futureCreated), 1015000, "esp32s3", "created_at more than 300 s ahead of the node clock"},
		"v2":                {hex.EncodeToString(v2), 1016000, "esp32s3", "well-signed metadata v=2: fail-closed (only v1 exists)"},
		"small":             {hex.EncodeToString(small), 1017000, "esp32s3", "chunk scenario capsule (2 chunks @ 200 B)"},
		"mid":               {hex.EncodeToString(mid), 1018000, "esp32s3", "chunk scenario capsule (3 chunks @ 200 B)"},
	}

	verdicts := []vecVerdict{
		{Name: "accept", Blob: "good", Pub: "release", Arch: "esp32s3", Running: 1010000, Staged: 0, Expect: "ok", ExpectRelease: 1012000},
		{Name: "accept_unknown_running", Blob: "good", Pub: "release", Arch: "esp32s3", Running: 0, Staged: 0, Expect: "ok", ExpectRelease: 1012000},
		{Name: "stale_vs_staged", Blob: "good", Pub: "release", Arch: "esp32s3", Running: 0, Staged: 1012000, Expect: "stale"},
		{Name: "stale_vs_running", Blob: "good", Pub: "release", Arch: "esp32s3", Running: 1012000, Staged: 0, Expect: "stale"},
		{Name: "unpinned", Blob: "good", Pub: "none", Arch: "esp32s3", Running: 0, Staged: 0, Expect: "unpinned"},
		{Name: "wrong_key", Blob: "good", Pub: "other", Arch: "esp32s3", Running: 0, Staged: 0, Expect: "bad_signature"},
		{Name: "wrong_arch", Blob: "foreign_arch", Pub: "release", Arch: "esp32s3", Running: 0, Staged: 0, Expect: "wrong_arch"},
		{Name: "arch_gate_off_accepts_foreign", Blob: "foreign_arch", Pub: "release", Arch: "", Running: 0, Staged: 0, Expect: "ok", ExpectRelease: 1013000},
		{Name: "tampered_payload", Blob: "tampered_payload", Pub: "release", Arch: "esp32s3", Running: 0, Staged: 0, Expect: "sha_mismatch"},
		{Name: "tampered_metadata", Blob: "tampered_metadata", Pub: "release", Arch: "esp32s3", Running: 0, Staged: 0, Expect: "bad_signature"},
		{Name: "bad_magic", Blob: "bad_magic", Pub: "release", Arch: "esp32s3", Running: 0, Staged: 0, Expect: "bad_magic"},
		{Name: "bad_format", Blob: "bad_format", Pub: "release", Arch: "esp32s3", Running: 0, Staged: 0, Expect: "bad_format"},
		{Name: "truncated", Blob: "truncated", Pub: "release", Arch: "esp32s3", Running: 0, Staged: 0, Expect: "length_mismatch"},
		{Name: "huge_mlen", Blob: "huge_mlen", Pub: "release", Arch: "esp32s3", Running: 0, Staged: 0, Expect: "bad_length"},
		{Name: "too_old", Blob: "floored", Pub: "release", Arch: "esp32s3", Running: 1000000, Staged: 0, Expect: "too_old"},
		{Name: "created_at_skew", Blob: "future_created", Pub: "release", Arch: "esp32s3", Running: 0, Staged: 0, Expect: "created_at_skew"},
		{Name: "metadata_v2", Blob: "v2", Pub: "release", Arch: "esp32s3", Running: 0, Staged: 0, Expect: "bad_version"},
	}

	// The chunk scenarios (§9.4). Per-step verdicts are the counter-diff
	// semantics of Reassembler.Offer: "stored" (partial grew), "dup"
	// (absorbed), "complete" (byte-exact assembly returned), "refused"
	// (any Offer error — corruption, dropped partial).
	split := func(blob []byte) [][]byte {
		t.Helper()
		pdus, err := Split(blob, 200)
		if err != nil {
			t.Fatalf("Split: %v", err)
		}
		return pdus
	}
	midP := split(mid) // (the scenarios re-split through resolveSteps; this asserts Split validity once)

	forgedMid1 := append([]byte(nil), midP[1]...)
	forgedMid1[len(forgedMid1)-1] ^= 0x01 // same header, differing bytes

	scenarios := []vecScenario{
		{
			Name: "interleaved_with_dups", ChunkSize: 200,
			Capsules: map[string]string{"a": hex.EncodeToString(small), "b": hex.EncodeToString(mid)},
			Steps: []vecStep{
				{C: "a", I: 0}, {C: "b", I: 0}, {C: "a", I: 1}, {C: "b", I: 1}, {C: "a", I: 0}, {C: "b", I: 2},
			},
			ExpectSteps:  []string{"stored", "stored", "complete", "stored", "dup", "complete"},
			CompleteAt:   map[string]int{"a": 2, "b": 5},
			AssembledSHA: map[string]string{"a": shaOf(small), "b": shaOf(mid)},
			Why:          "two capsules interleave freely and neither corrupts the other; a byte-identical redelivery of an in-flight chunk is absorbed",
		},
		{
			Name: "corruption_drops_partial_then_recovery", ChunkSize: 200,
			Capsules: map[string]string{"m": hex.EncodeToString(mid)},
			Steps: []vecStep{
				{C: "m", I: 0}, {C: "m", I: 1}, {PDU: hex.EncodeToString(forgedMid1)}, {C: "m", I: 0}, {C: "m", I: 1}, {C: "m", I: 2},
			},
			ExpectSteps:  []string{"stored", "stored", "refused", "stored", "stored", "complete"},
			CompleteAt:   map[string]int{"m": 5},
			AssembledSHA: map[string]string{"m": shaOf(mid)},
			Why:          "a chunk redelivered with DIFFERING bytes is corruption: the whole partial drops (fail-closed, the §5.4 rule) and an honest redelivery rebuilds it to exact completion",
		},
		{
			Name: "reverse_order", ChunkSize: 200,
			Capsules: map[string]string{"r": hex.EncodeToString(mid)},
			Steps: []vecStep{
				{C: "r", I: 2}, {C: "r", I: 1}, {C: "r", I: 0},
			},
			ExpectSteps:  []string{"stored", "stored", "complete"},
			CompleteAt:   map[string]int{"r": 2},
			AssembledSHA: map[string]string{"r": shaOf(mid)},
			Why:          "the LAST chunk arrives first (stride unfixed), the middles fix it, completion is exact",
		},
		{
			Name: "redelivery_after_completion", ChunkSize: 200,
			Capsules: map[string]string{"s": hex.EncodeToString(small)},
			Steps: []vecStep{
				{C: "s", I: 0}, {C: "s", I: 1}, {C: "s", I: 0}, {C: "s", I: 1}, {C: "s", I: 1},
			},
			ExpectSteps:  []string{"stored", "complete", "dup", "dup", "dup"},
			CompleteAt:   map[string]int{"s": 1},
			AssembledSHA: map[string]string{"s": shaOf(small)},
			Why:          "after staging, the completed-id memory absorbs every redelivered chunk — the epidemic plane WILL redeliver",
		},
	}

	return capsuleVectorSet{
		Provenance:     "Generated by node/internal/capsule (issue #33 P3.7) from the §2.1 capsule format and the §9.4 chunk transport (docs/node-network.md, docs/offline-maintenance.md §2). Go-signed capsules over the fixed RFC 8032 §7.1 TEST1 seed and a fixed wall clock; the C side (dtn_capsule.c) must reach identical §2.4.4 staging verdicts and identical §9.4 reassembly verdicts on the identical bytes. Committed copies MUST NOT be hand-edited.",
		RegenCommand:   "cd node && go test ./internal/capsule -run TestVectorsStable -regen",
		Now:            vecNow,
		ReleaseSeedHex: vecSeedHex,
		ReleasePubHex:  vecPubOf(vecSeed()),
		OtherPubHex:    otherPub,
		Blobs:          blobs,
		Verdicts:       verdicts,
		Scenarios:      scenarios,
	}
}

// --- generation -------------------------------------------------------------

// Paths are relative to the PACKAGE directory (go test runs there): up
// three levels to the repository root.
const (
	vecJSONPath   = "../../../tests/vectors/capsule/vectors.json"
	vecHeaderPath = "../../../esp32/components/dtn_core/host/tests/capsule_vectors.h"
)

func TestVectorsStable(t *testing.T) {
	set := buildVectorSet(t)
	if *regen {
		if err := writeVectors(set); err != nil {
			t.Fatalf("regen: %v", err)
		}
		t.Logf("regenerated %s and %s", vecJSONPath, vecHeaderPath)
	}
	// Both committed artifacts must exist and match this build exactly.
	onDisk, err := os.ReadFile(vecJSONPath)
	if err != nil {
		t.Fatalf("vectors.json missing (run with -regen): %v", err)
	}
	fresh, err := json.MarshalIndent(set, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	fresh = append(fresh, '\n')
	if string(onDisk) != string(fresh) {
		t.Fatalf("tests/vectors/capsule/vectors.json drifted from this build — regenerate with: %s", set.RegenCommand)
	}
	hdrOnDisk, err := os.ReadFile(vecHeaderPath)
	if err != nil {
		t.Fatalf("capsule_vectors.h missing (run with -regen): %v", err)
	}
	if want := renderCHeader(set); string(hdrOnDisk) != want {
		t.Fatalf("host/tests/capsule_vectors.h drifted — regenerate with: %s", set.RegenCommand)
	}
}

func writeVectors(set capsuleVectorSet) error {
	if err := os.MkdirAll(filepath.Dir(vecJSONPath), 0o755); err != nil {
		return err
	}
	blob, err := json.MarshalIndent(set, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(vecJSONPath, append(blob, '\n'), 0o644); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(vecHeaderPath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(vecHeaderPath, []byte(renderCHeader(set)), 0o644)
}

// --- the Go side of the vectors ---------------------------------------------

func TestCapsuleVectorsVerdicts(t *testing.T) {
	set := buildVectorSet(t)
	pubs := map[string][]byte{
		"release": mustUnhex(t, set.ReleasePubHex),
		"other":   mustUnhex(t, set.OtherPubHex),
		"none":    nil,
	}
	for _, v := range set.Verdicts {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			blob := mustUnhex(t, set.Blobs[v.Blob].Hex)
			s := &Stager{
				Pub:            pubs[v.Pub],
				Arch:           v.Arch,
				RunningRelease: v.Running,
				stagedR:        v.Staged,
				Now:            func() time.Time { return time.Unix(set.Now, 0) },
			}
			meta, err := s.Check(blob)
			got := "ok"
			if err != nil {
				got = ErrorCode(err)
			}
			if got != v.Expect {
				t.Fatalf("verdict %s: got %q (%v), want %q", v.Name, got, err, v.Expect)
			}
			if v.Expect == "ok" && meta.Release != v.ExpectRelease {
				t.Fatalf("verdict %s: release %d, want %d", v.Name, meta.Release, v.ExpectRelease)
			}
		})
	}
}

func TestCapsuleVectorsChunkScenarios(t *testing.T) {
	set := buildVectorSet(t)
	for _, sc := range set.Scenarios {
		sc := sc
		t.Run(sc.Name, func(t *testing.T) {
			caps := map[string][]byte{}
			for key, hx := range sc.Capsules {
				caps[key] = mustUnhex(t, hx)
			}
			pdus := map[string][][]byte{}
			for key, blob := range caps {
				split, err := Split(blob, sc.ChunkSize)
				if err != nil {
					t.Fatalf("Split %s: %v", key, err)
				}
				pdus[key] = split
			}
			r := NewReassembler()
			r.Now = func() time.Time { return time.Unix(set.Now, 0) }
			before := r.Counters()
			completed := map[string][]byte{}
			for si, step := range sc.Steps {
				var pdu []byte
				if step.PDU != "" {
					pdu = mustUnhex(t, step.PDU)
				} else {
					pdu = pdus[step.C][step.I]
				}
				blob, oErr := r.Offer(pdu, 3600)
				after := r.Counters()
				var got string
				switch {
				case oErr != nil:
					got = "refused"
				case blob != nil:
					got = "complete"
					completed[step.C] = blob
				case after.Dups > before.Dups:
					got = "dup"
				default:
					got = "stored"
				}
				before = after
				if got != sc.ExpectSteps[si] {
					t.Fatalf("step %d (%s#%d): got %q, want %q", si, step.C, step.I, got, sc.ExpectSteps[si])
				}
			}
			for key, blob := range caps {
				sum := shaOf(blob)
				if want := sc.AssembledSHA[key]; sum != want {
					t.Fatalf("test setup: assembled sha %s does not match capsule %s (%s)", sum, key, want)
				}
				got := completed[key]
				if got == nil {
					t.Fatalf("capsule %s never completed", key)
				}
				if string(got) != string(blob) {
					t.Fatalf("capsule %s reassembly not byte-exact", key)
				}
			}
		})
	}
}

func mustUnhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	return b
}

// --- the C header (capsule_vectors.h) ----------------------------------------

// renderCHeader emits the generated C vector header: the pinned pubs, the
// capsule blobs, the §2.4.4 verdict table and the §9.4 reassembly scenarios
// (steps as concrete PDU bytes — the C harness never re-splits).
func renderCHeader(set capsuleVectorSet) string {
	var sb strings.Builder
	sb.WriteString(`/* capsule_vectors.h — P3.7 capsule test vectors for the C host suite.
 * GENERATED from tests/vectors/capsule/vectors.json by the Go vector test:
 *   cd node && go test ./internal/capsule -run TestVectorsStable -regen
 * Do not edit by hand — regenerate. The capsules below were SIGNED in Go and
 * must reach identical §2.4.4 staging verdicts in C (dtn_capsule.c), byte
 * for byte, plus identical §9.4 reassembly verdicts on the step PDUs.
 */
#ifndef DTN_TEST_CAPSULE_VECTORS_H
#define DTN_TEST_CAPSULE_VECTORS_H

#include <stddef.h>
#include <stdint.h>

#define CAPSULE_VEC_NOW `)
	fmt.Fprintf(&sb, "%dll\n\n", set.Now)
	sb.WriteString(cBytes("CAPSULE_VEC_RELEASE_PUB", mustHexBytes(set.ReleasePubHex), "the pinned release key (the RFC 8032 §7.1 TEST1 public half)"))
	sb.WriteString(cBytes("CAPSULE_VEC_OTHER_PUB", mustHexBytes(set.OtherPubHex), "a WRONG key (never pinned)"))
	sb.WriteString("\n/* Capsule blobs (format v1, §2.1). */\n")
	names := make([]string, 0, len(set.Blobs))
	for name := range set.Blobs {
		names = append(names, name)
	}
	sortStrings(names)
	for _, name := range names {
		bl := set.Blobs[name]
		sb.WriteString(cBytes("CAPSULE_BLOB_"+cIdent(name), mustHexBytes(bl.Hex), bl.Why))
	}
	sb.WriteString(`
/* The §2.4.4 verdict table (dtn_capsule_stage must reproduce "expect").
 * pub: 0 = release key, 1 = other (wrong) key, 2 = none (unpinned). */
typedef struct {
    const char *name;
    const uint8_t *blob;
    size_t blob_len;
    int pub;
    const char *arch;        /* the node's arch; "" = gate off */
    uint64_t running;
    uint64_t staged;
    const char *expect;      /* the stable failure code, "ok" = accept */
    uint64_t expect_release; /* when expect == "ok" */
} capsule_vec_verdict;

static const capsule_vec_verdict CAPSULE_VERDICTS[] = {
`)
	for _, v := range set.Verdicts {
		pubIdx := map[string]int{"release": 0, "other": 1, "none": 2}[v.Pub]
		fmt.Fprintf(&sb, "    {\"%s\", CAPSULE_BLOB_%s, CAPSULE_BLOB_%s_LEN, %d, \"%s\", %dULL, %dULL, \"%s\", %dULL},\n",
			v.Name, cIdent(v.Blob), cIdent(v.Blob), pubIdx, v.Arch, v.Running, v.Staged, v.Expect, v.ExpectRelease)
	}
	fmt.Fprintf(&sb, "};\n\n#define CAPSULE_VERDICTS_N %d\n", len(set.Verdicts))
	sb.WriteString(`
/* §9.4 reassembly scenarios: steps are concrete PDUs (the corruption
 * variants are pre-built at generation time), and capsule keys carry their
 * capsule_id, the SHA-256 of the exact assembled bytes and the step at
 * which they must complete. */
typedef struct {
    const char *name;      /* step label */
    const uint8_t *pdu;
    size_t pdu_len;
    const char *expect;    /* stored | dup | complete | refused */
} capsule_vec_step;

typedef struct {
    const char *key;
    const uint8_t *id;      /* 8 B: SHA-256(capsule)[0:8] */
    const char *sha256_hex; /* the assembled bytes must hash to this */
    int complete_at;        /* step index */
    const uint8_t *bytes;   /* the capsule itself (id/sha/byte-exact pins) */
    size_t bytes_len;
} capsule_vec_capsule;

typedef struct {
    const char *name;
    const capsule_vec_capsule *capsules;
    size_t n_capsules;
    const capsule_vec_step *steps;
    size_t n_steps;
} capsule_vec_scenario;
`)
	for _, sc := range set.Scenarios {
		fmt.Fprintf(&sb, "\n/* %s */\n", sc.Why)
		// Steps resolved to concrete PDUs; each gets its own byte array.
		steps := resolveSteps(set, sc)
		for i, pdu := range steps {
			sb.WriteString(cBytes(cIdent("SCENARIO_PDU_"+sc.Name)+fmt.Sprintf("_%d", i), pdu, fmt.Sprintf("step %d of %s", i, sc.Name)))
		}
		// Per-scenario capsule descriptor table.
		keys := make([]string, 0, len(sc.Capsules))
		for key := range sc.Capsules {
			keys = append(keys, key)
		}
		sortStrings(keys)
		// The capsule byte arrays first (the table references them).
		byteNames := map[string]string{}
		for _, key := range keys {
			byteName := cIdent("SCENARIO_BYTES_" + sc.Name + "_" + key)
			byteNames[key] = byteName
			sb.WriteString(cBytes(byteName, mustHexBytes(sc.Capsules[key]), "capsule "+key+" of "+sc.Name))
		}
		fmt.Fprintf(&sb, "static const capsule_vec_capsule %s[] = {\n", cIdent("SCENARIO_CAPS_"+sc.Name))
		for _, key := range keys {
			capBytes := mustHexBytes(sc.Capsules[key])
			id := CapsuleIDOf(capBytes)
			var idArr strings.Builder
			for i, x := range id {
				if i > 0 {
					idArr.WriteString(", ")
				}
				fmt.Fprintf(&idArr, "0x%02x", x)
			}
			fmt.Fprintf(&sb, "    {\"%s\", (const uint8_t[8]){%s}, \"%s\", %d, %s, %s_LEN},\n",
				key, idArr.String(), shaOf(capBytes), sc.CompleteAt[key], byteNames[key], byteNames[key])
		}
		sb.WriteString("};\n")
		// The steps table.
		fmt.Fprintf(&sb, "static const capsule_vec_step %s[] = {\n", cIdent("SCENARIO_STEPS_"+sc.Name))
		for i, step := range sc.Steps {
			label := fmt.Sprintf("%s#%d", step.C, step.I)
			if step.PDU != "" {
				label = "raw"
			}
			pduName := cIdent("SCENARIO_PDU_"+sc.Name) + fmt.Sprintf("_%d", i)
			fmt.Fprintf(&sb, "    {\"%s\", %s, %s_LEN, \"%s\"},\n", label, pduName, pduName, sc.ExpectSteps[i])
		}
		sb.WriteString("};\n")
	}
	fmt.Fprintf(&sb, "\nstatic const capsule_vec_scenario CAPSULE_SCENARIOS[] = {\n")
	for _, sc := range set.Scenarios {
		fmt.Fprintf(&sb, "    {\"%s\", %s, %d, %s, %d},\n",
			sc.Name, cIdent("SCENARIO_CAPS_"+sc.Name), len(sc.Capsules),
			cIdent("SCENARIO_STEPS_"+sc.Name), len(sc.Steps))
	}
	fmt.Fprintf(&sb, "};\n\n#define CAPSULE_SCENARIOS_N %d\n\n", len(set.Scenarios))
	sb.WriteString("#endif /* DTN_TEST_CAPSULE_VECTORS_H */\n")
	return sb.String()
}

// resolveSteps resolves a scenario's steps to concrete PDUs (panics only on
// a generator bug — the set is built from Split-valid capsules above).
func resolveSteps(set capsuleVectorSet, sc vecScenario) [][]byte {
	pdus := map[string][][]byte{}
	for key, hx := range sc.Capsules {
		split, err := Split(mustHexBytes(hx), sc.ChunkSize)
		if err != nil {
			panic(err)
		}
		pdus[key] = split
	}
	out := make([][]byte, len(sc.Steps))
	for i, step := range sc.Steps {
		if step.PDU != "" {
			out[i] = mustHexBytes(step.PDU)
		} else {
			out[i] = pdus[step.C][step.I]
		}
	}
	return out
}

// --- small render helpers ---

func mustHexBytes(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func cBytes(name string, b []byte, comment string) string {
	var sb strings.Builder
	if comment != "" {
		fmt.Fprintf(&sb, "/* %s */\n", comment)
	}
	fmt.Fprintf(&sb, "static const uint8_t %s[] = {", name)
	for i, x := range b {
		if i%16 == 0 {
			sb.WriteString("\n    ")
		}
		fmt.Fprintf(&sb, "0x%02x,", x)
		if i%16 != 15 {
			sb.WriteString(" ")
		}
	}
	if len(b)%16 != 0 {
		sb.WriteString(" ")
	}
	sb.WriteString("\n};\n")
	fmt.Fprintf(&sb, "#define %s_LEN %d\n", name, len(b))
	return sb.String()
}

func cIdent(name string) string {
	out := make([]byte, 0, len(name))
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			out = append(out, c)
		default:
			out = append(out, '_')
		}
	}
	return string(out)
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
