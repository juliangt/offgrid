package main

// capsule_test.go — the release-capsule ceremony end to end (issue #33
// P3.7): keygen → sign → verify → show with the capsule library, plus the
// refusal paths (semver/release disagreement, foreign arch, tamper, wrong
// key). The signing key is the same fixed RFC 8032 seed the package tests
// and the shared vectors use.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"offgrid/dtn-node/internal/capsule"
)

const vecReleaseSeed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60" // RFC 8032 §7.1 TEST1
const vecOtherSeed = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"   // §7.2 TEST2

func TestCapsuleKeygenCommand(t *testing.T) {
	dir := t.TempDir()
	status := mustSucceed(t, "capsule", "keygen", "--out", dir)
	raw, err := os.ReadFile(filepath.Join(dir, "release.seed"))
	if err != nil {
		t.Fatal(err)
	}
	seed := strings.TrimSpace(string(raw))
	if len(seed) != 64 {
		t.Fatalf("release.seed must be 64 hex chars, got %q", seed)
	}
	// The pub file IS the seed's public half (the §2.2 discipline: the
	// operator records the fingerprint from these very files), and the
	// status line names both files.
	pubRaw, err := os.ReadFile(filepath.Join(dir, "release.pub"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.TrimSpace(string(pubRaw)), pubHexOfSeed(t, seed); got != want {
		t.Fatalf("release.pub does not derive from release.seed: %s vs %s", got, want)
	}
	if kv(t, status, "seed") == "" || kv(t, status, "public") == "" {
		t.Fatalf("keygen status must name the files: %s", status)
	}
	// --force regenerates; without it a second run fails.
	mustFail(t, "refusing to overwrite", "capsule", "keygen", "--out", dir)
}

func TestCapsuleSignVerifyShowLifecycle(t *testing.T) {
	dir := t.TempDir()
	seedPath := seedFile(t, dir, "release.seed", vecReleaseSeed)
	pubPath := seedFile(t, dir, "release.pub", pubHexOfSeed(t, vecReleaseSeed))
	binPath := filepath.Join(dir, "dtn-node-fake")
	payload := strings.Repeat("OFGRID-RELEASE-BYTES-", 2000) // 42 KB synthetic build
	if err := os.WriteFile(binPath, []byte(payload), 0o644); err != nil {
		t.Fatal(err)
	}
	capPath := filepath.Join(dir, "offgrid-update-1012000-esp32s3.capsule")
	status := mustSucceed(t, "capsule", "sign",
		"--priv", seedPath, "--arch", "esp32s3",
		"--release", "1012000", "--semver", "v1.12.0",
		"--vcs", "v1.12.0-3-gdeadbeef", "--min-upgrade-from", "1009000",
		"--created-at", "1791072000",
		"--bin", binPath, "--out", capPath)
	if kv(t, status, "release") != "1012000" {
		t.Fatalf("sign status: %s", status)
	}

	// verify: full parse + sha + signature.
	vstatus := mustSucceed(t, "capsule", "verify", "--pub", pubPath, "--in", capPath,
		"--now", "1791072000")
	for _, key := range []string{"release", "arch", "payload_bytes", "created_at", "min_upgrade_from"} {
		if kv(t, vstatus, key) == "" {
			t.Fatalf("verify must print %s: %s", key, vstatus)
		}
	}
	if kv(t, vstatus, "arch") != "esp32s3" || kv(t, vstatus, "payload_bytes") != "42000" {
		t.Fatalf("verify fields: %s", vstatus)
	}

	// show: keyless inspection + the release-note fingerprint.
	show := mustSucceed(t, "capsule", "show", "--in", capPath)
	if len(kv(t, show, "capsule_sha256")) != 64 {
		t.Fatalf("show fingerprint: %s", show)
	}
	if kv(t, show, "spa_embedded") != "true" {
		t.Fatalf("spa_embedded must print true (§2.1.2 member 7)")
	}

	// The raw file IS the §2.1.1 layout.
	blob, err := os.ReadFile(capPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(blob[:8]) != capsule.Magic {
		t.Fatalf("magic: %q", blob[:8])
	}

	// Tamper: one payload byte, verify refuses.
	blob[len(blob)-65] ^= 0x01
	if err := os.WriteFile(capPath, blob, 0o644); err != nil {
		t.Fatal(err)
	}
	_, stderr, _ := runTool(t, "capsule", "verify", "--pub", pubPath, "--in", capPath)
	if !strings.Contains(stderr, "sha_mismatch") && !strings.Contains(stderr, "bad_signature") {
		t.Fatalf("tampered capsule must refuse with a stable code, got: %s", stderr)
	}
}

func TestCapsuleSignRefusals(t *testing.T) {
	dir := t.TempDir()
	seedPath := seedFile(t, dir, "release.seed", vecReleaseSeed)
	binPath := filepath.Join(dir, "bin")
	if err := os.WriteFile(binPath, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	// semver/release disagreement (§2.1.2 member 3 is asserted, never signed).
	_, stderr, _ := runTool(t, "capsule", "sign", "--priv", seedPath, "--bin", binPath,
		"--created-at", "1791072000", "--out", filepath.Join(dir, "x.capsule"),
		"--arch", "esp32s3", "--release", "1012001", "--semver", "v1.12.0")
	if !strings.Contains(stderr, "does not agree") {
		t.Fatalf("semver disagreement must refuse: %s", stderr)
	}
	// Foreign arch is refused by the SIGNER (the enum is a signing-time
	// assertion; verifiers stay tolerant for forward compatibility).
	_, stderr, _ = runTool(t, "capsule", "sign", "--priv", seedPath, "--bin", binPath,
		"--created-at", "1791072000", "--out", filepath.Join(dir, "x.capsule"),
		"--arch", "riscv", "--release", "1012000", "--semver", "v1.12.0")
	if !strings.Contains(stderr, "§9.1 enum") {
		t.Fatalf("foreign arch must refuse at sign time: %s", stderr)
	}
	// Both --bin and --payload-text (or neither) is a usage error.
	_, stderr, _ = runTool(t, "capsule", "sign", "--priv", seedPath,
		"--created-at", "1791072000", "--out", filepath.Join(dir, "x.capsule"),
		"--arch", "esp32s3", "--release", "1012000", "--semver", "v1.12.0")
	if !strings.Contains(stderr, "exactly one") {
		t.Fatalf("payload-source ambiguity must refuse: %s", stderr)
	}
	// make is an alias of sign.
	status := mustSucceed(t, "capsule", "make", "--priv", seedPath,
		"--arch", "arm64", "--release", "1012000", "--semver", "v1.12.0",
		"--payload-text", "tiny", "--out", filepath.Join(dir, "y.capsule"))
	if kv(t, status, "arch") != "arm64" {
		t.Fatalf("make alias: %s", status)
	}
}

func TestCapsuleVerifyWrongKey(t *testing.T) {
	dir := t.TempDir()
	seedPath := seedFile(t, dir, "release.seed", vecReleaseSeed)
	otherPub := seedFile(t, dir, "other.pub", pubHexOfSeed(t, vecOtherSeed))
	capPath := filepath.Join(dir, "c.capsule")
	mustSucceed(t, "capsule", "sign", "--priv", seedPath, "--arch", "esp32",
		"--release", "7", "--semver", "v0.0.7", "--payload-text", "x", "--out", capPath)
	_, stderr, _ := runTool(t, "capsule", "verify", "--pub", otherPub, "--in", capPath)
	if !strings.Contains(stderr, "bad_signature") {
		t.Fatalf("wrong key must refuse bad_signature: %s", stderr)
	}
}
