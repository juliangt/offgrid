package main

// Spawn tests for capsuletool: build the real binary once into a temp dir
// and drive the whole §2.6 ceremony through it — the same commands an
// operator types, asserted end to end. This is the host-runnable half of
// the §11 row-e integration (the on-hardware boot legs are P3.2+/P3.3
// field work: the Pi daemon wiring and the ESP32 NVS payload).

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"offgrid/dtn-node/internal/nodeid"
)

var (
	toolOnce sync.Once
	toolPath string
	toolErr  error
)

// buildTool compiles capsuletool once per test run.
func buildTool(t *testing.T) string {
	t.Helper()
	toolOnce.Do(func() {
		dir, err := os.MkdirTemp("", "capsuletool-build-*")
		if err != nil {
			toolErr = err
			return
		}
		toolPath = filepath.Join(dir, "capsuletool")
		cmd := exec.Command("go", "build", "-o", toolPath, ".")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			toolErr = fmt.Errorf("go build: %w: %s", err, stderr.String())
		}
	})
	if toolErr != nil {
		t.Fatalf("build capsuletool: %v", toolErr)
	}
	return toolPath
}

func runTool(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	bin := buildTool(t)
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(bin, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	code := 0
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("run %v: %v", args, err)
		}
	}
	return stdout.String(), stderr.String(), code
}

func mustSucceed(t *testing.T, args ...string) string {
	t.Helper()
	stdout, stderr, code := runTool(t, args...)
	if code != 0 {
		t.Fatalf("%v failed (%d): %s", args, code, stderr)
	}
	return stdout
}

func mustFail(t *testing.T, wantErrIn string, args ...string) (string, string) {
	t.Helper()
	stdout, stderr, code := runTool(t, args...)
	if code == 0 {
		t.Fatalf("%v succeeded, want failure (stdout: %s)", args, stdout)
	}
	if wantErrIn != "" && !strings.Contains(stderr, wantErrIn) {
		t.Fatalf("%v: stderr %q lacks %q", args, stderr, wantErrIn)
	}
	return stdout, stderr
}

func kv(t *testing.T, out, key string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(line, "="); ok && k == key {
			return v
		}
	}
	t.Fatalf("output %q lacks key %q", out, key)
	return ""
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func seedFile(t *testing.T, dir, name, seedHex string) string {
	return writeFile(t, dir, name, seedHex+"\n")
}

// pubHexOfSeed derives the 64-hex public key of a seed through the same
// library the tool uses — the test knows the answers independently (RFC
// 8032 keys) and checks the ceremony against them.
func pubHexOfSeed(t *testing.T, seedHex string) string {
	t.Helper()
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		t.Fatal(err)
	}
	kp, err := nodeid.NewKeyPairFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(kp.Public)
}

// eidOfPub computes the expected EID of a 64-hex public key.
func eidOfPub(t *testing.T, pubHex string) string {
	t.Helper()
	pub, err := hex.DecodeString(pubHex)
	if err != nil {
		t.Fatal(err)
	}
	e, err := nodeid.EIDFromPub(pub)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// pairOfSeed returns the raw Ed25519 pair for a seed hex (tests only).
func pairOfSeed(t *testing.T, seedHex string) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		t.Fatal(err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return priv, priv.Public().(ed25519.PublicKey)
}

const (
	vecAnchorSeed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
	vecNodeSeed   = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
	vecNode2Seed  = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"
	// The fixed wall clock shared with the vector suite.
	vecNow = 1791072000
)

func TestAnchorKeygen(t *testing.T) {
	dir := t.TempDir()
	out := mustSucceed(t, "anchor", "keygen", "--out", dir)
	if kv(t, out, "eid") == "" {
		t.Fatal("no eid in keygen output")
	}
	seedStat, err := os.Stat(filepath.Join(dir, "anchor.seed"))
	if err != nil {
		t.Fatal(err)
	}
	if seedStat.Mode().Perm() != 0o600 {
		t.Fatalf("anchor.seed mode %v, want 0600", seedStat.Mode().Perm())
	}
	pubStat, err := os.Stat(filepath.Join(dir, "anchor.pub"))
	if err != nil {
		t.Fatal(err)
	}
	if pubStat.Mode().Perm() != 0o644 {
		t.Fatalf("anchor.pub mode %v, want 0644", pubStat.Mode().Perm())
	}
	// The seed file holds exactly 64 hex chars — what readSeedFile demands.
	seedBytes, err := os.ReadFile(filepath.Join(dir, "anchor.seed"))
	if err != nil {
		t.Fatal(err)
	}
	if len(strings.TrimSpace(string(seedBytes))) != 64 {
		t.Fatalf("seed file %q", seedBytes)
	}
	// Refuses overwrite without --force...
	_, stderr := mustFail(t, "refusing to overwrite", "anchor", "keygen", "--out", dir)
	if !strings.Contains(stderr, "anchor.seed") {
		t.Fatalf("stderr %q", stderr)
	}
	// ...and with --force it replaces them.
	mustSucceed(t, "anchor", "keygen", "--out", dir, "--force")
}

func TestRolecertKeygenAndID(t *testing.T) {
	dir := t.TempDir()
	mustSucceed(t, "rolecert", "keygen", "--out", dir)
	// id derives the EID from the seed: for the RFC 8032 TEST2 key the EID
	// is a public fact — pin it so the ceremony is anchored to a known key.
	seedPath := seedFile(t, dir, "fixed.seed", vecNodeSeed)
	out := mustSucceed(t, "rolecert", "id", "--seed", seedPath)
	wantEID := eidOfPub(t, pubHexOfSeed(t, vecNodeSeed))
	if got := kv(t, out, "eid"); got != wantEID {
		t.Fatalf("eid %s, want %s", got, wantEID)
	}
}

func TestFullCeremony(t *testing.T) {
	dir := t.TempDir()
	anchorSeed := seedFile(t, dir, "anchor.seed", vecAnchorSeed)
	nodeSeed := seedFile(t, dir, "node.seed", vecNodeSeed)

	// request: the unsigned payload the anchor operator reviews.
	req := mustSucceed(t, "rolecert", "request", "--seed", nodeSeed, "--roles", "edge,relay", "--level", "1")
	if kv(t, req, "roles") != "edge,relay" || kv(t, req, "level") != "1" {
		t.Fatalf("request: %s", req)
	}
	nodePub := writeFile(t, dir, "node.pub", kv(t, req, "node_key")+"\n")

	// sign: deterministic with fixed timestamps.
	certPath := filepath.Join(dir, "node_cert.cbor")
	issued := int64(vecNow - 3600)
	expires := issued + 90*86400
	mustSucceed(t, "rolecert", "sign",
		"--anchor-seed", anchorSeed, "--node-pub", nodePub,
		"--roles", "edge,relay", "--level", "1", "--seq", "1",
		"--issued-ts", strconv.FormatInt(issued, 10),
		"--expires-ts", strconv.FormatInt(expires, 10),
		"--out", certPath)
	cose, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(cose) < 100 || cose[0] != 0x84 {
		t.Fatalf("cert bytes: %d bytes, head % x", len(cose), cose[:1])
	}

	// verify (against the pinned anchor): happy path at the fixed clock.
	anchorPub := writeFile(t, dir, "anchor.pub", pubHexOfSeed(t, vecAnchorSeed)+"\n")
	vout := mustSucceed(t, "rolecert", "verify", "--anchor-pub", anchorPub, "--in", certPath,
		"--now", strconv.Itoa(vecNow))
	if kv(t, vout, "valid") != "true" || kv(t, vout, "eid") != kv(t, req, "eid") {
		t.Fatalf("verify: %s", vout)
	}
	if kv(t, vout, "roles") != "edge,relay" || kv(t, vout, "seq") != "1" {
		t.Fatalf("verify fields: %s", vout)
	}
	if got := kv(t, vout, "expires_ts"); got != strconv.FormatInt(expires, 10) {
		t.Fatalf("expires_ts %s", got)
	}

	// Determinism: the same inputs produce byte-identical certs (the shared
	// vector suite regenerates from exactly this property).
	cert2 := filepath.Join(dir, "node_cert2.cbor")
	mustSucceed(t, "rolecert", "sign",
		"--anchor-seed", anchorSeed, "--node-pub", nodePub,
		"--roles", "edge,relay", "--level", "1", "--seq", "1",
		"--issued-ts", strconv.FormatInt(issued, 10),
		"--expires-ts", strconv.FormatInt(expires, 10),
		"--out", cert2)
	again, err := os.ReadFile(cert2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cose, again) {
		t.Fatal("sign is not deterministic")
	}
}

func TestVerifyFailurePaths(t *testing.T) {
	dir := t.TempDir()
	anchorSeed := seedFile(t, dir, "anchor.seed", vecAnchorSeed)
	nodeSeed := seedFile(t, dir, "node.seed", vecNodeSeed)
	nodePub := writeFile(t, dir, "node.pub", pubHexOfSeed(t, vecNodeSeed)+"\n")
	anchorPub := writeFile(t, dir, "anchor.pub", pubHexOfSeed(t, vecAnchorSeed)+"\n")
	// A second anchor (a different pinned key) for the wrong-anchor case.
	_, otherPub := pairOfSeed(t, vecNode2Seed)
	otherAnchorPub := writeFile(t, dir, "other_anchor.pub", hex.EncodeToString(otherPub)+"\n")

	sign := func(out string, extra ...string) string {
		args := append([]string{"rolecert", "sign",
			"--anchor-seed", anchorSeed, "--node-pub", nodePub,
			"--roles", "edge", "--level", "1", "--seq", "1",
			"--issued-ts", strconv.Itoa(vecNow - 3600),
			"--expires-ts", strconv.Itoa(vecNow + 86400)}, extra...)
		args = append(args, "--out", out)
		mustSucceed(t, args...)
		return out
	}
	good := sign(filepath.Join(dir, "good.cbor"))

	// Happy baseline.
	mustSucceed(t, "rolecert", "verify", "--anchor-pub", anchorPub, "--in", good, "--now", strconv.Itoa(vecNow))

	// Bad signature: flip a bit in the signed payload (the last bstr before
	// the 64-byte signature, whose head+contents are the final 66 bytes).
	cose, err := os.ReadFile(good)
	if err != nil {
		t.Fatal(err)
	}
	bad := append([]byte(nil), cose...)
	bad[len(bad)-67] ^= 0x01
	badPath := writeFile(t, dir, "bad.cbor", string(bad))
	mustFail(t, "bad_signature", "rolecert", "verify", "--anchor-pub", anchorPub, "--in", badPath, "--now", strconv.Itoa(vecNow))

	// Wrong anchor: a different pinned key fails the kid check.
	mustFail(t, "wrong_anchor_fp", "rolecert", "verify", "--anchor-pub", otherAnchorPub, "--in", good, "--now", strconv.Itoa(vecNow))

	// Expired: same cert, later clock.
	expired := sign(filepath.Join(dir, "expired.cbor"),
		"--issued-ts", strconv.Itoa(vecNow-2*86400), "--expires-ts", strconv.Itoa(vecNow-3600))
	mustFail(t, "expired", "rolecert", "verify", "--anchor-pub", anchorPub, "--in", expired, "--now", strconv.Itoa(vecNow))

	// The CLI is stateless by design — staleness is a Cache (merge) property
	// and is unit-tested there. The seq validation the CLI does own is ≥ 1:
	mustFail(t, "seq", "rolecert", "sign",
		"--anchor-seed", anchorSeed, "--node-pub", nodePub,
		"--roles", "edge", "--level", "1", "--seq", "0",
		"--issued-ts", strconv.Itoa(vecNow-3600), "--expires-ts", strconv.Itoa(vecNow+86400))

	// Argument honesty: unknown role, bad level, missing/short files.
	mustFail(t, "not one of", "rolecert", "request", "--seed", nodeSeed, "--roles", "emperor", "--level", "1")
	mustFail(t, "ceiling", "rolecert", "request", "--seed", nodeSeed, "--roles", "edge", "--level", "9")
	mustFail(t, "want 64 hex", "rolecert", "id", "--seed", writeFile(t, dir, "short.seed", "abcd\n"))
	mustFail(t, "no such file", "rolecert", "id", "--seed", filepath.Join(dir, "missing.seed"))
	mustFail(t, "refusing to overwrite", "rolecert", "keygen", "--out", dir)
}

func TestSignDefaults(t *testing.T) {
	dir := t.TempDir()
	anchorSeed := seedFile(t, dir, "anchor.seed", vecAnchorSeed)
	nodePub := writeFile(t, dir, "node.pub", pubHexOfSeed(t, vecNodeSeed)+"\n")
	anchorPub := writeFile(t, dir, "anchor.pub", pubHexOfSeed(t, vecAnchorSeed)+"\n")
	// Without --issued-ts/--expires-ts: issued = now, expires = now+90d —
	// verifiable immediately (the skew rule has 300 s of slack).
	cert := filepath.Join(dir, "cert.cbor")
	mustSucceed(t, "rolecert", "sign",
		"--anchor-seed", anchorSeed, "--node-pub", nodePub,
		"--roles", "relay", "--level", "1", "--seq", "2", "--out", cert)
	vout := mustSucceed(t, "rolecert", "verify", "--anchor-pub", anchorPub, "--in", cert)
	if kv(t, vout, "valid") != "true" || kv(t, vout, "seq") != "2" {
		t.Fatalf("verify: %s", vout)
	}
	iss, err := strconv.ParseInt(kv(t, vout, "issued_ts"), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	exp, err := strconv.ParseInt(kv(t, vout, "expires_ts"), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Duration(exp-iss) * time.Second; d != 90*24*time.Hour {
		t.Fatalf("default lifetime %v", d)
	}
	if now := time.Now().Unix(); iss > now+300 || iss < now-300 {
		t.Fatalf("default issued_ts %d vs now %d", iss, now)
	}
	// stdout output (no --out) emits the raw CBOR.
	fixedSign := []string{"rolecert", "sign",
		"--anchor-seed", anchorSeed, "--node-pub", nodePub,
		"--roles", "relay", "--level", "1", "--seq", "2",
		"--issued-ts", strconv.Itoa(vecNow - 3600), "--expires-ts", strconv.Itoa(vecNow + 86400)}
	stdout := mustSucceed(t, fixedSign...)
	if len(stdout) == 0 || stdout[0] != 0x84 {
		t.Fatalf("stdout cert head % x", stdout[:1])
	}
	// ...byte-identical to --out for the same inputs.
	ref := filepath.Join(dir, "ref.cbor")
	mustSucceed(t, append(fixedSign, "--out", ref)...)
	refBytes, err := os.ReadFile(ref)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(hex.EncodeToString([]byte(stdout)), hex.EncodeToString(refBytes)) {
		t.Fatal("stdout bytes differ from --out bytes")
	}
}
