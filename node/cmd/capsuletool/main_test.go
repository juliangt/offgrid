package main

// Spawn tests for capsuletool: build the real binary once into a temp dir
// and drive the whole §2.6 ceremony through it — the same commands an
// operator types, asserted end to end. This is the host-runnable half of
// the §11 row-e integration (the on-hardware boot legs are P3.2+/P3.3
// field work: the Pi daemon wiring and the ESP32 NVS payload).

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"offgrid/dtn-node/internal/bundle"
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

// TestCertCommand exercises the §6.3 TCPCL/TLS certificate ceremony: the
// self-signed X.509 is derived from the node seed, carries the EID as CN
// and URI SAN, and regenerates deterministically per seed+validity (the
// deterministic serial and bindings; the wall-clock validity pair is
// second-granular). The PEM parses with the stdlib and verifies against
// its own public key.
func TestCertCommand(t *testing.T) {
	dir := t.TempDir()
	nodeSeed := seedFile(t, dir, "node.seed", vecNodeSeed)
	wantEID := eidOfPub(t, pubHexOfSeed(t, vecNodeSeed))

	// To --out: PEM file plus a clean status line on stdout.
	outPem := filepath.Join(dir, "node_cert.pem")
	status := mustSucceed(t, "cert", "--seed", nodeSeed, "--validity-hours", "24", "--out", outPem)
	if kv(t, status, "eid") != wantEID {
		t.Fatalf("status eid: %s", status)
	}
	certFP := kv(t, status, "cert_fp")
	if len(certFP) != 64 {
		t.Fatalf("cert_fp must be 64 hex chars, got %q", certFP)
	}
	if _, err := os.Stat(outPem); err != nil {
		t.Fatalf("pem file: %v", err)
	}
	raw, err := os.ReadFile(outPem)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(raw, []byte("-----BEGIN CERTIFICATE-----")) {
		t.Fatalf("the --out file must be PEM, got %q", raw[:32])
	}

	// The PEM parses; the certificate covers the seed's key and EID.
	pemBytes, _ := pem.Decode(raw)
	if pemBytes == nil {
		t.Fatalf("no PEM block in the file")
	}
	parsed, err := x509.ParseCertificate(pemBytes.Bytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.Subject.CommonName != wantEID {
		t.Fatalf("CN %q, want %q", parsed.Subject.CommonName, wantEID)
	}
	pub, err := nodeid.CertNodeKey(parsed)
	if err != nil {
		t.Fatalf("CertNodeKey: %v", err)
	}
	if hex.EncodeToString(pub) != pubHexOfSeed(t, vecNodeSeed) {
		t.Fatalf("the certificate must bind the seed's own key")
	}
	if err := nodeid.CertCoversEID(parsed, wantEID); err != nil {
		t.Fatalf("SAN binding: %v", err)
	}
	if d := parsed.NotAfter.Sub(parsed.NotBefore); d != 24*time.Hour+time.Hour {
		t.Fatalf("validity window %v (24 h + the 1 h backdate)", d)
	}
	// Self-signature verifies.
	if err := parsed.CheckSignature(parsed.SignatureAlgorithm, parsed.RawTBSCertificate, parsed.Signature); err != nil {
		t.Fatalf("self-signature: %v", err)
	}
	if got := nodeid.CertFingerprintHex(pemBytes.Bytes); got != certFP {
		t.Fatalf("cert_fp mismatch: %s vs %s", got, certFP)
	}

	// To stdout (no --out): the PEM stream is clean; the status line goes
	// to stderr so `capsuletool cert --seed F > node.pem` keeps working.
	stdout, stderr, code := runTool(t, "cert", "--seed", nodeSeed)
	if code != 0 {
		t.Fatalf("stdout mode failed: %s", stderr)
	}
	if !bytes.HasPrefix([]byte(stdout), []byte("-----BEGIN CERTIFICATE-----")) {
		t.Fatalf("stdout must carry the PEM, got %q", stdout[:32])
	}
	if !strings.Contains(stderr, "eid="+wantEID) {
		t.Fatalf("stderr must carry the status line, got %q", stderr)
	}

	// Determinism: the same seed + same validity window regenerate a
	// certificate with the identical deterministic serial, key and
	// bindings. The wall-clock NotBefore/NotAfter are second-granular, so
	// byte equality is only asserted when the two runs share a timestamp
	// pair — the semantic comparison below is the real invariant.
	again := filepath.Join(dir, "again.pem")
	mustSucceed(t, "cert", "--seed", nodeSeed, "--validity-hours", "24", "--out", again)
	againBytes, err := os.ReadFile(again)
	if err != nil {
		t.Fatal(err)
	}
	againPem, _ := pem.Decode(againBytes)
	if againPem == nil {
		t.Fatalf("no PEM block in the regeneration")
	}
	againCert, err := x509.ParseCertificate(againPem.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if againCert.SerialNumber.Cmp(parsed.SerialNumber) != 0 ||
		againCert.NotBefore.Equal(parsed.NotBefore) && !bytes.Equal(raw, againBytes) {
		t.Fatalf("the ceremony must be deterministic per seed+validity")
	}
	if !againCert.NotBefore.Equal(parsed.NotBefore) {
		// Different second of wall clock: the fields that ARE deterministic
		// must still match exactly.
		if againCert.Subject.CommonName != parsed.Subject.CommonName ||
			len(againCert.URIs) != 1 || againCert.URIs[0].String() != parsed.URIs[0].String() {
			t.Fatalf("regeneration diverged beyond the wall clock")
		}
	}

	// Argument honesty.
	mustFail(t, "not a positive number", "cert", "--seed", nodeSeed, "--validity-hours", "0")
	mustFail(t, "no such file", "cert", "--seed", filepath.Join(dir, "missing.seed"))
}

// TestBundleMake pins the P3.5 `bundle make` command: the P-4 anonymous
// mail shape, the printed bundle_id equal to the P-7 digest of the written
// PDU, run-time creation with the given TTL, and the honest argument
// errors. (The `bundle send` leg is the E2E's: tests/node_plane_e2e.sh
// drives it against three real daemons, and TestNodePlaneEndToEnd in the
// daemon package covers the wire against the real session engine.)
func TestBundleMake(t *testing.T) {
	dir := t.TempDir()
	pduPath := filepath.Join(dir, "cargo.pdu")

	stdout, stderr, code := runTool(t, "bundle", "make",
		"--out", pduPath, "--payload-text", "offgrid-test-cargo", "--ttl", "3600")
	if code != 0 {
		t.Fatalf("bundle make: %s", stderr)
	}
	_ = stderr
	raw, err := os.ReadFile(pduPath)
	if err != nil {
		t.Fatalf("read pdu: %v", err)
	}
	b, err := bundle.Parse(raw, time.Now())
	if err != nil {
		t.Fatalf("the minted PDU must parse as a profile bundle: %v", err)
	}
	if b.Destination.String() != "dtn:og-mail" || !b.Source.IsNone() {
		t.Fatalf("the minted bundle must be the P-4 anonymous mail shape, got %s → %s", b.Source, b.Destination)
	}
	if b.Hop != 0 || string(b.Payload) != "offgrid-test-cargo" {
		t.Fatalf("payload/hop mismatch: hop %d payload %q", b.Hop, b.Payload)
	}
	if b.Lifetime != 3600 {
		t.Fatalf("ttl %d, want 3600", b.Lifetime)
	}
	// Creation derives from run time (within a minute of the test's clock).
	createdUnix := int64(b.CreationDTNms)/1000 + bundle.DTNEpochUnixS
	if d := time.Since(time.Unix(createdUnix, 0)); d < -time.Minute || d > time.Minute {
		t.Fatalf("creation timestamp %d is not the run time (%v off)", createdUnix, d)
	}
	// The printed id IS the P-7 key of the written bytes.
	wantID, err := bundle.BundleIDOf(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "bundle_id="+hex.EncodeToString(wantID[:])) {
		t.Fatalf("stdout must carry the P-7 id, got %q", stdout)
	}

	// Deterministic for fixed inputs (--created-unix-ms).
	fixed := filepath.Join(dir, "fixed.pdu")
	mustSucceed(t, "bundle", "make", "--out", fixed,
		"--payload-text", "offgrid-test-cargo", "--ttl", "3600",
		"--created-unix-ms", "1791072000000")
	fixed2 := filepath.Join(dir, "fixed2.pdu")
	mustSucceed(t, "bundle", "make", "--out", fixed2,
		"--payload-text", "offgrid-test-cargo", "--ttl", "3600",
		"--created-unix-ms", "1791072000000")
	a, _ := os.ReadFile(fixed)
	bb, _ := os.ReadFile(fixed2)
	if !bytes.Equal(a, bb) {
		t.Fatalf("fixed inputs must produce byte-identical PDUs")
	}

	// A payload FILE works too.
	pl := filepath.Join(dir, "payload.bin")
	if err := os.WriteFile(pl, []byte("file-payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	mustSucceed(t, "bundle", "make", "--out", filepath.Join(dir, "fromfile.pdu"), "--payload", pl)

	// Argument honesty.
	mustFail(t, "exactly one of --payload-text", "bundle", "make", "--out", filepath.Join(dir, "x.pdu"))
	mustFail(t, "is not a positive number of seconds", "bundle", "make", "--out", filepath.Join(dir, "x.pdu"),
		"--payload-text", "x", "--ttl", "0")
	mustFail(t, "unknown subcommand", "bundle", "dance")
	_ = stdout
}
