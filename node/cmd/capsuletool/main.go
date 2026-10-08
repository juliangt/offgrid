// capsuletool — the offline identity and capsule ceremonies of the
// off-grid DTN node (docs/node-network.md §2.6; the capsule family of
// docs/offline-maintenance.md §2 lands with its own implementing issue).
//
// This binary is deliberately boring: deterministic flags in, files/bytes
// out, no network, no prompts, Unix-honest permissions (seeds 0600).
// Every command is scriptable and prints stable key=value lines or raw
// bytes; any failure prints one stderr line and exits nonzero.
//
// Commands (issue #33 P3.1 — the rolecert family and the anchor keygen):
//
//	capsuletool anchor keygen --out DIR [--force]
//	    32-byte Ed25519 anchor seed + public key (anchor.seed 0600 / anchor.pub).
//	    The anchor is the offline trust root: run this on an air-gapped machine
//	    and keep two copies of the seed (offline-maintenance §2.2 discipline).
//
//	capsuletool rolecert keygen --out DIR [--force]
//	    A node's key pair (node.seed 0600 / node.pub).
//
//	capsuletool rolecert request --seed FILE --roles edge,relay --level N
//	    Prints the unsigned cert payload fields — the request the offline
//	    anchor operator reviews before signing.
//
//	capsuletool rolecert sign --anchor-seed F --node-pub F --roles edge,relay
//	                          --level N --seq N [--issued-ts T] [--expires-ts T]
//	                          [--out FILE]
//	    Builds and signs the COSE_Sign1 role certificate; raw CBOR to stdout
//	    or --out. Defaults: issued now, expires now+90d.
//
//	capsuletool rolecert verify --anchor-pub F --in FILE [--now T]
//	    Verifies against the pinned anchor public key; prints the fields and
//	    the derived EID; nonzero exit on any failure.
//
//	capsuletool rolecert id --seed FILE
//	    Prints the node's self-certifying EID (dtn://og.<fp>/).
//
//	capsuletool cert --seed FILE [--validity-hours H] [--out FILE]
//	    Builds the node's self-signed X.509 certificate for the TCPCL/TLS
//	    plane (node-network §6.2 item 4, §6.3): the Ed25519 node key bound
//	    to its EID (CN + URI SAN), PureEd25519-signed, PEM to stdout or
//	    --out (0644). Prints eid= and cert_fp= (the certificate's own
//	    SHA-256, distinct from the node fingerprint the PinStore pins).
//	    Deterministic per seed and validity window.
package main

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"offgrid/dtn-node/internal/nodeid"
)

const (
	exitOK      = 0
	exitFailure = 1
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, _ io.Reader, out, errw io.Writer) int {
	if len(args) == 0 {
		usage(errw)
		return exitFailure
	}
	switch args[0] {
	case "anchor":
		return cmdAnchor(args[1:], out, errw)
	case "rolecert":
		return cmdRolecert(args[1:], out, errw)
	case "cert":
		return cmdCert(args[1:], out, errw)
	case "bundle":
		return cmdBundle(args[1:], out, errw)
	case "admin":
		return cmdAdmin(args[1:], out, errw)
	case "-h", "--help", "help":
		usage(out)
		return exitOK
	default:
		fmt.Fprintf(errw, "capsuletool: unknown command %q\n", args[0])
		usage(errw)
		return exitFailure
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `usage: capsuletool COMMAND [flags]

identity ceremonies (docs/node-network.md §2.6):
  anchor keygen --out DIR [--force]            anchor.seed (0600) + anchor.pub
  rolecert keygen --out DIR [--force]          node.seed (0600) + node.pub
  rolecert request --seed F --roles R --level N
                                               print the unsigned request
  rolecert sign --anchor-seed F --node-pub F --roles R --level N --seq N
                [--issued-ts T] [--expires-ts T] [--out F]
                                               sign the COSE_Sign1 cert
  rolecert verify --anchor-pub F --in F [--now T]
                                               verify + print fields + EID
  rolecert id --seed F                         print the node EID

roles: edge, relay, bridge, manager, anchor (docs/node-network.md §2.3)
levels: 0 telemetry, 1 operations, 2 administration, 3 ownership (§2.4)

tcpcl/tls plane (node-network §6.3):
  cert --seed F [--validity-hours H] [--out F]  self-signed X.509 (PEM) + eid + cert_fp

node plane (node-network §6.3/§7.1, issue #33 P3.5):
  bundle make --out F (--payload-text S | --payload F) [--ttl S]
              [--created-unix-ms T]   encode an anonymous mail bundle (P-4)
                                      and print its bundle_id=
  bundle send --host H:PORT --pdu F --seed F
              (--pins F | --insecure-skip-pin) [--timeout S]
              one-shot TCPCLv4 contact: TLS 1.3, mTLS, TOFU pin (--pins is
              the SAME store the daemon keeps; --insecure-skip-pin is the
              explicit loopback-only escape hatch), one bundle transfer,
              graceful termination. Prints peer=, bundle_id= (the P-7
              dedup key the receiving store rows are keyed by), bytes=.

management plane (node-network §8, issue #33 P3.6):
  admin sign --seed F --cmd NAME [--args JSON] [--target EID] [--cert F]
             [--issued-ts T] [--expiry T] --seq N [--out F]
             sign one §8.1 admin command (authority = the signer's cached
             role cert on the receivers; install_cert carries an ALREADY
             ANCHOR-SIGNED cert via --cert). Defaults: issued now,
             expires now+1h. The command's level gate is the v1 table.
  admin show --in F          shape-parse a signed command, print its fields
`)
}

func fatalf(errw io.Writer, format string, a ...any) int {
	fmt.Fprintf(errw, "capsuletool: "+format+"\n", a...)
	return exitFailure
}

// --- flag plumbing -----------------------------------------------------------
// spec maps flag name -> takesValue. Value-less flags (e.g. --force) are
// recorded as "true" and never swallow the next argument.

type flags map[string]string

func parseFlags(args []string, errw io.Writer, spec map[string]bool) (flags, int) {
	f := flags{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "--") {
			return nil, fatalf(errw, "unexpected argument %q (flags only)", a)
		}
		name := strings.TrimPrefix(a, "--")
		takes, known := spec[name]
		if !known {
			return nil, fatalf(errw, "unknown flag --%s", name)
		}
		if !takes {
			f[name] = "true"
			continue
		}
		if i+1 >= len(args) {
			return nil, fatalf(errw, "flag --%s needs a value", name)
		}
		f[name] = args[i+1]
		i++
	}
	return f, -1
}

func (f flags) req(errw io.Writer, name string) (string, int) {
	v, ok := f[name]
	if !ok || v == "" {
		return "", fatalf(errw, "missing required --%s", name)
	}
	return v, -1
}

// --- keygen (anchor + node share one implementation) ------------------------

func cmdAnchor(args []string, out, errw io.Writer) int {
	if len(args) == 0 || args[0] != "keygen" {
		return fatalf(errw, "anchor: want subcommand keygen")
	}
	f, code := parseFlags(args[1:], errw, map[string]bool{"out": true, "force": false})
	if code >= 0 {
		return code
	}
	dir, code := f.req(errw, "out")
	if code >= 0 {
		return code
	}
	return keygen(dir, "anchor", f.has("force"), out, errw)
}

func (f flags) has(name string) bool {
	_, ok := f[name]
	return ok
}

func keygen(dir, prefix string, force bool, out, errw io.Writer) int {
	kp, err := nodeid.GenerateKeyPair()
	if err != nil {
		return fatalf(errw, "keygen: %v", err)
	}
	seedPath := filepath.Join(dir, prefix+".seed")
	pubPath := filepath.Join(dir, prefix+".pub")
	for _, p := range []string{seedPath, pubPath} {
		if _, err := os.Stat(p); err == nil && !force {
			return fatalf(errw, "%s exists (refusing to overwrite without --force)", p)
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fatalf(errw, "%v", err)
	}
	if err := os.WriteFile(seedPath, []byte(hex.EncodeToString(kp.Private.Seed())+"\n"), 0o600); err != nil {
		return fatalf(errw, "%v", err)
	}
	if err := os.WriteFile(pubPath, []byte(hex.EncodeToString(kp.Public)+"\n"), 0o644); err != nil {
		return fatalf(errw, "%v", err)
	}
	fmt.Fprintf(out, "seed=%s\npublic=%s\neid=%s\n", seedPath, pubPath, mustEID(kp.Public))
	return exitOK
}

func mustEID(pub []byte) string {
	e, err := nodeid.EIDFromPub(pub)
	if err != nil {
		return "(invalid key)"
	}
	return e
}

// readSeedFile reads a 32-byte seed from a hex file (whitespace/newline
// tolerated; comments not — the ceremony files have exactly one line).
func readSeedFile(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	hx := strings.TrimSpace(string(raw))
	if len(hx) != 64 {
		return nil, fmt.Errorf("%s: want 64 hex chars (32 bytes), got %d chars", path, len(hx))
	}
	seed, err := hex.DecodeString(hx)
	if err != nil {
		return nil, fmt.Errorf("%s: not hex: %v", path, err)
	}
	return seed, nil
}

func readPubFile(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	hx := strings.TrimSpace(string(raw))
	if len(hx) != 64 {
		return nil, fmt.Errorf("%s: want 64 hex chars (32 bytes), got %d chars", path, len(hx))
	}
	pub, err := hex.DecodeString(hx)
	if err != nil {
		return nil, fmt.Errorf("%s: not hex: %v", path, err)
	}
	return pub, nil
}

// --- rolecert ----------------------------------------------------------------

func cmdRolecert(args []string, out, errw io.Writer) int {
	if len(args) == 0 {
		return fatalf(errw, "rolecert: want subcommand keygen|request|sign|verify|id")
	}
	switch args[0] {
	case "keygen":
		f, code := parseFlags(args[1:], errw, map[string]bool{"out": true, "force": false})
		if code >= 0 {
			return code
		}
		dir, code := f.req(errw, "out")
		if code >= 0 {
			return code
		}
		return keygen(dir, "node", f.has("force"), out, errw)
	case "request":
		return rolecertRequest(args[1:], out, errw)
	case "sign":
		return rolecertSign(args[1:], out, errw)
	case "verify":
		return rolecertVerify(args[1:], out, errw)
	case "id":
		return rolecertID(args[1:], out, errw)
	default:
		return fatalf(errw, "rolecert: unknown subcommand %q", args[0])
	}
}

// parseRoleList validates the --roles comma list against the closed §2.3
// set. The literal "none" (or an empty value) means NO roles — the §2.5
// rule-4 revocation record, which must carry --level 0.
func parseRoleList(s string) ([]string, error) {
	var roles []string
	for _, r := range strings.Split(s, ",") {
		r = strings.TrimSpace(r)
		if r == "" || r == "none" {
			continue
		}
		if !nodeid.ValidRoles[r] {
			return nil, fmt.Errorf("role %q is not one of edge|relay|bridge|manager|anchor (or \"none\" for a revocation)", r)
		}
		roles = append(roles, r)
	}
	return roles, nil
}

func parseLevel(s string) (uint64, error) {
	var level uint64
	if _, err := fmt.Sscanf(s, "%d", &level); err != nil {
		return 0, fmt.Errorf("level %q is not a number", s)
	}
	if level > nodeid.MaxLevel {
		return 0, fmt.Errorf("level %d exceeds the ceiling 3", level)
	}
	return level, nil
}

func parseSeq(s string) (uint64, error) {
	var seq uint64
	if _, err := fmt.Sscanf(s, "%d", &seq); err != nil {
		return 0, fmt.Errorf("seq %q is not a number", s)
	}
	if seq < 1 {
		return 0, fmt.Errorf("seq must be ≥ 1")
	}
	return seq, nil
}

func rolecertRequest(args []string, out, errw io.Writer) int {
	f, code := parseFlags(args, errw, map[string]bool{"seed": true, "roles": true, "level": true})
	if code >= 0 {
		return code
	}
	seedPath, code := f.req(errw, "seed")
	if code >= 0 {
		return code
	}
	rolesArg, code := f.req(errw, "roles")
	if code >= 0 {
		return code
	}
	levelArg, code := f.req(errw, "level")
	if code >= 0 {
		return code
	}
	seed, err := readSeedFile(seedPath)
	if err != nil {
		return fatalf(errw, "%v", err)
	}
	kp, err := nodeid.NewKeyPairFromSeed(seed)
	if err != nil {
		return fatalf(errw, "%v", err)
	}
	roles, err := parseRoleList(rolesArg)
	if err != nil {
		return fatalf(errw, "%v", err)
	}
	level, err := parseLevel(levelArg)
	if err != nil {
		return fatalf(errw, "%v", err)
	}
	// The request is the unsigned payload — everything the anchor operator
	// reviews. The binding check (EID from this key) is exactly what makes
	// the request unfakeable.
	eid, err := nodeid.EIDFromPub(kp.Public)
	if err != nil {
		return fatalf(errw, "%v", err)
	}
	fmt.Fprintf(out, "eid=%s\nnode_key=%s\nroles=%s\nlevel=%d\n",
		eid, hex.EncodeToString(kp.Public), strings.Join(roles, ","), level)
	return exitOK
}

func rolecertSign(args []string, out, errw io.Writer) int {
	f, code := parseFlags(args, errw, map[string]bool{
		"anchor-seed": true, "node-pub": true, "roles": true, "level": true,
		"seq": true, "issued-ts": true, "expires-ts": true, "out": true,
	})
	if code >= 0 {
		return code
	}
	anchorSeedPath, code := f.req(errw, "anchor-seed")
	if code >= 0 {
		return code
	}
	nodePubPath, code := f.req(errw, "node-pub")
	if code >= 0 {
		return code
	}
	rolesArg, code := f.req(errw, "roles")
	if code >= 0 {
		return code
	}
	levelArg, code := f.req(errw, "level")
	if code >= 0 {
		return code
	}
	seqArg, code := f.req(errw, "seq")
	if code >= 0 {
		return code
	}
	seed, err := readSeedFile(anchorSeedPath)
	if err != nil {
		return fatalf(errw, "%v", err)
	}
	anchor, err := nodeid.NewKeyPairFromSeed(seed)
	if err != nil {
		return fatalf(errw, "%v", err)
	}
	nodePub, err := readPubFile(nodePubPath)
	if err != nil {
		return fatalf(errw, "%v", err)
	}
	roles, err := parseRoleList(rolesArg)
	if err != nil {
		return fatalf(errw, "%v", err)
	}
	level, err := parseLevel(levelArg)
	if err != nil {
		return fatalf(errw, "%v", err)
	}
	seq, err := parseSeq(seqArg)
	if err != nil {
		return fatalf(errw, "%v", err)
	}
	now := time.Now().Unix()
	issued := now
	if v, ok := f["issued-ts"]; ok {
		if issued, err = parseUnix(v); err != nil {
			return fatalf(errw, "--issued-ts: %v", err)
		}
	}
	expires := issued + int64(nodeid.DefaultCertLifetime/time.Second)
	if v, ok := f["expires-ts"]; ok {
		if expires, err = parseUnix(v); err != nil {
			return fatalf(errw, "--expires-ts: %v", err)
		}
	}
	eid, err := nodeid.EIDFromPub(nodePub)
	if err != nil {
		return fatalf(errw, "%v", err)
	}
	cose, err := nodeid.SignCert(anchor, nodePub, eid, roles, level, issued, expires, seq, now)
	if err != nil {
		return fatalf(errw, "refusing to sign: %v", err)
	}
	if p, ok := f["out"]; ok {
		if err := os.WriteFile(p, cose, 0o644); err != nil {
			return fatalf(errw, "%v", err)
		}
		fmt.Fprintf(out, "wrote=%s\nbytes=%d\neid=%s\nseq=%d\n", p, len(cose), eid, seq)
	} else {
		if _, err := out.Write(cose); err != nil {
			return fatalf(errw, "%v", err)
		}
	}
	return exitOK
}

func parseUnix(s string) (int64, error) {
	var v int64
	if _, err := fmt.Sscanf(s, "%d", &v); err != nil {
		return 0, fmt.Errorf("%q is not a unix timestamp", s)
	}
	if v <= 0 {
		return 0, fmt.Errorf("timestamp must be > 0")
	}
	return v, nil
}

func rolecertVerify(args []string, out, errw io.Writer) int {
	f, code := parseFlags(args, errw, map[string]bool{"anchor-pub": true, "in": true, "now": true})
	if code >= 0 {
		return code
	}
	anchorPubPath, code := f.req(errw, "anchor-pub")
	if code >= 0 {
		return code
	}
	inPath, code := f.req(errw, "in")
	if code >= 0 {
		return code
	}
	anchorPub, err := readPubFile(anchorPubPath)
	if err != nil {
		return fatalf(errw, "%v", err)
	}
	cose, err := os.ReadFile(inPath)
	if err != nil {
		return fatalf(errw, "%v", err)
	}
	now := time.Now().Unix()
	if v, ok := f["now"]; ok {
		if now, err = parseUnix(v); err != nil {
			return fatalf(errw, "--now: %v", err)
		}
	}
	c, err := nodeid.VerifyCert(cose, anchorPub, now)
	if err != nil {
		if code := nodeid.ErrorCode(err); code != "" {
			return fatalf(errw, "invalid certificate [%s]: %v", code, err)
		}
		return fatalf(errw, "invalid certificate: %v", err)
	}
	anchorFP := nodeid.Fingerprint(anchorPub)
	fmt.Fprintf(out, "valid=true\neid=%s\nnode_key=%s\nroles=%s\nlevel=%d\nissued_ts=%d\nexpires_ts=%d\nseq=%d\nanchor_fp=%s\n",
		c.EID, hex.EncodeToString(c.NodeKey), strings.Join(c.Roles, ","), c.Level,
		c.IssuedTS, c.ExpiresTS, c.Seq, hex.EncodeToString(anchorFP[:]))
	return exitOK
}

func rolecertID(args []string, out, errw io.Writer) int {
	f, code := parseFlags(args, errw, map[string]bool{"seed": true})
	if code >= 0 {
		return code
	}
	seedPath, code := f.req(errw, "seed")
	if code >= 0 {
		return code
	}
	seed, err := readSeedFile(seedPath)
	if err != nil {
		return fatalf(errw, "%v", err)
	}
	kp, err := nodeid.NewKeyPairFromSeed(seed)
	if err != nil {
		return fatalf(errw, "%v", err)
	}
	eid, err := nodeid.EIDFromPub(kp.Public)
	if err != nil {
		return fatalf(errw, "%v", err)
	}
	fmt.Fprintf(out, "eid=%s\n", eid)
	return exitOK
}

// --- cert (the TCPCL/TLS plane certificate, node-network §6.3) --------------

func cmdCert(args []string, out, errw io.Writer) int {
	f, code := parseFlags(args, errw, map[string]bool{"seed": true, "validity-hours": true, "out": true})
	if code >= 0 {
		return code
	}
	seedPath, code := f.req(errw, "seed")
	if code >= 0 {
		return code
	}
	seed, err := readSeedFile(seedPath)
	if err != nil {
		return fatalf(errw, "%v", err)
	}
	kp, err := nodeid.NewKeyPairFromSeed(seed)
	if err != nil {
		return fatalf(errw, "%v", err)
	}
	eid, err := nodeid.EIDFromPub(kp.Public)
	if err != nil {
		return fatalf(errw, "%v", err)
	}
	validity := nodeid.DefaultCertValidity
	if v, ok := f["validity-hours"]; ok {
		var hours int64
		if _, err := fmt.Sscanf(v, "%d", &hours); err != nil || hours <= 0 {
			return fatalf(errw, "--validity-hours %q is not a positive number of hours", v)
		}
		validity = time.Duration(hours) * time.Hour
	}
	cert, err := nodeid.SelfSignedX509(kp, eid, validity)
	if err != nil {
		return fatalf(errw, "%v", err)
	}
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	if p, ok := f["out"]; ok {
		if err := os.WriteFile(p, pemBlock, 0o644); err != nil {
			return fatalf(errw, "%v", err)
		}
	} else {
		if _, err := out.Write(pemBlock); err != nil {
			return fatalf(errw, "%v", err)
		}
	}
	// The status line goes to stderr when the PEM goes to stdout, so the
	// PEM stream stays clean for `>` redirection; to a file, stdout is free.
	status := io.Writer(out)
	if _, ok := f["out"]; !ok {
		status = errw
	}
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fatalf(errw, "parse own certificate: %v", err)
	}
	fmt.Fprintf(status, "eid=%s\ncert_fp=%s\nnot_after=%s\n",
		eid, nodeid.CertFingerprintHex(cert.Certificate[0]), parsed.NotAfter.UTC().Format(time.RFC3339))
	return exitOK
}
