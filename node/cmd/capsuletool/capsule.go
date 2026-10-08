package main

// capsule.go — the RELEASE-key ceremony of capsule format v1
// (docs/offline-maintenance.md §2.1/§2.2, reused verbatim by the node plane
// per docs/node-network.md §9; issue #33 P3.7). A SECOND pinned Ed25519 key
// beside the anchor: the anchor key signs role certificates (COSE_Sign1,
// cmd/rolecert.go); the release key signs release capsules (a detached
// signature over meta ‖ payload, internal/capsule). Neither key verifies
// the other's artifacts — key separation is a pinned property (§2.2/§2.7:
// the compromise analyses are per-key).
//
//	capsuletool capsule keygen --out DIR [--force]
//	    32-byte Ed25519 release seed + public key (release.seed 0600 /
//	    release.pub). Air-gapped machine, two offline copies (§2.2.1).
//
//	capsuletool capsule sign --priv F --arch A --release N --semver TAG
//	              [--vcs REV] [--min-upgrade-from N] [--created-at T]
//	              (--bin F | --payload-text S) [--out F]   (alias: make)
//	    Builds and signs the §2.1.1 capsule from a release binary. Refuses
//	    to sign when semver disagrees with --release (§2.1.2 member 3) or
//	    the arch is outside the §9.1 enum. One capsule per target arch.
//
//	capsuletool capsule verify --pub F --in F [--now T]
//	    Full §2.4.4 steps 1-2: parse, payload SHA-256, Ed25519 signature.
//	    Prints the fields; nonzero exit on any refusal.
//
//	capsuletool capsule show --in F
//	    Inspect without a key: the metadata block, the payload fingerprint
//	    and the capsule's own SHA-256 (the §2.2.2 release-note entry).

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"offgrid/dtn-node/internal/capsule"
)

func cmdCapsule(args []string, out, errw io.Writer) int {
	if len(args) == 0 {
		return fatalf(errw, "capsule: want subcommand keygen|sign|verify|show")
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
		return keygen(dir, "release", f.has("force"), out, errw)
	case "sign", "make":
		return capsuleSign(args[1:], out, errw)
	case "verify":
		return capsuleVerify(args[1:], out, errw)
	case "show":
		return capsuleShow(args[1:], out, errw)
	default:
		return fatalf(errw, "capsule: unknown subcommand %q", args[0])
	}
}

func capsuleSign(args []string, out, errw io.Writer) int {
	f, code := parseFlags(args, errw, map[string]bool{
		"priv": true, "arch": true, "release": true, "semver": true,
		"vcs": true, "min-upgrade-from": true, "created-at": true,
		"bin": true, "payload-text": true, "out": true,
	})
	if code >= 0 {
		return code
	}
	privPath, code := f.req(errw, "priv")
	if code >= 0 {
		return code
	}
	archArg, code := f.req(errw, "arch")
	if code >= 0 {
		return code
	}
	releaseArg, code := f.req(errw, "release")
	if code >= 0 {
		return code
	}
	semverArg, code := f.req(errw, "semver")
	if code >= 0 {
		return code
	}
	if (f.has("bin") && f.has("payload-text")) || (!f.has("bin") && !f.has("payload-text")) {
		return fatalf(errw, "capsule sign: exactly one of --bin F | --payload-text S is required")
	}
	seed, err := readSeedFile(privPath)
	if err != nil {
		return fatalf(errw, "%v", err)
	}
	release, err := parseU64(releaseArg)
	if err != nil {
		return fatalf(errw, "--release: %v", err)
	}
	if !capsule.ValidArch(archArg) {
		return fatalf(errw, "--arch %q is outside the §9.1 enum (armv6|armv7|arm64|esp32s3|esp32)", archArg)
	}
	// §2.1.2 member 3: the display tag MUST agree with the ordering integer
	// (the formula is frozen for format v1). The signer asserts it — a
	// disagreeing pair is refused, never signed.
	derived, ok := releaseFromSemverTag(semverArg)
	if !ok || derived != release {
		return fatalf(errw, "--semver %q does not agree with --release %d (v1 formula: major*1_000_000+minor*1_000+patch = %d)", semverArg, release, derived)
	}
	var payload []byte
	if p := f["bin"]; p != "" {
		if payload, err = os.ReadFile(p); err != nil {
			return fatalf(errw, "%v", err)
		}
	} else {
		payload = []byte(f["payload-text"])
	}
	minUpgrade := uint64(0)
	if v, ok := f["min-upgrade-from"]; ok {
		if minUpgrade, err = parseU64(v); err != nil {
			return fatalf(errw, "--min-upgrade-from: %v", err)
		}
	}
	createdAt := time.Now().Unix()
	if v, ok := f["created-at"]; ok {
		if createdAt, err = parseUnix(v); err != nil {
			return fatalf(errw, "--created-at: %v", err)
		}
	}
	sum := sha256.Sum256(payload)
	meta := capsule.Metadata{
		V:              capsule.FormatV1,
		Release:        release,
		Semver:         semverArg,
		VCS:            f["vcs"],
		Arch:           archArg,
		MinUpgradeFrom: minUpgrade,
		SPAEmbedded:    true,
		PayloadSHA256:  hex.EncodeToString(sum[:]),
		PayloadBytes:   len(payload),
		CreatedAt:      createdAt,
	}
	blob, err := capsule.Build(seed, meta, payload)
	if err != nil {
		return fatalf(errw, "refusing to sign: %v", err)
	}
	if p, ok := f["out"]; ok {
		if err := os.WriteFile(p, blob, 0o644); err != nil {
			return fatalf(errw, "%v", err)
		}
		fmt.Fprintf(out, "wrote=%s\nbytes=%d\nrelease=%d\narch=%s\ncapsule_sha256=%s\n",
			p, len(blob), release, archArg, capsule.FingerprintHex(blob))
		return exitOK
	}
	if _, err := out.Write(blob); err != nil {
		return fatalf(errw, "%v", err)
	}
	return exitOK
}

// releaseFromSemverTag parses "v1.12.0" / "1.12.0" into the frozen §2.1.2
// formula value. ok is false for anything the formula cannot represent.
func releaseFromSemverTag(tag string) (uint64, bool) {
	tag = strings.TrimPrefix(tag, "v")
	parts := strings.Split(tag, ".")
	if len(parts) != 3 {
		return 0, false
	}
	var n [3]uint64
	for i, p := range parts {
		if p == "" || len(p) > 6 {
			return 0, false
		}
		for _, c := range []byte(p) {
			if c < '0' || c > '9' {
				return 0, false
			}
			n[i] = n[i]*10 + uint64(c-'0')
		}
	}
	return capsule.ReleaseFromSemver(int(n[0]), int(n[1]), int(n[2])), true
}

func parseU64(s string) (uint64, error) {
	var v uint64
	if _, err := fmt.Sscanf(s, "%d", &v); err != nil {
		return 0, fmt.Errorf("%q is not a number", s)
	}
	return v, nil
}

func capsuleVerify(args []string, out, errw io.Writer) int {
	f, code := parseFlags(args, errw, map[string]bool{"pub": true, "in": true, "now": true})
	if code >= 0 {
		return code
	}
	pubPath, code := f.req(errw, "pub")
	if code >= 0 {
		return code
	}
	inPath, code := f.req(errw, "in")
	if code >= 0 {
		return code
	}
	pub, err := readPubFile(pubPath)
	if err != nil {
		return fatalf(errw, "%v", err)
	}
	blob, err := os.ReadFile(inPath)
	if err != nil {
		return fatalf(errw, "%v", err)
	}
	c, err := capsule.Parse(blob)
	if err != nil {
		if code := capsule.ErrorCode(err); code != "" {
			return fatalf(errw, "invalid capsule [%s]: %v", code, err)
		}
		return fatalf(errw, "invalid capsule: %v", err)
	}
	if err := c.Verify(pub); err != nil {
		if code := capsule.ErrorCode(err); code != "" {
			return fatalf(errw, "invalid capsule [%s]: %v", code, err)
		}
		return fatalf(errw, "invalid capsule: %v", err)
	}
	// The §2.1.2 skew check is a STAGING-side rule (against a node's local
	// clock, §2.4.4 step 6); verify reports created_at and, with --now,
	// flags a future stamp the way a node would see it.
	skew := ""
	if v, ok := f["now"]; ok {
		var now int64
		if now, err = parseUnix(v); err != nil {
			return fatalf(errw, "--now: %v", err)
		}
		if c.Meta.CreatedAt > now+int64(capsule.MaxCreatedSkew/time.Second) {
			skew = "created_at_skew=more-than-300s-ahead"
		}
	}
	printCapsuleFields(out, c)
	if skew != "" {
		fmt.Fprintf(out, "%s\n", skew)
	}
	return exitOK
}

func capsuleShow(args []string, out, errw io.Writer) int {
	f, code := parseFlags(args, errw, map[string]bool{"in": true})
	if code >= 0 {
		return code
	}
	inPath, code := f.req(errw, "in")
	if code >= 0 {
		return code
	}
	blob, err := os.ReadFile(inPath)
	if err != nil {
		return fatalf(errw, "%v", err)
	}
	c, err := capsule.Parse(blob)
	if err != nil {
		if code := capsule.ErrorCode(err); code != "" {
			return fatalf(errw, "invalid capsule [%s]: %v", code, err)
		}
		return fatalf(errw, "invalid capsule: %v", err)
	}
	printCapsuleFields(out, c)
	fmt.Fprintf(out, "capsule_sha256=%s\n", capsule.FingerprintHex(blob))
	return exitOK
}

func printCapsuleFields(out io.Writer, c *capsule.Capsule) {
	fmt.Fprintf(out, "valid_shape=true\nv=%d\nrelease=%d\nsemver=%s\nvcs=%s\narch=%s\nmin_upgrade_from=%d\nspa_embedded=%t\npayload_sha256=%s\npayload_bytes=%d\ncreated_at=%d\n",
		c.Meta.V, c.Meta.Release, c.Meta.Semver, c.Meta.VCS, c.Meta.Arch,
		c.Meta.MinUpgradeFrom, c.Meta.SPAEmbedded, c.Meta.PayloadSHA256,
		c.Meta.PayloadBytes, c.Meta.CreatedAt)
}
