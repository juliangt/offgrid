// admin.go — capsuletool's management-plane ceremonies (docs/node-network.md
// §8; issue #33 P3.6):
//
//	capsuletool admin sign --seed F --cmd NAME [--args JSON] [--target EID]
//	                        [--cert FILE] [--issued-ts T] [--expiry T]
//	                        [--seq N] [--out F]
//	    Signs one §8.1 admin command with a node's key. The signer's AUTHORITY
//	    is its cached role certificate on the receiving nodes — this tool
//	    signs, it does not grant: a node whose cert carries L1 gets its L2
//	    commands dropped and counted island-wide. install_cert carries an
//	    ALREADY ANCHOR-SIGNED certificate (--cert FILE, the rolecert sign
//	    output): issuance stays an offline anchor ceremony, this command only
//	    distributes/installs it.
//
//	capsuletool admin show --in F
//	    Shape-parses a signed command object and prints its fields (the
//	    operator's inspection tool; no keys touched, no verification — the
//	    signer's cert lives in the nodes' caches, not on the operator's desk).
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"time"

	"offgrid/dtn-node/internal/mgmt"
	"offgrid/dtn-node/internal/nodeid"
)

func cmdAdmin(args []string, out, errw io.Writer) int {
	if len(args) == 0 {
		return fatalf(errw, "admin: want subcommand sign|show")
	}
	switch args[0] {
	case "sign":
		return adminSign(args[1:], out, errw)
	case "show":
		return adminShow(args[1:], out, errw)
	default:
		return fatalf(errw, "admin: unknown subcommand %q", args[0])
	}
}

func adminSign(args []string, out, errw io.Writer) int {
	f, code := parseFlags(args, errw, map[string]bool{
		"seed": true, "cmd": true, "args": true, "target": true, "cert": true,
		"issued-ts": true, "expiry": true, "seq": true, "out": true,
	})
	if code >= 0 {
		return code
	}
	return adminSignRun(f, out, errw)
}

func adminSignRun(f flags, out, errw io.Writer) int {
	var err error
	seedPath, code := f.req(errw, "seed")
	if code >= 0 {
		return code
	}
	cmdName, code := f.req(errw, "cmd")
	if code >= 0 {
		return code
	}
	if _, known := mgmt.RequiredLevel(cmdName); !known {
		return fatalf(errw, "unknown command %q (the v1 §8.1 table is closed; see docs/node-network.md §8)", cmdName)
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

	cargs := map[string]mgmt.Arg{}
	if v, ok := f["args"]; ok && strings.TrimSpace(v) != "" && v != "{}" {
		if err := parseArgsJSON(v, cargs); err != nil {
			return fatalf(errw, "--args: %v", err)
		}
	}
	if v, ok := f["cert"]; ok {
		if _, clash := cargs["cert"]; clash {
			return fatalf(errw, "--cert and an args \"cert\" member are mutually exclusive")
		}
		cose, err := os.ReadFile(v)
		if err != nil {
			return fatalf(errw, "%v", err)
		}
		cargs["cert"] = mgmt.Arg{Kind: mgmt.ArgBstr, Bytes: cose}
	}
	if cmdName == mgmt.CmdInstallCert {
		if _, ok := cargs["cert"]; !ok {
			return fatalf(errw, "install_cert needs --cert FILE (an ALREADY ANCHOR-SIGNED role cert; issuance is an offline anchor ceremony)")
		}
	}

	var target string
	if t, ok := f["target"]; ok {
		target = t
		if target != "" {
			if _, err := nodeid.ParseEID(target); err != nil {
				return fatalf(errw, "--target: %v", err)
			}
		}
	}

	now := time.Now().Unix()
	issued := now
	if v, ok := f["issued-ts"]; ok {
		if issued, err = parseUnix(v); err != nil {
			return fatalf(errw, "--issued-ts: %v", err)
		}
	}
	expiry := issued + 3600 // the ceremony default: one hour of validity
	if v, ok := f["expiry"]; ok {
		if expiry, err = parseUnix(v); err != nil {
			return fatalf(errw, "--expiry: %v", err)
		}
	}
	seqArg, code := f.req(errw, "seq")
	if code >= 0 {
		return code
	}
	seq, err := parseSeq(seqArg)
	if err != nil {
		return fatalf(errw, "--seq: %v", err)
	}

	cose, err := mgmt.SignCommand(kp, cmdName, cargs, target, issued, expiry, seq)
	if err != nil {
		return fatalf(errw, "refusing to sign: %v", err)
	}
	if p, ok := f["out"]; ok {
		if err := os.WriteFile(p, cose, 0o644); err != nil {
			return fatalf(errw, "%v", err)
		}
		fmt.Fprintf(out, "wrote=%s\n", p)
	} else {
		if _, err := out.Write(cose); err != nil {
			return fatalf(errw, "%v", err)
		}
	}
	// The status lines go to stderr when the COSE goes to stdout, so the
	// byte stream stays clean for `>` redirection; to a file, stdout is free.
	status := io.Writer(out)
	if _, ok := f["out"]; !ok {
		status = errw
	}
	fmt.Fprintf(status, "eid=%s\ncmd=%s\ntarget=%s\nseq=%d\nissued_ts=%d\nexpiry=%d\nbytes=%d\n",
		eid, cmdName, target, seq, issued, expiry, len(cose))
	return exitOK
}

// parseArgsJSON converts the --args JSON object into the v1 CBOR arg map:
// JSON strings → tstr, JSON numbers (non-negative integers) → uint. Anything
// else is refused (the v1 CBOR value set is uint | tstr | bstr; bstr values
// ride the dedicated --cert flag).
func parseArgsJSON(s string, into map[string]mgmt.Arg) error {
	var raw map[string]any
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return fmt.Errorf("not a JSON object: %v", err)
	}
	for k, v := range raw {
		switch tv := v.(type) {
		case string:
			into[k] = mgmt.Arg{Kind: mgmt.ArgTstr, Str: tv}
		case json.Number:
			n, err := tv.Float64()
			if err != nil || n != math.Trunc(n) || n < 0 || n > math.MaxUint64 {
				return fmt.Errorf("args[%q]: %q must be a non-negative integer", k, tv.String())
			}
			into[k] = mgmt.Arg{Kind: mgmt.ArgUint, Uint: uint64(n)}
		default:
			return fmt.Errorf("args[%q]: only JSON strings and non-negative integers are valid in v1 (bstr values ride --cert)", k)
		}
	}
	return nil
}

func adminShow(args []string, out, errw io.Writer) int {
	f, code := parseFlags(args, errw, map[string]bool{"in": true})
	if code >= 0 {
		return code
	}
	inPath, code := f.req(errw, "in")
	if code >= 0 {
		return code
	}
	cose, err := os.ReadFile(inPath)
	if err != nil {
		return fatalf(errw, "%v", err)
	}
	c, err := mgmt.ParseCommandShape(cose)
	if err != nil {
		return fatalf(errw, "invalid command object: %v", err)
	}
	kid, err := mgmt.SignerFingerprint(cose)
	if err != nil {
		return fatalf(errw, "invalid COSE: %v", err)
	}
	argsJSON, _ := json.Marshal(c.Args)
	fmt.Fprintf(out, "cmd=%s\nargs=%s\ntarget=%s\nissued_ts=%d\nexpiry=%d\nseq=%d\nsigner_fp=%s\n",
		c.Cmd, string(argsJSON), c.TargetNode, c.IssuedTS, c.Expiry, c.Seq, hex.EncodeToString(kid))
	return exitOK
}
