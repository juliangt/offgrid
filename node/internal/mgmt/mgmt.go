// Package mgmt implements the management plane of docs/node-network.md §8
// (issue #33 P3.6): admin command bundles (§8.1), the enforcement pipeline
// (§8.2), telemetry replies (§8.3) and the v1 command table — the mechanism
// that lets a MANAGER run an island with no online server.
//
// Everything here rides the ordinary bundle plane: a command is an identified
// bundle (§3 P-5) whose payload is a COSE_Sign1 signed by the issuing node's
// node_key; the signer's authority is its cached role certificate (§2.2,
// level ceiling). Enforcement failures are SILENT drops + RAM counters —
// no error packets to strangers (the §13.6 refusal-to-confirm pattern).
// Executed commands earn exactly one aggregate-data telemetry reply (§8.3,
// the §10.7 privacy rules).
//
// The C counterpart (esp32/components/dtn_core/dtn_mgmt.c) implements the
// VERIFY/DECIDE half of this file — same order, same failure classes — and
// both sides run the shared vectors of tests/vectors/mgmt/vectors.json.
package mgmt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"time"

	"offgrid/dtn-node/internal/bundle"
	"offgrid/dtn-node/internal/nodeid"
)

// AdminEID is the well-known admin group of §8.1 (dtn://og-admin/): the
// broadcast address every og-admin subscriber (every node) consumes. Kept
// as an alias of forward.AdminEID's literal so the two can never diverge —
// mgmt must not import forward (the store imports THIS package).
const AdminEID = "dtn://og-admin/"

// Bounds of the v1 command object (frozen in §8.1):
const (
	// MaxCommandValidity bounds expiry - issued (≤ 24 h in v1): a policy
	// command is an operational act, not standing law; anything longer must
	// be re-issued (and re-authorized) by the manager.
	MaxCommandValidity = 24 * time.Hour
	// MaxIssuedSkew is the §4.3 skew rule applied to issued_ts: the
	// receiver drops commands issued more than 300 s into its future.
	MaxIssuedSkew = int64(300)
	// MaxArgs bounds the args map (8 pairs is generous for the v1 table).
	MaxArgs = 8
	// MaxCmdLen bounds the command name.
	MaxCmdLen = 31
	// MaxPayload bounds the COSE a receiver will even look at.
	MaxPayload = 4096
)

// The v1 command table (docs/node-network.md §8.1; frozen). Name → required
// authority level (§2.4). An unknown name is dropped + counted (forward
// compatibility: newer firmware may speak commands older nodes refuse).
const (
	CmdGetStatus             = "get_status"
	CmdForceJanitor          = "force_janitor"
	CmdTriggerSync           = "trigger_sync"
	CmdSetQuietHours         = "set_quiet_hours"
	CmdSetStoreCap           = "set_store_cap"
	CmdSetBudgets            = "set_budgets"
	CmdSetDialInterval       = "set_dial_interval"
	CmdFederationOn          = "federation_on"
	CmdFederationOff         = "federation_off"
	CmdInstallCert           = "install_cert"
	CmdFactoryResetNodePlane = "factory_reset_node_plane"
)

// ArgKind is the closed set of CBOR value types an args/data map may carry
// in v1: uint, tstr, bstr. Anything else (bool, float, negative int, array,
// nested map, tag) fails the shape check — fail-closed, both implementations.
type ArgKind int

const (
	ArgUint ArgKind = iota
	ArgTstr
	ArgBstr
)

// Arg is one args/data map value.
type Arg struct {
	Kind  ArgKind
	Uint  uint64
	Str   string
	Bytes []byte
}

// commandTable is the frozen v1 table (name → required §2.4 level). Read it
// through RequiredLevel.
var commandTable = map[string]uint64{
	CmdGetStatus:             0, // L0 telemetry: aggregate health/counters/peers
	CmdForceJanitor:          1, // L1 operations: force a bundle-store janitor pass
	CmdTriggerSync:           1, // L1 operations: dial peers now
	CmdSetQuietHours:         1, // L1 operations: radio quiet hours (stored policy)
	CmdSetStoreCap:           2, // L2 administration: bundle-store cap
	CmdSetBudgets:            2, // L2 administration: contact budgets
	CmdSetDialInterval:       2, // L2 administration: opportunistic dial cadence
	CmdFederationOn:          2, // L2 administration: directory federation flag (P3.8 consumes)
	CmdFederationOff:         2, // L2 administration: directory federation flag (P3.8 consumes)
	CmdInstallCert:           3, // L3 ownership: distribute an ALREADY ANCHOR-SIGNED role cert
	CmdFactoryResetNodePlane: 3, // L3 ownership: clear node-plane state (never user-plane mail)
}

// RequiredLevel returns the command's required authority level and whether
// the name is in the v1 table at all.
func RequiredLevel(cmd string) (uint64, bool) {
	lvl, ok := commandTable[cmd]
	return lvl, ok
}

// Command is a parsed, signature-VERIFIED admin command (§8.1). RefID is the
// command's P-7 bundle identity — SHA-256 over the bundle payload after the
// hop octet — the handle replies reference (§8.3).
type Command struct {
	Cmd        string
	Args       map[string]Arg
	TargetNode string // "" = broadcast to the og-admin group subscribers
	IssuedTS   int64
	Expiry     int64
	Seq        uint64

	SignerEID string
	Level     uint64 // the signer's cert level (the authority it acted with)
	RefID     [sha256.Size]byte
}

// ArgUintOf fetches a uint arg (ok=false when absent or of another kind).
func (c *Command) ArgUintOf(key string) (uint64, bool) {
	a, ok := c.Args[key]
	if !ok || a.Kind != ArgUint {
		return 0, false
	}
	return a.Uint, true
}

// ArgBytesOf fetches a bstr arg.
func (c *Command) ArgBytesOf(key string) ([]byte, bool) {
	a, ok := c.Args[key]
	if !ok || a.Kind != ArgBstr {
		return nil, false
	}
	return a.Bytes, true
}

// ---------------------------------------------------------------------------
// Encoding — the exact CBOR layouts of §8.1/§8.3 (fixed key order, canonical
// values). The single canonical encoder of internal/bundle writes every byte.
// ---------------------------------------------------------------------------

// EncodeArgs serializes an args/data map: canonical CBOR map, keys in
// ascending bytewise order (RFC 8949 deterministic order), each value one of
// the three v1 kinds. An empty map encodes as map(0).
func EncodeArgs(args map[string]Arg) []byte {
	return EncodeCborArgs(args)
}

// writeArgs writes the args/data map onto e (keys in ascending bytewise
// order, values from the closed v1 kind set). It writes INTO the enclosing
// encoding, so the command/reply maps embed it without a re-parse.
func writeArgs(e *bundle.Cbor, args map[string]Arg) {
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	e.MapHead(len(keys))
	for _, k := range keys {
		e.Tstr(k)
		a := args[k]
		switch a.Kind {
		case ArgUint:
			e.Uint(a.Uint)
		case ArgTstr:
			e.Tstr(a.Str)
		default:
			e.Bstr(a.Bytes)
		}
	}
}

// EncodeCborArgs is EncodeArgs over the shared encoder entry point.
func EncodeCborArgs(args map[string]Arg) []byte {
	return bundle.EncodeCbor(func(e *bundle.Cbor) { writeArgs(e, args) })
}

// coseProtected is the exact protected header of every node-plane COSE_Sign1
// (commands, replies, certs): {1: -8} in canonical bytes.
func coseProtected() []byte {
	return bundle.EncodeCbor(func(e *bundle.Cbor) {
		e.MapHead(1)
		e.Uint(1)
		e.Negint(-8)
	})
}

// coseSign1 builds a COSE_Sign1 over payload with the signer's node key:
// Sig_structure = ["Signature1", protected, external_aad(empty), payload]
// per RFC 9052 §4.4; unprotected carries {4: kid = SHA-256(pub)[0:8]}.
func coseSign1(signer nodeid.KeyPair, payload []byte) ([]byte, error) {
	protected := coseProtected()
	sigStruct := bundle.EncodeCbor(func(e *bundle.Cbor) {
		e.Array(4)
		e.Tstr("Signature1")
		e.Bstr(protected)
		e.Bstr(nil)
		e.Bstr(payload)
	})
	sig := ed25519.Sign(signer.Private, sigStruct)
	fp := nodeid.Fingerprint(signer.Public)
	return bundle.EncodeCbor(func(e *bundle.Cbor) {
		e.Array(4)
		e.Bstr(protected)
		e.MapHead(1)
		e.Uint(4)
		e.Bstr(fp[:])
		e.Bstr(payload)
		e.Bstr(sig)
	}), nil
}

// EncodeCommandMap writes the §8.1 command map — keys 0..5 in ascending
// order, the canonical encoding.
func EncodeCommandMap(c *Command) []byte {
	return bundle.EncodeCbor(func(e *bundle.Cbor) {
		e.MapHead(6)
		e.Uint(0)
		e.Tstr(c.Cmd)
		e.Uint(1)
		writeArgs(e, c.Args)
		e.Uint(2)
		e.Tstr(c.TargetNode)
		e.Uint(3)
		e.Uint(uint64(c.IssuedTS))
		e.Uint(4)
		e.Uint(uint64(c.Expiry))
		e.Uint(5)
		e.Uint(c.Seq)
	})
}

// SignCommand builds and signs the COSE_Sign1 command object (§8.1). The
// caller owns policy sanity (expiry windows, seq allocation); the constructor
// enforces only what a receiver would reject outright (unknown command name,
// validity window beyond the v1 bound) so the ceremony cannot mint garbage.
func SignCommand(signer nodeid.KeyPair, cmd string, args map[string]Arg, targetNode string, issued, expiry int64, seq uint64) ([]byte, error) {
	if _, known := RequiredLevel(cmd); !known {
		return nil, ErrUnknownCmd
	}
	if expiry <= issued {
		return nil, ErrValidity
	}
	if expiry-issued > int64(MaxCommandValidity/time.Second) {
		return nil, ErrValidity
	}
	if seq < 1 {
		return nil, ErrValidity
	}
	c := &Command{Cmd: cmd, Args: args, TargetNode: targetNode, IssuedTS: issued, Expiry: expiry, Seq: seq}
	return coseSign1(signer, EncodeCommandMap(c))
}

// EncodeReplyMap writes the §8.3 reply map: {0: ref bstr(32), 1: code uint,
// 2: data map}.
func EncodeReplyMap(ref [sha256.Size]byte, code uint64, data map[string]Arg) []byte {
	return bundle.EncodeCbor(func(e *bundle.Cbor) {
		e.MapHead(3)
		e.Uint(0)
		e.Bstr(ref[:])
		e.Uint(1)
		e.Uint(code)
		e.Uint(2)
		writeArgs(e, data)
	})
}

// SignReply builds the COSE_Sign1 telemetry reply (§8.3), signed by the
// EXECUTING node's key.
func SignReply(executor nodeid.KeyPair, ref [sha256.Size]byte, code uint64, data map[string]Arg) ([]byte, error) {
	return coseSign1(executor, EncodeReplyMap(ref, code, data))
}

// Reply codes (frozen, §8.3): the pipeline's drops never reply, so the only
// codes are success and a locally-failed execution of an authorized command.
const (
	ReplyOK    = 0
	ReplyError = 1
)

// Reply is a parsed telemetry reply (§8.3).
type Reply struct {
	RefID [sha256.Size]byte
	Code  uint64
	Data  map[string]Arg
	From  string // the replying node's EID (the bundle's source)
}

// ---------------------------------------------------------------------------
// Parsing — strict at both ends of the frozen shapes. Every failure is a
// stable Verdict the C mirror shares (the vectors pin the classes).
// ---------------------------------------------------------------------------

// Verdict classifies the enforcement outcome of one command payload. The
// strings are the shared Go/C vocabulary the vectors pin (v is the C enum's
// numeric twin in tests/vectors/mgmt/vectors.json).
type Verdict int

const (
	VerdictOK Verdict = iota
	VerdictShape
	VerdictSig
	VerdictTarget
	VerdictUnknownCmd
	VerdictLevel
	VerdictSeq
	VerdictExpired
)

func (v Verdict) String() string {
	switch v {
	case VerdictOK:
		return "ok"
	case VerdictShape:
		return "shape"
	case VerdictSig:
		return "sig"
	case VerdictTarget:
		return "target"
	case VerdictUnknownCmd:
		return "unknown_cmd"
	case VerdictLevel:
		return "level"
	case VerdictSeq:
		return "seq"
	default:
		return "expired"
	}
}

// Sentinel constructor errors (the signing side).
var (
	ErrUnknownCmd = errorf("mgmt: unknown command name")
	ErrValidity   = errorf("mgmt: validity window out of the v1 bounds (0 < expiry-issued ≤ 24h, seq ≥ 1)")
)

// errorf builds an error (Sprintf semantics); every mgmt error is terminal
// for the pipeline that produced it and is never surfaced to a stranger.
func errorf(format string, a ...any) error {
	return errors.New(fmt.Sprintf(format, a...))
}

// payloadKind discriminates the three COSE_Sign1 payload classes of the
// management plane (and "other" = not our business). The discriminator is the
// inner map's pair count and first key type: a cert map is 8 pairs keyed
// 0..7 (key 0 = uint v), a command map is 6 pairs keyed 0..5 (key 0 = the
// tstr cmd), a reply map is 3 pairs keyed 0..2 (key 0 = the bstr ref).
type payloadKind int

const (
	kindOther payloadKind = iota
	kindCommand
	kindCert
	kindReply
)

// classifyPayload peeks at a management-plane payload. It is deliberately
// SHALLOW (shape only, no verification) — the sink uses it to route; the
// verification lives in the pipeline and nodeid.VerifyCert. The
// discriminator is the inner map's PAIR COUNT: all three §8 classes fix the
// key order with uint keys 0..n-1, so the count alone separates them (8 =
// the §2.2 cert, 6 = the §8.1 command, 3 = the §8.3 reply) — the strict
// key-order/type checks happen in the class's own parser.
func classifyPayload(payload []byte) payloadKind {
	_, _, inner, _, err := splitCOSE(payload)
	if err != nil {
		return kindOther
	}
	r := bundle.NewCborReader(inner)
	pairs, err := r.Map()
	if err != nil {
		return kindOther
	}
	defer r.Pop()
	switch pairs {
	case 8:
		return kindCert
	case 6:
		return kindCommand
	case 3:
		return kindReply
	default:
		return kindOther
	}
}

// ParseCommandShape is the shape-only §8.1 command parse — the same parser
// the pipeline's first gate runs, exported for the operator's inspection
// tool (capsuletool admin show) and the shared-vector generator. NO
// verification: a shape-valid command may still be unsigned garbage.
func ParseCommandShape(cose []byte) (*Command, error) { return parseCommandCOSE(cose) }

// SignerFingerprint extracts the unprotected kid of a COSE_Sign1 command —
// the signer's node fingerprint (§2.1), the handle the enforcement pipeline
// resolves against the §2.5 cache.
func SignerFingerprint(cose []byte) ([]byte, error) {
	_, kid, _, _, err := splitCOSE(cose)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), kid...), nil
}

// parseCommandCOSE fully parses a §8.1 command COSE_Sign1 — SHAPE ONLY (the
// signature is verified by the pipeline against the signer's cached cert
// key, because the kid that selects that key lives in the object itself).
// Fixed key order 0..5, args per EncodeArgs rules, target a node EID or "".
func parseCommandCOSE(cose []byte) (*Command, error) {
	bad := func(format string, a ...any) (*Command, error) {
		return nil, errorf("mgmt: command shape: "+format, a...)
	}
	if len(cose) == 0 || len(cose) > MaxPayload {
		return bad("payload length %d outside [1, %d]", len(cose), MaxPayload)
	}
	protected, kid, inner, sig, err := splitCOSE(cose)
	if err != nil {
		return bad("%v", err)
	}
	if !bytes.Equal(protected, coseProtected()) {
		return bad("protected header is not exactly {1: -8}")
	}
	if len(kid) != nodeid.FingerprintLen {
		return bad("kid must be bstr(8), got %d bytes", len(kid))
	}
	if len(sig) != ed25519.SignatureSize {
		return bad("signature must be bstr(64), got %d bytes", len(sig))
	}

	r := bundle.NewCborReader(inner)
	n, err := r.Map()
	if err != nil {
		return bad("payload is not a map: %v", err)
	}
	defer r.Pop()
	if n != 6 {
		return bad("command map must have exactly 6 pairs, got %d", n)
	}
	c := &Command{Args: map[string]Arg{}}
	for want := 0; want < 6; want++ {
		k, err := r.Uint()
		if err != nil {
			return bad("map key %d: %v", want, err)
		}
		if k != uint64(want) {
			return bad("map keys must be 0..5 in order, got %d where %d was due", k, want)
		}
		switch want {
		case 0: // cmd
			if c.Cmd, err = r.Tstr(); err != nil {
				return bad("cmd: %v", err)
			}
			if c.Cmd == "" || len(c.Cmd) > MaxCmdLen {
				return bad("cmd name length %d outside [1, %d]", len(c.Cmd), MaxCmdLen)
			}
		case 1: // args
			if err := parseArgs(r, c.Args); err != nil {
				return bad("args: %v", err)
			}
		case 2: // target_node
			if c.TargetNode, err = r.Tstr(); err != nil {
				return bad("target_node: %v", err)
			}
			if c.TargetNode != "" {
				if _, err := nodeid.ParseEID(c.TargetNode); err != nil {
					return bad("target_node %q: %v", c.TargetNode, err)
				}
			}
		case 3: // issued_ts
			var u uint64
			if u, err = r.Uint(); err != nil {
				return bad("issued_ts: %v", err)
			}
			c.IssuedTS = int64(u)
		case 4: // expiry
			var u uint64
			if u, err = r.Uint(); err != nil {
				return bad("expiry: %v", err)
			}
			c.Expiry = int64(u)
		case 5: // seq
			if c.Seq, err = r.Uint(); err != nil {
				return bad("seq: %v", err)
			}
		}
	}
	if !r.Done() {
		return bad("%d trailing bytes inside the command map", len(inner)-r.Pos())
	}
	return c, nil
}

// parseArgs reads the args map: ≤ MaxArgs pairs, tstr keys in ascending
// order (canonical CBOR), values limited to the three v1 kinds.
func parseArgs(r *bundle.CborReader, into map[string]Arg) error {
	n, err := r.Map()
	if err != nil {
		return err
	}
	defer r.Pop()
	if n > MaxArgs {
		return errorf("args map has %d pairs (the v1 bound is %d)", n, MaxArgs)
	}
	var prev string
	for i := 0; i < n; i++ {
		key, err := r.Tstr()
		if err != nil {
			return err
		}
		if i > 0 && key <= prev {
			return errorf("args keys must be in ascending order (canonical CBOR), got %q after %q", key, prev)
		}
		prev = key
		if err := parseArgValue(r, key, into); err != nil {
			return err
		}
	}
	return nil
}

func parseArgValue(r *bundle.CborReader, key string, into map[string]Arg) error {
	// Dispatch on the major type without consuming; the typed read follows.
	head, ok := r.Peek()
	if !ok {
		return errorf("args[%q]: truncated value", key)
	}
	switch head >> 5 {
	case 0: // uint
		u, err := r.Uint()
		if err != nil {
			return err
		}
		into[key] = Arg{Kind: ArgUint, Uint: u}
		return nil
	case 2: // bstr
		b, err := r.Bstr()
		if err != nil {
			return err
		}
		into[key] = Arg{Kind: ArgBstr, Bytes: append([]byte(nil), b...)}
		return nil
	case 3: // tstr
		s, err := r.Tstr()
		if err != nil {
			return err
		}
		into[key] = Arg{Kind: ArgTstr, Str: s}
		return nil
	default:
		return errorf("args[%q]: value type 0x%02x is outside the v1 set (uint | tstr | bstr)", key, head)
	}
}

// parseReplyCOSE parses a §8.3 reply COSE_Sign1 (shape only — the caller
// verifies the signature when the replier's cert is cached).
func parseReplyCOSE(cose []byte) (*Reply, error) {
	if len(cose) == 0 || len(cose) > MaxPayload {
		return nil, errorf("mgmt: reply shape: payload length %d outside [1, %d]", len(cose), MaxPayload)
	}
	_, _, inner, _, err := splitCOSE(cose)
	if err != nil {
		return nil, errorf("mgmt: reply shape: %v", err)
	}
	r := bundle.NewCborReader(inner)
	n, err := r.Map()
	if err != nil {
		return nil, errorf("mgmt: reply shape: payload is not a map: %v", err)
	}
	defer r.Pop()
	if n != 3 {
		return nil, errorf("mgmt: reply map must have exactly 3 pairs, got %d", n)
	}
	rep := &Reply{Data: map[string]Arg{}}
	for want := 0; want < 3; want++ {
		k, err := r.Uint()
		if err != nil {
			return nil, errorf("mgmt: reply map key %d: %v", want, err)
		}
		if k != uint64(want) {
			return nil, errorf("mgmt: reply map keys must be 0..2 in order, got %d", k)
		}
		switch want {
		case 0:
			b, err := r.Bstr()
			if err != nil || len(b) != sha256.Size {
				return nil, errorf("mgmt: reply ref must be bstr(32)")
			}
			copy(rep.RefID[:], b)
		case 1:
			if rep.Code, err = r.Uint(); err != nil {
				return nil, errorf("mgmt: reply code: %v", err)
			}
		case 2:
			if err := parseArgs(r, rep.Data); err != nil {
				return nil, errorf("mgmt: reply data: %v", err)
			}
		}
	}
	if !r.Done() {
		return nil, errorf("mgmt: reply shape: %d trailing bytes", len(inner)-r.Pos())
	}
	return rep, nil
}

// splitCOSE takes a COSE_Sign1 apart: [protected, unprotected{4: kid},
// payload, signature], no trailing bytes. Views into cose — copy what
// outlives the call.
func splitCOSE(cose []byte) (protected, kid, payload, sig []byte, err error) {
	r := bundle.NewCborReader(cose)
	n, err := r.Array()
	if err != nil || n != 4 {
		return nil, nil, nil, nil, errorf("not a COSE_Sign1 array(4)")
	}
	if protected, err = r.Bstr(); err != nil {
		return nil, nil, nil, nil, errorf("protected header: %v", err)
	}
	if m, err := r.Map(); err != nil || m != 1 {
		return nil, nil, nil, nil, errorf("unprotected header must be map(1)")
	}
	label, err := r.Uint()
	if err != nil || label != 4 {
		return nil, nil, nil, nil, errorf("unprotected header must carry label 4 (kid)")
	}
	if kid, err = r.Bstr(); err != nil {
		return nil, nil, nil, nil, errorf("kid: %v", err)
	}
	r.Pop()
	if payload, err = r.Bstr(); err != nil {
		return nil, nil, nil, nil, errorf("payload: %v", err)
	}
	if sig, err = r.Bstr(); err != nil {
		return nil, nil, nil, nil, errorf("signature: %v", err)
	}
	if !r.Done() {
		return nil, nil, nil, nil, errorf("%d trailing bytes", len(cose)-r.Pos())
	}
	return protected, kid, payload, sig, nil
}

// verifyCommandSignature checks the Ed25519 signature of a command COSE
// against the signer's certified node key (the Sig_structure of RFC 9052
// §4.4 — the same machinery the role certs use, pinned by the same vectors).
func verifyCommandSignature(cose, nodeKey []byte) bool {
	r := bundle.NewCborReader(cose)
	if n, err := r.Array(); err != nil || n != 4 {
		return false
	}
	protected, err := r.Bstr()
	if err != nil {
		return false
	}
	if _, err := r.Map(); err != nil { // unprotected {4: kid} — skipped, not interpreted
		return false
	}
	if _, err := r.Uint(); err != nil { // label 4
		return false
	}
	if _, err := r.Bstr(); err != nil { // kid
		return false
	}
	r.Pop()
	payload, err := r.Bstr()
	if err != nil {
		return false
	}
	sig, err := r.Bstr()
	if err != nil {
		return false
	}
	sigStruct := bundle.EncodeCbor(func(e *bundle.Cbor) {
		e.Array(4)
		e.Tstr("Signature1")
		e.Bstr(protected)
		e.Bstr(nil)
		e.Bstr(payload)
	})
	return ed25519.Verify(nodeKey, sigStruct, sig)
}
