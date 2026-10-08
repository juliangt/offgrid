package mgmt

// mgmt_test.go — the P3.6 unit tests: the §8.1 object round-trips, the
// §8.2 pipeline verdict classes with NO reply on any drop (the §13.6
// refusal-to-confirm stance), the §8.3 reply path, install_cert's cache
// feed, the §8.5 broadcast-propagation contract, and the policy store.

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"

	"offgrid/dtn-node/internal/bundle"
	"offgrid/dtn-node/internal/nodeid"
)

// bench is one deterministic test bench: an anchor, a manager key pair, a
// receiving enforcer, and a capture of everything the enforcer injected.
type bench struct {
	t          *testing.T
	anchor     nodeid.KeyPair
	mgr        nodeid.KeyPair
	low        nodeid.KeyPair
	mgrEID     string
	lowEID     string
	localEID   string
	enf        *Enforcer
	cache      *nodeid.Cache
	injected   [][]byte // guarded by capMu (the Enforcer calls Inject concurrently)
	capMu      sync.Mutex
	executed   []string
	replies    []Reply
	now        time.Time
	mgrCert    []byte
	lowCert    []byte
	revocation []byte
}

func newBench(t *testing.T) *bench {
	t.Helper()
	anchor, err := nodeid.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	mgr, err := nodeid.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	low, err := nodeid.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	node, err := nodeid.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	mgrEID, err := nodeid.EIDFromPub(mgr.Public)
	if err != nil {
		t.Fatal(err)
	}
	lowEID, err := nodeid.EIDFromPub(low.Public)
	if err != nil {
		t.Fatal(err)
	}
	localEID, err := nodeid.EIDFromPub(node.Public)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_791_072_000, 0)
	b := &bench{
		t: t, anchor: anchor, mgr: mgr, low: low,
		mgrEID: mgrEID, lowEID: lowEID, localEID: localEID, now: now,
	}
	b.cache = nodeid.NewCache()
	b.enf = NewEnforcer(b.cache, anchor.Public, localEID, node)
	b.enf.Now = func() time.Time { return b.now }
	b.enf.Inject = func(pdu []byte) error {
		b.capMu.Lock()
		defer b.capMu.Unlock()
		b.injected = append(b.injected, append([]byte(nil), pdu...))
		return nil
	}
	b.enf.Exec = &Executors{
		Status: func() map[string]Arg {
			b.capMu.Lock()
			defer b.capMu.Unlock()
			b.executed = append(b.executed, CmdGetStatus)
			return map[string]Arg{"store_fill": {Kind: ArgUint, Uint: 7}}
		},
		SyncNow: func() { b.capMu.Lock(); b.executed = append(b.executed, CmdTriggerSync); b.capMu.Unlock() },
		SetStoreCap: func(uint64) error {
			b.capMu.Lock()
			b.executed = append(b.executed, CmdSetStoreCap)
			b.capMu.Unlock()
			return nil
		},
		SetBudgets:      func(mib uint64) error { b.enf.Policy.SetContactBudgetMiB(mib); return nil },
		SetDialInterval: func(sec uint64) error { b.enf.Policy.SetDialIntervalSec(sec); return nil },
		SetFederation:   func(on bool) error { b.enf.Policy.SetFederation(on); return nil },
		FactoryReset:    func() error { b.executed = append(b.executed, CmdFactoryResetNodePlane); return nil },
	}
	b.enf.OnReply = func(r Reply) {
		b.capMu.Lock()
		defer b.capMu.Unlock()
		b.replies = append(b.replies, r)
	}

	issued := now.Unix() - 60
	expires := issued + 3600
	sign := func(kp nodeid.KeyPair, roles []string, level, seq uint64) []byte {
		t.Helper()
		eid, err := nodeid.EIDFromPub(kp.Public)
		if err != nil {
			t.Fatal(err)
		}
		cose, err := nodeid.SignCert(anchor, kp.Public, eid, roles, level, issued, expires, seq, now.Unix())
		if err != nil {
			t.Fatal(err)
		}
		return cose
	}
	b.mgrCert = sign(mgr, []string{nodeid.RoleManager}, 3, 1)
	b.lowCert = sign(low, []string{nodeid.RoleManager}, 1, 1)
	b.revocation = sign(low, nil, 0, 2) // the §2.5 rule-4 revocation of the LOW signer
	return b
}

// seed merges a cert into the enforcer's cache (the boot-provisioning path).
func (b *bench) seed(cose []byte) {
	b.t.Helper()
	if st := b.cache.Merge(cose, b.anchor.Public, b.now.Unix()); st.Outcome != nodeid.OutcomeReplaced {
		b.t.Fatalf("seed: %s", st.Outcome)
	}
}

// deliver builds the identified bundle the manager's client would inject and
// runs it through Consume (the sink path).
func (b *bench) deliver(cose []byte) {
	b.t.Helper()
	b2, err := bundle.NewManagement(b.mgrEID, AdminEID, b.now.UnixMilli(), 3600, 1, cose)
	if err != nil {
		b.t.Fatal(err)
	}
	if !b.enf.Consume(b2) {
		b.t.Fatalf("a command payload must always be consumed")
	}
}

func (b *bench) sign(cmd string, args map[string]Arg, target string, seq uint64, signer nodeid.KeyPair) []byte {
	b.t.Helper()
	cose, err := SignCommand(signer, cmd, args, target, b.now.Unix()-30, b.now.Unix()+1800, seq)
	if err != nil {
		b.t.Fatal(err)
	}
	return cose
}

// findInjected returns the LAST parsed bundle injected toward dest (nil if
// none) — the most recent injection wins, which is what the tests assert.
func findInjected(b *bench, dest string) *bundle.Bundle {
	b.capMu.Lock()
	defer b.capMu.Unlock()
	var found *bundle.Bundle
	for _, pdu := range b.injected {
		parsed, err := bundle.Parse(pdu, b.now)
		if err != nil {
			continue
		}
		if parsed.Destination.String() == dest {
			found = parsed
		}
	}
	return found
}

// TestCommandObjectRoundTrip pins the §8.1 object: sign → shape-parse →
// identical fields, args in canonical key order, and the kid = the signer's
// fingerprint.
func TestCommandObjectRoundTrip(t *testing.T) {
	b := newBench(t)
	cose := b.sign(CmdSetStoreCap, map[string]Arg{"bundles": {Kind: ArgUint, Uint: 4000}, "reason": {Kind: ArgTstr, Str: "ops"}}, "", 4, b.mgr)
	cmd, err := ParseCommandShape(cose)
	if err != nil {
		t.Fatalf("shape: %v", err)
	}
	if cmd.Cmd != CmdSetStoreCap || cmd.TargetNode != "" || cmd.Seq != 4 {
		t.Fatalf("fields: %+v", cmd)
	}
	if len(cmd.Args) != 2 || cmd.Args["bundles"].Uint != 4000 || cmd.Args["reason"].Str != "ops" {
		t.Fatalf("args: %+v", cmd.Args)
	}
	// Determinism: the same fields re-encode to the same map bytes (the
	// args keys must sort canonically).
	cmd2, err := ParseCommandShape(cose)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(EncodeCommandMap(cmd2), EncodeCommandMap(cmd)) {
		t.Fatal("encode(parse(encode)) is not the identity")
	}
	// The kid selects the signer.
	kid, err := SignerFingerprint(cose)
	if err != nil {
		t.Fatal(err)
	}
	fp := nodeid.Fingerprint(b.mgr.Public)
	if !bytes.Equal(kid, fp[:]) {
		t.Fatalf("kid %x is not the signer fingerprint %x", kid, fp)
	}
}

// TestBelowLevelDropsSilently is THE acceptance scenario: an L1 signer's L2
// command is dropped + counted, with NO reply, NO executed executor —
// nothing to confirm (§13.6). The admin-group COPY still propagates (every
// node reaches its own verdict — the epidemic design); the assertion is
// that the single injection is the propagation copy, never a reply.
func TestBelowLevelDropsSilently(t *testing.T) {
	b := newBench(t)
	b.seed(b.lowCert)
	b.deliver(b.sign(CmdSetStoreCap, map[string]Arg{"bundles": {Kind: ArgUint, Uint: 4000}}, "", 1, b.low))
	got := b.enf.CountersSnapshot()
	if got.DroppedByLevel != 1 || got.Accepted != 0 {
		t.Fatalf("below-level verdict: %+v", got)
	}
	if len(b.injected) != 1 {
		t.Fatalf("want exactly the propagation copy, got %d injections", len(b.injected))
	}
	if prop := findInjected(b, AdminEID); prop == nil {
		t.Fatal("the injection is not the propagation copy")
	}
	if findInjected(b, b.lowEID) != nil {
		t.Fatal("a dropped command must never be replied to")
	}
	if len(b.executed) != 0 || len(b.replies) != 0 {
		t.Fatal("a dropped command must execute nothing and reply nothing")
	}
}

// TestPipelineVerdictClasses walks every §8.2 drop class with the exact
// per-class counter.
func TestPipelineVerdictClasses(t *testing.T) {
	b := newBench(t)
	b.seed(b.mgrCert)

	// Replay: same seq twice — the second is a replay (drop + count).
	b.deliver(b.sign(CmdGetStatus, nil, "", 5, b.mgr))
	if got := b.enf.CountersSnapshot(); got.Accepted != 1 {
		t.Fatalf("first execution: %+v", got)
	}
	b.deliver(b.sign(CmdGetStatus, nil, "", 5, b.mgr))
	if got := b.enf.CountersSnapshot(); got.DroppedSeq != 1 || got.Accepted != 1 {
		t.Fatalf("replay verdict: %+v", got)
	}
	// Lower seq: also a replay.
	b.deliver(b.sign(CmdGetStatus, nil, "", 4, b.mgr))
	if got := b.enf.CountersSnapshot(); got.DroppedSeq != 2 {
		t.Fatalf("lower seq: %+v", got)
	}

	// Expiry: expiry in the past — dropped_expired, and NO seq burned (the
	// same seq still executes afterwards).
	cose, err := SignCommand(b.mgr, CmdGetStatus, nil, "", b.now.Unix()-100, b.now.Unix()-50, 9)
	if err != nil {
		t.Fatal(err)
	}
	b.deliver(cose)
	if got := b.enf.CountersSnapshot(); got.DroppedExpired != 1 {
		t.Fatalf("expired: %+v", got)
	}
	b.deliver(b.sign(CmdGetStatus, nil, "", 9, b.mgr))
	if got := b.enf.CountersSnapshot(); got.Accepted != 2 {
		t.Fatalf("expired must not burn a seq: %+v", got)
	}

	// Future issued beyond the skew.
	cose, err = SignCommand(b.mgr, CmdGetStatus, nil, "", b.now.Unix()+MaxIssuedSkew+1, b.now.Unix()+MaxIssuedSkew+1801, 10)
	if err != nil {
		t.Fatal(err)
	}
	b.deliver(cose)
	if got := b.enf.CountersSnapshot(); got.DroppedExpired != 2 {
		t.Fatalf("future issued: %+v", got)
	}

	// Unknown command name: silent, unconfirmed (forward compat).
	c := &Command{Cmd: "reboot_node", Args: map[string]Arg{}, IssuedTS: b.now.Unix() - 30, Expiry: b.now.Unix() + 1800, Seq: 11}
	cose, err = coseSign1(b.mgr, EncodeCommandMap(c))
	if err != nil {
		t.Fatal(err)
	}
	b.deliver(cose)
	if got := b.enf.CountersSnapshot(); got.DroppedUnknown != 1 {
		t.Fatalf("unknown cmd: %+v", got)
	}

	// Wrong target: consumed here, never executed.
	b.deliver(b.sign(CmdGetStatus, nil, b.lowEID, 12, b.mgr))
	if got := b.enf.CountersSnapshot(); got.DroppedTarget != 1 {
		t.Fatalf("wrong target: %+v", got)
	}

	// Bad signature against a KNOWN signer: sig class.
	good := b.sign(CmdGetStatus, nil, "", 13, b.mgr)
	good[len(good)-1] ^= 0x01
	b.deliver(good)
	if got := b.enf.CountersSnapshot(); got.DroppedSig != 1 {
		t.Fatalf("bad sig: %+v", got)
	}

	// Revoked signer: sig class (§2.5 rule 4 — revoked managers get nothing).
	b2 := newBench(t)
	b2.seed(b2.revocation)
	b2.deliver(b2.sign(CmdGetStatus, nil, "", 1, b2.low))
	if got := b2.enf.CountersSnapshot(); got.DroppedSig != 1 {
		t.Fatalf("revoked signer: %+v", got)
	}

	// Unknown signer (no cert at all): sig class.
	b.deliver(b.sign(CmdGetStatus, nil, "", 1, b.low))
	if got := b.enf.CountersSnapshot(); got.DroppedSig != 2 {
		t.Fatalf("unknown signer: %+v", got)
	}
}

// TestShapeGarbageFallsThroughToStore: a bundle addressed to us that is NOT
// a management object (a P3.8 directory card, random junk) is not management
// business — the sink must store it (the P3.5 behavior, unchanged).
func TestShapeGarbageFallsThroughToStore(t *testing.T) {
	b := newBench(t)
	b2, err := bundle.NewManagement(b.mgrEID, b.localEID, b.now.UnixMilli(), 3600, 1, []byte(`{"v":1,"alias":"someone"}`))
	if err != nil {
		t.Fatal(err)
	}
	if b.enf.Consume(b2) {
		t.Fatal("non-management cargo must fall through to the store")
	}
	if got := b.enf.CountersSnapshot(); got.DroppedShape != 0 {
		t.Fatalf("fall-through is not a mgmt shape drop: %+v", got)
	}
}

// TestBroadcastPropagatesAndReplies pins the §8.5 sink contract: an
// admin-group command executes AND is re-admitted for epidemic propagation;
// the telemetry reply is an identified bundle back to the source with the
// aggregate-only data (§10.7).
func TestBroadcastPropagatesAndReplies(t *testing.T) {
	b := newBench(t)
	b.seed(b.mgrCert)
	b.deliver(b.sign(CmdGetStatus, nil, "", 5, b.mgr))
	got := b.enf.CountersSnapshot()
	if got.Accepted != 1 || got.RepliesSent != 1 {
		t.Fatalf("broadcast acceptance: %+v", got)
	}
	if len(b.injected) != 2 {
		t.Fatalf("want propagation copy + reply on the inject path, got %d", len(b.injected))
	}
	// One injection is the reply (built during execution), one is the
	// propagation copy — identify them by destination.
	repBundle := findInjected(b, b.mgrEID)
	propBundle := findInjected(b, AdminEID)
	if repBundle == nil || propBundle == nil {
		t.Fatalf("want one reply (to %s) + one propagation copy (%s), got %d injections",
			b.mgrEID, AdminEID, len(b.injected))
	}
	rep, err := parseReplyCOSE(repBundle.Payload)
	if err != nil {
		t.Fatalf("reply shape: %v", err)
	}
	if rep.Code != ReplyOK || len(rep.Data) != 1 || rep.Data["store_fill"].Uint != 7 {
		t.Fatalf("reply content: %+v", rep)
	}
	if len(b.replies) != 0 {
		t.Fatal("the executor is not the source of its own reply — no self-consumption")
	}
}

// TestReplyConsumedBySource: the manager consumes a reply addressed to it,
// verifying the signature against the replier's cached cert; a CORRUPT reply
// from a known replier is a silent drop.
func TestReplyConsumedBySource(t *testing.T) {
	b := newBench(t)
	b.seed(b.mgrCert)
	b.seed(b.lowCert) // so the manager can verify the replier
	cmd := b.sign(CmdGetStatus, nil, "", 1, b.mgr)
	refID := sha256.Sum256(cmd)
	repCose, err := SignReply(b.low, refID, ReplyOK, map[string]Arg{"peer_count": {Kind: ArgUint, Uint: 3}})
	if err != nil {
		t.Fatal(err)
	}
	rb, err := bundle.NewManagement(b.lowEID, b.localEID, b.now.UnixMilli(), 3600, 1, repCose)
	if err != nil {
		t.Fatal(err)
	}
	if !b.enf.Consume(rb) {
		t.Fatal("a reply addressed to us is management business")
	}
	if got := b.enf.CountersSnapshot(); got.RepliesReceived != 1 {
		t.Fatalf("reply receipt: %+v", got)
	}
	if len(b.replies) != 1 || b.replies[0].Code != ReplyOK || b.replies[0].Data["peer_count"].Uint != 3 {
		t.Fatalf("observed replies: %+v", b.replies)
	}
	if RefIDHex(b.replies[0].RefID) == "" {
		t.Fatal("ref must be recorded")
	}

	// A corrupted reply from the KNOWN replier: signature mismatch → drop.
	corrupt := append([]byte(nil), repCose...)
	corrupt[len(corrupt)-1] ^= 0x01
	rb2, err := bundle.NewManagement(b.lowEID, b.localEID, b.now.UnixMilli(), 3600, 2, corrupt)
	if err != nil {
		t.Fatal(err)
	}
	_ = b.enf.Consume(rb2)
	if got := b.enf.CountersSnapshot(); got.DroppedSig != 1 || got.RepliesReceived != 1 {
		t.Fatalf("corrupt reply verdict: %+v", got)
	}
}

// TestInstallCertFeedsCache: the L3 executor merges the args cert into the
// §2.5 cache (the seq rules decide), and the reply reports the merge outcome.
func TestInstallCertFeedsCache(t *testing.T) {
	b := newBench(t)
	b.seed(b.mgrCert)
	b.deliver(b.sign(CmdInstallCert, map[string]Arg{"cert": {Kind: ArgBstr, Bytes: b.lowCert}}, "", 3, b.mgr))
	got := b.enf.CountersSnapshot()
	if got.Accepted != 1 {
		t.Fatalf("install_cert: %+v", got)
	}
	if _, state := b.cache.Effective(b.lowEID, b.now.Unix()); state != nodeid.StateAuthority {
		t.Fatalf("the distributed cert must be cached with authority, got %s", state)
	}
	repBundle := findInjected(b, b.mgrEID)
	if repBundle == nil {
		t.Fatal("install_cert must send a telemetry reply to the source")
	}
	rep, err := parseReplyCOSE(repBundle.Payload)
	if err != nil {
		t.Fatalf("install reply shape: %v", err)
	}
	if rep.Code != ReplyOK || rep.Data["outcome"].Str != "replace" {
		t.Fatalf("install reply: %+v", rep)
	}

	// Redelivering the SAME cert bytes is an Unchanged merge — the §2.5
	// conflict counters stay quiet (identical bytes have one author).
	b.deliver(b.sign(CmdInstallCert, map[string]Arg{"cert": {Kind: ArgBstr, Bytes: b.lowCert}}, "", 4, b.mgr))
	if b.cache.Conflicts != 0 || b.cache.StaleDropped != 0 {
		t.Fatalf("identical redelivery moved the conflict counters: %d/%d", b.cache.StaleDropped, b.cache.Conflicts)
	}
}

// TestBareCertBroadcastIsMerged: a revocation riding og-admin as a BARE cert
// payload merges into the cache and propagates (the island-wide revocation
// path), and the revoked signer's authority dies with it.
func TestBareCertBroadcastIsMerged(t *testing.T) {
	b := newBench(t)
	b.seed(b.lowCert)
	revBundle, err := bundle.NewManagement(b.mgrEID, AdminEID, b.now.UnixMilli(), 3600, 1, b.revocation)
	if err != nil {
		t.Fatal(err)
	}
	if !b.enf.Consume(revBundle) {
		t.Fatal("a cert payload to og-admin is management business")
	}
	if _, state := b.cache.Effective(b.lowEID, b.now.Unix()); state != nodeid.StateRevoked {
		t.Fatalf("state after revocation = %s, want revoked", state)
	}
	if len(b.injected) != 1 {
		t.Fatalf("the revocation must propagate (inject path), got %d", len(b.injected))
	}
	// The revoked node's commands now drop.
	b.deliver(b.sign(CmdGetStatus, nil, "", 3, b.low))
	if got := b.enf.CountersSnapshot(); got.DroppedSig != 1 {
		t.Fatalf("post-revocation command: %+v", got)
	}
}

// TestExecutorsAndPolicy walks the v1 table's executor wiring: every L1/L2
// policy command stores what it says, and a missing executor (or malformed
// args) is a FAILED EXECUTION with reply code 1 — never a silent lie.
func TestExecutorsAndPolicy(t *testing.T) {
	b := newBench(t)
	b.seed(b.mgrCert)

	b.deliver(b.sign(CmdTriggerSync, nil, "", 1, b.mgr))
	b.deliver(b.sign(CmdSetStoreCap, map[string]Arg{"bundles": {Kind: ArgUint, Uint: 123}}, "", 2, b.mgr))
	b.deliver(b.sign(CmdSetDialInterval, map[string]Arg{"seconds": {Kind: ArgUint, Uint: 45}}, "", 3, b.mgr))
	b.deliver(b.sign(CmdSetBudgets, map[string]Arg{"contact_mib": {Kind: ArgUint, Uint: 8}}, "", 4, b.mgr))
	b.deliver(b.sign(CmdSetQuietHours, map[string]Arg{
		"enabled": {Kind: ArgUint, Uint: 1}, "start_min": {Kind: ArgUint, Uint: 1380}, "end_min": {Kind: ArgUint, Uint: 360},
	}, "", 5, b.mgr))
	b.deliver(b.sign(CmdFederationOn, nil, "", 6, b.mgr))

	p := b.enf.Policy
	if p.ContactBudgetMiB() != 8 || p.DialIntervalSec() != 45 || !p.Federation() {
		t.Fatalf("policy after commands: budget=%d dial=%d fed=%v", p.ContactBudgetMiB(), p.DialIntervalSec(), p.Federation())
	}
	en, s, e := p.QuietHours()
	if !en || s != 1380 || e != 360 {
		t.Fatalf("quiet hours: %v %d %d", en, s, e)
	}
	if got := b.enf.CountersSnapshot(); got.Accepted != 6 {
		t.Fatalf("acceptance: %+v", got)
	}

	// Malformed args for a known command: authorized, but not executable —
	// reply code 1, counted, nothing stored. (The reply is the LAST one
	// injected toward the manager — findInjected returns the newest.)
	b.deliver(b.sign(CmdSetQuietHours, map[string]Arg{"enabled": {Kind: ArgUint, Uint: 1}}, "", 7, b.mgr))
	if got := b.enf.CountersSnapshot(); got.ExecErrors != 1 {
		t.Fatalf("missing-args execution: %+v", got)
	}
	repBundle := findInjected(b, b.mgrEID)
	if repBundle == nil {
		t.Fatal("a failed execution must still reply (code 1) to the authorized manager")
	}
	rep, err := parseReplyCOSE(repBundle.Payload)
	if err != nil || rep.Code != ReplyError {
		t.Fatalf("failed execution reply: %+v err=%v", rep, err)
	}
}

// TestNoExecutorsIsExecErrorNotSilence: a node wired without executors still
// answers its manager honestly (code 1) — the opposite failure mode of the
// silent drops, which belong to UNTRUSTED traffic only.
func TestNoExecutorsIsExecErrorNotSilence(t *testing.T) {
	b := newBench(t)
	b.enf.Exec = nil
	b.seed(b.mgrCert)
	b.deliver(b.sign(CmdGetStatus, nil, "", 1, b.mgr))
	got := b.enf.CountersSnapshot()
	if got.ExecErrors != 1 || got.Accepted != 0 {
		t.Fatalf("no-executor verdict: %+v", got)
	}
	if findInjected(b, b.mgrEID) == nil {
		t.Fatal("the manager deserves a code-1 reply")
	}
}

// TestConcurrentPipeline is the -race witness: sessions and the sync engine
// hit one Enforcer from many goroutines.
func TestConcurrentPipeline(t *testing.T) {
	b := newBench(t)
	b.seed(b.mgrCert)
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func(n int) {
			defer func() { done <- struct{}{} }()
			for s := 1; s <= 5; s++ {
				b2, err := bundle.NewManagement(b.mgrEID, AdminEID, b.now.UnixMilli(), 3600, uint64(s), b.sign(CmdGetStatus, nil, "", uint64(s*10+n), b.mgr))
				if err != nil {
					t.Error(err)
					return
				}
				b.enf.Consume(b2)
			}
		}(i)
	}
	for i := 0; i < 8; i++ {
		<-done
	}
	// Every seq value is distinct per signer; whatever the interleaving,
	// each executed command moved the signer floor monotonically and nothing
	// dropped by signature or shape.
	got := b.enf.CountersSnapshot()
	if got.DroppedSig != 0 || got.DroppedShape != 0 {
		t.Fatalf("concurrency corruption: %+v", got)
	}
	if got.Accepted+got.DroppedSeq != 40 {
		t.Fatalf("accepted %d + replayed %d != 40", got.Accepted, got.DroppedSeq)
	}
}

// TestSignCommandRefusesGarbage: the constructor cannot mint what receivers
// would drop (unknown name, inverted window, over-long validity, seq 0).
func TestSignCommandRefusesGarbage(t *testing.T) {
	b := newBench(t)
	now := b.now.Unix()
	if _, err := SignCommand(b.mgr, "reboot_node", nil, "", now, now+600, 1); !errors.Is(err, ErrUnknownCmd) {
		t.Fatalf("unknown cmd: %v", err)
	}
	if _, err := SignCommand(b.mgr, CmdGetStatus, nil, "", now+600, now, 1); !errors.Is(err, ErrValidity) {
		t.Fatalf("inverted window: %v", err)
	}
	if _, err := SignCommand(b.mgr, CmdGetStatus, nil, "", now, now+int64(MaxCommandValidity/time.Second)+1, 1); !errors.Is(err, ErrValidity) {
		t.Fatalf("over-long validity: %v", err)
	}
	if _, err := SignCommand(b.mgr, CmdGetStatus, nil, "", now, now+600, 0); !errors.Is(err, ErrValidity) {
		t.Fatalf("seq 0: %v", err)
	}
}
