package mgmt

// enforcer.go — the §8.2 enforcement pipeline, the §8.3 reply path, the RAM
// counters (§10.7 discipline) and the v1 policy store. One Enforcer per
// daemon; every method is safe for concurrent use (sessions, sync and the
// dial loop all touch it).
//
// Sink contract (frozen in §8.5 of the spec): a received, profile-valid
// bundle whose destination is THIS node's EID or dtn://og-admin/ is offered
// to Consume BEFORE the forward store (the P3.5 hop-ceiling note). Consume
// reports whether the bytes were management business (the sink must then not
// store them); broadcast-class cargo (commands and certs addressed to the
// admin group) is ALSO admitted to the store by the Enforcer itself, so the
// epidemic sync propagates it island-wide (revocation rides the same path).

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"sync/atomic"
	"time"

	"offgrid/dtn-node/internal/bundle"
	"offgrid/dtn-node/internal/nodeid"
)

// Counters is the RAM-only bookkeeping of the enforcement pipeline (§10.7:
// aggregates only, never persisted, die with the process). Zero value ready.
type Counters struct {
	Accepted        atomic.Uint64 // executed (reply sent or attempted)
	DroppedShape    atomic.Uint64 // not a §8.1 command object
	DroppedSig      atomic.Uint64 // unknown signer / no, revoked or expired cert / bad signature
	DroppedTarget   atomic.Uint64 // targeted at another node (relayed, not executed)
	DroppedUnknown  atomic.Uint64 // command name outside the v1 table (forward compat)
	DroppedByLevel  atomic.Uint64 // signer's cert level below the command's requirement
	DroppedSeq      atomic.Uint64 // replayed or non-monotonic per-signer seq
	DroppedExpired  atomic.Uint64 // expired, or issued_ts sanity failed
	RepliesSent     atomic.Uint64 // telemetry replies handed to the route
	RepliesDropped  atomic.Uint64 // reply could not be routed (no inject / store refused)
	RepliesReceived atomic.Uint64 // telemetry replies consumed as the command's source
	ExecErrors      atomic.Uint64 // authorized command whose local execution failed
}

// CountersSnapshot is a plain read of the counters at one instant. The field
// set is exactly what the /status node-plane section serves (§10.7).
type CountersSnapshot struct {
	Accepted        uint64
	DroppedShape    uint64
	DroppedSig      uint64
	DroppedTarget   uint64
	DroppedUnknown  uint64
	DroppedByLevel  uint64
	DroppedSeq      uint64
	DroppedExpired  uint64
	RepliesSent     uint64
	RepliesDropped  uint64
	RepliesReceived uint64
	ExecErrors      uint64
}

// Snapshot renders the current values.
func (c *Counters) Snapshot() CountersSnapshot {
	return CountersSnapshot{
		Accepted:        c.Accepted.Load(),
		DroppedShape:    c.DroppedShape.Load(),
		DroppedSig:      c.DroppedSig.Load(),
		DroppedTarget:   c.DroppedTarget.Load(),
		DroppedUnknown:  c.DroppedUnknown.Load(),
		DroppedByLevel:  c.DroppedByLevel.Load(),
		DroppedSeq:      c.DroppedSeq.Load(),
		DroppedExpired:  c.DroppedExpired.Load(),
		RepliesSent:     c.RepliesSent.Load(),
		RepliesDropped:  c.RepliesDropped.Load(),
		RepliesReceived: c.RepliesReceived.Load(),
		ExecErrors:      c.ExecErrors.Load(),
	}
}

// Policy is the v1 policy store commands act on: quiet hours (store-only —
// the radio wiring is hardware bring-up), the contact budget and dial
// interval the daemon's dial loop reads per contact, and the federation flag
// P3.8 consumes. RAM-only (a restart reverts to defaults — documented).
type Policy struct {
	mu               sync.Mutex
	quietEnabled     bool
	quietStartMin    uint64 // minutes-of-day window start
	quietEndMin      uint64
	contactBudgetMiB uint64 // 0 = the daemon default
	dialIntervalSec  uint64 // 0 = the daemon default
	federation       bool
}

// SetQuietHours stores the L1 quiet-hours policy (start/end in minutes of
// day; the radio applies it at hardware bring-up).
func (p *Policy) SetQuietHours(enabled bool, startMin, endMin uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.quietEnabled, p.quietStartMin, p.quietEndMin = enabled, startMin, endMin
}

// QuietHours reads the stored quiet-hours policy.
func (p *Policy) QuietHours() (enabled bool, startMin, endMin uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.quietEnabled, p.quietStartMin, p.quietEndMin
}

// SetContactBudgetMiB stores the L2 per-contact budget (applies to sessions
// opened after the change — the honest v1 semantics).
func (p *Policy) SetContactBudgetMiB(mib uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.contactBudgetMiB = mib
}

// ContactBudgetMiB reads the stored budget (0 = daemon default).
func (p *Policy) ContactBudgetMiB() uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.contactBudgetMiB
}

// SetDialIntervalSec stores the L2 opportunistic dial cadence.
func (p *Policy) SetDialIntervalSec(sec uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.dialIntervalSec = sec
}

// DialIntervalSec reads the stored cadence (0 = daemon default).
func (p *Policy) DialIntervalSec() uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.dialIntervalSec
}

// SetFederation stores the L2 federation flag (P3.8 consumes it).
func (p *Policy) SetFederation(on bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.federation = on
}

// Federation reads the flag.
func (p *Policy) Federation() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.federation
}

// Executors carries the node-plane handles the v1 command table acts on.
// Every member is optional: a nil handle makes its command a failed
// execution (telemetry reply code 1, no silent lie).
type Executors struct {
	// Status returns the aggregate status data of a get_status reply
	// (§10.7: aggregates only — the counters, store fill/cap, peer count).
	Status func() map[string]Arg
	// Janitor forces a bundle-store janitor pass; returns swept rows.
	Janitor func() (int64, error)
	// SyncNow dials the configured peers at the next opportunity.
	SyncNow func()
	// SetStoreCap applies a new bundle-store cap.
	SetStoreCap func(bundles uint64) error
	// SetBudgets stores the contact-budget policy.
	SetBudgets func(contactMiB uint64) error
	// SetDialInterval stores the dial-cadence policy.
	SetDialInterval func(seconds uint64) error
	// SetFederation stores the federation flag.
	SetFederation func(on bool) error
	// FactoryReset clears the node-plane state (bundle store, TOFU pins).
	// NEVER the user-plane mail — documented loudly at the wiring site.
	FactoryReset func() error
}

// Enforcer is the §8.2 pipeline. Construct with NewEnforcer.
type Enforcer struct {
	Cache     *nodeid.Cache  // the §2.5 role-cert cache (shared with the daemon)
	AnchorPub []byte         // the pinned anchor public key (cert verification)
	LocalEID  string         // this node's EID
	Signer    nodeid.KeyPair // this node's key (replies are signed with it)
	Exec      *Executors
	Policy    *Policy

	// Inject routes outbound management PDUs (replies, and broadcast-class
	// commands/certs re-admitted for epidemic propagation) into the bundle
	// store. Nil = replies are dropped (counted).
	Inject func(pdu []byte) error

	// OnReply observes consumed telemetry replies (tests; the daemon only
	// counts). Called with the parsed reply after the counters moved.
	OnReply func(Reply)

	Now func() time.Time

	counters Counters

	mu   sync.Mutex
	seqs map[string]uint64 // per-signer last EXECUTED seq (§8.2; RAM-only)
	// bundleSeq is the per-source creation sequence of identified bundles
	// this node emits (telemetry replies, §3 P-3). RAM-only: a restart
	// restarts at 1 — the P-3 sequence is a wire hygiene counter, not
	// enforcement state (dedup is bundle_id-based, P-7).
	bundleSeq uint64
}

// NewEnforcer wires the pipeline over a role-cert cache. The anchor public
// key MUST be pinned (32 bytes) — without it no cert verifies and no command
// can ever be trusted (fail-closed by construction).
func NewEnforcer(cache *nodeid.Cache, anchorPub []byte, localEID string, signer nodeid.KeyPair) *Enforcer {
	return &Enforcer{
		Cache:     cache,
		AnchorPub: append([]byte(nil), anchorPub...),
		LocalEID:  localEID,
		Signer:    signer,
		Policy:    &Policy{},
		Now:       time.Now,
		seqs:      make(map[string]uint64),
	}
}

// CountersSnapshot exposes the pipeline counters (/status, §10.7).
func (e *Enforcer) CountersSnapshot() CountersSnapshot { return e.counters.Snapshot() }

// CertCountersSnapshot exposes the cert merge counters of the §2.5 cache
// (the stale/conflict pair /status carries).
func (e *Enforcer) CertCountersSnapshot() (staleDropped, conflicts uint64) {
	return e.Cache.StaleDropped, e.Cache.Conflicts
}

// OwnCertState interprets this node's own cert (§2.5 rules 4-5) — the
// role/level the status surface reports.
func (e *Enforcer) OwnCertState() (*nodeid.Cert, nodeid.CertState) {
	return e.Cache.Effective(e.LocalEID, e.Now().Unix())
}

// Consume runs the sink's management-plane half (§8.5): b is a received,
// profile-valid bundle. Handled=true means the bytes were management
// business — the sink must NOT store them (the Enforcer already re-admitted
// broadcast-class cargo for propagation). Handled=false = not ours; the sink
// falls through to the store (P3.5 behavior, future payload classes).
func (e *Enforcer) Consume(b *bundle.Bundle) (handled bool) {
	dest := b.Destination.String()
	if dest != AdminEID && dest != e.LocalEID {
		return false
	}
	payload := b.Payload
	if len(payload) == 0 || len(payload) > MaxPayload {
		return false // not our shape; the store judges it
	}
	switch classifyPayload(payload) {
	case kindCommand:
		e.processCommand(b)
		// ALWAYS re-admit the consumed copy: an og-admin broadcast
		// propagates island-wide by epidemic sync (dedup bounds re-transfer,
		// seq freshness bounds re-execution), and even a locally-targeted
		// copy must enter OUR store — otherwise the §7.1 summaries never
		// cover it and the peers that hold it re-deliver it forever.
		e.inject(b)
		return true
	case kindCert:
		// A bare role cert (e.g. a revocation riding og-admin): merge into
		// the §2.5 cache. Verification failures are silent (the merge
		// counters are the record). Re-admitted for the same convergence.
		e.Cache.Merge(payload, e.AnchorPub, e.Now().Unix())
		e.inject(b)
		return true
	case kindReply:
		if dest == e.LocalEID {
			e.receiveReply(b)
			e.inject(b) // cover it in our summaries: no perpetual redelivery
			return true
		}
		return false // a reply addressed to the admin group is not a thing
	default:
		return false // not management cargo (directory cards, P3.8, land here)
	}
}

// inject admits one PDU into the propagation path (the store), counting.
func (e *Enforcer) inject(b *bundle.Bundle) {
	if e.Inject == nil {
		return
	}
	pdu, err := bundle.Encode(b)
	if err != nil {
		return
	}
	if err := e.Inject(pdu); err != nil {
		// The store refused (cap/hop) — the command still ran locally; the
		// next contact re-diff will not carry it. Counted, never surfaced.
		e.counters.RepliesDropped.Add(1)
	}
}

// processCommand is the §8.2 pipeline, in the normative order:
//
//	shape → resolve the signer's cert in the cache (valid, unrevoked,
//	unexpired) → verify the COSE signature with the certified node key →
//	target gate → command-table lookup → level gate → seq freshness →
//	expiry/issued sanity → execute (+ one telemetry reply).
//
// EVERY failure: silent drop + the matching RAM counter. No error packets.
func (e *Enforcer) processCommand(b *bundle.Bundle) {
	now := e.Now()
	nowUnix := now.Unix()

	// 1. Shape (§8.1 fixed layout).
	cmd, err := parseCommandCOSE(b.Payload)
	if err != nil {
		e.counters.DroppedShape.Add(1)
		return
	}
	cmd.RefID = sha256.Sum256(b.Payload) // P-7: the payload after the hop octet

	// 2. The signer's cert: the unprotected kid is the signer's fingerprint
	// (§2.1), so the candidate EID is derived — never looked up by name.
	_, kid, _, _, err := splitCOSE(b.Payload)
	if err != nil || len(kid) != nodeid.FingerprintLen {
		e.counters.DroppedShape.Add(1)
		return
	}
	var signerFP [nodeid.FingerprintLen]byte
	copy(signerFP[:], kid) // the kid IS the §2.1 fingerprint — never re-hashed
	signerEID := nodeid.EID(signerFP)
	cert, state := e.Cache.Effective(signerEID, nowUnix)
	if state != nodeid.StateAuthority {
		// Absent / revoked / expired: no authority, no discussion (§2.5
		// rules 4-5). Silent drop; mail stays receivable, commands are not.
		e.counters.DroppedSig.Add(1)
		return
	}

	// 3. COSE verify with the signer's CERTIFIED node key (never a key the
	// payload itself named).
	if !verifyCommandSignature(b.Payload, cert.NodeKey) {
		e.counters.DroppedSig.Add(1)
		return
	}
	cmd.SignerEID = signerEID
	cmd.Level = cert.Level

	// 4. Target gate (§8.2): execute only when this node is the target or
	// the command is a documented broadcast. Anything else: consumed here
	// (the admin group address makes every subscriber see it) and counted —
	// the admin-addressed copy still propagates via the store for the real
	// target.
	if cmd.TargetNode != "" && cmd.TargetNode != e.LocalEID {
		e.counters.DroppedTarget.Add(1)
		return
	}

	// 5. Command table: unknown names drop + count (forward compat: newer
	// firmware may speak commands this build refuses — never confirm).
	required, known := RequiredLevel(cmd.Cmd)
	if !known {
		e.counters.DroppedUnknown.Add(1)
		return
	}

	// 6. Level gate (§2.4): the signer's cert level is its whole authority.
	if cmd.Level < required {
		e.counters.DroppedByLevel.Add(1)
		return
	}

	// 7. Seq freshness (§8.2): strictly monotonic per signer — a replayed
	// or lower seq is a replay, dropped + counted.
	e.mu.Lock()
	if last, ok := e.seqs[signerEID]; ok && cmd.Seq <= last {
		e.mu.Unlock()
		e.counters.DroppedSeq.Add(1)
		return
	}
	e.mu.Unlock()

	// 8. Expiry / issued sanity (against the LOCAL clock):
	//    issued ≤ now + 300 (skew), 0 < expiry - issued ≤ 24 h, now < expiry.
	if cmd.IssuedTS <= 0 || cmd.IssuedTS > nowUnix+MaxIssuedSkew ||
		cmd.Expiry <= cmd.IssuedTS ||
		cmd.Expiry-cmd.IssuedTS > int64(MaxCommandValidity/time.Second) ||
		nowUnix >= cmd.Expiry {
		e.counters.DroppedExpired.Add(1)
		return
	}

	// 9. Execute. The seq floor moves at execution (§8.2: "must exceed the
	// last executed") — a command dropped by a later gate never burns a seq.
	e.mu.Lock()
	e.seqs[signerEID] = cmd.Seq
	e.mu.Unlock()

	data, execErr := e.execute(cmd)
	if execErr != nil {
		e.counters.ExecErrors.Add(1)
		e.sendReply(cmd, ReplyError, nil)
		return
	}
	e.counters.Accepted.Add(1)
	e.sendReply(cmd, ReplyOK, data)
}

// execute dispatches one authorized command to the v1 executors. A nil
// handle is a failed execution (reply code 1) — never a silent lie.
func (e *Enforcer) execute(cmd *Command) (map[string]Arg, error) {
	x := e.Exec
	if x == nil {
		return nil, errorf("mgmt: no executors wired")
	}
	switch cmd.Cmd {
	case CmdGetStatus:
		if x.Status == nil {
			return nil, errorf("mgmt: get_status: no status source")
		}
		return x.Status(), nil
	case CmdForceJanitor:
		if x.Janitor == nil {
			return nil, errorf("mgmt: force_janitor: no janitor")
		}
		n, err := x.Janitor()
		if err != nil {
			return nil, err
		}
		return map[string]Arg{"deleted": {Kind: ArgUint, Uint: uint64(n)}}, nil
	case CmdTriggerSync:
		if x.SyncNow == nil {
			return nil, errorf("mgmt: trigger_sync: no dial loop")
		}
		x.SyncNow()
		return nil, nil
	case CmdSetQuietHours:
		enabled, start, end, err := quietHoursArgs(cmd)
		if err != nil {
			return nil, err
		}
		e.Policy.SetQuietHours(enabled, start, end)
		return nil, nil
	case CmdSetStoreCap:
		cap, ok := cmd.ArgUintOf("bundles")
		if !ok {
			return nil, errorf("mgmt: set_store_cap: args need {bundles: uint}")
		}
		if x.SetStoreCap == nil {
			return nil, errorf("mgmt: set_store_cap: no store handle")
		}
		if err := x.SetStoreCap(cap); err != nil {
			return nil, err
		}
		return nil, nil
	case CmdSetBudgets:
		mib, ok := cmd.ArgUintOf("contact_mib")
		if !ok {
			return nil, errorf("mgmt: set_budgets: args need {contact_mib: uint}")
		}
		if x.SetBudgets == nil {
			return nil, errorf("mgmt: set_budgets: no policy handle")
		}
		if err := x.SetBudgets(mib); err != nil {
			return nil, err
		}
		return nil, nil
	case CmdSetDialInterval:
		sec, ok := cmd.ArgUintOf("seconds")
		if !ok {
			return nil, errorf("mgmt: set_dial_interval: args need {seconds: uint}")
		}
		if x.SetDialInterval == nil {
			return nil, errorf("mgmt: set_dial_interval: no dial loop")
		}
		if err := x.SetDialInterval(sec); err != nil {
			return nil, err
		}
		return nil, nil
	case CmdFederationOn:
		if x.SetFederation == nil {
			return nil, errorf("mgmt: federation_on: no policy handle")
		}
		if err := x.SetFederation(true); err != nil {
			return nil, err
		}
		return nil, nil
	case CmdFederationOff:
		if x.SetFederation == nil {
			return nil, errorf("mgmt: federation_off: no policy handle")
		}
		if err := x.SetFederation(false); err != nil {
			return nil, err
		}
		return nil, nil
	case CmdInstallCert:
		cose, ok := cmd.ArgBytesOf("cert")
		if !ok {
			return nil, errorf("mgmt: install_cert: args need {cert: bstr}")
		}
		st := e.Cache.Merge(cose, e.AnchorPub, e.Now().Unix())
		return map[string]Arg{"outcome": {Kind: ArgTstr, Str: st.Outcome.String()}}, nil
	case CmdFactoryResetNodePlane:
		if x.FactoryReset == nil {
			return nil, errorf("mgmt: factory_reset_node_plane: no reset handle")
		}
		if err := x.FactoryReset(); err != nil {
			return nil, err
		}
		return nil, nil
	default:
		// Unreachable (the table gate ran), but stay silent + counted.
		return nil, errorf("mgmt: unknown command %q", cmd.Cmd)
	}
}

// quietHoursArgs parses the set_quiet_hours args:
// {enabled: uint 0|1, start_min: uint, end_min: uint}.
func quietHoursArgs(cmd *Command) (enabled bool, start, end uint64, err error) {
	en, ok := cmd.ArgUintOf("enabled")
	if !ok || en > 1 {
		return false, 0, 0, errorf("mgmt: set_quiet_hours: args need {enabled: uint 0|1, start_min: uint, end_min: uint}")
	}
	start, ok = cmd.ArgUintOf("start_min")
	if !ok || start >= 1440 {
		return false, 0, 0, errorf("mgmt: set_quiet_hours: start_min must be uint < 1440")
	}
	end, ok = cmd.ArgUintOf("end_min")
	if !ok || end >= 1440 {
		return false, 0, 0, errorf("mgmt: set_quiet_hours: end_min must be uint < 1440")
	}
	return en == 1, start, end, nil
}

// sendReply builds and routes the §8.3 telemetry reply: an identified bundle
// back to the command's source EID, payload = COSE_Sign1 over
// {0: ref bstr(32), 1: code, 2: data} signed by THIS node's key. Aggregate
// data only (§10.7) — the executors above are the only data source and they
// return aggregates by contract.
func (e *Enforcer) sendReply(cmd *Command, code uint64, data map[string]Arg) {
	cose, err := SignReply(e.Signer, cmd.RefID, code, data)
	if err != nil {
		e.counters.RepliesDropped.Add(1)
		return
	}
	b, err := bundle.NewManagement(e.LocalEID, cmd.SignerEID, e.Now().UnixMilli(), replyLifetime, e.nextBundleSeq(), cose)
	if err != nil {
		e.counters.RepliesDropped.Add(1)
		return
	}
	pdu, err := bundle.Encode(b)
	if err != nil {
		e.counters.RepliesDropped.Add(1)
		return
	}
	if e.Inject == nil {
		e.counters.RepliesDropped.Add(1)
		return
	}
	if err := e.Inject(pdu); err != nil {
		e.counters.RepliesDropped.Add(1)
		return
	}
	e.counters.RepliesSent.Add(1)
}

// receiveReply consumes a telemetry reply addressed to this node (this node
// was the command's source): shape-parse, verify the signature WHEN the
// replier's cert is cached (a replier without a cert executed a broadcast
// command legitimately — its reply is accepted on shape, honestly counted),
// then count + observe.
func (e *Enforcer) receiveReply(b *bundle.Bundle) {
	rep, err := parseReplyCOSE(b.Payload)
	if err != nil {
		e.counters.DroppedShape.Add(1)
		return
	}
	rep.From = b.Source.String()
	if cert, state := e.Cache.Effective(rep.From, e.Now().Unix()); state == nodeid.StateAuthority {
		if !verifyReplySignature(b.Payload, cert.NodeKey) {
			e.counters.DroppedSig.Add(1)
			return
		}
	}
	e.counters.RepliesReceived.Add(1)
	if e.OnReply != nil {
		e.OnReply(*rep)
	}
}

// verifyReplySignature is verifyCommandSignature's twin for replies (same
// Sig_structure, same machinery).
func verifyReplySignature(cose, nodeKey []byte) bool {
	return verifyCommandSignature(cose, nodeKey)
}

// replyLifetime is the bundle lifetime of a telemetry reply: telemetry is
// contact-scoped ephemera (like the §7.1 summaries) — one hour covers a
// waylaid relay, no longer.
const replyLifetime uint64 = 3600

// nextBundleSeq allocates the per-source creation sequence (§3 P-3) for
// identified bundles this node emits (replies).
func (e *Enforcer) nextBundleSeq() uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.bundleSeq++
	return e.bundleSeq
}

// RefIDHex renders a reply reference for logs/inspection.
func RefIDHex(ref [sha256.Size]byte) string { return hex.EncodeToString(ref[:]) }
