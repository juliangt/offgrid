// sync.go — controlled epidemic contact sync v1 (docs/node-network.md §7.1)
// over the TCPCL plane, plus the local priority queue discipline (§7.3).
//
// THE V1 SYNC HANDSHAKE (spec §7.1, additive note): TCPCL carries bundles
// and nothing else — the profile invents NO new convergence-layer messages.
// On every established session each side sends its Bloom summary AS A
// BUNDLE: an identified bundle (source = its own node EID, destination =
// the PEER's node EID, §3 P-5 shape) whose payload after the hop octet is
// `sync-version(1) ‖ summary(512 B)`. The receiver's Sink recognizes that
// shape (destination == local EID, version byte, exact length), feeds the
// summary to this Engine instead of the store, computes its diff, and sends
// the bundles the peer lacks — ordinary bundles, prioritized management >
// mail > bulk (§7.3), within the session's §7.4 per-contact budget (the
// tcpcl egress gate defers the rest to the next contact). No wire bytes
// beyond profile bundles ever cross a session.
//
// Privacy stance of the summary (spec does not salt the filter): the Bloom
// filter is UNSALTED, but its inputs are bundle_ids — opaque SHA-256
// digests (P-7). A passive observer of a summary learns set membership of
// opaque digests only; a peer that already knows an id can test membership
// (inherent to any epidemic diff); payload bytes (mail is E2EE, §14.2)
// never appear.

package forward

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"offgrid/dtn-node/internal/bundle"
	"offgrid/dtn-node/internal/capsule"
	"offgrid/dtn-node/internal/tcpcl"
)

// Bloom parameters of §7.1 (frozen): 4096 bits (512 B), k = 4 — false
// positives ≈ 0.1% at 200 entries, ≈ 2% at 500. A false "peer has it"
// answer costs one skipped transfer that a later contact repairs (the
// filter bytes shift as sets change); it never corrupts anything.
const (
	BloomBits  = 4096
	BloomBytes = BloomBits / 8
	BloomK     = 4
)

// SyncVersion tags the summary payload shape carried inside a summary
// bundle (payload = SyncVersion ‖ BloomBytes). Unknown versions are dropped
// (forward-compatible extension point for the §7.1 side channel).
const SyncVersion = 1

// SummaryPayloadLen is the exact PDU length of a v1 summary payload.
const SummaryPayloadLen = 1 + BloomBytes

// SummaryWait bounds how long a contact waits for the peer's summary
// bundle before giving the contact up (the peer may be a plain client that
// never syncs — the daemon still serves it; nothing is pushed to a peer
// whose summary never arrived).
const SummaryWait = 10 * time.Second

// SummaryLifetime is the lifetime of a summary bundle (§3 P-6): summaries
// are contact-scoped ephemera, never store cargo (the consuming node never
// stores them), so a short TTL keeps a waylaid copy from propagating.
const SummaryLifetime uint64 = 3600

// Summary is the §7.1 contact summary: a 4096-bit Bloom filter over 32-byte
// bundle_ids, k = 4, unsalted (see the privacy stance above).
type Summary struct {
	Bits [BloomBytes]byte
}

// bloomHash derives the k filter indexes of one id: h_i = SHA-256(i ‖ id),
// index = big-endian uint32 of the first 4 bytes, mod BloomBits. Fully
// deterministic — the C mirror (dtn_epidemic.c) implements exactly this.
func bloomHashes(id *[sha256.Size]byte) [BloomK]uint32 {
	var out [BloomK]uint32
	for i := 0; i < BloomK; i++ {
		sum := sha256.New()
		sum.Write([]byte{byte(i)})
		sum.Write(id[:])
		digest := sum.Sum(nil)
		out[i] = binary.BigEndian.Uint32(digest[:4]) % BloomBits
	}
	return out
}

// Add inserts one id into the filter.
func (s *Summary) Add(id *[sha256.Size]byte) {
	for _, bit := range bloomHashes(id) {
		s.Bits[bit/8] |= 1 << (bit % 8)
	}
}

// Contains reports whether the filter MIGHT hold the id (false positives
// are the Bloom trade-off §7.1 accepts).
func (s *Summary) Contains(id *[sha256.Size]byte) bool {
	for _, bit := range bloomHashes(id) {
		if s.Bits[bit/8]&(1<<(bit%8)) == 0 {
			return false
		}
	}
	return true
}

// NewSummary builds the filter of one id set.
func NewSummary(ids [][sha256.Size]byte) *Summary {
	s := &Summary{}
	for i := range ids {
		s.Add(&ids[i])
	}
	return s
}

// Missing returns, in order, every id of `ids` that `s` does NOT claim —
// the transfer list a node computes from a peer's summary ("ids it has that
// we lack → it sends" is the peer's symmetric run of this same function
// over its own set).
func Missing(ids [][sha256.Size]byte, s *Summary) [][sha256.Size]byte {
	var out [][sha256.Size]byte
	for i := range ids {
		if !s.Contains(&ids[i]) {
			out = append(out, ids[i])
		}
	}
	return out
}

// EncodeSummaryPDU serializes the summary payload: version byte ‖ filter.
func EncodeSummaryPDU(s *Summary) []byte {
	pdu := make([]byte, 0, SummaryPayloadLen)
	pdu = append(pdu, SyncVersion)
	pdu = append(pdu, s.Bits[:]...)
	return pdu
}

// ParseSummaryPDU recognizes a v1 summary payload; ok is false for any
// other shape (including future versions — dropped, not an error).
func ParseSummaryPDU(payload []byte) (*Summary, bool) {
	if len(payload) != SummaryPayloadLen || payload[0] != SyncVersion {
		return nil, false
	}
	s := &Summary{}
	copy(s.Bits[:], payload[1:])
	return s, true
}

// ---------------------------------------------------------------------------
// The §7.3 local priority queue.
// ---------------------------------------------------------------------------

// sendQueue is the outbound contact queue: three FIFO lanes, popped strictly
// management > mail > bulk (§7.3 — a LOCAL scheduling policy, invisible on
// the wire). A bulk backlog can never starve a management bundle for more
// than one in-flight transfer: pop() happens between transfers, so whatever
// the lanes hold when a slot opens, the most important lane wins it.
type sendQueue struct {
	mu      sync.Mutex
	lanes   [3][][sha256.Size]byte // indexed by Class
	entries int
}

func (q *sendQueue) push(id [sha256.Size]byte, class Class) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.lanes[class] = append(q.lanes[class], id)
	q.entries++
}

func (q *sendQueue) pop() ([sha256.Size]byte, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for c := ClassManagement; c <= ClassBulk; c++ {
		if len(q.lanes[c]) > 0 {
			id := q.lanes[c][0]
			q.lanes[c] = q.lanes[c][1:]
			q.entries--
			return id, true
		}
	}
	return [sha256.Size]byte{}, false
}

func (q *sendQueue) len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.entries
}

// ---------------------------------------------------------------------------
// The sync engine.
// ---------------------------------------------------------------------------

// Engine runs the §7.1 sync on every established TCPCL session. One Engine
// per daemon; it owns no goroutines between contacts.
type Engine struct {
	store    *Store
	localEID string
	log      *log.Logger
	now      func() time.Time
	seq      atomic.Uint64 // per-source creation sequence (P-3 identified bundles)

	// SummaryWait bounds the peer-summary wait of a contact (0 → the
	// SummaryWait default; tests shorten it).
	SummaryWait time.Duration

	mu       sync.Mutex
	contacts map[string]*contact // by certified peer EID

	counters EngineCounters
}

// EngineCounters is the sync layer's RAM-only bookkeeping.
type EngineCounters struct {
	ContactsStarted  atomic.Uint64
	SummariesSent    atomic.Uint64
	SummariesIn      atomic.Uint64
	SummariesDropped atomic.Uint64 // malformed/unknown-version/unexpected source
	Transferred      atomic.Uint64 // bundles handed to a session this boot
	DeferredOut      atomic.Uint64 // transfers left for the next contact (§7.4 egress)
	SendErrors       atomic.Uint64
	HopExpiredSkips  atomic.Uint64 // RewriteHop refused at the ceiling on send
}

// EngineCountersSnapshot is a plain read of the engine counters.
type EngineCountersSnapshot struct {
	ContactsStarted, SummariesSent, SummariesIn, SummariesDropped uint64
	Transferred, DeferredOut, SendErrors, HopExpiredSkips         uint64
}

// Snapshot renders the current values.
func (c *EngineCounters) Snapshot() EngineCountersSnapshot {
	return EngineCountersSnapshot{
		ContactsStarted:  c.ContactsStarted.Load(),
		SummariesSent:    c.SummariesSent.Load(),
		SummariesIn:      c.SummariesIn.Load(),
		SummariesDropped: c.SummariesDropped.Load(),
		Transferred:      c.Transferred.Load(),
		DeferredOut:      c.DeferredOut.Load(),
		SendErrors:       c.SendErrors.Load(),
		HopExpiredSkips:  c.HopExpiredSkips.Load(),
	}
}

// NewEngine builds the sync engine over a store. localEID is this node's
// EID (summary bundles are addressed FROM it).
func NewEngine(store *Store, localEID string, log *log.Logger) *Engine {
	return &Engine{
		store:    store,
		localEID: localEID,
		log:      log,
		now:      time.Now,
		contacts: make(map[string]*contact),
	}
}

// contact is one live §7.1 exchange with one peer over one session.
type contact struct {
	peerEID string
	sess    *tcpcl.Session
	queue   sendQueue
	summCh  chan *Summary
}

// HandleSession is the tcpcl.Config.OnEstablished hook: called once per
// established session (inbound or outbound), it opens a contact in its own
// goroutine. The wire exchange is bundle-only (see the file header); a
// session whose peer has no certified EID (mTLS-optional, no certificate)
// carries no sync — an unnamed peer cannot be addressed.
func (e *Engine) HandleSession(sess *tcpcl.Session) {
	peer := sess.PeerEID()
	if peer == "" {
		e.logf("sync: session with an unnamed peer carries no summary exchange")
		return
	}
	c := &contact{peerEID: peer, sess: sess, summCh: make(chan *Summary, 1)}
	e.mu.Lock()
	e.contacts[peer] = c
	e.mu.Unlock()
	e.counters.ContactsStarted.Add(1)
	go e.runContact(c)
}

// runContact is the v1 handshake: send OUR summary bundle, wait for the
// peer's, queue the diff, pump it in §7.3 priority order within the §7.4
// budget.
func (e *Engine) runContact(c *contact) {
	defer func() {
		e.mu.Lock()
		if e.contacts[c.peerEID] == c {
			delete(e.contacts, c.peerEID)
		}
		e.mu.Unlock()
	}()

	// 1. Our summary, as a bundle (dest = the peer — only it consumes it).
	entries, err := e.store.Entries()
	if err != nil {
		e.logf("sync: %s: list store: %v", c.peerEID, err)
		return
	}
	ids := make([][sha256.Size]byte, len(entries))
	for i, en := range entries {
		ids[i] = en.ID
	}
	summary := NewSummary(ids)
	pdu, err := e.summaryBundle(c.peerEID, summary)
	if err != nil {
		e.logf("sync: %s: build summary bundle: %v", c.peerEID, err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), tcpcl.WriteTimeout)
	err = c.sess.SendBundle(ctx, pdu)
	cancel()
	if err != nil {
		e.logf("sync: %s: send summary: %v", c.peerEID, err)
		e.counters.SendErrors.Add(1)
		return
	}
	e.counters.SummariesSent.Add(1)

	// 2. The peer's summary (its symmetric run of step 1).
	wait := e.SummaryWait
	if wait <= 0 {
		wait = SummaryWait
	}
	var theirs *Summary
	select {
	case theirs = <-c.summCh:
	case <-time.After(wait):
		e.logf("sync: %s: no summary within %s — contact carries none of our bundles", c.peerEID, wait)
		return
	case <-c.sess.Done():
		return
	}
	e.counters.SummariesIn.Add(1)

	// 3. Diff: our live ids the peer's filter does not claim.
	missing := Missing(ids, theirs)
	if len(missing) == 0 {
		e.logf("sync: %s: converged (nothing to send, store %d)", c.peerEID, len(ids))
		return
	}
	classes := make(map[[sha256.Size]byte]Class, len(entries))
	for _, en := range entries {
		classes[en.ID] = en.Class
	}
	for _, id := range missing {
		c.queue.push(id, classes[id])
	}
	e.logf("sync: %s: sending %d bundle(s) (mgmt %d, mail %d, bulk %d)", c.peerEID,
		len(missing),
		e.queueClassCount(classes, missing, ClassManagement),
		e.queueClassCount(classes, missing, ClassMail),
		e.queueClassCount(classes, missing, ClassBulk))

	// 4. The §7.3 pump: one transfer at a time (§5.2.2 forbids interleaving),
	// priority order, until the queue drains or the §7.4 budget defers us.
	for {
		id, ok := c.queue.pop()
		if !ok {
			return
		}
		stored, found, err := e.store.Get(id)
		if err != nil || !found {
			continue // janitor/eviction raced us; the next contact re-diffs
		}
		wire, err := bundle.RewriteHop(stored)
		if err != nil {
			// The §3.1 ceiling: this relay's copy is at hop 7 — it never
			// leaves again. Drop from this contact's queue silently.
			e.counters.HopExpiredSkips.Add(1)
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), tcpcl.WriteTimeout)
		err = c.sess.SendBundle(ctx, wire)
		cancel()
		switch {
		case err == nil:
			e.counters.Transferred.Add(1)
		case errors.Is(err, tcpcl.ErrBudgetDeferred):
			// §7.4 egress: the contact's budget is spent. Everything still
			// queued stays for the next contact (the queue dies with this
			// contact; the next contact re-diffs from the store — same set).
			e.counters.DeferredOut.Add(uint64(c.queue.len() + 1))
			e.logf("sync: %s: contact budget spent; %d bundle(s) deferred", c.peerEID, c.queue.len()+1)
			return
		default:
			e.counters.SendErrors.Add(1)
			e.logf("sync: %s: send failed: %v", c.peerEID, err)
			return
		}
	}
}

func (e *Engine) queueClassCount(classes map[[sha256.Size]byte]Class, ids [][sha256.Size]byte, class Class) int {
	n := 0
	for _, id := range ids {
		if classes[id] == class {
			n++
		}
	}
	return n
}

// summaryBundle encodes our Bloom summary as an identified bundle addressed
// to the peer (the §7.1 v1 handshake — bundle plane only).
func (e *Engine) summaryBundle(peerEID string, s *Summary) ([]byte, error) {
	b, err := bundle.NewManagement(e.localEID, peerEID, e.now().UnixMilli(),
		SummaryLifetime, e.seq.Add(1), EncodeSummaryPDU(s))
	if err != nil {
		return nil, err
	}
	return bundle.Encode(b)
}

// deliverSummary routes a recognized summary bundle from the Sink to the
// contact that expects it. Unexpected sources (no live contact) are dropped
// and counted — never an error to the sender.
func (e *Engine) deliverSummary(fromEID string, s *Summary) {
	e.mu.Lock()
	c, ok := e.contacts[fromEID]
	e.mu.Unlock()
	if !ok {
		e.counters.SummariesDropped.Add(1)
		return
	}
	select {
	case c.summCh <- s:
	default: // a second summary on one contact is ignored (first wins)
	}
}

// HandleSession is invoked per session; Accept is the receiving half.
// Sink is the tcpcl.BundleSink the daemon wires into tcpcl.Config. The P3.6
// management plane (docs/node-network.md §8.5) sits IN FRONT of the store:
// bundles whose destination is this node's EID or dtn://og-admin/ are offered
// to the Enforcer first (commands execute or drop silently; certs merge into
// the §2.5 cache; replies to us are recorded), and broadcast-class cargo is
// re-admitted into the store BY the Enforcer so epidemic sync propagates it
// island-wide. Fields Store and Engine are required; Mgmt is optional (nil =
// the P3.5 behavior, exactly). P3.7 adds Updates (§9.4): the capsule.Receiver
// that consumes chunk cargo addressed to this node — nil = updates disabled,
// the store refuses chunk bundles at admission (UpdatesOff). P3.8 adds
// Directory (§9.3): the federation consumer for bundles addressed to the
// dtn://og-dir/ group — nil = the P3.5 behavior (og-dir cargo is ordinary
// bulk transit).
type Sink struct {
	Store     *Store
	Engine    *Engine
	LocalEID  string
	Now       func() time.Time
	Mgmt      MgmtConsumer
	Updates   *capsule.Receiver
	Directory DirectoryConsumer
}

// MgmtConsumer is the management-plane seam (internal/mgmt.Enforcer satisfies
// it). An interface — not the concrete type — keeps forward importable by
// everything that imports mgmt without a cycle in future phases.
type MgmtConsumer interface {
	// Consume reports whether the received bundle was management business
	// (consumed — never store cargo; broadcast copies the Enforcer re-admits
	// for propagation go through its own Inject path).
	Consume(b *bundle.Bundle) (handled bool)
}

// DirectoryConsumer is the P3.8 federation seam (internal/directory.Federator
// satisfies it): the §9.3 consumer for dtn://og-dir/ bundles. An interface —
// not the concrete type — keeps forward free of the directory storage layer.
type DirectoryConsumer interface {
	// ConsumeDirectory reports whether the og-dir bundle was directory
	// business (consumed — verified, merged, and re-admitted through the
	// consumer's own Inject). false = the federation gate is off: the sink
	// falls through to the store, which relays the bundle as ordinary bulk
	// transit while this node absorbs nothing.
	ConsumeDirectory(b *bundle.Bundle) (handled bool)
}

// Accept implements tcpcl.BundleSink.
func (s *Sink) Accept(pdu []byte) error {
	now := s.Now
	if now == nil {
		now = time.Now
	}
	b, err := bundle.Parse(pdu, now())
	if err != nil {
		return fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	// §8.5: the management plane consumes destination-bound bundles BEFORE
	// the store (and before the §3.1 hop ceiling — a hop-7 broadcast command
	// still executes where it arrived; only its further relay dies there).
	if s.Mgmt != nil && s.Mgmt.Consume(b) {
		return nil
	}
	if payload, ok := s.summaryPayload(b); ok {
		if summary, ok := ParseSummaryPDU(payload); ok {
			s.Engine.deliverSummary(b.Source.String(), summary)
			return nil // consumed; a summary is never store cargo
		}
		s.Engine.counters.SummariesDropped.Add(1)
		return nil // our shape, unknown version: consumed and dropped
	}
	// §9.4 (P3.7): chunk cargo addressed to THIS node (or the og-admin
	// group) is fed to the updates receiver — reassembly + staging are the
	// capsule's delivery here — and then RE-ADMITTED into the store like
	// §8.5's consumed management copies, so this node's §7.1 summaries
	// cover the chunks and peers never re-deliver them. With Updates nil
	// (updates disabled) the dispatch declines and the store's admission
	// refusal below is the §9.4 policy.
	s.dispatchUpdates(b)
	// §9.3 (P3.8): directory cards addressed to the og-dir group are offered
	// to the federation consumer before the store — verified, merged into
	// the user-plane directory per the §3.4 rules, and re-admitted for
	// epidemic convergence by the consumer itself. A declined dispatch
	// (federation off) falls through: the store relays the card as ordinary
	// bulk transit, this node absorbs nothing.
	if s.Directory != nil && b.Destination.String() == DirEID && s.Directory.ConsumeDirectory(b) {
		return nil
	}
	return s.Store.Accept(pdu)
}

// summaryPayload recognizes the v1 sync-summary shape: destination is OUR
// EID, the source an identified node (the P-5 shape guarantees it — mail is
// anonymous), and the payload is EXACTLY version byte ‖ 512 filter bytes.
// The exact-length rule is what keeps the dispatch unambiguous: any other
// payload addressed to us (a P3.6 admin command, a directory card) falls
// through to the store even when its first byte is 0x01. The hop octet sits
// at ContentOff, the payload at ContentOff+1. (The §8.5 Mgmt gate above
// takes precedence when wired: commands and certs addressed to us are
// management business and never reach here.)
func (s *Sink) summaryPayload(b *bundle.Bundle) ([]byte, bool) {
	if b.Destination.String() != s.LocalEID {
		return nil, false
	}
	if b.Source.IsNone() || len(b.Payload) != SummaryPayloadLen || b.Payload[0] != SyncVersion {
		return nil, false
	}
	return b.Payload, true
}

// CountersSnapshot exposes the sync counters (internal observability;
// /status wiring is P3.6's).
func (e *Engine) CountersSnapshot() EngineCountersSnapshot { return e.counters.Snapshot() }

// logf is the nil-safe logger.
func (e *Engine) logf(format string, a ...any) {
	if e.log != nil {
		e.log.Printf("forward: "+format, a...)
	}
}
