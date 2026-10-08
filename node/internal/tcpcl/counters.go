package tcpcl

// Counters — the §7.4/§11 exposed bookkeeping of the layer. All RAM-only
// (the protocol.md §10.7 counter discipline), atomics because the read
// loop, senders and the keepalive goroutine all bump them concurrently.
// A nil *Counters everywhere in the package means "not wired": every inc
// method is nil-safe, never a panic.

import "sync/atomic"

// Counters is the session-layer counter set. Zero value is ready.
type Counters struct {
	sessionsIn, sessionsOut atomic.Uint64
	handshakeFailures       atomic.Uint64
	pinRejections           atomic.Uint64
	bundlesIn, bundlesOut   atomic.Uint64
	bytesIn, bytesOut       atomic.Uint64
	refusalsIn, refusalsOut atomic.Uint64
	budgetRefusalsIn        atomic.Uint64
	budgetDeferralsOut      atomic.Uint64
	malformedBundles        atomic.Uint64
	protocolErrors          atomic.Uint64
	keepaliveTimeouts       atomic.Uint64
	unauthenticatedPeers    atomic.Uint64
	gracefulTerms           atomic.Uint64
}

// Count is a snapshot of every counter at one instant.
type Count struct {
	SessionsIn, SessionsOut uint64
	HandshakeFailures       uint64
	PinRejections           uint64
	BundlesIn, BundlesOut   uint64
	BytesIn, BytesOut       uint64
	RefusalsIn, RefusalsOut uint64
	BudgetRefusalsIn        uint64
	BudgetDeferralsOut      uint64
	MalformedBundles        uint64
	ProtocolErrors          uint64
	KeepaliveTimeouts       uint64
	UnauthenticatedPeers    uint64
	GracefulTerms           uint64
}

// Snapshot renders the current values.
func (c *Counters) Snapshot() Count {
	if c == nil {
		return Count{}
	}
	return Count{
		SessionsIn:           c.sessionsIn.Load(),
		SessionsOut:          c.sessionsOut.Load(),
		HandshakeFailures:    c.handshakeFailures.Load(),
		PinRejections:        c.pinRejections.Load(),
		BundlesIn:            c.bundlesIn.Load(),
		BundlesOut:           c.bundlesOut.Load(),
		BytesIn:              c.bytesIn.Load(),
		BytesOut:             c.bytesOut.Load(),
		RefusalsIn:           c.refusalsIn.Load(),
		RefusalsOut:          c.refusalsOut.Load(),
		BudgetRefusalsIn:     c.budgetRefusalsIn.Load(),
		BudgetDeferralsOut:   c.budgetDeferralsOut.Load(),
		MalformedBundles:     c.malformedBundles.Load(),
		ProtocolErrors:       c.protocolErrors.Load(),
		KeepaliveTimeouts:    c.keepaliveTimeouts.Load(),
		UnauthenticatedPeers: c.unauthenticatedPeers.Load(),
		GracefulTerms:        c.gracefulTerms.Load(),
	}
}

// The inc family: nil-safe, one line each, honest names.
func (c *Counters) incSessionsIn() {
	if c != nil {
		c.sessionsIn.Add(1)
	}
}
func (c *Counters) incSessionsOut() {
	if c != nil {
		c.sessionsOut.Add(1)
	}
}
func (c *Counters) incHandshakeFailures() {
	if c != nil {
		c.handshakeFailures.Add(1)
	}
}
func (c *Counters) incPinRejections() {
	if c != nil {
		c.pinRejections.Add(1)
	}
}
func (c *Counters) incBundlesIn(n uint64) {
	if c != nil {
		c.bundlesIn.Add(n)
	}
}
func (c *Counters) incBundlesOut(n uint64) {
	if c != nil {
		c.bundlesOut.Add(n)
	}
}
func (c *Counters) addBytesIn(n uint64) {
	if c != nil {
		c.bytesIn.Add(n)
	}
}
func (c *Counters) addBytesOut(n uint64) {
	if c != nil {
		c.bytesOut.Add(n)
	}
}
func (c *Counters) incRefusalsIn() {
	if c != nil {
		c.refusalsIn.Add(1)
	}
}
func (c *Counters) incRefusalsOut() {
	if c != nil {
		c.refusalsOut.Add(1)
	}
}
func (c *Counters) incBudgetRefusalsIn() {
	if c != nil {
		c.budgetRefusalsIn.Add(1)
	}
}
func (c *Counters) incBudgetDeferralsOut() {
	if c != nil {
		c.budgetDeferralsOut.Add(1)
	}
}
func (c *Counters) incMalformedBundles() {
	if c != nil {
		c.malformedBundles.Add(1)
	}
}
func (c *Counters) incProtocolErrors() {
	if c != nil {
		c.protocolErrors.Add(1)
	}
}
func (c *Counters) incKeepaliveTimeouts() {
	if c != nil {
		c.keepaliveTimeouts.Add(1)
	}
}
func (c *Counters) incUnauthenticatedPeers() {
	if c != nil {
		c.unauthenticatedPeers.Add(1)
	}
}
func (c *Counters) incGracefulTerms() {
	if c != nil {
		c.gracefulTerms.Add(1)
	}
}
