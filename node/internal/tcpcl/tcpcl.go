// Package tcpcl implements the Offgrid TCPCLv4 profile: a faithful, minimal
// subset of RFC 9174 (Bundle Protocol TCP Convergence-Layer Version 4) for
// the node plane's Wi-Fi/IP leg — docs/node-network.md §6.2 item 4 and the
// subset decisions of §6.3. TLS 1.3 (RFC 8446, carried forward by RFC 9846)
// runs via Go's crypto/tls; node identity and TOFU pinning are the §2/§6.1
// nodeid primitives (same node identity, same certificates as the LoRa
// plane). The issue-33 P3.4 exit gate is the Go loopback suite (§11 row h);
// the daemon's forwarding path lands with P3.5.
//
// The RFC subset implemented (see §6.3 of the spec for the pinned choices):
//
//   - Contact header exchange over plaintext TCP, active peer first (§4.2,
//     §4.3), with the CAN_TLS flag (0x01) and version 4 only.
//   - TLS negotiated by the logical AND of the CAN_TLS flags, then an
//     in-band TLS upgrade BEFORE any other message — the active peer is the
//     TLS client (§4.4.3). TLS is REQUIRED by profile policy: a peer
//     without CAN_TLS is terminated with SESS_TERM "Contact Failure".
//   - SESS_INIT from BOTH entities after TLS (Figure 17), with keepalive
//     interval, segment MRU, transfer MRU, node ID and an empty session
//     extension list; keepalive = min of the two (§4.6, §4.7).
//   - XFER_SEGMENT / XFER_ACK / XFER_REFUSE with the RFC's transfer-ID
//     semantics (sender-allocated, unique per direction, first 0 +1 each,
//     §5.2.1) and the mandated extension-length fields; the Transfer Length
//     Extension (§5.2.5.1) is sent on multi-segment transfers.
//   - KEEPALIVE (§5.1.1) with the idle-termination rule (≥ 2× interval →
//     SESS_TERM "Idle timeout").
//   - SESS_TERM graceful exchange with the REPLY flag and the reason codes
//     of Table 9, plus the abrupt path (§6.1).
//   - MSG_REJECT for unknown/unexpected messages (§5.1.2).
//
// What the profile deliberately leaves out, per the minimal-conforming-path
// rule: protocol version fallback (only v4 is spoken), session extension
// items (none are sent; unknown non-critical ones are skipped, critical ones
// terminate the session), TLS session resumption, and SNI (peers are
// addressed by IP/fingerprint on an island, not by DNS names).
package tcpcl

import "errors"

// Protocol constants (RFC 9174 §4.2, §4.5 Table 2, §8.5, §8.6, §8.7).
const (
	// ProtocolVersion is the only TCPCL version this profile speaks.
	ProtocolVersion = 4

	// ContactMagic is the §4.2 magic field: "dtn!" in ASCII.
	ContactMagic = "dtn!"

	// FlagCAN_TLS is the §4.2 contact-header TLS flag (0x01).
	FlagCAN_TLS = 0x01

	// Message type codes (§4.5 Table 2).
	MsgXFER_SEGMENT = 0x01
	MsgXFER_ACK     = 0x02
	MsgXFER_REFUSE  = 0x03
	MsgKEEPALIVE    = 0x04
	MsgSESS_TERM    = 0x05
	MsgMSG_REJECT   = 0x06
	MsgSESS_INIT    = 0x07

	// XFER_SEGMENT message flags (§5.2.2 Table 5).
	FlagXFER_END   = 0x01
	FlagXFER_START = 0x02

	// SESS_TERM message flags (§6.1 Table 8).
	FlagTERM_REPLY = 0x01

	// Transfer Length Extension (§5.2.5.1, §8.4 Table 13) and the
	// extension-item CRITICAL flag (§4.8/§5.2.5 Table 7).
	ExtensionTransferLength = 0x0001
	FlagItemCRITICAL        = 0x01
)

// TermReason is the SESS_TERM reason code (§6.1 Table 9 / §8.7).
type TermReason byte

const (
	TermUnknown            TermReason = 0x00
	TermIdleTimeout        TermReason = 0x01
	TermVersionMismatch    TermReason = 0x02
	TermBusy               TermReason = 0x03
	TermContactFailure     TermReason = 0x04
	TermResourceExhaustion TermReason = 0x05
)

func (r TermReason) String() string {
	switch r {
	case TermUnknown:
		return "Unknown"
	case TermIdleTimeout:
		return "Idle timeout"
	case TermVersionMismatch:
		return "Version mismatch"
	case TermBusy:
		return "Busy"
	case TermContactFailure:
		return "Contact Failure"
	case TermResourceExhaustion:
		return "Resource Exhaustion"
	}
	return "term-reason(0x00)"
}

// RefuseReason is the XFER_REFUSE reason code (§5.2.4 Table 6 / §8.6).
type RefuseReason byte

const (
	RefuseUnknown            RefuseReason = 0x00
	RefuseCompleted          RefuseReason = 0x01
	RefuseNoResources        RefuseReason = 0x02
	RefuseRetransmit         RefuseReason = 0x03
	RefuseNotAcceptable      RefuseReason = 0x04
	RefuseExtensionFailure   RefuseReason = 0x05
	RefuseSessionTerminating RefuseReason = 0x06
)

func (r RefuseReason) String() string {
	switch r {
	case RefuseUnknown:
		return "Unknown"
	case RefuseCompleted:
		return "Completed"
	case RefuseNoResources:
		return "No Resources"
	case RefuseRetransmit:
		return "Retransmit"
	case RefuseNotAcceptable:
		return "Not Acceptable"
	case RefuseExtensionFailure:
		return "Extension Failure"
	case RefuseSessionTerminating:
		return "Session Terminating"
	}
	return "refuse-reason(0x00)"
}

// RejectReason is the MSG_REJECT reason code (§5.1.2 Table 4).
type RejectReason byte

const (
	RejectTypeUnknown RejectReason = 0x01
	RejectUnsupported RejectReason = 0x02
	RejectUnexpected  RejectReason = 0x03
)

func (r RejectReason) String() string {
	switch r {
	case RejectTypeUnknown:
		return "Message Type Unknown"
	case RejectUnsupported:
		return "Message Unsupported"
	case RejectUnexpected:
		return "Message Unexpected"
	}
	return "reject-reason(0x00)"
}

// Session errors — the fail-closed vocabulary of the layer. Every one of
// these terminates the session (or refuses the transfer) without ever
// leaving the peer's bytes unparsed.
var (
	// ErrHandshake covers contact-header and negotiation failures (§4.3).
	ErrHandshake = errors.New("tcpcl: contact handshake failed")
	// ErrBadMagic is a contact header whose magic is not "dtn!" (§4.3: the
	// connection MUST be terminated; an inadvertent-protocol guard).
	ErrBadMagic = errors.New("tcpcl: contact header magic is not \"dtn!\"")
	// ErrBadVersion is a contact header version ≠ 4 (profile speaks v4 only,
	// no fallback ladder).
	ErrBadVersion = errors.New("tcpcl: contact header version is not 4")
	// ErrTLSRequired is the profile policy verdict on Enable TLS = false
	// (§4.3: terminate with "Contact Failure"; TLS stripping is not ours to
	// tolerate — node-network §6.2 item 4 pins TLS 1.3).
	ErrTLSRequired = errors.New("tcpcl: peer refused TLS (profile requires TLS 1.3)")
	// ErrProtocol is any post-establishment framing/state violation: after a
	// best-effort MSG_REJECT, the session dies (fail-closed).
	ErrProtocol = errors.New("tcpcl: protocol violation")
	// ErrSessionClosed is returned by SendBundle after the session ended.
	ErrSessionClosed = errors.New("tcpcl: session closed")
	// ErrSessionEnding is SendBundle during the §6.1 Ending state (no new
	// transfers; in-progress ones MAY finish).
	ErrSessionEnding = errors.New("tcpcl: session is terminating")
	// ErrBudgetDeferred is the §7.4 egress gate: the transfer does not fit
	// this contact's remaining byte budget; the sender defers it (P3.5's
	// queue keeps it for the next contact).
	ErrBudgetDeferred = errors.New("tcpcl: transfer exceeds the per-contact egress budget; deferred")
	// ErrTransferRefused wraps a peer XFER_REFUSE delivered to the sender.
	ErrTransferRefused = errors.New("tcpcl: transfer refused by peer")
	// ErrIdleTimeout is the local §5.1.1 idle termination.
	ErrIdleTimeout = errors.New("tcpcl: idle timeout (missed keepalives)")
	// ErrPeerIdentity is the SESS_INIT/certificate identity mismatch: the
	// peer's node ID is not the identity its certificate certifies (or not
	// the one this session expected). Loud, always.
	ErrPeerIdentity = errors.New("tcpcl: peer identity mismatch")
)
