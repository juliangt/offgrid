// bundle.go — `capsuletool bundle make` and `capsuletool bundle send`: the
// node-plane bundle companions of the offline ceremonies (docs/node-network.md
// §6.3/§7.1; issue #33 P3.5). Deterministic flags in, stable key=value lines
// out; `make` is offline, `send` is exactly one TCPCL contact.
//
//	capsuletool bundle make --out FILE (--payload-text S | --payload FILE)
//	                        [--ttl S] [--created-unix-ms T]
//	    Encodes an anonymous mail bundle (the P-4 shape: dtn:none →
//	    dtn:og-mail, payload = the bytes verbatim behind the hop octet) and
//	    prints bundle_id= (the P-7 dedup key). The E2E cargo generator.
//
//	capsuletool bundle send --host H:PORT --pdu FILE --seed FILE
//	                        [--pins FILE | --insecure-skip-pin] [--timeout S]
//	    A minimal one-shot TCPCLv4 client: TLS 1.3, mTLS, TOFU pin — the
//	    exact §6.1 machinery the daemon runs. `--pins FILE` loads (or
//	    creates, 0600) the SAME PinStore format the daemon keeps and
//	    checkpoints it after a successful contact; the explicit escape
//	    hatch `--insecure-skip-pin` discards the server pin instead
//	    (loopback tests only — first-contact substitution would go
//	    unnoticed, which is exactly what the §6.1 loud warning prevents).
//
// The daemon's P3.5 sync engine answers with its §7.1 summary bundle on
// every contact; this client's sink discards it (a non-sync peer is a
// legitimate node-plane citizen — the engine gives up after its wait).

package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"time"

	"offgrid/dtn-node/internal/bundle"
	"offgrid/dtn-node/internal/nodeid"
	"offgrid/dtn-node/internal/tcpcl"
)

func cmdBundle(args []string, out, errw io.Writer) int {
	if len(args) == 0 {
		return fatalf(errw, "bundle: want subcommand make|send")
	}
	switch args[0] {
	case "make":
		return cmdBundleMake(args[1:], out, errw)
	case "send":
		return cmdBundleSend(args[1:], out, errw)
	default:
		return fatalf(errw, "bundle: unknown subcommand %q", args[0])
	}
}

func cmdBundleMake(args []string, out, errw io.Writer) int {
	f, code := parseFlags(args, errw, map[string]bool{
		"out": true, "payload-text": true, "payload": true,
		"ttl": true, "created-unix-ms": true,
	})
	if code >= 0 {
		return code
	}
	outPath, code := f.req(errw, "out")
	if code >= 0 {
		return code
	}
	if f.has("payload-text") == f.has("payload") {
		return fatalf(errw, "bundle make: exactly one of --payload-text S or --payload FILE is required")
	}
	var payload []byte
	if v, ok := f["payload-text"]; ok {
		payload = []byte(v)
	} else {
		b, err := os.ReadFile(f["payload"])
		if err != nil {
			return fatalf(errw, "%v", err)
		}
		payload = b
	}
	created := time.Now().UnixMilli()
	if v, ok := f["created-unix-ms"]; ok {
		ms, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return fatalf(errw, "--created-unix-ms %q is not a number", v)
		}
		created = ms
	}
	ttl := uint64(7 * 24 * 3600) // the envelope-TTL default (one week)
	if v, ok := f["ttl"]; ok {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil || n == 0 {
			return fatalf(errw, "--ttl %q is not a positive number of seconds", v)
		}
		ttl = n
	}
	b, err := bundle.NewMail(payload, created, ttl)
	if err != nil {
		return fatalf(errw, "%v", err)
	}
	pdu, err := bundle.Encode(b)
	if err != nil {
		return fatalf(errw, "%v", err)
	}
	if err := os.WriteFile(outPath, pdu, 0o644); err != nil {
		return fatalf(errw, "%v", err)
	}
	id, err := bundle.BundleIDOf(pdu)
	if err != nil {
		return fatalf(errw, "%v", err)
	}
	fmt.Fprintf(out, "bundle_id=%s\nbytes=%d\nttl=%d\ncreated_unix_ms=%d\n",
		hex.EncodeToString(id[:]), len(pdu), ttl, created)
	return exitOK
}

func cmdBundleSend(args []string, out, errw io.Writer) int {
	f, code := parseFlags(args, errw, map[string]bool{
		"host": true, "pdu": true, "seed": true, "pins": true,
		"insecure-skip-pin": false, "timeout": true,
	})
	if code >= 0 {
		return code
	}
	host, code := f.req(errw, "host")
	if code >= 0 {
		return code
	}
	pduPath, code := f.req(errw, "pdu")
	if code >= 0 {
		return code
	}
	seedPath, code := f.req(errw, "seed")
	if code >= 0 {
		return code
	}
	if f.has("insecure-skip-pin") == f.has("pins") {
		return fatalf(errw, "bundle send: exactly one of --pins FILE (the §6.1 TOFU store) or --insecure-skip-pin (loopback tests only) is required")
	}
	timeout := 10 * time.Second
	if v, ok := f["timeout"]; ok {
		secs, err := strconv.Atoi(v)
		if err != nil || secs <= 0 {
			return fatalf(errw, "--timeout %q is not a positive number of seconds", v)
		}
		timeout = time.Duration(secs) * time.Second
	}

	pdu, err := os.ReadFile(pduPath)
	if err != nil {
		return fatalf(errw, "%v", err)
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
	cert, err := nodeid.SelfSignedX509(kp, eid, 24*time.Hour)
	if err != nil {
		return fatalf(errw, "%v", err)
	}

	pinsPath := f["pins"]
	pins, err := loadToolPinStore(pinsPath, errw)
	if err != nil {
		return fatalf(errw, "%v", err)
	}
	if f.has("insecure-skip-pin") {
		// Explicit, loud, and discarded: a throwaway store gives the
		// handshake SOMEwhere to pin, but nothing survives the process.
		fmt.Fprintln(errw, "capsuletool: WARNING: --insecure-skip-pin — the server's node key is NOT persisted; use --pins for anything but loopback tests")
		pins = nodeid.NewPinStore()
	}

	cfg := tcpcl.Config{
		EID:           eid,
		Identity:      cert,
		Pins:          pins,
		MTLS:          tcpcl.MTLSRequired,
		Keepalive:     -1, // a one-shot contact needs no keepalives
		ContactBudget: tcpcl.DefaultContactBudget,
		Sink:          discardSink{}, // the daemon's summary bundle is absorbed
		Log:           log.New(errw, "", 0),
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	sess, err := tcpcl.Dial(ctx, "tcp", host, cfg)
	if err != nil {
		return fatalf(errw, "dial %s: %v", host, err)
	}
	peer := sess.PeerEID()
	if err := sess.SendBundle(ctx, pdu); err != nil {
		_ = sess.Close()
		return fatalf(errw, "send: %v", err)
	}
	_ = sess.Terminate(tcpcl.TermUnknown)

	if pinsPath != "" {
		if err := writeToolPinStore(pinsPath, pins); err != nil {
			return fatalf(errw, "checkpoint pins: %v", err)
		}
	}
	// The id the receiving store keys on: the P-7 digest, computed by the
	// same codec the daemon admits with (a malformed PDU fails here first,
	// before any wire byte).
	id, err := bundle.BundleIDOf(pdu)
	if err != nil {
		return fatalf(errw, "%s is not a profile bundle: %v", pduPath, err)
	}
	fmt.Fprintf(out, "peer=%s\nbundle_id=%s\nbytes=%d\n", peer, hex.EncodeToString(id[:]), len(pdu))
	return exitOK
}

// loadToolPinStore loads (or creates) the §6.1 PinStore file — the exact
// format the daemon checkpoints.
func loadToolPinStore(path string, errw io.Writer) (*nodeid.PinStore, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		fmt.Fprintf(errw, "capsuletool: pins file %s absent — first contact will TOFU-record the server's key\n", path)
		return nodeid.NewPinStore(), nil
	}
	return nodeid.UnmarshalPinStore(raw)
}

// writeToolPinStore persists the store atomically, 0600 (trust state).
func writeToolPinStore(path string, pins *nodeid.PinStore) error {
	blob, err := pins.Marshal()
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, blob, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// discardSink absorbs everything (the §7.1 summary of the peer).
type discardSink struct{}

func (discardSink) Accept([]byte) error { return nil }
