// Package serialcl implements the Pi-bridge leg of the §3 convergence
// layers (docs/node-network.md): the SAME §5.4 link frames carried over a
// serial/io channel between the bridge daemon and a radio head (the
// ESP32-S3 + SX1262 node of §12.3), instead of over the air.
//
// Wire format (frozen, §5.5): [len: 2 bytes big-endian] ‖ [link frame].
// The length covers the frame only (header + payload + AEAD tag; ≤ 252 B
// on air — the prefix exists because a UART stream has no frame
// boundaries, which radio bursts provide for free). Values above
// maxFrameLen fail closed (a 2-byte prefix covers 64 KiB; the bound keeps
// a hostile or garbled stream from allocating it).
//
// Session coupling: a Transport carries session-protected frames through
// its *link.Session (nil session = beacons only, §6.1's fail-closed rule).
// The C counterpart (the radio head's serial leg) speaks the identical
// prefix + frame bytes and is pinned by the shared link vectors.
package serialcl

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync"
)

// The frozen §5.5 serial-CL framing constants.
const (
	// PrefixLen is the 2-byte big-endian length prefix.
	PrefixLen = 2
	// MaxFrameLen bounds one length-prefixed frame (the §5.4 on-air
	// maximum of 252 B, with headroom for future flag-defined shapes).
	MaxFrameLen = 1024
)

// ErrTruncated is returned when the stream ends mid-frame.
var ErrTruncated = fmt.Errorf("serialcl: stream ended mid-frame")

// ErrTooLarge is returned for a length prefix above MaxFrameLen — a
// garbled or hostile stream fails closed instead of allocating.
var ErrTooLarge = fmt.Errorf("serialcl: length prefix exceeds the frame bound")

// Transport reads and writes length-prefixed link frames over an
// io.ReadWriteCloser. WriteFrame is mutex-serialized (one writer at a
// time, the §3 bridge's send path); reads are the caller's single read
// loop (ReadFrame / Serve).
type Transport struct {
	conn io.ReadWriteCloser
	wmu  sync.Mutex
}

// NewTransport wraps a serial-style connection.
func NewTransport(conn io.ReadWriteCloser) *Transport {
	return &Transport{conn: conn}
}

// WriteFrame writes one length-prefixed frame (the frame is whatever the
// caller built — a §5.4 link frame; this layer adds only the prefix). The
// prefix and frame go out in ONE Write: a serial link has no message
// boundaries, and splitting the write would let an interrupted flush
// wedge the stream mid-prefix.
func (t *Transport) WriteFrame(frame []byte) error {
	if len(frame) == 0 || len(frame) > MaxFrameLen {
		return fmt.Errorf("serialcl: frame length %d outside 1..%d", len(frame), MaxFrameLen)
	}
	out := make([]byte, 0, PrefixLen+len(frame))
	var prefix [PrefixLen]byte
	binary.BigEndian.PutUint16(prefix[:], uint16(len(frame)))
	out = append(out, prefix[:]...)
	out = append(out, frame...)
	t.wmu.Lock()
	defer t.wmu.Unlock()
	if _, err := t.conn.Write(out); err != nil {
		return fmt.Errorf("serialcl: write: %w", err)
	}
	return nil
}

// ReadFrame blocks for one length-prefixed frame.
func (t *Transport) ReadFrame() ([]byte, error) {
	var prefix [PrefixLen]byte
	if _, err := io.ReadFull(t.conn, prefix[:]); err != nil {
		if err == io.ErrUnexpectedEOF {
			return nil, ErrTruncated
		}
		return nil, err // io.EOF = clean stream end
	}
	n := binary.BigEndian.Uint16(prefix[:])
	if n == 0 || n > MaxFrameLen {
		return nil, ErrTooLarge
	}
	frame := make([]byte, n)
	if _, err := io.ReadFull(t.conn, frame); err != nil {
		if err == io.ErrUnexpectedEOF {
			return nil, ErrTruncated
		}
		return nil, err
	}
	return frame, nil
}

// Close closes the underlying connection.
func (t *Transport) Close() error { return t.conn.Close() }

// Serve runs the read loop until the stream ends, handing each frame to
// handler. The handler owns frame interpretation (OpenFrame/ParseFrame).
func (t *Transport) Serve(handler func(frame []byte) error) error {
	for {
		frame, err := t.ReadFrame()
		if err != nil {
			return err
		}
		if herr := handler(frame); herr != nil {
			return herr
		}
	}
}
