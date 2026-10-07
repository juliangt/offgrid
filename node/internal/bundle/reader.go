package bundle

import (
	"fmt"
	"unicode/utf8"
)

// A minimal canonical-CBOR READER (RFC 8949 subset) for the node plane —
// the decode counterpart of this package's spike encoder. Scope, identical
// to the C reader of dtn_core (dtn_cbor.c) so Go and C fail on the same
// bytes:
//
//   - major types 0-5 plus the type-7 `null` needed by the BPv7 profile;
//   - definite lengths only; indefinite-length items are REJECTED in v1;
//   - reserved additional-info values (28-30) are rejected;
//   - fail-closed on truncation (a value may never run past the buffer);
//   - nesting depth is bounded (arrays/maps), recursion in skipVal bounded.
//
// Strings are returned as views into the input (zero copy); bstr contents
// are therefore immutable and the caller must not retain them past the next
// read.
//
// Provenance: promoted from node/internal/nodeid (P3.1) into this package
// for P3.2 — the profile codec is its primary consumer, and nodeid reads
// through the exported CborReader alias below. The C mirror of every rule
// here is dtn_core's dtn_cbor.c.

const cborMaxDepth = 32

type cborReader struct {
	buf   []byte
	off   int
	depth int
}

func newCborReader(b []byte) *cborReader { return &cborReader{buf: b} }

// CborReader is the canonical-CBOR reader above, exported so the sibling
// node-plane packages decode from this ONE implementation (the role
// certificates of internal/nodeid consume it through this alias). An alias —
// not a wrapper — so the reader's own methods keep working unchanged.
type CborReader = cborReader

// NewCborReader returns a reader over b. Views returned by Bstr/Tstr point
// into b and are only valid until the next read on the same reader.
func NewCborReader(b []byte) *CborReader { return newCborReader(b) }

// Pos returns the current read offset (for callers that need to know where
// a value started or how many bytes remain).
func (r *cborReader) Pos() int { return r.off }

func (r *cborReader) errAt(format string, a ...any) error {
	return fmt.Errorf("cbor at offset %d: %s", r.off, fmt.Sprintf(format, a...))
}

// head reads one head and requires major type `major`; returns the value
// argument for definite lengths.
func (r *cborReader) head(major byte) (uint64, error) {
	if r.off >= len(r.buf) {
		return 0, r.errAt("truncated (expected major %d)", major)
	}
	b := r.buf[r.off]
	if b>>5 != major {
		return 0, r.errAt("expected major type %d, got %d (0x%02x)", major, b>>5, b)
	}
	ai := b & 0x1f
	r.off++
	switch {
	case ai < 24:
		return uint64(ai), nil
	case ai == 24:
		return r.uintN(1)
	case ai == 25:
		return r.uintN(2)
	case ai == 26:
		return r.uintN(4)
	case ai == 27:
		return r.uintN(8)
	case ai >= 28 && ai <= 30:
		return 0, r.errAt("reserved additional info %d", ai)
	default: // 31: indefinite length — not in v1
		return 0, r.errAt("indefinite length is rejected in v1 (0x%02x)", b)
	}
}

func (r *cborReader) uintN(n int) (uint64, error) {
	if len(r.buf)-r.off < n {
		return 0, r.errAt("truncated uint argument (want %d bytes, have %d)", n, len(r.buf)-r.off)
	}
	var v uint64
	for i := 0; i < n; i++ {
		v = v<<8 | uint64(r.buf[r.off+i])
	}
	r.off += n
	return v, nil
}

// Uint reads major type 0.
func (r *cborReader) Uint() (uint64, error) { return r.head(0) }

// Int reads major types 0 (n ≥ 0) and 1 (n = -1-arg).
func (r *cborReader) Int() (int64, error) {
	if r.off >= len(r.buf) {
		return 0, r.errAt("truncated (expected int)")
	}
	major := r.buf[r.off] >> 5
	switch major {
	case 0:
		u, err := r.head(0)
		if err != nil {
			return 0, err
		}
		if u > 1<<63-1 {
			return 0, r.errAt("uint %d overflows int64", u)
		}
		return int64(u), nil
	case 1:
		u, err := r.head(1)
		if err != nil {
			return 0, err
		}
		if u > 1<<63-1 {
			return 0, r.errAt("negative int -1-%d overflows int64", u)
		}
		return -1 - int64(u), nil
	default:
		return 0, r.errAt("expected int, got major %d", major)
	}
}

// Bstr reads major type 2 as a view into the underlying buffer.
func (r *cborReader) Bstr() ([]byte, error) {
	n, err := r.head(2)
	if err != nil {
		return nil, err
	}
	if uint64(len(r.buf)-r.off) < n {
		return nil, r.errAt("truncated bstr (want %d, have %d)", n, len(r.buf)-r.off)
	}
	out := r.buf[r.off : r.off+int(n)]
	r.off += int(n)
	return out, nil
}

// Tstr reads major type 3 as a Go string; contents must be valid UTF-8.
func (r *cborReader) Tstr() (string, error) {
	n, err := r.head(3)
	if err != nil {
		return "", err
	}
	if uint64(len(r.buf)-r.off) < n {
		return "", r.errAt("truncated tstr (want %d, have %d)", n, len(r.buf)-r.off)
	}
	s := string(r.buf[r.off : r.off+int(n)])
	r.off += int(n)
	if !utf8.ValidString(s) {
		return "", r.errAt("tstr is not valid UTF-8")
	}
	return s, nil
}

// Array reads major type 4 and enters the value (depth-bounded).
func (r *cborReader) Array() (int, error) {
	n, err := r.head(4)
	if err != nil {
		return 0, err
	}
	if n > uint64(len(r.buf)) { // each item needs ≥ 1 byte
		return 0, r.errAt("array of %d items cannot fit the buffer", n)
	}
	r.depth++
	if r.depth > cborMaxDepth {
		return 0, r.errAt("nesting depth exceeds %d", cborMaxDepth)
	}
	return int(n), nil
}

// Map reads major type 5 and enters the value (depth-bounded).
func (r *cborReader) Map() (int, error) {
	n, err := r.head(5)
	if err != nil {
		return 0, err
	}
	if n > uint64(len(r.buf)) { // each pair needs ≥ 2 bytes; 1 per entry is a cheap floor
		return 0, r.errAt("map of %d pairs cannot fit the buffer", n)
	}
	r.depth++
	if r.depth > cborMaxDepth {
		return 0, r.errAt("nesting depth exceeds %d", cborMaxDepth)
	}
	return int(n), nil
}

// Pop leaves the innermost array/map.
func (r *cborReader) Pop() {
	if r.depth > 0 {
		r.depth--
	}
}

// Null reads the type-7 null (0xf6).
func (r *cborReader) Null() error {
	if r.off >= len(r.buf) {
		return r.errAt("truncated (expected null)")
	}
	b := r.buf[r.off]
	if b != 0xf6 {
		return r.errAt("expected null (0xf6), got 0x%02x", b)
	}
	r.off++
	return nil
}

// Done reports whether the whole buffer was consumed (fail-closed on
// trailing garbage).
func (r *cborReader) Done() bool { return r.off == len(r.buf) }

// Skip consumes any single value (recursion bounded by cborMaxDepth).
func (r *cborReader) Skip() error {
	if r.off >= len(r.buf) {
		return r.errAt("truncated (skip at end)")
	}
	if r.depth >= cborMaxDepth {
		return r.errAt("nesting depth exceeds %d", cborMaxDepth)
	}
	b := r.buf[r.off]
	switch b >> 5 {
	case 0:
		_, err := r.Uint()
		return err
	case 1:
		_, err := r.head(1)
		return err
	case 2:
		_, err := r.Bstr()
		return err
	case 3:
		_, err := r.Tstr()
		return err
	case 4:
		n, err := r.Array()
		if err != nil {
			return err
		}
		for i := 0; i < n; i++ {
			if err := r.Skip(); err != nil {
				return err
			}
		}
		r.Pop()
		return nil
	case 5:
		n, err := r.Map()
		if err != nil {
			return err
		}
		for i := 0; i < 2*n; i++ {
			if err := r.Skip(); err != nil {
				return err
			}
		}
		r.Pop()
		return nil
	default: // 7: null only in v1; floats/tags rejected
		if b == 0xf6 {
			return r.Null()
		}
		if b>>5 == 6 {
			return r.errAt("CBOR tags are rejected in v1 (0x%02x)", b)
		}
		return r.errAt("simple/float value 0x%02x is rejected in v1", b)
	}
}
