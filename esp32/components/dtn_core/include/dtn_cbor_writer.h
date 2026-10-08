/* dtn_cbor_writer.h — minimal canonical-CBOR WRITER (RFC 8949 preferred
 * serialization subset) for the dtn_core portable core (P3.2 bundle codec).
 *
 * The encode counterpart of dtn_cbor.h's reader, mirroring Go's canonical
 * encoder of node/internal/bundle (spike.go): major types 0/2/3/4 plus the
 * type-7 null the BPv7 profile needs. Every head is the shortest encoding
 * of its value; only definite lengths exist. No floats, no tags, no maps —
 * the bundle profile has none (role certs stay Go-encoded; the C side is a
 * verify-only consumer there).
 *
 * Buffers are caller-owned (no malloc): a write that does not fit sets the
 * sticky err flag; dtn_cbor_w_ok reports it. Sticky means later calls are
 * no-ops, so builders never need per-call checks.
 */
#ifndef DTN_CBOR_WRITER_H
#define DTN_CBOR_WRITER_H

#include <stddef.h>
#include <stdint.h>

#define DTN_CBOR_W_ERR_NOSPACE (-1)

typedef struct {
    uint8_t *buf;
    size_t cap;
    size_t len;
    int err; /* sticky: 0 = ok */
} dtn_cbor_writer;

void dtn_cbor_writer_init(dtn_cbor_writer *w, uint8_t *buf, size_t cap);
int dtn_cbor_w_ok(const dtn_cbor_writer *w); /* 1 when no error is set */

void dtn_cbor_w_uint(dtn_cbor_writer *w, uint64_t v); /* major 0, shortest head */
void dtn_cbor_w_bstr(dtn_cbor_writer *w, const uint8_t *b, size_t n); /* major 2 */
void dtn_cbor_w_tstr(dtn_cbor_writer *w, const char *s);              /* major 3 */
void dtn_cbor_w_array(dtn_cbor_writer *w, size_t n);                  /* major 4 */
void dtn_cbor_w_null(dtn_cbor_writer *w);                             /* 0xf6 */

/* dtn_cbor_w_raw appends bytes verbatim — for the CONTENT of a length
 * already declared by dtn_cbor_w_bstr's head (the writer never inspects
 * it; canonicality stays the head's job). */
void dtn_cbor_w_raw(dtn_cbor_writer *w, const uint8_t *b, size_t n);

#endif /* DTN_CBOR_WRITER_H */
