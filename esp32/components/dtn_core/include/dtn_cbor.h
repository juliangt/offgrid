/* dtn_cbor.h — minimal canonical-CBOR READER (RFC 8949 subset) for the
 * dtn_core portable core (P3.1 role certs; P3.2's bundle codec consumes the
 * same reader).
 *
 * Scope — identical to the Go reader of node/internal/nodeid/cborread.go so
 * Go and C fail on the same bytes:
 *   - major types 0-5 plus the type-7 `null` the BPv7 profile needs;
 *   - definite lengths only; indefinite-length items are REJECTED in v1;
 *   - reserved additional-info values (28-30) are rejected;
 *   - fail-closed on truncation (a value never runs past the buffer);
 *   - nesting depth bounded (DTN_CBOR_MAX_DEPTH);
 *   - tstr contents must be valid UTF-8.
 * Strings are returned as views into the input buffer (zero copy); the view
 * is only valid until the next reader call on the same dtn_cbor. After any
 * error return the cursor position is unspecified: a caller must not keep
 * reading the same dtn_cbor past an error (re-init to try another shape). */
#ifndef DTN_CBOR_H
#define DTN_CBOR_H

#include <stddef.h>
#include <stdint.h>

#define DTN_CBOR_MAX_DEPTH 32

/* Error codes (all < 0; DTN_CBOR_OK = 0). */
enum {
    DTN_CBOR_OK = 0,
    DTN_CBOR_ERR_TRUNCATED = -1,
    DTN_CBOR_ERR_INDEFINITE = -2,
    DTN_CBOR_ERR_RESERVED = -3,
    DTN_CBOR_ERR_DEPTH = -4,
    DTN_CBOR_ERR_TYPE = -5,
    DTN_CBOR_ERR_UTF8 = -6,
    DTN_CBOR_ERR_RANGE = -7, /* uint value does not fit the caller's type */
};

typedef struct {
    const uint8_t *buf;
    size_t len;
    size_t off;
    int depth;
} dtn_cbor;

void dtn_cbor_init(dtn_cbor *c, const uint8_t *buf, size_t len);

int dtn_cbor_uint(dtn_cbor *c, uint64_t *out); /* major 0 */
int dtn_cbor_int(dtn_cbor *c, int64_t *out);   /* major 0 or 1 */
int dtn_cbor_bstr(dtn_cbor *c, const uint8_t **out, size_t *out_len); /* major 2 */
int dtn_cbor_tstr(dtn_cbor *c, const char **out, size_t *out_len);   /* major 3 */
int dtn_cbor_array(dtn_cbor *c, size_t *items); /* major 4; enters (depth+1) */
int dtn_cbor_map(dtn_cbor *c, size_t *pairs);   /* major 5; enters (depth+1) */
void dtn_cbor_pop(dtn_cbor *c);                 /* leave the innermost array/map */
int dtn_cbor_null(dtn_cbor *c);                 /* 0xf6 */
int dtn_cbor_skip(dtn_cbor *c);                 /* skip any value (depth-bounded) */

/* dtn_cbor_done — 1 when the whole input was consumed (callers checking
 * trailing garbage must call this; a top-level parse is not done until it
 * returns 1). */
int dtn_cbor_done(const dtn_cbor *c);

/* dtn_cbor_peek — the next head byte WITHOUT consuming it (0 ok / nonzero
 * at end of input). Callers dispatch on the major type (*head >> 5) before
 * the typed read; the cursor is untouched. The mgmt command object's args
 * map is the consumer (P3.6) — the Go reader's Peek is its twin. */
int dtn_cbor_peek(const dtn_cbor *c, uint8_t *head);

#endif /* DTN_CBOR_H */
