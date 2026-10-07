/* dtn_cbor_writer.c — canonical-CBOR writer; see dtn_cbor_writer.h for the
 * contract. The head math mirrors node/internal/bundle/spike.go's encoder
 * byte for byte (preferred serialization: shortest-form heads only). */
#include "dtn_cbor_writer.h"

#include <string.h>

void dtn_cbor_writer_init(dtn_cbor_writer *w, uint8_t *buf, size_t cap)
{
    w->buf = buf;
    w->cap = cap;
    w->len = 0;
    w->err = 0;
}

int dtn_cbor_w_ok(const dtn_cbor_writer *w)
{
    return w->err == 0;
}

/* put appends n bytes, or sets the sticky flag when they do not fit. */
static void put(dtn_cbor_writer *w, const uint8_t *b, size_t n)
{
    if (w->err) return;
    if (w->cap - w->len < n) {
        w->err = DTN_CBOR_W_ERR_NOSPACE;
        return;
    }
    memcpy(w->buf + w->len, b, n);
    w->len += n;
}

static void put_byte(dtn_cbor_writer *w, uint8_t b)
{
    put(w, &b, 1);
}

/* w_head emits major|ai plus the shortest argument encoding. */
static void w_head(dtn_cbor_writer *w, uint8_t major, uint64_t val)
{
    uint8_t arg[8];
    if (val < 24) {
        put_byte(w, (uint8_t)(major << 5) | (uint8_t)val);
        return;
    }
    if (val <= 0xff) {
        arg[0] = (uint8_t)val;
        put_byte(w, (uint8_t)(major << 5) | 24);
        put(w, arg, 1);
        return;
    }
    if (val <= 0xffff) {
        arg[0] = (uint8_t)(val >> 8);
        arg[1] = (uint8_t)val;
        put_byte(w, (uint8_t)(major << 5) | 25);
        put(w, arg, 2);
        return;
    }
    if (val <= 0xffffffffULL) {
        arg[0] = (uint8_t)(val >> 24);
        arg[1] = (uint8_t)(val >> 16);
        arg[2] = (uint8_t)(val >> 8);
        arg[3] = (uint8_t)val;
        put_byte(w, (uint8_t)(major << 5) | 26);
        put(w, arg, 4);
        return;
    }
    arg[0] = (uint8_t)(val >> 56);
    arg[1] = (uint8_t)(val >> 48);
    arg[2] = (uint8_t)(val >> 40);
    arg[3] = (uint8_t)(val >> 32);
    arg[4] = (uint8_t)(val >> 24);
    arg[5] = (uint8_t)(val >> 16);
    arg[6] = (uint8_t)(val >> 8);
    arg[7] = (uint8_t)val;
    put_byte(w, (uint8_t)(major << 5) | 27);
    put(w, arg, 8);
}

void dtn_cbor_w_uint(dtn_cbor_writer *w, uint64_t v)
{
    w_head(w, 0, v);
}

void dtn_cbor_w_bstr(dtn_cbor_writer *w, const uint8_t *b, size_t n)
{
    w_head(w, 2, (uint64_t)n);
    put(w, b, n);
}

void dtn_cbor_w_tstr(dtn_cbor_writer *w, const char *s)
{
    size_t n = strlen(s);
    w_head(w, 3, (uint64_t)n);
    put(w, (const uint8_t *)s, n);
}

void dtn_cbor_w_array(dtn_cbor_writer *w, size_t n)
{
    w_head(w, 4, (uint64_t)n);
}

void dtn_cbor_w_null(dtn_cbor_writer *w)
{
    put_byte(w, 0xf6);
}

void dtn_cbor_w_raw(dtn_cbor_writer *w, const uint8_t *b, size_t n)
{
    put(w, b, n);
}
