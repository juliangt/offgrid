/* dtn_cbor.c — minimal canonical-CBOR reader; see dtn_cbor.h for the
 * contract. The byte-level decisions mirror the Go reader of
 * node/internal/nodeid/cborread.go so the shared vectors fail identically
 * on both sides. */
#include "dtn_cbor.h"

#include <string.h>

void dtn_cbor_init(dtn_cbor *c, const uint8_t *buf, size_t len)
{
    c->buf = buf;
    c->len = len;
    c->off = 0;
    c->depth = 0;
}

/* read_head consumes one head byte plus its argument; returns the value and
 * sets *major. Fails closed on truncation, reserved and indefinite heads. */
static int read_head(dtn_cbor *c, uint8_t *major, uint64_t *value)
{
    uint8_t b, ai;
    int nbytes;

    if (c->off >= c->len) {
        return DTN_CBOR_ERR_TRUNCATED;
    }
    b = c->buf[c->off];
    *major = (uint8_t)(b >> 5);
    ai = (uint8_t)(b & 0x1f);
    c->off++;
    if (ai < 24) {
        *value = ai;
        return DTN_CBOR_OK;
    }
    switch (ai) {
    case 24: nbytes = 1; break;
    case 25: nbytes = 2; break;
    case 26: nbytes = 4; break;
    case 27: nbytes = 8; break;
    case 31: return DTN_CBOR_ERR_INDEFINITE;
    default: return DTN_CBOR_ERR_RESERVED; /* 28-30 */
    }
    if (c->len - c->off < (size_t)nbytes) {
        return DTN_CBOR_ERR_TRUNCATED;
    }
    *value = 0;
    for (int i = 0; i < nbytes; i++) {
        *value = (*value << 8) | c->buf[c->off + i];
    }
    c->off += (size_t)nbytes;
    return DTN_CBOR_OK;
}

int dtn_cbor_uint(dtn_cbor *c, uint64_t *out)
{
    uint8_t major;
    uint64_t v;
    int rc = read_head(c, &major, &v);
    if (rc != DTN_CBOR_OK) return rc;
    if (major != 0) return DTN_CBOR_ERR_TYPE;
    *out = v;
    return DTN_CBOR_OK;
}

int dtn_cbor_int(dtn_cbor *c, int64_t *out)
{
    uint8_t major;
    uint64_t v;
    int rc = read_head(c, &major, &v);
    if (rc != DTN_CBOR_OK) return rc;
    if (major == 0) {
        if (v > (uint64_t)0x7fffffffffffffffULL) return DTN_CBOR_ERR_RANGE;
        *out = (int64_t)v;
        return DTN_CBOR_OK;
    }
    if (major == 1) {
        if (v > (uint64_t)0x7fffffffffffffffULL) return DTN_CBOR_ERR_RANGE;
        *out = -1 - (int64_t)v;
        return DTN_CBOR_OK;
    }
    return DTN_CBOR_ERR_TYPE;
}

/* read_string_body — the length-checked contents of a 2/3-type value. */
static int read_string_body(dtn_cbor *c, uint64_t n, const void **out, size_t *out_len)
{
    if (n > (uint64_t)(c->len - c->off)) {
        return DTN_CBOR_ERR_TRUNCATED;
    }
    *out = c->buf + c->off;
    *out_len = (size_t)n;
    c->off += (size_t)n;
    return DTN_CBOR_OK;
}

int dtn_cbor_bstr(dtn_cbor *c, const uint8_t **out, size_t *out_len)
{
    uint8_t major;
    uint64_t n;
    int rc = read_head(c, &major, &n);
    if (rc != DTN_CBOR_OK) return rc;
    if (major != 2) return DTN_CBOR_ERR_TYPE;
    return read_string_body(c, n, (const void **)out, out_len);
}

/* utf8_valid — compact validator: rejects truncated sequences, overlongs,
 * surrogates and values above U+10FFFF. */
static int utf8_valid(const char *s, size_t n)
{
    size_t i = 0;
    while (i < n) {
        uint8_t b = (uint8_t)s[i];
        if (b < 0x80) {
            i++;
            continue;
        }
        uint32_t cp;
        int extra;
        if ((b & 0xe0) == 0xc0) { cp = b & 0x1f; extra = 1; }
        else if ((b & 0xf0) == 0xe0) { cp = b & 0x0f; extra = 2; }
        else if ((b & 0xf8) == 0xf0) { cp = b & 0x07; extra = 3; }
        else return 0;
        if (i + (size_t)extra >= n) {
            return 0; /* truncated sequence */
        }
        for (int k = 1; k <= extra; k++) {
            uint8_t cb = (uint8_t)s[i + k];
            if ((cb & 0xc0) != 0x80) return 0;
            cp = (cp << 6) | (cb & 0x3f);
        }
        if (extra == 1 && cp < 0x80) return 0;      /* overlong */
        if (extra == 2 && cp < 0x800) return 0;     /* overlong */
        if (extra == 3 && cp < 0x10000) return 0;   /* overlong */
        if (cp >= 0xd800 && cp <= 0xdfff) return 0; /* surrogate */
        if (cp > 0x10ffff) return 0;
        i += (size_t)extra + 1;
    }
    return 1;
}

int dtn_cbor_tstr(dtn_cbor *c, const char **out, size_t *out_len)
{
    uint8_t major;
    uint64_t n;
    int rc = read_head(c, &major, &n);
    if (rc != DTN_CBOR_OK) return rc;
    if (major != 3) return DTN_CBOR_ERR_TYPE;
    if (n > (uint64_t)(c->len - c->off)) {
        return DTN_CBOR_ERR_TRUNCATED;
    }
    if (!utf8_valid((const char *)c->buf + c->off, (size_t)n)) {
        return DTN_CBOR_ERR_UTF8;
    }
    *out = (const char *)c->buf + c->off;
    *out_len = (size_t)n;
    c->off += (size_t)n;
    return DTN_CBOR_OK;
}

static int enter(dtn_cbor *c, uint8_t want_major, size_t *count)
{
    uint8_t major;
    uint64_t n;
    int rc = read_head(c, &major, &n);
    if (rc != DTN_CBOR_OK) return rc;
    if (major != want_major) return DTN_CBOR_ERR_TYPE;
    /* each item/pair needs at least one byte */
    if (n > (uint64_t)(c->len - c->off)) {
        return DTN_CBOR_ERR_TRUNCATED;
    }
    c->depth++;
    if (c->depth > DTN_CBOR_MAX_DEPTH) {
        c->depth--;
        return DTN_CBOR_ERR_DEPTH;
    }
    *count = (size_t)n;
    return DTN_CBOR_OK;
}

int dtn_cbor_array(dtn_cbor *c, size_t *items)
{
    return enter(c, 4, items);
}

int dtn_cbor_map(dtn_cbor *c, size_t *pairs)
{
    return enter(c, 5, pairs);
}

void dtn_cbor_pop(dtn_cbor *c)
{
    if (c->depth > 0) c->depth--;
}

int dtn_cbor_null(dtn_cbor *c)
{
    uint8_t major;
    uint64_t v;
    int rc = read_head(c, &major, &v);
    if (rc != DTN_CBOR_OK) return rc;
    /* 0xf6 = major 7, ai 6, no argument */
    if (major != 7 || c->buf[c->off - 1] != 0xf6) return DTN_CBOR_ERR_TYPE;
    return DTN_CBOR_OK;
}

int dtn_cbor_skip(dtn_cbor *c)
{
    uint8_t b, major;
    size_t n;

    if (c->off >= c->len) return DTN_CBOR_ERR_TRUNCATED;
    if (c->depth >= DTN_CBOR_MAX_DEPTH) return DTN_CBOR_ERR_DEPTH;
    b = c->buf[c->off];
    major = (uint8_t)(b >> 5);
    switch (major) {
    case 0: {
        uint64_t u;
        return dtn_cbor_uint(c, &u);
    }
    case 1: {
        int64_t i;
        return dtn_cbor_int(c, &i);
    }
    case 2: {
        const uint8_t *p;
        size_t l;
        return dtn_cbor_bstr(c, &p, &l);
    }
    case 3: {
        const char *p;
        size_t l;
        return dtn_cbor_tstr(c, &p, &l);
    }
    case 4: {
        int rc = enter(c, 4, &n);
        if (rc != DTN_CBOR_OK) return rc;
        for (size_t i = 0; i < n; i++) {
            rc = dtn_cbor_skip(c);
            if (rc != DTN_CBOR_OK) return rc;
        }
        dtn_cbor_pop(c);
        return DTN_CBOR_OK;
    }
    case 5: {
        int rc = enter(c, 5, &n);
        if (rc != DTN_CBOR_OK) return rc;
        for (size_t i = 0; i < 2 * n; i++) {
            rc = dtn_cbor_skip(c);
            if (rc != DTN_CBOR_OK) return rc;
        }
        dtn_cbor_pop(c);
        return DTN_CBOR_OK;
    }
    default: /* 6: tags rejected; 7: null only in v1 */
        if (b == 0xf6) return dtn_cbor_null(c);
        if (major == 6) return DTN_CBOR_ERR_RESERVED;
        return DTN_CBOR_ERR_TYPE;
    }
}

int dtn_cbor_done(const dtn_cbor *c)
{
    return c->off == c->len;
}
