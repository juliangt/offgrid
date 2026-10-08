/* dtn_bundle.c — the Offgrid BPv7 profile codec; see dtn_bundle.h for the
 * contract. The byte-level decisions, the validation ORDER and the stable
 * failure codes mirror node/internal/bundle/bundle.go so the shared vectors
 * of tests/vectors/bundle/vectors.json fail identically on both sides:
 *
 *   reader-shape walk → version/flags/CRC-type/block rules → both CRCs →
 *   EID shapes → content/hop/lifetime → skew (receiver only) → canonical
 *   re-encode comparison.
 *
 * Parse validates by re-encoding what it read: the primary block must be
 * byte-identical to its canonical form and the payload block must carry the
 * canonical head — so non-shortest heads and any other preferred-
 * serialization deviation fail closed (P-1). The profile has no CBOR maps,
 * so duplicate map keys cannot occur on the wire. */
#include "dtn_bundle.h"

#include "dtn_cbor.h"
#include "dtn_cbor_writer.h"
#include "dtn_sha256.h"

#include <stdio.h>
#include <string.h>

const char *dtn_bundle_strerr(int code)
{
    switch (code) {
    case DTN_BUNDLE_OK: return "ok";
    case DTN_BUNDLE_ERR_TRUNCATED: return "truncated";
    case DTN_BUNDLE_ERR_STRUCTURE: return "bad_structure";
    case DTN_BUNDLE_ERR_VERSION: return "bad_version";
    case DTN_BUNDLE_ERR_FLAGS: return "bad_flags";
    case DTN_BUNDLE_ERR_CRC: return "bad_crc";
    case DTN_BUNDLE_ERR_BLOCK_COUNT: return "block_count";
    case DTN_BUNDLE_ERR_BLOCK_TYPE: return "unknown_block";
    case DTN_BUNDLE_ERR_NON_CANONICAL: return "non_canonical";
    case DTN_BUNDLE_ERR_EID: return "bad_eid";
    case DTN_BUNDLE_ERR_HOP: return "hop_limit";
    case DTN_BUNDLE_ERR_SKEW: return "future_skew";
    case DTN_BUNDLE_ERR_LIFETIME: return "bad_lifetime";
    case DTN_BUNDLE_ERR_EMPTY_PAYLOAD: return "empty_payload";
    case DTN_BUNDLE_ERR_NOSPACE: return "no_space";
    case DTN_BUNDLE_ERR_ARGUMENT: return "bad_argument";
    default: return "?";
    }
}

/* CRC-16/X.25 — identical to spike.go's crc16x25 (type code 1). */
uint16_t dtn_bundle_crc16(const uint8_t *b, size_t n)
{
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < n; i++) {
        crc ^= (uint16_t)b[i];
        for (int bit = 0; bit < 8; bit++) {
            if (crc & 1) {
                crc = (uint16_t)(crc >> 1) ^ 0x8408;
            } else {
                crc >>= 1;
            }
        }
    }
    return (uint16_t)~crc;
}

/* ------------------------------------------------------------------ */
/* EID shapes (§2.1, P-4/P-5).                                        */
/* ------------------------------------------------------------------ */

static int is_lower_hex(const char *s, size_t n)
{
    if (n == 0) return 0;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        int ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        if (!ok) return 0;
    }
    return 1;
}

/* is_node_authority: "og." + 16 lowercase hex (the self-certifying EID). */
static int is_node_authority(const char *a)
{
    size_t n = strlen(a);
    if (n != 3 + 16 || a[0] != 'o' || a[1] != 'g' || a[2] != '.') return 0;
    return is_lower_hex(a + 3, 16);
}

/* valid_eid_token: 1..63 chars of [a-z0-9-], starting alphanumeric. */
static int valid_eid_token(const char *s)
{
    size_t n = strlen(s);
    if (n == 0 || n > 63) return 0;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        int ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
        if (!ok) return 0;
    }
    return (s[0] >= 'a' && s[0] <= 'z') || (s[0] >= '0' && s[0] <= '9');
}

static int valid_profile_eid(const dtn_bundle_eid *e)
{
    int has_auth = e->authority[0] != 0;
    int has_ssp = e->ssp[0] != 0;
    if (e->none) return 1;
    if (has_auth == has_ssp) return 0; /* both or neither set */
    if (has_auth) return is_node_authority(e->authority) || valid_eid_token(e->authority);
    return valid_eid_token(e->ssp);
}

/* valid_source: P-4/P-5 — anonymous or an identified node. */
static int valid_source_eid(const dtn_bundle_eid *e)
{
    return e->none || (!e->ssp[0] && is_node_authority(e->authority));
}

/* valid_destination: group, node or the well-known admin EID; never none. */
static int valid_destination_eid(const dtn_bundle_eid *e)
{
    return !e->none && valid_profile_eid(e);
}

/* The profile pins report-to = dtn:none on both bundle classes. */
static int valid_report_to_eid(const dtn_bundle_eid *e)
{
    return e->none;
}

static void eid_clear(dtn_bundle_eid *e)
{
    memset(e, 0, sizeof(*e));
}

int dtn_bundle_eid_parse(const char *s, dtn_bundle_eid *out)
{
    eid_clear(out);
    if (s == NULL) return DTN_BUNDLE_ERR_ARGUMENT;
    if (strcmp(s, "dtn:none") == 0) {
        out->none = 1;
        return DTN_BUNDLE_OK;
    }
    if (strncmp(s, "dtn://", 6) == 0) {
        const char *rest = s + 6;
        size_t n = strlen(rest);
        if (n == 0 || rest[n - 1] != '/') return DTN_BUNDLE_ERR_EID;
        n--; /* the trailing slash */
        if (n >= DTN_BUNDLE_EID_MAX) return DTN_BUNDLE_ERR_EID;
        memcpy(out->authority, rest, n);
        out->authority[n] = 0;
        if (!valid_eid_token(out->authority) && !is_node_authority(out->authority)) {
            return DTN_BUNDLE_ERR_EID;
        }
        return DTN_BUNDLE_OK;
    }
    if (strncmp(s, "dtn:", 4) == 0) {
        const char *ssp = s + 4;
        if (strlen(ssp) >= DTN_BUNDLE_EID_MAX || !valid_eid_token(ssp)) {
            return DTN_BUNDLE_ERR_EID;
        }
        strcpy(out->ssp, ssp);
        return DTN_BUNDLE_OK;
    }
    return DTN_BUNDLE_ERR_EID;
}

int dtn_bundle_eid_format(const dtn_bundle_eid *e, char *out, size_t cap)
{
    if (e->none) {
        if (cap < 9) return DTN_BUNDLE_ERR_NOSPACE;
        strcpy(out, "dtn:none");
        return DTN_BUNDLE_OK;
    }
    const char *part = e->authority[0] ? e->authority : e->ssp;
    int n;
    if (e->authority[0]) {
        n = snprintf(out, cap, "dtn://%s/", part);
    } else {
        n = snprintf(out, cap, "dtn:%s", part);
    }
    if (n < 0 || (size_t)n >= cap) return DTN_BUNDLE_ERR_NOSPACE;
    return DTN_BUNDLE_OK;
}

/* ------------------------------------------------------------------ */
/* CBOR value shapes.                                                 */
/* ------------------------------------------------------------------ */

/* map_reader_code mirrors Go's readerCode: the reader failure vocabulary
 * folds into the codec's stable codes (dtn_cbor.c's fit guard reports
 * TRUNCATED, matching Go's "cannot fit the buffer" mapping). */
static int map_reader_code(int rc)
{
    switch (rc) {
    case DTN_CBOR_OK:
        return DTN_BUNDLE_OK;
    case DTN_CBOR_ERR_TRUNCATED:
        return DTN_BUNDLE_ERR_TRUNCATED;
    case DTN_CBOR_ERR_INDEFINITE:
    case DTN_CBOR_ERR_RESERVED:
    case DTN_CBOR_ERR_DEPTH:
        return DTN_BUNDLE_ERR_NON_CANONICAL; /* definite lengths only (P-1) */
    default: /* TYPE, UTF8, RANGE */
        return DTN_BUNDLE_ERR_STRUCTURE;
    }
}

static void cbor_eid(dtn_cbor_writer *w, const dtn_bundle_eid *e)
{
    if (e->none) {
        dtn_cbor_w_null(w);
        return;
    }
    dtn_cbor_w_array(w, 2);
    if (e->authority[0]) {
        dtn_cbor_w_tstr(w, e->authority);
    } else {
        dtn_cbor_w_tstr(w, "");
    }
    if (e->ssp[0]) {
        dtn_cbor_w_tstr(w, e->ssp);
    } else {
        dtn_cbor_w_tstr(w, "");
    }
}

/* read_eid: null or the two-tstr form. Wrong CBOR types fold to
 * bad_structure; shape violations are the caller's bad_eid (mirroring Go's
 * split). The null probe peeks at the byte so the array fallback re-reads
 * the same position (the reader's cursor is unspecified past an error). */
static int read_eid(dtn_cbor *r, dtn_bundle_eid *out)
{
    eid_clear(out);
    if (r->off >= r->len) return DTN_BUNDLE_ERR_TRUNCATED;
    if (r->buf[r->off] == 0xf6) { /* the profile's only type-7 value */
        r->off++;
        out->none = 1;
        return DTN_BUNDLE_OK;
    }
    size_t n;
    int rc = dtn_cbor_array(r, &n);
    if (rc != DTN_CBOR_OK) return map_reader_code(rc);
    if (n != 2) return DTN_BUNDLE_ERR_STRUCTURE;
    const char *s;
    size_t l;
    rc = dtn_cbor_tstr(r, &s, &l);
    if (rc != DTN_CBOR_OK) return map_reader_code(rc);
    if (l >= DTN_BUNDLE_EID_MAX) return DTN_BUNDLE_ERR_EID; /* never a valid token */
    memcpy(out->authority, s, l);
    out->authority[l] = 0;
    rc = dtn_cbor_tstr(r, &s, &l);
    if (rc != DTN_CBOR_OK) return map_reader_code(rc);
    if (l >= DTN_BUNDLE_EID_MAX) return DTN_BUNDLE_ERR_EID;
    memcpy(out->ssp, s, l);
    out->ssp[l] = 0;
    return DTN_BUNDLE_OK;
}

/* ------------------------------------------------------------------ */
/* decode: the structural walk both parse and rewrite_hop run.        */
/* ------------------------------------------------------------------ */

typedef struct {
    dtn_bundle b;        /* parsed fields; payload view left NULL here */
    size_t content_len;  /* hop octet ‖ PDU */
    size_t pay_crc_head; /* offset of the payload CRC bstr head (0x42) */
} dtn_dec;

/* cbor_primary re-encodes the primary block WITHOUT the CRC value — the
 * canonicality comparison covers pdu[0 : primary_len-3]. */
static void cbor_primary(dtn_cbor_writer *w, const dtn_bundle *b)
{
    dtn_cbor_w_array(w, 9);
    dtn_cbor_w_uint(w, 7);
    dtn_cbor_w_uint(w, 0);
    dtn_cbor_w_uint(w, 1);
    cbor_eid(w, &b->destination);
    cbor_eid(w, &b->source);
    cbor_eid(w, &b->report_to);
    dtn_cbor_w_array(w, 2);
    dtn_cbor_w_uint(w, b->creation_dtn_ms);
    dtn_cbor_w_uint(w, b->sequence);
    dtn_cbor_w_uint(w, b->lifetime);
}

/* payload_block_head writes the canonical head before the content:
 * 0x86 0x01 0x00 0x00 0x01 + the shortest bstr head of the content length. */
static size_t payload_block_head(uint8_t out[10], size_t content_len)
{
    out[0] = 0x86;
    out[1] = 0x01;
    out[2] = 0x00;
    out[3] = 0x00;
    out[4] = 0x01;
    if (content_len < 24) {
        out[5] = (uint8_t)(0x40 | content_len);
        return 6;
    }
    if (content_len <= 0xff) {
        out[5] = 0x58;
        out[6] = (uint8_t)content_len;
        return 7;
    }
    if (content_len <= 0xffff) {
        out[5] = 0x59;
        out[6] = (uint8_t)(content_len >> 8);
        out[7] = (uint8_t)content_len;
        return 8;
    }
    out[5] = 0x5a;
    out[6] = (uint8_t)(content_len >> 24);
    out[7] = (uint8_t)(content_len >> 16);
    out[8] = (uint8_t)(content_len >> 8);
    out[9] = (uint8_t)content_len;
    return 10;
}

static int decode(const uint8_t *pdu, size_t len, dtn_dec *d)
{
    dtn_cbor r;
    dtn_cbor_init(&r, pdu, len);
    memset(d, 0, sizeof(*d));

    /* ---- primary block: array(9) = 8 fields + the CRC value. */
    size_t n;
    int rc = dtn_cbor_array(&r, &n);
    if (rc != DTN_CBOR_OK) return map_reader_code(rc);
    if (n != 9) return DTN_BUNDLE_ERR_STRUCTURE;
    uint64_t v;
    rc = dtn_cbor_uint(&r, &v);
    if (rc != DTN_CBOR_OK) return map_reader_code(rc);
    if (v != 7) return DTN_BUNDLE_ERR_VERSION;
    rc = dtn_cbor_uint(&r, &v);
    if (rc != DTN_CBOR_OK) return map_reader_code(rc);
    if (v != 0) return DTN_BUNDLE_ERR_FLAGS;
    rc = dtn_cbor_uint(&r, &v);
    if (rc != DTN_CBOR_OK) return map_reader_code(rc);
    if (v != 1) return DTN_BUNDLE_ERR_STRUCTURE; /* CRC type: 1 (CRC-16/X.25) */
    int rc2;
    rc2 = read_eid(&r, &d->b.destination);
    if (rc2) return rc2;
    rc2 = read_eid(&r, &d->b.source);
    if (rc2) return rc2;
    rc2 = read_eid(&r, &d->b.report_to);
    if (rc2) return rc2;
    /* creation [dtnMs, sequence] */
    rc = dtn_cbor_array(&r, &n);
    if (rc != DTN_CBOR_OK) return map_reader_code(rc);
    if (n != 2) return DTN_BUNDLE_ERR_STRUCTURE;
    rc = dtn_cbor_uint(&r, &d->b.creation_dtn_ms);
    if (rc != DTN_CBOR_OK) return map_reader_code(rc);
    rc = dtn_cbor_uint(&r, &d->b.sequence);
    if (rc != DTN_CBOR_OK) return map_reader_code(rc);
    rc = dtn_cbor_uint(&r, &d->b.lifetime);
    if (rc != DTN_CBOR_OK) return map_reader_code(rc);
    /* the primary CRC covers the block bytes before its 0x42 bstr head */
    size_t prim_crc_head = r.off;
    const uint8_t *stored;
    size_t stored_len;
    rc = dtn_cbor_bstr(&r, &stored, &stored_len);
    if (rc != DTN_CBOR_OK) return map_reader_code(rc);
    if (stored_len != 2) return DTN_BUNDLE_ERR_STRUCTURE;
    if (dtn_bundle_crc16(pdu, prim_crc_head) !=
        (uint16_t)((uint16_t)stored[0] << 8 | stored[1])) {
        return DTN_BUNDLE_ERR_CRC;
    }
    d->b.primary_len = r.off;
    if (dtn_cbor_done(&r)) return DTN_BUNDLE_ERR_BLOCK_COUNT;

    /* ---- payload block: array(6) = [1, 0, 0, 1, bstr(content), CRC]. */
    rc = dtn_cbor_array(&r, &n);
    if (rc != DTN_CBOR_OK) return map_reader_code(rc);
    if (n != 6) return DTN_BUNDLE_ERR_STRUCTURE;
    rc = dtn_cbor_uint(&r, &v);
    if (rc != DTN_CBOR_OK) return map_reader_code(rc);
    if (v != 1) return DTN_BUNDLE_ERR_BLOCK_TYPE; /* P-2: payload only */
    rc = dtn_cbor_uint(&r, &v);
    if (rc != DTN_CBOR_OK) return map_reader_code(rc);
    if (v != 0) return DTN_BUNDLE_ERR_STRUCTURE; /* payload block number 0 */
    rc = dtn_cbor_uint(&r, &v);
    if (rc != DTN_CBOR_OK) return map_reader_code(rc);
    if (v != 0) return DTN_BUNDLE_ERR_FLAGS;
    rc = dtn_cbor_uint(&r, &v);
    if (rc != DTN_CBOR_OK) return map_reader_code(rc);
    if (v != 1) return DTN_BUNDLE_ERR_STRUCTURE;
    rc = dtn_cbor_bstr(&r, &stored, &d->content_len);
    if (rc != DTN_CBOR_OK) return map_reader_code(rc);
    d->b.content_off = r.off - d->content_len; /* hop octet position */
    d->pay_crc_head = r.off;
    rc = dtn_cbor_bstr(&r, &stored, &stored_len);
    if (rc != DTN_CBOR_OK) return map_reader_code(rc);
    if (stored_len != 2) return DTN_BUNDLE_ERR_STRUCTURE;
    if (dtn_bundle_crc16(pdu + d->b.primary_len, d->pay_crc_head - d->b.primary_len) !=
        (uint16_t)((uint16_t)stored[0] << 8 | stored[1])) {
        return DTN_BUNDLE_ERR_CRC;
    }
    if (!dtn_cbor_done(&r)) return DTN_BUNDLE_ERR_BLOCK_COUNT;

    /* ---- canonicality (P-1): the primary block must BE its canonical
     * encoding, and the payload block must carry the canonical head.
     * (Same position in the pipeline as Go: before the profile-level
     * field checks.) */
    uint8_t prim[512];
    dtn_cbor_writer w;
    dtn_cbor_writer_init(&w, prim, sizeof(prim));
    cbor_primary(&w, &d->b);
    if (!dtn_cbor_w_ok(&w)) return DTN_BUNDLE_ERR_STRUCTURE; /* EIDs overflowed the fixed buffers */
    if (w.len != d->b.primary_len - 3 ||
        memcmp(prim, pdu, w.len) != 0) {
        return DTN_BUNDLE_ERR_NON_CANONICAL;
    }
    uint8_t head[10];
    size_t head_len = payload_block_head(head, d->content_len);
    if (memcmp(head, pdu + d->b.primary_len, head_len) != 0) {
        return DTN_BUNDLE_ERR_NON_CANONICAL;
    }

    /* ---- EID shapes (P-4/P-5), then content/hop/lifetime (P-4..P-6). */
    if (!valid_destination_eid(&d->b.destination)) return DTN_BUNDLE_ERR_EID;
    if (!valid_source_eid(&d->b.source)) return DTN_BUNDLE_ERR_EID;
    if (!valid_report_to_eid(&d->b.report_to)) return DTN_BUNDLE_ERR_EID;
    if (d->content_len < 2) return DTN_BUNDLE_ERR_EMPTY_PAYLOAD;
    d->b.hop = pdu[d->b.content_off];
    if (d->b.hop > DTN_BUNDLE_HOP_LIMIT) return DTN_BUNDLE_ERR_HOP;
    if (d->b.lifetime == 0) return DTN_BUNDLE_ERR_LIFETIME;
    return DTN_BUNDLE_OK;
}

/* validate_profile_finish applies the receiver-side checks decode leaves to
 * its callers: the skew rule is admission's (P-6), evaluated once. */
static int validate_profile_finish(const dtn_dec *d, int check_skew,
                                   uint64_t now_dtn_ms)
{
    if (check_skew && d->b.creation_dtn_ms > now_dtn_ms + 300000ULL) {
        return DTN_BUNDLE_ERR_SKEW;
    }
    return DTN_BUNDLE_OK;
}

static uint64_t dtn_ms_of(int64_t unix_ms)
{
    if (unix_ms < DTN_BUNDLE_DTN_EPOCH_S * 1000) return 0; /* caller checked */
    return (uint64_t)(unix_ms - DTN_BUNDLE_DTN_EPOCH_S * 1000);
}

static uint64_t dtn_ms_of_clock(int64_t now_unix_s)
{
    if (now_unix_s < DTN_BUNDLE_DTN_EPOCH_S) return 0; /* pre-2000 clock: reject all, honestly */
    return (uint64_t)(now_unix_s - DTN_BUNDLE_DTN_EPOCH_S) * 1000ULL;
}

int dtn_bundle_parse(const uint8_t *pdu, size_t len, int64_t now_unix_s,
                     dtn_bundle *out)
{
    if (pdu == NULL || out == NULL) return DTN_BUNDLE_ERR_ARGUMENT;
    memset(out, 0, sizeof(*out));
    dtn_dec d;
    int rc = decode(pdu, len, &d);
    if (rc != DTN_BUNDLE_OK) return rc;
    rc = validate_profile_finish(&d, 1, dtn_ms_of_clock(now_unix_s));
    if (rc != DTN_BUNDLE_OK) return rc;
    *out = d.b;
    out->payload = pdu + d.b.content_off + 1;
    out->payload_len = d.content_len - 1;
    return DTN_BUNDLE_OK;
}

/* ------------------------------------------------------------------ */
/* encode + constructors.                                             */
/* ------------------------------------------------------------------ */

/* validate checks a constructed bundle against every rule Encode enforces
 * (the same order as Go's Encode: EIDs, lifetime, hop, payload). */
static int validate(const dtn_bundle *b)
{
    if (!valid_destination_eid(&b->destination)) return DTN_BUNDLE_ERR_EID;
    if (!valid_source_eid(&b->source)) return DTN_BUNDLE_ERR_EID;
    if (!valid_report_to_eid(&b->report_to)) return DTN_BUNDLE_ERR_EID;
    if (b->lifetime == 0) return DTN_BUNDLE_ERR_LIFETIME;
    if (b->hop > DTN_BUNDLE_HOP_LIMIT) return DTN_BUNDLE_ERR_HOP;
    if (b->payload == NULL || b->payload_len == 0) return DTN_BUNDLE_ERR_EMPTY_PAYLOAD;
    return DTN_BUNDLE_OK;
}

int dtn_bundle_encode(const dtn_bundle *b, uint8_t *out, size_t cap,
                      size_t *out_len)
{
    if (b == NULL || out == NULL || out_len == NULL) return DTN_BUNDLE_ERR_ARGUMENT;
    *out_len = 0;
    int rc = validate(b);
    if (rc != DTN_BUNDLE_OK) return rc;

    /* primary block + CRC-16 value (a 2-byte bstr, big-endian). */
    uint8_t prim[512];
    dtn_cbor_writer w;
    dtn_cbor_writer_init(&w, prim, sizeof(prim));
    cbor_primary(&w, b);
    if (!dtn_cbor_w_ok(&w)) return DTN_BUNDLE_ERR_NOSPACE;
    uint16_t crc = dtn_bundle_crc16(prim, w.len);
    uint8_t crcb[2] = { (uint8_t)(crc >> 8), (uint8_t)crc };
    dtn_cbor_w_bstr(&w, crcb, 2);
    if (!dtn_cbor_w_ok(&w)) return DTN_BUNDLE_ERR_NOSPACE;

    /* payload block: [1, 0, 0, 1, bstr(hop ‖ payload)] + CRC. The content
     * is streamed (no copy): declare the bstr length, then raw-append. */
    size_t content_len = 1 + b->payload_len;
    uint8_t head[10];
    size_t head_len = payload_block_head(head, content_len);
    dtn_cbor_writer p;
    dtn_cbor_writer_init(&p, out, cap);
    dtn_cbor_w_raw(&p, prim, w.len);
    dtn_cbor_w_raw(&p, head, head_len);
    uint8_t hop = b->hop;
    dtn_cbor_w_raw(&p, &hop, 1);
    dtn_cbor_w_raw(&p, b->payload, b->payload_len);
    if (!dtn_cbor_w_ok(&p)) return DTN_BUNDLE_ERR_NOSPACE;
    /* the payload block's CRC covers only its own bytes (from the primary
     * block's end through the content) — not the primary block. */
    crc = dtn_bundle_crc16(out + w.len, p.len - w.len);
    uint8_t tail[3] = { 0x42, (uint8_t)(crc >> 8), (uint8_t)crc };
    dtn_cbor_w_raw(&p, tail, 3);
    if (!dtn_cbor_w_ok(&p)) return DTN_BUNDLE_ERR_NOSPACE;
    *out_len = p.len;
    return DTN_BUNDLE_OK;
}

int dtn_bundle_mail(const uint8_t *envelope, size_t envelope_len,
                    int64_t created_unix_ms, uint64_t ttl_s, dtn_bundle *out)
{
    if (out == NULL) return DTN_BUNDLE_ERR_ARGUMENT;
    memset(out, 0, sizeof(*out));
    if (envelope == NULL || envelope_len == 0) return DTN_BUNDLE_ERR_EMPTY_PAYLOAD;
    if (created_unix_ms < DTN_BUNDLE_DTN_EPOCH_S * 1000) return DTN_BUNDLE_ERR_ARGUMENT;
    out->destination.none = 0;
    strcpy(out->destination.ssp, "og-mail");
    out->source.none = 1;
    out->report_to.none = 1;
    out->creation_dtn_ms = dtn_ms_of(created_unix_ms);
    out->sequence = 0;
    out->lifetime = ttl_s;
    out->hop = 0;
    out->payload = envelope;
    out->payload_len = envelope_len;
    return DTN_BUNDLE_OK;
}

int dtn_bundle_mgmt(const char *src_eid, const char *dst_eid,
                    int64_t created_unix_ms, uint64_t lifetime_s, uint64_t seq,
                    const uint8_t *inner, size_t inner_len, dtn_bundle *out)
{
    if (out == NULL) return DTN_BUNDLE_ERR_ARGUMENT;
    memset(out, 0, sizeof(*out));
    if (src_eid == NULL || dst_eid == NULL) return DTN_BUNDLE_ERR_ARGUMENT;
    int rc = dtn_bundle_eid_parse(src_eid, &out->source);
    if (rc != DTN_BUNDLE_OK) return rc;
    rc = dtn_bundle_eid_parse(dst_eid, &out->destination);
    if (rc != DTN_BUNDLE_OK) return rc;
    if (!valid_source_eid(&out->source)) return DTN_BUNDLE_ERR_EID;
    if (!valid_destination_eid(&out->destination)) return DTN_BUNDLE_ERR_EID;
    if (inner == NULL || inner_len == 0) return DTN_BUNDLE_ERR_EMPTY_PAYLOAD;
    if (created_unix_ms < DTN_BUNDLE_DTN_EPOCH_S * 1000) return DTN_BUNDLE_ERR_ARGUMENT;
    out->report_to.none = 1;
    out->creation_dtn_ms = dtn_ms_of(created_unix_ms);
    out->lifetime = lifetime_s;
    out->sequence = seq;
    out->hop = 0;
    out->payload = inner;
    out->payload_len = inner_len;
    return DTN_BUNDLE_OK;
}

/* ------------------------------------------------------------------ */
/* relay + identity.                                                  */
/* ------------------------------------------------------------------ */

int dtn_bundle_rewrite_hop(const uint8_t *pdu, size_t len, uint8_t *out,
                           size_t cap, size_t *out_len)
{
    if (pdu == NULL || out == NULL || out_len == NULL) return DTN_BUNDLE_ERR_ARGUMENT;
    *out_len = 0;
    dtn_dec d;
    int rc = decode(pdu, len, &d);
    if (rc != DTN_BUNDLE_OK) return rc;
    if (d.b.hop >= DTN_BUNDLE_HOP_LIMIT) return DTN_BUNDLE_ERR_HOP; /* drop, not wrap */
    if (cap < len) return DTN_BUNDLE_ERR_NOSPACE;
    memcpy(out, pdu, len);
    out[d.b.content_off]++;
    /* only the payload block's CRC changes: it covers
     * [primary_len, pay_crc_head) — the 2 value bytes follow the head. */
    uint16_t crc = dtn_bundle_crc16(out + d.b.primary_len,
                                    d.pay_crc_head - d.b.primary_len);
    out[d.pay_crc_head + 1] = (uint8_t)(crc >> 8);
    out[d.pay_crc_head + 2] = (uint8_t)crc;
    *out_len = len;
    return DTN_BUNDLE_OK;
}

int dtn_bundle_id(const uint8_t *pdu, size_t len, uint8_t out[DTN_BUNDLE_ID_LEN])
{
    if (pdu == NULL || out == NULL) return DTN_BUNDLE_ERR_ARGUMENT;
    dtn_dec d;
    int rc = decode(pdu, len, &d);
    if (rc != DTN_BUNDLE_OK) return rc;
    if (d.content_len < 2) return DTN_BUNDLE_ERR_EMPTY_PAYLOAD;
    dtn_sha256(pdu + d.b.content_off + 1, d.content_len - 1, out);
    return DTN_BUNDLE_OK;
}
