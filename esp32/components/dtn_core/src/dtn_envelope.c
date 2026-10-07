/* dtn_envelope.c — §3 envelope + §10.5/§15.3 server-side validation.
 * Decision order mirrors node/internal/envelope/envelope.go Validate(). */
#include "dtn_envelope.h"
#include "dtn_base64.h"

#include <string.h>

bool dtn_is_hex_n(const char *s, size_t n)
{
    if (s[0] == '\0') return false;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        if (!ok) return false;
    }
    return s[n] == '\0';
}

bool dtn_valid_alias(const char *s)
{
    size_t n = strlen(s);
    if (n < 1 || n > DTN_ALIAS_MAX) return false;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                  (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-';
        if (!ok) return false;
    }
    return true;
}

bool dtn_valid_base64_of_len(const char *s, size_t want)
{
    size_t n;
    if (s == NULL) return false;
    n = strlen(s);
    /* the Go reference rejects \r/\n explicitly (base64 ignores them even in
     * Strict mode); dtn_base64_decode rejects them anyway as invalid chars */
    if (n == 0) return false;
    if ((long)want != dtn_base64_decoded_len(s, n)) return false;
    uint8_t tmp[1];
    (void)tmp;
    /* full decode check without a want-sized buffer: scan already validated
     * charset/padding/canonical form; length check done above */
    return true;
}

static bool supported_version(int64_t v)
{
    return v >= DTN_ENVELOPE_VERSION_MIN && v <= DTN_ENVELOPE_VERSION_MAX;
}

/* §15.3 per-version meta rules: meta absent on v1; on v2 a present meta
 * carried an object marker (the parser only flags well-formed members — a
 * non-object meta is rejected AT PARSE TIME by the sync processor, which
 * mirrors Go accepting any valid JSON into RawMessage and then failing the
 * '{' check) with orig_v, if present, equal to the integer 1. */
static dtn_env_err validate_meta(const dtn_envelope *e)
{
    if (!e->meta_flags) return DTN_ENV_OK;
    if (e->v == 1) return DTN_ENV_ERR_META;
    if (e->meta_orig_v_present && e->meta_orig_v != 1) {
        return DTN_ENV_ERR_META;
    }
    return DTN_ENV_OK;
}

dtn_env_err dtn_envelope_validate(const dtn_envelope *e, int64_t now)
{
    long decoded;

    if (!supported_version(e->v)) return DTN_ENV_ERR_VERSION;
    if (validate_meta(e) != DTN_ENV_OK) return DTN_ENV_ERR_META;
    if (!dtn_is_hex_n(e->id, DTN_ID_LEN)) return DTN_ENV_ERR_ID;
    if (!dtn_is_hex_n(e->dest_hint, DTN_DEST_HINT_LEN)) {
        return DTN_ENV_ERR_DEST_HINT;
    }
    if (e->created_at <= 0) return DTN_ENV_ERR_CREATED_AT;
    if (e->created_at > now + DTN_CLOCK_SKEW_SECONDS) {
        return DTN_ENV_ERR_CREATED_AT;
    }
    if (e->ttl < DTN_TTL_MIN || e->ttl > DTN_TTL_MAX) return DTN_ENV_ERR_TTL;
    if (e->payload_len == 0) return DTN_ENV_ERR_PAYLOAD;
    /* \r/\n check before decoding (Go parity; they are invalid b64 here) */
    for (size_t i = 0; i < e->payload_len; i++) {
        if (e->payload[i] == '\r' || e->payload[i] == '\n') {
            return DTN_ENV_ERR_PAYLOAD;
        }
    }
    decoded = dtn_base64_decoded_len(e->payload, e->payload_len);
    if (decoded < DTN_PAYLOAD_DECODED_MIN ||
        decoded > DTN_PAYLOAD_DECODED_MAX) {
        return DTN_ENV_ERR_PAYLOAD;
    }
    return DTN_ENV_OK;
}

/* Minimal JSON string escaper (Go encoding/json semantics for the
 * characters that can legally appear; the envelope field alphabets make
 * escaping unreachable in practice, but the writer is total). */
static size_t write_json_string(char *out, size_t cap, size_t pos,
                                const char *s, size_t n)
{
    if (pos + 1 >= cap) return (size_t)-1;
    out[pos++] = '"';
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        char esc = 0;
        switch (c) {
        case '"': esc = '"'; break;
        case '\\': esc = '\\'; break;
        case '\b': esc = 'b'; break;
        case '\f': esc = 'f'; break;
        case '\n': esc = 'n'; break;
        case '\r': esc = 'r'; break;
        case '\t': esc = 't'; break;
        default:
            if (c < 0x20) {
                if (pos + 6 >= cap) return (size_t)-1;
                static const char HEX[] = "0123456789abcdef";
                out[pos++] = '\\';
                out[pos++] = 'u';
                out[pos++] = '0';
                out[pos++] = '0';
                out[pos++] = HEX[c >> 4];
                out[pos++] = HEX[c & 0x0F];
                continue;
            }
            if (pos + 1 >= cap) return (size_t)-1;
            out[pos++] = (char)c;
            continue;
        }
        if (pos + 2 >= cap) return (size_t)-1;
        out[pos++] = '\\';
        out[pos++] = esc;
    }
    if (pos + 2 >= cap) return (size_t)-1;
    out[pos++] = '"';
    return pos;
}

static size_t write_int(char *out, size_t cap, size_t pos, int64_t v)
{
    char tmp[24];
    size_t n = 0;
    uint64_t u;
    if (pos + 1 >= cap) return (size_t)-1;
    if (v < 0) {
        out[pos++] = '-';
        u = (uint64_t)(-(v + 1)) + 1;
    } else {
        u = (uint64_t)v;
    }
    do {
        tmp[n++] = (char)('0' + (int)(u % 10));
        u /= 10;
    } while (u);
    if (pos + n + 1 >= cap) return (size_t)-1;
    while (n) out[pos++] = tmp[--n];
    return pos;
}

long dtn_envelope_write_json(char *out, size_t cap, const dtn_envelope *e)
{
    size_t pos = 0;
#define WR_LIT(s)                         \
    do {                                  \
        size_t n_ = strlen(s);            \
        if (pos + n_ >= cap) return -1;   \
        memcpy(out + pos, s, n_);         \
        pos += n_;                        \
    } while (0)
#define WR_VAL(s, n)                                 \
    do {                                             \
        pos = write_json_string(out, cap, pos, s, n);\
        if (pos == (size_t)-1) return -1;            \
    } while (0)
#define WR_INT(v)                            \
    do {                                     \
        pos = write_int(out, cap, pos, (v)); \
        if (pos == (size_t)-1) return -1;    \
    } while (0)

    WR_LIT("{\"v\":");
    WR_INT(e->v);
    WR_LIT(",\"id\":");
    WR_VAL(e->id, DTN_ID_LEN);
    WR_LIT(",\"dest_hint\":");
    WR_VAL(e->dest_hint, DTN_DEST_HINT_LEN);
    WR_LIT(",\"created_at\":");
    WR_INT(e->created_at);
    WR_LIT(",\"ttl\":");
    WR_INT(e->ttl);
    WR_LIT(",\"payload\":");
    WR_VAL(e->payload, e->payload_len);
    WR_LIT("}");
    if (pos >= cap) return -1;
    out[pos] = '\0';
    return (long)pos;
#undef WR_LIT
#undef WR_VAL
#undef WR_INT
}
