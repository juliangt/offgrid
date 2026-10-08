/* dtn_base64.c — strict RFC 4648 standard Base64 (padded). See dtn_base64.h. */
#include "dtn_base64.h"

#include <string.h>

static int b64_val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

/* Common validation walk: returns decoded length, or -1 invalid. */
static long b64_scan(const char *src, size_t src_len)
{
    size_t i = 0;
    long out = 0;
    int pad_groups = 0;

    if (src_len == 0 || src_len % 4 != 0) {
        return -1;
    }
    for (; i < src_len; i += 4) {
        int v0 = b64_val(src[i]);
        int v1 = b64_val(src[i + 1]);
        int v2 = -1, v3 = -1;
        if (v0 < 0 || v1 < 0) return -1;
        if (src[i + 2] == '=' && src[i + 3] == '=') {
            /* one data byte in this group */
            if ((v1 & 0x0F) != 0) return -1; /* non-canonical trailing bits */
            out += 1;
            pad_groups++;
            continue;
        }
        v2 = b64_val(src[i + 2]);
        if (v2 < 0) return -1;
        if (src[i + 3] == '=') {
            if ((v2 & 0x03) != 0) return -1; /* non-canonical trailing bits */
            out += 2;
            pad_groups++;
            continue;
        }
        v3 = b64_val(src[i + 3]);
        if (v3 < 0) return -1;
        out += 3;
    }
    if (pad_groups > 1) return -1; /* padding only in the final group */
    return out;
}

long dtn_base64_decoded_len(const char *src, size_t src_len)
{
    return b64_scan(src, src_len);
}

long dtn_base64_decode(const char *src, size_t src_len,
                       uint8_t *out, size_t cap)
{
    long total = b64_scan(src, src_len);
    size_t o = 0;
    size_t i;

    if (total < 0 || (size_t)total > cap) {
        return -1;
    }
    for (i = 0; i < src_len; i += 4) {
        int v0 = b64_val(src[i]);
        int v1 = b64_val(src[i + 1]);
        int v2 = 0, v3 = 0;
        int n;
        if (src[i + 2] == '=' && src[i + 3] == '=') {
            n = 1;
        } else if (src[i + 3] == '=') {
            n = 2;
        } else {
            n = 3;
        }
        v2 = (n >= 2) ? b64_val(src[i + 2]) : 0;
        v3 = (n >= 3) ? b64_val(src[i + 3]) : 0;
        out[o] = (uint8_t)((v0 << 2) | (v1 >> 4));
        if (n >= 2) out[o + 1] = (uint8_t)(((v1 & 0x0F) << 4) | (v2 >> 2));
        if (n >= 3) out[o + 2] = (uint8_t)(((v2 & 0x03) << 6) | v3);
        o += (size_t)n;
    }
    return total;
}

/* dtn_base64_encode — canonical padded standard-alphabet Base64 (the §3.3
 * wire encoding; byte-parity with Go's encoding/base64 StdEncoding). Added
 * for P3.8: the directory merge keys rows by the Base64 TEXT the directory
 * table stores (the Go side encodes; the C mirror must produce the exact
 * same strings). */
long dtn_base64_encode(const uint8_t *src, size_t src_len,
                       char *out, size_t cap)
{
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t groups = (src_len + 2) / 3;
    size_t total = groups * 4;
    size_t o = 0, i = 0;

    if (total + 1 > cap) {
        return -1;
    }
    while (i + 3 <= src_len) {
        uint32_t v = ((uint32_t)src[i] << 16) |
                     ((uint32_t)src[i + 1] << 8) |
                     (uint32_t)src[i + 2];
        out[o++] = alphabet[(v >> 18) & 0x3F];
        out[o++] = alphabet[(v >> 12) & 0x3F];
        out[o++] = alphabet[(v >> 6) & 0x3F];
        out[o++] = alphabet[v & 0x3F];
        i += 3;
    }
    if (i < src_len) {
        uint32_t v = (uint32_t)src[i] << 16;
        int rem = (int)(src_len - i);
        if (rem == 2) v |= (uint32_t)src[i + 1] << 8;
        out[o++] = alphabet[(v >> 18) & 0x3F];
        out[o++] = alphabet[(v >> 12) & 0x3F];
        if (rem == 2) {
            out[o++] = alphabet[(v >> 6) & 0x3F];
            out[o++] = '=';
        } else {
            out[o++] = '=';
            out[o++] = '=';
        }
    }
    out[o] = '\0';
    return (long)o;
}
