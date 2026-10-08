/* dtn_nodeid.c — self-certifying node identity (docs/node-network.md §2.1)
 * and the RAM reference implementation of the dtn_nodeid_store HAL seam. */
#include "dtn_nodeid.h"

#include <string.h>

#include "dtn_sha256.h"

void dtn_nodeid_fingerprint(const uint8_t pub[DTN_NODEID_KEY_LEN],
                            uint8_t fp[DTN_NODEID_FP_LEN])
{
    uint8_t digest[32];
    dtn_sha256(pub, DTN_NODEID_KEY_LEN, digest);
    memcpy(fp, digest, DTN_NODEID_FP_LEN);
}

void dtn_nodeid_eid(const uint8_t fp[DTN_NODEID_FP_LEN],
                    char eid[DTN_NODEID_EID_MAX + 1])
{
    static const char hex[] = "0123456789abcdef";
    size_t i, o = 0;
    const char prefix[] = "dtn://og.";

    memcpy(eid + o, prefix, sizeof(prefix) - 1);
    o += sizeof(prefix) - 1;
    for (i = 0; i < DTN_NODEID_FP_LEN; i++) {
        eid[o++] = hex[fp[i] >> 4];
        eid[o++] = hex[fp[i] & 0x0f];
    }
    eid[o++] = '/';
    eid[o] = '\0';
}

static int hex_digit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1; /* uppercase rejected: the EID form is lowercase */
}

int dtn_nodeid_eid_fingerprint(const char *eid, uint8_t fp[DTN_NODEID_FP_LEN])
{
    size_t i;
    /* exact shape: dtn://og. (9) + 16 hex + / (+ NUL) */
    if (eid == NULL) return -1;
    if (strlen(eid) != DTN_NODEID_EID_MAX) return -1;
    if (strncmp(eid, "dtn://og.", 9) != 0) return -1;
    if (eid[DTN_NODEID_EID_MAX - 1] != '/') return -1;
    for (i = 0; i < DTN_NODEID_FP_LEN; i++) {
        int hi = hex_digit(eid[9 + 2 * i]);
        int lo = hex_digit(eid[9 + 2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        fp[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

int dtn_nodeid_eid_binding(const uint8_t pub[DTN_NODEID_KEY_LEN], const char *eid)
{
    uint8_t want[DTN_NODEID_FP_LEN], got[DTN_NODEID_FP_LEN];
    char want_eid[DTN_NODEID_EID_MAX + 1];

    if (eid == NULL) return -1;
    if (dtn_nodeid_eid_fingerprint(eid, got) != 0) return -1;
    dtn_nodeid_fingerprint(pub, want);
    if (memcmp(want, got, DTN_NODEID_FP_LEN) != 0) return -1;
    /* the string must be the canonical rendering, not just a parseable one */
    dtn_nodeid_eid(want, want_eid);
    if (strcmp(want_eid, eid) != 0) return -1;
    return 0;
}

int dtn_nodeid_self_fingerprint(const dtn_nodeid_store *v,
                                uint8_t fp[DTN_NODEID_FP_LEN])
{
    uint8_t key[DTN_NODEID_KEY_LEN];
    if (v == NULL || v->load_key == NULL) return -1;
    if (v->load_key(v->ctx, key) != 0) return -1;
    dtn_nodeid_fingerprint(key, fp);
    return 0;
}

/* --- RAM reference store ----------------------------------------------------- */

static int ram_load_key(void *ctx, uint8_t key[DTN_NODEID_KEY_LEN])
{
    dtn_nodeid_ram_store *s = ctx;
    if (!s->has_key) return -1;
    memcpy(key, s->key, DTN_NODEID_KEY_LEN);
    return 0;
}

static int ram_save_key(void *ctx, const uint8_t key[DTN_NODEID_KEY_LEN])
{
    dtn_nodeid_ram_store *s = ctx;
    memcpy(s->key, key, DTN_NODEID_KEY_LEN);
    s->has_key = 1;
    return 0;
}

static int ram_load_cert(void *ctx, uint8_t *buf, size_t cap, size_t *len)
{
    dtn_nodeid_ram_store *s = ctx;
    if (!s->has_cert) return -1;
    if (cap < s->cert_len) return -1;
    memcpy(buf, s->cert, s->cert_len);
    *len = s->cert_len;
    return 0;
}

static int ram_save_cert(void *ctx, const uint8_t *blob, size_t len)
{
    dtn_nodeid_ram_store *s = ctx;
    if (len > sizeof(s->cert)) return -1;
    memcpy(s->cert, blob, len);
    s->cert_len = len;
    s->has_cert = 1;
    return 0;
}

void dtn_nodeid_ram_store_init(dtn_nodeid_ram_store *s)
{
    memset(s, 0, sizeof(*s));
}

void dtn_nodeid_ram_vtable(dtn_nodeid_ram_store *s, dtn_nodeid_store *v)
{
    v->load_key = ram_load_key;
    v->save_key = ram_save_key;
    v->load_cert = ram_load_cert;
    v->save_cert = ram_save_cert;
    v->ctx = s;
}
