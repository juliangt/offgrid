/* dtn_epidemic.c — the §7.1 epidemic primitives (docs/node-network.md).
 * See dtn_epidemic.h. Byte-exact mirror of node/internal/forward/sync.go,
 * pinned by the shared vectors (host/tests/forward_vectors.h). */
#include "dtn_epidemic.h"

#include <string.h>

#include "dtn_sha256.h"

void dtn_epidemic_bloom_indexes(const uint8_t id[DTN_EPIDEMIC_ID_LEN],
                                uint32_t out[DTN_EPIDEMIC_BLOOM_K])
{
    uint8_t buf[1 + DTN_EPIDEMIC_ID_LEN];
    uint8_t digest[32];
    for (uint32_t i = 0; i < DTN_EPIDEMIC_BLOOM_K; i++) {
        buf[0] = (uint8_t)i;
        memcpy(buf + 1, id, DTN_EPIDEMIC_ID_LEN);
        dtn_sha256(buf, sizeof buf, digest);
        out[i] = ((uint32_t)digest[0] << 24 | (uint32_t)digest[1] << 16 |
                  (uint32_t)digest[2] << 8 | (uint32_t)digest[3]) %
                 DTN_EPIDEMIC_BLOOM_BITS;
    }
}

void dtn_bloom_init(dtn_bloom *b)
{
    memset(b->bits, 0, sizeof b->bits);
}

void dtn_bloom_add(dtn_bloom *b, const uint8_t id[DTN_EPIDEMIC_ID_LEN])
{
    uint32_t idx[DTN_EPIDEMIC_BLOOM_K];
    dtn_epidemic_bloom_indexes(id, idx);
    for (int i = 0; i < DTN_EPIDEMIC_BLOOM_K; i++) {
        b->bits[idx[i] / 8] |= (uint8_t)(1u << (idx[i] % 8));
    }
}

bool dtn_bloom_contains(const dtn_bloom *b, const uint8_t id[DTN_EPIDEMIC_ID_LEN])
{
    uint32_t idx[DTN_EPIDEMIC_BLOOM_K];
    dtn_epidemic_bloom_indexes(id, idx);
    for (int i = 0; i < DTN_EPIDEMIC_BLOOM_K; i++) {
        if ((b->bits[idx[i] / 8] & (uint8_t)(1u << (idx[i] % 8))) == 0) {
            return false;
        }
    }
    return true;
}

size_t dtn_epidemic_diff(const dtn_bloom *summary,
                         const uint8_t (*ids)[DTN_EPIDEMIC_ID_LEN], size_t n,
                         uint8_t (*out)[DTN_EPIDEMIC_ID_LEN], size_t out_cap)
{
    size_t missing = 0;
    for (size_t i = 0; i < n; i++) {
        if (!dtn_bloom_contains(summary, ids[i])) {
            if (missing < out_cap && out != NULL) {
                memcpy(out[missing], ids[i], DTN_EPIDEMIC_ID_LEN);
            }
            missing++;
        }
    }
    return missing;
}

void dtn_epidemic_summary_encode(const dtn_bloom *b, uint8_t out[DTN_EPIDEMIC_SUMMARY_PDU_LEN])
{
    out[0] = DTN_EPIDEMIC_SYNC_VERSION;
    memcpy(out + 1, b->bits, DTN_EPIDEMIC_BLOOM_BYTES);
}

bool dtn_epidemic_summary_parse(const uint8_t *payload, size_t len, dtn_bloom *out)
{
    if (len != DTN_EPIDEMIC_SUMMARY_PDU_LEN || payload[0] != DTN_EPIDEMIC_SYNC_VERSION) {
        return false;
    }
    memcpy(out->bits, payload + 1, DTN_EPIDEMIC_BLOOM_BYTES);
    return true;
}
