/* test_capsule.c — P3.7 capsule conformance for the C side: every vector
 * from tests/vectors/capsule/vectors.json (via the GENERATED header
 * capsule_vectors.h) — Go-SIGNED capsules that must reach the SAME §2.4.4
 * staging verdicts here (dtn_capsule_stage), plus the §9.4 reassembly
 * scenarios whose per-step verdicts and assembled SHA-256 must match
 * byte for byte (dtn_capsule_reasm_*).
 *
 * The header route is the Go<->C interop contract. Regenerate with:
 *   cd node && go test ./internal/capsule -run TestVectorsStable -regen
 */
#include "harness.h"

#include "capsule_vectors.h"
#include "dtn_capsule.h"
#include "dtn_sha256.h"

#include <stdint.h>
#include <string.h>

static const char *verdict_name(int v)
{
    switch (v) {
    case DTN_CAPSULE_OK: return "ok";
    case DTN_CAPSULE_BAD_MAGIC: return "bad_magic";
    case DTN_CAPSULE_BAD_FORMAT: return "bad_format";
    case DTN_CAPSULE_BAD_LENGTH: return "bad_length";
    case DTN_CAPSULE_BAD_METADATA: return "bad_metadata";
    case DTN_CAPSULE_BAD_VERSION: return "bad_version";
    case DTN_CAPSULE_CREATED_AT_SKEW: return "created_at_skew";
    case DTN_CAPSULE_SHA_MISMATCH: return "sha_mismatch";
    case DTN_CAPSULE_LEN_MISMATCH: return "length_mismatch";
    case DTN_CAPSULE_BAD_SIGNATURE: return "bad_signature";
    case DTN_CAPSULE_STALE: return "stale";
    case DTN_CAPSULE_TOO_OLD: return "too_old";
    case DTN_CAPSULE_WRONG_ARCH: return "wrong_arch";
    case DTN_CAPSULE_UNPINNED: return "unpinned";
    default: return "?";
    }
}

static void test_capsule_stage_verdicts(void)
{
    T_BEGIN("capsule: staging verdict vectors (Go-signed)");
    for (size_t i = 0; i < (size_t)CAPSULE_VERDICTS_N; i++) {
        const capsule_vec_verdict *v = &CAPSULE_VERDICTS[i];
        const uint8_t *pub = (v->pub == 0) ? CAPSULE_VEC_RELEASE_PUB
                           : (v->pub == 1) ? CAPSULE_VEC_OTHER_PUB
                                           : NULL;
        dtn_capsule_meta meta;
        memset(&meta, 0, sizeof meta);
        int rc = dtn_capsule_stage(v->blob, v->blob_len, pub, v->arch,
                                   v->running, v->staged, CAPSULE_VEC_NOW, &meta);
        CHECK(strcmp(verdict_name(rc), v->expect) == 0);
        if (rc != DTN_CAPSULE_OK) {
            printf("    verdict %s: got %s, want %s\n", v->name,
                   verdict_name(rc), v->expect);
            continue;
        }
        CHECK(meta.release == v->expect_release);
    }
}

/* The chunk scenario harness: a tiny chunk store the src callback reads
 * from (the "caller keeps the chunks" contract — on a node these ARE the
 * stored bundles). */
#define SC_MAX_CHUNKS 32
struct chunk_slot {
    uint8_t id[8];
    uint32_t idx;
    uint32_t total;
    const uint8_t *data;
    size_t len;
};
struct chunk_store {
    struct chunk_slot slots[SC_MAX_CHUNKS];
    size_t n;
};

static int chunk_store_put(struct chunk_store *cs, const uint8_t *pdu, size_t len)
{
    dtn_capsule_chunk ch;
    if (!dtn_capsule_chunk_parse(pdu, len, &ch)) return -1;
    for (size_t i = 0; i < cs->n; i++) {
        if (memcmp(cs->slots[i].id, ch.id, 8) == 0 && cs->slots[i].idx == ch.idx) {
            return 0; /* already stored (dup offer absorbed earlier) */
        }
    }
    if (cs->n >= SC_MAX_CHUNKS) return -1;
    struct chunk_slot *s = &cs->slots[cs->n++];
    memcpy(s->id, ch.id, 8);
    s->idx = ch.idx;
    s->total = ch.total;
    s->data = ch.data;
    s->len = ch.len;
    return 0;
}

static int chunk_store_src(void *ud, const uint8_t id[8], uint32_t idx,
                           uint32_t total, const uint8_t **data, size_t *len)
{
    struct chunk_store *cs = ud;
    for (size_t i = 0; i < cs->n; i++) {
        if (memcmp(cs->slots[i].id, id, 8) == 0 && cs->slots[i].idx == idx) {
            if (cs->slots[i].total != total) return -1;
            *data = cs->slots[i].data;
            *len = cs->slots[i].len;
            return 0;
        }
    }
    return -1;
}

static void test_capsule_reasm_scenarios(void)
{
    T_BEGIN("capsule: §9.4 reassembly scenarios");
    static uint8_t assembled[64 * 1024]; /* the largest vector capsule (~600 B) */
    for (size_t si = 0; si < (size_t)CAPSULE_SCENARIOS_N; si++) {
        const capsule_vec_scenario *sc = &CAPSULE_SCENARIOS[si];
        dtn_capsule_reasm st;
        dtn_capsule_reasm_init(&st);
        struct chunk_store cs;
        memset(&cs, 0, sizeof cs);
        for (size_t step = 0; step < sc->n_steps; step++) {
            const capsule_vec_step *s = &sc->steps[step];
            uint8_t completed[8];
            int rc = dtn_capsule_reasm_offer(&st, s->pdu, s->pdu_len,
                                             CAPSULE_VEC_NOW, 3600, completed);
            const char *got;
            switch (rc) {
            case DTN_CAPSULE_REASM_STORED: got = "stored"; break;
            case DTN_CAPSULE_REASM_DUP: got = "dup"; break;
            case DTN_CAPSULE_REASM_COMPLETE: got = "complete"; break;
            case DTN_CAPSULE_REASM_REFUSED: got = "refused"; break;
            default: got = "bad"; break;
            }
            if (strcmp(got, s->expect) != 0) {
                printf("    %s step %zu: got %s, want %s\n", sc->name, step, got, s->expect);
            }
            CHECK(strcmp(got, s->expect) == 0);
            /* Remember the chunk bytes for assembly (stored and completed
             * steps delivered real cargo). */
            if (rc == DTN_CAPSULE_REASM_STORED || rc == DTN_CAPSULE_REASM_COMPLETE) {
                CHECK(chunk_store_put(&cs, s->pdu, s->pdu_len) == 0);
            }
            if (rc == DTN_CAPSULE_REASM_COMPLETE) {
                /* Which capsule completed? Match the id against the
                 * scenario's capsule table. */
                size_t found = (size_t)-1;
                for (size_t k = 0; k < sc->n_capsules; k++) {
                    if (memcmp(sc->capsules[k].id, completed, 8) == 0) {
                        found = k;
                    }
                }
                CHECK(found != (size_t)-1);
                if (found == (size_t)-1) continue;
                CHECK((int)step == sc->capsules[found].complete_at);
                /* Assemble byte-exactly and hash. total comes from the
                 * completing PDU's header (bytes 8..11, §9.4). */
                uint32_t total = ((uint32_t)sc->steps[step].pdu[8] << 24) |
                                 ((uint32_t)sc->steps[step].pdu[9] << 16) |
                                 ((uint32_t)sc->steps[step].pdu[10] << 8) |
                                 (uint32_t)sc->steps[step].pdu[11];
                size_t out_len = 0;
                int arc = dtn_capsule_reasm_assemble(completed, total,
                                                     chunk_store_src, &cs,
                                                     assembled, sizeof assembled, &out_len);
                CHECK(arc == 0);
                if (arc == 0) {
                    /* Byte-exactness against the vector capsule itself,
                     * then the pinned sha (the Go executor's identical
                     * assertion). */
                    CHECK(out_len == sc->capsules[found].bytes_len);
                    CHECK(memcmp(assembled, sc->capsules[found].bytes, out_len) == 0);
                    uint8_t sum[32];
                    char hex[65];
                    dtn_sha256(assembled, out_len, sum);
                    for (int k = 0; k < 32; k++) {
                        sprintf(hex + 2 * k, "%02x", sum[k]);
                    }
                    hex[64] = '\0';
                    if (strcmp(hex, sc->capsules[found].sha256_hex) != 0) {
                        printf("    %s capsule %s: assembled sha %s, want %s\n",
                               sc->name, sc->capsules[found].key, hex,
                               sc->capsules[found].sha256_hex);
                    }
                    CHECK(strcmp(hex, sc->capsules[found].sha256_hex) == 0);
                }
            }
        }
    }
}

static void test_capsule_chunk_header_and_ids(void)
{
    T_BEGIN("capsule: chunk header arithmetic + capsule_id derivation");
    /* A corrupted-PDU sanity set around the first real scenario step. */
    const capsule_vec_scenario *sc = &CAPSULE_SCENARIOS[0];
    dtn_capsule_chunk ch;
    CHECK(dtn_capsule_chunk_parse(sc->steps[0].pdu, sc->steps[0].pdu_len, &ch) == 1);
    CHECK(ch.total >= 1 && ch.idx < ch.total);
    CHECK(ch.len == sc->steps[0].pdu_len - DTN_CAPSULE_CHUNK_HEADER_LEN);

    uint8_t truncated[32];
    memset(truncated, 0, sizeof truncated);
    CHECK(dtn_capsule_chunk_parse(truncated, sizeof truncated, &ch) == 0); /* total 0 */
    truncated[8] = 0;
    truncated[9] = 0;
    truncated[10] = 0x10;
    truncated[11] = 0x00; /* total 4096 > the ceiling */
    CHECK(dtn_capsule_chunk_parse(truncated, sizeof truncated, &ch) == 0);
    truncated[11] = 0x01;
    truncated[12] = 0;
    truncated[13] = 0;
    truncated[14] = 0;
    truncated[15] = 0x01; /* idx 1 >= total 1 */
    CHECK(dtn_capsule_chunk_parse(truncated, sizeof truncated, &ch) == 0);

    /* capsule_id = SHA-256(capsule)[0:8] and sha256_hex, both pinned
     * against every scenario's embedded capsule bytes — the exact
     * derivation of CapsuleIDOf on the Go side. */
    for (size_t si = 0; si < (size_t)CAPSULE_SCENARIOS_N; si++) {
        const capsule_vec_scenario *sc = &CAPSULE_SCENARIOS[si];
        for (size_t k = 0; k < sc->n_capsules; k++) {
            uint8_t sum[32];
            char hex[65];
            dtn_sha256(sc->capsules[k].bytes, sc->capsules[k].bytes_len, sum);
            for (int j = 0; j < 32; j++) {
                sprintf(hex + 2 * j, "%02x", sum[j]);
            }
            hex[64] = '\0';
            CHECK(strcmp(hex, sc->capsules[k].sha256_hex) == 0);
            CHECK(memcmp(sum, sc->capsules[k].id, 8) == 0);
        }
    }
}

void test_capsule(void)
{
    test_capsule_stage_verdicts();
    test_capsule_reasm_scenarios();
    test_capsule_chunk_header_and_ids();
}
