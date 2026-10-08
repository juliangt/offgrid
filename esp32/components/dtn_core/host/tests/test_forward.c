/* test_forward.c — the P3.5 forwarding engine (docs/node-network.md §7,
 * issue #33) in the dtn_core host suite: the §7.1 epidemic primitives
 * (dtn_epidemic) and the §7.5 bundle store (dtn_bundlestore), pinned to
 * the Go implementation through the shared vectors of
 * tests/vectors/forward/vectors.json (host/tests/forward_vectors.h):
 * byte-exact Bloom summaries, identical diff outcomes, and step-identical
 * admission verdicts + survivor sets for the store scenarios.
 *
 * The generated header names one symbol per vector (FORWARD_*_<i>_*); the
 * per-index pointer tables below assume the committed vector counts and
 * CHECK them, so a regenerated vector set with more scenarios fails loudly
 * here instead of silently skipping. */
#include "harness.h"
#include "forward_vectors.h"

#include <stdlib.h>
#include <string.h>

#include "dtn_bundlestore.h"
#include "dtn_epidemic.h"

static char g_fdir[128];

static const char *fdir(const char *name)
{
    snprintf(g_fdir, sizeof(g_fdir), "/tmp/dtn_bstore_test_%s", name);
    char cmd[176];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", g_fdir);
    if (system(cmd) != 0) {
        /* best effort: the open below fails loudly if removal failed */
    }
    return g_fdir;
}

static const char *verdict_str(dtn_bstore_verdict v)
{
    switch (v) {
    case DTN_BSTORE_ADMITTED:
        return "accepted";
    case DTN_BSTORE_DUP:
        return "dup";
    case DTN_BSTORE_EXPIRED:
        return "expired";
    case DTN_BSTORE_HOP_CAPPED:
        return "hop_capped";
    case DTN_BSTORE_AT_CAP:
        return "at_cap";
    }
    return "?";
}

/* ---- per-index vector tables (counted by the CHECKs below) ---- */
#if FORWARD_BLOOM_VEC_N != 5 || FORWARD_DIFF_VEC_N != 3 || FORWARD_STORE_VEC_N != 2
#error "forward vector set changed shape — update the tables in test_forward.c"
#endif

static const uint8_t *const BLOOM_IDS[FORWARD_BLOOM_VEC_N] = {
    FORWARD_BLOOM_0_IDS, FORWARD_BLOOM_1_IDS, FORWARD_BLOOM_2_IDS,
    FORWARD_BLOOM_3_IDS, FORWARD_BLOOM_4_IDS,
};
static const uint16_t BLOOM_ID_N[FORWARD_BLOOM_VEC_N] = {
    FORWARD_BLOOM_0_ID_COUNT, FORWARD_BLOOM_1_ID_COUNT, FORWARD_BLOOM_2_ID_COUNT,
    FORWARD_BLOOM_3_ID_COUNT, FORWARD_BLOOM_4_ID_COUNT,
};
static const uint8_t *const BLOOM_EXPECT[FORWARD_BLOOM_VEC_N] = {
    FORWARD_BLOOM_0_EXPECT, FORWARD_BLOOM_1_EXPECT, FORWARD_BLOOM_2_EXPECT,
    FORWARD_BLOOM_3_EXPECT, FORWARD_BLOOM_4_EXPECT,
};

static const uint8_t *const DIFF_SUMMARY[FORWARD_DIFF_VEC_N] = {
    FORWARD_DIFF_0_SUMMARY, FORWARD_DIFF_1_SUMMARY, FORWARD_DIFF_2_SUMMARY,
};
static const uint8_t *const DIFF_IDS[FORWARD_DIFF_VEC_N] = {
    FORWARD_DIFF_0_IDS, FORWARD_DIFF_1_IDS, FORWARD_DIFF_2_IDS,
};
static const uint16_t DIFF_ID_N[FORWARD_DIFF_VEC_N] = {
    FORWARD_DIFF_0_ID_COUNT, FORWARD_DIFF_1_ID_COUNT, FORWARD_DIFF_2_ID_COUNT,
};
static const uint8_t *const DIFF_MISSING[FORWARD_DIFF_VEC_N] = {
    FORWARD_DIFF_0_MISSING, FORWARD_DIFF_1_MISSING, FORWARD_DIFF_2_MISSING,
};
static const uint16_t DIFF_MISSING_N[FORWARD_DIFF_VEC_N] = {
    FORWARD_DIFF_0_MISSING_COUNT, FORWARD_DIFF_1_MISSING_COUNT, FORWARD_DIFF_2_MISSING_COUNT,
};

/* store scenarios: step PDU/len/verdict tables (7 steps max). */
#define FORWARD_MAX_STEPS 7
static const uint8_t *const STORE_PDU[FORWARD_STORE_VEC_N][FORWARD_MAX_STEPS] = {
    { FORWARD_STORE_0_STEP_0_PDU, FORWARD_STORE_0_STEP_1_PDU, FORWARD_STORE_0_STEP_2_PDU,
      FORWARD_STORE_0_STEP_3_PDU, FORWARD_STORE_0_STEP_4_PDU, NULL, NULL },
    { FORWARD_STORE_1_STEP_0_PDU, FORWARD_STORE_1_STEP_1_PDU, FORWARD_STORE_1_STEP_2_PDU,
      FORWARD_STORE_1_STEP_3_PDU, FORWARD_STORE_1_STEP_4_PDU, FORWARD_STORE_1_STEP_5_PDU,
      FORWARD_STORE_1_STEP_6_PDU },
};
static const uint16_t STORE_LEN[FORWARD_STORE_VEC_N][FORWARD_MAX_STEPS] = {
    { FORWARD_STORE_0_STEP_0_LEN, FORWARD_STORE_0_STEP_1_LEN, FORWARD_STORE_0_STEP_2_LEN,
      FORWARD_STORE_0_STEP_3_LEN, FORWARD_STORE_0_STEP_4_LEN, 0, 0 },
    { FORWARD_STORE_1_STEP_0_LEN, FORWARD_STORE_1_STEP_1_LEN, FORWARD_STORE_1_STEP_2_LEN,
      FORWARD_STORE_1_STEP_3_LEN, FORWARD_STORE_1_STEP_4_LEN, FORWARD_STORE_1_STEP_5_LEN,
      FORWARD_STORE_1_STEP_6_LEN },
};
static const char *const STORE_VERDICT[FORWARD_STORE_VEC_N][FORWARD_MAX_STEPS] = {
    { FORWARD_STORE_0_STEP_0_VERDICT, FORWARD_STORE_0_STEP_1_VERDICT,
      FORWARD_STORE_0_STEP_2_VERDICT, FORWARD_STORE_0_STEP_3_VERDICT,
      FORWARD_STORE_0_STEP_4_VERDICT, "", "" },
    { FORWARD_STORE_1_STEP_0_VERDICT, FORWARD_STORE_1_STEP_1_VERDICT,
      FORWARD_STORE_1_STEP_2_VERDICT, FORWARD_STORE_1_STEP_3_VERDICT,
      FORWARD_STORE_1_STEP_4_VERDICT, FORWARD_STORE_1_STEP_5_VERDICT,
      FORWARD_STORE_1_STEP_6_VERDICT },
};
static const int STORE_CAP[FORWARD_STORE_VEC_N] = { FORWARD_STORE_0_CAP, FORWARD_STORE_1_CAP };
static const int STORE_STEPS[FORWARD_STORE_VEC_N] = { FORWARD_STORE_0_STEP_N,
                                                      FORWARD_STORE_1_STEP_N };
static const uint16_t STORE_SURV_N[FORWARD_STORE_VEC_N] = { FORWARD_STORE_0_SURVIVOR_N,
                                                            FORWARD_STORE_1_SURVIVOR_N };
static const uint8_t *const STORE_SURV[FORWARD_STORE_VEC_N] = { FORWARD_STORE_0_SURVIVORS,
                                                                FORWARD_STORE_1_SURVIVORS };

static void test_epidemic_vectors(void)
{
    T_BEGIN("epidemic: bloom vectors byte-exact (Go<->C, shared vectors)");
    for (int v = 0; v < FORWARD_BLOOM_VEC_N; v++) {
        dtn_bloom b;
        dtn_bloom_init(&b);
        for (uint16_t i = 0; i < BLOOM_ID_N[v]; i++) {
            dtn_bloom_add(&b, BLOOM_IDS[v] + (size_t)i * DTN_EPIDEMIC_ID_LEN);
        }
        CHECK(memcmp(b.bits, BLOOM_EXPECT[v], DTN_EPIDEMIC_BLOOM_BYTES) == 0);
    }

    T_BEGIN("epidemic: diff vectors (transfer lists identical to Go)");
    for (int v = 0; v < FORWARD_DIFF_VEC_N; v++) {
        dtn_bloom s;
        memcpy(s.bits, DIFF_SUMMARY[v], DTN_EPIDEMIC_BLOOM_BYTES);
        uint16_t n = DIFF_ID_N[v];
        uint8_t(*out)[DTN_EPIDEMIC_ID_LEN] = malloc(sizeof(*out) * (n ? n : 1));
        CHECK(out != NULL);
        size_t got = dtn_epidemic_diff(&s, (const uint8_t (*)[DTN_EPIDEMIC_ID_LEN])DIFF_IDS[v],
                                       n, out, n);
        CHECK_EQ_INT((long long)got, (long long)DIFF_MISSING_N[v]);
        CHECK(memcmp(out, DIFF_MISSING[v], (size_t)DIFF_MISSING_N[v] * DTN_EPIDEMIC_ID_LEN) == 0);
        free(out);
    }

    T_BEGIN("epidemic: summary PDU codec round-trip + version gate");
    {
        dtn_bloom b;
        dtn_bloom_init(&b);
        uint8_t pdu[DTN_EPIDEMIC_SUMMARY_PDU_LEN];
        dtn_epidemic_summary_encode(&b, pdu);
        CHECK_EQ_INT(pdu[0], DTN_EPIDEMIC_SYNC_VERSION);
        dtn_bloom back;
        CHECK(dtn_epidemic_summary_parse(pdu, sizeof pdu, &back));
        CHECK(memcmp(back.bits, b.bits, DTN_EPIDEMIC_BLOOM_BYTES) == 0);
        CHECK(!dtn_epidemic_summary_parse(pdu, sizeof pdu - 1, &back));
        pdu[0] = DTN_EPIDEMIC_SYNC_VERSION + 1;
        CHECK(!dtn_epidemic_summary_parse(pdu, sizeof pdu, &back));
    }
}

/* ---- store vectors ---- */

struct id_collect {
    uint8_t (*out)[DTN_EPIDEMIC_ID_LEN];
    size_t n;
    size_t cap;
};

static void collect_id(void *ud, const uint8_t id[DTN_BUNDLE_ID_LEN], uint8_t cls)
{
    (void)cls;
    struct id_collect *c = ud;
    if (c->n < c->cap) {
        memcpy(c->out[c->n], id, DTN_BUNDLE_ID_LEN);
    }
    c->n++;
}

static void test_store_vectors(void)
{
    T_BEGIN("bundlestore: cap honesty (the enforced cap is the reported one)");
    {
        dtn_bundlestore *st = NULL;
        CHECK(dtn_bundlestore_open(&st, fdir("caphonesty"), 7) == DTN_BSTORE_OK);
        CHECK_EQ_INT(dtn_bundlestore_cap(st), 7);
        dtn_bundlestore_close(st);
        CHECK(dtn_bundlestore_open(&st, fdir("capbig"), DTN_BUNDLESTORE_DEFAULT_CAP) ==
              DTN_BSTORE_OK);
        CHECK_EQ_INT(dtn_bundlestore_cap(st), (long long)DTN_BUNDLESTORE_DEFAULT_CAP);
        dtn_bundlestore_close(st);
        CHECK(dtn_bundlestore_open(&st, fdir("capbad"), 0) == DTN_BSTORE_ERR_ARG);
        CHECK(st == NULL);
    }

    T_BEGIN("bundlestore: classification mirrors the Go EID rules");
    {
        dtn_bundle_eid none, mail, admin, node, other;
        CHECK(dtn_bundle_eid_parse("dtn:none", &none) == DTN_BUNDLE_OK);
        CHECK(dtn_bundle_eid_parse("dtn:og-mail", &mail) == DTN_BUNDLE_OK);
        CHECK(dtn_bundle_eid_parse("dtn://og-admin/", &admin) == DTN_BUNDLE_OK);
        CHECK(dtn_bundle_eid_parse("dtn://og.0123456789abcdef/", &node) == DTN_BUNDLE_OK);
        CHECK(dtn_bundle_eid_parse("dtn:og-updates", &other) == DTN_BUNDLE_OK);
        CHECK_EQ_INT(dtn_bundlestore_classify(&mail, &none), DTN_BSTORE_CLASS_MAIL);
        CHECK_EQ_INT(dtn_bundlestore_classify(&mail, &node), DTN_BSTORE_CLASS_BULK);
        CHECK_EQ_INT(dtn_bundlestore_classify(&admin, &node), DTN_BSTORE_CLASS_MGMT);
        CHECK_EQ_INT(dtn_bundlestore_classify(&admin, &none), DTN_BSTORE_CLASS_MGMT);
        CHECK_EQ_INT(dtn_bundlestore_classify(&node, &node), DTN_BSTORE_CLASS_BULK);
        CHECK_EQ_INT(dtn_bundlestore_classify(&other, &none), DTN_BSTORE_CLASS_BULK);
    }

    T_BEGIN("bundlestore: shared store-scenario vectors (verdict + survivors)");
    for (int v = 0; v < FORWARD_STORE_VEC_N; v++) {
        dtn_bundlestore *st = NULL;
        char name[32];
        snprintf(name, sizeof(name), "vec%d", v);
        CHECK(dtn_bundlestore_open(&st, fdir(name), (int32_t)STORE_CAP[v]) == DTN_BSTORE_OK);
        for (int s = 0; s < STORE_STEPS[v]; s++) {
            dtn_bstore_verdict got = dtn_bundlestore_admit(
                st, STORE_PDU[v][s], STORE_LEN[v][s], FORWARD_VEC_NOW);
            CHECK_STR(verdict_str(got), STORE_VERDICT[v][s]);
        }
        /* Survivors: the live id set, bundle_id-ascending, byte-equal —
         * the eviction ORDER pin (both sides order identically). */
        uint16_t want_n = STORE_SURV_N[v];
        uint8_t(*got)[DTN_EPIDEMIC_ID_LEN] = malloc(sizeof(*got) * (want_n ? want_n : 1));
        struct id_collect cx = { got, 0, want_n };
        CHECK(dtn_bundlestore_each_live_id(st, FORWARD_VEC_NOW, &cx, collect_id) == DTN_BSTORE_OK);
        CHECK_EQ_INT((long long)cx.n, (long long)want_n);
        CHECK(memcmp(got, STORE_SURV[v], (size_t)want_n * DTN_EPIDEMIC_ID_LEN) == 0);
        free(got);
        dtn_bundlestore_close(st);
    }

    T_BEGIN("bundlestore: persist + dedup across reopen; byte-exact fetch; janitor");
    {
        /* Scenario 0 step 0 is a valid 1-hour mail bundle — reuse it for
         * the lifecycle checks (the vector set guarantees its bytes). */
        const uint8_t *pdu = STORE_PDU[0][0];
        size_t pdu_len = STORE_LEN[0][0];
        uint8_t id[DTN_BUNDLE_ID_LEN];
        CHECK(dtn_bundle_id(pdu, pdu_len, id) == DTN_BUNDLE_OK);

        /* ONE clean directory for the whole lifecycle (fdir() re-wipes, so
         * it is captured once). */
        const char *dir = fdir("persist");
        dtn_bundlestore *st = NULL;
        CHECK(dtn_bundlestore_open(&st, dir, 100) == DTN_BSTORE_OK);
        CHECK_EQ_INT(dtn_bundlestore_admit(st, pdu, pdu_len, FORWARD_VEC_NOW),
                     DTN_BSTORE_ADMITTED);
        CHECK_EQ_INT(dtn_bundlestore_count(st), 1);
        dtn_bundlestore_close(st);

        CHECK(dtn_bundlestore_open(&st, dir, 100) == DTN_BSTORE_OK);
        CHECK_EQ_INT(dtn_bundlestore_count(st), 1); /* replayed from the log */
        CHECK_EQ_INT(dtn_bundlestore_admit(st, pdu, pdu_len, FORWARD_VEC_NOW),
                     DTN_BSTORE_DUP);
        /* Byte-exact fetch (size query + copy). */
        size_t need = 0;
        CHECK_EQ_INT(dtn_bundlestore_get_pdu(st, id, NULL, 0, &need), 0);
        CHECK_EQ_INT((long long)need, (long long)pdu_len);
        uint8_t buf[2048];
        CHECK_EQ_INT(dtn_bundlestore_get_pdu(st, id, buf, sizeof buf, &need), 0);
        CHECK(memcmp(buf, pdu, pdu_len) == 0);
        CHECK_EQ_INT(dtn_bundlestore_get_pdu(st, id, buf, pdu_len - 1, &need),
                     DTN_BSTORE_ERR_IO);
        /* Janitor: the exclusive boundary — live exactly at expires_at,
         * gone one second later. */
        int32_t deleted = -1;
        CHECK(dtn_bundlestore_janitor(st, FORWARD_VEC_NOW + 3600, &deleted) == 0);
        CHECK_EQ_INT(deleted, 0);
        CHECK(dtn_bundlestore_janitor(st, FORWARD_VEC_NOW + 3601, &deleted) == 0);
        CHECK_EQ_INT(deleted, 1);
        CHECK_EQ_INT(dtn_bundlestore_count(st), 0);
        dtn_bstore_counters cs;
        dtn_bundlestore_counters(st, &cs);
        CHECK_EQ_INT((long long)cs.expired, 1);
        CHECK_EQ_INT((long long)cs.janitor_swept, 1);
        dtn_bundlestore_close(st);
    }
}

void test_forward(void)
{
    printf("dtn_core host tests — issue #33 P3.5 (forwarding engine)\n");
    test_epidemic_vectors();
    test_store_vectors();
}
