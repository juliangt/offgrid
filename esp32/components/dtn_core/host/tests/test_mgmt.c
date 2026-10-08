/* test_mgmt.c — P3.6 management-plane conformance for the C side: every
 * vector from tests/vectors/mgmt/vectors.json (via the GENERATED header
 * mgmt_vectors.h) — Go-SIGNED command objects that must reach the SAME
 * §8.2 verdict here (dtn_mgmt_decide), the same per-signer seq-table state,
 * and install_cert's args-cert merging through the §2.5 rules (dtn_rolecert).
 *
 * The header route is the Go<->C interop contract: the commands below were
 * SIGNED in Go and must decide identically here, byte for byte. Regenerate
 * with:  cd node && go test ./internal/mgmt -run TestMgmtVectorsStable -regen
 */
#include "harness.h"

#include "dtn_mgmt.h"
#include "dtn_nodeid.h"
#include "dtn_rolecert.h"
#include "mgmt_vectors.h"

#include <string.h>

static const char *verdict_name(int v)
{
    switch (v) {
    case DTN_MGMT_OK: return "ok";
    case DTN_MGMT_ERR_SHAPE: return "shape";
    case DTN_MGMT_ERR_SIG: return "sig";
    case DTN_MGMT_ERR_TARGET: return "target";
    case DTN_MGMT_ERR_UNKNOWN: return "unknown_cmd";
    case DTN_MGMT_ERR_LEVEL: return "level";
    case DTN_MGMT_ERR_SEQ: return "seq";
    case DTN_MGMT_ERR_EXPIRED: return "expired";
    }
    return "?";
}

static const char *merge_name(int outcome)
{
    switch (outcome) {
    case DTN_ROLECERT_MERGE_REPLACED: return "replace";
    case DTN_ROLECERT_MERGE_STALE_DROPPED: return "stale_drop";
    case DTN_ROLECERT_MERGE_CONFLICT_KEPT: return "conflict_keep";
    case DTN_ROLECERT_MERGE_UNCHANGED: return "unchanged";
    case DTN_ROLECERT_MERGE_EXPIRED_DROPPED: return "expired_drop";
    default: return "invalid";
    }
}

/* cert_lookup — name → (cose, len, eid) from the generated table. */
static const dtn_mgmt_cert_vec *cert_lookup(const char *name)
{
    for (size_t i = 0; i < sizeof(MGMT_CERTS) / sizeof(MGMT_CERTS[0]); i++) {
        if (strcmp(MGMT_CERTS[i].name, name) == 0) return &MGMT_CERTS[i];
    }
    return NULL;
}

/* arg_lookup — the parsed command's args member by key (NULL if absent). */
static const dtn_mgmt_arg *arg_lookup(const dtn_mgmt_cmd *cmd, const char *key)
{
    for (size_t i = 0; i < cmd->arg_count; i++) {
        if (strcmp(cmd->args[i].key, key) == 0) return &cmd->args[i];
    }
    return NULL;
}

static void test_mgmt_table(void)
{
    T_BEGIN("mgmt: the frozen v1 command table");
    CHECK_EQ_INT(dtn_mgmt_required_level("get_status"), 0);
    CHECK_EQ_INT(dtn_mgmt_required_level("force_janitor"), 1);
    CHECK_EQ_INT(dtn_mgmt_required_level("trigger_sync"), 1);
    CHECK_EQ_INT(dtn_mgmt_required_level("set_quiet_hours"), 1);
    CHECK_EQ_INT(dtn_mgmt_required_level("set_store_cap"), 2);
    CHECK_EQ_INT(dtn_mgmt_required_level("set_budgets"), 2);
    CHECK_EQ_INT(dtn_mgmt_required_level("set_dial_interval"), 2);
    CHECK_EQ_INT(dtn_mgmt_required_level("federation_on"), 2);
    CHECK_EQ_INT(dtn_mgmt_required_level("federation_off"), 2);
    CHECK_EQ_INT(dtn_mgmt_required_level("install_cert"), 3);
    CHECK_EQ_INT(dtn_mgmt_required_level("factory_reset_node_plane"), 3);
    CHECK_EQ_INT(dtn_mgmt_required_level("reboot_node"), -1);
}

static void test_mgmt_seqs(void)
{
    T_BEGIN("mgmt: per-signer seq table");
    dtn_mgmt_seqs s;
    dtn_mgmt_seqs_init(&s);
    /* No floor recorded: a first command (seq >= 1) never collides with 0. */
    CHECK_EQ_INT(dtn_mgmt_seq_last(&s, "dtn://og.0123456789abcdef/"), 0);
    CHECK_EQ_INT(dtn_mgmt_seq_commit(&s, "dtn://og.0123456789abcdef/", 5), 0);
    CHECK_EQ_INT(dtn_mgmt_seq_last(&s, "dtn://og.0123456789abcdef/"), 5);
    CHECK_EQ_INT(dtn_mgmt_seq_commit(&s, "dtn://og.0123456789abcdef/", 9), 0);
    CHECK_EQ_INT(dtn_mgmt_seq_last(&s, "dtn://og.0123456789abcdef/"), 9);
    CHECK_EQ_INT(dtn_mgmt_seq_commit(&s, "dtn://og.fedcba9876543210/", 2), 0);
    CHECK_EQ_INT(dtn_mgmt_seq_last(&s, "dtn://og.fedcba9876543210/"), 2);
    CHECK_EQ_INT(dtn_mgmt_seq_last(&s, "dtn://og.absent00000000/"), 0);
}

static void test_mgmt_vector_verdicts(void)
{
    T_BEGIN("mgmt: shared verdict vectors (Go-signed, C-decided)");
    size_t n = sizeof(MGMT_VECS) / sizeof(MGMT_VECS[0]);
    CHECK(n >= 12); /* the §11 row-i catalogue: every verdict class covered */

    for (size_t v = 0; v < n; v++) {
        const dtn_mgmt_vec *vec = &MGMT_VECS[v];

        /* 1. Seed the §2.5 cache with the vector's certs (the Go side merged
         * the same bytes in the same order). */
        dtn_rolecert_cache cache;
        dtn_rolecert_cache_init(&cache);
        for (size_t i = 0; i < 4 && vec->seed_names[i] != NULL; i++) {
            const dtn_mgmt_cert_vec *c = cert_lookup(vec->seed_names[i]);
            if (!c) {
                CHECK(0); /* generator/consumer drift */
                continue;
            }
            dtn_rolecert_merge_status st;
            (void)dtn_rolecert_cache_merge(&cache, c->cose, c->len,
                                           MGMT_ANCHOR_PUB, MGMT_VEC_NOW, &st);
        }

        /* 2. Seed the per-signer seq table pre-state. */
        dtn_mgmt_seqs seqs;
        dtn_mgmt_seqs_init(&seqs);
        for (size_t i = 0; i < vec->lseq_count; i++) {
            const dtn_mgmt_cert_vec *c = cert_lookup(vec->lseq_names[i]);
            if (!c) continue;
            (void)dtn_mgmt_seq_commit(&seqs, c->eid, vec->lseq_vals[i]);
        }

        /* 3. THE decision — the same bytes the Go pipeline consumed. */
        dtn_mgmt_cmd cmd;
        memset(&cmd, 0xaa, sizeof(cmd));
        int verdict = dtn_mgmt_decide(&cache, vec->local_eid,
                                      vec->cose, vec->cose_len,
                                      MGMT_VEC_NOW, &seqs, &cmd);
        if (verdict != vec->expect) {
            printf("    vector %s: verdict %s, want %s\n", vec->name,
                   verdict_name(verdict), verdict_name(vec->expect));
        }
        CHECK_EQ_INT(verdict, vec->expect);

        /* 4. The seq-table post-state: every recorded floor matches, and the
         * table holds EXACTLY the expected entries. */
        size_t entries = 0;
        for (size_t i = 0; i < vec->xseq_count; i++) {
            const dtn_mgmt_cert_vec *c = cert_lookup(vec->xseq_names[i]);
            if (!c) continue;
            CHECK_EQ_INT(dtn_mgmt_seq_last(&seqs, c->eid) == vec->xseq_vals[i], 1);
            entries++;
        }
        CHECK_EQ_INT(seqs.used, entries);

        /* 5. install_cert: the parsed args cert merges into a FRESH cache
         * with the recorded outcome (the executor layer's cache feed). */
        if (vec->expect_merge[0] != '\0') {
            const dtn_mgmt_arg *cert_arg = arg_lookup(&cmd, "cert");
            if (!cert_arg || cert_arg->kind != DTN_MGMT_ARG_BSTR) {
                CHECK(0); /* the ok verdict must carry the parsed cert */
                continue;
            }
            dtn_rolecert_cache fresh;
            dtn_rolecert_cache_init(&fresh);
            dtn_rolecert_merge_status st;
            (void)dtn_rolecert_cache_merge(&fresh, cert_arg->bytes,
                                           cert_arg->bytes_len,
                                           MGMT_ANCHOR_PUB, MGMT_VEC_NOW, &st);
            CHECK_STR(merge_name(st.outcome), vec->expect_merge);
            CHECK_EQ_INT(st.revoked, 0);
        }
    }
}

static void test_mgmt_shape_fail_closed(void)
{
    T_BEGIN("mgmt: fail-closed shapes");
    /* A valid vector command, truncated at the signature — and a target that
     * is not an EID — must both be DTN_MGMT_ERR_SHAPE, never a crash. */
    const dtn_mgmt_vec *first = &MGMT_VECS[0];

    dtn_rolecert_cache cache;
    dtn_rolecert_cache_init(&cache);
    dtn_mgmt_seqs seqs;
    dtn_mgmt_seqs_init(&seqs);
    for (size_t i = 0; first->seed_names[i] != NULL; i++) {
        const dtn_mgmt_cert_vec *c = cert_lookup(first->seed_names[i]);
        dtn_rolecert_merge_status st;
        (void)dtn_rolecert_cache_merge(&cache, c->cose, c->len,
                                       MGMT_ANCHOR_PUB, MGMT_VEC_NOW, &st);
    }
    CHECK_EQ_INT(dtn_mgmt_decide(&cache, first->local_eid, first->cose,
                                 first->cose_len / 2, MGMT_VEC_NOW, &seqs, NULL),
                 DTN_MGMT_ERR_SHAPE);
    static const uint8_t garbage[] = {0x01, 0x02, 0x03};
    CHECK_EQ_INT(dtn_mgmt_decide(&cache, first->local_eid, garbage,
                                 sizeof(garbage), MGMT_VEC_NOW, &seqs, NULL),
                 DTN_MGMT_ERR_SHAPE);
    CHECK_EQ_INT(dtn_mgmt_decide(&cache, first->local_eid, NULL, 0,
                                 MGMT_VEC_NOW, &seqs, NULL),
                 DTN_MGMT_ERR_SHAPE);
}

void test_mgmt(void);

void test_mgmt(void)
{
    printf("dtn_core host tests — issue #33 P3.6 (management plane)\n");
    test_mgmt_table();
    test_mgmt_seqs();
    test_mgmt_vector_verdicts();
    test_mgmt_shape_fail_closed();
}
