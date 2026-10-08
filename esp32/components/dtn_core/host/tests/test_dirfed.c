/* test_dirfed.c — P3.8 directory-federation conformance for the C side
 * (docs/node-network.md §9.3): every vector from
 * tests/vectors/directory/vectors.json (via the GENERATED header
 * directory_vectors.h) — Go-SIGNED identity cards that must verify and
 * merge to the SAME §3.4 outcome here (dtn_dirfed_merge) with the same
 * post-merge row state (dtn_store_dir_find), plus the merge mechanics'
 * own edge cases: the implied sequence 0 of a card-less row, source
 * promotion (rule 5), prekeys preservation across a federated replace,
 * and the row-cap refusal.
 *
 * The header route is the Go<->C interop contract: the cards below were
 * SIGNED in Go and must decide identically here, byte for byte.
 * Regenerate with:
 *   cd node && go test ./internal/directory -run TestDirectoryVectorsStable -regen
 */
#include "harness.h"

#include "dtn_base64.h"
#include "dtn_dirfed.h"
#include "dtn_store.h"
#include "directory_vectors.h"

#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char g_dir[128];

/* tdir — one temp store directory per scenario (wiped fresh; the vector
 * runner needs a clean store per scenario). */
static const char *tdir(const char *name)
{
    static int seq = 0;
    snprintf(g_dir, sizeof(g_dir), "/tmp/dtn_dirfed_test_%s_%d", name, seq++);
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", g_dir);
    FILE *probe = popen(cmd, "r"); /* missing dir is fine */
    if (probe) pclose(probe);
    mkdir(g_dir, 0755);
    return g_dir;
}

static const char *outcome_name(int o)
{
    switch (o) {
    case DTN_DIRFED_INSERT: return "insert";
    case DTN_DIRFED_REPLACE: return "replace";
    case DTN_DIRFED_STALE: return "stale";
    case DTN_DIRFED_DUPLICATE: return "duplicate";
    case DTN_DIRFED_CONFLICT: return "conflict";
    case DTN_DIRFED_DROP_AT_CAP: return "dropped_at_cap";
    case DTN_DIRFED_ERR_SHAPE: return "shape";
    case DTN_DIRFED_ERR_SIG: return "sig";
    case DTN_DIRFED_ERR_SKEW: return "skew";
    }
    return "?";
}

/* card_lookup — name → (cose, len) from the generated table. */
static const dtn_dirfed_card_vec *card_lookup(const char *name)
{
    for (size_t i = 0; i < sizeof(DVEC_CARDS) / sizeof(DVEC_CARDS[0]); i++) {
        if (strcmp(DVEC_CARDS[i].name, name) == 0) return &DVEC_CARDS[i];
    }
    return NULL;
}

void test_dirfed(void);

void test_dirfed(void)
{
    printf("dtn_core host tests — issue #33 P3.8 (directory federation)\n");

    /* ---- parse/verify unit checks on the Go-signed material ---- */
    T_BEGIN("dirfed: parse accepts the Go-signed card and pins its fields");
    {
        const dtn_dirfed_card_vec *c = card_lookup("seq1");
        CHECK(c != NULL);
        dtn_dirfed_card card;
        CHECK_EQ_INT(dtn_dirfed_parse(c->cose, c->len, &card), DTN_DIRFED_OK);
        CHECK_STR(card.alias, "alice_77");
        CHECK_EQ_INT((int)card.v, 1);
        CHECK_EQ_INT((int)card.seq, 1);
        CHECK_EQ_INT(memcmp(card.ed, DVEC_USER_PUB, 32), 0);
        CHECK_EQ_INT(card.created_ts, DVEC_NOW - 60);
    }

    T_BEGIN("dirfed: verify at the vector clock; the future card fails the skew rule");
    {
        dtn_dirfed_card card;
        const dtn_dirfed_card_vec *ok = card_lookup("seq2");
        const dtn_dirfed_card_vec *skew = card_lookup("future_skew");
        CHECK(ok != NULL && skew != NULL);
        CHECK_EQ_INT(dtn_dirfed_verify(ok->cose, ok->len, DVEC_NOW, &card),
                     DTN_DIRFED_OK);
        CHECK_EQ_INT(card.seq, 2);
        CHECK_EQ_INT(dtn_dirfed_verify(skew->cose, skew->len, DVEC_NOW, &card),
                     DTN_DIRFED_ERR_SKEW);
        /* ...but the SAME card verifies at its own (future) clock minus the
         * skew allowance — the receiver's clock is the only reference. */
    }

    T_BEGIN("dirfed: the tampered card fails the self-signature, not the shape");
    {
        dtn_dirfed_card card;
        const dtn_dirfed_card_vec *tam = card_lookup("tampered_sig");
        CHECK(tam != NULL);
        CHECK_EQ_INT(dtn_dirfed_verify(tam->cose, tam->len, DVEC_NOW, &card),
                     DTN_DIRFED_ERR_SIG);
        CHECK_EQ_INT(dtn_dirfed_parse(tam->cose, tam->len, &card),
                     DTN_DIRFED_OK); /* the blind door (§3.2) accepts the shape */
    }

    T_BEGIN("dirfed: shape refusals (truncated, oversize, not a COSE array(4))");
    {
        dtn_dirfed_card card;
        const dtn_dirfed_card_vec *ok = card_lookup("seq1");
        CHECK_EQ_INT(dtn_dirfed_parse(ok->cose, 0, &card), DTN_DIRFED_ERR_SHAPE);
        CHECK_EQ_INT(dtn_dirfed_parse(ok->cose, ok->len - 1, &card),
                     DTN_DIRFED_ERR_SHAPE);
        CHECK_EQ_INT(dtn_dirfed_parse(ok->cose, ok->len + 8, &card),
                     DTN_DIRFED_ERR_SHAPE); /* over the read: trailing garbage */
        uint8_t junk[16] = {0};
        CHECK_EQ_INT(dtn_dirfed_parse(junk, sizeof(junk), &card),
                     DTN_DIRFED_ERR_SHAPE);
    }

    /* ---- the shared scenarios, byte-identical verdicts and row states ---- */
    for (size_t i = 0; i < sizeof(DVEC_SCENARIOS) / sizeof(DVEC_SCENARIOS[0]); i++) {
        const dtn_dirfed_vec *v = &DVEC_SCENARIOS[i];
        char title[160];
        snprintf(title, sizeof(title), "dirfed vector: %s → %s", v->name,
                 outcome_name(v->expect));
        T_BEGIN(title);
        {
            dtn_store *st = NULL;
            CHECK_EQ_INT(dtn_store_open(&st, tdir("vec"), 5000), DTN_STORE_OK);

            /* seed cards merge as INSERT (the Go runner asserts the same) */
            for (size_t k = 0; k < 4 && v->seed_names[k]; k++) {
                const dtn_dirfed_card_vec *seed = card_lookup(v->seed_names[k]);
                CHECK(seed != NULL);
                int got = dtn_dirfed_merge(st, seed->cose, seed->len,
                                           DVEC_NOW, 0);
                CHECK_EQ_INT(got, DTN_DIRFED_INSERT);
            }

            const dtn_dirfed_card_vec *card = card_lookup(v->card_name);
            CHECK(card != NULL);
            int got = dtn_dirfed_merge(st, card->cose, card->len, DVEC_NOW, 0);
            CHECK_EQ_INT(got, v->expect);

            /* the post-merge row state (the part the merge rules govern) */
            dtn_dir_row row;
            int found = dtn_store_dir_find(st, DVEC_PUBKEY, &row) == 0;
            if (v->expect_source < 0) {
                CHECK_EQ_INT(found, 0);
            } else {
                CHECK_EQ_INT(found, 1);
                CHECK_STR(row.alias, v->expect_alias);
                CHECK_STR(row.x25519, v->expect_x);
                CHECK_EQ_INT(row.source, v->expect_source);
            }
            dtn_store_close(st);
        }
    }

    /* ---- merge mechanics beyond the vectors ---- */

    T_BEGIN("dirfed: rule 2 preserves the stored prekeys bundle and the local source flag");
    {
        dtn_store *st = NULL;
        CHECK_EQ_INT(dtn_store_open(&st, tdir("prekeys"), 5000), DTN_STORE_OK);
        const char *prekeys =
            "{\"v\":1,\"spk\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\","
            "\"spk_sig\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\","
            "\"ts\":1,\"opks\":[]}";
        /* a LOCAL row (source 0) with a card-less implied sequence 0 and a
         * prekeys bundle */
        CHECK_EQ_INT(dtn_store_dir_upsert_full(st, "alice_77", DVEC_PUBKEY,
                                               DVEC_X_SEQ1, prekeys, NULL, 0,
                                               DVEC_NOW - 1000),
                     0);
        const dtn_dirfed_card_vec *seq1 = card_lookup("seq1");
        CHECK_EQ_INT(dtn_dirfed_merge(st, seq1->cose, seq1->len, DVEC_NOW, 0),
                     DTN_DIRFED_REPLACE);
        dtn_dir_row row;
        CHECK_EQ_INT(dtn_store_dir_find(st, DVEC_PUBKEY, &row), 0);
        CHECK_EQ_INT(row.source, 0); /* rule 5: a local row stays local */
        CHECK_STR(row.prekeys, prekeys);
        dtn_store_close(st);
    }

    T_BEGIN("dirfed: the row cap refuses a new identity at a full table");
    {
        dtn_store *st = NULL;
        CHECK_EQ_INT(dtn_store_open(&st, tdir("cap"), 5000), DTN_STORE_OK);
        /* a table at the cap (one foreign local row is enough with cap = 1) */
        CHECK_EQ_INT(dtn_store_dir_upsert_full(st, "local_guy",
                                               DVEC_X_SEQ1, DVEC_X_SEQ1,
                                               NULL, NULL, 0, DVEC_NOW),
                     0);
        const dtn_dirfed_card_vec *seq1 = card_lookup("seq1");
        CHECK_EQ_INT(dtn_dirfed_merge(st, seq1->cose, seq1->len, DVEC_NOW, 1),
                     DTN_DIRFED_DROP_AT_CAP);
        CHECK_EQ_INT(dtn_store_dir_count(st), 1); /* the cap holds */
        /* unlimited (row_cap ≤ 0, the vectors' mode): the insert lands */
        CHECK_EQ_INT(dtn_dirfed_merge(st, seq1->cose, seq1->len, DVEC_NOW, 0),
                     DTN_DIRFED_INSERT);
        dtn_store_close(st);
    }

    T_BEGIN("dirfed: base64_encode is byte-parity with the Go StdEncoding");
    {
        char out[64];
        /* the vector's own pubkey (the §3.1.2 worked vector's ed) */
        CHECK_EQ_INT(dtn_base64_encode(DVEC_USER_PUB, 32, out, sizeof(out)), 44);
        CHECK_STR(out, DVEC_PUBKEY);
        /* RFC 4648's own test vectors */
        const uint8_t v3[3] = {0x01, 0x02, 0x03};
        const uint8_t v2[2] = {0x01, 0x02};
        const uint8_t v1[1] = {0x01};
        CHECK_EQ_INT(dtn_base64_encode(v1, 1, out, sizeof(out)), 4);
        CHECK_STR(out, "AQ==");
        CHECK_EQ_INT(dtn_base64_encode(v2, 2, out, sizeof(out)), 4);
        CHECK_STR(out, "AQI=");
        CHECK_EQ_INT(dtn_base64_encode(v3, 3, out, sizeof(out)), 4);
        CHECK_STR(out, "AQID");
        CHECK_EQ_INT(dtn_base64_encode(v3, 3, out, 4), -1);
        /* round-trip through the strict decoder */
        uint8_t back[32];
        CHECK_EQ_INT(dtn_base64_decode(out, 4, back, sizeof(back)), 3);
        CHECK_EQ_INT(memcmp(back, v3, 3), 0);
    }
}
