/* test_store.c — the §9 storage contract on flash: dedup, cap semantics,
 * boundary exactness, power-loss safety, schema versioning, quarantine,
 * directory ordering and the §10.3 prekeys blind validation. */
#include "harness.h"

#include "dtn_store.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define NOW 1759500000LL

static char g_dir[128];

static const char *tdir(const char *name)
{
    static char last[64] = "";
    snprintf(g_dir, sizeof(g_dir), "/tmp/dtn_store_test_%s", name);
    if (strcmp(last, name) != 0) {
        /* wipe only on first use — reopen cycles within one test must see
         * the committed state, not a freshly deleted directory */
        char cmd[192];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", g_dir);
        (void)system(cmd); /* missing dir is fine */
        mkdir(g_dir, 0755);
        snprintf(last, sizeof(last), "%s", name);
    }
    return g_dir;
}

/* a valid envelope: given 64-hex id, 16-hex hint, timestamps, and a
 * floor-size (248-byte decoded) payload of canonical Base64. Returns a
 * pointer into a small rotating ring (tests consume it immediately). */
static dtn_envelope *mk_env(const char *id_hex, const char *hint,
                            int64_t created, int64_t ttl)
{
    static dtn_envelope ring[8];
    static int rot;
    dtn_envelope *e = &ring[rot++ % 8];
    memset(e, 0, sizeof(*e));
    e->v = 1;
    snprintf(e->id, sizeof(e->id), "%s", id_hex);
    snprintf(e->dest_hint, sizeof(e->dest_hint), "%s", hint);
    e->created_at = created;
    e->ttl = ttl;
    size_t n = 332; /* Base64 of exactly 248 bytes */
    memset(e->payload, 'A', n);
    e->payload[n - 2] = '=';
    e->payload[n - 1] = '=';
    e->payload[n] = '\0';
    e->payload_len = n;
    return e;
}

#define ID_A "aaaa000000000000000000000000000000000000000000000000000000000001"
#define ID_B "bbbb000000000000000000000000000000000000000000000000000000000002"
#define ID_C "cccc000000000000000000000000000000000000000000000000000000000003"
#define ID_D "dddd000000000000000000000000000000000000000000000000000000000004"
#define ID_E "eeee000000000000000000000000000000000000000000000000000000000005"
#define HINT "9f3ab02c1d77e4c1"
/* same first 8 bytes (fingerprint collision by construction), different rest */
#define ID_FP1 "1234567811111111111111111111111111111111111111111111111111111111"
#define ID_FP2 "1234567822222222222222222222222222222222222222222222222222222222"

struct pull_sink {
    dtn_envelope envs[64];
    char ids[64][65];
    int n;
};

static void pull_cb(void *ud, const dtn_envelope *e)
{
    struct pull_sink *s = ud;
    if (s->n < 64) {
        s->envs[s->n] = *e;
        snprintf(s->ids[s->n], 65, "%s", e->id);
        s->n++;
    }
}

struct dir_sink {
    char alias[64][25];
    char pubkey[64][45];
    char prekeys[64][2100];
    int64_t last_seen[64];
    int64_t epoch[64];
    int n;
};

static void dir_cb(void *ud, const char *alias, const char *pubkey,
                   const char *x25519, int64_t last_seen, int64_t epoch,
                   const char *prekeys)
{
    struct dir_sink *s = ud;
    (void)x25519;
    if (s->n < 64) {
        snprintf(s->alias[s->n], 25, "%s", alias);
        snprintf(s->pubkey[s->n], 45, "%s", pubkey);
        s->last_seen[s->n] = last_seen;
        s->epoch[s->n] = epoch;
        if (prekeys) {
            snprintf(s->prekeys[s->n], 2100, "%s", prekeys);
        } else {
            s->prekeys[s->n][0] = '\0';
        }
        s->n++;
    }
}

static void put_ok(dtn_store *st, const dtn_envelope *e, int expect_absorbed)
{
    int absorbed = -1;
    CHECK_EQ_INT(dtn_store_batch_begin(st), 0);
    CHECK_EQ_INT(dtn_store_batch_put(st, e, &absorbed), 0);
    CHECK_EQ_INT(absorbed, expect_absorbed);
    CHECK_EQ_INT(dtn_store_batch_commit(st), 0);
}

static const char *VALID_PREKEYS =
    "{\"v\":1,\"spk\":\"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"
    "=\",\"spk_sig\":\"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g"
    "ISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw==\",\"ts\":17910720"
    "00,\"opks\":[\"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\","
    "\"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\",\"AwMDAwMDAwM"
    "DAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=\",\"BAQEBAQEBAQEBAQEBAQEBAQE"
    "BAQEBAQEBAQEBAQEBAQ=\",\"BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB"
    "QUFBQU=\",\"BgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgY=\",\"B"
    "wcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=\",\"CAgICAgICAgICA"
    "gICAgICAgICAgICAgICAgICAgICAg=\"]}";

void test_store(void)
{
    dtn_store *st = NULL;
    struct pull_sink ps;
    struct dir_sink ds;
    int absorbed;

    T_BEGIN("store: fresh open — schema 4, empty, clean flags");
    CHECK_EQ_INT(dtn_store_open(&st, tdir("fresh"), 5000), DTN_STORE_OK);
    CHECK_EQ_INT(dtn_store_envelope_count(st), 0);
    CHECK_EQ_INT(dtn_store_schema_version_on_disk(st), 4);
    CHECK_EQ_INT(dtn_store_dir_count(st), 0);
    CHECK(!dtn_store_quarantined(st));
    CHECK(!dtn_store_pending_migration(st));
    CHECK_EQ_INT((int)dtn_store_last_cleanup_unix(st), 0);
    dtn_store_close(st);

    T_BEGIN("store: batch commit persists across reopen (the sync point)");
    CHECK_EQ_INT(dtn_store_open(&st, tdir("persist"), 5000), DTN_STORE_OK);
    put_ok(st, mk_env(ID_A, HINT, NOW, 604800), 0);
    CHECK_EQ_INT(dtn_store_envelope_count(st), 1);
    dtn_store_close(st);
    CHECK_EQ_INT(dtn_store_open(&st, tdir("persist"), 5000), DTN_STORE_OK);
    CHECK_EQ_INT(dtn_store_envelope_count(st), 1);
    dtn_store_close(st);

    T_BEGIN("store: dedup by id — re-put absorbed silently (§10.4/§6.2)");
    CHECK_EQ_INT(dtn_store_open(&st, tdir("dedup"), 5000), DTN_STORE_OK);
    dtn_envelope *e1 = mk_env(ID_A, HINT, NOW, 604800);
    CHECK_EQ_INT(dtn_store_batch_begin(st), 0);
    CHECK_EQ_INT(dtn_store_batch_put(st, e1, &absorbed), 0);
    CHECK_EQ_INT(absorbed, 0);
    CHECK_EQ_INT(dtn_store_batch_put(st, e1, &absorbed), 0);
    CHECK_EQ_INT(absorbed, 1); /* same batch: INSERT OR IGNORE */
    CHECK_EQ_INT(dtn_store_batch_commit(st), 0);
    CHECK_EQ_INT(dtn_store_envelope_count(st), 1);
    dtn_store_close(st);
    CHECK_EQ_INT(dtn_store_open(&st, tdir("dedup"), 5000), DTN_STORE_OK);
    put_ok(st, e1, 1); /* across reopen too */
    CHECK_EQ_INT(dtn_store_envelope_count(st), 1);
    dtn_store_close(st);

    T_BEGIN("store: abort discards the whole batch (fail-closed)");
    CHECK_EQ_INT(dtn_store_open(&st, tdir("abort"), 5000), DTN_STORE_OK);
    put_ok(st, mk_env(ID_A, HINT, NOW, 604800), 0); /* committed base */
    CHECK_EQ_INT(dtn_store_batch_begin(st), 0);
    CHECK_EQ_INT(dtn_store_batch_put(
                     st, mk_env(ID_B, HINT, NOW, 604800), &absorbed), 0);
    dtn_store_batch_abort(st);
    CHECK_EQ_INT(dtn_store_envelope_count(st), 1); /* only the committed */
    dtn_store_close(st);
    CHECK_EQ_INT(dtn_store_open(&st, tdir("abort"), 5000), DTN_STORE_OK);
    CHECK_EQ_INT(dtn_store_envelope_count(st), 1);
    dtn_store_close(st);

    T_BEGIN("store: power cut mid-batch — uncommitted tail discarded at open");
    CHECK_EQ_INT(dtn_store_open(&st, tdir("crash"), 5000), DTN_STORE_OK);
    put_ok(st, mk_env(ID_A, HINT, NOW, 604800), 0);
    CHECK_EQ_INT(dtn_store_batch_begin(st), 0);
    CHECK_EQ_INT(dtn_store_batch_put(
                     st, mk_env(ID_B, HINT, NOW, 604800), &absorbed), 0);
    dtn_store_test_crash(st); /* no commit, no clean close */
    CHECK_EQ_INT(dtn_store_open(&st, tdir("crash"), 5000), DTN_STORE_OK);
    CHECK_EQ_INT(dtn_store_envelope_count(st), 1);
    dtn_store_close(st);

    T_BEGIN("store: torn tail (junk after last frame) truncated, store intact");
    {
        CHECK_EQ_INT(dtn_store_open(&st, tdir("torn"), 5000), DTN_STORE_OK);
        put_ok(st, mk_env(ID_A, HINT, NOW, 604800), 0);
        dtn_store_close(st);
        /* append a partial frame the way a power cut would */
        char p[256];
        snprintf(p, sizeof(p), "%s/envelopes.log", tdir("torn"));
        FILE *f = fopen(p, "ab");
        CHECK(f != NULL);
        fwrite("OGDT-JUNK-FRAME", 1, 15, f); /* not even a valid header */
        fclose(f);
        CHECK_EQ_INT(dtn_store_open(&st, tdir("torn"), 5000), DTN_STORE_OK);
        CHECK_EQ_INT(dtn_store_envelope_count(st), 1);
        dtn_store_close(st);
        /* and the junk stays gone: reopening again is idempotent */
        CHECK_EQ_INT(dtn_store_open(&st, tdir("torn"), 5000), DTN_STORE_OK);
        CHECK_EQ_INT(dtn_store_envelope_count(st), 1);
        dtn_store_close(st);
    }

    T_BEGIN("store: cap decided per batch — overshoot ≤ one batch, then full");
    {
        dtn_store *small;
        CHECK_EQ_INT(dtn_store_open(&small, tdir("cap"), 10), DTN_STORE_OK);
        char id[65];
        for (int i = 0; i < 15; i++) { /* batch of 15 over a cap of 10 */
            snprintf(id, sizeof(id), "%08x%056d", i, i);
            CHECK_EQ_INT(dtn_store_batch_begin(small), 0);
            CHECK_EQ_INT(
                dtn_store_batch_put(small, mk_env(id, HINT, NOW, 604800),
                                    &absorbed), 0);
        }
        CHECK_EQ_INT(dtn_store_batch_commit(small), 0);
        CHECK_EQ_INT(dtn_store_envelope_count(small), 15); /* overshoot OK */
        /* the NEXT batch is refused whole — 429 node_full */
        CHECK_EQ_INT(dtn_store_batch_begin(small), 0);
        CHECK_EQ_INT(dtn_store_batch_put(
                         small, mk_env(ID_A, HINT, NOW, 604800), &absorbed),
                     -2);
        dtn_store_batch_abort(small);
        CHECK_EQ_INT(dtn_store_envelope_count(small), 15); /* nothing evicted */
        dtn_store_close(small);
    }

    T_BEGIN("store: pull — inclusive expiry boundary and ordering (§10.4)");
    {
        CHECK_EQ_INT(dtn_store_open(&st, tdir("pull"), 5000), DTN_STORE_OK);
        put_ok(st, mk_env(ID_A, HINT, NOW - 100, 100), 0); /* exp@NOW */
        put_ok(st, mk_env(ID_B, HINT, NOW - 200, 100), 0); /* exp@NOW-100 */
        put_ok(st, mk_env(ID_C, HINT, NOW - 50, 604800), 0);
        put_ok(st, mk_env(ID_D, HINT, NOW - 60, 604800), 0);
        dtn_known_ids k = { NULL, 0, 0 };
        memset(&ps, 0, sizeof(ps));
        CHECK_EQ_INT(dtn_store_pull(st, &k, 50, NOW, &ps, pull_cb, NULL), 0);
        /* A expires AT NOW: inclusive → served. B expired: exclusive → gone.
         * Order: created_at DESC → C(-50) then D(-60) then A(-100+100=NOW) */
        CHECK_EQ_INT(ps.n, 3);
        CHECK_STR(ps.ids[0], ID_C);
        CHECK_STR(ps.ids[1], ID_D);
        CHECK_STR(ps.ids[2], ID_A);
        dtn_store_close(st);
    }

    T_BEGIN("store: pull — id ASC tie-break on equal created_at");
    {
        CHECK_EQ_INT(dtn_store_open(&st, tdir("tie"), 5000), DTN_STORE_OK);
        put_ok(st, mk_env(ID_D, HINT, NOW, 604800), 0);
        put_ok(st, mk_env(ID_B, HINT, NOW, 604800), 0);
        put_ok(st, mk_env(ID_C, HINT, NOW, 604800), 0);
        dtn_known_ids k = { NULL, 0, 0 };
        memset(&ps, 0, sizeof(ps));
        CHECK_EQ_INT(dtn_store_pull(st, &k, 50, NOW, &ps, pull_cb, NULL), 0);
        CHECK_EQ_INT(ps.n, 3);
        CHECK_STR(ps.ids[0], ID_B);
        CHECK_STR(ps.ids[1], ID_C);
        CHECK_STR(ps.ids[2], ID_D);
        dtn_store_close(st);
    }

    T_BEGIN("store: pull — known_ids exclusion is fingerprint-safe");
    {
        /* ID_FP1 and ID_FP2 share the first 8 bytes by construction: the
         * RAM fingerprint of the one in known_ids must NOT exclude the
         * other — the full on-flash id decides (design note §4) */
        CHECK_EQ_INT(dtn_store_open(&st, tdir("fpsafe"), 5000), DTN_STORE_OK);
        put_ok(st, mk_env(ID_FP1, HINT, NOW, 604800), 0);
        put_ok(st, mk_env(ID_FP2, HINT, NOW, 604800), 0);
        char (*known)[65] = malloc(sizeof(char[65]) * 1);
        snprintf(known[0], 65, "%s", ID_FP1);
        dtn_known_ids k = { known, 500, 1 };
        memset(&ps, 0, sizeof(ps));
        CHECK_EQ_INT(dtn_store_pull(st, &k, 50, NOW, &ps, pull_cb, NULL), 0);
        CHECK_EQ_INT(ps.n, 1);
        CHECK_STR(ps.ids[0], ID_FP2);
        free(known);
        dtn_store_close(st);
    }

    T_BEGIN("store: pull — served envelope is byte-identical (§15.7 q)");
    {
        CHECK_EQ_INT(dtn_store_open(&st, tdir("bytes"), 5000), DTN_STORE_OK);
        dtn_envelope *orig = mk_env(ID_A, HINT, NOW - 10, 604800);
        put_ok(st, orig, 0);
        dtn_known_ids k = { NULL, 0, 0 };
        memset(&ps, 0, sizeof(ps));
        CHECK_EQ_INT(dtn_store_pull(st, &k, 50, NOW, &ps, pull_cb, NULL), 0);
        CHECK_EQ_INT(ps.n, 1);
        CHECK_EQ_INT(ps.envs[0].v, orig->v);
        CHECK_STR(ps.envs[0].id, orig->id);
        CHECK_STR(ps.envs[0].dest_hint, orig->dest_hint);
        CHECK_EQ_INT((int)ps.envs[0].created_at, (int)orig->created_at);
        CHECK_EQ_INT((int)ps.envs[0].ttl, (int)orig->ttl);
        CHECK_EQ_INT((int)ps.envs[0].payload_len, (int)orig->payload_len);
        CHECK(memcmp(ps.envs[0].payload, orig->payload, orig->payload_len) == 0);
        dtn_store_close(st);
    }

    T_BEGIN("store: sweep — exclusive boundary, counters, nothing evicted "
            "before its deadline");
    {
        CHECK_EQ_INT(dtn_store_open(&st, tdir("sweep"), 5000), DTN_STORE_OK);
        put_ok(st, mk_env(ID_A, HINT, NOW - 100, 100), 0); /* deadline NOW */
        put_ok(st, mk_env(ID_B, HINT, NOW - 101, 100), 0); /* deadline NOW-1 */
        int32_t deleted = -1;
        CHECK_EQ_INT(dtn_store_sweep(st, NOW, &deleted), 0);
        CHECK_EQ_INT(deleted, 1); /* only B: deadline < NOW is exclusive */
        CHECK_EQ_INT(dtn_store_envelope_count(st), 1);
        CHECK_EQ_INT((int)dtn_store_last_cleanup_unix(st), (int)NOW);
        CHECK_EQ_INT(dtn_store_last_cleanup_deleted(st), 1);
        CHECK_EQ_INT((int)dtn_store_ttl_swept_total(st), 1);
        dtn_store_close(st);
    }

    T_BEGIN("store: expiring-within buckets (§10.7, pure index counts)");
    {
        CHECK_EQ_INT(dtn_store_open(&st, tdir("buckets"), 5000), DTN_STORE_OK);
        put_ok(st, mk_env(ID_A, HINT, NOW, 1800), 0);      /* +30 min */
        put_ok(st, mk_env(ID_B, HINT, NOW, 7200), 0);      /* +2 h */
        put_ok(st, mk_env(ID_C, HINT, NOW, 90000), 0);     /* +25 h */
        CHECK_EQ_INT(dtn_store_expiring_within(st, NOW, 3600), 1);
        CHECK_EQ_INT(dtn_store_expiring_within(st, NOW, 6 * 3600), 2);
        CHECK_EQ_INT(dtn_store_expiring_within(st, NOW, 24 * 3600), 2);
        CHECK_EQ_INT(dtn_store_expiring_within(st, NOW, 48 * 3600), 3);
        CHECK(dtn_store_db_size(st) > 0);
        dtn_store_close(st);
    }

    T_BEGIN("store: compaction keeps live records and reopens cleanly");
    {
        CHECK_EQ_INT(dtn_store_open(&st, tdir("compact"), 5000), DTN_STORE_OK);
        char id[65];
        for (int i = 0; i < 200; i++) { /* ~150 KB log */
            snprintf(id, sizeof(id), "%08x%056d", i, i);
            put_ok(st, mk_env(id, HINT, NOW, i < 10 ? 604800 : 3600), 0);
        }
        int32_t deleted = 0;
        CHECK_EQ_INT(dtn_store_sweep(st, NOW + 7200, &deleted), 0);
        CHECK_EQ_INT(deleted, 190); /* the 1-hour envelopes expire first */
        CHECK_EQ_INT(dtn_store_envelope_count(st), 10);
        dtn_store_close(st);
        CHECK_EQ_INT(dtn_store_open(&st, tdir("compact"), 5000), DTN_STORE_OK);
        CHECK_EQ_INT(dtn_store_envelope_count(st), 10);
        dtn_known_ids k = { NULL, 0, 0 };
        memset(&ps, 0, sizeof(ps));
        CHECK_EQ_INT(dtn_store_pull(st, &k, 50, NOW + 7200, &ps, pull_cb, NULL), 0);
        CHECK_EQ_INT(ps.n, 10);
        dtn_store_close(st);
    }

    T_BEGIN("directory: upsert, latest wins, verbatim prekeys, clear (§9)");
    {
        CHECK_EQ_INT(dtn_store_open(&st, tdir("dir"), 5000), DTN_STORE_OK);
        const char *pk = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";
        const char *xk = "/R7hH59JUnnBjDLCUFTQ46F9eKg0kK8Chze1mEQpqVg=";
        CHECK_EQ_INT(
            dtn_store_dir_upsert(st, "alice_77", pk, xk, VALID_PREKEYS, NOW),
            0);
        CHECK_EQ_INT(
            dtn_store_dir_upsert(st, "alice_77", pk, xk, NULL, NOW + 10), 0);
        CHECK_EQ_INT(dtn_store_dir_count(st), 1); /* upsert, not insert */
        memset(&ds, 0, sizeof(ds));
        CHECK_EQ_INT(dtn_store_dir_get(st, 500, &ds, dir_cb, NULL), 0);
        CHECK_EQ_INT(ds.n, 1);
        CHECK_STR(ds.alias[0], "alice_77");
        CHECK_EQ_INT((int)ds.last_seen[0], (int)NOW + 10);
        CHECK_EQ_INT((int)ds.epoch[0], (int)((NOW + 10) / 86400)); /* §6.1 */
        CHECK_STR(ds.prekeys[0], ""); /* NULL cleared the bundle */
        CHECK_EQ_INT(
            dtn_store_dir_upsert(st, "bob_1", pk, xk, VALID_PREKEYS, NOW + 20),
            0);
        memset(&ds, 0, sizeof(ds));
        CHECK_EQ_INT(dtn_store_dir_get(st, 500, &ds, dir_cb, NULL), 0);
        CHECK_EQ_INT(ds.n, 1);
        CHECK_STR(ds.prekeys[0], VALID_PREKEYS); /* verbatim (§10.3) */
        dtn_store_close(st);
    }

    T_BEGIN("directory: GET order last_seen DESC, pubkey ASC, limit ≤ 500");
    {
        CHECK_EQ_INT(dtn_store_open(&st, tdir("dirord"), 5000), DTN_STORE_OK);
        char pk[45], alias[25];
        /* three entries: two share last_seen (tie → pubkey ASC), one older */
        CHECK_EQ_INT(dtn_store_dir_upsert(
                         st, "zeta",
                         "zzAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                         "xx", NULL, NOW), 0);
        CHECK_EQ_INT(dtn_store_dir_upsert(
                         st, "alpha",
                         "aaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                         "xx", NULL, NOW), 0);
        CHECK_EQ_INT(dtn_store_dir_upsert(
                         st, "older",
                         "mmAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                         "xx", NULL, NOW - 100), 0);
        memset(&ds, 0, sizeof(ds));
        CHECK_EQ_INT(dtn_store_dir_get(st, 500, &ds, dir_cb, NULL), 0);
        CHECK_EQ_INT(ds.n, 3);
        CHECK_STR(ds.alias[0], "alpha"); /* tie: pubkey ASC */
        CHECK_STR(ds.alias[1], "zeta");
        CHECK_STR(ds.alias[2], "older"); /* last_seen DESC */
        (void)pk;
        (void)alias;
        dtn_store_close(st);
    }

    T_BEGIN("store: corrupt superblocks → quarantine, fresh store, loud");
    {
        CHECK_EQ_INT(dtn_store_open(&st, tdir("quar"), 5000), DTN_STORE_OK);
        put_ok(st, mk_env(ID_A, HINT, NOW, 604800), 0);
        dtn_store_close(st);
        /* garble both super slots */
        char p[256];
        snprintf(p, sizeof(p), "%s/super.a.bin", tdir("quar"));
        FILE *f = fopen(p, "r+b");
        CHECK(f != NULL);
        fseek(f, 20, SEEK_SET); /* inside the CRC-covered tail (16..63) */
        fwrite("\xff\xff\xff\xff", 1, 4, f); /* CRC now fails */
        fclose(f);
        snprintf(p, sizeof(p), "%s/super.b.bin", tdir("quar"));
        f = fopen(p, "r+b");
        if (f) {
            fwrite("\x00\x00\x00\x00", 1, 4, f);
            fclose(f);
        }
        CHECK_EQ_INT(dtn_store_open(&st, tdir("quar"), 5000), DTN_STORE_OK);
        CHECK(dtn_store_quarantined(st)); /* renamed aside, recreated */
        CHECK_EQ_INT(dtn_store_envelope_count(st), 0); /* fresh, not half */
        dtn_store_close(st);
        /* the corrupt store was preserved for forensics */
        char c[256];
        snprintf(c, sizeof(c), "%s/envelopes.corrupt.log", tdir("quar"));
        FILE *g = fopen(c, "rb");
        CHECK(g != NULL);
        if (g) fclose(g);
    }

    T_BEGIN("store: downgrade refusal — newer store, older firmware (§15.3)");
    {
        CHECK_EQ_INT(dtn_store_open(&st, tdir("down"), 5000), DTN_STORE_OK);
        put_ok(st, mk_env(ID_A, HINT, NOW, 604800), 0);
        dtn_store_close(st);
        /* hand-craft a version-5 superblock (CRC recomputed the same way) */
        for (const char *slot = "a"; *slot; slot++) {
            char p[256];
            snprintf(p, sizeof(p), "%s/super.%c.bin", tdir("down"), *slot);
            FILE *f = fopen(p, "wb");
            CHECK(f != NULL);
            uint8_t buf[64];
            memset(buf, 0, sizeof(buf));
            uint32_t magic = 0x5447444Fu;
            int32_t version = 5;
            uint32_t seq = 99;
            memcpy(buf, &magic, 4);
            memcpy(buf + 4, &version, 4);
            memcpy(buf + 8, &seq, 4);
            /* CRC-32 (zlib) over bytes 4..63 — same algorithm as the store */
            uint32_t table[256];
            for (uint32_t i = 0; i < 256; i++) {
                uint32_t c = i;
                for (int kk = 0; kk < 8; kk++) {
                    c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
                }
                table[i] = c;
            }
            uint32_t crc = 0xFFFFFFFFu;
            for (int i = 16; i < 64; i++) { /* the store's CRC region */
                crc = table[(crc ^ buf[i]) & 0xFFu] ^ (crc >> 8);
            }
            crc ^= 0xFFFFFFFFu;
            memcpy(buf + 12, &crc, 4);
            fwrite(buf, 1, sizeof(buf), f);
            fclose(f);
        }
        dtn_store *refused = NULL;
        CHECK_EQ_INT(dtn_store_open(&refused, tdir("down"), 5000),
                     DTN_STORE_ERR_DOWNGRADE);
        /* the store was left untouched (refusal semantics, §15.3) */
        char c[256];
        snprintf(c, sizeof(c), "%s/envelopes.log", tdir("down"));
        FILE *g = fopen(c, "rb");
        CHECK(g != NULL);
        if (g) {
            fseek(g, 0, SEEK_END);
            CHECK(ftell(g) > 0); /* the data is still there */
            fclose(g);
        }
    }

    T_BEGIN("prekeys: §10.3 blind shape validation");
    CHECK(dtn_store_valid_prekeys(VALID_PREKEYS, strlen(VALID_PREKEYS)));
    CHECK(!dtn_store_valid_prekeys(NULL, 0));
    CHECK(!dtn_store_valid_prekeys("", 0));
    /* > 2048 bytes */
    {
        char big[3000];
        memset(big, ' ', sizeof(big));
        big[sizeof(big) - 1] = '\0';
        CHECK(!dtn_store_valid_prekeys(big, strlen(big)));
    }
    /* missing member (no ts) */
    {
        const char *no_ts =
            "{\"v\":1,\"spk\":\"3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08=\","
            "\"spk_sig\":\"2TtmiNYcVcX0QpegeLuAnOCzNChs4L6z2iEu9TuuoprjZa8c5UL"
            "Qtph1UWWTcrweXqs61iLEX0o2xqTVPW6HBg==\",\"opks\":["
            "\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\","
            "\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\","
            "\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\","
            "\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\","
            "\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\","
            "\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\","
            "\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\","
            "\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"]}";
        CHECK(!dtn_store_valid_prekeys(no_ts, strlen(no_ts)));
    }
    /* v != 1 */
    {
        char bad[2100];
        snprintf(bad, sizeof(bad), "%s", VALID_PREKEYS);
        memcpy(strstr(bad, "\"v\":1"), "\"v\":2", 5);
        CHECK(!dtn_store_valid_prekeys(bad, strlen(bad)));
    }
    /* opks with 7 entries (below the 8 floor) */
    {
        char bad[2100];
        const char *opk =
            "\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",";
        int n = snprintf(bad, sizeof(bad),
                         "{\"v\":1,\"spk\":\"3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrf"
                         "x+FG+IK08=\",\"spk_sig\":\"aa\",\"ts\":5,\"opks\":[");
        for (int i = 0; i < 7; i++) n += snprintf(bad + n, sizeof(bad) - n, "%s", opk);
        snprintf(bad + n - 1, sizeof(bad) - n + 1, "]}");
        CHECK(!dtn_store_valid_prekeys(bad, strlen(bad)));
    }
    /* spk not Base64-of-32 */
    {
        char bad[2100];
        snprintf(bad, sizeof(bad),
                 "{\"v\":1,\"spk\":\"c2hvcnQ=\",\"spk_sig\":\"aa\",\"ts\":5,"
                 "\"opks\":[\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"]}");
        CHECK(!dtn_store_valid_prekeys(bad, strlen(bad)));
    }
    /* unknown members are ignored (§15.4) */
    {
        char okk[2100];
        snprintf(okk, sizeof(okk),
                 "{\"v\":1,\"future_member\":{\"x\":1},"
                 "\"spk\":\"3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08=\","
                 "\"spk_sig\":\"2TtmiNYcVcX0QpegeLuAnOCzNChs4L6z2iEu9TuuoprjZa"
                 "8c5ULQtph1UWWTcrweXqs61iLEX0o2xqTVPW6HBg==\",\"ts\":17910720"
                 "00,\"opks\":[");
        const char *opk =
            "\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",";
        int n = (int)strlen(okk);
        for (int i = 0; i < 8; i++) {
            n += snprintf(okk + n, sizeof(okk) - (size_t)n, "%s", opk);
        }
        snprintf(okk + n - 1, sizeof(okk) - (size_t)n + 1, "]}");
        CHECK(dtn_store_valid_prekeys(okk, strlen(okk)));
    }
    /* syntax error */
    CHECK(!dtn_store_valid_prekeys("{\"v\":1,", 7));
}
