/* test_sync.c — §10.4 processing order, fail-closed semantics and the error
 * precedence of the Go reference (node/internal/api/handlers.go). */
#include "harness.h"

#include "dtn_sync.h"

#include <stdlib.h>
#include <string.h>

#define NOW 1759500000

#define FIX_ID "d375c17f54525e1816e5f2c01da100e17176c38fd016ea07acb5d3077eb6444f"
#define FIX_HINT "9f3ab02c1d77e4c1"
#define FIX_PAYLOAD                                                \
    "f46MqdLy8TaHj3lnjcYvHnOuAU8lrXD/nDHUzwGAW/5rQERh00/2ez0ZkfsZz6yc2FpGq2uk" \
    "rJYxb/P0OQPt6vbAt4I3TKcA21aBVxCxjX4ZZZA23cub/SQusRHDZzjPDmI3HQj6ZpTbEnt"  \
    "NfCKagXtQY/MCjvusFuP24DZVGxRhZ0K6l1KKsV0fZ5MOgg+QfFheegNat7plIFMf1Y0TuQ"  \
    "rii+JffAfgGh1vAWRr3OvAxWyRbH04Ofw/UBrKZLdevwAcCUcn7mgYcCrXZvSFlHavFH84P"  \
    "yk2egL0mnPXubm9iMVQOraXcklUzgYVbGlme8w+0yZrDNE="

/* ---- recording sink ---- */
typedef struct {
    int begins, commits, aborts;
    int puts;
    int absorbed_total;
    int fail_put_at;    /* 0 = never; n = fail the n-th put */
    int absorb_at;      /* 0 = never; n = the n-th put reports dedup */
    int fail_commit;
    int rolled_back;    /* set by abort (the store truncates to the mark) */
} rec_sink;

static int rs_begin(void *ud)
{
    ((rec_sink *)ud)->begins++;
    return 0;
}

static int rs_put(void *ud, const dtn_envelope *e, int *absorbed)
{
    rec_sink *rs = ud;
    (void)e;
    rs->puts++;
    if (rs->fail_put_at && rs->puts == rs->fail_put_at) {
        return -1;
    }
    *absorbed = (rs->absorb_at && rs->puts == rs->absorb_at);
    if (*absorbed) rs->absorbed_total++;
    return 0;
}

static int rs_commit(void *ud)
{
    rec_sink *rs = ud;
    rs->commits++;
    if (rs->fail_commit) return -1;
    return 0;
}

static void rs_abort(void *ud)
{
    ((rec_sink *)ud)->aborts++;
    ((rec_sink *)ud)->rolled_back = 1;
}

static const dtn_sync_sink REC_SINK = { NULL, rs_begin, rs_put, rs_commit,
                                       rs_abort };

static char known_store[DTN_KNOWN_IDS_MAX][DTN_ID_LEN + 1];

static void run(dtn_sync *s, rec_sink *rs, const char *body, bool budget_ok)
{
    dtn_known_ids k = { known_store, DTN_KNOWN_IDS_MAX, 0 };
    memset(rs, 0, sizeof(*rs));
    dtn_sync_init(s, NOW, &REC_SINK, &k);
    s->sink.ud = rs;
    dtn_sync_feed(s, body, strlen(body));
    s->verdict = dtn_sync_finish(s, budget_ok);
}

/* build a valid envelope JSON with a fresh id */
static const char *env_json(int v, long long created)
{
    static char buf[1024];
    snprintf(buf, sizeof(buf),
             "{\"v\":%d,\"id\":\"%s\",\"dest_hint\":\"%s\",\"created_at\":%lld,"
             "\"ttl\":604800,\"payload\":\"%s\"}",
             v, FIX_ID, FIX_HINT, created, FIX_PAYLOAD);
    return buf;
}

void test_sync(void)
{
    dtn_sync s;
    rec_sink rs;

    T_BEGIN("sync: §10.4 happy path — push + pull members resolve");
    run(&s, &rs,
        "{\"known_ids\":[\"d375c17f54525e1816e5f2c01da100e17176c38fd016ea07a"
        "cb5d3077eb6444f\"],\"push_envelopes\":["
        "{\"v\":1,\"id\":\"d375c17f54525e1816e5f2c01da100e17176c38fd016ea07a"
        "cb5d3077eb6444f\",\"dest_hint\":\"9f3ab02c1d77e4c1\",\"created_at\":"
        "1759500000,\"ttl\":604800,\"payload\":\"" FIX_PAYLOAD "\"}],\"limit\":50}",
        true);
    CHECK_EQ_INT(s.verdict, DTN_SYNC_OK);
    CHECK_EQ_INT(rs.begins, 1);
    CHECK_EQ_INT(rs.puts, 1);
    CHECK_EQ_INT(rs.commits, 1);
    CHECK_EQ_INT(rs.aborts, 0);
    CHECK_EQ_INT(dtn_sync_pushed(&s), 1);
    CHECK_EQ_INT(dtn_sync_absorbed(&s), 0);
    CHECK_EQ_INT(dtn_sync_limit(&s), 50);
    CHECK_EQ_INT(s.known->count, 1);

    T_BEGIN("sync: pull-only costs nothing and skips the batch machinery");
    run(&s, &rs, "{\"known_ids\":[],\"push_envelopes\":[]}", true);
    CHECK_EQ_INT(s.verdict, DTN_SYNC_OK);
    CHECK_EQ_INT(rs.begins, 0);
    CHECK_EQ_INT(rs.puts, 0);

    T_BEGIN("sync: fail-closed — invalid envelope rejects whole request");
    run(&s, &rs,
        "{\"push_envelopes\":["
        "{\"v\":1,\"id\":\"d375c17f54525e1816e5f2c01da100e17176c38fd016ea07a"
        "cb5d3077eb6444f\",\"dest_hint\":\"9f3ab02c1d77e4c1\",\"created_at\":"
        "1759500000,\"ttl\":604800,\"payload\":\"" FIX_PAYLOAD "\"},"
        "{\"v\":3,\"id\":\"d375c17f54525e1816e5f2c01da100e17176c38fd016ea07a"
        "cb5d3077eb6444f\",\"dest_hint\":\"9f3ab02c1d77e4c1\",\"created_at\":"
        "1759500000,\"ttl\":604800,\"payload\":\"" FIX_PAYLOAD "\"}]}",
        true);
    CHECK_EQ_INT(s.verdict, DTN_SYNC_ERR_INVALID_ENVELOPE);
    CHECK_EQ_INT(rs.aborts, 1); /* batch rolled back: nothing stored */
    CHECK_EQ_INT(rs.commits, 0);

    T_BEGIN("sync: error precedence — bad limit beats too-many-pushes");
    {
        /* 101 envelopes ≈ 75 KB: heap, never the test stack */
        char *body = malloc(96000);
        strcpy(body, "{\"limit\":0,\"push_envelopes\":[");
        for (int i = 0; i < 101; i++) {
            strcat(body, env_json(1, NOW));
            if (i < 100) strcat(body, ",");
        }
        strcat(body, "]}");
        run(&s, &rs, body, true);
        CHECK_EQ_INT(s.verdict, DTN_SYNC_ERR_INVALID_LIMIT);
        free(body);
    }

    T_BEGIN("sync: 101 envelopes → 400 too_many_envelopes");
    {
        char *body = malloc(96000);
        strcpy(body, "{\"push_envelopes\":[");
        for (int i = 0; i < 101; i++) {
            strcat(body, env_json(1, NOW));
            if (i < 100) strcat(body, ",");
        }
        strcat(body, "]}");
        run(&s, &rs, body, true);
        CHECK_EQ_INT(s.verdict, DTN_SYNC_ERR_TOO_MANY_PUSH);
        CHECK_EQ_INT(rs.commits, 0);
        free(body);
    }

    T_BEGIN("sync: exactly 100 envelopes with budget → OK");
    {
        char *body = malloc(96000);
        strcpy(body, "{\"push_envelopes\":[");
        for (int i = 0; i < 100; i++) {
            strcat(body, env_json(1, NOW));
            if (i < 99) strcat(body, ",");
        }
        strcat(body, "]}");
        run(&s, &rs, body, true);
        CHECK_EQ_INT(s.verdict, DTN_SYNC_OK);
        CHECK_EQ_INT(dtn_sync_pushed(&s), 100);
        free(body);
    }

    T_BEGIN("sync: known_ids count beats format (Go check order)");
    {
        /* 501 entries, entry #3 malformed: Go checks len>500 FIRST */
        char body[40000];
        strcpy(body, "{\"known_ids\":[");
        for (int i = 0; i < 501; i++) {
            if (i == 3) {
                strcat(body, "\"NOTHEX\"");
            } else {
                strcat(body, "\"d375c17f54525e1816e5f2c01da100e17176c38fd016ea07acb5d3077eb6444f\"");
            }
            if (i < 500) strcat(body, ",");
        }
        strcat(body, "]}");
        run(&s, &rs, body, true);
        CHECK_EQ_INT(s.verdict, DTN_SYNC_ERR_TOO_MANY_KNOWN);
    }

    T_BEGIN("sync: malformed known id → 400 invalid_known_id");
    run(&s, &rs,
        "{\"known_ids\":[\"ZZZ\"]}", true);
    CHECK_EQ_INT(s.verdict, DTN_SYNC_ERR_INVALID_KNOWN);

    T_BEGIN("sync: null element in known_ids → invalid_known_id (\"\" in Go)");
    run(&s, &rs, "{\"known_ids\":[null]}", true);
    CHECK_EQ_INT(s.verdict, DTN_SYNC_ERR_INVALID_KNOWN);

    T_BEGIN("sync: budget refusal beats envelope validity (§10.1 order)");
    run(&s, &rs,
        "{\"push_envelopes\":[{\"v\":9,\"id\":\"x\"}]}", false);
    CHECK_EQ_INT(s.verdict, DTN_SYNC_ERR_RATE_LIMITED);

    T_BEGIN("sync: body over 1 MiB → 413 body_too_large, top precedence");
    {
        size_t need = (size_t)DTN_BODY_MAX_BYTES + 64;
        char *body = malloc(need + 1);
        memset(body, ' ', need); /* whitespace padding inside the top object */
        body[0] = '{';
        body[need - 1] = '}';
        body[need] = '\0';
        dtn_known_ids k = { known_store, DTN_KNOWN_IDS_MAX, 0 };
        memset(&rs, 0, sizeof(rs));
        dtn_sync_init(&s, NOW, &REC_SINK, &k);
        s.sink.ud = &rs;
        /* feed in chunks like the adapter */
        for (size_t off = 0; off < need; off += 4096) {
            size_t n = need - off < 4096 ? need - off : 4096;
            if (dtn_sync_feed(&s, body + off, n) != DTN_JSONFEED_OK) break;
        }
        s.verdict = dtn_sync_finish(&s, true);
        CHECK_EQ_INT(s.verdict, DTN_SYNC_ERR_BODY_TOO_LARGE);
        free(body);
    }

    T_BEGIN("sync: valid JSON closed under 1 MiB then megabytes of garbage "
            "→ still OK (decoder reads one value)");
    {
        size_t tail = 2u * 1024 * 1024;
        char *body = malloc(tail + 64);
        memset(body, 'x', tail);
        body[tail] = '\0';
        memcpy(body, env_json(1, NOW), strlen(env_json(1, NOW)));
        run(&s, &rs, body, true);
        CHECK_EQ_INT(s.verdict, DTN_SYNC_OK);
        free(body);
    }

    T_BEGIN("sync: chunked feeding preserves semantics");
    {
        const char *body =
            "{\"push_envelopes\":[" /* cut mid-envelope, mid-string below */
            "{\"v\":1,\"id\":\"d375c17f54525e1816e5f2c01da10"
            "0e17176c38fd016ea07acb5d3077eb6444f\",\"dest_hint\":\"9f3ab02c1d77"
            "e4c1\",\"created_at\":1759500000,\"ttl\":604800,\"payload\":\"" FIX_PAYLOAD "\"}]}";
        dtn_known_ids k = { known_store, DTN_KNOWN_IDS_MAX, 0 };
        memset(&rs, 0, sizeof(rs));
        dtn_sync_init(&s, NOW, &REC_SINK, &k);
        s.sink.ud = &rs;
        size_t len = strlen(body);
        for (size_t off = 0; off < len; off += 7) {
            size_t n = len - off < 7 ? len - off : 7;
            dtn_json_feed_result r = dtn_sync_feed(&s, body + off, n);
            if (r == DTN_JSONFEED_DONE) break;
            CHECK(r == DTN_JSONFEED_OK);
        }
        s.verdict = dtn_sync_finish(&s, true);
        CHECK_EQ_INT(s.verdict, DTN_SYNC_OK);
        CHECK_EQ_INT(dtn_sync_pushed(&s), 1);
    }

    T_BEGIN("sync: duplicate known_ids are harmless (§10.4)");
    run(&s, &rs,
        "{\"known_ids\":[\"" FIX_ID "\",\"" FIX_ID "\"]}", true);
    CHECK_EQ_INT(s.verdict, DTN_SYNC_OK);
    CHECK_EQ_INT(s.known->count, 2);

    T_BEGIN("sync: limit absent → 50; limit null → absent; limit 0/201 → 400");
    run(&s, &rs, "{}", true);
    CHECK_EQ_INT(s.verdict, DTN_SYNC_OK);
    CHECK_EQ_INT(dtn_sync_limit(&s), 50);
    run(&s, &rs, "{\"limit\":null}", true);
    CHECK_EQ_INT(dtn_sync_limit(&s), 50);
    run(&s, &rs, "{\"limit\":0}", true);
    CHECK_EQ_INT(s.verdict, DTN_SYNC_ERR_INVALID_LIMIT);
    run(&s, &rs, "{\"limit\":201}", true);
    CHECK_EQ_INT(s.verdict, DTN_SYNC_ERR_INVALID_LIMIT);
    run(&s, &rs, "{\"limit\":200}", true);
    CHECK_EQ_INT(s.verdict, DTN_SYNC_OK);
    run(&s, &rs, "{\"limit\":1.5}", true);
    CHECK_EQ_INT(s.verdict, DTN_SYNC_ERR_JSON);
    run(&s, &rs, "{\"limit\":\"50\"}", true);
    CHECK_EQ_INT(s.verdict, DTN_SYNC_ERR_JSON);

    T_BEGIN("sync: v2 envelope with meta.orig_v=1 admitted; meta dropped");
    {
        char body[1024];
        snprintf(body, sizeof(body),
                 "{\"push_envelopes\":[{\"v\":2,\"meta\":{\"orig_v\":1,"
                 "\"future\":9},\"id\":\"%s\",\"dest_hint\":\"%s\","
                 "\"created_at\":%lld,\"ttl\":604800,\"payload\":\"%s\"}]}",
                 FIX_ID, FIX_HINT, (long long)NOW, FIX_PAYLOAD);
        run(&s, &rs, body, true);
        CHECK_EQ_INT(s.verdict, DTN_SYNC_OK);
        CHECK_EQ_INT(rs.puts, 1);
    }

    T_BEGIN("sync: v1 with meta → invalid_envelope (§15.3)");
    {
        char body[1024];
        snprintf(body, sizeof(body),
                 "{\"push_envelopes\":[{\"v\":1,\"meta\":{},\"id\":\"%s\","
                 "\"dest_hint\":\"%s\",\"created_at\":%lld,\"ttl\":604800,"
                 "\"payload\":\"%s\"}]}",
                 FIX_ID, FIX_HINT, (long long)NOW, FIX_PAYLOAD);
        run(&s, &rs, body, true);
        CHECK_EQ_INT(s.verdict, DTN_SYNC_ERR_INVALID_ENVELOPE);
    }

    T_BEGIN("sync: meta non-object / orig_v wrong type → invalid_envelope "
            "(validation-time, Go RawMessage)");
    run(&s, &rs,
        "{\"push_envelopes\":[{\"v\":2,\"meta\":5,\"id\":\"x\"}]}", true);
    CHECK_EQ_INT(s.verdict, DTN_SYNC_ERR_INVALID_ENVELOPE);
    run(&s, &rs,
        "{\"push_envelopes\":[{\"v\":2,\"meta\":{\"orig_v\":\"1\"},\"id\":\"x\"}]}",
        true);
    CHECK_EQ_INT(s.verdict, DTN_SYNC_ERR_INVALID_ENVELOPE);
    run(&s, &rs,
        "{\"push_envelopes\":[{\"v\":2,\"meta\":{\"orig_v\":null},\"id\":\"x\"}]}",
        true);
    CHECK_EQ_INT(s.verdict, DTN_SYNC_ERR_INVALID_ENVELOPE);
    run(&s, &rs,
        "{\"push_envelopes\":[{\"v\":2,\"meta\":{\"orig_v\":1.5},\"id\":\"x\"}]}",
        true);
    CHECK_EQ_INT(s.verdict, DTN_SYNC_ERR_INVALID_ENVELOPE);
    run(&s, &rs,
        "{\"push_envelopes\":[{\"v\":2,\"meta\":{\"orig_v\":2},\"id\":\"x\"}]}",
        true);
    CHECK_EQ_INT(s.verdict, DTN_SYNC_ERR_INVALID_ENVELOPE);

    T_BEGIN("sync: null v decodes to zero → invalid_envelope (Go no-op)");
    run(&s, &rs,
        "{\"push_envelopes\":[{\"v\":null,\"id\":\"x\"}]}", true);
    CHECK_EQ_INT(s.verdict, DTN_SYNC_ERR_INVALID_ENVELOPE);

    T_BEGIN("sync: float v is a DECODE failure → invalid_json");
    run(&s, &rs, "{\"push_envelopes\":[{\"v\":1.0,\"id\":\"x\"}]}", true);
    CHECK_EQ_INT(s.verdict, DTN_SYNC_ERR_JSON);

    T_BEGIN("sync: non-object envelope element → invalid_json");
    run(&s, &rs, "{\"push_envelopes\":[\"x\"]}", true);
    CHECK_EQ_INT(s.verdict, DTN_SYNC_ERR_JSON);

    T_BEGIN("sync: storage failure on put → 507 and rollback");
    {
        dtn_known_ids k = { known_store, DTN_KNOWN_IDS_MAX, 0 };
        memset(&rs, 0, sizeof(rs));
        rs.fail_put_at = 1;
        dtn_sync_init(&s, NOW, &REC_SINK, &k);
        s.sink.ud = &rs;
        const char *body = env_json(1, NOW);
        char wrap[1200];
        snprintf(wrap, sizeof(wrap), "{\"push_envelopes\":[%s]}", body);
        dtn_sync_feed(&s, wrap, strlen(wrap));
        s.verdict = dtn_sync_finish(&s, true);
        CHECK_EQ_INT(s.verdict, DTN_SYNC_ERR_STORAGE);
        CHECK_EQ_INT(rs.aborts, 1);
    }

    T_BEGIN("sync: commit failure → 507 with batch abort");
    {
        dtn_known_ids k = { known_store, DTN_KNOWN_IDS_MAX, 0 };
        memset(&rs, 0, sizeof(rs));
        rs.fail_commit = 1;
        dtn_sync_init(&s, NOW, &REC_SINK, &k);
        s.sink.ud = &rs;
        char wrap[1200];
        snprintf(wrap, sizeof(wrap), "{\"push_envelopes\":[%s]}",
                 env_json(1, NOW));
        dtn_sync_feed(&s, wrap, strlen(wrap));
        s.verdict = dtn_sync_finish(&s, true);
        CHECK_EQ_INT(s.verdict, DTN_SYNC_ERR_STORAGE);
        CHECK_EQ_INT(rs.aborts, 1);
    }

    T_BEGIN("sync: duplicate push_envelopes key — last array replaces first");
    {
        char body[3000];
        snprintf(body, sizeof(body),
                 "{\"push_envelopes\":[%s],\"push_envelopes\":[%s]}",
                 env_json(1, NOW), env_json(1, NOW + 1));
        run(&s, &rs, body, true);
        CHECK_EQ_INT(s.verdict, DTN_SYNC_OK);
        CHECK_EQ_INT(dtn_sync_pushed(&s), 1); /* only the LAST array counts */
        CHECK_EQ_INT(rs.puts, 2); /* first array's put rolled back via abort */
        CHECK_EQ_INT(rs.aborts, 1);
    }

    T_BEGIN("sync: empty body and non-object top → invalid_json");
    run(&s, &rs, "", true);
    CHECK_EQ_INT(s.verdict, DTN_SYNC_ERR_JSON);
    run(&s, &rs, "[1,2]", true);
    CHECK_EQ_INT(s.verdict, DTN_SYNC_ERR_JSON);
    run(&s, &rs, "{\"broken\":", true);
    CHECK_EQ_INT(s.verdict, DTN_SYNC_ERR_JSON);

    T_BEGIN("sync: dedup absorption is reported for the §10.7 counters");
    {
        dtn_known_ids k = { known_store, DTN_KNOWN_IDS_MAX, 0 };
        memset(&rs, 0, sizeof(rs));
        rs.absorb_at = 2; /* the second identical put is absorbed */
        dtn_sync_init(&s, NOW, &REC_SINK, &k);
        s.sink.ud = &rs;
        char wrap[3000];
        snprintf(wrap, sizeof(wrap),
                 "{\"push_envelopes\":[%s,%s]}", env_json(1, NOW),
                 env_json(1, NOW));
        dtn_sync_feed(&s, wrap, strlen(wrap));
        s.verdict = dtn_sync_finish(&s, true);
        CHECK_EQ_INT(s.verdict, DTN_SYNC_OK);
        CHECK_EQ_INT(dtn_sync_pushed(&s), 2);
        CHECK_EQ_INT(dtn_sync_absorbed(&s), 1);
    }
}
