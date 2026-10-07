/* test_envelope.c — §10.5/§15.3 validation, fixture vectors, serialization. */
#include "harness.h"

#include "dtn_base64.h"
#include "dtn_envelope.h"

#include <stdio.h>
#include <string.h>

#define NOW 1759500000 /* the §3.2 fixture timestamp */

/* §3.2 — the spec's concrete valid envelope (synthetic deterministic
 * payload bytes). Pinned byte-for-byte by tests/sync_e2e.sh on the Go node
 * too; this is the shared fixture set. */
static const char *FIX_ID =
    "d375c17f54525e1816e5f2c01da100e17176c38fd016ea07acb5d3077eb6444f";
static const char *FIX_HINT = "9f3ab02c1d77e4c1";
static const char *FIX_PAYLOAD =
    "f46MqdLy8TaHj3lnjcYvHnOuAU8lrXD/nDHUzwGAW/5rQERh00/2ez0ZkfsZz6yc2FpGq2uk"
    "rJYxb/P0OQPt6vbAt4I3TKcA21aBVxCxjX4ZZZA23cub/SQusRHDZzjPDmI3HQj6ZpTbEnt"
    "NfCKagXtQY/MCjvusFuP24DZVGxRhZ0K6l1KKsV0fZ5MOgg+QfFheegNat7plIFMf1Y0TuQ"
    "rii+JffAfgGh1vAWRr3OvAxWyRbH04Ofw/UBrKZLdevwAcCUcn7mgYcCrXZvSFlHavFH84P"
    "yk2egL0mnPXubm9iMVQOraXcklUzgYVbGlme8w+0yZrDNE=";

static dtn_envelope fixture(void)
{
    dtn_envelope e;
    memset(&e, 0, sizeof(e));
    e.v = 1;
    memcpy(e.id, FIX_ID, DTN_ID_LEN);
    e.id[DTN_ID_LEN] = '\0';
    memcpy(e.dest_hint, FIX_HINT, DTN_DEST_HINT_LEN);
    e.dest_hint[DTN_DEST_HINT_LEN] = '\0';
    e.created_at = NOW;
    e.ttl = 604800;
    e.payload_len = strlen(FIX_PAYLOAD);
    memcpy(e.payload, FIX_PAYLOAD, e.payload_len + 1);
    return e;
}

static long b64len_for(size_t decoded)
{
    /* padded length of a decoded-size payload: 3→4 groups */
    size_t groups = (decoded + 2) / 3;
    return (long)(groups * 4);
}

static void fill_payload(dtn_envelope *e, size_t decoded, int valid_shape)
{
    /* 'A'*n with canonical padding in the final group; valid_shape=0 embeds
     * a non-alphabet char */
    size_t n = (size_t)b64len_for(decoded);
    memset(e->payload, 'A', n);
    e->payload[n] = '\0';
    size_t rem = decoded % 3;
    if (rem == 1) {
        e->payload[n - 1] = '=';
        e->payload[n - 2] = '=';
    } else if (rem == 2) {
        e->payload[n - 1] = '=';
    }
    if (!valid_shape && n > 4) e->payload[2] = '*';
    e->payload_len = n;
}

void test_envelope(void)
{
    T_BEGIN("envelope: §3.2 fixture validates (shared vector)");
    dtn_envelope e = fixture();
    CHECK_EQ_INT(dtn_envelope_validate(&e, NOW), DTN_ENV_OK);
    /* an envelope stays valid at any LATER clock (its deadline is checked
     * only on the serving side, never at admission — §10.5 bounds created_at
     * from above only) */
    CHECK_EQ_INT(dtn_envelope_validate(&e, NOW + 100000), DTN_ENV_OK);
    CHECK_EQ_INT(dtn_envelope_validate(&e, NOW + DTN_TTL_MAX), DTN_ENV_OK);
    /* and was NOT yet valid at an earlier clock (future-skew bound) */
    CHECK_EQ_INT(dtn_envelope_validate(&e, NOW - 1000), DTN_ENV_ERR_CREATED_AT);

    T_BEGIN("envelope: version set {1,2} admission (§15.3)");
    e.v = 2;
    CHECK_EQ_INT(dtn_envelope_validate(&e, NOW), DTN_ENV_OK); /* v2 native */
    e.v = 3;
    CHECK_EQ_INT(dtn_envelope_validate(&e, NOW), DTN_ENV_ERR_VERSION);
    e.v = 0;
    CHECK_EQ_INT(dtn_envelope_validate(&e, NOW), DTN_ENV_ERR_VERSION);

    T_BEGIN("envelope: meta absent on v1 (§15.3)");
    e = fixture();
    e.meta_flags = 1;
    CHECK_EQ_INT(dtn_envelope_validate(&e, NOW), DTN_ENV_ERR_META);

    T_BEGIN("envelope: v2 meta.orig_v must be 1 when present");
    e = fixture();
    e.v = 2;
    e.meta_flags = 1;
    CHECK_EQ_INT(dtn_envelope_validate(&e, NOW), DTN_ENV_OK); /* no orig_v */
    e.meta_orig_v_present = 1;
    e.meta_orig_v = 1;
    CHECK_EQ_INT(dtn_envelope_validate(&e, NOW), DTN_ENV_OK);
    e.meta_orig_v = 2;
    CHECK_EQ_INT(dtn_envelope_validate(&e, NOW), DTN_ENV_ERR_META);

    T_BEGIN("envelope: id regex ^[0-9a-f]{64}$");
    e = fixture();
    e.id[0] = 'D'; /* uppercase */
    CHECK_EQ_INT(dtn_envelope_validate(&e, NOW), DTN_ENV_ERR_ID);
    e = fixture();
    e.id[63] = '\0'; /* 63 chars */
    CHECK_EQ_INT(dtn_envelope_validate(&e, NOW), DTN_ENV_ERR_ID);
    e = fixture();
    e.id[63] = 'g';
    CHECK_EQ_INT(dtn_envelope_validate(&e, NOW), DTN_ENV_ERR_ID);

    T_BEGIN("envelope: dest_hint regex ^[0-9a-f]{16}$");
    e = fixture();
    e.dest_hint[15] = '\0';
    CHECK_EQ_INT(dtn_envelope_validate(&e, NOW), DTN_ENV_ERR_DEST_HINT);

    T_BEGIN("envelope: created_at > 0 and ≤ now+300 (§10.5)");
    e = fixture();
    e.created_at = 0;
    CHECK_EQ_INT(dtn_envelope_validate(&e, NOW), DTN_ENV_ERR_CREATED_AT);
    e.created_at = -5;
    CHECK_EQ_INT(dtn_envelope_validate(&e, NOW), DTN_ENV_ERR_CREATED_AT);
    e.created_at = NOW + 300;
    CHECK_EQ_INT(dtn_envelope_validate(&e, NOW), DTN_ENV_OK);
    e.created_at = NOW + 301;
    CHECK_EQ_INT(dtn_envelope_validate(&e, NOW), DTN_ENV_ERR_CREATED_AT);

    T_BEGIN("envelope: ttl range [3600, 2592000] (§8.1)");
    e = fixture();
    e.ttl = 3599;
    CHECK_EQ_INT(dtn_envelope_validate(&e, NOW), DTN_ENV_ERR_TTL);
    e.ttl = 3600;
    CHECK_EQ_INT(dtn_envelope_validate(&e, NOW), DTN_ENV_OK);
    e.ttl = 2592000;
    CHECK_EQ_INT(dtn_envelope_validate(&e, NOW), DTN_ENV_OK);
    e.ttl = 2592001;
    CHECK_EQ_INT(dtn_envelope_validate(&e, NOW), DTN_ENV_ERR_TTL);

    T_BEGIN("envelope: payload Base64 + decoded bounds [248,400] (§8.2)");
    e = fixture();
    fill_payload(&e, 248, 1);
    CHECK_EQ_INT(dtn_envelope_validate(&e, NOW), DTN_ENV_OK);
    fill_payload(&e, 400, 1);
    CHECK_EQ_INT(dtn_envelope_validate(&e, NOW), DTN_ENV_OK);
    fill_payload(&e, 247, 1);
    CHECK_EQ_INT(dtn_envelope_validate(&e, NOW), DTN_ENV_ERR_PAYLOAD);
    fill_payload(&e, 401, 1);
    CHECK_EQ_INT(dtn_envelope_validate(&e, NOW), DTN_ENV_ERR_PAYLOAD);
    fill_payload(&e, 300, 0); /* '*' is not standard alphabet */
    CHECK_EQ_INT(dtn_envelope_validate(&e, NOW), DTN_ENV_ERR_PAYLOAD);
    e = fixture();
    e.payload_len = 0; /* empty */
    CHECK_EQ_INT(dtn_envelope_validate(&e, NOW), DTN_ENV_ERR_PAYLOAD);

    T_BEGIN("envelope: payload rejects newline even around valid b64");
    e = fixture();
    e.payload_len = strlen(FIX_PAYLOAD);
    memcpy(e.payload, FIX_PAYLOAD, e.payload_len + 1);
    e.payload[3] = '\n';
    CHECK_EQ_INT(dtn_envelope_validate(&e, NOW), DTN_ENV_ERR_PAYLOAD);

    T_BEGIN("base64: canonical padding and trailing-bit strictness");
    {
        uint8_t out[16];
        /* "aGVsbG8=" = "hello" */
        CHECK_EQ_INT(dtn_base64_decode("aGVsbG8=", 8, out, sizeof(out)), 5);
        CHECK(memcmp(out, "hello", 5) == 0);
        CHECK_EQ_INT(dtn_base64_decode("aGVsbG8", 7, out, sizeof(out)),
                     -1); /* unpadded */
        CHECK_EQ_INT(dtn_base64_decode("aGVs\nG8=", 8, out, sizeof(out)),
                     -1); /* whitespace */
        CHECK_EQ_INT(dtn_base64_decode("aGVsbGo=", 8, out, sizeof(out)), 5);
        /* "aGR=" would decode 1 byte with non-zero trailing bits? 'R'→17,
         * 17 & 0x0F = 1 → non-canonical */
        CHECK_EQ_INT(dtn_base64_decode("aGR=", 4, out, sizeof(out)), -1);
        CHECK_EQ_INT(dtn_base64_decode("aA==", 4, out, sizeof(out)), 1);
        CHECK_EQ_INT(out[0], 'h');
        /* base64url alphabet rejected */
        CHECK_EQ_INT(dtn_base64_decode("a-b=", 4, out, sizeof(out)), -1);
    }

    T_BEGIN("envelope: serialization is the exact §5.2-fixed member order");
    e = fixture();
    char buf[1024];
    long n = dtn_envelope_write_json(buf, sizeof(buf), &e);
    CHECK(n > 0);
    /* expected: {"v":1,"id":..,"dest_hint":..,"created_at":..,"ttl":..,
     * "payload":..} */
    char want[1024];
    snprintf(want, sizeof(want),
             "{\"v\":1,\"id\":\"%s\",\"dest_hint\":\"%s\",\"created_at\":%lld,"
             "\"ttl\":604800,\"payload\":\"%s\"}",
             FIX_ID, FIX_HINT, (long long)NOW, FIX_PAYLOAD);
    CHECK_STR(buf, want);

    T_BEGIN("alias: ^[A-Za-z0-9_.-]{1,24}$ (§8.1)");
    CHECK(dtn_valid_alias("alice_77"));
    CHECK(dtn_valid_alias("a"));
    CHECK(dtn_valid_alias("A-b.c_9"));
    CHECK(!dtn_valid_alias(""));
    CHECK(!dtn_valid_alias(" HasSpace"));
    CHECK(!dtn_valid_alias("bad alias!"));
    CHECK(!dtn_valid_alias(
        "1234567890123456789012345")); /* 25 chars */
    CHECK(dtn_valid_alias("123456789012345678901234")); /* 24 chars */
}
