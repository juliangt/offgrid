/* test_nodeid.c — P3.1 role-cert conformance for the C side: every vector
 * from tests/vectors/nodeid/vectors.json (via the GENERATED header
 * nodeid_vectors.h), the merge rules over the same pairs Go merges, the
 * identity primitives, the CBOR reader's fail-closed classes, the SHA-256
 * catalogue values and the RFC 8032 §7.1/§7.2 Ed25519 sanity vectors.
 *
 * The header route is the Go<->C interop contract: the certs below were
 * SIGNED in Go and must verify here, byte for byte. Regenerate the header
 * with:  cd node && go test ./internal/nodeid -run TestVectorsStable -regen
 */
#include "harness.h"

#include "dtn_cbor.h"
#include "dtn_ed25519.h"
#include "dtn_nodeid.h"
#include "dtn_rolecert.h"
#include "dtn_sha256.h"
#include "dtn_tweetnacl.h"
#include "nodeid_vectors.h"

#include <stdio.h>
#include <string.h>

static uint8_t hexval(char c)
{
    if (c >= '0' && c <= '9') return (uint8_t)(c - '0');
    if (c >= 'a' && c <= 'f') return (uint8_t)(c - 'a' + 10);
    return (uint8_t)(c - 'A' + 10);
}

static size_t hexbytes(const char *hex, uint8_t *out, size_t cap)
{
    size_t n = strlen(hex) / 2;
    if (n > cap) return 0;
    for (size_t i = 0; i < n; i++) {
        out[i] = (uint8_t)((hexval(hex[2 * i]) << 4) | hexval(hex[2 * i + 1]));
    }
    return n;
}

static const char *verify_code_name(int code)
{
    switch (code) {
    case DTN_ROLECERT_OK: return "ok";
    case DTN_ROLECERT_EXPIRED: return "expired";
    case DTN_ROLECERT_ERR_COSE: return "cose_shape";
    case DTN_ROLECERT_ERR_PROTECTED: return "bad_protected";
    case DTN_ROLECERT_ERR_ANCHOR_FP: return "wrong_anchor_fp";
    case DTN_ROLECERT_ERR_SIGNATURE: return "bad_signature";
    case DTN_ROLECERT_ERR_SCHEMA: return "cert_schema";
    case DTN_ROLECERT_ERR_VERSION: return "bad_version";
    case DTN_ROLECERT_ERR_ROLE: return "unknown_role";
    case DTN_ROLECERT_ERR_LEVEL: return "level_roles_mismatch";
    case DTN_ROLECERT_ERR_BINDING: return "bad_eid_binding";
    case DTN_ROLECERT_ERR_TS: return "bad_ts";
    case DTN_ROLECERT_ERR_SEQ: return "bad_seq";
    default: return "?";
    }
}

static const char *state_name(int state)
{
    switch (state) {
    case DTN_ROLECERT_STATE_ABSENT: return "absent";
    case DTN_ROLECERT_STATE_AUTHORITY: return "authority";
    case DTN_ROLECERT_STATE_REVOKED: return "revoked";
    case DTN_ROLECERT_STATE_EXPIRED: return "expired";
    default: return "?";
    }
}

static void test_sha256(void)
{
    uint8_t digest[32];
    uint8_t expect[32];

    T_BEGIN("sha256: FIPS 180-4 catalogue vectors (\"abc\", empty, 56-byte boundary)");
    dtn_sha256((const uint8_t *)"", 0, digest);
    CHECK(hexbytes("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", expect, 32) == 32);
    CHECK(memcmp(digest, expect, 32) == 0);
    dtn_sha256((const uint8_t *)"abc", 3, digest);
    CHECK(hexbytes("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", expect, 32) == 32);
    CHECK(memcmp(digest, expect, 32) == 0);
    /* the 56-byte length-padding boundary (exactly one fill block) */
    dtn_sha256((const uint8_t *)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, digest);
    CHECK(hexbytes("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", expect, 32) == 32);
    CHECK(memcmp(digest, expect, 32) == 0);

    T_BEGIN("sha256: anchor fingerprint equals the Go-derived vector");
    {
        uint8_t fp[DTN_NODEID_FP_LEN];
        dtn_nodeid_fingerprint(NODEID_ANCHOR_PUB, fp);
        CHECK(memcmp(fp, NODEID_ANCHOR_FP, DTN_NODEID_FP_LEN) == 0);
    }
}

static void test_ed25519(void)
{
    /* RFC 8032 §7.1: empty message — exercises the verify path's n == 0
     * SHA-512 handling (the tweetnacl trim's deviation 3). */
    static const char pk_hex[] = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    static const char sig_hex[] =
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
    /* RFC 8032 §7.2: one-byte message 0x72. */
    static const char pk2_hex[] = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
    static const char sig2_hex[] =
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00";
    static const char msg2[] = {0x72};
    uint8_t pk[32], sig[64];
    uint8_t pk2[32], sig2[64];

    T_BEGIN("ed25519: RFC 8032 §7.1 empty-message vector (tweetnacl trim)");
    CHECK(hexbytes(pk_hex, pk, 32) == 32);
    CHECK(hexbytes(sig_hex, sig, 64) == 64);
    CHECK_EQ_INT(dtn_ed25519_verify(pk, sig, (const uint8_t *)"", 0), DTN_ED25519_OK);
    sig[0] ^= 0x01;
    CHECK_EQ_INT(dtn_ed25519_verify(pk, sig, (const uint8_t *)"", 0), DTN_ED25519_ERR_SIGNATURE);

    T_BEGIN("ed25519: RFC 8032 §7.2 one-byte vector + oversize rejection");
    CHECK(hexbytes(pk2_hex, pk2, 32) == 32);
    CHECK(hexbytes(sig2_hex, sig2, 64) == 64);
    CHECK_EQ_INT(dtn_ed25519_verify(pk2, sig2, (const uint8_t *)msg2, 1), DTN_ED25519_OK);
    CHECK_EQ_INT(dtn_ed25519_verify(pk2, sig2, (const uint8_t *)msg2, 1), DTN_ED25519_OK);
    {
        static uint8_t big[DTN_ED25519_MAX_MSG + 1];
        memset(big, 'A', sizeof(big));
        CHECK_EQ_INT(dtn_ed25519_verify(pk2, sig2, big, sizeof(big)), DTN_ED25519_ERR_TOO_LONG);
    }
}

static void test_cbor_reader(void)
{
    T_BEGIN("cbor: canonical values (uints, ints, bstr/tstr views, null, map/array)");
    {
        static const uint8_t buf[] = {
            0xa2,             /* map(2) */
            0x01, 0x27,       /* 1: -8 */
            0x04, 0x48, 1, 2, 3, 4, 5, 6, 7, 8, /* 4: bstr(8) */
        };
        dtn_cbor r;
        size_t pairs;
        uint64_t k;
        int64_t v;
        const uint8_t *b;
        size_t bl;
        dtn_cbor_init(&r, buf, sizeof(buf));
        CHECK_EQ_INT(dtn_cbor_map(&r, &pairs), DTN_CBOR_OK);
        CHECK_EQ_INT((int)pairs, 2);
        CHECK_EQ_INT(dtn_cbor_uint(&r, &k), DTN_CBOR_OK);
        CHECK_EQ_INT((int)k, 1);
        CHECK_EQ_INT(dtn_cbor_int(&r, &v), DTN_CBOR_OK);
        CHECK_EQ_INT((int)v, -8);
        CHECK_EQ_INT(dtn_cbor_uint(&r, &k), DTN_CBOR_OK);
        CHECK_EQ_INT((int)k, 4);
        CHECK_EQ_INT(dtn_cbor_bstr(&r, &b, &bl), DTN_CBOR_OK);
        CHECK_EQ_INT((int)bl, 8);
        CHECK_EQ_INT(b[7], 8);
        dtn_cbor_pop(&r);
        CHECK_EQ_INT(dtn_cbor_done(&r), 1);
    }

    T_BEGIN("cbor: fail-closed classes (truncated, indefinite, reserved, depth, trailing, utf8)");
    {
        /* truncated bstr */
        static const uint8_t trunc[] = {0x58, 0x20, 0x01};
        dtn_cbor r;
        const uint8_t *p;
        size_t l;
        dtn_cbor_init(&r, trunc, sizeof(trunc));
        CHECK_EQ_INT(dtn_cbor_bstr(&r, &p, &l), DTN_CBOR_ERR_TRUNCATED);

        /* indefinite-length map (0xbf) */
        static const uint8_t indef[] = {0xbf, 0xff};
        dtn_cbor_init(&r, indef, sizeof(indef));
        size_t n;
        CHECK_EQ_INT(dtn_cbor_map(&r, &n), DTN_CBOR_ERR_INDEFINITE);

        /* reserved additional info 28-30 */
        static const uint8_t resv[] = {0x1d, 0x00};
        dtn_cbor_init(&r, resv, sizeof(resv));
        uint64_t u;
        CHECK_EQ_INT(dtn_cbor_uint(&r, &u), DTN_CBOR_ERR_RESERVED);

        /* wrong type; then the SAME buffer reads fine as a tstr from a
         * fresh reader (after any error the cursor is unspecified) */
        static const uint8_t tstrm[] = {0x64, 'e', 'd', 'g', 'e'};
        dtn_cbor_init(&r, tstrm, sizeof(tstrm));
        const char *s;
        size_t sl;
        CHECK_EQ_INT(dtn_cbor_bstr(&r, &p, &l), DTN_CBOR_ERR_TYPE);
        dtn_cbor_init(&r, tstrm, sizeof(tstrm));
        CHECK_EQ_INT(dtn_cbor_tstr(&r, &s, &sl), DTN_CBOR_OK);
        CHECK_EQ_INT((int)sl, 4);
        CHECK(memcmp(s, "edge", 4) == 0);

        /* trailing garbage after a top-level value */
        static const uint8_t trail[] = {0x01, 0x02};
        dtn_cbor_init(&r, trail, sizeof(trail));
        uint64_t tv;
        CHECK_EQ_INT(dtn_cbor_uint(&r, &tv), DTN_CBOR_OK);
        CHECK_EQ_INT(dtn_cbor_done(&r), 0);

        /* invalid UTF-8 in a tstr */
        static const uint8_t badutf[] = {0x62, 0xc3, 0x28};
        dtn_cbor_init(&r, badutf, sizeof(badutf));
        CHECK_EQ_INT(dtn_cbor_tstr(&r, &s, &sl), DTN_CBOR_ERR_UTF8);

        /* depth overrun: 33 nested arrays */
        static uint8_t deep[64];
        for (int i = 0; i < 33; i++) deep[i] = 0x81; /* array(1) */
        deep[33] = 0x00;
        dtn_cbor_init(&r, deep, 34);
        CHECK_EQ_INT(dtn_cbor_skip(&r), DTN_CBOR_ERR_DEPTH);

        /* null */
        static const uint8_t nul[] = {0xf6};
        dtn_cbor_init(&r, nul, sizeof(nul));
        CHECK_EQ_INT(dtn_cbor_null(&r), DTN_CBOR_OK);
        CHECK_EQ_INT(dtn_cbor_done(&r), 1);
    }
}

static void test_identity(void)
{
    uint8_t got_fp[DTN_NODEID_FP_LEN];
    uint8_t key[32], key2[32];
    char eid[DTN_NODEID_EID_MAX + 1];

    T_BEGIN("nodeid: EID derivation matches the shared vectors");
    CHECK(hexbytes(NODEID_EID_NODE_KEY_HEX, key, 32) == 32);
    dtn_nodeid_fingerprint(key, got_fp);
    dtn_nodeid_eid(got_fp, eid);
    CHECK_STR(eid, NODEID_EID_NODE_EID);
    {
        uint8_t want_fp[DTN_NODEID_FP_LEN];
        CHECK(hexbytes(NODEID_EID_NODE_FP_HEX, want_fp, DTN_NODEID_FP_LEN) == DTN_NODEID_FP_LEN);
        CHECK(memcmp(want_fp, got_fp, DTN_NODEID_FP_LEN) == 0);
    }
    CHECK_EQ_INT(dtn_nodeid_eid_binding(key, NODEID_EID_NODE_EID), 0);

    T_BEGIN("nodeid: binding + EID parsing reject every deviation");
    CHECK(hexbytes(NODEID_EID_NODE2_KEY_HEX, key2, 32) == 32);
    /* node2's key against the node's EID: exactly the forged-cert case */
    CHECK_EQ_INT(dtn_nodeid_eid_binding(key2, NODEID_EID_NODE_EID) != 0, 1);
    CHECK_EQ_INT(dtn_nodeid_eid_fingerprint("", got_fp) != 0, 1);
    CHECK_EQ_INT(dtn_nodeid_eid_fingerprint("dtn://og.0123456789abcdef", got_fp) != 0, 1);
    CHECK_EQ_INT(dtn_nodeid_eid_fingerprint("dtn://og.0123456789ABCDEF/", got_fp) != 0, 1);
    CHECK_EQ_INT(dtn_nodeid_eid_fingerprint("dtn://og.0123456789abcdefg/", got_fp) != 0, 1);
    CHECK_EQ_INT(dtn_nodeid_eid_fingerprint("dtn://og.zzzzzzzzzzzzzzzz/", got_fp) != 0, 1);
    CHECK_EQ_INT(dtn_nodeid_eid_fingerprint(NODEID_EID_NODE_EID, got_fp), 0);
    (void)key2;
}

static void test_valid_cert(const uint8_t *anchor_pub)
{
    dtn_rolecert c;

    T_BEGIN("rolecert: the Go-signed valid cert verifies and its fields match");
    int rc = dtn_rolecert_verify(NODEID_VALID_CERT, sizeof(NODEID_VALID_CERT),
                                 anchor_pub, NODEID_VEC_NOW, &c);
    CHECK_EQ_INT(rc, DTN_ROLECERT_OK);
    CHECK_STR(c.eid, NODEID_EID_NODE_EID);
    {
        uint8_t key[32];
        CHECK(hexbytes(NODEID_EID_NODE_KEY_HEX, key, 32) == 32);
        CHECK(memcmp(c.node_key, key, 32) == 0);
    }
    CHECK_EQ_INT((int)c.role_count, 2);
    CHECK_EQ_INT(dtn_rolecert_has_role(&c, "edge"), 1);
    CHECK_EQ_INT(dtn_rolecert_has_role(&c, "relay"), 1);
    CHECK_EQ_INT(dtn_rolecert_has_role(&c, "manager"), 0);
    CHECK_EQ_INT((int)c.level, 1);
    CHECK_EQ_INT((int)c.seq, 1);
    CHECK_EQ_INT((int)c.issued_ts, (int)(NODEID_VEC_NOW - 3600));
    CHECK_EQ_INT(dtn_rolecert_expired(&c, NODEID_VEC_NOW), 0);
}

static void test_negative_vectors(const uint8_t *anchor_pub)
{
    char label[128];

    for (size_t i = 0; i < sizeof(NODEID_NEG_VECS) / sizeof(NODEID_NEG_VECS[0]); i++) {
        const dtn_nodeid_neg_vec *v = &NODEID_NEG_VECS[i];
        snprintf(label, sizeof(label), "rolecert: negative vector \"%s\" -> %s",
                 v->name, v->expect_code);
        T_BEGIN(label);
        dtn_rolecert c;
        int rc = dtn_rolecert_verify(v->cose, v->len, anchor_pub, NODEID_VEC_NOW, &c);
        CHECK_STR(verify_code_name(rc), v->expect_code);
    }
}

static void test_merge_vectors(const uint8_t *anchor_pub)
{
    char label[128];

    for (size_t i = 0; i < sizeof(NODEID_MERGE_VECS) / sizeof(NODEID_MERGE_VECS[0]); i++) {
        const dtn_nodeid_merge_vec *v = &NODEID_MERGE_VECS[i];
        snprintf(label, sizeof(label), "merge: vector \"%s\"", v->name);
        T_BEGIN(label);
        dtn_rolecert_cache cache;
        dtn_rolecert_merge_status st;
        dtn_rolecert_cache_init(&cache);
        CHECK_EQ_INT(dtn_rolecert_cache_merge(&cache, v->cached, v->cached_len,
                                              anchor_pub, NODEID_VEC_NOW, &st),
                     DTN_ROLECERT_OK);
        CHECK_EQ_INT(st.outcome, DTN_ROLECERT_MERGE_REPLACED);
        CHECK_EQ_INT(dtn_rolecert_cache_merge(&cache, v->next, v->next_len,
                                              anchor_pub, NODEID_VEC_NOW, &st),
                     DTN_ROLECERT_OK);
        CHECK_EQ_INT(st.outcome, v->expect);
        CHECK_EQ_INT(st.revoked, v->expect_revoked);
        CHECK_EQ_INT((int)cache.conflicts, v->expect == DTN_ROLECERT_MERGE_CONFLICT_KEPT ? 1 : 0);
        CHECK_EQ_INT((int)cache.stale_dropped, v->expect == DTN_ROLECERT_MERGE_STALE_DROPPED ? 1 : 0);
        if (v->expect_revoked) {
            const dtn_rolecert *eff = NULL;
            dtn_rolecert cert;
            CHECK_EQ_INT(dtn_rolecert_verify(v->next, v->next_len, anchor_pub, NODEID_VEC_NOW, &cert),
                         DTN_ROLECERT_OK);
            CHECK_EQ_INT(dtn_rolecert_cache_effective(&cache, cert.eid, NODEID_VEC_NOW, &eff),
                         DTN_ROLECERT_STATE_REVOKED);
            CHECK(eff != NULL && eff->role_count == 0);
        }
    }
}

static void test_cache_states(const uint8_t *anchor_pub)
{
    T_BEGIN("merge: expiry is absence; redelivery is UNCHANGED; invalid touches nothing");
    dtn_rolecert_cache cache;
    dtn_rolecert_merge_status st;
    dtn_rolecert_cache_init(&cache);

    /* byte-identical redelivery at the same seq */
    CHECK_EQ_INT(dtn_rolecert_cache_merge(&cache, NODEID_VALID_CERT, sizeof(NODEID_VALID_CERT),
                                          anchor_pub, NODEID_VEC_NOW, &st),
                 DTN_ROLECERT_OK);
    CHECK_EQ_INT(st.outcome, DTN_ROLECERT_MERGE_REPLACED);
    CHECK_EQ_INT(dtn_rolecert_cache_merge(&cache, NODEID_VALID_CERT, sizeof(NODEID_VALID_CERT),
                                          anchor_pub, NODEID_VEC_NOW, &st),
                 DTN_ROLECERT_OK);
    CHECK_EQ_INT(st.outcome, DTN_ROLECERT_MERGE_UNCHANGED);
    CHECK_EQ_INT((int)cache.conflicts, 0);

    /* states at the wall clock and after expiry */
    const dtn_rolecert *eff = NULL;
    CHECK_EQ_INT(dtn_rolecert_cache_effective(&cache, NODEID_EID_NODE_EID, NODEID_VEC_NOW, &eff),
                 DTN_ROLECERT_STATE_AUTHORITY);
    CHECK_STR(state_name(DTN_ROLECERT_STATE_AUTHORITY), "authority");
    CHECK_EQ_INT(dtn_rolecert_cache_effective(&cache, NODEID_EID_NODE_EID, NODEID_VEC_NOW + 91 * 86400, &eff),
                 DTN_ROLECERT_STATE_EXPIRED);
    CHECK_STR(state_name(DTN_ROLECERT_STATE_EXPIRED), "expired");
    CHECK_EQ_INT(dtn_rolecert_cache_effective(&cache, NODEID_EID_NODE2_EID, NODEID_VEC_NOW, &eff),
                 DTN_ROLECERT_STATE_ABSENT);
    CHECK_STR(state_name(DTN_ROLECERT_STATE_ABSENT), "absent");

    /* garbage never touches state or counters */
    static const uint8_t junk[] = {0x84, 0x00};
    CHECK_EQ_INT(dtn_rolecert_cache_merge(&cache, junk, sizeof(junk), anchor_pub, NODEID_VEC_NOW, &st),
                 DTN_ROLECERT_OK);
    CHECK_EQ_INT(st.outcome, DTN_ROLECERT_MERGE_INVALID);
    CHECK_EQ_INT((int)cache.conflicts, 0);
    CHECK_EQ_INT((int)cache.stale_dropped, 0);
    CHECK_EQ_INT(dtn_rolecert_cache_effective(&cache, NODEID_EID_NODE_EID, NODEID_VEC_NOW, &eff),
                 DTN_ROLECERT_STATE_AUTHORITY);

    /* the expired vector merges as EXPIRED_DROPPED and stores nothing */
    const dtn_nodeid_neg_vec *nv = NULL;
    for (size_t i = 0; i < sizeof(NODEID_NEG_VECS) / sizeof(NODEID_NEG_VECS[0]); i++) {
        if (strcmp(NODEID_NEG_VECS[i].name, "expired") == 0) nv = &NODEID_NEG_VECS[i];
    }
    CHECK(nv != NULL);
    CHECK_EQ_INT(dtn_rolecert_cache_merge(&cache, nv->cose, nv->len, anchor_pub, NODEID_VEC_NOW, &st),
                 DTN_ROLECERT_OK);
    CHECK_EQ_INT(st.outcome, DTN_ROLECERT_MERGE_EXPIRED_DROPPED);
    CHECK_EQ_INT((int)cache.used, 1); /* only the valid cert slot */
}

static void test_nodeid_store(void)
{
    T_BEGIN("nodeid store: HAL seam round-trip through the RAM reference");
    dtn_nodeid_ram_store ram;
    dtn_nodeid_store v;
    uint8_t key[32], loaded[32], fp[DTN_NODEID_FP_LEN];
    uint8_t cert[256];
    size_t cert_len = 0;

    CHECK(hexbytes(NODEID_EID_NODE_KEY_HEX, key, 32) == 32);
    dtn_nodeid_ram_store_init(&ram);
    dtn_nodeid_ram_vtable(&ram, &v);

    /* nothing provisioned yet: self-fingerprint fails loudly */
    CHECK_EQ_INT(dtn_nodeid_self_fingerprint(&v, fp) != 0, 1);
    CHECK_EQ_INT(v.load_cert(v.ctx, cert, sizeof(cert), &cert_len) != 0, 1);

    /* provision: seed + cert land through the vtable */
    CHECK_EQ_INT(v.save_key(v.ctx, key), 0);
    CHECK_EQ_INT(v.save_cert(v.ctx, NODEID_VALID_CERT, sizeof(NODEID_VALID_CERT)), 0);
    CHECK_EQ_INT(v.load_key(v.ctx, loaded), 0);
    CHECK(memcmp(loaded, key, 32) == 0);
    CHECK_EQ_INT(v.load_cert(v.ctx, cert, sizeof(cert), &cert_len), 0);
    CHECK_EQ_INT((int)cert_len, (int)sizeof(NODEID_VALID_CERT));
    CHECK(memcmp(cert, NODEID_VALID_CERT, sizeof(NODEID_VALID_CERT)) == 0);
    CHECK_EQ_INT(dtn_nodeid_self_fingerprint(&v, fp), 0);
    CHECK(memcmp(fp, NODEID_ANCHOR_FP, DTN_NODEID_FP_LEN) != 0); /* node != anchor */
    {
        uint8_t want_fp[DTN_NODEID_FP_LEN];
        char eid[DTN_NODEID_EID_MAX + 1];
        dtn_nodeid_fingerprint(key, want_fp);
        dtn_nodeid_eid(want_fp, eid);
        CHECK_STR(eid, NODEID_EID_NODE_EID);
    }
}

void test_nodeid(void)
{
    test_sha256();
    test_ed25519();
    test_cbor_reader();
    test_identity();
    test_valid_cert(NODEID_ANCHOR_PUB);
    test_negative_vectors(NODEID_ANCHOR_PUB);
    test_merge_vectors(NODEID_ANCHOR_PUB);
    test_cache_states(NODEID_ANCHOR_PUB);
    test_nodeid_store();
}
