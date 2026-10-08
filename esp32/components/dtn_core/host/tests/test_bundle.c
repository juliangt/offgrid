/* test_bundle.c — P3.2 BPv7 profile-codec conformance for the C side: every
 * vector from tests/vectors/bundle/vectors.json (via the GENERATED header
 * bundle_vectors.h), the §3.1 relay operation's in-place byte contract, the
 * fail-closed truncation/single-bit-flip properties, the EID shape rules
 * and the CRC-16/X.25 catalogue value.
 *
 * The header route is the Go<->C interop contract: the PDUs below were
 * ENCODED in Go and must be reproduced here, byte for byte — the vectors'
 * parse verdicts (accept, reject-with-code, hop rewrite) must match too.
 * Regenerate the header with:
 *   cd node && go test ./internal/bundle -run TestVectorsStable -regen
 */
#include "harness.h"

#include "dtn_bundle.h"
#include "dtn_cbor.h"
#include "dtn_cbor_writer.h"
#include "bundle_vectors.h"

#include <stdio.h>
#include <string.h>

static void test_crc16(void)
{
    T_BEGIN("bundle: CRC-16/X.25 catalogue value (\"123456789\" -> 0x906E)");
    CHECK_EQ_INT((int)dtn_bundle_crc16((const uint8_t *)"123456789", 9), 0x906E);
}

/* test_cross_implementation_byte_identity — the issue's "byte-identical
 * encodings Go<->C" gate (§11 row c): every encode vector is built from its
 * constructor inputs and must equal the committed Go-encoded PDU bytes; the
 * parse_accept fields/bundle_ids, the parse_reject codes and the hop_rewrite
 * outputs must match on both sides too. */
static void test_cross_implementation_byte_identity(void)
{
    char label[128];
    int enc_ok = 0, acc_ok = 0, rej_ok = 0, hop_ok = 0;

    for (size_t i = 0; i < sizeof(BUNDLE_ENC_VECS) / sizeof(BUNDLE_ENC_VECS[0]); i++) {
        const dtn_bundle_enc_vec *v = &BUNDLE_ENC_VECS[i];
        snprintf(label, sizeof(label), "bundle: byte identity, encode vector \"%s\"", v->name);
        T_BEGIN(label);
        dtn_bundle b;
        int rc;
        if (v->kind == 0) {
            rc = dtn_bundle_mail(v->envelope, v->envelope_len,
                                 v->created_unix_ms, v->ttl_s, &b);
        } else {
            rc = dtn_bundle_mgmt(v->src_eid, v->dst_eid,
                                 v->created_unix_ms, v->ttl_s, v->seq,
                                 v->inner, v->inner_len, &b);
        }
        CHECK_EQ_INT(rc, DTN_BUNDLE_OK);
        b.hop = v->hop;
        uint8_t out[1024];
        size_t n = 0;
        rc = dtn_bundle_encode(&b, out, sizeof(out), &n);
        CHECK_EQ_INT(rc, DTN_BUNDLE_OK);
        CHECK_EQ_INT((int)n, (int)v->pdu_len);
        CHECK(memcmp(out, v->expect_pdu, n) == 0);
        if (rc == DTN_BUNDLE_OK && n == v->pdu_len && memcmp(out, v->expect_pdu, n) == 0) enc_ok++;
    }

    for (size_t i = 0; i < sizeof(BUNDLE_ACC_VECS) / sizeof(BUNDLE_ACC_VECS[0]); i++) {
        const dtn_bundle_acc_vec *v = &BUNDLE_ACC_VECS[i];
        snprintf(label, sizeof(label), "bundle: byte identity, parse_accept vector \"%s\"", v->name);
        T_BEGIN(label);
        dtn_bundle b;
        int rc = dtn_bundle_parse(v->pdu, v->pdu_len, v->now_unix_s, &b);
        CHECK_EQ_INT(rc, DTN_BUNDLE_OK);
        if (rc != DTN_BUNDLE_OK) continue;
        char dest[96], src[96], rpt[96];
        CHECK_EQ_INT(dtn_bundle_eid_format(&b.destination, dest, sizeof(dest)), DTN_BUNDLE_OK);
        CHECK_EQ_INT(dtn_bundle_eid_format(&b.source, src, sizeof(src)), DTN_BUNDLE_OK);
        CHECK_EQ_INT(dtn_bundle_eid_format(&b.report_to, rpt, sizeof(rpt)), DTN_BUNDLE_OK);
        CHECK_STR(dest, v->destination);
        CHECK_STR(src, v->source);
        CHECK_STR(rpt, v->report_to);
        CHECK_EQ_INT((long long)b.creation_dtn_ms, (long long)v->creation_dtn_ms);
        CHECK_EQ_INT((long long)b.sequence, (long long)v->sequence);
        CHECK_EQ_INT((long long)b.lifetime, (long long)v->lifetime);
        CHECK_EQ_INT((int)b.hop, v->hop);
        CHECK_EQ_INT((int)b.payload_len, (int)v->payload_len);
        CHECK(memcmp(b.payload, v->payload, v->payload_len) == 0);
        CHECK_EQ_INT((int)b.primary_len, v->primary_len);
        CHECK_EQ_INT((int)b.content_off, v->content_off);
        uint8_t id[DTN_BUNDLE_ID_LEN];
        CHECK_EQ_INT(dtn_bundle_id(v->pdu, v->pdu_len, id), DTN_BUNDLE_OK);
        CHECK(memcmp(id, v->bundle_id, DTN_BUNDLE_ID_LEN) == 0);
        acc_ok++;
    }

    for (size_t i = 0; i < sizeof(BUNDLE_REJ_VECS) / sizeof(BUNDLE_REJ_VECS[0]); i++) {
        const dtn_bundle_rej_vec *v = &BUNDLE_REJ_VECS[i];
        snprintf(label, sizeof(label), "bundle: byte identity, parse_reject vector \"%s\" -> %s",
                 v->name, v->expect_code);
        T_BEGIN(label);
        dtn_bundle b;
        int rc = dtn_bundle_parse(v->pdu, v->pdu_len, v->now_unix_s, &b);
        CHECK_STR(dtn_bundle_strerr(rc), v->expect_code);
        if (strcmp(dtn_bundle_strerr(rc), v->expect_code) == 0) rej_ok++;
    }

    for (size_t i = 0; i < sizeof(BUNDLE_HOP_VECS) / sizeof(BUNDLE_HOP_VECS[0]); i++) {
        const dtn_bundle_hop_vec *v = &BUNDLE_HOP_VECS[i];
        snprintf(label, sizeof(label), "bundle: byte identity, hop_rewrite vector \"%s\"", v->name);
        T_BEGIN(label);
        uint8_t out[1024];
        size_t n = 0;
        int rc = dtn_bundle_rewrite_hop(v->in, v->in_len, out, sizeof(out), &n);
        if (v->expect_code != NULL) {
            CHECK_STR(dtn_bundle_strerr(rc), v->expect_code);
            if (strcmp(dtn_bundle_strerr(rc), v->expect_code) == 0) hop_ok++;
        } else {
            CHECK_EQ_INT(rc, DTN_BUNDLE_OK);
            CHECK_EQ_INT((int)n, (int)v->out_len);
            CHECK(memcmp(out, v->out, n) == 0);
            if (rc == DTN_BUNDLE_OK && n == v->out_len && memcmp(out, v->out, n) == 0) hop_ok++;
        }
    }

    T_BEGIN("bundle: cross-implementation byte identity evidence");
    CHECK_EQ_INT(enc_ok, (int)(sizeof(BUNDLE_ENC_VECS) / sizeof(BUNDLE_ENC_VECS[0])));
    CHECK_EQ_INT(acc_ok, (int)(sizeof(BUNDLE_ACC_VECS) / sizeof(BUNDLE_ACC_VECS[0])));
    CHECK_EQ_INT(rej_ok, (int)(sizeof(BUNDLE_REJ_VECS) / sizeof(BUNDLE_REJ_VECS[0])));
    CHECK_EQ_INT(hop_ok, (int)(sizeof(BUNDLE_HOP_VECS) / sizeof(BUNDLE_HOP_VECS[0])));
    printf("    byte identity: %d encode + %d accept + %d reject + %d hop vectors matched on the C side\n",
           enc_ok, acc_ok, rej_ok, hop_ok);
}

/* The §3.1 relay operation over a real vector PDU: exactly three bytes may
 * change (the hop octet and the payload block's two CRC value bytes); the
 * primary block and the payload bytes are untouched; identity (P-7) is
 * stable; the limit refuses. */
static void test_relay_replay(void)
{
    const dtn_bundle_enc_vec *v = &BUNDLE_ENC_VECS[0]; /* mail_small_envelope, hop 0 */
    const uint8_t *pdu = v->expect_pdu;
    size_t len = v->pdu_len;

    T_BEGIN("bundle: hop rewrite touches exactly [hop, crcHi, crcLo]");
    dtn_bundle b;
    CHECK_EQ_INT(dtn_bundle_parse(pdu, len, BUNDLE_VEC_NOW, &b), DTN_BUNDLE_OK);
    uint8_t out[1024];
    size_t n = 0;
    CHECK_EQ_INT(dtn_bundle_rewrite_hop(pdu, len, out, sizeof(out), &n), DTN_BUNDLE_OK);
    CHECK_EQ_INT((int)n, (int)len);
    int changed[8];
    int changed_n = 0;
    for (size_t i = 0; i < len; i++) {
        if (pdu[i] != out[i] && changed_n < 8) changed[changed_n++] = (int)i;
    }
    CHECK_EQ_INT(changed_n, 3);
    CHECK_EQ_INT(changed[0], (int)b.content_off);
    CHECK_EQ_INT(changed[1], (int)len - 2);
    CHECK_EQ_INT(changed[2], (int)len - 1);
    CHECK(memcmp(out, pdu, b.content_off) == 0); /* primary block untouched */

    T_BEGIN("bundle: rewritten PDU parses at hop+1 with identical identity and payload");
    dtn_bundle rb;
    CHECK_EQ_INT(dtn_bundle_parse(out, n, BUNDLE_VEC_NOW, &rb), DTN_BUNDLE_OK);
    CHECK_EQ_INT((int)rb.hop, (int)b.hop + 1);
    CHECK_EQ_INT((int)rb.payload_len, (int)b.payload_len);
    CHECK(memcmp(rb.payload, b.payload, b.payload_len) == 0);
    uint8_t id_before[DTN_BUNDLE_ID_LEN], id_after[DTN_BUNDLE_ID_LEN];
    CHECK_EQ_INT(dtn_bundle_id(pdu, len, id_before), DTN_BUNDLE_OK);
    CHECK_EQ_INT(dtn_bundle_id(out, n, id_after), DTN_BUNDLE_OK);
    CHECK(memcmp(id_before, id_after, DTN_BUNDLE_ID_LEN) == 0);

    T_BEGIN("bundle: hop 7 refuses the rewrite but still parses (delivery, not relay)");
    dtn_bundle b7;
    CHECK_EQ_INT(dtn_bundle_mail(v->envelope, v->envelope_len,
                                 v->created_unix_ms, v->ttl_s, &b7), DTN_BUNDLE_OK);
    b7.hop = 7;
    uint8_t pdu7[1024];
    size_t n7 = 0;
    CHECK_EQ_INT(dtn_bundle_encode(&b7, pdu7, sizeof(pdu7), &n7), DTN_BUNDLE_OK);
    CHECK_STR(dtn_bundle_strerr(DTN_BUNDLE_ERR_HOP), "hop_limit");
    CHECK_EQ_INT(dtn_bundle_rewrite_hop(pdu7, n7, out, sizeof(out), &n), DTN_BUNDLE_ERR_HOP);
    dtn_bundle p7;
    CHECK_EQ_INT(dtn_bundle_parse(pdu7, n7, BUNDLE_VEC_NOW, &p7), DTN_BUNDLE_OK);
    CHECK_EQ_INT((int)p7.hop, 7);

    T_BEGIN("bundle: hop 8 is unparseable (encode refuses it too)");
    b7.hop = 8;
    CHECK_EQ_INT(dtn_bundle_encode(&b7, pdu7, sizeof(pdu7), &n7), DTN_BUNDLE_ERR_HOP);
    CHECK_EQ_INT(dtn_bundle_rewrite_hop(v->expect_pdu, 4, out, sizeof(out), &n),
                 DTN_BUNDLE_ERR_TRUNCATED);
}

/* Fail-closed properties over a whole canonical PDU (the C half of Go's
 * TestMalformedFailClosed): every proper prefix and every single-bit flip
 * must be rejected. */
static void test_malformed_property(void)
{
    const dtn_bundle_enc_vec *v = &BUNDLE_ENC_VECS[0];
    const uint8_t *pdu = v->expect_pdu;
    size_t len = v->pdu_len;
    dtn_bundle b;

    T_BEGIN("bundle: every truncation of a canonical PDU is rejected");
    for (size_t i = 0; i < len; i++) {
        if (dtn_bundle_parse(pdu, i, BUNDLE_VEC_NOW, &b) == DTN_BUNDLE_OK) {
            CHECK(0); /* prints the failing position via the harness */
            printf("    truncation accepted at %zu of %zu bytes\n", i, len);
            return;
        }
    }
    CHECK(1);

    T_BEGIN("bundle: every single-bit flip of a canonical PDU is rejected");
    uint8_t mut[1024];
    for (size_t i = 0; i < len; i++) {
        for (int bit = 0; bit < 8; bit++) {
            memcpy(mut, pdu, len);
            mut[i] ^= (uint8_t)(1 << bit);
            if (dtn_bundle_parse(mut, len, BUNDLE_VEC_NOW, &b) == DTN_BUNDLE_OK) {
                CHECK(0);
                printf("    bit %d of byte %zu flipped -> accepted\n", bit, i);
                return;
            }
        }
    }
    CHECK(1);
}

static void test_eid_shapes(void)
{
    struct { const char *uri; } round[] = {
        {"dtn:none"},
        {"dtn:og-mail"},
        {"dtn://og-admin/"},
        {"dtn://og.0123456789abcdef/"},
    };
    T_BEGIN("bundle: EID parse/format round-trips over the profile shapes");
    for (size_t i = 0; i < sizeof(round) / sizeof(round[0]); i++) {
        dtn_bundle_eid e;
        char out[80];
        CHECK_EQ_INT(dtn_bundle_eid_parse(round[i].uri, &e), DTN_BUNDLE_OK);
        CHECK_EQ_INT(dtn_bundle_eid_format(&e, out, sizeof(out)), DTN_BUNDLE_OK);
        CHECK_STR(out, round[i].uri);
    }

    T_BEGIN("bundle: EID parsing rejects every deviation");
    const char *bad[] = {
        "", "dtn:", "dtn:none/", "dtn://", "dtn://og.0123456789abcdef",
        "dtn://og.0123456789abcdef//", "dtn://OG.0123456789ABCDEF/",
        "dtn://og.0123/", "dtn://og.zzzzzzzzzzzzzzzz/", "dtn:OG-MAIL",
        "dtn:-og-mail", "dtn:og.mail", "http://og.0123456789abcdef/", "ipn:1.1",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        dtn_bundle_eid e;
        if (dtn_bundle_eid_parse(bad[i], &e) == DTN_BUNDLE_OK) {
            CHECK(0);
            printf("    EID \"%s\" accepted\n", bad[i]);
            return;
        }
    }
    CHECK(1);
}

static void test_api_misuse(void)
{
    const dtn_bundle_enc_vec *v = &BUNDLE_ENC_VECS[0];
    dtn_bundle b;
    uint8_t out[1024];
    size_t n = 0;

    T_BEGIN("bundle: constructors and encode refuse invalid arguments");
    CHECK_EQ_INT(dtn_bundle_mail(NULL, 0, v->created_unix_ms, v->ttl_s, &b),
                 DTN_BUNDLE_ERR_EMPTY_PAYLOAD);
    CHECK_EQ_INT(dtn_bundle_mail(v->envelope, v->envelope_len, 0, v->ttl_s, &b),
                 DTN_BUNDLE_ERR_ARGUMENT); /* before the DTN epoch */
    CHECK_EQ_INT(dtn_bundle_mgmt("dtn:og-mail", "dtn:og-mail", v->created_unix_ms,
                                 v->ttl_s, 1, v->envelope, v->envelope_len, &b),
                 DTN_BUNDLE_ERR_EID); /* a group EID cannot be the source */
    CHECK_EQ_INT(dtn_bundle_mgmt("dtn://og.0123456789abcdef/", "dtn:none",
                                 v->created_unix_ms, v->ttl_s, 1,
                                 v->envelope, v->envelope_len, &b),
                 DTN_BUNDLE_ERR_EID); /* anonymous destination */

    T_BEGIN("bundle: encode re-validates every profile rule");
    CHECK_EQ_INT(dtn_bundle_mail(v->envelope, v->envelope_len,
                                 v->created_unix_ms, v->ttl_s, &b), DTN_BUNDLE_OK);
    b.lifetime = 0;
    CHECK_EQ_INT(dtn_bundle_encode(&b, out, sizeof(out), &n), DTN_BUNDLE_ERR_LIFETIME);
    b.lifetime = v->ttl_s;
    b.hop = 8;
    CHECK_EQ_INT(dtn_bundle_encode(&b, out, sizeof(out), &n), DTN_BUNDLE_ERR_HOP);
    b.hop = 0;
    b.report_to.none = 0;
    strcpy(b.report_to.authority, "og.0123456789abcdef");
    CHECK_EQ_INT(dtn_bundle_encode(&b, out, sizeof(out), &n), DTN_BUNDLE_ERR_EID);
    b.report_to.none = 1;
    b.destination.none = 1; /* anonymous destination */
    CHECK_EQ_INT(dtn_bundle_encode(&b, out, sizeof(out), &n), DTN_BUNDLE_ERR_EID);

    T_BEGIN("bundle: the receiver's skew rule is admission's, with the 300 s ceiling");
    CHECK_EQ_INT(dtn_bundle_parse(v->expect_pdu, v->pdu_len,
                                  v->created_unix_ms / 1000 - 301, &b),
                 DTN_BUNDLE_ERR_SKEW);
    CHECK_EQ_INT(dtn_bundle_parse(v->expect_pdu, v->pdu_len,
                                  v->created_unix_ms / 1000 - 300, &b),
                 DTN_BUNDLE_OK);

    T_BEGIN("bundle: the stable failure-code vocabulary matches Go");
    CHECK_STR(dtn_bundle_strerr(DTN_BUNDLE_OK), "ok");
    CHECK_STR(dtn_bundle_strerr(DTN_BUNDLE_ERR_TRUNCATED), "truncated");
    CHECK_STR(dtn_bundle_strerr(DTN_BUNDLE_ERR_STRUCTURE), "bad_structure");
    CHECK_STR(dtn_bundle_strerr(DTN_BUNDLE_ERR_VERSION), "bad_version");
    CHECK_STR(dtn_bundle_strerr(DTN_BUNDLE_ERR_FLAGS), "bad_flags");
    CHECK_STR(dtn_bundle_strerr(DTN_BUNDLE_ERR_CRC), "bad_crc");
    CHECK_STR(dtn_bundle_strerr(DTN_BUNDLE_ERR_BLOCK_COUNT), "block_count");
    CHECK_STR(dtn_bundle_strerr(DTN_BUNDLE_ERR_BLOCK_TYPE), "unknown_block");
    CHECK_STR(dtn_bundle_strerr(DTN_BUNDLE_ERR_NON_CANONICAL), "non_canonical");
    CHECK_STR(dtn_bundle_strerr(DTN_BUNDLE_ERR_EID), "bad_eid");
    CHECK_STR(dtn_bundle_strerr(DTN_BUNDLE_ERR_HOP), "hop_limit");
    CHECK_STR(dtn_bundle_strerr(DTN_BUNDLE_ERR_SKEW), "future_skew");
    CHECK_STR(dtn_bundle_strerr(DTN_BUNDLE_ERR_LIFETIME), "bad_lifetime");
    CHECK_STR(dtn_bundle_strerr(DTN_BUNDLE_ERR_EMPTY_PAYLOAD), "empty_payload");
    CHECK_STR(dtn_bundle_strerr(DTN_BUNDLE_ERR_NOSPACE), "no_space");
    CHECK_STR(dtn_bundle_strerr(DTN_BUNDLE_ERR_ARGUMENT), "bad_argument");
    CHECK_STR(dtn_bundle_strerr(99), "?");
}

void test_bundle(void)
{
    test_crc16();
    test_cross_implementation_byte_identity();
    test_relay_replay();
    test_malformed_property();
    test_eid_shapes();
    test_api_misuse();
}
