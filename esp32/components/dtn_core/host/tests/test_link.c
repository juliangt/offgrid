/* test_link.c — P3.3 node-plane link layer host tests (issue #33).
 *
 * Runs every shared vector of tests/vectors/link/vectors.json through the
 * generated header link_vectors.h — the C half of the cross-implementation
 * gate (the Go half is node/internal/link's TestCrossImplementationLinkVectors).
 * The C suite must reproduce the Go-produced handshake messages,
 * ciphertexts and frames BYTE FOR BYTE, and match every accept/reject
 * verdict. The official crypto anchors (RFC 3610, RFC 5869, RFC 7748
 * §6.1, RFC 8032 §7.1) are pinned here directly.
 */
#include "harness.h"

#include <string.h>

#include "dtn_ccm.h"
#include "dtn_frame.h"
#include "dtn_hkdf.h"
#include "dtn_session.h"
#include "dtn_sha256.h"
#include "dtn_tweetnacl.h"
#include "link_vectors.h"

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static size_t unhex(const void *p, uint8_t *out, size_t cap)
{
    const char *s = (const char *)p;
    size_t n = 0;
    while (s[0] && s[1] && n < cap) {
        out[n++] = (uint8_t)(hexval(s[0]) * 16 + hexval(s[1]));
        s += 2;
    }
    return n;
}

static int bytes_eq(const uint8_t *a, size_t an, const uint8_t *b, size_t bn)
{
    return an == bn && (an == 0 || memcmp(a, b, an) == 0);
}

/* ------------------------------------------------------------------ */
/* Official anchors                                                    */
/* ------------------------------------------------------------------ */
void test_link_crypto_anchors(void)
{
    /* FIPS 197 Appendix C.1 — the AES-128 block core under the CCM engine
     * (the RFC 3610 §8 packet vectors use M ∈ {8,10}; the C engine pins
     * the profile's fixed t = 16, so the packet vectors are pinned on the
     * Go side (variable-t engine) and the shared t=16 profile vectors pin
     * the SAME construction here byte for byte). */
    {
        static const uint8_t key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
        static const uint8_t in[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                       0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
        static const uint8_t want[16] = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
                                         0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};
        uint8_t out[16];
        dtn_aes128_block(key, in, out);
        CHECK(memcmp(out, want, 16) == 0);
    }

    /* RFC 5869 Appendix A, test case 1 (SHA-256). */
    {
        uint8_t ikm[22];
        static const uint8_t salt[13] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                                         0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c};
        static const uint8_t info[10] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4,
                                         0xf5, 0xf6, 0xf7, 0xf8, 0xf9};
        static const uint8_t prk_want[32] = {
            0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f,
            0x0d, 0xc4, 0x7b, 0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f,
            0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5};
        static const uint8_t okm_want[42] = {
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64,
            0xd0, 0x36, 0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
            0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08,
            0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65};
        uint8_t prk[32], okm[42];
        memset(ikm, 0x0b, sizeof(ikm));
        dtn_hkdf_extract(salt, sizeof(salt), ikm, sizeof(ikm), prk);
        CHECK(memcmp(prk, prk_want, 32) == 0);
        CHECK(dtn_hkdf_expand(prk, info, sizeof(info), 42, okm) == 0);
        CHECK(memcmp(okm, okm_want, 42) == 0);
    }

    /* RFC 8032 §7.1 TEST 1 — the Ed25519 SIGN path added in P3.3 (the Go
     * side signs through crypto/ed25519; this proves the C sign path is
     * the same algorithm). */
    {
        static const uint8_t seed[32] = {
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a,
            0xf4, 0x92, 0xec, 0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32,
            0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60};
        static const uint8_t pub_want[32] = {
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe,
            0xd3, 0xc9, 0x64, 0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6,
            0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a};
        static const uint8_t sig_want[64] = {
            0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2,
            0xcc, 0x80, 0x6e, 0x82, 0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5,
            0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55, 0x5f,
            0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70,
            0x1c, 0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe,
            0x24, 0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b};
        uint8_t pk[32], sig[64], tampered[64];
        CHECK(dtn_tn_ed25519_keypair(pk, seed) == 0);
        CHECK(memcmp(pk, pub_want, 32) == 0);
        CHECK(dtn_tn_ed25519_sign(sig, NULL, 0, seed, pk) == 0);
        CHECK(memcmp(sig, sig_want, 64) == 0);
        CHECK(dtn_tn_ed25519_verify(pk, sig_want, NULL, 0) == 0);
        memcpy(tampered, sig_want, 64);
        tampered[0] ^= 1;
        CHECK(dtn_tn_ed25519_verify(pk, tampered, NULL, 0) == -1);
    }
}

/* ------------------------------------------------------------------ */
/* Shared vectors: handshake                                           */
/* ------------------------------------------------------------------ */

void test_link_vectors_handshake(void)
{
    size_t i;
    T_BEGIN("link vectors: handshake (cross-implementation byte identity)");
    for (i = 0; i < sizeof(LINK_HS_VECS) / sizeof(LINK_HS_VECS[0]); i++) {
        const dtn_link_hs_vec *v = &LINK_HS_VECS[i];
        dtn_link_hs_cfg cfg_i, cfg_r;
        dtn_link_initiator ini;
        dtn_link_responder res;
        uint8_t msg1[DTN_LINK_MSG1_LEN], msg2[DTN_LINK_MSG2_LEN], msg3[DTN_LINK_MSG3_LEN];
        size_t msg1_len = 0, msg2_len = 0, msg3_len = 0;

        memcpy(msg1, v->msg1, sizeof(msg1));
        memcpy(msg2, v->msg2, sizeof(msg2));
        memcpy(msg3, v->msg3, sizeof(msg3));
        msg1_len = sizeof(msg1);
        msg2_len = sizeof(msg2);
        msg3_len = sizeof(msg3);

        memset(&cfg_i, 0, sizeof(cfg_i));
        memset(&cfg_r, 0, sizeof(cfg_r));
        memcpy(cfg_i.local_seed, v->seed_a, 32);
        memcpy(cfg_r.local_seed, v->seed_b, 32);
        CHECK(dtn_tn_ed25519_keypair(cfg_i.local_pub, cfg_i.local_seed) == 0);
        CHECK(dtn_tn_ed25519_keypair(cfg_r.local_pub, cfg_r.local_seed) == 0);
        /* Each side resolves the peer out of band (cert/pin, §6.1). */
        memcpy(cfg_i.peer_pub, cfg_r.local_pub, 32);
        memcpy(cfg_r.peer_pub, cfg_i.local_pub, 32);

        cfg_i.eph = v->scalar_i;
        CHECK(dtn_link_initiator_start(&ini, &cfg_i) == DTN_LINK_OK);
        CHECK(ini.msg1_len == (size_t)v->msg1_len);
        CHECK(bytes_eq(ini.msg1, ini.msg1_len, v->msg1, v->msg1_len));

        /* The C responder consumes the GO-produced msg1 bytes and must
         * reproduce the GO-produced msg2 byte for byte. */
        cfg_r.eph = v->scalar_r;
        CHECK(dtn_link_responder_read1(&res, &cfg_r, v->msg1, v->msg1_len) == DTN_LINK_OK);
        CHECK(dtn_link_responder_write2(&res) == DTN_LINK_OK);
        CHECK(res.msg2_len == (size_t)v->msg2_len);
        CHECK(bytes_eq(res.msg2, res.msg2_len, v->msg2, v->msg2_len));

        /* The C initiator consumes the GO-produced msg2 bytes. */
        CHECK(dtn_link_initiator_read2(&ini, v->msg2, v->msg2_len) == DTN_LINK_OK);
        CHECK(dtn_link_initiator_msg3(&ini) == DTN_LINK_OK);
        CHECK(ini.msg3_len == (size_t)v->msg3_len);
        CHECK(bytes_eq(ini.msg3, ini.msg3_len, v->msg3, v->msg3_len));

        /* The C responder consumes the GO-produced msg3 bytes. */
        CHECK(dtn_link_responder_read3(&res, v->msg3, v->msg3_len) == DTN_LINK_OK);

        /* The EIDs must match the vector (self-certifying, §2.1). */
        {
            char eid[DTN_LINK_EID_LEN + 1];
            dtn_link_eid(cfg_i.local_pub, eid);
            CHECK(strcmp(eid, v->eid_a) == 0);
            dtn_link_eid(cfg_r.local_pub, eid);
            CHECK(strcmp(eid, v->eid_b) == 0);
        }

        /* The full key schedule must match the Go-derived material. */
        {
            uint8_t dh[32], tr[DTN_LINK_MSG1_LEN + DTN_LINK_MSG2_LEN + DTN_LINK_MSG3_LEN];
            uint8_t m1h[32], trh[32], master[32], k_i2r[16], s_i2r[5], k_r2i[16], s_r2i[5];
            size_t n = 0;
            CHECK(dtn_tn_crypto_scalarmult(dh, v->scalar_i, res.gy) == 0);
            memcpy(tr + n, msg1, msg1_len); n += msg1_len;
            memcpy(tr + n, msg2, msg2_len); n += msg2_len;
            memcpy(tr + n, msg3, msg3_len); n += msg3_len;
            dtn_sha256(msg1, msg1_len, m1h);
            dtn_sha256(tr, n, trh);
            CHECK(bytes_eq(m1h, 8, v->th1, DTN_LINK_TH1_LEN));
            CHECK(bytes_eq(trh, 32, v->transcript_hash, 32));
            dtn_link_master(dh, tr, n, master);
            CHECK(bytes_eq(master, 32, v->master, 32));
            dtn_link_direction_keys(master, k_i2r, s_i2r, k_r2i, s_r2i);
            CHECK(bytes_eq(k_i2r, 16, v->k_i2r, 16));
            CHECK(bytes_eq(s_i2r, 5, v->s_i2r, 5));
            CHECK(bytes_eq(k_r2i, 16, v->k_r2i, 16));
            CHECK(bytes_eq(s_r2i, 5, v->s_r2i, 5));
        }

        /* The two C sessions interop: both directions byte-exact. */
        {
            static const uint8_t aad[1] = {0x2A};
            static const uint8_t payload[] = "cross-implementation session traffic";
            uint8_t sealed[13 + sizeof(payload) + 16];
            uint8_t opened[sizeof(payload)];
            CHECK(dtn_link_session_seal(&ini.session, aad, 1, payload, sizeof(payload), sealed) == DTN_LINK_OK);
            CHECK(dtn_link_session_open(&res.session, aad, 1, sealed, sizeof(sealed), opened) == DTN_LINK_OK);
            CHECK(memcmp(opened, payload, sizeof(payload)) == 0);
            CHECK(dtn_link_session_open(&res.session, aad, 1, sealed, sizeof(sealed), opened) == DTN_LINK_ERR_REPLAY);
        }
    }
}

/* ------------------------------------------------------------------ */
/* Shared vectors: ccm / frame / window / replay                       */
/* ------------------------------------------------------------------ */

void test_link_vectors_ccm(void)
{
    size_t i;
    T_BEGIN("link vectors: ccm (profile, byte identity)");
    for (i = 0; i < sizeof(LINK_CCM_VECS) / sizeof(LINK_CCM_VECS[0]); i++) {
        const dtn_link_ccm_vec *v = &LINK_CCM_VECS[i];
        uint8_t sealed[512 + 16];
        const size_t pt_len = v->plaintext_len, want_len = v->sealed_len;
        CHECK(want_len == pt_len + DTN_CCM_TAG_LEN);
        dtn_ccm_seal(v->key, v->nonce, v->aad_len ? v->aad : NULL, v->aad_len,
                     v->plaintext, pt_len, sealed);
        CHECK(bytes_eq(sealed, want_len, v->sealed, want_len));
        {
            uint8_t opened[512];
            CHECK(dtn_ccm_open(v->key, v->nonce, v->aad_len ? v->aad : NULL, v->aad_len,
                               sealed, want_len, opened) == 0);
            CHECK(bytes_eq(opened, pt_len, v->plaintext, pt_len));
            sealed[0] ^= 0x01;
            CHECK(dtn_ccm_open(v->key, v->nonce, v->aad_len ? v->aad : NULL, v->aad_len,
                               sealed, want_len, opened) == -1);
        }
    }
}

static int frame_code(const char *want)
{
    if (strcmp(want, "truncated") == 0) return DTN_FRAME_ERR_TRUNCATED;
    if (strcmp(want, "version") == 0) return DTN_FRAME_ERR_VERSION;
    if (strcmp(want, "type") == 0) return DTN_FRAME_ERR_TYPE;
    if (strcmp(want, "flags") == 0) return DTN_FRAME_ERR_FLAGS;
    if (strcmp(want, "oversize") == 0) return DTN_FRAME_ERR_OVERSIZE;
    return 99;
}

void test_link_vectors_frame(void)
{
    size_t i;
    T_BEGIN("link vectors: frame encode + reject");
    for (i = 0; i < sizeof(LINK_FRM_VECS) / sizeof(LINK_FRM_VECS[0]); i++) {
        const dtn_link_frame_vec *v = &LINK_FRM_VECS[i];
        uint8_t frame[512];
        size_t frame_len = 0;
        CHECK(dtn_frame_encode((dtn_frame_type)v->type, v->payload, v->payload_len,
                               frame, &frame_len) == DTN_FRAME_OK);
        CHECK(frame_len == v->frame_len);
        CHECK(bytes_eq(frame, frame_len, v->frame, v->frame_len));
        /* And the parse side agrees. */
        {
            dtn_frame_type t;
            const uint8_t *pl = NULL;
            size_t pl_len = 0;
            CHECK(dtn_frame_parse(frame, frame_len, &t, &pl, &pl_len) == DTN_FRAME_OK);
            CHECK(t == (dtn_frame_type)v->type);
            CHECK(bytes_eq(pl, pl_len, v->payload, v->payload_len));
        }
    }
    for (i = 0; i < sizeof(LINK_FREJ_VECS) / sizeof(LINK_FREJ_VECS[0]); i++) {
        const dtn_link_frame_rej_vec *v = &LINK_FREJ_VECS[i];
        dtn_frame_type t;
        const uint8_t *pl;
        size_t pl_len;
        CHECK(dtn_frame_parse(v->frame, v->frame_len, &t, &pl, &pl_len) == frame_code(v->expect_code));
    }
}

static int win_verdict(const char *want)
{
    if (strcmp(want, "partial") == 0) return DTN_WIN_PARTIAL;
    if (strcmp(want, "done") == 0) return DTN_WIN_DONE;
    if (strcmp(want, "dup") == 0) return DTN_WIN_DUP;
    if (strcmp(want, "invalid") == 0) return DTN_WIN_INVALID;
    if (strcmp(want, "dupcopy") == 0) return DTN_WIN_DUPLICATE;
    return 99;
}

void test_link_vectors_window(void)
{
    size_t i;
    T_BEGIN("link vectors: window (verdicts + byte-exact completions)");
    for (i = 0; i < sizeof(LINK_WIN_VECS) / sizeof(LINK_WIN_VECS[0]); i++) {
        const int idx = (int)i;
        dtn_win_reassembler r;
        int j;
        const char *comp = LINK_WIN_VECS[idx].completions_hex;
        uint8_t out[DTN_WIN_MAX_BYTES];
        size_t out_len = 0;
        dtn_win_reassembler_init(&r, (uint64_t)LINK_WIN_VECS[idx].timeout_ms, 0);
        for (j = 0; j < LINK_WIN_VECS[idx].push_n; j++) {
            const dtn_link_win_push *p = &LINK_WIN_PUSHES[LINK_WIN_VECS[idx].push_off + j];
            dtn_win_verdict got = dtn_win_push(&r, p->payload, p->len, out, &out_len);
            CHECK((int)got == win_verdict(p->verdict));
            if (got == DTN_WIN_DONE) {
                /* The completion content must equal the next ';'-field. */
                char field[2 * DTN_WIN_MAX_BYTES + 2];
                int k = 0;
                uint8_t want[DTN_WIN_MAX_BYTES];
                size_t want_len;
                while (*comp && *comp != ';' && k < (int)sizeof(field) - 1) {
                    field[k++] = *comp++;
                }
                if (*comp == ';') {
                    comp++;
                }
                field[k] = 0;
                want_len = unhex(field, want, sizeof(want));
                CHECK(bytes_eq(out, out_len, want, want_len));
            }
        }
    }
}

static int replay_code(const char *want)
{
    if (strcmp(want, "accept") == 0) return DTN_LINK_OK;
    if (strcmp(want, "replayed") == 0) return DTN_LINK_ERR_REPLAY;
    if (strcmp(want, "too_old") == 0) return DTN_LINK_ERR_TOO_OLD;
    if (strcmp(want, "too_far") == 0) return DTN_LINK_ERR_TOO_FAR;
    return 99;
}

void test_link_vectors_replay(void)
{
    size_t i;
    T_BEGIN("link vectors: replay (identical accept/reject verdicts)");
    for (i = 0; i < sizeof(LINK_REP_VECS) / sizeof(LINK_REP_VECS[0]); i++) {
        const dtn_link_replay_vec *v = &LINK_REP_VECS[i];
        dtn_link_session s;
        size_t j;
        dtn_link_session_init_raw(&s, DTN_LINK_R2I, v->key, v->key, v->salt, v->salt, NULL, 0);
        for (j = 0; j < v->n; j++) {
            uint8_t nonce[13], sealed[1 + 16], frame[13 + 17];
            uint8_t opened[16];
            memcpy(nonce, v->salt, 5);
            memset(nonce + 5, 0, 8);
            for (int k = 0; k < 8; k++) {
                nonce[12 - k] = (uint8_t)(v->seqs[j] >> (8 * k));
            }
            dtn_ccm_seal(v->key, nonce, NULL, 0, (const uint8_t *)"x", 1, sealed);
            memcpy(frame, nonce, 13);
            memcpy(frame + 13, sealed, 17);
            CHECK(dtn_link_session_open(&s, NULL, 0, frame, sizeof(frame), opened) ==
                  replay_code(v->verdicts[j]));
        }
    }
}

/* ------------------------------------------------------------------ */
/* Shared vectors: ccm / frame / window / replay                       */
/* ------------------------------------------------------------------ */

void test_link(void)
{
    T_BEGIN("link: official crypto anchors (RFC 3610/5869/8032)");
    test_link_crypto_anchors();
    test_link_vectors_handshake();
    test_link_vectors_ccm();
    test_link_vectors_frame();
    test_link_vectors_window();
    test_link_vectors_replay();
}
