/* dtn_session.c — the §6.1 handshake and §6.2 session (see dtn_session.h).
 *
 * Go mirror: node/internal/link (handshake.go / session.go). Every layout,
 * hash, key-derivation label and verdict class here is pinned by the
 * shared vectors (tests/vectors/link → host/tests/link_vectors.h); the
 * official anchors (RFC 3610, RFC 5869, RFC 7748 §6.1, RFC 8032 §7.1) are
 * pinned in both suites' test files.
 */

#include "dtn_session.h"

#include <stdio.h>
#include <string.h>

#include "dtn_ccm.h"
#include "dtn_cbor.h"
#include "dtn_cbor_writer.h"
#include "dtn_hkdf.h"
#include "dtn_sha256.h"
#include "dtn_tweetnacl.h"

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */

static uint8_t hs_salt[DTN_LINK_SALT_LEN]; /* SHA-256("offgrid-link-v1-handshake")[0:5] */
static int hs_salt_ready;

static void hs_salt_init(void)
{
    uint8_t sum[32];
    static const char label[] = DTN_LINK_INFO_PREFIX "-handshake";
    dtn_sha256((const uint8_t *)label, sizeof(label) - 1, sum);
    memcpy(hs_salt, sum, DTN_LINK_SALT_LEN);
    hs_salt_ready = 1;
}

static void hs_nonce(uint8_t n, uint8_t out[DTN_LINK_NONCE_LEN])
{
    if (!hs_salt_ready) {
        hs_salt_init();
    }
    memset(out, 0, DTN_LINK_NONCE_LEN);
    memcpy(out, hs_salt, DTN_LINK_SALT_LEN);
    out[12] = n; /* BE64(n): the message number is tiny */
}

static void sha256_two(const uint8_t *a, size_t na, const uint8_t *b, size_t nb, uint8_t out[32])
{
    uint8_t buf[64 + 384]; /* transcripts are ≤ ~300 B; oversized fails closed */
    if (na + nb > sizeof(buf)) {
        memset(out, 0, 32);
        return;
    }
    memcpy(buf, a, na);
    memcpy(buf + na, b, nb);
    dtn_sha256(buf, na + nb, out);
}

static void fp_of(const uint8_t pub[32], uint8_t fp[DTN_LINK_FP_LEN])
{
    uint8_t sum[32];
    dtn_sha256(pub, 32, sum);
    memcpy(fp, sum, DTN_LINK_FP_LEN);
}

static void hex8(const uint8_t fp[DTN_LINK_FP_LEN], char out[17])
{
    static const char hexd[] = "0123456789abcdef";
    int i;
    for (i = 0; i < 8; i++) {
        out[i * 2] = hexd[fp[i] >> 4];
        out[i * 2 + 1] = hexd[fp[i] & 0x0f];
    }
    out[16] = 0;
}

void dtn_link_eid(const uint8_t node_pub[32], char out[DTN_LINK_EID_LEN + 1])
{
    uint8_t fp[DTN_LINK_FP_LEN];
    fp_of(node_pub, fp);
    memcpy(out, "dtn://og.", 9);
    hex8(fp, out + 9);
    out[25] = '/';
    out[26] = 0;
}

/* ------------------------------------------------------------------ */
/* Key schedule (§6.2)                                                 */
/* ------------------------------------------------------------------ */

void dtn_link_master(const uint8_t dh[32],
                     const uint8_t *transcript, size_t transcript_len,
                     uint8_t master[32])
{
    uint8_t th[32], prk[32];
    dtn_sha256(transcript, transcript_len, th);
    dtn_hkdf_extract(th, 32, dh, 32, prk);
    if (dtn_hkdf_expand(prk, (const uint8_t *)DTN_LINK_INFO_PREFIX,
                        sizeof(DTN_LINK_INFO_PREFIX) - 1, 32, master) != 0) {
        memset(master, 0, 32);
    }
}

static void derive_label(const uint8_t master[32], const char *label, size_t n,
                         uint8_t *out, size_t out_len)
{
    uint8_t info[64];
    size_t off = 0;
    memcpy(info + off, DTN_LINK_INFO_PREFIX, sizeof(DTN_LINK_INFO_PREFIX) - 1);
    off += sizeof(DTN_LINK_INFO_PREFIX) - 1;
    info[off++] = ' ';
    memcpy(info + off, label, n);
    off += n;
    if (dtn_hkdf_expand(master, info, off, out_len, out) != 0) {
        memset(out, 0, out_len);
    }
}

void dtn_link_direction_keys(const uint8_t master[32],
                             uint8_t k_i2r[DTN_LINK_KEY_LEN], uint8_t s_i2r[DTN_LINK_SALT_LEN],
                             uint8_t k_r2i[DTN_LINK_KEY_LEN], uint8_t s_r2i[DTN_LINK_SALT_LEN])
{
    derive_label(master, "i2r key", 7, k_i2r, DTN_LINK_KEY_LEN);
    derive_label(master, "i2r salt", 8, s_i2r, DTN_LINK_SALT_LEN);
    derive_label(master, "r2i key", 7, k_r2i, DTN_LINK_KEY_LEN);
    derive_label(master, "r2i salt", 8, s_r2i, DTN_LINK_SALT_LEN);
}

static void k2_of(const uint8_t dh[32], const uint8_t *msg1, size_t msg1_len,
                  uint8_t k2[DTN_LINK_KEY_LEN])
{
    uint8_t salt[32], prk[32];
    dtn_sha256(msg1, msg1_len, salt);
    dtn_hkdf_extract(salt, 32, dh, 32, prk);
    if (dtn_hkdf_expand(prk, (const uint8_t *)DTN_LINK_INFO_PREFIX " k2",
                        sizeof(DTN_LINK_INFO_PREFIX " k2") - 1, DTN_LINK_KEY_LEN, k2) != 0) {
        memset(k2, 0, DTN_LINK_KEY_LEN);
    }
}

static void k3_of(const uint8_t dh[32], const uint8_t *msg1, size_t msg1_len,
                  const uint8_t *gy /* 32 */, uint8_t k3[DTN_LINK_KEY_LEN])
{
    uint8_t salt[32], prk[32];
    sha256_two(msg1, msg1_len, gy, 32, salt);
    dtn_hkdf_extract(salt, 32, dh, 32, prk);
    if (dtn_hkdf_expand(prk, (const uint8_t *)DTN_LINK_INFO_PREFIX " k3",
                        sizeof(DTN_LINK_INFO_PREFIX " k3") - 1, DTN_LINK_KEY_LEN, k3) != 0) {
        memset(k3, 0, DTN_LINK_KEY_LEN);
    }
}

/* ------------------------------------------------------------------ */
/* Session (§6.2)                                                      */
/* ------------------------------------------------------------------ */

#define DTN_LINK_CHECKPOINT 32
#define DTN_LINK_RESUME_SKIP 32
#define DTN_LINK_REPLAY_WINDOW 64

void dtn_link_session_init_raw(dtn_link_session *s, dtn_link_dir dir,
                               const uint8_t send_key[DTN_LINK_KEY_LEN],
                               const uint8_t recv_key[DTN_LINK_KEY_LEN],
                               const uint8_t send_salt[DTN_LINK_SALT_LEN],
                               const uint8_t recv_salt[DTN_LINK_SALT_LEN],
                               dtn_session_store *store, uint64_t now_unix)
{
    memset(s, 0, sizeof(*s));
    s->dir = dir;
    memcpy(s->send_key, send_key, DTN_LINK_KEY_LEN);
    memcpy(s->recv_key, recv_key, DTN_LINK_KEY_LEN);
    memcpy(s->send_salt, send_salt, DTN_LINK_SALT_LEN);
    memcpy(s->recv_salt, recv_salt, DTN_LINK_SALT_LEN);
    s->est_unix = now_unix;
    s->store = store;
    if (store != NULL) {
        const uint64_t persisted = store->load(store, dir);
        s->send_seq = persisted + DTN_LINK_RESUME_SKIP; /* 0 + 32 = the clean-start skip */
    }
}

int dtn_link_session_seal(dtn_link_session *s,
                          const uint8_t *aad, size_t aad_len,
                          const uint8_t *pt, size_t pt_len, uint8_t *out)
{
    uint8_t nonce[DTN_LINK_NONCE_LEN];
    const uint64_t seq = s->send_seq;
    int rc;

    memcpy(nonce, s->send_salt, DTN_LINK_SALT_LEN);
    memset(nonce + 5, 0, 8);
    for (int i = 0; i < 8; i++) {
        nonce[12 - i] = (uint8_t)(seq >> (8 * i));
    }
    dtn_ccm_seal(s->send_key, nonce, aad, aad_len, pt, pt_len, out + DTN_LINK_NONCE_LEN);
    memcpy(out, nonce, DTN_LINK_NONCE_LEN);
    s->send_seq = seq + 1;
    if (s->store != NULL && s->send_seq % DTN_LINK_CHECKPOINT == 0) {
        rc = s->store->save(s->store, s->dir, s->send_seq);
        if (rc != DTN_LINK_OK) {
            return DTN_LINK_ERR_STATE;
        }
    }
    return DTN_LINK_OK;
}

int dtn_link_session_open(dtn_link_session *s,
                          const uint8_t *aad, size_t aad_len,
                          const uint8_t *in, size_t in_len, uint8_t *out)
{
    uint8_t diff = 0;
    uint64_t seq = 0;
    size_t i, pt_len;
    int rc;

    if (in_len < DTN_LINK_NONCE_LEN + DTN_LINK_TAG_LEN) {
        return DTN_LINK_ERR_SHORT;
    }
    for (i = 0; i < DTN_LINK_SALT_LEN; i++) {
        diff |= (uint8_t)(in[i] ^ s->recv_salt[i]);
    }
    if (diff != 0) {
        s->drops_rejected_salt++;
        return DTN_LINK_ERR_SALT;
    }
    for (i = 0; i < 8; i++) {
        seq = (seq << 8) | in[5 + i];
    }
    if (seq > s->recv_highest + DTN_LINK_REPLAY_WINDOW) {
        s->drops_too_far++;
        return DTN_LINK_ERR_TOO_FAR;
    }
    if (seq + DTN_LINK_REPLAY_WINDOW <= s->recv_highest) {
        s->drops_too_old++;
        return DTN_LINK_ERR_TOO_OLD;
    }
    if (seq <= s->recv_highest) {
        const size_t d = (size_t)(s->recv_highest - seq);
        if (s->recv_seen[d / 8] & (1u << (d % 8))) {
            s->drops_replayed++;
            return DTN_LINK_ERR_REPLAY;
        }
    }
    pt_len = in_len - DTN_LINK_NONCE_LEN;
    rc = dtn_ccm_open(s->recv_key, in, aad, aad_len, in + DTN_LINK_NONCE_LEN, pt_len, out);
    if (rc != 0) {
        return DTN_LINK_ERR_AUTH; /* nothing is marked seen */
    }
    if (seq > s->recv_highest) {
        /* Shift the distance bitmap up by the new high-water mark: bit d
         * moves to d+delta, bits past the window fall off, bit 0 sets. */
        const uint64_t delta = seq - s->recv_highest;
        uint8_t fresh[8] = {0};
        size_t d;
        if (delta < DTN_LINK_REPLAY_WINDOW) {
            for (d = delta; d < DTN_LINK_REPLAY_WINDOW; d++) {
                const size_t src = d - delta;
                if (s->recv_seen[src / 8] & (1u << (src % 8))) {
                    fresh[d / 8] |= (uint8_t)(1u << (d % 8));
                }
            }
        }
        fresh[0] |= 1;
        memcpy(s->recv_seen, fresh, sizeof(fresh));
        s->recv_highest = seq;
    } else {
        const size_t d = (size_t)(s->recv_highest - seq);
        s->recv_seen[d / 8] |= (uint8_t)(1u << (d % 8));
    }
    return DTN_LINK_OK;
}

void dtn_link_session_drops(const dtn_link_session *s, dtn_link_drops *out)
{
    out->replayed = s->drops_replayed;
    out->too_old = s->drops_too_old;
    out->too_far = s->drops_too_far;
    out->rejected_salt = s->drops_rejected_salt;
}

uint64_t dtn_link_session_send_seq(const dtn_link_session *s)
{
    return s->send_seq;
}

int dtn_link_session_needs_rekey(const dtn_link_session *s, uint64_t now_unix)
{
    if (s->send_seq >= DTN_LINK_REKEY_PACKETS) {
        return 1;
    }
    /* est_unix == 0 = the clock is not armed (embedded bring-up); only the
     * packet bound applies. */
    if (s->est_unix == 0 || now_unix <= s->est_unix) {
        return 0;
    }
    return now_unix - s->est_unix >= DTN_LINK_REKEY_SECONDS;
}

/* ------------------------------------------------------------------ */
/* The §6.1 handshake                                                  */
/* ------------------------------------------------------------------ */
/* The §6.1 handshake state machines                                   */
/* ------------------------------------------------------------------ */

static int x25519_pub(const uint8_t scalar[32], uint8_t pub[32])
{
    return dtn_tn_crypto_scalarmult_base(pub, scalar);
}

static int x25519_dh(const uint8_t scalar[32], const uint8_t peer[32], uint8_t dh[32])
{
    return dtn_tn_crypto_scalarmult(dh, scalar, peer);
}

/* build_msg1 = [1, 1, g_x(32), 0] — 38 B canonical CBOR. */
static void build_msg1(const uint8_t gx[32], uint8_t out[DTN_LINK_MSG1_LEN])
{
    dtn_cbor_writer w;
    dtn_cbor_writer_init(&w, out, DTN_LINK_MSG1_LEN);
    dtn_cbor_w_array(&w, 4);
    dtn_cbor_w_uint(&w, 1); /* suite */
    dtn_cbor_w_uint(&w, 1); /* curve: X25519 */
    dtn_cbor_w_bstr(&w, gx, 32);
    dtn_cbor_w_uint(&w, 0); /* c_i, pinned */
}

/* sigMessageR = th1 ‖ EID_r (all the transcript the responder has seen
 * when it signs — msg3, which carries the initiator's EID, follows). */
static void sig_message_r(const uint8_t th1[DTN_LINK_TH1_LEN], const char eid_r[],
                          uint8_t out[DTN_LINK_TH1_LEN + DTN_LINK_EID_LEN])
{
    memcpy(out, th1, DTN_LINK_TH1_LEN);
    memcpy(out + DTN_LINK_TH1_LEN, eid_r, DTN_LINK_EID_LEN);
}

/* sigMessageI = th1 ‖ EID_r ‖ EID_i (the FULL §6.1 transcript). */
static void sig_message_i(const uint8_t th1[DTN_LINK_TH1_LEN], const char eid_r[],
                          const char eid_i[],
                          uint8_t out[DTN_LINK_TH1_LEN + 2 * DTN_LINK_EID_LEN])
{
    memcpy(out, th1, DTN_LINK_TH1_LEN);
    memcpy(out + DTN_LINK_TH1_LEN, eid_r, DTN_LINK_EID_LEN);
    memcpy(out + DTN_LINK_TH1_LEN + DTN_LINK_EID_LEN, eid_i, DTN_LINK_EID_LEN);
}

/* derive_session installs the §6.2 per-direction material from the full
 * transcript and the shared secret. */
static void derive_session(dtn_link_session *s, dtn_link_dir dir,
                           const uint8_t dh[32],
                           const uint8_t *msg1, size_t l1,
                           const uint8_t *msg2, size_t l2,
                           const uint8_t *msg3, size_t l3)
{
    uint8_t transcript[DTN_LINK_MSG1_LEN + DTN_LINK_MSG2_LEN + DTN_LINK_MSG3_LEN];
    uint8_t master[32], k_i2r[DTN_LINK_KEY_LEN], k_r2i[DTN_LINK_KEY_LEN];
    uint8_t s_i2r[DTN_LINK_SALT_LEN], s_r2i[DTN_LINK_SALT_LEN];
    size_t n = 0;
    memcpy(transcript + n, msg1, l1);
    n += l1;
    memcpy(transcript + n, msg2, l2);
    n += l2;
    memcpy(transcript + n, msg3, l3);
    n += l3;
    dtn_link_master(dh, transcript, n, master);
    dtn_link_direction_keys(master, k_i2r, s_i2r, k_r2i, s_r2i);
    if (dir == DTN_LINK_I2R) {
        dtn_link_session_init_raw(s, DTN_LINK_I2R, k_i2r, k_r2i, s_i2r, s_r2i, NULL, 0);
    } else {
        dtn_link_session_init_raw(s, DTN_LINK_R2I, k_r2i, k_i2r, s_r2i, s_i2r, NULL, 0);
    }
}

int dtn_link_initiator_start(dtn_link_initiator *ini, const dtn_link_hs_cfg *cfg)
{
    memset(ini, 0, sizeof(*ini));
    ini->cfg = *cfg;
    if (ini->cfg.eph == NULL) {
        /* No portable RNG in the core: the caller supplies the ephemeral
         * (the ESP32 sources it from its RNG one layer up). Fail-closed. */
        return DTN_LINK_ERR_STATE;
    }
    memcpy(ini->x, ini->cfg.eph, 32);
    if (x25519_pub(ini->x, ini->gx) != 0) {
        ini->failed = 1;
        return DTN_LINK_ERR_STATE;
    }
    build_msg1(ini->gx, ini->msg1);
    ini->msg1_len = DTN_LINK_MSG1_LEN;
    {
        uint8_t sum[32];
        dtn_sha256(ini->msg1, ini->msg1_len, sum);
        memcpy(ini->th1, sum, DTN_LINK_TH1_LEN);
    }
    return DTN_LINK_OK;
}

int dtn_link_initiator_read2(dtn_link_initiator *ini, const uint8_t *msg2, size_t len)
{
    dtn_cbor c;
    size_t items = 0, gy_len = 0, ct2_head = 0, ct2_len = 0;
    const uint8_t *gy = NULL, *ct2 = NULL;
    uint64_t c_r = 0;
    uint8_t k2[DTN_LINK_KEY_LEN], pt[DTN_LINK_CT2_LEN];
    uint8_t sigmsg[DTN_LINK_TH1_LEN + DTN_LINK_EID_LEN];
    uint8_t fp_want[DTN_LINK_FP_LEN], nonce[DTN_LINK_NONCE_LEN];

    if (ini->failed || ini->msg1_len != DTN_LINK_MSG1_LEN || ini->msg2_len != 0) {
        return DTN_LINK_ERR_STATE;
    }
    dtn_cbor_init(&c, msg2, len);
    if (dtn_cbor_array(&c, &items) != DTN_CBOR_OK || items != 3 ||
        dtn_cbor_bstr(&c, &gy, &gy_len) != DTN_CBOR_OK || gy_len != 32 ||
        dtn_cbor_uint(&c, &c_r) != DTN_CBOR_OK || c_r != 1) {
        ini->failed = 1;
        return DTN_LINK_ERR_SHORT;
    }
    ct2_head = c.off; /* everything before the ct2 head is the AAD */
    if (dtn_cbor_bstr(&c, &ct2, &ct2_len) != DTN_CBOR_OK ||
        ct2_len != DTN_LINK_CT2_LEN + DTN_LINK_TAG_LEN || !dtn_cbor_done(&c)) {
        ini->failed = 1;
        return DTN_LINK_ERR_SHORT;
    }
    if (x25519_dh(ini->x, gy, ini->dh) != 0) {
        ini->failed = 1;
        return DTN_LINK_ERR_STATE;
    }
    memcpy(ini->gy, gy, 32);
    k2_of(ini->dh, ini->msg1, DTN_LINK_MSG1_LEN, k2);
    hs_nonce(2, nonce);
    if (dtn_ccm_open(k2, nonce, msg2, ct2_head, ct2, ct2_len, pt) != 0) {
        ini->failed = 1;
        return DTN_LINK_ERR_AUTH;
    }
    /* pt = th1(8) ‖ id_cred_r(8) ‖ sig_r(64) */
    if (memcmp(pt, ini->th1, DTN_LINK_TH1_LEN) != 0) {
        ini->failed = 1;
        return DTN_LINK_ERR_AUTH; /* transcript prefix mismatch */
    }
    fp_of(ini->cfg.peer_pub, fp_want);
    if (memcmp(pt + DTN_LINK_TH1_LEN, fp_want, DTN_LINK_FP_LEN) != 0) {
        ini->failed = 1;
        return DTN_LINK_ERR_AUTH; /* the presented id_cred is not the pinned key */
    }
    dtn_link_eid(ini->cfg.peer_pub, (char *)ini->eid_r);
    sig_message_r(ini->th1, (const char *)ini->eid_r, sigmsg);
    if (dtn_tn_ed25519_verify(ini->cfg.peer_pub, pt + DTN_LINK_TH1_LEN + DTN_LINK_FP_LEN,
                              sigmsg, sizeof(sigmsg)) != 0) {
        ini->failed = 1;
        return DTN_LINK_ERR_AUTH;
    }
    memcpy(ini->msg2, msg2, len);
    ini->msg2_len = len;
    memset(ini->x, 0, 32);
    return DTN_LINK_OK;
}

int dtn_link_initiator_msg3(dtn_link_initiator *ini)
{
    uint8_t k3[DTN_LINK_KEY_LEN], pt[DTN_LINK_CT3_LEN];
    uint8_t ct3[DTN_LINK_CT3_LEN + DTN_LINK_TAG_LEN];
    uint8_t sigmsg[DTN_LINK_TH1_LEN + 2 * DTN_LINK_EID_LEN];
    uint8_t nonce[DTN_LINK_NONCE_LEN];
    const uint8_t aad[1] = {0x81}; /* msg3's array head */
    char eid_i[DTN_LINK_EID_LEN + 1];
    dtn_cbor_writer w;

    if (ini->failed || ini->msg2_len != DTN_LINK_MSG2_LEN) {
        return DTN_LINK_ERR_STATE;
    }
    k3_of(ini->dh, ini->msg1, DTN_LINK_MSG1_LEN, ini->gy, k3);
    dtn_link_eid(ini->cfg.local_pub, eid_i);
    sig_message_i(ini->th1, (const char *)ini->eid_r, eid_i, sigmsg);
    if (dtn_tn_ed25519_sign(pt + DTN_LINK_FP_LEN, sigmsg, sizeof(sigmsg),
                            ini->cfg.local_seed, ini->cfg.local_pub) != 0) {
        ini->failed = 1;
        return DTN_LINK_ERR_STATE;
    }
    fp_of(ini->cfg.local_pub, pt);
    /* ct3 = AEAD(K3, id_cred_i ‖ sig_i). */
    hs_nonce(3, nonce);
    dtn_ccm_seal(k3, nonce, aad, 1, pt, DTN_LINK_CT3_LEN, ct3);
    dtn_cbor_writer_init(&w, ini->msg3, DTN_LINK_MSG3_LEN);
    dtn_cbor_w_array(&w, 1);
    dtn_cbor_w_bstr(&w, ct3, sizeof(ct3));
    if (!dtn_cbor_w_ok(&w)) {
        ini->failed = 1;
        return DTN_LINK_ERR_STATE;
    }
    ini->msg3_len = DTN_LINK_MSG3_LEN;
    derive_session(&ini->session, DTN_LINK_I2R, ini->dh,
                   ini->msg1, DTN_LINK_MSG1_LEN,
                   ini->msg2, ini->msg2_len,
                   ini->msg3, ini->msg3_len);
    memset(ini->x, 0, 32);
    memset(ini->dh, 0, 32);
    return DTN_LINK_OK;
}

int dtn_link_responder_read1(dtn_link_responder *res, const dtn_link_hs_cfg *cfg,
                             const uint8_t *msg1, size_t len)
{
    dtn_cbor c;
    size_t items = 0, gx_len = 0;
    const uint8_t *gx = NULL;
    uint64_t suite = 0, curve = 0, c_i = 0;
    uint8_t sum[32];

    memset(res, 0, sizeof(*res));
    res->cfg = *cfg;
    if (len != DTN_LINK_MSG1_LEN) {
        res->failed = 1;
        return DTN_LINK_ERR_SHORT;
    }
    dtn_cbor_init(&c, msg1, len);
    if (dtn_cbor_array(&c, &items) != DTN_CBOR_OK || items != 4 ||
        dtn_cbor_uint(&c, &suite) != DTN_CBOR_OK || suite != 1 ||
        dtn_cbor_uint(&c, &curve) != DTN_CBOR_OK || curve != 1 ||
        dtn_cbor_bstr(&c, &gx, &gx_len) != DTN_CBOR_OK || gx_len != 32 ||
        dtn_cbor_uint(&c, &c_i) != DTN_CBOR_OK || c_i != 0 ||
        !dtn_cbor_done(&c)) {
        res->failed = 1;
        return DTN_LINK_ERR_SHORT;
    }
    memcpy(res->msg1, msg1, DTN_LINK_MSG1_LEN);
    memcpy(res->gx, gx, 32);
    dtn_sha256(res->msg1, DTN_LINK_MSG1_LEN, sum);
    memcpy(res->th1, sum, DTN_LINK_TH1_LEN);
    return DTN_LINK_OK;
}

int dtn_link_responder_write2(dtn_link_responder *res)
{
    uint8_t k2[DTN_LINK_KEY_LEN], pt[DTN_LINK_CT2_LEN], sig[DTN_LINK_SIG_LEN];
    uint8_t ct2[DTN_LINK_CT2_LEN + DTN_LINK_TAG_LEN];
    uint8_t sigmsg[DTN_LINK_TH1_LEN + DTN_LINK_EID_LEN];
    uint8_t nonce[DTN_LINK_NONCE_LEN];
    uint8_t prefix[DTN_LINK_MSG2_LEN];
    size_t prefix_len;
    dtn_cbor_writer w;
    char eid_r[DTN_LINK_EID_LEN + 1];
    uint8_t fp_r[DTN_LINK_FP_LEN];

    if (res->failed || res->msg1[0] == 0) {
        return DTN_LINK_ERR_STATE;
    }
    if (res->cfg.eph == NULL) {
        return DTN_LINK_ERR_STATE; /* caller supplies the ephemeral */
    }
    memcpy(res->x, res->cfg.eph, 32);
    if (x25519_pub(res->x, res->gy) != 0 || x25519_dh(res->x, res->gx, res->dh) != 0) {
        res->failed = 1;
        return DTN_LINK_ERR_STATE;
    }
    /* The prefix (array ‖ g_y ‖ c_r) doubles as the ct2 AAD. */
    dtn_cbor_writer_init(&w, prefix, sizeof(prefix));
    dtn_cbor_w_array(&w, 3);
    dtn_cbor_w_bstr(&w, res->gy, 32);
    dtn_cbor_w_uint(&w, 1); /* c_r, pinned */
    if (!dtn_cbor_w_ok(&w)) {
        res->failed = 1;
        return DTN_LINK_ERR_STATE;
    }
    prefix_len = w.len;
    k2_of(res->dh, res->msg1, DTN_LINK_MSG1_LEN, k2);
    dtn_link_eid(res->cfg.local_pub, eid_r);
    sig_message_r(res->th1, eid_r, sigmsg);
    if (dtn_tn_ed25519_sign(sig, sigmsg, sizeof(sigmsg),
                            res->cfg.local_seed, res->cfg.local_pub) != 0) {
        res->failed = 1;
        return DTN_LINK_ERR_STATE;
    }
    /* pt = th1(8) ‖ id_cred_r(8) ‖ sig_r(64) */
    memcpy(pt, res->th1, DTN_LINK_TH1_LEN);
    fp_of(res->cfg.local_pub, fp_r);
    memcpy(pt + DTN_LINK_TH1_LEN, fp_r, DTN_LINK_FP_LEN);
    memcpy(pt + DTN_LINK_TH1_LEN + DTN_LINK_FP_LEN, sig, DTN_LINK_SIG_LEN);
    hs_nonce(2, nonce);
    dtn_ccm_seal(k2, nonce, prefix, prefix_len, pt, DTN_LINK_CT2_LEN, ct2);
    /* msg2 = prefix ‖ bstr-head(ct2) ‖ ct2 = 134 B. */
    memcpy(res->msg2, prefix, prefix_len);
    dtn_cbor_writer_init(&w, res->msg2 + prefix_len, DTN_LINK_MSG2_LEN - prefix_len);
    dtn_cbor_w_bstr(&w, ct2, sizeof(ct2));
    if (!dtn_cbor_w_ok(&w)) {
        res->failed = 1;
        return DTN_LINK_ERR_STATE;
    }
    res->msg2_len = prefix_len + w.len;
    return DTN_LINK_OK;
}

int dtn_link_responder_read3(dtn_link_responder *res, const uint8_t *msg3, size_t len)
{
    dtn_cbor c;
    size_t items = 0, ct3_len = 0;
    const uint8_t *ct3 = NULL;
    uint8_t k3[DTN_LINK_KEY_LEN], pt[DTN_LINK_CT3_LEN];
    uint8_t sigmsg[DTN_LINK_TH1_LEN + 2 * DTN_LINK_EID_LEN];
    uint8_t fp_want[DTN_LINK_FP_LEN], nonce[DTN_LINK_NONCE_LEN];
    const uint8_t aad[1] = {0x81}; /* msg3's array head */
    char eid_r[DTN_LINK_EID_LEN + 1];

    if (res->failed || res->msg2_len != DTN_LINK_MSG2_LEN || res->msg3[0] != 0) {
        return DTN_LINK_ERR_STATE;
    }
    if (len != DTN_LINK_MSG3_LEN) {
        res->failed = 1;
        return DTN_LINK_ERR_SHORT;
    }
    memcpy(res->msg3, msg3, DTN_LINK_MSG3_LEN);
    dtn_cbor_init(&c, msg3, len);
    if (dtn_cbor_array(&c, &items) != DTN_CBOR_OK || items != 1 ||
        dtn_cbor_bstr(&c, &ct3, &ct3_len) != DTN_CBOR_OK ||
        ct3_len != DTN_LINK_CT3_LEN + DTN_LINK_TAG_LEN || !dtn_cbor_done(&c)) {
        res->failed = 1;
        return DTN_LINK_ERR_SHORT;
    }
    k3_of(res->dh, res->msg1, DTN_LINK_MSG1_LEN, res->gy, k3);
    hs_nonce(3, nonce);
    if (dtn_ccm_open(k3, nonce, aad, 1, ct3, ct3_len, pt) != 0) {
        res->failed = 1;
        return DTN_LINK_ERR_AUTH;
    }
    /* pt = id_cred_i(8) ‖ sig_i(64) */
    fp_of(res->cfg.peer_pub, fp_want);
    if (memcmp(pt, fp_want, DTN_LINK_FP_LEN) != 0) {
        res->failed = 1;
        return DTN_LINK_ERR_AUTH;
    }
    dtn_link_eid(res->cfg.local_pub, eid_r);
    dtn_link_eid(res->cfg.peer_pub, (char *)res->eid_i);
    sig_message_i(res->th1, eid_r, (const char *)res->eid_i, sigmsg);
    if (dtn_tn_ed25519_verify(res->cfg.peer_pub, pt + DTN_LINK_FP_LEN,
                              sigmsg, sizeof(sigmsg)) != 0) {
        res->failed = 1;
        return DTN_LINK_ERR_AUTH;
    }
    derive_session(&res->session, DTN_LINK_R2I, res->dh,
                   res->msg1, DTN_LINK_MSG1_LEN,
                   res->msg2, res->msg2_len,
                   res->msg3, DTN_LINK_MSG3_LEN);
    memset(res->x, 0, 32);
    memset(res->dh, 0, 32);
    return DTN_LINK_OK;
}
