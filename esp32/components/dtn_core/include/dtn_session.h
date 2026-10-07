/* dtn_session.h — the §6.1 EDHOC-shaped link handshake and the §6.2 link
 * session of docs/node-network.md (issue #33 P3.3).
 *
 * Handshake (frozen layouts, byte-identical to node/internal/link):
 *
 *   msg1 = [1(suite), 1(curve), g_x(32), c_i=0]                     — 38 B
 *   msg2 = [g_y(32), c_r=1, ct2]                                    — 134 B
 *          ct2 = AEAD(K2, th1(8) ‖ id_cred_r(8) ‖ sig_r(64))        — 96 B
 *   msg3 = [ct3]                                                    — 91 B
 *          ct3 = AEAD(K3, id_cred_i(8) ‖ sig_i(64))                 — 88 B
 *
 * th1 = SHA-256(msg1)[0:8]; id_cred = SHA-256(node_key)[0:8];
 * sig_r = Ed25519 over th1 ‖ EID_r (all the transcript the responder has
 * when it signs); sig_i = Ed25519 over th1 ‖ EID_r ‖ EID_i (the full
 * transcript). K2 = HKDF(dh, SHA-256(msg1), "offgrid-link-v1 k2");
 * K3 = HKDF(dh, SHA-256(msg1 ‖ g_y), "offgrid-link-v1 k3"); the ct
 * nonces are hsSalt ‖ BE64(n) with hsSalt = SHA-256("offgrid-link-v1-
 * handshake")[0:5]; each ct is AAD-bound to the message bytes preceding
 * its CBOR head.
 *
 * Session keys (§6.2): prk = HKDF-Extract(SHA-256(msg1 ‖ msg2 ‖ msg3), dh);
 * master = HKDF-Expand(prk, "offgrid-link-v1", 32); per-direction keys and
 * salts via HKDF-Expand(master, "offgrid-link-v1 i2r|r2i key|salt").
 *
 * Session: AES-CCM-128 with the 13-byte nonce (5-byte session salt ‖
 * 8-byte BE per-direction sequence), monotonic send counter persisted
 * every 32nd packet through the dtn_session_store seam (flash on ESP32 —
 * the NVS driver is hardware bring-up; RAM impl for host), a 64-wide
 * sliding replay window on receive, and the rekey bounds (2^20 packets /
 * 24 h). Go mirror: node/internal/link; both sides are pinned by the
 * shared vectors (tests/vectors/link via host/tests/link_vectors.h).
 */
#ifndef DTN_SESSION_H
#define DTN_SESSION_H

#include <stddef.h>
#include <stdint.h>

/* Frozen parameters (§6.1/§6.2). */
#define DTN_LINK_KEY_LEN 16
#define DTN_LINK_SALT_LEN 5
#define DTN_LINK_NONCE_LEN 13
#define DTN_LINK_TAG_LEN 16
#define DTN_LINK_TH1_LEN 8
#define DTN_LINK_SIG_LEN 64
#define DTN_LINK_FP_LEN 8
#define DTN_LINK_MSG1_LEN 38
#define DTN_LINK_MSG2_LEN 134
#define DTN_LINK_MSG3_LEN 91
#define DTN_LINK_CT2_LEN 80   /* plaintext inside msg2: th1 ‖ id_cred ‖ sig */
#define DTN_LINK_CT3_LEN 72   /* plaintext inside msg3: id_cred ‖ sig */
#define DTN_LINK_EID_LEN 26   /* "dtn://og.<16 hex>/" */
#define DTN_LINK_INFO_PREFIX "offgrid-link-v1"

/* Verdicts: 0 = OK; negative classes are stable across implementations
 * (the replay vectors pin the mapping). */
enum {
    DTN_LINK_OK = 0,
    DTN_LINK_ERR_AUTH = -1,   /* AEAD tag mismatch */
    DTN_LINK_ERR_REPLAY = -2, /* sequence already accepted */
    DTN_LINK_ERR_TOO_OLD = -3,
    DTN_LINK_ERR_TOO_FAR = -4,
    DTN_LINK_ERR_SALT = -5,   /* nonce salt prefix is not this session */
    DTN_LINK_ERR_SHORT = -6,  /* truncated input */
    DTN_LINK_ERR_STATE = -7,  /* wrong state, bad argument, failed machine */
};

typedef enum {
    DTN_LINK_I2R = 0, /* initiator → responder */
    DTN_LINK_R2I = 1  /* responder → initiator */
} dtn_link_dir;

/* ------------------------------------------------------------------ */
/* Key-schedule helpers (exposed for the shared vectors).              */
/* ------------------------------------------------------------------ */

/* dtn_link_eid renders dtn://og.<16 lowercase hex>/ for a node key. */
void dtn_link_eid(const uint8_t node_pub[32], char out[DTN_LINK_EID_LEN + 1]);

/* dtn_link_master: prk = Extract(SHA-256(transcript), dh);
 * master = Expand(prk, "offgrid-link-v1", 32). */
void dtn_link_master(const uint8_t dh[32],
                     const uint8_t *transcript, size_t transcript_len,
                     uint8_t master[32]);

/* dtn_link_direction_keys derives the per-direction §6.2 material. */
void dtn_link_direction_keys(const uint8_t master[32],
                             uint8_t k_i2r[DTN_LINK_KEY_LEN], uint8_t s_i2r[DTN_LINK_SALT_LEN],
                             uint8_t k_r2i[DTN_LINK_KEY_LEN], uint8_t s_r2i[DTN_LINK_SALT_LEN]);

/* ------------------------------------------------------------------ */
/* Session (established) + persisted-counter seam (§6.2).              */
/* ------------------------------------------------------------------ */

/* dtn_session_store — the persisted-counter HAL seam (flash on ESP32;
 * RAM reference impl for the host tests). load returns 0 when no counter
 * was persisted. */
typedef struct dtn_session_store {
    void *ctx;
    uint64_t (*load)(struct dtn_session_store *s, dtn_link_dir dir);
    int (*save)(struct dtn_session_store *s, dtn_link_dir dir, uint64_t seq);
} dtn_session_store;

typedef struct {
    dtn_link_dir dir; /* the LOCAL sender direction */
    uint8_t send_key[DTN_LINK_KEY_LEN], recv_key[DTN_LINK_KEY_LEN];
    uint8_t send_salt[DTN_LINK_SALT_LEN], recv_salt[DTN_LINK_SALT_LEN];
    uint64_t send_seq;     /* next outgoing sequence */
    uint64_t recv_highest; /* highest accepted incoming sequence */
    uint8_t recv_seen[8];  /* 64-wide distance bitmap (bit d = highest-d) */
    uint64_t est_unix;     /* establishment (rekey time anchor; 0 = not armed) */
    dtn_session_store *store;
    /* §6.2 "dropped and counted" (RAM-only). */
    uint64_t drops_replayed, drops_too_old, drops_too_far, drops_rejected_salt;
} dtn_link_session;

/* Raw constructor (rekey/restore paths and the vectors): derives nothing,
 * installs exactly the given direction material. */
void dtn_link_session_init_raw(dtn_link_session *s, dtn_link_dir dir,
                               const uint8_t send_key[DTN_LINK_KEY_LEN],
                               const uint8_t recv_key[DTN_LINK_KEY_LEN],
                               const uint8_t send_salt[DTN_LINK_SALT_LEN],
                               const uint8_t recv_salt[DTN_LINK_SALT_LEN],
                               dtn_session_store *store, uint64_t now_unix);

/* Seal protects one outgoing payload: out = nonce(13) ‖ ct ‖ tag(16),
 * out_len = 13 + pt_len + 16. Checkpoints the counter every 32nd packet. */
int dtn_link_session_seal(dtn_link_session *s,
                          const uint8_t *aad, size_t aad_len,
                          const uint8_t *pt, size_t pt_len, uint8_t *out);

/* Open verifies one incoming nonce(13) ‖ ct ‖ tag(16): writes
 * in_len - 29 plaintext bytes to out. Replayed/too-old/too-far frames are
 * DTN_LINK_ERR_* and counted internally (out is zeroed on failure). */
int dtn_link_session_open(dtn_link_session *s,
                          const uint8_t *aad, size_t aad_len,
                          const uint8_t *in, size_t in_len, uint8_t *out);

/* Drop counters (§6.2 "dropped and counted"). */
typedef struct {
    uint64_t replayed, too_old, too_far, rejected_salt;
} dtn_link_drops;

void dtn_link_session_drops(const dtn_link_session *s, dtn_link_drops *out);
uint64_t dtn_link_session_send_seq(const dtn_link_session *s);

/* Rekey bounds (§6.2): 2^20 packets or 24 h, whichever first. The actual
 * rekey is a NEW handshake; this only gates the trigger. */
#define DTN_LINK_REKEY_PACKETS (1ULL << 20)
#define DTN_LINK_REKEY_SECONDS (24ULL * 3600)
int dtn_link_session_needs_rekey(const dtn_link_session *s, uint64_t now_unix);

/* ------------------------------------------------------------------ */
/* The §6.1 handshake state machines.                                  */
/* ------------------------------------------------------------------ */

/* Config: the local identity and the peer's node key. The peer key is
 * resolved out of band (role-cert cache / pin store — §6.1): the full key
 * never crosses the wire, so the C side takes it as input and verifies
 * the handshake binds it (id_cred + signature). */
typedef struct {
    uint8_t local_seed[32];
    uint8_t local_pub[32];
    uint8_t peer_pub[32];
    const uint8_t *eph; /* optional fixed 32 B X25519 scalar (vectors) */
} dtn_link_hs_cfg;

typedef struct {
    dtn_link_hs_cfg cfg;
    uint8_t msg1[DTN_LINK_MSG1_LEN];
    size_t msg1_len;
    uint8_t th1[DTN_LINK_TH1_LEN];
    uint8_t gx[32];
    uint8_t x[32]; /* ephemeral scalar (in flight) */
    uint8_t dh[32];
    uint8_t gy[32];
    uint8_t eid_r[DTN_LINK_EID_LEN + 1];
    uint8_t msg2[DTN_LINK_MSG2_LEN]; /* retained for the transcript hash */
    size_t msg2_len;
    uint8_t msg3[DTN_LINK_MSG3_LEN];
    size_t msg3_len;
    dtn_link_session session;
    int failed;
} dtn_link_initiator;

int dtn_link_initiator_start(dtn_link_initiator *ini, const dtn_link_hs_cfg *cfg);
/* Consumes the responder's msg2; on OK the initiator is in msg3 state. */
int dtn_link_initiator_read2(dtn_link_initiator *ini, const uint8_t *msg2, size_t len);
/* Produces msg3 (ini->msg3/msg3_len) and derives the §6.2 session. */
int dtn_link_initiator_msg3(dtn_link_initiator *ini);

typedef struct {
    dtn_link_hs_cfg cfg;
    uint8_t msg1[DTN_LINK_MSG1_LEN];
    uint8_t th1[DTN_LINK_TH1_LEN];
    uint8_t gx[32];
    uint8_t x[32];
    uint8_t dh[32];
    uint8_t gy[32];
    uint8_t msg2[DTN_LINK_MSG2_LEN];
    size_t msg2_len;
    uint8_t eid_i[DTN_LINK_EID_LEN + 1];
    uint8_t msg3[DTN_LINK_MSG3_LEN];
    dtn_link_session session;
    int failed;
} dtn_link_responder;

int dtn_link_responder_read1(dtn_link_responder *res, const dtn_link_hs_cfg *cfg,
                             const uint8_t *msg1, size_t len);
/* Produces msg2 (res->msg2/msg2_len). */
int dtn_link_responder_write2(dtn_link_responder *res);
/* Consumes msg3 and derives the §6.2 session. */
int dtn_link_responder_read3(dtn_link_responder *res, const uint8_t *msg3, size_t len);

#endif /* DTN_SESSION_H */
