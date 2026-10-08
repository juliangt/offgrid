/* dtn_nodeid.h — self-certifying node identity for the dtn_core portable
 * core (docs/node-network.md §2.1, issue #33 P3.1) and the persistent-
 * identity HAL seam.
 *
 * Identity: fingerprint = SHA-256(Ed25519 pub)[0:8]; EID = dtn://og.<16
 * lowercase hex>/. The EID is derived, never chosen; ValidateBinding is the
 * §2.1 check every verifier MUST run.
 *
 * HAL seam: `dtn_nodeid_store` is the vtable the node's own identity lives
 * through (32-byte seed + cert blob). Host tests use the RAM implementation
 * below; the ESP32 bring-up (P3.3+/field) provides the NVS one — the seam,
 * not the flash driver, is the P3.1 deliverable. */
#ifndef DTN_NODEID_H
#define DTN_NODEID_H

#include <stddef.h>
#include <stdint.h>

#define DTN_NODEID_KEY_LEN 32
#define DTN_NODEID_FP_LEN 8
/* dtn://og. (9) + 16 hex + / (1) */
#define DTN_NODEID_EID_MAX 26

/* dtn_nodeid_fingerprint — SHA-256(pub)[0:8] (dtn_sha256 underneath). */
void dtn_nodeid_fingerprint(const uint8_t pub[DTN_NODEID_KEY_LEN],
                            uint8_t fp[DTN_NODEID_FP_LEN]);

/* dtn_nodeid_eid — render dtn://og.<fp hex>/ (lowercase, NUL-terminated). */
void dtn_nodeid_eid(const uint8_t fp[DTN_NODEID_FP_LEN],
                    char eid[DTN_NODEID_EID_MAX + 1]);

/* dtn_nodeid_eid_fingerprint — parse the EXACT EID form back into its
 * fingerprint. Returns 0 on success; nonzero on any deviation (length,
 * prefix/suffix, non-lowercase-hex). */
int dtn_nodeid_eid_fingerprint(const char *eid, uint8_t fp[DTN_NODEID_FP_LEN]);

/* dtn_nodeid_eid_binding — the §2.1 self-certification check: 0 when eid
 * is exactly EID(Fingerprint(pub)). */
int dtn_nodeid_eid_binding(const uint8_t pub[DTN_NODEID_KEY_LEN], const char *eid);

/* --- the HAL seam ----------------------------------------------------------- */

typedef struct dtn_nodeid_store {
    /* load_key — the node's own 32-byte Ed25519 seed. Returns 0 on success,
     * nonzero when absent (never provisioned). */
    int (*load_key)(void *ctx, uint8_t key[DTN_NODEID_KEY_LEN]);
    /* save_key — persist the seed (provisioning time). */
    int (*save_key)(void *ctx, const uint8_t key[DTN_NODEID_KEY_LEN]);
    /* load_cert — the node's own COSE_Sign1 role cert blob. Returns 0 and
     * sets *len (≤ cap) on success, nonzero when absent. */
    int (*load_cert)(void *ctx, uint8_t *buf, size_t cap, size_t *len);
    /* save_cert — persist the cert blob. */
    int (*save_cert)(void *ctx, const uint8_t *blob, size_t len);
    void *ctx;
} dtn_nodeid_store;

/* dtn_nodeid_self_fingerprint — convenience: the fingerprint of the key a
 * store holds. Returns 0 on success (key present), nonzero otherwise. */
int dtn_nodeid_self_fingerprint(const dtn_nodeid_store *v,
                                uint8_t fp[DTN_NODEID_FP_LEN]);

/* RAM implementation for host tests (and as the reference behavior: a
 * missing key/cert is an explicit has_* flag, never silent zeros). */
typedef struct {
    uint8_t key[DTN_NODEID_KEY_LEN];
    int has_key;
    uint8_t cert[1024];
    size_t cert_len;
    int has_cert;
} dtn_nodeid_ram_store;

void dtn_nodeid_ram_store_init(dtn_nodeid_ram_store *s);
void dtn_nodeid_ram_vtable(dtn_nodeid_ram_store *s, dtn_nodeid_store *v);

#endif /* DTN_NODEID_H */
