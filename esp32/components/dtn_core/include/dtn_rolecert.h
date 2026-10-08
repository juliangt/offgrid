/* dtn_rolecert.h — COSE_Sign1 role-certificate VERIFY + the §2.5 seq merge
 * rules for the dtn_core portable core (docs/node-network.md §2.2/§2.5,
 * issue #33 P3.1).
 *
 * The C side is a verifier/consumer by design — it never signs. The checks
 * mirror node/internal/nodeid/rolecert.go exactly (same order, same stable
 * failure classes) and the shared vectors in
 * host/tests/nodeid_vectors.h (generated from tests/vectors/nodeid/
 * vectors.json) pin both implementations to the same bytes. */
#ifndef DTN_ROLECERT_H
#define DTN_ROLECERT_H

#include <stddef.h>
#include <stdint.h>

/* dtn_nodeid.h is included for the EID length constant and the binding
 * check used by the schema pass. */
#include "dtn_nodeid.h"

/* A verifier will not even look at a COSE_Sign1 longer than this: the
 * realistic cert is ≈ 200 bytes, the §2.2 map ≤ ~130. */
#define DTN_ROLECERT_MAX 1024

#define DTN_ROLECERT_ROLES_CAP 5  /* the closed §2.3 set */
#define DTN_ROLECERT_ROLE_MAX 8   /* "manager" + NUL */
#define DTN_ROLECERT_MAX_LEVEL 3
#define DTN_ROLECERT_MAX_SKEW 300 /* §4.3 skew rule: issued ≤ now + 300 */

/* Verification result codes. DTN_ROLECERT_EXPIRED is a positive answer:
 * the bytes are genuinely signed and schema-valid, but §2.5 rule 5 treats
 * an expired cert as absent. */
enum {
    DTN_ROLECERT_OK = 0,
    DTN_ROLECERT_ERR_COSE = -1,       /* not a COSE_Sign1 / truncated / trailing bytes */
    DTN_ROLECERT_ERR_PROTECTED = -2,  /* protected header is not exactly {1: -8} */
    DTN_ROLECERT_ERR_ANCHOR_FP = -3,  /* kid ≠ SHA-256(pinned anchor pub)[0:8] */
    DTN_ROLECERT_ERR_SIGNATURE = -4,  /* Ed25519 verify failed */
    DTN_ROLECERT_ERR_SCHEMA = -5,     /* map shape: keys, types, extra/missing pairs */
    DTN_ROLECERT_ERR_VERSION = -6,    /* v != 1 */
    DTN_ROLECERT_ERR_ROLE = -7,       /* role outside the closed §2.3 set / duplicate */
    DTN_ROLECERT_ERR_LEVEL = -8,      /* level > 3 or the 0-iff-roles-empty rule */
    DTN_ROLECERT_ERR_BINDING = -9,    /* node_eid is not node_key's fingerprint */
    DTN_ROLECERT_ERR_TS = -10,        /* issued/expires sanity (incl. > now+300) */
    DTN_ROLECERT_ERR_SEQ = -11,       /* seq < 1 */
    DTN_ROLECERT_EXPIRED = 1,         /* verified, but expires_ts < now */
};

typedef struct {
    char eid[DTN_NODEID_EID_MAX + 1]; /* dtn://og.<16 hex>/ + NUL */
    uint8_t node_key[32];
    char roles[DTN_ROLECERT_ROLES_CAP][DTN_ROLECERT_ROLE_MAX];
    size_t role_count; /* 0 = revocation record (§2.5 rule 4) */
    unsigned level;
    int64_t issued_ts;
    int64_t expires_ts;
    uint64_t seq;
} dtn_rolecert;

/* dtn_rolecert_expired — rule-5 boundary: expires < now (strictly). */
int dtn_rolecert_expired(const dtn_rolecert *c, int64_t now);

/* dtn_rolecert_has_role — membership in the parsed roles array. */
int dtn_rolecert_has_role(const dtn_rolecert *c, const char *role);

/* dtn_rolecert_verify — parse + fully verify a COSE_Sign1 role certificate
 * against the PINNED anchor public key at wall clock `now`. On
 * DTN_ROLECERT_OK (or DTN_ROLECERT_EXPIRED) *out holds the parsed cert.
 * One result code per failure class — the codes the shared vectors' Go
 * side prints (bad_signature, wrong_anchor_fp, expired, ...). */
int dtn_rolecert_verify(const uint8_t *cose, size_t len,
                        const uint8_t anchor_pub[32], int64_t now,
                        dtn_rolecert *out);

/* --- the §2.5 merge cache (offline-maintenance §3.4, verbatim) ------------- */

#define DTN_ROLECERT_CACHE_CAP 8 /* per-node slots; an island's honest v1 bound */

/* Merge outcomes (the shared vectors' "expect" values). */
enum {
    DTN_ROLECERT_MERGE_REPLACED = 0,
    DTN_ROLECERT_MERGE_STALE_DROPPED = 1,
    DTN_ROLECERT_MERGE_CONFLICT_KEPT = 2,
    DTN_ROLECERT_MERGE_UNCHANGED = 3, /* byte-identical redelivery: no counters */
    DTN_ROLECERT_MERGE_EXPIRED_DROPPED = 4, /* rule 5: absent, not stored */
    DTN_ROLECERT_MERGE_INVALID = 5,   /* verification failed; .reason holds the code */
};

typedef struct {
    dtn_rolecert cert;
    uint8_t raw[DTN_ROLECERT_MAX]; /* exact received bytes (conflict compares) */
    size_t raw_len;
} dtn_rolecert_slot;

typedef struct {
    dtn_rolecert_slot slots[DTN_ROLECERT_CACHE_CAP]; /* packed from 0 */
    size_t used;
    uint64_t stale_dropped; /* rule 2 — RAM-only, resets on restart */
    uint64_t conflicts;     /* rule 3 — the ATTACK SIGNAL; nonzero is loud */
} dtn_rolecert_cache;

typedef struct {
    int outcome;  /* DTN_ROLECERT_MERGE_* */
    int reason;   /* verify code when outcome == DTN_ROLECERT_MERGE_INVALID */
    int revoked;  /* effective cert is a revocation record (roles empty) */
} dtn_rolecert_merge_status;

void dtn_rolecert_cache_init(dtn_rolecert_cache *c);

/* dtn_rolecert_cache_merge — verify cose against anchor_pub, then apply
 * the §2.5 rules for its node_eid. Never touches state on failure. */
int dtn_rolecert_cache_merge(dtn_rolecert_cache *c, const uint8_t *cose, size_t len,
                             const uint8_t anchor_pub[32], int64_t now,
                             dtn_rolecert_merge_status *out);

/* Effective states at a wall clock (§2.5 rules 4-5). */
enum {
    DTN_ROLECERT_STATE_ABSENT = 0,
    DTN_ROLECERT_STATE_AUTHORITY = 1,
    DTN_ROLECERT_STATE_REVOKED = 2,
    DTN_ROLECERT_STATE_EXPIRED = 3,
};

/* dtn_rolecert_cache_effective — interpret the cached cert at `now`.
 * Returns one of the DTN_ROLECERT_STATE_* codes; *out (may be NULL) is the
 * cached cert when the state is not ABSENT. */
int dtn_rolecert_cache_effective(const dtn_rolecert_cache *c, const char *eid,
                                 int64_t now, const dtn_rolecert **out);

#endif /* DTN_ROLECERT_H */
