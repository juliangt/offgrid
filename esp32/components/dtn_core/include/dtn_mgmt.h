/* dtn_mgmt.h — the management plane's VERIFY/DECIDE half for the dtn_core
 * portable core (docs/node-network.md §8, issue #33 P3.6).
 *
 * The C side is a verifier by design — it never signs and never executes:
 * dtn_mgmt_decide implements the §8.2 enforcement pipeline UP TO the verdict
 * (shape → signer's cached cert → signature → target → command table →
 * level → per-signer seq freshness → expiry), and the firmware's executor
 * layer acts on DTN_MGMT_OK with the parsed dtn_mgmt_cmd. install_cert's
 * cache feed is the caller merging the parsed args cert through
 * dtn_rolecert_cache_merge (the §2.5 rules).
 *
 * The check ORDER and failure classes mirror node/internal/mgmt exactly;
 * the shared vectors (tests/vectors/mgmt/vectors.json via the generated
 * host/tests/mgmt_vectors.h) pin both implementations to the same bytes and
 * the same verdicts. */
#ifndef DTN_MGMT_H
#define DTN_MGMT_H

#include <stddef.h>
#include <stdint.h>

#include "dtn_nodeid.h"
#include "dtn_rolecert.h"

/* A verifier will not even look at a command COSE longer than this (the
 * §8.1 realistic object is ≈ 120-200 B; install_cert carries a cert). */
#define DTN_MGMT_MAX 4096

#define DTN_MGMT_CMD_MAX 32      /* command name + NUL */
#define DTN_MGMT_ARGS_MAX 8      /* the v1 args bound */
#define DTN_MGMT_ARG_KEY_MAX 32  /* args key + NUL */

/* The v1 command validity bounds (§8.1, frozen): issued ≤ now + 300
 * (the §4.3 skew) and 0 < expiry - issued ≤ 24 h. */
#define DTN_MGMT_MAX_SKEW 300
#define DTN_MGMT_MAX_VALIDITY 86400

/* The per-signer seq table bound (an island's honest v1: 8 simultaneous
 * signers; a full table fails closed). */
#define DTN_MGMT_SEQS_CAP 8

/* Verdicts — the C twins of the Go Verdict strings the vectors pin. */
enum {
    DTN_MGMT_OK = 0,
    DTN_MGMT_ERR_SHAPE = -1,    /* not a §8.1 command object */
    DTN_MGMT_ERR_SIG = -2,      /* unknown/revoked/expired signer or bad signature */
    DTN_MGMT_ERR_TARGET = -3,   /* targeted at another node */
    DTN_MGMT_ERR_UNKNOWN = -4,  /* command name outside the v1 table */
    DTN_MGMT_ERR_LEVEL = -5,    /* signer's cert level below the requirement */
    DTN_MGMT_ERR_SEQ = -6,      /* replayed / non-monotonic per-signer seq */
    DTN_MGMT_ERR_EXPIRED = -7,  /* expired or issued_ts sanity failed */
};

/* Arg kinds (the closed v1 CBOR value set: uint | tstr | bstr). */
enum {
    DTN_MGMT_ARG_UINT = 0,
    DTN_MGMT_ARG_TSTR = 1,
    DTN_MGMT_ARG_BSTR = 2,
};

typedef struct {
    char key[DTN_MGMT_ARG_KEY_MAX];
    int kind;
    uint64_t u;               /* DTN_MGMT_ARG_UINT */
    const char *str;          /* DTN_MGMT_ARG_TSTR (view into cose) */
    size_t str_len;
    const uint8_t *bytes;     /* DTN_MGMT_ARG_BSTR (view into cose) */
    size_t bytes_len;
} dtn_mgmt_arg;

/* dtn_mgmt_cmd is the parsed, VERIFIED command (valid when the verdict was
 * DTN_MGMT_OK). String/bstr members view into the caller's cose buffer. */
typedef struct {
    char cmd[DTN_MGMT_CMD_MAX];
    dtn_mgmt_arg args[DTN_MGMT_ARGS_MAX];
    size_t arg_count;
    char target[DTN_NODEID_EID_MAX + 1]; /* "" = broadcast to og-admin */
    int64_t issued_ts;
    int64_t expiry;
    uint64_t seq;
    char signer_eid[DTN_NODEID_EID_MAX + 1]; /* resolved from the COSE kid */
    unsigned level;                          /* the signer's cert level */
} dtn_mgmt_cmd;

/* --- the per-signer seq table (RAM-only, §8.2; the counter discipline of
 * §10.7 applies: it dies with the process, bounded by the 24 h validity) --- */

typedef struct {
    char eid[DTN_NODEID_EID_MAX + 1];
    uint64_t last_seq;
} dtn_mgmt_seq_slot;

typedef struct {
    dtn_mgmt_seq_slot slots[DTN_MGMT_SEQS_CAP]; /* packed from 0 */
    size_t used;
} dtn_mgmt_seqs;

void dtn_mgmt_seqs_init(dtn_mgmt_seqs *s);

/* dtn_mgmt_required_level — the frozen v1 command table (name → required
 * §2.4 level); -1 when the name is outside the table (DTN_MGMT_ERR_UNKNOWN
 * at the decision). */
int dtn_mgmt_required_level(const char *cmd);

/* dtn_mgmt_seq_last — the recorded floor for eid (0 when none; command seq
 * starts at 1, so 0 never blocks a first command). */
uint64_t dtn_mgmt_seq_last(const dtn_mgmt_seqs *s, const char *eid);

/* dtn_mgmt_seq_commit — record the floor AFTER execution (the Go side moves
 * its floor at execution too; §8.2 "must exceed the last executed"). */
int dtn_mgmt_seq_commit(dtn_mgmt_seqs *s, const char *eid, uint64_t seq);

/* dtn_mgmt_decide — the §8.2 pipeline, in the normative order, ending at a
 * verdict. On DTN_MGMT_OK the per-signer floor is committed and *out (may
 * be NULL) holds the parsed command. EVERY failure is a silent verdict —
 * the caller drops; no error packet exists in this protocol. */
int dtn_mgmt_decide(const dtn_rolecert_cache *certs,
                    const char *local_eid,
                    const uint8_t *cose, size_t len,
                    int64_t now,
                    dtn_mgmt_seqs *seqs,
                    dtn_mgmt_cmd *out);

#endif /* DTN_MGMT_H */
