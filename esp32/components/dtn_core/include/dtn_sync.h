/* dtn_sync.h — the §10.4 POST /api/v1/sync processing order as a streaming,
 * fail-closed state machine.
 *
 * The body is fed in chunks through the dtn_json reader; at most one envelope
 * is staged at a time (the 1 MiB body is never resident — docs/esp32-design.md
 * §2). Envelopes are handed to a storage sink INSIDE a pending batch; the
 * sink's abort() discards the batch, so any rejection leaves nothing stored —
 * the observable contract of the Go node's single SQLite transaction per
 * sync (§10.4 step 2; the flash analogue is documented in §4 of the design
 * note).
 *
 * Error resolution reproduces the reference node's decision order exactly:
 * first the whole-body JSON validity (decoding), then limit, then known_ids
 * count, then known_ids format, then push count, then the per-source-IP
 * envelope budget (withdrawn by the CALLER before finish — §10.1 order),
 * then per-envelope validity, then storage errors, then commit. The first
 * surviving violation is the answer; everything earlier in the stream has
 * already been rolled back. */
#ifndef DTN_SYNC_H
#define DTN_SYNC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dtn_envelope.h"
#include "dtn_json.h"
#include "dtn_limits.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    DTN_SYNC_OK = 0,
    DTN_SYNC_ERR_BODY_TOO_LARGE,   /* 413 body_too_large */
    DTN_SYNC_ERR_JSON,             /* 400 invalid_json */
    DTN_SYNC_ERR_INVALID_LIMIT,    /* 400 invalid_limit */
    DTN_SYNC_ERR_TOO_MANY_KNOWN,   /* 400 too_many_known_ids */
    DTN_SYNC_ERR_INVALID_KNOWN,    /* 400 invalid_known_id */
    DTN_SYNC_ERR_TOO_MANY_PUSH,    /* 400 too_many_envelopes */
    DTN_SYNC_ERR_RATE_LIMITED,     /* 429 rate_limited */
    DTN_SYNC_ERR_INVALID_ENVELOPE, /* 400 invalid_envelope */
    DTN_SYNC_ERR_NODE_FULL,        /* 429 node_full (§8.1 cap) */
    DTN_SYNC_ERR_STORAGE,          /* 507 storage_unavailable */
} dtn_sync_err;

/* Storage sink — the flash store (phase 2) implements this. begin brackets a
 * pending batch; put appends one envelope; commit makes it visible; abort
 * discards it. put returns 0 on success, -1 on a storage failure (507) and
 * -2 when the §8.1 envelope cap is reached (429 node_full — nothing is
 * stored, nothing evicted). All others return 0 on success, -1 on failure. */
typedef struct {
    void *ud;
    int (*begin)(void *ud);
    int (*put)(void *ud, const dtn_envelope *e, int *absorbed);
    int (*commit)(void *ud);
    void (*abort)(void *ud);
} dtn_sync_sink;

/* Caller-provided storage for the pulled-side known_ids (≤ 500 × 65 B). */
typedef struct {
    char (*ids)[DTN_ID_LEN + 1];
    uint16_t cap;
    uint16_t count;
} dtn_known_ids;

typedef struct dtn_sync {
    dtn_json_parser json;
    dtn_sync_sink sink;
    dtn_known_ids *known;
    int64_t now;

    /* request-scoped facts */
    dtn_sync_err verdict; /* the resolved answer, set by dtn_sync_finish */
    int64_t pushed_count;
    int64_t absorbed_count;
    bool have_limit;
    int64_t limit_val;
    bool body_too_large;
    bool json_err;
    bool known_too_many;
    bool known_invalid;
    bool too_many_push;
    bool env_invalid;
    bool node_full;
    bool storage_err;
    bool batch_open;

    /* streaming state */
    int st;              /* processor state */
    int cur_top_key;     /* which top-level member the value belongs to */
    int cur_env_key;     /* which envelope member the value belongs to */
    int skip_return;     /* state to return to after a skipped subtree */
    int skip_depth;      /* nested containers inside a skipped subtree */
    dtn_envelope env;    /* envelope under assembly */
    struct {
        bool id_ovf, hint_ovf, payload_ovf;
        bool meta_not_obj, meta_origv_bad;
    } flags;
} dtn_sync;

void dtn_sync_init(dtn_sync *s, int64_t now, const dtn_sync_sink *sink,
                   dtn_known_ids *known);

/* Feed one chunk of the request body. Returns DTN_JSONFEED_OK (keep
 * feeding), DTN_JSONFEED_DONE (the top-level value is complete; further
 * input is ignored — the caller still drains the socket), or an error. */
dtn_json_feed_result dtn_sync_feed(dtn_sync *s, const char *data, size_t len);

/* Bytes consumed for the first top-level value (for the caller's 1 MiB
 * accounting — only bytes the decoder actually needs count, encoding/json
 * parity). */
size_t dtn_sync_consumed(const dtn_sync *s);

/* True once the top-level value is complete. */
bool dtn_sync_done(const dtn_sync *s);

/* Resolve the request. budget_allowed: the caller withdrew the pushed-
 * envelope budget for dtn_sync_pushed(s) envelopes first (pull-only syncs
 * cost nothing, §10.1); pass false when the budget refused the batch.
 * Commits (or aborts) the storage batch as dictated by the precedence. */
dtn_sync_err dtn_sync_finish(dtn_sync *s, bool budget_allowed);

/* Facts for the response and the §10.7 counters (valid after finish). */
int64_t dtn_sync_pushed(const dtn_sync *s);
int64_t dtn_sync_absorbed(const dtn_sync *s);
int64_t dtn_sync_limit(const dtn_sync *s);   /* resolved: default 50 */
const dtn_known_ids *dtn_sync_known(const dtn_sync *s);

#ifdef __cplusplus
}
#endif

#endif /* DTN_SYNC_H */
