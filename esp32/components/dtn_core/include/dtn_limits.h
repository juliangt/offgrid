/* dtn_limits.h — the binding limits table of docs/protocol.md §8.1, plus the
 * derived payload bounds of §8.2 and the admission constants of §10/§15.
 * Every value here is byte-identical to the Go reference (node/internal). */
#ifndef DTN_LIMITS_H
#define DTN_LIMITS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* §8.1 limits table. */
#define DTN_TTL_MIN 3600L           /* 1 hour */
#define DTN_TTL_MAX 2592000L        /* 30 days */
#define DTN_TTL_DEFAULT 604800L     /* 7 days (client-side default) */
#define DTN_SYNC_LIMIT_DEFAULT 50L
#define DTN_SYNC_LIMIT_MAX 200L
#define DTN_PUSH_ENVELOPES_MAX 100
#define DTN_KNOWN_IDS_MAX 500
#define DTN_BODY_MAX_BYTES 1048576L /* 1 MiB — larger → 413 */
#define DTN_ENVELOPE_CAP_MAX 5000   /* per-node cap; a board MAY enforce less (honest capacity) */
#define DTN_DIRECTORY_MAX 500       /* GET cap; 500 most recent by last_seen DESC */
#define DTN_JANITOR_INTERVAL_SECONDS 900 /* 15 minutes, plus one run at boot */

/* §4.1/§8.1 alias regex: ^[A-Za-z0-9_.-]{1,24}$ */
#define DTN_ALIAS_MAX 24

/* §8.2 derived payload bounds (decoded bytes). */
#define DTN_PAYLOAD_DECODED_MIN 248
#define DTN_PAYLOAD_DECODED_MAX 400
/* Longest padded standard Base64 string decoding to ≤ 400 bytes (§8.2). */
#define DTN_PAYLOAD_B64_MAX 536

/* §10.5 admission skew: created_at MUST NOT be more than 300 s in the future. */
#define DTN_CLOCK_SKEW_SECONDS 300L

/* §6.1 hint epoch length (seconds). */
#define DTN_HINT_EPOCH_SECONDS 86400L

/* §10.1 admission budgets (issue #16) — RAM-only, per source IP. */
#define DTN_BUDGET_REQUEST_BURST 60
#define DTN_BUDGET_REQUEST_REFILL_RATE 0.5      /* 1 request per 2 s */
#define DTN_BUDGET_ENVELOPE_BURST 600
#define DTN_BUDGET_ENVELOPE_REFILL_RATE (600.0 / 3600.0) /* 600 envelopes/h */
#define DTN_BUDGET_DIAG_BURST 60
#define DTN_BUDGET_DIAG_REFILL_RATE 1.0         /* 1 request per second */

/* §15.3 supported envelope-version set {1, 2}, ascending, no duplicates. */
#define DTN_ENVELOPE_VERSION_MIN 1
#define DTN_ENVELOPE_VERSION_MAX 2

#ifdef __cplusplus
}
#endif

#endif /* DTN_LIMITS_H */
