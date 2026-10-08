/* dtn_bundlestore.h — the node-plane bundle store on flash
 * (docs/node-network.md §7.5, issue #33 P3.5). C99 mirror of
 * node/internal/forward/store.go: same admission pipeline (parse → hop
 * ceiling → local expiry → dedup by bundle_id → EID classification → cap
 * with priority-aware eviction), same janitor, same counters — pinned to
 * Go through the shared vectors of tests/vectors/forward/vectors.json
 * (generated header: host/tests/forward_vectors.h).
 *
 * Layout in the store directory (the §7.5 "own namespace" — the §9
 * envelope store's files are never touched):
 *   bundles.log   CRC-framed records: BPUT (id, class, hop, expires_at,
 *                 received_at, pdu) / BDEL (id). A torn tail (power loss
 *                 mid-append) truncates at open — the dtn_store pattern.
 * A RAM index (one slot per live bundle, sized by the cap) makes dedup,
 * the janitor and the eviction pick RAM walks; PDUs are fetched from the
 * log on demand — the full store is never resident.
 *
 * CAP HONESTY (§7.5): cap is decided ONCE by the caller — the board's
 * flash budget, never a fabricated number — reported by
 * dtn_bundlestore_cap, and enforced: at cap an admission either evicts (the
 * §7.3 priority rule: never evict management before mail before bulk; the
 * soonest-expiring row of the lowest-priority class at-or-below the
 * newcomer's importance) or refuses (DTN_BSTORE_AT_CAP).
 *
 * Single-writer, like dtn_store: the adapter serializes all calls onto one
 * task (or a mutex); no internal locking. No ESP-IDF in the host path. */
#ifndef DTN_BUNDLESTORE_H
#define DTN_BUNDLESTORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dtn_bundle.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DTN_BUNDLESTORE_DEFAULT_CAP 5000 /* the Pi-reference cap of §7.5 */

typedef struct dtn_bundlestore dtn_bundlestore;

typedef enum {
    DTN_BSTORE_OK = 0,
    DTN_BSTORE_ERR_IO = -1,   /* opens/reads/writes failed */
    DTN_BSTORE_ERR_ARG = -2,  /* bad argument (nil, non-positive cap) */
    DTN_BSTORE_ERR_PARSE = -3 /* the PDU is not a profile bundle */
} dtn_bstore_err;

/* Admission verdicts — the shared vocabulary of the vectors'
 * expect_verdict field ("accepted", "dup", "expired", "hop_capped",
 * "at_cap"). DTN_BSTORE_AT_CAP and the DTN_BSTORE_ERR_* codes refuse the
 * bundle; DUP/EXPIRED/HOP_CAPPED are policy drops (§7.2 — the transfer is
 * acknowledged, the cargo disposed of). */
typedef enum {
    DTN_BSTORE_ADMITTED = 0,
    DTN_BSTORE_DUP = 1,
    DTN_BSTORE_EXPIRED = 2,
    DTN_BSTORE_HOP_CAPPED = 3,
    DTN_BSTORE_AT_CAP = 4
} dtn_bstore_verdict;

/* Local priority classes of §7.3 (management > mail > bulk). Never a wire
 * field. */
typedef enum {
    DTN_BSTORE_CLASS_MGMT = 0,
    DTN_BSTORE_CLASS_MAIL = 1,
    DTN_BSTORE_CLASS_BULK = 2
} dtn_bstore_class;

/* RAM-only bookkeeping of every admission path (the §10.7 discipline). */
typedef struct {
    uint64_t accepted;
    uint64_t dup;
    uint64_t expired; /* admission-refused AND janitor-swept */
    uint64_t hop_capped;
    uint64_t at_cap_rejected;
    uint64_t evicted;
    uint64_t janitor_swept;
} dtn_bstore_counters;

/* The v1 EID-based classification (mirror of forward.Classify):
 * destination dtn://og-admin/ → management; source dtn:none and
 * destination dtn:og-mail → mail; everything else bulk. P3.6/P3.7 extend
 * the rules in both implementations together. */
dtn_bstore_class dtn_bundlestore_classify(const dtn_bundle_eid *dest,
                                          const dtn_bundle_eid *src);

/* Open (or create) the store rooted at dir (created if missing). cap is
 * the enforced §7.5 ceiling of this board (the ESP32 passes its honest
 * flash-derived number; DTN_BUNDLESTORE_DEFAULT_CAP is the Pi reference).
 * Returns DTN_BSTORE_OK, or an error and *out == NULL. */
int dtn_bundlestore_open(dtn_bundlestore **out, const char *dir, int32_t cap);
void dtn_bundlestore_close(dtn_bundlestore *st);

/* Admission (the full pipeline; mirrors forward.Store.Accept). now_unix_s
 * is the LOCAL clock for the P-6 expiry and skew rules. */
dtn_bstore_verdict dtn_bundlestore_admit(dtn_bundlestore *st,
                                         const uint8_t *pdu, size_t len,
                                         int64_t now_unix_s);

/* The live (unexpired) ids, in bundle_id ascending order — the epidemic
 * summary/diff input. Callback receives one id + its class per call. */
typedef void (*dtn_bstore_id_cb)(void *ud, const uint8_t id[DTN_BUNDLE_ID_LEN],
                                 uint8_t cls);
int dtn_bundlestore_each_live_id(dtn_bundlestore *st, int64_t now_unix_s,
                                 void *cb_ud, dtn_bstore_id_cb cb);

/* Fetch the stored PDU (byte-exact as admitted). 0 found, 1 absent,
 * DTN_BSTORE_ERR_IO on I/O or a too-small buffer (needed length via
 * *out_len when known). */
int dtn_bundlestore_get_pdu(dtn_bundlestore *st, const uint8_t id[DTN_BUNDLE_ID_LEN],
                            uint8_t *out, size_t cap, size_t *out_len);

/* The §7.5 TTL janitor (the §10.6 cadence): deletes every bundle with
 * expires_at < now (exclusive boundary — servable or deleted, never in
 * limbo). *deleted (optional) receives the count. 0 ok, -1 io. */
int dtn_bundlestore_janitor(dtn_bundlestore *st, int64_t now_unix_s, int32_t *deleted);

int32_t dtn_bundlestore_count(const dtn_bundlestore *st);
int32_t dtn_bundlestore_cap(const dtn_bundlestore *st);
void dtn_bundlestore_counters(const dtn_bundlestore *st, dtn_bstore_counters *out);

#ifdef __cplusplus
}
#endif

#endif /* DTN_BUNDLESTORE_H */
