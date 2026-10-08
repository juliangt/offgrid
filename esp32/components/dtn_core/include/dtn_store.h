/* dtn_store.h — the §9 storage contract on flash: a log-structured,
 * CRC-framed, power-loss-safe store behind the same logical semantics as
 * the Go node's SQLite engine (docs/esp32-design.md §4).
 *
 * Portability: implemented over plain <stdio.h>. On the ESP32 the files
 * live on a LittleFS VFS mount; on the CI host, on a temp directory — the
 * same code is what the host tests exercise.
 *
 * The sync batch API mirrors dtn_sync's sink exactly: begin/put/commit/
 * abort with the Go node's fail-closed transaction semantics — a rejected
 * or crashed batch leaves nothing behind (BATCH_BEGIN/BATCH_COMMIT log
 * records are the flash analogue of the single SQLite transaction).
 *
 * Concurrency model: like the Go node's single SQLite connection, the store
 * is single-writer — the adapter serializes all calls onto one task (or a
 * mutex); no internal locking. */
#ifndef DTN_STORE_H
#define DTN_STORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dtn_core.h"
#include "dtn_envelope.h"
#include "dtn_sync.h" /* dtn_known_ids */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct dtn_store dtn_store;

typedef enum {
    DTN_STORE_OK = 0,
    DTN_STORE_ERR_IO,        /* opens/reads/writes failed → 507 path */
    DTN_STORE_ERR_CAPACITY,  /* §8.1 cap reached → 429 node_full */
    DTN_STORE_ERR_DOWNGRADE, /* on-flash schema newer than the firmware:
                                refuse to mount, leave the store untouched
                                (§15.3 downgrade refusal — the ESP32 stance
                                is refuse-to-serve + loud log, not a
                                process exit) */
} dtn_store_err;

/* Open (or create) the store rooted at dir. envelope_capacity is the
 * enforced §8.1 cap of this board (5000 reference / 1000 minimum, honest
 * capacity reporting). Both an older schema (forward-only migration chain)
 * and a corrupt superblock (quarantine + fresh store, loud) are handled
 * here. */
dtn_store_err dtn_store_open(dtn_store **out, const char *dir,
                             int32_t envelope_capacity);
void dtn_store_close(dtn_store *st);

/* ---- sync batch (the dtn_sync sink) ---- */
int dtn_store_batch_begin(dtn_store *st); /* 0 ok, -1 io */
/* put: 0 stored, 1 absorbed (dedup hit), -1 io, -2 capacity (whole batch
 * rejected when the store is AT/over the cap at batch start; a batch
 * admitted below the cap may overshoot by up to the batch size — §8.1
 * reject-newest/keep-oldest, nothing is ever evicted). */
int dtn_store_batch_put(dtn_store *st, const dtn_envelope *e, int *absorbed);
int dtn_store_batch_commit(dtn_store *st); /* 0 ok, -1 io */
void dtn_store_batch_abort(dtn_store *st);

/* ---- pull (§10.4 step 3) ----
 * Serves live envelopes with deadline >= now (INCLUSIVE boundary), excluding
 * every known id, ordered created_at DESC then id ASC (exact SQLite TEXT
 * ordering — full ids are compared on flash for ties), at most limit.
 * served receives the count. Returns 0 ok, -1 io. */
typedef void (*dtn_pull_cb)(void *ud, const dtn_envelope *e);
int dtn_store_pull(dtn_store *st, const dtn_known_ids *known, int64_t limit,
                   int64_t now, void *cb_ud, dtn_pull_cb cb,
                   int32_t *served);

/* ---- TTL janitor (§10.6): every 15 minutes + once at boot ----
 * Deletes every envelope with created_at + ttl < now (EXCLUSIVE boundary —
 * an envelope is servable or deleted, never in limbo). deleted (optional)
 * receives the count; the store records last_cleanup_unix / -deleted and
 * bumps ttl_sweeps. Returns 0 ok, -1 io. */
int dtn_store_sweep(dtn_store *st, int64_t now, int32_t *deleted);

/* ---- directory (§10.3) ----
 * Upsert keyed by pubkey; the node sets last_seen = now and
 * epoch = now / 86400 (§6.1); prekeys_raw is the client-published bundle
 * stored VERBATIM, or NULL to clear (the §9 downgrade self-heal). Returns
 * 0 ok, -1 io. */
int dtn_store_dir_upsert(dtn_store *st, const char *alias, const char *pubkey,
                         const char *x25519, const char *prekeys_raw,
                         int64_t now);

/* The §9.3 directory-federation extension (issue #33 P3.8): the same upsert
 * with the two internal columns the merge rules need — card_b64 is the
 * identity card exactly as published (canonical Base64 of the COSE, ≤
 * DTN_DIR_CARD_B64_MAX-1 chars; NULL/"" clears, the §3.2 self-heal) and
 * source is the row provenance (0 = local upsert, 1 = federated merge —
 * §3.4 rule 5). The tail is written as an OPTIONAL record extension: frames
 * written without it (the pre-P3.8 format) parse unchanged. */
int dtn_store_dir_upsert_full(dtn_store *st, const char *alias,
                              const char *pubkey, const char *x25519,
                              const char *prekeys_raw, const char *card_b64,
                              int source, int64_t now);

/* One full directory row by pubkey (the merge's lookup): the served fields
 * plus the two internal §9.3 columns. Returns 0 found (out filled; card is
 * "" when the entry carries none), -1 absent or I/O error. */
#define DTN_DIR_CARD_B64_MAX 1372 /* Base64 of a 1024-byte card, + NUL */
typedef struct {
    char alias[25];
    char x25519[45];
    int64_t last_seen;
    int64_t epoch;
    int source; /* 0 local upsert, 1 federated merge (§3.4 rule 5) */
    char prekeys[2049]; /* the §4.6 bundle as stored, "" when none — the
                         * federated replace (rule 2) preserves it */
    char card[DTN_DIR_CARD_B64_MAX];
} dtn_dir_row;
int dtn_store_dir_find(dtn_store *st, const char *pubkey, dtn_dir_row *out);

/* GET: at most limit entries (≤ 500), ordered last_seen DESC, pubkey ASC
 * (deterministic tie-break). prekeys_cb receives NULL when the entry has no
 * bundle. served (optional) receives the count. Returns 0 ok, -1 io. */
typedef void (*dtn_dir_cb)(void *ud, const char *alias, const char *pubkey,
                           const char *x25519, int64_t last_seen,
                           int64_t epoch, const char *prekeys_or_null);
int dtn_store_dir_get(dtn_store *st, int32_t limit, void *cb_ud,
                      dtn_dir_cb cb, int32_t *served);
int32_t dtn_store_dir_count(const dtn_store *st);

/* ---- figures for capabilities/health (single-sourced identity) ---- */
int32_t dtn_store_envelope_count(const dtn_store *st);
/* store size on flash: super + envelopes.log + directory.log (the analogue
 * of db + -wal + -shm, §10.7). -1 when unavailable. */
int64_t dtn_store_db_size(const dtn_store *st);
/* live envelopes expiring within `seconds` of now (the §10.7 buckets) —
 * a pure index count that never reads row content. */
int32_t dtn_store_expiring_within(const dtn_store *st, int64_t now,
                                  int64_t seconds);
int64_t dtn_store_last_cleanup_unix(const dtn_store *st); /* 0 = none yet */
int32_t dtn_store_last_cleanup_deleted(const dtn_store *st);
int64_t dtn_store_ttl_swept_total(const dtn_store *st);
int dtn_store_schema_version_on_disk(const dtn_store *st);
bool dtn_store_pending_migration(const dtn_store *st); /* false post-open */
bool dtn_store_quarantined(const dtn_store *st); /* a corrupt store was
                                                    renamed aside at open */

/* ---- §10.3 blind prekeys admission (shape only; NO signature check —
 * the node never verifies signatures, §1). Rules: v == 1; spk Base64 of
 * exactly 32 bytes; spk_sig Base64 of exactly 64 bytes; ts integer > 0;
 * opks an array of 8..16 Base64 strings each decoding to 32 bytes; the
 * whole serialized member ≤ 2048 bytes; unknown members inside prekeys are
 * ignored (§15.4). */
bool dtn_store_valid_prekeys(const char *raw, size_t raw_len);

/* Test/verification helper: abandon the store WITHOUT the clean close path
 * — the files are left exactly as a power cut mid-batch would leave them.
 * The object and its FILE handles are intentionally leaked; call only from
 * crash-semantics tests (host suite, hardware cut-procedures). */
void dtn_store_test_crash(dtn_store *st);

#ifdef __cplusplus
}
#endif

#endif /* DTN_STORE_H */
