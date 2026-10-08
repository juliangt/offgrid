/* dtn_dirfed.h — the directory-federation verifier/merger for the dtn_core
 * portable core (docs/node-network.md §9.3, issue #33 P3.8).
 *
 * The C side mirrors node/internal/directory exactly: dtn_dirfed_verify
 * checks offline-maintenance §3.1's canonical-JSON identity card with its
 * detached Ed25519 self-signature — the §3.2/§3.3 mule/HTTP bytes verbatim,
 * one serialization across transports (the node-network.md §9.3 freeze) —
 * and dtn_dirfed_merge applies the §3.4 merge rules
 * VERBATIM against the dtn_store_dir_* storage (the same rows the HTTP
 * register path writes — the property that makes a federated row
 * indistinguishable from a registered one for the SPA).
 *
 * The check ORDER and the verdict/outcome vocabulary mirror Go; the shared
 * vectors (tests/vectors/directory/vectors.json via the generated
 * host/tests/directory_vectors.h) pin both implementations to the same
 * bytes, the same verdicts and the same post-merge row states.
 *
 * Honest scope note (the §11 row-k boundary): the §3.4 EVICTION branch
 * (evicting the oldest federated rows under a hard table cap) is the Pi
 * side's storage policy (storage.MergeFederatedCard, against the 5000-row
 * cap). Here the merge takes an optional row_cap (≤ 0 = unlimited) and
 * refuses a new identity at a full table with DTN_DIRFED_DROP_AT_CAP — the
 * flash adapter owns any eviction of its bounded RAM index at hardware
 * bring-up, exactly like the honest bundle-store cap. */
#ifndef DTN_DIRFED_H
#define DTN_DIRFED_H

#include <stddef.h>
#include <stdint.h>

#include "dtn_store.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The §3.1 whole-card admission cap: the serialized canonical-JSON card
 * MUST be ≤ 1024 bytes at every admission point. */
#define DTN_DIRFED_MAX 1024

/* The §4.3 skew rule applied to created_ts (§3.1: "≤ merge time + 300"). */
#define DTN_DIRFED_MAX_SKEW 300

/* Verdicts of dtn_dirfed_verify — the C twins of the Go error classes the
 * vectors pin (the strings live only in Go; the vectors reference these
 * enum values). */
enum {
    DTN_DIRFED_OK = 0,
    DTN_DIRFED_ERR_SHAPE = -1, /* not a §9.3 card object (shape/kid/fields) */
    DTN_DIRFED_ERR_SIG = -2,   /* the self-signature check failed */
    DTN_DIRFED_ERR_SKEW = -3,  /* created_ts more than 300 s ahead of now */
};

/* §3.4 merge outcomes — the C twins of the Go MergeOutcome strings. */
enum {
    DTN_DIRFED_INSERT = 0,      /* rule 1: absent pubkey → new federated row */
    DTN_DIRFED_REPLACE = 1,     /* rule 2: higher seq → alias/x25519/card replaced */
    DTN_DIRFED_STALE = 2,       /* rule 3: lower seq → dropped, row untouched */
    DTN_DIRFED_DUPLICATE = 3,   /* rule 4: equal seq, byte-equal → no-op */
    DTN_DIRFED_CONFLICT = 4,    /* rule 4: equal seq, differing → keep existing */
    DTN_DIRFED_DROP_AT_CAP = 5, /* rule 1 at a full table (row_cap) → dropped */
    DTN_DIRFED_MERGE_ERR = -10, /* store I/O failure */
};

/* A parsed card (valid after DTN_DIRFED_OK). Fixed-size copy-out: nothing
 * views into the caller's cose buffer. */
typedef struct {
    unsigned v;
    char alias[25];
    uint8_t ed[32];  /* the identity key — the §3.4 dedup key */
    uint8_t x[32];   /* the encryption key (carried data, §9.3) */
    int64_t created_ts;
    uint64_t seq;    /* ≥ 1 — the §3.4 merge ordering key */
} dtn_dirfed_card;

/* dtn_dirfed_parse — the SHAPE half (§3.2's blind validation): exact
 * member set (6 pairs, uint keys 0..5 in order), v == 1, the §8.1 alias
 * regex, 32-byte keys, created_ts > 0, seq ≥ 1, the kid = SHA-256(ed)[0:8]
 * fingerprint equality, the whole card ≤ DTN_DIRFED_MAX. NO signature
 * check, NO skew check. */
int dtn_dirfed_parse(const uint8_t *cose, size_t len, dtn_dirfed_card *out);

/* dtn_dirfed_verify — parse + the Ed25519 self-signature over the
 * RFC 9052 Sig_structure with the card's OWN key + the §3.1 created_ts
 * skew rule against the receiver's clock. This is the one trust step the
 * federation input gets (§3.4 preamble). */
int dtn_dirfed_verify(const uint8_t *cose, size_t len, int64_t now,
                      dtn_dirfed_card *out);

/* dtn_dirfed_merge — verify, then the §3.4 rules against st's directory:
 *   rule 1  absent pubkey → INSERT (alias/x25519/card from the card,
 *           last_seen/epoch server-set from now, source = 1);
 *   rule 2  stored sequence (a NULL card has the implied sequence 0)
 *           lower → REPLACE alias/x25519/card, refresh last_seen/epoch,
 *           source untouched (rule 5: promotion is one-directional);
 *   rule 3  higher stored sequence → STALE (the row is not even touched);
 *   rule 4  equal sequence: byte-equal card → DUPLICATE; differing →
 *           CONFLICT (keep the existing row — the old key survives);
 *   rule 1  at row_cap (> 0) rows → DROP_AT_CAP (see the header note).
 * Returns the outcome, or a negative verify verdict (no row is touched
 * when the card does not verify). */
int dtn_dirfed_merge(dtn_store *st, const uint8_t *cose, size_t len,
                     int64_t now, int32_t row_cap);

#ifdef __cplusplus
}
#endif

#endif /* DTN_DIRFED_H */
