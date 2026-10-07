/* dtn_prekeys.h — the §10.3 blind prekeys-bundle shape validator (SAX-based,
 * allocation-free). Shape only; NO signature verification — the node never
 * verifies signatures (§1).
 *
 * Rules (§4.6/§10.3): the member set is exactly v, spk, spk_sig, ts, opks —
 * every one required; v == 1; spk padded standard Base64 of exactly 32
 * bytes; spk_sig of exactly 64 bytes; ts an integer > 0; opks an array of
 * 8..16 Base64 strings each decoding to exactly 32 bytes; the whole
 * serialized member ≤ 2048 bytes; unknown members are ignored (§15.4) but
 * still syntax-walked. Shared by dtn_store_valid_prekeys (whole-string
 * form) and the HTTP directory POST handler (embedded-member form). */
#ifndef DTN_PREKEYS_H
#define DTN_PREKEYS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dtn_json.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DTN_PREKEYS_MAX_BYTES 2048

/* Collected members of a VALID bundle — the http layer re-serializes the
 * bundle in canonical fixed order from these (the store keeps the bundle as
 * an opaque validated blob; see docs/esp32-design.md §7 on the
 * whitespace-only re-serialization deviation). */
typedef struct {
    int64_t v;
    int64_t ts;
    char spk[48];      /* Base64 of 32 B (44 chars) */
    char spk_sig[96];  /* Base64 of 64 B (88 chars) */
    char opks[16][48]; /* Base64 of 32 B each */
    int opk_count;
} dtn_prekeys_members;

typedef struct {
    dtn_json_parser json;
    bool started;
    int cur;         /* 0..4 = known member being read; -1 unknown */
    int skip_depth;  /* nested containers of an ignored member */
    bool in_opks;
    int opks_seen;
    int64_t v, ts;   /* member values (v_set/ts_set say they were seen) */
    dtn_prekeys_members *out; /* optional member capture */
    bool bad;
    bool have_spk, have_sig;
    bool v_set, ts_set, saw_opks;
} dtn_prekeys_val;

void dtn_prekeys_val_init(dtn_prekeys_val *pv, dtn_prekeys_members *out);
/* Returns DTN_JSONFEED_*; a syntax/range error marks the validator bad. */
dtn_json_feed_result dtn_prekeys_val_feed(dtn_prekeys_val *pv,
                                          const char *data, size_t len);
/* True when the fed bytes are a complete, valid §4.6 bundle. */
bool dtn_prekeys_val_ok(dtn_prekeys_val *pv);

#ifdef __cplusplus
}
#endif

#endif /* DTN_PREKEYS_H */
