/* dtn_envelope.h — the DTN envelope (§3) and the server-side validation of
 * §10.5 as generalized by §15.3.
 *
 * The node is a blind intermediary: validation is structural only — no
 * decryption, no signature verification, no id recomputation (§6.2). The
 * decision set here is byte-parity with node/internal/envelope/envelope.go;
 * the spec fixture vectors (§3.2/§6.2) pin it in the host tests. */
#ifndef DTN_ENVELOPE_H
#define DTN_ENVELOPE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dtn_limits.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Max JSON lengths of the string fields (§3.1). id: 64 hex; dest_hint: 16
 * hex; payload: 536 base64 chars. A longer input can never be valid; the
 * parser fails the field fast instead of buffering it (bounded RAM, §4 of
 * docs/esp32-design.md). */
#define DTN_ID_LEN 64
#define DTN_DEST_HINT_LEN 16

typedef struct {
    int64_t v;                          /* format version, in {1, 2} */
    char id[DTN_ID_LEN + 1];            /* 64 lowercase hex */
    char dest_hint[DTN_DEST_HINT_LEN + 1]; /* 16 lowercase hex */
    int64_t created_at;                 /* unix seconds */
    int64_t ttl;                        /* seconds, [DTN_TTL_MIN, DTN_TTL_MAX] */
    char payload[DTN_PAYLOAD_B64_MAX + 1]; /* padded standard Base64 */
    size_t payload_len;
    /* meta bookkeeping (§15.1/§15.3): meta_flags != 0 means a meta member was
     * present at parse time; meta_orig_v_present/meta_orig_v carry the only
     * field v2 validation reads. meta itself is NEVER persisted or served
     * (§15.3). */
    uint8_t meta_flags;                 /* 1 = meta present */
    uint8_t meta_orig_v_present;
    int64_t meta_orig_v;
} dtn_envelope;

/* Validation outcomes, ordered exactly as the Go Validate() checks so the
 * first-failure reason is identical (not that the node reveals it — a
 * failing envelope fails the whole sync batch with 400 invalid_envelope,
 * §10.4). */
typedef enum {
    DTN_ENV_OK = 0,
    DTN_ENV_ERR_VERSION,        /* v outside the supported set {1, 2} */
    DTN_ENV_ERR_META,           /* meta present on v1, or not an object, or
                                   meta.orig_v present and != 1 (v2) */
    DTN_ENV_ERR_ID,             /* not 64 lowercase hex */
    DTN_ENV_ERR_DEST_HINT,      /* not 16 lowercase hex */
    DTN_ENV_ERR_CREATED_AT,     /* <= 0 or > now + 300 */
    DTN_ENV_ERR_TTL,            /* outside [3600, 2592000] */
    DTN_ENV_ERR_PAYLOAD         /* not valid padded standard Base64, or
                                   decoded length outside [248, 400] */
} dtn_env_err;

/* Validate one envelope against every §10.5 rule (version set, per-version
 * meta rules, regexes, timestamps, TTL range, Base64 payload with decoded
 * length bounds). now is the node's current unix time in seconds. */
dtn_env_err dtn_envelope_validate(const dtn_envelope *e, int64_t now);

/* ^[0-9a-f]{64}$ / ^[0-9a-f]{16}$ — exact-length lowercase hex checks. */
bool dtn_is_hex_n(const char *s, size_t n);

/* ^[A-Za-z0-9_.-]{1,24}$ (§4.1/§8.1) — enforced on directory writes. */
bool dtn_valid_alias(const char *s);

/* Padded standard Base64 decoding to exactly want bytes (§10.3 keys, §4.6
 * prekey members): rejects \r/\n, non-canonical padding, wrong length. */
bool dtn_valid_base64_of_len(const char *s, size_t want);

/* Serialize the six core fields in the fixed §3.1 order (compact JSON, no
 * whitespace, Go-style minimal escaping — the field alphabets make escaping
 * unreachable, but the writer is total anyway). Returns bytes written or
 * -1 on out-cap. Used for pull responses and store records. */
long dtn_envelope_write_json(char *out, size_t cap, const dtn_envelope *e);

#ifdef __cplusplus
}
#endif

#endif /* DTN_ENVELOPE_H */
