/* dtn_bundle.h — the Offgrid BPv7 profile codec (docs/node-network.md §3,
 * issue #33 P3.2) for the dtn_core portable core. C99 mirror of
 * node/internal/bundle/bundle.go: encode/parse/validate per rules P-1..P-7,
 * the §3.1 hop rewrite, the P-7 bundle id — the same rejection table with
 * the same stable failure codes, pinned to Go through the shared vectors of
 * tests/vectors/bundle/vectors.json (generated header:
 * host/tests/bundle_vectors.h). The C side NEVER invents acceptance where
 * Go rejects.
 *
 * Profile shape (frozen):
 *   bundle     = primary ‖ payload                       (exactly 2 blocks)
 *   primary    = [7, 0, 1, destination, source, report-to,
 *                 [creationDTNms, sequence], lifetime] + CRC-16/X.25
 *   payload    = [1, 0, 0, 1, bstr(content)] + CRC-16/X.25
 *   content    = hop(1 B, ≤ 7) ‖ PDU
 *   bundle_id  = SHA-256(PDU)                            (PDU = after hop)
 *   EIDs       = dtn:none → null; group dtn:<token> → ["", "<token>"];
 *                node/admin dtn://<auth>/ → ["<auth>", ""]
 *   canonical  = RFC 8949 preferred serialization, definite lengths only
 *
 * Parsing yields VIEWS into the caller's PDU (zero copy); the views stay
 * valid as long as the input buffer does. Encoding writes into a
 * caller-owned buffer (no malloc anywhere). No ESP-IDF in the host path. */
#ifndef DTN_BUNDLE_H
#define DTN_BUNDLE_H

#include <stddef.h>
#include <stdint.h>

#define DTN_BUNDLE_HOP_LIMIT 7
#define DTN_BUNDLE_ID_LEN 32
/* EID authority/ssp buffers: tokens are capped at 63 chars ("og." + 16 hex
 * fingerprints fit comfortably); longer parts can never be valid. */
#define DTN_BUNDLE_EID_MAX 64
/* dtn_epoch_unix: 2000-01-01T00:00:00Z (RFC 9171 §4.2.9). */
#define DTN_BUNDLE_DTN_EPOCH_S 946684800LL
/* MaxFutureSkew (P-6): 300 s. */
#define DTN_BUNDLE_MAX_FUTURE_SKEW_S 300

/* Stable failure codes — the shared vocabulary of the Go rejection table
 * (node/internal/bundle/bundle.go Code* constants) and of the vectors'
 * expect_code fields. dtn_bundle_strerr renders them; NEVER rename a code
 * without regenerating the vectors and the Go side in the same change. */
enum {
    DTN_BUNDLE_OK = 0,
    DTN_BUNDLE_ERR_TRUNCATED = -1,
    DTN_BUNDLE_ERR_STRUCTURE = -2,
    DTN_BUNDLE_ERR_VERSION = -3,
    DTN_BUNDLE_ERR_FLAGS = -4,
    DTN_BUNDLE_ERR_CRC = -5,
    DTN_BUNDLE_ERR_BLOCK_COUNT = -6,
    DTN_BUNDLE_ERR_BLOCK_TYPE = -7,
    DTN_BUNDLE_ERR_NON_CANONICAL = -8,
    DTN_BUNDLE_ERR_EID = -9,
    DTN_BUNDLE_ERR_HOP = -10,
    DTN_BUNDLE_ERR_SKEW = -11,
    DTN_BUNDLE_ERR_LIFETIME = -12,
    DTN_BUNDLE_ERR_EMPTY_PAYLOAD = -13,
    DTN_BUNDLE_ERR_NOSPACE = -14,
    DTN_BUNDLE_ERR_ARGUMENT = -15,
};

typedef struct {
    int none; /* 1 = dtn:none (CBOR null; authority/ssp unused) */
    char authority[DTN_BUNDLE_EID_MAX]; /* node/admin form ("og.<fp>", "og-admin") */
    char ssp[DTN_BUNDLE_EID_MAX];       /* group form ("og-mail") */
} dtn_bundle_eid;

typedef struct {
    dtn_bundle_eid destination;
    dtn_bundle_eid source;
    dtn_bundle_eid report_to;
    uint64_t creation_dtn_ms; /* DTN time, ms since 2000-01-01Z */
    uint64_t sequence;        /* 0 for mail, per-source counter for identified */
    uint64_t lifetime;        /* seconds (P-6: the envelope TTL) */
    uint8_t hop;              /* the hop octet, 0..7 (§3.1) */
    /* PDU after the hop octet — a VIEW into the parse input (parse) or the
     * caller's bytes (constructors); not NUL-terminated. */
    const uint8_t *payload;
    size_t payload_len;
    /* Wire locations (parse): the payload block starts at primary_len and
     * the hop octet sits at content_off (§3.1's envelope-at-offset-1 pin:
     * the envelope is pdu[content_off + 1 .. content_off + payload_len]). */
    size_t primary_len;
    size_t content_off;
} dtn_bundle;

/* dtn_bundle_strerr renders a stable code string ("truncated",
 * "bad_crc", ...) matching Go's ErrorCode vocabulary; "?" for unknown. */
const char *dtn_bundle_strerr(int code);

/* dtn_bundle_crc16 is CRC-16/X.25 (reflected poly 0x8408, init 0xFFFF,
 * xorout 0xFFFF) — BPv7's CRC type code 1. Catalogue check over
 * "123456789" is 0x906E. */
uint16_t dtn_bundle_crc16(const uint8_t *b, size_t n);

/* dtn_bundle_eid_parse parses the three profile URI shapes ("dtn:none",
 * "dtn:<token>", "dtn://<authority>/") into an EID; rejects everything
 * else. dtn_bundle_eid_format renders back the same string. */
int dtn_bundle_eid_parse(const char *s, dtn_bundle_eid *out);
int dtn_bundle_eid_format(const dtn_bundle_eid *e, char *out, size_t cap);

/* dtn_bundle_mail builds the anonymous mail bundle (P-4): destination
 * dtn:og-mail, source and report-to dtn:none, sequence 0, lifetime = ttl_s,
 * payload = the envelope verbatim (view — keep it alive until encode). */
int dtn_bundle_mail(const uint8_t *envelope, size_t envelope_len,
                    int64_t created_unix_ms, uint64_t ttl_s, dtn_bundle *out);

/* dtn_bundle_mgmt builds an identified bundle (P-5): src_eid must be a node
 * EID (dtn://og.<fp>/), dst_eid a node or group/admin EID (never anonymous),
 * report-to dtn:none, payload = the inner PDU verbatim (view). */
int dtn_bundle_mgmt(const char *src_eid, const char *dst_eid,
                    int64_t created_unix_ms, uint64_t lifetime_s, uint64_t seq,
                    const uint8_t *inner, size_t inner_len, dtn_bundle *out);

/* dtn_bundle_encode serializes b into out (caller-owned, cap bytes),
 * re-validating every profile rule first — an invalid bundle never reaches
 * the wire. *out_len receives the PDU length. */
int dtn_bundle_encode(const dtn_bundle *b, uint8_t *out, size_t cap,
                      size_t *out_len);

/* dtn_bundle_parse decodes and fully validates a PDU; now_unix_s is the
 * receiver's clock for the P-6 skew rule (creation ≤ now + 300 s). The
 * views in *out point into pdu. */
int dtn_bundle_parse(const uint8_t *pdu, size_t len, int64_t now_unix_s,
                     dtn_bundle *out);

/* dtn_bundle_rewrite_hop is the §3.1 relay operation: increment the hop
 * octet, recompute ONLY the payload block's CRC, write the new PDU to out
 * (cap bytes). The primary block and the payload bytes at offset 1 are
 * never touched. Refuses at hop == 7 (drop semantics), hop > 7 and on any
 * parse failure. The skew rule is deliberately NOT applied here: it is the
 * admission check (P-6), evaluated once at reception. */
int dtn_bundle_rewrite_hop(const uint8_t *pdu, size_t len, uint8_t *out,
                           size_t cap, size_t *out_len);

/* dtn_bundle_id computes the P-7 dedup key of a valid bundle: SHA-256 over
 * the payload content AFTER the hop octet (hop rewrites never change it). */
int dtn_bundle_id(const uint8_t *pdu, size_t len,
                  uint8_t out[DTN_BUNDLE_ID_LEN]);

#endif /* DTN_BUNDLE_H */
