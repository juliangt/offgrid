/* dtn_frame.h — the §5.4 node-plane link frame and bundle window.
 *
 * Frame (frozen byte layout, 1.3.0 precision note in the spec):
 *
 *   header(1) ‖ payload ‖ [AEAD tag for session types]
 *
 *   header:  bit 7..6 version (1) | bit 5..3 type | bit 2..0 flags (0 in v1)
 *   types:   0 = beacon, 1 = session, 2 = mail-win, 3 = bundle-frag
 *
 * Encrypted types protect the payload with the §6.2 session AEAD, the
 * header byte as AAD; the wire payload is nonce(13) ‖ ct ‖ tag(16) and the
 * plaintext budget per frame is 222 B (the bundle-frag window: 1 B window
 * header + 221 B window content). Beacons are plaintext with the fixed
 * content version(1) ‖ fingerprint(8). On-air maximum: 252 B ≤ the SX126x
 * 255-byte radio limit.
 *
 * Window: bundle chunks ride as bundle-frag payloads behind a 1-byte
 * window header of the §14.3(a) grammar — win_id(4) | idx(2) | total(2),
 * the 2-bit field carrying total−1 so counts 1..4 fit — with ≤ 221 B of
 * bundle bytes per frame and at most 4 frames per window. The
 * reassembler accepts interleaved windows keyed by win_id, completes
 * in-order or out-of-order, refuses duplicate indices, and expires
 * partial windows after the caller's timeout (the bundle's TTL). A lost
 * frame never corrupts sibling windows. Go mirror: node/internal/link
 * (frame.go / window.go); the shared vectors pin both sides.
 */
#ifndef DTN_FRAME_H
#define DTN_FRAME_H

#include <stddef.h>
#include <stdint.h>

#include "dtn_session.h"

#define DTN_FRAME_VERSION 1
#define DTN_FRAME_PAYLOAD_MAX 222   /* plaintext budget per frame */
#define DTN_FRAME_ONAIR_MAX 252     /* 1 + 13 + 222 + 16 */
#define DTN_FRAME_BEACON_LEN 9      /* version(1) ‖ fingerprint(8) */

typedef enum {
    DTN_FRAME_BEACON = 0,
    DTN_FRAME_SESSION = 1,
    DTN_FRAME_MAIL_WIN = 2,
    DTN_FRAME_BUNDLE_FRAG = 3,
} dtn_frame_type;

/* Verdicts (stable codes; the shared frame vectors pin the mapping). */
enum {
    DTN_FRAME_OK = 0,
    DTN_FRAME_ERR_TRUNCATED = -1,
    DTN_FRAME_ERR_VERSION = -2,
    DTN_FRAME_ERR_TYPE = -3,
    DTN_FRAME_ERR_FLAGS = -4,
    DTN_FRAME_ERR_OVERSIZE = -5,
    DTN_FRAME_ERR_AUTH = -6,
    DTN_FRAME_ERR_STATE = -7,
};

uint8_t dtn_frame_encode_header(dtn_frame_type type, uint8_t flags);
/* dtn_frame_parse_header: 0 = OK; negative = the stable code above. */
int dtn_frame_parse_header(uint8_t h, dtn_frame_type *type, uint8_t *flags);

/* Plaintext frames (beacons). out needs 1 + payload_len bytes. */
int dtn_frame_encode(dtn_frame_type type, const uint8_t *payload, size_t payload_len,
                     uint8_t *out, size_t *out_len);
/* Splits header ‖ payload WITHOUT authenticating (beacons; session types
 * go through dtn_frame_open). payload is a view into the input. */
int dtn_frame_parse(const uint8_t *in, size_t in_len,
                    dtn_frame_type *type, const uint8_t **payload, size_t *payload_len);

/* Session frames: out = header(1) ‖ nonce(13) ‖ ct ‖ tag(16); out needs
 * 30 + payload_len bytes; payload_len ≤ 222. */
int dtn_frame_seal(dtn_link_session *s, dtn_frame_type type,
                   const uint8_t *payload, size_t payload_len,
                   uint8_t *out, size_t *out_len);
/* Authenticates and opens: writes payload_len = in_len − 30 to out. */
int dtn_frame_open(dtn_link_session *s, const uint8_t *in, size_t in_len,
                   dtn_frame_type *type, uint8_t *out, size_t *out_len);

/* Beacon content (fixed): version ‖ the node's 8-byte fingerprint. */
void dtn_frame_beacon(const uint8_t fingerprint[DTN_LINK_FP_LEN], uint8_t out[DTN_FRAME_BEACON_LEN]);
int dtn_frame_parse_beacon(const uint8_t *payload, size_t payload_len,
                           uint8_t fingerprint[DTN_LINK_FP_LEN]);

/* ------------------------------------------------------------------ */
/* Bundle window (§5.4)                                                */
/* ------------------------------------------------------------------ */

#define DTN_WIN_PAYLOAD_PER_FRAME 221
#define DTN_WIN_MAX_TOTAL 4
#define DTN_WIN_MAX_BYTES (DTN_WIN_PAYLOAD_PER_FRAME * DTN_WIN_MAX_TOTAL)
#define DTN_WIN_MAX_ACTIVE 16

uint8_t dtn_win_header(uint8_t win_id, uint8_t idx, uint8_t total);
/* Splits the 1-byte header; total is the DECODED count (1..4). */
int dtn_win_parse_header(uint8_t h, uint8_t *win_id, uint8_t *idx, uint8_t *total);

/* dtn_win_split chunks content into bundle-frag payloads (window header ‖
 * ≤ 221 B); out_frames receives up to 4 frame pointers, each into out.
 * Returns the frame count, or DTN_FRAME_ERR_OVERSIZE when the content
 * needs more than 4 frames (refuse, never grow the window). */
int dtn_win_split(uint8_t win_id, const uint8_t *content, size_t content_len,
                  uint8_t *out, size_t out_cap,
                  const uint8_t *frames[DTN_WIN_MAX_TOTAL], size_t frame_lens[DTN_WIN_MAX_TOTAL]);

/* Reassembler verdicts per push (the shared window vectors pin them). */
typedef enum {
    DTN_WIN_PARTIAL = 0,
    DTN_WIN_DONE = 1,
    DTN_WIN_DUP = 2,    /* a CONFLICTING duplicate (different bytes for a
                         * seen idx) — corruption, refused */
    DTN_WIN_INVALID = 3,
    DTN_WIN_FULL = 4,   /* too many concurrent windows */
    DTN_WIN_DUPLICATE = 5, /* an IDENTICAL retransmission — the redundancy
                            * mechanism; idempotent, counted, not an error */
} dtn_win_verdict;

typedef struct {
    uint8_t total;
    uint8_t seen[DTN_WIN_MAX_TOTAL];
    const uint8_t *parts[DTN_WIN_MAX_TOTAL]; /* views into the pushed data */
    size_t part_lens[DTN_WIN_MAX_TOTAL];
    uint8_t got;
    uint64_t created_ms;
    uint8_t content[DTN_WIN_MAX_BYTES];
} dtn_win_state;

typedef struct {
    uint64_t timeout_ms;
    uint64_t now_ms;
    dtn_win_state windows[DTN_WIN_MAX_ACTIVE];
    uint8_t win_ids[DTN_WIN_MAX_ACTIVE];
    int active;
    uint64_t expired;    /* partial windows pruned by timeout */
    uint64_t rejected;   /* malformed or conflicting-duplicate frames dropped */
    uint64_t dup_copies; /* identical retransmissions absorbed */
} dtn_win_reassembler;

void dtn_win_reassembler_init(dtn_win_reassembler *r, uint64_t timeout_ms, uint64_t now_ms);

/* Push feeds one bundle-frag payload (window header ‖ data). On
 * DTN_WIN_DONE the byte-exact content lands in out (out_cap ≥
 * DTN_WIN_MAX_BYTES) and *out_len is set. */
dtn_win_verdict dtn_win_push(dtn_win_reassembler *r, const uint8_t *payload, size_t len,
                             uint8_t *out, size_t *out_len);

/* Expire prunes partial windows older than the timeout; returns how many. */
int dtn_win_expire(dtn_win_reassembler *r, uint64_t now_ms);
int dtn_win_active(const dtn_win_reassembler *r);

#endif /* DTN_FRAME_H */
