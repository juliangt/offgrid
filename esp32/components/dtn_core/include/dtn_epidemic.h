/* dtn_epidemic.h — the controlled epidemic contact-sync primitives of the
 * node plane (docs/node-network.md §7.1, issue #33 P3.5). C99 mirror of
 * node/internal/forward/sync.go: the Bloom contact summary and the diff,
 * pinned byte-identical to Go through the shared vectors of
 * tests/vectors/forward/vectors.json (generated header:
 * host/tests/forward_vectors.h).
 *
 * Frozen parameters (§7.1): 4096 bits (512 B), k = 4, UNSALTED — the inputs
 * are bundle_ids, opaque SHA-256 digests (P-7), so a summary reveals set
 * membership of opaque digests only. Hash derivation: for i in 0..3,
 * digest_i = SHA-256(i ‖ id); index_i = big-endian uint32 of digest_i[0..3]
 * mod 4096; bit i/8, mask 1 << (i%8) (LSB-first within a byte).
 *
 * The §7.1 v1 sync HANDSHAKE itself is a daemon-side concern (the Go
 * engine runs it over TCPCL sessions; summaries ride the bundle plane as
 * ordinary profile bundles): this module carries the pure, testable
 * primitives both implementations must agree on byte for byte.
 *
 * No malloc anywhere; no ESP-IDF in the host path. */
#ifndef DTN_EPIDEMIC_H
#define DTN_EPIDEMIC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define DTN_EPIDEMIC_BLOOM_BITS 4096
#define DTN_EPIDEMIC_BLOOM_BYTES (DTN_EPIDEMIC_BLOOM_BITS / 8) /* 512 */
#define DTN_EPIDEMIC_BLOOM_K 4
#define DTN_EPIDEMIC_ID_LEN 32

/* The §7.1 summary payload carried inside a summary bundle (after the §3.1
 * hop octet): version byte ‖ filter. Unknown versions are dropped. */
#define DTN_EPIDEMIC_SYNC_VERSION 1
#define DTN_EPIDEMIC_SUMMARY_PDU_LEN (1 + DTN_EPIDEMIC_BLOOM_BYTES)

typedef struct {
    uint8_t bits[DTN_EPIDEMIC_BLOOM_BYTES];
} dtn_bloom;

/* dtn_epidemic_bloom_indexes derives the k filter indexes of one id
 * (exposed for the vector tests; both sides must agree bit for bit). */
void dtn_epidemic_bloom_indexes(const uint8_t id[DTN_EPIDEMIC_ID_LEN],
                                uint32_t out[DTN_EPIDEMIC_BLOOM_K]);

/* dtn_bloom_init zeroes the filter. */
void dtn_bloom_init(dtn_bloom *b);

/* dtn_bloom_add inserts one id. */
void dtn_bloom_add(dtn_bloom *b, const uint8_t id[DTN_EPIDEMIC_ID_LEN]);

/* dtn_bloom_contains reports whether the filter MIGHT hold the id (false
 * positives are the §7.1 trade-off: one skipped transfer, repaired by a
 * later contact, never corruption). */
bool dtn_bloom_contains(const dtn_bloom *b, const uint8_t id[DTN_EPIDEMIC_ID_LEN]);

/* dtn_epidemic_diff computes the transfer list: every id of `ids` (n of
 * them) the summary does NOT claim, written to out (capacity out_cap ids).
 * Returns the number of missing ids (which may exceed out_cap — size the
 * buffer for the whole store or iterate). Order follows the input. */
size_t dtn_epidemic_diff(const dtn_bloom *summary,
                         const uint8_t (*ids)[DTN_EPIDEMIC_ID_LEN], size_t n,
                         uint8_t (*out)[DTN_EPIDEMIC_ID_LEN], size_t out_cap);

/* dtn_epidemic_summary_encode serializes the summary payload:
 * out[0] = version, out[1..513) = the filter bytes. */
void dtn_epidemic_summary_encode(const dtn_bloom *b, uint8_t out[DTN_EPIDEMIC_SUMMARY_PDU_LEN]);

/* dtn_epidemic_summary_parse recognizes a v1 summary payload; false for
 * any other shape (including future versions — dropped, not an error). */
bool dtn_epidemic_summary_parse(const uint8_t *payload, size_t len, dtn_bloom *out);

#endif /* DTN_EPIDEMIC_H */
