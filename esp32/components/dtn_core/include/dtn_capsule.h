/* dtn_capsule.h — release capsule format v1 (P3.7).
 *
 * Implements the byte-exact §2.1 format of docs/offline-maintenance.md,
 * reused VERBATIM by the node plane per docs/node-network.md §9, plus the
 * §9.4 chunk transport (header parse + reassembler). This is the C mirror
 * of node/internal/capsule: the shared vectors of tests/vectors/capsule/
 * pin both to identical §2.4.4 staging verdicts and identical §9.4
 * reassembly verdicts on identical bytes.
 *
 * FORMAT (§2.1.1):
 *   0    8   magic "OFGRIDUP"
 *   8    2   format  big-endian uint16 == 1
 *   10   4   mlen    big-endian uint32, M <= 1024
 *   14   M   metadata  UTF-8 canonical JSON, fixed member order
 *   14+M P   payload
 *   14+M+P 64  sig   Ed25519 detached over meta || payload (release key)
 *
 * The C side is a VERIFY/CONSUME consumer (like dtn_rolecert): it parses,
 * verifies, applies the §9.1 arch gate and the §2.6 anti-rollback rules,
 * and reassembles chunks. Signing lives in the offline Go capsuletool.
 *
 * HONESTY NOTE (issue #33 P3.7): staging here means the DECISION (the
 * §2.4.4 ladder through dtn_capsule_stage) — the ESP32's flash write of
 * the staged capsule and the esp_ota_ops A/B apply + health gate are
 * hardware bring-up (the `apply` callback seam of the reassembler); the
 * apply machinery itself stays the #22 operator path on the Pi.
 */
#ifndef DTN_CAPSULE_H
#define DTN_CAPSULE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Stable failure codes — the shared vocabulary of the Go and C rejection
 * tables (node/internal/capsule's Code* strings; the vectors' expect
 * fields). dtn_capsule_stage returns these; "ok" is 0. */
#define DTN_CAPSULE_OK              0
#define DTN_CAPSULE_BAD_MAGIC       1
#define DTN_CAPSULE_BAD_FORMAT      2
#define DTN_CAPSULE_BAD_LENGTH      3
#define DTN_CAPSULE_BAD_METADATA    4
#define DTN_CAPSULE_BAD_VERSION     5
#define DTN_CAPSULE_CREATED_AT_SKEW 6
#define DTN_CAPSULE_SHA_MISMATCH    7
#define DTN_CAPSULE_LEN_MISMATCH    8
#define DTN_CAPSULE_BAD_SIGNATURE   9
#define DTN_CAPSULE_STALE           10
#define DTN_CAPSULE_TOO_OLD         11
#define DTN_CAPSULE_WRONG_ARCH      12
#define DTN_CAPSULE_UNPINNED        13

/* Frozen format v1 constants (§2.1.1). */
#define DTN_CAPSULE_MAGIC_LEN  8
#define DTN_CAPSULE_HEADER_LEN 14 /* magic(8) + format(2) + mlen(4) */
#define DTN_CAPSULE_SIG_LEN    64
#define DTN_CAPSULE_MAX_MLEN   1024
#define DTN_CAPSULE_MAX_PAYLOAD (48ULL * 1024 * 1024 + 64ULL * 1024) /* the §2.4.2 cap */

/* dtn_capsule_meta — the §2.1.2 metadata block (frozen member order on the
 * wire; the fields here are the parsed values). Strings are NUL-terminated
 * copies; a string longer than its buffer refuses (BAD_METADATA) rather
 * than truncating — the v1 members are short ASCII, and the 1024-byte M
 * budget bounds them anyway. */
#define DTN_CAPSULE_SEMVER_MAX 48
#define DTN_CAPSULE_VCS_MAX    64
#define DTN_CAPSULE_ARCH_MAX   16

typedef struct {
    unsigned v;                /* MUST be 1 */
    uint64_t release;          /* the §2.6 monotonic ordering key */
    char semver[DTN_CAPSULE_SEMVER_MAX];
    char vcs[DTN_CAPSULE_VCS_MAX];
    char arch[DTN_CAPSULE_ARCH_MAX];
    uint64_t min_upgrade_from;
    int spa_embedded;          /* MUST be true */
    char payload_sha256[65];   /* 64 lowercase hex + NUL */
    uint64_t payload_bytes;    /* length-coherent with the actual bytes */
    int64_t created_at;        /* unix seconds, > 0 */
} dtn_capsule_meta;

/* dtn_capsule — a parsed capsule. payload/meta_bytes/sig VIEW the input
 * buffer (which must outlive the struct); nothing is copied. */
typedef struct {
    dtn_capsule_meta meta;
    const uint8_t *meta_bytes; size_t meta_len;
    const uint8_t *payload;    size_t payload_len;
    const uint8_t *sig;        /* DTN_CAPSULE_SIG_LEN bytes */
} dtn_capsule;

/* dtn_capsule_parse — the §2.1.1 layout and every NON-cryptographic rule
 * (magic, format, the M budget, the canonical fixed-order metadata
 * scanner, payload_bytes coherence). Returns a DTN_CAPSULE_* code. */
int dtn_capsule_parse(const uint8_t *blob, size_t len, dtn_capsule *out);

/* dtn_capsule_verify — the §2.4.4 step 2: the payload SHA-256 first (a
 * corrupted payload dies before any cryptography), then the Ed25519
 * detached signature over the VERBATIM meta || payload bytes against the
 * pinned release key. Returns DTN_CAPSULE_OK / SHA_MISMATCH /
 * BAD_SIGNATURE / UNPINNED (pub NULL or wrong size). */
int dtn_capsule_verify(const dtn_capsule *c, const uint8_t pub[32]);

/* dtn_capsule_stage — the binding §2.4.4 ladder WITHOUT the write (the
 * write and the apply are the caller's — the #22/#37 paths):
 *
 *   parse -> verify(sha, signature) -> §9.1 arch gate (node_arch != NULL
 *   and non-empty enables it) -> §2.6 rule 2 (release > max(running,
 *   staged)) -> §2.6 rule 3 (min_upgrade_from <= running; running == 0
 *   means "unknown" and refuses any nonzero floor) -> created_at <=
 *   now_unix + 300.
 *
 * Returns DTN_CAPSULE_OK (and the parsed metadata) or the failure code. */
int dtn_capsule_stage(const uint8_t *blob, size_t len,
                      const uint8_t pub[32], const char *node_arch,
                      uint64_t running_release, uint64_t staged_release,
                      int64_t now_unix, dtn_capsule_meta *out_meta);

/* dtn_capsule_release_from_semver — the frozen §2.1.2 formula. */
uint64_t dtn_capsule_release_from_semver(unsigned major, unsigned minor, unsigned patch);

/* --- the §9.4 chunk transport ------------------------------------------- */

#define DTN_CAPSULE_CHUNK_HEADER_LEN 16 /* id(8) + total(4) + idx(4) */
#define DTN_CAPSULE_CHUNK_LORA 200      /* §9.1: the LoRa-plane stride (constant only; the leg is hardware) */
#define DTN_CAPSULE_CHUNK_TCPCL (64 * 1024) /* §9.1: the Wi-Fi/IP stride */
#define DTN_CAPSULE_CHUNK_MAX_TOTAL 1024    /* the C reassembler's compiled ceiling on `total` (fail-closed; the board tunes it) */

typedef struct {
    const uint8_t *data; /* the chunk bytes (a view) */
    size_t len;
    uint32_t total;
    uint32_t idx;
    uint8_t id[8];
} dtn_capsule_chunk;

/* dtn_capsule_chunk_parse — the header arithmetic of §9.4 (total in
 * [1, ceiling], idx < total, at least one chunk byte). Returns 1 ok,
 * 0 reject. False positives (arbitrary bytes that parse) cost nothing:
 * real validation is the reassembler's, and the capsule SHA bounds the
 * end result. */
int dtn_capsule_chunk_parse(const uint8_t *pdu, size_t len, dtn_capsule_chunk *out);

/* Reassembly offer results (the vectors' step vocabulary): */
#define DTN_CAPSULE_REASM_STORED    0
#define DTN_CAPSULE_REASM_DUP       1
#define DTN_CAPSULE_REASM_COMPLETE  2
#define DTN_CAPSULE_REASM_REFUSED   3 /* corruption: the partial was dropped */
#define DTN_CAPSULE_REASM_BAD       4 /* header arithmetic */

#define DTN_CAPSULE_REASM_MAX_PARTIALS 4
#define DTN_CAPSULE_REASM_DONE_CAP     16

/* dtn_capsule_reasm — the §9.4 reassembler. Like Go's Reassembler: keyed
 * by capsule_id, duplicate chunks absorbed idempotently, a chunk
 * redelivered with DIFFERING bytes is corruption (the whole partial
 * drops), interleaved capsules stay independent, partials expire with the
 * chunk bundles' lifetime, and the partial-slot pool evicts the
 * soonest-expiring partial when a flood arrives.
 *
 * DESIGN DIVERGENCE (documented, deliberate): the C side buffers NO chunk
 * bytes — the caller keeps them (on a node they ARE stored bundles; in the
 * host suite, the vector arrays). Per-index 32-bit checksums detect the
 * differing-redelivery case without the copies. dtn_capsule_reasm_assemble
 * pulls the bytes back through the caller's chunk-source callback. RAM
 * honesty: the state is one static-sized struct (~9 KB), sized by
 * DTN_CAPSULE_CHUNK_MAX_TOTAL — totals above the ceiling are refused
 * (fail-closed), the board lowers it to fit. */
typedef struct {
    int used;
    uint8_t id[8];
    uint32_t total;
    uint32_t received;
    uint16_t stride;      /* 0 = not yet fixed (only the last chunk seen) */
    int64_t expires;      /* unix seconds: sliding now + lifetime */
    uint8_t have[(DTN_CAPSULE_CHUNK_MAX_TOTAL + 7) / 8];
    uint32_t sum[DTN_CAPSULE_CHUNK_MAX_TOTAL]; /* per-index checksums */
} dtn_capsule_partial;

typedef struct {
    dtn_capsule_partial slots[DTN_CAPSULE_REASM_MAX_PARTIALS];
    uint8_t done[DTN_CAPSULE_REASM_DONE_CAP][8];
    int done_n; /* FIFO; over the cap the oldest id forgets */
    uint32_t chunks_in, dups, refused, completions, expired;
} dtn_capsule_reasm;

void dtn_capsule_reasm_init(dtn_capsule_reasm *st);

/* dtn_capsule_reasm_offer — feed one chunk PDU. now_unix is the delivery
 * clock; lifetime_s the chunk bundle's TTL (the partial's expiry slides
 * with every delivery). On DTN_CAPSULE_REASM_COMPLETE, completed_id
 * receives the capsule_id. */
int dtn_capsule_reasm_offer(dtn_capsule_reasm *st,
                            const uint8_t *pdu, size_t len,
                            int64_t now_unix, uint64_t lifetime_s,
                            uint8_t completed_id[8]);

/* dtn_capsule_chunk_src — the caller's chunk storage: resolve index idx of
 * a capsule to its bytes (NULL views into caller-owned memory are fine for
 * the call's duration). Return 0 ok, -1 missing. */
typedef int (*dtn_capsule_chunk_src)(void *ud, const uint8_t id[8],
                                     uint32_t idx, uint32_t total,
                                     const uint8_t **data, size_t *len);

/* dtn_capsule_reasm_assemble — concatenate one completed capsule's chunks
 * in index order into out (caller-sized; DTN_CAPSULE_MAX_PAYLOAD bounds
 * the honest size). id/total come from the offer's completion (and the
 * caller's own bookkeeping). Returns 0 ok, -1 (missing chunk, bad
 * geometry, or output too small). */
int dtn_capsule_reasm_assemble(const uint8_t id[8], uint32_t total,
                               dtn_capsule_chunk_src src, void *ud,
                               uint8_t *out, size_t cap, size_t *out_len);

#ifdef __cplusplus
}
#endif
#endif /* DTN_CAPSULE_H */
