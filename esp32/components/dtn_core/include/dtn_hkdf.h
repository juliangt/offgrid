/* dtn_hkdf.h — HMAC-SHA256 and HKDF-SHA256 (RFC 5869) for dtn_core.
 *
 * Built over dtn_sha256 (one-shot FIPS 180-4). Go mirror:
 * node/internal/link/hkdf.go; pinned by the RFC 5869 Appendix A test
 * cases 1–3 (both suites) and the shared link vectors.
 */
#ifndef DTN_HKDF_H
#define DTN_HKDF_H

#include <stddef.h>
#include <stdint.h>

#define DTN_HKDF_HASH_LEN 32

/* dtn_hmac_sha256 — HMAC (RFC 2104) over one message. A NULL/zero key is
 * the RFC's zero-padded form. */
void dtn_hmac_sha256(const uint8_t *key, size_t key_len,
                     const uint8_t *data, size_t data_len,
                     uint8_t out[DTN_HKDF_HASH_LEN]);

/* dtn_hmac_sha256_two — HMAC over a two-part message (avoids copies for
 * HKDF-Expand's T ‖ info ‖ counter input). */
void dtn_hmac_sha256_two(const uint8_t *key, size_t key_len,
                         const uint8_t *d1, size_t n1,
                         const uint8_t *d2, size_t n2,
                         uint8_t out[DTN_HKDF_HASH_LEN]);

/* dtn_hkdf_extract — PRK = HMAC-SHA256(salt, IKM); a NULL/empty salt is
 * HashLen zero bytes, per the RFC. */
void dtn_hkdf_extract(const uint8_t *salt, size_t salt_len,
                      const uint8_t *ikm, size_t ikm_len,
                      uint8_t prk[DTN_HKDF_HASH_LEN]);

/* dtn_hkdf_expand — OKM = HKDF-Expand(PRK, info, L); out_len ≤ 255*32.
 * Returns 0, or -1 on an out-of-bounds length (fail-closed). */
int dtn_hkdf_expand(const uint8_t prk[DTN_HKDF_HASH_LEN],
                    const uint8_t *info, size_t info_len,
                    size_t out_len, uint8_t *okm);

#endif /* DTN_HKDF_H */
