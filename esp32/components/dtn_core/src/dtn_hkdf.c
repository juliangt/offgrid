/* dtn_hkdf.c — HMAC-SHA256 + HKDF-SHA256 (RFC 5869) over dtn_sha256.
 *
 * HMAC(K, m) = SHA256(opad ‖ SHA256(ipad ‖ K' ‖ m)) with the RFC 2104
 * padding. The data path is a fixed stack buffer sized for the HKDF
 * shapes (T(32) ‖ info ≤ 255 ‖ counter, or the 32-byte IKM of Extract);
 * anything larger fails closed rather than allocate. Go mirror:
 * node/internal/link/hkdf.go.
 */

#include "dtn_hkdf.h"

#include <string.h>

#include "dtn_sha256.h"

/* Maximum total data bytes across the segments (see the buffer below). */
#define DTN_HKDF_MAX_DATA 288

static void hmac3(const uint8_t *key, size_t key_len,
                  const uint8_t *d1, size_t n1,
                  const uint8_t *d2, size_t n2,
                  const uint8_t *d3, size_t n3,
                  uint8_t out[DTN_HKDF_HASH_LEN])
{
    uint8_t k[64], pad[64];
    uint8_t buf[64 + DTN_HKDF_MAX_DATA];
    uint8_t inner[DTN_HKDF_HASH_LEN];
    size_t off = 64, i;

    memset(k, 0, sizeof(k));
    if (key_len > 64) {
        dtn_sha256(key, key_len, k); /* long keys are hashed down */
    } else if (key_len > 0 && key != NULL) {
        memcpy(k, key, key_len);
    }
    if ((uint64_t)n1 + n2 + n3 > DTN_HKDF_MAX_DATA) {
        memset(out, 0, DTN_HKDF_HASH_LEN); /* fail-closed, never the data */
        return;
    }
    for (i = 0; i < 64; i++) {
        pad[i] = (uint8_t)(k[i] ^ 0x36);
    }
    memcpy(buf, pad, 64);
    if (d1 != NULL && n1 > 0) {
        memcpy(buf + off, d1, n1);
        off += n1;
    }
    if (d2 != NULL && n2 > 0) {
        memcpy(buf + off, d2, n2);
        off += n2;
    }
    if (d3 != NULL && n3 > 0) {
        memcpy(buf + off, d3, n3);
        off += n3;
    }
    dtn_sha256(buf, off, inner);

    for (i = 0; i < 64; i++) {
        pad[i] = (uint8_t)(k[i] ^ 0x5c);
    }
    memcpy(buf, pad, 64);
    memcpy(buf + 64, inner, DTN_HKDF_HASH_LEN);
    dtn_sha256(buf, 64 + DTN_HKDF_HASH_LEN, out);
}

void dtn_hmac_sha256(const uint8_t *key, size_t key_len,
                     const uint8_t *data, size_t data_len,
                     uint8_t out[DTN_HKDF_HASH_LEN])
{
    hmac3(key, key_len, data, data_len, NULL, 0, NULL, 0, out);
}

void dtn_hmac_sha256_two(const uint8_t *key, size_t key_len,
                         const uint8_t *d1, size_t n1,
                         const uint8_t *d2, size_t n2,
                         uint8_t out[DTN_HKDF_HASH_LEN])
{
    hmac3(key, key_len, d1, n1, d2, n2, NULL, 0, out);
}

void dtn_hkdf_extract(const uint8_t *salt, size_t salt_len,
                      const uint8_t *ikm, size_t ikm_len,
                      uint8_t prk[DTN_HKDF_HASH_LEN])
{
    uint8_t zeros[DTN_HKDF_HASH_LEN] = {0};
    if (salt == NULL || salt_len == 0) {
        hmac3(zeros, DTN_HKDF_HASH_LEN, ikm, ikm_len, NULL, 0, NULL, 0, prk);
        return;
    }
    dtn_hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
}

int dtn_hkdf_expand(const uint8_t prk[DTN_HKDF_HASH_LEN],
                    const uint8_t *info, size_t info_len,
                    size_t out_len, uint8_t *okm)
{
    uint8_t t[DTN_HKDF_HASH_LEN] = {0};
    uint8_t counter;
    size_t done = 0, tlen = 0;

    if (out_len == 0 || out_len > 255u * DTN_HKDF_HASH_LEN || info_len > 255) {
        return -1;
    }
    /* T(i) = HMAC(PRK, T(i-1) ‖ info ‖ i), with T(0) empty. */
    for (counter = 1; done < out_len; counter++) {
        size_t n;
        hmac3(prk, DTN_HKDF_HASH_LEN, t, tlen, info, info_len, &counter, 1, t);
        tlen = DTN_HKDF_HASH_LEN;
        n = out_len - done < DTN_HKDF_HASH_LEN ? out_len - done : DTN_HKDF_HASH_LEN;
        memcpy(okm + done, t, n);
        done += n;
    }
    return 0;
}
