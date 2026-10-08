/* dtn_ccm.h — AES-CCM-128 (RFC 3610) for the node-plane link sessions.
 *
 * The §6.2 profile of docs/node-network.md, frozen: 16-byte key, 13-byte
 * nonce (5-byte session salt ‖ 8-byte big-endian sequence), 16-byte tag,
 * q = 2. Pure C99, no platform dependencies; the Go mirror is
 * node/internal/link/ccm.go and both are pinned to the RFC 3610 packet
 * vectors and the shared link vectors (tests/vectors/link).
 */
#ifndef DTN_CCM_H
#define DTN_CCM_H

#include <stddef.h>
#include <stdint.h>

#define DTN_CCM_KEY_LEN 16
#define DTN_CCM_NONCE_LEN 13
#define DTN_CCM_TAG_LEN 16
#define DTN_CCM_MAX_PLAINTEXT 65535 /* the q=2 length field */
#define DTN_CCM_MAX_AAD 65279       /* the 2-byte length header form */

/* dtn_ccm_seal encrypts pt under (key, nonce, aad) and writes
 * pt_len + 16 bytes (ciphertext ‖ tag) to out. out may alias pt. */
void dtn_ccm_seal(const uint8_t key[DTN_CCM_KEY_LEN],
                  const uint8_t nonce[DTN_CCM_NONCE_LEN],
                  const uint8_t *aad, size_t aad_len,
                  const uint8_t *pt, size_t pt_len,
                  uint8_t *out);

/* dtn_ccm_open verifies and decrypts in (in_len = pt_len + 16): writes the
 * plaintext to out (in_len - 16 bytes) and returns 0, or returns -1
 * WITHOUT writing anything on any failure (fail-closed). */
int dtn_ccm_open(const uint8_t key[DTN_CCM_KEY_LEN],
                 const uint8_t nonce[DTN_CCM_NONCE_LEN],
                 const uint8_t *aad, size_t aad_len,
                 const uint8_t *in, size_t in_len,
                 uint8_t *out);

/* dtn_aes128_block is the bare forward block cipher (exposed for the
 * test suite's RFC FIPS-197 spot check). */
void dtn_aes128_block(const uint8_t key[DTN_CCM_KEY_LEN],
                      const uint8_t in[16], uint8_t out[16]);

#endif /* DTN_CCM_H */
