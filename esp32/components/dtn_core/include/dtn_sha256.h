/* dtn_sha256.h — compact SHA-256 for the dtn_core portable core (P3.1).
 *
 * FIPS 180-4, byte-exact with Go's crypto/sha256 (the shared nodeid vectors
 * pin the first 8 digest bytes of the anchor key). Self-contained C99; no
 * ESP-IDF in the host path. Role: fingerprint derivation (dtn_nodeid) and
 * any P3.2+ need — the SHA-512 the Ed25519 verify needs comes from the
 * embedded TweetNaCl, not from here. */
#ifndef DTN_SHA256_H
#define DTN_SHA256_H

#include <stddef.h>
#include <stdint.h>

/* dtn_sha256 — one-shot FIPS 180-4 digest. out receives 32 bytes. */
void dtn_sha256(const uint8_t *data, size_t len, uint8_t out[32]);

#endif /* DTN_SHA256_H */
