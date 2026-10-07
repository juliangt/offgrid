/* dtn_ed25519.h — thin Ed25519 VERIFY-ONLY wrapper over the embedded
 * TweetNaCl trim (dtn_tweetnacl.c) for the P3.1 role-cert checks.
 *
 * The C node plane is a verifier/consumer by design (docs/node-network.md
 * §2.2: a conforming node stores only certs it verified against a PINNED
 * anchor): there is no sign entry point here. X25519 and SHA-512 stay
 * reachable through dtn_tweetnacl.h for the P3.3 link sessions. */
#ifndef DTN_ED25519_H
#define DTN_ED25519_H

#include <stddef.h>
#include <stdint.h>

/* The largest message dtn_ed25519_verify accepts: the role-cert
 * Sig_structure is ≤ ~1.1 KiB (DTN_ROLECERT_MAX payload + framing) and the
 * P3.3 handshake transcripts are ≤ 221 B, so 2 KiB is ≥ 4x margin for
 * everything this component verifies. Verification is O(1) stack (no copy
 * of the message is made). */
#define DTN_ED25519_MAX_MSG 2048

#define DTN_ED25519_OK 0
#define DTN_ED25519_ERR_SIGNATURE (-1) /* verify failed (or malformed key) */
#define DTN_ED25519_ERR_TOO_LONG  (-2) /* len > DTN_ED25519_MAX_MSG */

/* dtn_ed25519_verify — RFC 8032 Ed25519 verification. Returns
 * DTN_ED25519_OK when sig[64] is a valid signature by pub over msg[0:len]. */
int dtn_ed25519_verify(const uint8_t pub[32], const uint8_t sig[64],
                       const uint8_t *msg, size_t len);

#endif /* DTN_ED25519_H */
