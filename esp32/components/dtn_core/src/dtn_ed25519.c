/* dtn_ed25519.c — Ed25519 verify-only wrapper (P3.1). Everything below is
 * the embedded TweetNaCl trim; this file only translates its int result
 * into the component's error codes and enforces the message bound. */
#include "dtn_ed25519.h"

#include "dtn_tweetnacl.h"

int dtn_ed25519_verify(const uint8_t pub[32], const uint8_t sig[64],
                       const uint8_t *msg, size_t len)
{
    if (len > (size_t)DTN_ED25519_MAX_MSG) {
        return DTN_ED25519_ERR_TOO_LONG;
    }
    /* dtn_tn_ed25519_verify rejects malformed public keys (unpackneg) and
     * bad signatures with the same -1; the wrapper does not distinguish —
     * a failed verification must never leak which half was wrong. */
    if (dtn_tn_ed25519_verify(pub, sig, msg, (unsigned long long)len) != 0) {
        return DTN_ED25519_ERR_SIGNATURE;
    }
    return DTN_ED25519_OK;
}
