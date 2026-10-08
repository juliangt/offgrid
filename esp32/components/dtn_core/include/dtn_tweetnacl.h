/* dtn_tweetnacl.h — the public surface of the embedded TweetNaCl trim.
 *
 * Upstream: TweetNaCl (version 20140427) — public domain.
 *   Daniel J. Bernstein, Bernard van Gastel, Wesley Janssen, Tanja Lange,
 *   Peter Schwabe, Sjaak Smetsers.
 *   https://tweetnacl.cr.yp.to/20140427/tweetnacl.c
 * Signature types match the .c's own typedefs (u8 = unsigned char,
 * u64 = unsigned long long); uint8_t/uint64_t callers are ABI-compatible
 * on every supported platform.
 */
#ifndef DTN_TWEETNACL_H
#define DTN_TWEETNACL_H

/* Ed25519 VERIFY (dtn_core was a verifier/consumer in P3.1; since P3.3 the
 * link-session handshake signs on BOTH sides, so the sign path below is
 * enabled too). Same check as upstream crypto_sign_open, minus the message
 * copy; returns 0 on a valid signature, -1 otherwise. */
int dtn_tn_ed25519_verify(const unsigned char pk[32], const unsigned char sig[64],
                          const unsigned char *msg, unsigned long long msglen);

/* Ed25519 SIGN + keypair-from-seed (added P3.3). Built strictly from the
 * upstream pieces in dtn_tweetnacl.c (sha512, reduce, scalarbase, add,
 * pack, modL) and restating the upstream crypto_sign /
 * crypto_sign_keypair algorithm without the signed-message buffer; the
 * public-domain attribution covers this file in full.
 *
 * dtn_tn_ed25519_keypair: pk = clamp(SHA512(seed)[0:32])·B.
 * dtn_tn_ed25519_sign: the deterministic RFC 8032 signature of msg under
 * (seed,pk). Ed25519 signing is deterministic, so Go and C produce
 * byte-identical signatures — the shared handshake vectors pin that.
 * Messages up to 223 bytes are hashed in a fixed stack buffer (the
 * transcript signatures are ≤ 60 B); longer inputs return -1. */
int dtn_tn_ed25519_keypair(unsigned char pk[32], const unsigned char seed[32]);
int dtn_tn_ed25519_sign(unsigned char sig[64], const unsigned char *msg,
                        unsigned long long msglen,
                        const unsigned char seed[32], const unsigned char pk[32]);

/* Upstream crypto_sign_open, kept verbatim (renamed) as the reference
 * implementation of the same check — it also recovers the message. */
int dtn_tn_crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                            const unsigned char *sm, unsigned long long smlen,
                            const unsigned char *pk);

/* X25519 (RFC 7748) — kept reachable for the P3.3 link-session handshake;
 * not built upon in P3.1. */
int dtn_tn_crypto_scalarmult(unsigned char *q, const unsigned char *n,
                             const unsigned char *p);
int dtn_tn_crypto_scalarmult_base(unsigned char *q, const unsigned char *n);

/* SHA-512 — upstream crypto_hash; needed by the Ed25519 verify and kept
 * reachable for the P3.3 transcript hashing. */
int dtn_tn_sha512(unsigned char out[64], const unsigned char *m,
                  unsigned long long n);

/* Constant-time 32-byte comparison (upstream crypto_verify_32): 0 = equal,
 * -1 = different. */
int dtn_tn_crypto_verify_32(const unsigned char *x, const unsigned char *y);

#endif /* DTN_TWEETNACL_H */
