/* dtn_base64.h — strict RFC 4648 standard-alphabet Base64 (padded), the §3.3
 * wire encoding. Byte-parity with Go's encoding/base64 StdEncoding.Strict():
 * canonical padding required, zero trailing padding bits, no whitespace (the
 * Go code additionally rejects \r/\n explicitly before decoding), standard
 * alphabet only (base64url characters are invalid). */
#ifndef DTN_BASE64_H
#define DTN_BASE64_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Decode src (length src_len) into out (capacity cap). Returns the number of
 * decoded bytes, or -1 on any violation: invalid character, wrong padding,
 * non-canonical trailing bits, or out-cap. No whitespace is tolerated. */
long dtn_base64_decode(const char *src, size_t src_len,
                       uint8_t *out, size_t cap);

/* Just the decoded length of a VALID input, without decoding (-1 invalid).
 * Used by the payload bound check before any buffer is touched. */
long dtn_base64_decoded_len(const char *src, size_t src_len);

#ifdef __cplusplus
}
#endif

#endif /* DTN_BASE64_H */
