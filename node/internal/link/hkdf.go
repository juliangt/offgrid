// hkdf.go — HKDF-SHA256 (RFC 5869), hand-rolled per the phase crypto
// policy (stdlib has no HKDF; HMAC-SHA256 comes from crypto/hmac). The
// handshake and the session key schedule (handshake.go) are the only
// consumers; the C mirror is dtn_hkdf.c, pinned to the same RFC 5869 and
// shared vectors.
package link

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

// HashLen is the SHA-256 output length (RFC 5869 HashLen).
const HashLen = sha256.Size

// HkdfExtract is RFC 5869 §2.2: PRK = HMAC-SHA256(salt, IKM). A nil/empty
// salt is HashLen zero bytes, per the RFC.
func HkdfExtract(salt, ikm []byte) [HashLen]byte {
	if len(salt) == 0 {
		salt = make([]byte, HashLen)
	}
	m := hmac.New(sha256.New, salt)
	m.Write(ikm)
	var prk [HashLen]byte
	copy(prk[:], m.Sum(nil))
	return prk
}

// HkdfExpand is RFC 5869 §2.3: OKM = HKDF-Expand(PRK, info, L), with the
// RFC's counter suffix and the 255*HashLen output bound.
func HkdfExpand(prk [HashLen]byte, info []byte, length int) ([]byte, error) {
	if length <= 0 {
		return nil, fmt.Errorf("link: hkdf length must be positive, got %d", length)
	}
	if length > 255*HashLen {
		return nil, fmt.Errorf("link: hkdf length %d exceeds the RFC 5869 bound", length)
	}
	m := hmac.New(sha256.New, prk[:])
	out := make([]byte, 0, length+HashLen)
	var t []byte
	for counter := byte(1); len(out) < length; counter++ {
		m.Reset()
		m.Write(t)
		m.Write(info)
		m.Write([]byte{counter})
		t = m.Sum(t[:0])
		out = append(out, t...)
	}
	return out[:length], nil
}

// HkdfKey derives exactly `length` bytes: Extract(salt, ikm) then Expand
// with info. The one-liner every key schedule in this package reduces to
// (§6.2: HKDF-SHA256 over the X25519 shared secret, transcript-hash salt,
// "offgrid-link-v1" info).
func HkdfKey(ikm, salt, info []byte, length int) ([]byte, error) {
	return HkdfExpand(HkdfExtract(salt, ikm), info, length)
}
