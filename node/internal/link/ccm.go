// Package link implements the node-plane link security and framing of
// docs/node-network.md §5.4/§6 (issue #33 P3.3): the EDHOC-shaped handshake
// (§6.1), the AES-CCM-128 link sessions with persisted monotonic sequences
// and replay windows (§6.2), the node-plane link frame header and the
// bundle-window reassembly (§5.4). The C mirror lives in
// esp32/components/dtn_core (dtn_ccm/dtn_hkdf/dtn_session/dtn_frame); both
// sides are pinned to the same shared vectors (tests/vectors/link).
//
// Crypto policy: Go stdlib only. This file hand-rolls AES-CCM (RFC 3610)
// over crypto/aes's block cipher — Go's stdlib has no CCM — with the
// profile's fixed parameters: 13-byte nonce, 16-byte tag.
package link

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"fmt"
)

// The §6.2 AEAD profile, frozen: AES-CCM-128 with a 13-byte nonce and a
// 16-byte tag. The nonce is 5-byte session salt ‖ 8-byte big-endian
// per-direction sequence (§6.2); the handshake ct2/ct3 use the same length
// profile with the handshake constants of handshake.go.
const (
	KeyLen   = 16 // AES-128
	NonceLen = 13 // 5-byte salt ‖ 8-byte BE sequence
	TagLen   = 16 // CCM-MAC t; q = 15 - NonceLen = 2
	// MaxPlaintext is the largest message CCM can seal with q = 2
	// (the 2-byte length field of the CCM B0 block).
	MaxPlaintext = 0xffff
	// MaxAAD bounds the associated data (a 2-byte length header covers
	// up to 0xfeff; the link plane never needs more — the frame header
	// is 1 byte).
	MaxAAD = 0xfeff
)

// ccmTagOK validates a tag length against RFC 3610 (t ∈ {4,6,...,16}).
func ccmTagOK(t int) bool { return t >= 4 && t <= 16 && t%2 == 0 }

// ccmBlocks builds the CBC-MAC input B0 ‖ aad-blocks ‖ msg-blocks
// (RFC 3610 §2.2) and the CTR flags byte. q = 15 - len(nonce).
func ccmMACInput(nonce, aad, msg []byte, t int) []byte {
	q := 15 - len(nonce)
	// B0: flags = 0x40 reserved (Adata is carried via the aad encoding,
	// not the flag — RFC 3610 sets the Adata flag AND the length header;
	// the flag here reflects whether aad is present).
	flags := byte(0)
	if len(aad) > 0 {
		flags |= 0x40
	}
	flags |= byte((t-2)/2) << 3
	flags |= byte(q - 1)

	buf := make([]byte, 0, 16+len(aad)+3+len(msg)+15)
	buf = append(buf, flags)
	buf = append(buf, nonce...)
	for i := q - 1; i >= 0; i-- { // Q: message length, q bytes BE
		buf = append(buf, byte(len(msg)>>(8*i)))
	}
	if len(aad) > 0 {
		// a < 65280 only (MaxAAD): 2-byte BE length header, no escape form.
		buf = append(buf, byte(len(aad)>>8), byte(len(aad)))
		buf = append(buf, aad...)
	}
	if pad := (16 - len(buf)%16) % 16; pad > 0 {
		buf = append(buf, make([]byte, pad)...)
	}
	buf = append(buf, msg...)
	if pad := (16 - len(buf)%16) % 16; pad > 0 {
		buf = append(buf, make([]byte, pad)...)
	}
	return buf
}

// ccmCBCMAC runs CBC-MAC over the formatted input with the zero IV.
func ccmCBCMAC(block cipher.Block, input []byte) [16]byte {
	var mac [16]byte
	var blk [16]byte
	for off := 0; off < len(input); off += 16 {
		for i := 0; i < 16; i++ {
			blk[i] = mac[i] ^ input[off+i]
		}
		block.Encrypt(mac[:], blk[:])
	}
	return mac
}

// ccmCTR produces S_i = E(flags ‖ nonce ‖ counter_i) for i = 0..n-1. The
// CTR flags byte is L' = q-1 ALONE (RFC 3610 §2.3: "Flags = L'", the M
// bits are deliberately zero so A blocks never collide with B0).
func ccmCTR(block cipher.Block, nonce []byte, t, n int) [][]byte {
	q := 15 - len(nonce)
	flags := byte(q - 1)
	out := make([][]byte, n)
	var blk, s [16]byte
	for i := 0; i < n; i++ {
		blk[0] = flags
		copy(blk[1:1+len(nonce)], nonce)
		ctr := i // q-byte BE counter
		for j := q - 1; j >= 0; j-- {
			blk[15-j] = byte(ctr >> (8 * j))
		}
		block.Encrypt(s[:], blk[:])
		row := make([]byte, 16)
		copy(row, s[:])
		out[i] = row
	}
	return out
}

// sealCCM is the RFC 3610 forward direction with a caller-chosen tag
// length: returns plaintext ‖ tag. The exported Seal pins t = TagLen.
func sealCCM(key, nonce, aad, msg []byte, t int) ([]byte, error) {
	if len(key) != KeyLen {
		return nil, fmt.Errorf("link: ccm key must be %d bytes", KeyLen)
	}
	if len(nonce) != NonceLen {
		return nil, fmt.Errorf("link: ccm nonce must be %d bytes, got %d", NonceLen, len(nonce))
	}
	if !ccmTagOK(t) {
		return nil, fmt.Errorf("link: ccm tag length %d is invalid", t)
	}
	if len(msg) > MaxPlaintext {
		return nil, fmt.Errorf("link: ccm plaintext %d exceeds the q=2 bound %d", len(msg), MaxPlaintext)
	}
	if len(aad) > MaxAAD {
		return nil, fmt.Errorf("link: ccm aad %d exceeds %d", len(aad), MaxAAD)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mac := ccmCBCMAC(block, ccmMACInput(nonce, aad, msg, t))
	S := ccmCTR(block, nonce, t, len(msg)/16+2) // S0 + one per payload block
	out := make([]byte, 0, len(msg)+t)
	ctr := 1
	for off := 0; off < len(msg); off += 16 {
		end := off + 16
		if end > len(msg) {
			end = len(msg)
		}
		for i := off; i < end; i++ {
			out = append(out, msg[i]^S[ctr][i-off])
		}
		ctr++
	}
	tag := S[0][:t]
	for i := 0; i < t; i++ {
		tag[i] ^= mac[i]
	}
	return append(out, tag...), nil
}

// openCCM verifies and decrypts ciphertext ‖ tag (RFC 3610 reverse
// direction). On any failure the returned plaintext is nil.
func openCCM(key, nonce, aad, data []byte, t int) ([]byte, error) {
	if len(data) < t {
		return nil, fmt.Errorf("link: ccm data shorter than the %d-byte tag", t)
	}
	ct, tag := data[:len(data)-t], data[len(data)-t:]
	// Recompute the MAC over the ciphertext, then compare in constant time
	// BEFORE releasing any plaintext (fail-closed; nothingDecryptsOnError).
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	S := ccmCTR(block, nonce, t, len(ct)/16+2)
	msg := make([]byte, len(ct))
	ctr := 1
	for off := 0; off < len(ct); off += 16 {
		end := off + 16
		if end > len(ct) {
			end = len(ct)
		}
		for i := off; i < end; i++ {
			msg[i] = ct[i] ^ S[ctr][i-off]
		}
		ctr++
	}
	mac := ccmCBCMAC(block, ccmMACInput(nonce, aad, msg, t))
	want := S[0][:t]
	for i := 0; i < t; i++ {
		want[i] ^= mac[i]
	}
	if subtle.ConstantTimeCompare(want, tag) != 1 {
		return nil, fmt.Errorf("link: ccm tag mismatch")
	}
	return msg, nil
}

// Seal encrypts plaintext under the §6.2 profile (AES-CCM-128, 13-byte
// nonce, 16-byte tag, no AAD beyond what the caller passes): returns
// ciphertext ‖ tag.
func Seal(key [KeyLen]byte, nonce [NonceLen]byte, aad, plaintext []byte) ([]byte, error) {
	return sealCCM(key[:], nonce[:], aad, plaintext, TagLen)
}

// Open decrypts data (= ciphertext ‖ tag) under the §6.2 profile. A tag
// mismatch or a malformed input is an error; no plaintext is returned.
func Open(key [KeyLen]byte, nonce [NonceLen]byte, aad, data []byte) ([]byte, error) {
	return openCCM(key[:], nonce[:], aad, data, TagLen)
}
