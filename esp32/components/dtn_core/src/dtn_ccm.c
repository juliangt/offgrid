/* dtn_ccm.c — AES-128 (encrypt-only core) + CCM (RFC 3610) for dtn_core.
 *
 * CCM needs only the forward block-cipher direction. Go mirror:
 * node/internal/link/ccm.go; pinned by RFC 3610 §8 packet vectors (both
 * suites) and the shared link vectors (tests/vectors/link).
 */

#include "dtn_ccm.h"

#include <string.h>

/* ------------------------------------------------------------------ */
/* AES-128 encryption only (FIPS 197).                                 */
/* ------------------------------------------------------------------ */

static const uint8_t aes_sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

/* Rcon for AES-128's 10 rounds (the round-9/10 values are not 1<<n). */
static const uint8_t aes_rcon[11] = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10,
                                     0x20, 0x40, 0x80, 0x1b, 0x36};

static uint8_t xtime(uint8_t x)
{
    return (uint8_t)((x << 1) ^ ((x >> 7) * 0x1b));
}

void dtn_aes128_block(const uint8_t key[DTN_CCM_KEY_LEN], const uint8_t in[16], uint8_t out[16])
{
    uint8_t rk[176]; /* 11 round keys */
    uint8_t t[4];
    uint8_t s[16];
    int i, j, r;

    /* Key expansion (AES-128: 10 rounds), column-major rk[c*4+ ... flat]. */
    memcpy(rk, key, 16);
    for (i = 16; i < 176; i += 4) {
        memcpy(t, rk + i - 4, 4);
        if (i % 16 == 0) {
            const uint8_t rot = t[0];
            t[0] = (uint8_t)(aes_sbox[t[1]] ^ aes_rcon[i / 16]);
            t[1] = aes_sbox[t[2]];
            t[2] = aes_sbox[t[3]];
            t[3] = aes_sbox[rot];
        }
        for (j = 0; j < 4; j++) {
            rk[i + j] = (uint8_t)(rk[i - 16 + j] ^ t[j]);
        }
    }

    memcpy(s, in, 16);
    for (i = 0; i < 16; i++) {
        s[i] = (uint8_t)(s[i] ^ rk[i]); /* ARK(0), the initial whitening */
    }
    for (r = 0; r < 10; r++) {
        uint8_t nxt[16];
        /* SubBytes + ShiftRows (state is column-major s[col*4+row];
         * ShiftRows: new[r][c] = old[r][(c+r) mod 4]). */
        for (i = 0; i < 16; i++) {
            const int row = i % 4, col = i / 4;
            nxt[col * 4 + row] = aes_sbox[s[((col + row) % 4) * 4 + row]];
        }
        if (r < 9) { /* MixColumns */
            for (i = 0; i < 4; i++) {
                const uint8_t a0 = nxt[i * 4], a1 = nxt[i * 4 + 1];
                const uint8_t a2 = nxt[i * 4 + 2], a3 = nxt[i * 4 + 3];
                s[i * 4] = (uint8_t)(xtime(a0) ^ xtime(a1) ^ a1 ^ a2 ^ a3);
                s[i * 4 + 1] = (uint8_t)(a0 ^ xtime(a1) ^ xtime(a2) ^ a2 ^ a3);
                s[i * 4 + 2] = (uint8_t)(a0 ^ a1 ^ xtime(a2) ^ xtime(a3) ^ a3);
                s[i * 4 + 3] = (uint8_t)(xtime(a0) ^ a0 ^ a1 ^ a2 ^ xtime(a3));
            }
        } else {
            memcpy(s, nxt, 16);
        }
        for (i = 0; i < 16; i++) {
            s[i] = (uint8_t)(s[i] ^ rk[16 + r * 16 + i]);
        }
    }
    memcpy(out, s, 16);
}

/* ------------------------------------------------------------------ */
/* CCM (RFC 3610), t = 16, q = 2 fixed by the §6.2 profile.            */
/* ------------------------------------------------------------------ */

static void ccm_xor(uint8_t *dst, const uint8_t *src, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        dst[i] = (uint8_t)(dst[i] ^ src[i]);
    }
}

/* S_i = E(0x01 ‖ nonce ‖ counter_i); the CTR flags byte is q-1 = 0x01
 * ALONE (RFC 3610 §2.3 — the M bits are zero so A blocks never collide
 * with B0). Counter 0 is S0 (the tag mask), 1..m encrypt the message. */
static void ccm_s(const uint8_t *key, const uint8_t *nonce, uint16_t ctr, uint8_t s[16])
{
    uint8_t blk[16];
    blk[0] = 0x01;
    memcpy(blk + 1, nonce, DTN_CCM_NONCE_LEN);
    blk[14] = (uint8_t)(ctr >> 8);
    blk[15] = (uint8_t)ctr;
    dtn_aes128_block(key, blk, s);
}

/* ccm_mac = CBC-MAC over B0 ‖ aad-blocks ‖ msg-blocks (RFC 3610 §2.2).
 * The aad stream (2-byte BE length header ‖ aad, zero-padded) is folded
 * block by block — no large buffers, the ESP32 stack stays small. */
static void ccm_mac(const uint8_t *key, const uint8_t *nonce,
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *msg, size_t msg_len, uint8_t mac[16])
{
    uint8_t blk[16];
    size_t off, n, blen = 0;

    /* B0: flags = [Adata] | (t-2)/2<<3 | q-1, nonce, msg length (q=2 BE);
     * the Adata bit is set only when aad is present (RFC 3610 §2.2). */
    blk[0] = (uint8_t)((aad_len > 0 ? 0x40 : 0x00) |
                       (((DTN_CCM_TAG_LEN - 2) / 2) << 3) | 0x01);
    memcpy(blk + 1, nonce, DTN_CCM_NONCE_LEN);
    blk[14] = (uint8_t)(msg_len >> 8);
    blk[15] = (uint8_t)msg_len;
    dtn_aes128_block(key, blk, mac);

    if (aad_len > 0) {
        const uint8_t hdr[2] = {(uint8_t)(aad_len >> 8), (uint8_t)aad_len};
        for (n = 0; n < 2; n++) { /* length header */
            blk[blen++] = hdr[n];
            if (blen == 16) {
                ccm_xor(mac, blk, 16);
                dtn_aes128_block(key, mac, mac);
                blen = 0;
            }
        }
        for (off = 0; off < aad_len; off++) { /* the data */
            blk[blen++] = aad[off];
            if (blen == 16) {
                ccm_xor(mac, blk, 16);
                dtn_aes128_block(key, mac, mac);
                blen = 0;
            }
        }
        if (blen > 0) { /* zero-pad the tail block */
            memset(blk + blen, 0, 16 - blen);
            ccm_xor(mac, blk, 16);
            dtn_aes128_block(key, mac, mac);
            blen = 0;
        }
    }
    for (off = 0; off < msg_len; off += 16) {
        n = msg_len - off < 16 ? msg_len - off : 16;
        memcpy(blk, mac, 16);
        ccm_xor(blk, msg + off, n);
        dtn_aes128_block(key, blk, mac);
    }
}

void dtn_ccm_seal(const uint8_t key[DTN_CCM_KEY_LEN],
                  const uint8_t nonce[DTN_CCM_NONCE_LEN],
                  const uint8_t *aad, size_t aad_len,
                  const uint8_t *pt, size_t pt_len,
                  uint8_t *out)
{
    uint8_t mac[16], s[16], s0[16];
    size_t off, n;
    uint16_t ctr = 1;

    ccm_mac(key, nonce, aad, aad_len, pt, pt_len, mac);
    ccm_s(key, nonce, 0, s0); /* S0 masks the tag — kept aside */
    for (off = 0; off < pt_len; off += 16) {
        n = pt_len - off < 16 ? pt_len - off : 16;
        ccm_s(key, nonce, ctr++, s);
        memcpy(out + off, pt + off, n);
        ccm_xor(out + off, s, n);
    }
    ccm_xor(mac, s0, DTN_CCM_TAG_LEN);
    memcpy(out + pt_len, mac, DTN_CCM_TAG_LEN);
}

int dtn_ccm_open(const uint8_t key[DTN_CCM_KEY_LEN],
                 const uint8_t nonce[DTN_CCM_NONCE_LEN],
                 const uint8_t *aad, size_t aad_len,
                 const uint8_t *in, size_t in_len,
                 uint8_t *out)
{
    uint8_t mac[16], s[16];
    size_t pt_len, off, n;
    uint16_t ctr = 1;
    uint8_t diff = 0;

    if (in_len < DTN_CCM_TAG_LEN || in_len > DTN_CCM_MAX_PLAINTEXT + DTN_CCM_TAG_LEN) {
        return -1;
    }
    pt_len = in_len - DTN_CCM_TAG_LEN;
    /* Decrypt into out, then recompute the MAC over the plaintext and
     * compare tag = MAC ⊕ S0 in full before any caller may act on out
     * (fail-closed: on a mismatch out is zeroed). */
    for (off = 0; off < pt_len; off += 16) {
        n = pt_len - off < 16 ? pt_len - off : 16;
        ccm_s(key, nonce, ctr++, s);
        memcpy(out + off, in + off, n);
        ccm_xor(out + off, s, n);
    }
    ccm_mac(key, nonce, aad, aad_len, out, pt_len, mac);
    ccm_s(key, nonce, 0, s); /* S0 */
    ccm_xor(mac, s, DTN_CCM_TAG_LEN);
    for (n = 0; n < DTN_CCM_TAG_LEN; n++) {
        diff |= (uint8_t)(mac[n] ^ in[pt_len + n]);
    }
    if (diff != 0) {
        memset(out, 0, pt_len);
        return -1;
    }
    return 0;
}
