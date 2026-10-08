package link

// AES-CCM tests: the RFC 3610 §8 packet vectors (fetched from the RFC text,
// 2026-10-07 — inputs quoted verbatim; each RFC "authenticated and
// encrypted output" is AData ‖ ciphertext ‖ MAC), the §6.2 profile
// roundtrip, and fail-closed tamper tests.

import (
	"bytes"
	"encoding/hex"
	"testing"
)

type rfc3610Vector struct {
	name, key, nonce, adata, msg, out string // out = AData ‖ CT ‖ MAC
	m                                 int    // MAC length
}

var rfc3610Vectors = []rfc3610Vector{
	{
		name: "packet_vector_1", m: 8,
		key:   "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF",
		nonce: "00000003020100A0A1A2A3A4A5",
		adata: "0001020304050607",
		msg:   "08090A0B0C0D0E0F101112131415161718191A1B1C1D1E",
		out:   "0001020304050607" + "588C979A61C663D2F066D0C2C0F989806D5F6B61DAC38417" + "E8D12CFDF926E0",
	},
	{
		name: "packet_vector_3", m: 8,
		key:   "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF",
		nonce: "00000005040302A0A1A2A3A4A5",
		adata: "0001020304050607",
		msg:   "08090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20",
		out:   "0001020304050607" + "51B1E5F44A197D1DA46B0F8E2D282AE871E838BB64DA8596574ADAA76FBD9FB0" + "C5",
	},
	{
		name: "packet_vector_6", m: 8,
		key:   "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF",
		nonce: "00000008070605A0A1A2A3A4A5",
		adata: "000102030405060708090A0B",
		msg:   "0C0D0E0F101112131415161718191A1B1C1D1E1F20",
		out:   "000102030405060708090A0B" + "6FC1B011F006568B5171A42D953D469B2570A4BD87405A04" + "43AC91CB94",
	},
	{
		name: "packet_vector_7", m: 10,
		key:   "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF",
		nonce: "00000009080706A0A1A2A3A4A5",
		adata: "0001020304050607",
		msg:   "08090A0B0C0D0E0F101112131415161718191A1B1C1D1E",
		out:   "0001020304050607" + "0135D1B2C95F41D5D1D4FEC185D166B8094E999DFED96C" + "048C56602C97ACBB7490",
	},
	{
		name: "packet_vector_12", m: 10,
		key:   "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF",
		nonce: "0000000E0D0C0BA0A1A2A3A4A5",
		adata: "000102030405060708090A0B",
		msg:   "0C0D0E0F101112131415161718191A1B1C1D1E1F20",
		out:   "000102030405060708090A0B" + "C0FFA0D6F05BDB67F24D43A4338D2AA4BED7B20E43CD1AA31662E7AD" + "65D6DB",
	},
	{
		name: "packet_vector_13", m: 8,
		key:   "D7828D13B2B0BDC325A76236DF93CC6B",
		nonce: "00412B4EA9CDBE3C9696766CFA",
		adata: "0BE1A88BACE018B1",
		msg:   "08E8CF97D820EA258460E96AD9CF5289054D895CEAC47C",
		out:   "0BE1A88BACE018B1" + "4CB97F86A2A4689A877947AB8091EF5386A6FFBDD080F8E78CF7CB0C" + "DDD7B3",
	},
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("vector hex %q: %v", s, err)
	}
	return b
}

func TestCCMRFC3610(t *testing.T) {
	for _, v := range rfc3610Vectors {
		t.Run(v.name, func(t *testing.T) {
			key, nonce, adata, msg, out := mustHex(t, v.key), mustHex(t, v.nonce), mustHex(t, v.adata), mustHex(t, v.msg), mustHex(t, v.out)
			if len(nonce) != NonceLen {
				t.Fatalf("test bug: nonce %d B", len(nonce))
			}
			got, err := sealCCM(key, nonce, adata, msg, v.m)
			if err != nil {
				t.Fatalf("seal: %v", err)
			}
			if !bytes.Equal(got, out[len(adata):]) {
				t.Fatalf("seal diverged from RFC 3610:\n got %X\nwant %X", got, out[len(adata):])
			}
			pt, err := openCCM(key, nonce, adata, out[len(adata):], v.m)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			if !bytes.Equal(pt, msg) {
				t.Fatalf("open roundtrip mismatch: %X != %X", pt, msg)
			}
		})
	}
}

func TestCCMProfileRoundtrip(t *testing.T) {
	// The §6.2 profile: 16-byte tag, 13-byte nonce = salt ‖ BE8(seq),
	// variable plaintexts across the AES block boundary.
	var key [KeyLen]byte
	var nonce [NonceLen]byte
	for i := range key {
		key[i] = byte(i + 1)
	}
	nonce = Nonce([NonceSaltLen]byte{0xa1, 0xa2, 0xa3, 0xa4, 0xa5}, 42)
	for _, n := range []int{0, 1, 15, 16, 17, 221, 222} {
		msg := make([]byte, n)
		for i := range msg {
			msg[i] = byte(i ^ n)
		}
		aad := []byte{EncodeHeader(TypeBundleFrag, 0)}
		ct, err := Seal(key, nonce, aad, msg)
		if err != nil {
			t.Fatalf("seal(%d): %v", n, err)
		}
		if len(ct) != n+TagLen {
			t.Fatalf("seal(%d): %d B out, want %d", n, len(ct), n+TagLen)
		}
		pt, err := Open(key, nonce, aad, ct)
		if err != nil {
			t.Fatalf("open(%d): %v", n, err)
		}
		if !bytes.Equal(pt, msg) {
			t.Fatalf("open(%d) mismatch", n)
		}
		// Tamper: every flipped bit anywhere in ct‖tag must fail closed.
		for _, pos := range []int{0, n / 2, n, n + TagLen - 1} {
			bad := append([]byte(nil), ct...)
			bad[pos] ^= 0x80
			if _, err := Open(key, nonce, aad, bad); err == nil {
				t.Fatalf("tampered ct at %d accepted (%d B plaintext)", pos, n)
			}
		}
		// AAD mismatch must fail too.
		if _, err := Open(key, nonce, []byte{0xff}, ct); err == nil {
			t.Fatalf("aad mismatch accepted (%d B plaintext)", n)
		}
	}
}

func TestCCMRejectsBadParams(t *testing.T) {
	var key [KeyLen]byte
	var nonce [NonceLen]byte
	if _, err := Seal(key, [NonceLen]byte{}, nil, []byte{1}); err != nil {
		t.Fatalf("zero nonce is a valid input: %v", err)
	}
	short := make([]byte, NonceLen-1)
	if _, err := sealCCM(key[:], short, nil, []byte{1}, TagLen); err == nil {
		t.Fatal("short nonce accepted")
	}
	bigNonce := make([]byte, NonceLen+1)
	if _, err := sealCCM(key[:], bigNonce, nil, []byte{1}, TagLen); err == nil {
		t.Fatal("long nonce accepted")
	}
	badKey := make([]byte, KeyLen-1)
	if _, err := sealCCM(badKey, nonce[:], nil, []byte{1}, TagLen); err == nil {
		t.Fatal("short key accepted")
	}
	if _, err := sealCCM(key[:], nonce[:], nil, []byte{1}, 15); err == nil {
		t.Fatal("odd tag length accepted")
	}
	if _, err := sealCCM(key[:], nonce[:], nil, make([]byte, MaxPlaintext+1), TagLen); err == nil {
		t.Fatal("oversize plaintext accepted")
	}
}
