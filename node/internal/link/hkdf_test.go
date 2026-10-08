package link

// HKDF-SHA256 tests: RFC 5869 Appendix A test cases 1–3 for SHA-256
// (fetched from the RFC text, 2026-10-07, values verbatim).

import (
	"bytes"
	"testing"
)

func TestHkdfRFC5869Case1(t *testing.T) {
	ikm := bytes.Repeat([]byte{0x0b}, 22)
	salt := mustHex(t, "000102030405060708090a0b0c")
	info := mustHex(t, "f0f1f2f3f4f5f6f7f8f9")
	wantPRK := mustHex(t, "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
	wantOKM := mustHex(t, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
	prk := HkdfExtract(salt, ikm)
	if !bytes.Equal(prk[:], wantPRK) {
		t.Fatalf("PRK:\n got %X\nwant %X", prk, wantPRK)
	}
	okm, err := HkdfExpand(prk, info, 42)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(okm, wantOKM) {
		t.Fatalf("OKM:\n got %X\nwant %X", okm, wantOKM)
	}
	via, err := HkdfKey(ikm, salt, info, 42)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(via, wantOKM) {
		t.Fatal("HkdfKey diverges from Extract+Expand")
	}
}

func TestHkdfRFC5869Case2(t *testing.T) {
	ikm := mustHex(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f")
	salt := mustHex(t, "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf")
	info := mustHex(t, "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf"+
		"d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef"+
		"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	wantPRK := mustHex(t, "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244")
	wantOKM := mustHex(t, "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87")
	prk := HkdfExtract(salt, ikm)
	if !bytes.Equal(prk[:], wantPRK) {
		t.Fatalf("PRK:\n got %X\nwant %X", prk, wantPRK)
	}
	okm, err := HkdfExpand(prk, info, 82)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(okm, wantOKM) {
		t.Fatalf("OKM:\n got %X\nwant %X", okm, wantOKM)
	}
}

func TestHkdfRFC5869Case3(t *testing.T) {
	ikm := bytes.Repeat([]byte{0x0b}, 22)
	wantPRK := mustHex(t, "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04")
	wantOKM := mustHex(t, "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")
	prk := HkdfExtract(nil, ikm) // zero-length salt = HashLen zeros
	if !bytes.Equal(prk[:], wantPRK) {
		t.Fatalf("PRK:\n got %X\nwant %X", prk, wantPRK)
	}
	okm, err := HkdfExpand(prk, nil, 42)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(okm, wantOKM) {
		t.Fatalf("OKM:\n got %X\nwant %X", okm, wantOKM)
	}
}

func TestHkdfBounds(t *testing.T) {
	prk := HkdfExtract(nil, []byte("ikm"))
	if _, err := HkdfExpand(prk, nil, 0); err == nil {
		t.Fatal("length 0 accepted")
	}
	if _, err := HkdfExpand(prk, nil, 255*HashLen+1); err == nil {
		t.Fatal("length over the RFC bound accepted")
	}
	// The 255*HashLen bound itself must succeed (expand runs the full chain).
	if okm, err := HkdfExpand(prk, nil, 255*HashLen); err != nil || len(okm) != 255*HashLen {
		t.Fatalf("max length: %d B, err %v", len(okm), err)
	}
}
