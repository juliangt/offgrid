package bundle

// Shared conformance vectors for P3.2 (tests/vectors/bundle/vectors.json) —
// the single source of truth executed by BOTH the Go suite (this test) and
// the C host suite (esp32/components/dtn_core/host/tests/test_bundle.c via
// the generated header host/tests/bundle_vectors.h). This is the issue's
// "byte-identical encodings Go↔C" mechanism, the #39/P3.1 pattern: one
// committed JSON + one generated C header, both rewritten by this test's
// -regen flag and never allowed to drift.
//
// Provenance: RFC 9171 (nor any published erratum or official companion —
// verified against the RFC text and the errata registry, 2026-10-07)
// provides NO byte-level example bundles usable as vectors; the profile's
// own conformance anchors are its §3 rules and the §4 measured encodings of
// docs/node-network.md, which these vectors ARE. The optional µD3TN interop
// spot-check remains deferred (and AGPLv3 forbids code linkage anyway).

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// Fixed vector clock and fixture EIDs (the repo fixture time and the §4
// example fingerprint — the same og.0123456789abcdef the spec's byte tables
// use; fpB is nodeid's second vector node for continuity).
const (
	vecNow      = int64(1791072000)
	vecFPA      = testFP             // "0123456789abcdef"
	vecFPB      = "dac073e0123bdea5" // nodeid vector node2's fingerprint
	vecRegenCmd = "cd node && go test ./internal/bundle -run TestVectorsStable -regen"
)

// JSON schema types (field order = marshal order = deterministic bytes).
type (
	vecEncode struct {
		Name          string `json:"name"`
		Kind          string `json:"kind"` // "mail" | "management"
		EnvelopeHex   string `json:"envelope_hex,omitempty"`
		SrcEID        string `json:"src_eid,omitempty"`
		DstEID        string `json:"dst_eid,omitempty"`
		InnerHex      string `json:"inner_hex,omitempty"`
		CreatedUnixMs int64  `json:"created_unix_ms"`
		TtlS          uint64 `json:"ttl_s"`
		Seq           uint64 `json:"seq"`
		Hop           byte   `json:"hop"`
		ExpectPDUHex  string `json:"expect_pdu_hex"`
	}
	vecAcceptExpect struct {
		Destination   string `json:"destination"`
		Source        string `json:"source"`
		ReportTo      string `json:"report_to"`
		CreationDTNms uint64 `json:"creation_dtn_ms"`
		Sequence      uint64 `json:"sequence"`
		Lifetime      uint64 `json:"lifetime"`
		Hop           int    `json:"hop"`
		PayloadHex    string `json:"payload_hex"`
		BundleIDHex   string `json:"bundle_id_hex"`
		PrimaryLen    int    `json:"primary_len"`
		ContentOff    int    `json:"content_off"`
	}
	vecAccept struct {
		Name     string          `json:"name"`
		PDUHex   string          `json:"pdu_hex"`
		NowUnixS int64           `json:"now_unix_s"`
		Expect   vecAcceptExpect `json:"expect"`
	}
	vecReject struct {
		Name       string `json:"name"`
		PDUHex     string `json:"pdu_hex"`
		NowUnixS   int64  `json:"now_unix_s"`
		ExpectCode string `json:"expect_code"`
		Why        string `json:"why"`
	}
	vecHop struct {
		Name       string `json:"name"`
		InHex      string `json:"in_hex"`
		OutHex     string `json:"out_hex,omitempty"`
		ExpectCode string `json:"expect_code,omitempty"` // set → RewriteHop must refuse
	}
	vectorSet struct {
		Provenance   string      `json:"provenance"`
		RegenCommand string      `json:"regen_command"`
		Now          int64       `json:"now"`
		Encode       []vecEncode `json:"encode"`
		ParseAccept  []vecAccept `json:"parse_accept"`
		ParseReject  []vecReject `json:"parse_reject"`
		HopRewrite   []vecHop    `json:"hop_rewrite"`
	}
)

// Paths resolve from THIS file's location (runtime.Caller), never from the
// test process's working directory, which the go tool does not guarantee.
func vecRoot() string {
	_, thisFile, _, _ := runtime.Caller(0)
	// vectors_test.go -> bundle -> internal -> node -> repo root
	return filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(thisFile))))
}

func vecJSONPath() string {
	return filepath.Join(vecRoot(), "tests", "vectors", "bundle", "vectors.json")
}

func vecHeaderPath() string {
	return filepath.Join(vecRoot(), "esp32", "components", "dtn_core", "host", "tests", "bundle_vectors.h")
}

var regenBundleVectors = flag.Bool("regen", false, "regenerate tests/vectors/bundle/vectors.json and the C host header")

// buildVectorSet deterministically derives every vector from the profile's
// own fixtures. Same inputs → byte-identical JSON and C header.
func buildVectorSet(t *testing.T) *vectorSet {
	t.Helper()
	createdUnix := vecNow - 3600
	createdMs := createdUnix * 1000
	docCreatedMs := int64(testCreated) * 1000 // the §3.2 example's created_at
	ttl := uint64(testTTL)

	// -- encode vectors: constructor inputs → the full canonical PDU.
	mkMail := func(name string, envLen int, created int64, hop byte) (vecEncode, []byte) {
		b, err := NewMail(envelopeOf(envLen), created, ttl)
		if err != nil {
			t.Fatal(err)
		}
		b.Hop = hop
		pdu, err := Encode(b)
		if err != nil {
			t.Fatal(err)
		}
		return vecEncode{
			Name: name, Kind: "mail", EnvelopeHex: hex.EncodeToString(envelopeOf(envLen)),
			CreatedUnixMs: created, TtlS: ttl, Hop: hop, ExpectPDUHex: hex.EncodeToString(pdu),
		}, pdu
	}
	mkMgmt := func(name, src, dst string, created int64, seq uint64, hop byte, inner []byte) (vecEncode, []byte) {
		b, err := NewManagement("dtn://og."+src+"/", "dtn://og."+dst+"/", created, ttl, seq, inner)
		if err != nil {
			t.Fatal(err)
		}
		b.Hop = hop
		pdu, err := Encode(b)
		if err != nil {
			t.Fatal(err)
		}
		return vecEncode{
			Name: name, Kind: "management",
			SrcEID: "dtn://og." + src + "/", DstEID: "dtn://og." + dst + "/",
			InnerHex:      hex.EncodeToString(inner),
			CreatedUnixMs: created, TtlS: ttl, Seq: seq, Hop: hop,
			ExpectPDUHex: hex.EncodeToString(pdu),
		}, pdu
	}
	innerCOSE := minimalCOSESign1(make([]byte, 20)) // the §4.1 floor, 93 B
	e1, pduMailSmall := mkMail("mail_small_envelope", 32, createdMs, 0)
	e2, _ := mkMail("mail_doc_example", 16, docCreatedMs, 0)                           // §4's primary block
	e3, _ := mkMgmt("mgmt_doc_example", vecFPA, vecFPA, docCreatedMs, 1, 0, innerCOSE) // §4's primary block
	e4, _ := mkMgmt("mgmt_pair", vecFPA, vecFPB, createdMs, 42, 0, innerCOSE)
	e5, _ := mkMail("mail_max_envelope_399", 399, createdMs, 0)
	enc := []vecEncode{e1, e2, e3, e4, e5}

	expect := func(name string, pdu []byte, now int64) vecAccept {
		t.Helper()
		b, err := Parse(pdu, timeUnix(now))
		if err != nil {
			t.Fatalf("%s: vector PDU does not parse: %v", name, err)
		}
		id, err := BundleIDOf(pdu)
		if err != nil {
			t.Fatal(err)
		}
		return vecAccept{
			Name: name, PDUHex: hex.EncodeToString(pdu), NowUnixS: now,
			Expect: vecAcceptExpect{
				Destination: b.Destination.String(), Source: b.Source.String(), ReportTo: b.ReportTo.String(),
				CreationDTNms: b.CreationDTNms, Sequence: b.Sequence, Lifetime: b.Lifetime, Hop: int(b.Hop),
				PayloadHex: hex.EncodeToString(b.Payload), BundleIDHex: hex.EncodeToString(id[:]),
				PrimaryLen: b.PrimaryLen, ContentOff: b.ContentOff,
			},
		}
	}

	// -- parse_accept: the encoded vectors re-read at fixed receiver clocks.
	hop7 := mailWithHop(t, 32, createdMs, 7)
	hop3 := mgmtWithHop(t, vecFPA, vecFPB, createdMs, 42, 3, innerCOSE)
	acc := []vecAccept{
		expect("mail_small_hop0", pduMailSmall, vecNow),
		expect("mail_skew_boundary_300s", pduMailSmall, createdUnix-300), // exactly the P-6 ceiling
		expect("mail_hop7_still_parses", hop7, vecNow),
		expect("mgmt_pair_hop3", hop3, vecNow),
	}

	// -- parse_reject: every malformed class, CRC-recomputed where the class
	// under test is NOT the CRC.
	d, err := decode(pduMailSmall)
	if err != nil {
		t.Fatal(err)
	}
	content := append([]byte{0}, envelopeOf(32)...)
	mut := func(f func(p []byte)) []byte {
		out := bytes.Clone(pduMailSmall)
		f(out)
		return out
	}
	patchPrimaryCRC := func(p []byte) {
		// Only user: non_shortest_version, whose INSERTED byte shifts the
		// primary CRC head by 1.
		crcHead := d.primaryLen + 1 - 3
		c := crc16x25(p[:crcHead])
		p[crcHead+1] = byte(c >> 8)
		p[crcHead+2] = byte(c)
	}
	patchPayCRC := func(p []byte) { patchPayloadCRC(t, p, d.primaryLen) }
	customPrimary := func(dest, src, rpt EID, lifetime uint64) []byte {
		return bundle(primaryBlockDTNms(dest, src, rpt, d.creationDTNms, 0, lifetime), payloadBlock(content))
	}
	nonShortest := func() []byte {
		p := append(bytes.Clone(pduMailSmall[:2]), append([]byte{0x18}, pduMailSmall[2:]...)...)
		patchPrimaryCRC(p) // the primary CRC head shifted by the insert
		return p
	}
	rej := []vecReject{
		{"empty_input", "", vecNow, CodeTruncated, "the empty PDU truncates before the first head"},
		{"truncated_head", hex.EncodeToString(pduMailSmall[:4]), vecNow, CodeTruncated, "ends mid-primary-block"},
		{"truncated_tail", hex.EncodeToString(pduMailSmall[:len(pduMailSmall)-1]), vecNow, CodeTruncated, "the last CRC byte is missing"},
		{"bad_crc_primary", hex.EncodeToString(mut(func(p []byte) { p[d.primaryLen-1] ^= 0x01 })), vecNow, CodeCRC, "one flipped bit in the primary block's CRC value"},
		{"bad_crc_payload", hex.EncodeToString(mut(func(p []byte) { p[len(p)-1] ^= 0x01 })), vecNow, CodeCRC, "one flipped bit in the payload block's CRC value"},
		{"bitflip_content", hex.EncodeToString(mut(func(p []byte) { p[d.contentOff+5] ^= 0x80 })), vecNow, CodeCRC, "one flipped bit inside the payload content — the block CRC must catch it"},
		{"version_6", hex.EncodeToString(mut(func(p []byte) { p[1] = 6 })), vecNow, CodeVersion, "RFC 5050's version is out of profile (P-3)"},
		{"version_8", hex.EncodeToString(mut(func(p []byte) { p[1] = 8 })), vecNow, CodeVersion, "unknown BP version"},
		{"primary_flags_1", hex.EncodeToString(mut(func(p []byte) { p[2] = 1 })), vecNow, CodeFlags, "processing-control flags must be 0 in v1 (P-3)"},
		{"payload_flags_1", hex.EncodeToString(mut(func(p []byte) { p[d.primaryLen+3] = 1 })), vecNow, CodeFlags, "payload block control flags must be 0 in v1"},
		{"three_blocks", hex.EncodeToString(append(bytes.Clone(pduMailSmall), payloadBlock([]byte{0, 1})...)), vecNow, CodeBlockCount, "a bundle is exactly two blocks (P-1)"},
		{"trailing_byte", hex.EncodeToString(append(bytes.Clone(pduMailSmall), 0x00)), vecNow, CodeBlockCount, "trailing bytes after the payload block"},
		{"payload_block_type_2", hex.EncodeToString(mut(func(p []byte) { p[d.primaryLen+1] = 2 })), vecNow, CodeBlockType, "extension blocks are outside the profile (P-2)"},
		{"indefinite_primary", hex.EncodeToString(mut(func(p []byte) { p[0] = 0x9f })), vecNow, CodeNonCanonical, "indefinite-length heads are rejected (P-1)"},
		{"non_shortest_version", hex.EncodeToString(nonShortest()), vecNow, CodeNonCanonical, "version encoded 0x18 0x07 is not the shortest form (P-1)"},
		{"hop_8", hex.EncodeToString(mut(func(p []byte) { p[d.contentOff] = 8; patchPayCRC(p) })), vecNow, CodeHop, "the hop octet exceeds 7 (§3.1)"},
		{"future_skew_301", hex.EncodeToString(pduMailSmall), createdUnix - 301, CodeSkew, "creation is 301 s ahead of the receiver — past the 300 s ceiling (P-6)"},
		{"lifetime_0", hex.EncodeToString(customPrimary(mailGroupEID, eidNone, eidNone, 0)), vecNow, CodeLifetime, "lifetime 0 expires on arrival (P-6)"},
		{"dest_none", hex.EncodeToString(customPrimary(eidNone, eidNone, eidNone, ttl)), vecNow, CodeEID, "an anonymous destination has no plane to ride (P-4/P-5)"},
		{"source_group_eid", hex.EncodeToString(customPrimary(mailGroupEID, mailGroupEID, eidNone, ttl)), vecNow, CodeEID, "a mail source must be anonymous, not a group EID (P-4)"},
		{"report_to_node", hex.EncodeToString(customPrimary(mailGroupEID, eidNone, nodeEID(vecFPA), ttl)), vecNow, CodeEID, "report-to is pinned to dtn:none in this profile (P-4/P-5)"},
		{"source_uppercase_fp", hex.EncodeToString(customPrimary(mailGroupEID, nodeEID("0123456789ABCDEF"), eidNone, ttl)), vecNow, CodeEID, "node fingerprints are 16 LOWERCASE hex chars (§2.1)"},
		{"source_short_fp", hex.EncodeToString(customPrimary(mailGroupEID, nodeEID("01234567"), eidNone, ttl)), vecNow, CodeEID, "an 8-hex-char fingerprint is not a node EID"},
		{"source_empty_eid", hex.EncodeToString(customPrimary(mailGroupEID, eid{}, eidNone, ttl)), vecNow, CodeEID, "[\"\",\"\"] is anonymous-shaped but must never stand in for dtn:none"},
		{"source_both_parts", hex.EncodeToString(customPrimary(mailGroupEID, eid{authority: "og." + vecFPA, local: "x"}, eidNone, ttl)), vecNow, CodeEID, "an EID with both authority and SSP set is not a profile shape"},
		{"empty_content", hex.EncodeToString(bundle(primaryBlockDTNms(mailGroupEID, eidNone, eidNone, d.creationDTNms, 0, ttl), payloadBlock(nil))), vecNow, CodeEmptyPayload, "payload content must be hop ‖ non-empty PDU"},
		{"hop_only_content", hex.EncodeToString(bundle(primaryBlockDTNms(mailGroupEID, eidNone, eidNone, d.creationDTNms, 0, ttl), payloadBlock([]byte{0}))), vecNow, CodeEmptyPayload, "an empty PDU behind the hop octet is not a profile bundle"},
	}

	// -- hop_rewrite: the §3.1 relay operation end-to-end.
	rewritten := func(p []byte) []byte {
		t.Helper()
		out, err := RewriteHop(p)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	hop := []vecHop{
		{Name: "hop_0_to_1", InHex: hex.EncodeToString(pduMailSmall), OutHex: hex.EncodeToString(rewritten(pduMailSmall))},
		{Name: "hop_6_to_7", InHex: hex.EncodeToString(mailWithHop(t, 32, createdMs, 6)), OutHex: hex.EncodeToString(rewritten(mailWithHop(t, 32, createdMs, 6)))},
		{Name: "hop_7_rejected", InHex: hex.EncodeToString(hop7), ExpectCode: CodeHop},
		{Name: "truncated_rejected", InHex: hex.EncodeToString(pduMailSmall[:10]), ExpectCode: CodeTruncated},
	}

	return &vectorSet{
		Provenance: "Generated by node/internal/bundle (issue #33 P3.2) from the Offgrid BPv7 profile: " +
			"docs/node-network.md §3 rules P-1..P-7 and the §4 measured encodings. RFC 9171 provides NO " +
			"byte-level example bundles (verified against the RFC text and the errata registry, 2026-10-07); " +
			"the optional µD3TN interop spot-check remains deferred (AGPLv3 forbids code linkage). The og." +
			"0123456789abcdef fixture is the §4 example fingerprint. Deterministic; committed copies MUST " +
			"NOT be hand-edited.",
		RegenCommand: vecRegenCmd,
		Now:          vecNow,
		Encode:       enc,
		ParseAccept:  acc,
		ParseReject:  rej,
		HopRewrite:   hop,
	}
}

func mailWithHop(t *testing.T, envLen int, createdMs int64, hop byte) []byte {
	t.Helper()
	b, err := NewMail(envelopeOf(envLen), createdMs, testTTL)
	if err != nil {
		t.Fatal(err)
	}
	b.Hop = hop
	pdu, err := Encode(b)
	if err != nil {
		t.Fatal(err)
	}
	return pdu
}

func mgmtWithHop(t *testing.T, srcFP, dstFP string, createdMs int64, seq uint64, hop byte, inner []byte) []byte {
	t.Helper()
	b, err := NewManagement("dtn://og."+srcFP+"/", "dtn://og."+dstFP+"/", createdMs, testTTL, seq, inner)
	if err != nil {
		t.Fatal(err)
	}
	b.Hop = hop
	pdu, err := Encode(b)
	if err != nil {
		t.Fatal(err)
	}
	return pdu
}

func timeUnix(sec int64) time.Time { return time.Unix(sec, 0) }

// --- the generated C header --------------------------------------------------

func vecJSONBytes(t *testing.T, vs *vectorSet) []byte {
	t.Helper()
	b, err := json.MarshalIndent(vs, "", "  ")
	if err != nil {
		t.Fatalf("marshal vectors: %v", err)
	}
	return append(b, '\n')
}

func vecCHeaderBytes(t *testing.T, vs *vectorSet) []byte {
	t.Helper()
	hexb := func(s string) []byte {
		t.Helper()
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatalf("vector hex: %v", err)
		}
		return b
	}
	var out bytes.Buffer
	fmt.Fprintf(&out, `/* bundle_vectors.h — P3.2 BPv7 profile codec test vectors for the C host
 * suite. GENERATED from tests/vectors/bundle/vectors.json by the Go vector
 * test:
 *   %s
 * Do not edit by hand — regenerate (the JSON provenance field records the
 * profile derivation; RFC 9171 has no official byte-level examples). Sharing
 * one generated file is the Go<->C interop contract: the PDUs below were
 * ENCODED in Go and must be reproduced byte for byte in C.
 */
#ifndef DTN_TEST_BUNDLE_VECTORS_H
#define DTN_TEST_BUNDLE_VECTORS_H

#include <stddef.h>
#include <stdint.h>

#define BUNDLE_VEC_NOW %dll

`, vecRegenCmd, vs.Now)

	hexBytes := func(w *bytes.Buffer, name string, b []byte) {
		fmt.Fprintf(w, "static const uint8_t %s[] = {", name)
		for i, c := range b {
			if i%16 == 0 {
				w.WriteString("\n    ")
			}
			fmt.Fprintf(w, "0x%02x,", c)
		}
		if len(b)%16 != 0 {
			w.WriteString("\n")
		}
		w.WriteString("};\n")
	}

	fmt.Fprintf(&out, "/* encode vectors: build the inputs with the C constructors and compare the\n * encoded PDU bytes — the cross-implementation byte-identity gate. */\n")
	fmt.Fprintf(&out, "typedef struct {\n    const char *name;\n    int kind;                                     /* 0 = mail, 1 = management */\n    const uint8_t *envelope; size_t envelope_len; /* mail */\n    const char *src_eid, *dst_eid;                /* management */\n    const uint8_t *inner; size_t inner_len;       /* management */\n    long long created_unix_ms;\n    unsigned long long ttl_s;\n    unsigned long long seq;\n    unsigned char hop;\n    const uint8_t *expect_pdu; size_t pdu_len;\n} dtn_bundle_enc_vec;\n\n")
	for i, e := range vs.Encode {
		sym := fmt.Sprintf("BUNDLE_ENC_%d", i)
		switch e.Kind {
		case "mail":
			hexBytes(&out, sym+"_ENVELOPE", hexb(e.EnvelopeHex))
		case "management":
			hexBytes(&out, sym+"_INNER", hexb(e.InnerHex))
		}
		hexBytes(&out, sym+"_PDU", hexb(e.ExpectPDUHex))
	}
	fmt.Fprintf(&out, "\nstatic const dtn_bundle_enc_vec BUNDLE_ENC_VECS[] = {\n")
	for i, e := range vs.Encode {
		sym := fmt.Sprintf("BUNDLE_ENC_%d", i)
		kind := 0
		inputs := "0, 0, \"\", \"\", 0, 0"
		switch e.Kind {
		case "mail":
			inputs = fmt.Sprintf("%s, sizeof(%s), \"\", \"\", 0, 0", sym+"_ENVELOPE", sym+"_ENVELOPE")
		case "management":
			kind = 1
			inputs = fmt.Sprintf("0, 0, \"%s\", \"%s\", %s, sizeof(%s)", e.SrcEID, e.DstEID, sym+"_INNER", sym+"_INNER")
		}
		fmt.Fprintf(&out, "    {\"%s\", %d, %s, %s, %s, %s, %d, %s, sizeof(%s)},\n",
			e.Name, kind, inputs, cLL(e.CreatedUnixMs), cULL(e.TtlS), cULL(e.Seq), e.Hop, sym+"_PDU", sym+"_PDU")
	}
	out.WriteString("};\n")

	fmt.Fprintf(&out, "\n/* parse_accept: verdicts + every parsed field + the P-7 bundle_id. */\n")
	fmt.Fprintf(&out, "typedef struct {\n    const char *name;\n    const uint8_t *pdu; size_t pdu_len;\n    long long now_unix_s;\n    const char *destination, *source, *report_to;\n    unsigned long long creation_dtn_ms, sequence, lifetime;\n    int hop;\n    const uint8_t *payload; size_t payload_len;\n    const uint8_t *bundle_id; /* 32 bytes */\n    int primary_len, content_off;\n} dtn_bundle_acc_vec;\n\n")
	for i, a := range vs.ParseAccept {
		hexBytes(&out, fmt.Sprintf("BUNDLE_ACC_%d_PDU", i), hexb(a.PDUHex))
		hexBytes(&out, fmt.Sprintf("BUNDLE_ACC_%d_PAYLOAD", i), hexb(a.Expect.PayloadHex))
		hexBytes(&out, fmt.Sprintf("BUNDLE_ACC_%d_BID", i), hexb(a.Expect.BundleIDHex))
	}
	fmt.Fprintf(&out, "\nstatic const dtn_bundle_acc_vec BUNDLE_ACC_VECS[] = {\n")
	for i, a := range vs.ParseAccept {
		pdu, pay, bid := fmt.Sprintf("BUNDLE_ACC_%d_PDU", i), fmt.Sprintf("BUNDLE_ACC_%d_PAYLOAD", i), fmt.Sprintf("BUNDLE_ACC_%d_BID", i)
		fmt.Fprintf(&out, "    {\"%s\", %s, sizeof(%s), %s, \"%s\", \"%s\", \"%s\", %s, %s, %s, %d, %s, sizeof(%s), %s, %d, %d},\n",
			a.Name, pdu, pdu, cLL(a.NowUnixS), a.Expect.Destination, a.Expect.Source, a.Expect.ReportTo,
			cULL(a.Expect.CreationDTNms), cULL(a.Expect.Sequence), cULL(a.Expect.Lifetime), a.Expect.Hop,
			pay, pay, bid, a.Expect.PrimaryLen, a.Expect.ContentOff)
	}
	out.WriteString("};\n")

	fmt.Fprintf(&out, "\n/* parse_reject: every malformed class with its stable failure code. */\n")
	fmt.Fprintf(&out, "typedef struct {\n    const char *name;\n    const uint8_t *pdu; size_t pdu_len;\n    long long now_unix_s;\n    const char *expect_code;\n} dtn_bundle_rej_vec;\n\n")
	for i, r := range vs.ParseReject {
		hexBytes(&out, fmt.Sprintf("BUNDLE_REJ_%d_PDU", i), hexb(r.PDUHex))
	}
	fmt.Fprintf(&out, "\nstatic const dtn_bundle_rej_vec BUNDLE_REJ_VECS[] = {\n")
	for i, r := range vs.ParseReject {
		sym := fmt.Sprintf("BUNDLE_REJ_%d_PDU", i)
		fmt.Fprintf(&out, "    {\"%s\", %s, sizeof(%s), %s, \"%s\"},\n", r.Name, sym, sym, cLL(r.NowUnixS), r.ExpectCode)
	}
	out.WriteString("};\n")

	fmt.Fprintf(&out, "\n/* hop_rewrite: the §3.1 relay operation (expect_code set = refuse). */\n")
	fmt.Fprintf(&out, "typedef struct {\n    const char *name;\n    const uint8_t *in; size_t in_len;\n    const uint8_t *out; size_t out_len; /* when expect_code == NULL */\n    const char *expect_code;            /* NULL = success */\n} dtn_bundle_hop_vec;\n\n")
	for i, h := range vs.HopRewrite {
		hexBytes(&out, fmt.Sprintf("BUNDLE_HOP_%d_IN", i), hexb(h.InHex))
		if h.OutHex != "" {
			hexBytes(&out, fmt.Sprintf("BUNDLE_HOP_%d_OUT", i), hexb(h.OutHex))
		}
	}
	fmt.Fprintf(&out, "\nstatic const dtn_bundle_hop_vec BUNDLE_HOP_VECS[] = {\n")
	for i, h := range vs.HopRewrite {
		inSym := fmt.Sprintf("BUNDLE_HOP_%d_IN", i)
		if h.ExpectCode != "" {
			fmt.Fprintf(&out, "    {\"%s\", %s, sizeof(%s), 0, 0, \"%s\"},\n", h.Name, inSym, inSym, h.ExpectCode)
		} else {
			outSym := fmt.Sprintf("BUNDLE_HOP_%d_OUT", i)
			fmt.Fprintf(&out, "    {\"%s\", %s, sizeof(%s), %s, sizeof(%s), NULL},\n", h.Name, inSym, inSym, outSym, outSym)
		}
	}
	out.WriteString("};\n")

	out.WriteString("\n#endif /* DTN_TEST_BUNDLE_VECTORS_H */\n")
	return out.Bytes()
}

// cLL / cULL render C integer literals with their suffixes (%dll / %dull in
// a format string would trip go vet's printf checker).
func cLL(v int64) string   { return fmt.Sprintf("%dll", v) }
func cULL(v uint64) string { return fmt.Sprintf("%dull", v) }

// TestVectorsStable pins the committed artifacts: the deterministic builder
// must reproduce tests/vectors/bundle/vectors.json AND the C header
// byte-for-byte. -regen rewrites both (the only sanctioned way to change
// them).
func TestVectorsStable(t *testing.T) {
	wantJSON := vecJSONBytes(t, buildVectorSet(t))
	wantHeader := vecCHeaderBytes(t, buildVectorSet(t))
	jsonPath := vecJSONPath()
	headerPath := vecHeaderPath()
	if regenBundleVectors != nil && *regenBundleVectors {
		if err := os.MkdirAll(filepath.Dir(jsonPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(headerPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(jsonPath, wantJSON, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(headerPath, wantHeader, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("regenerated %s and %s", jsonPath, headerPath)
		return
	}
	gotJSON, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("committed vectors missing (run %s): %v", vecRegenCmd, err)
	}
	if !bytes.Equal(gotJSON, wantJSON) {
		t.Fatalf("vectors.json drifted from the deterministic builder — run %s and commit", vecRegenCmd)
	}
	gotHeader, err := os.ReadFile(headerPath)
	if err != nil {
		t.Fatalf("committed C header missing (run %s): %v", vecRegenCmd, err)
	}
	if !bytes.Equal(gotHeader, wantHeader) {
		t.Fatalf("bundle_vectors.h drifted from vectors.json — run %s and commit", vecRegenCmd)
	}
}

// TestCrossImplementationByteIdentity executes every committed vector against
// the GO implementation: the encode vectors pin the exact PDU bytes the C
// side must reproduce (the generated header carries the same bytes), and the
// parse/hop vectors pin the verdicts both sides must agree on. This is the
// Go half of the issue's "byte-identical encodings Go↔C" criterion (§11 row
// c); test_bundle.c's test_cross_implementation_byte_identity is the C half.
func TestCrossImplementationByteIdentity(t *testing.T) {
	raw, err := os.ReadFile(vecJSONPath())
	if err != nil {
		t.Skipf("vectors not committed yet (%v)", err)
	}
	var vs vectorSet
	if err := json.Unmarshal(raw, &vs); err != nil {
		t.Fatalf("vectors.json: %v", err)
	}

	var encOK, accOK, rejOK, hopOK int
	for _, e := range vs.Encode {
		var b *Bundle
		var err error
		switch e.Kind {
		case "mail":
			env, herr := hex.DecodeString(e.EnvelopeHex)
			if herr != nil {
				t.Fatalf("%s: %v", e.Name, herr)
			}
			b, err = NewMail(env, e.CreatedUnixMs, e.TtlS)
		case "management":
			inner, herr := hex.DecodeString(e.InnerHex)
			if herr != nil {
				t.Fatalf("%s: %v", e.Name, herr)
			}
			b, err = NewManagement(e.SrcEID, e.DstEID, e.CreatedUnixMs, e.TtlS, e.Seq, inner)
		default:
			t.Fatalf("%s: unknown kind %q", e.Name, e.Kind)
		}
		if err != nil {
			t.Fatalf("%s: %v", e.Name, err)
		}
		b.Hop = e.Hop
		pdu, err := Encode(b)
		if err != nil {
			t.Fatalf("%s: %v", e.Name, err)
		}
		if got := hex.EncodeToString(pdu); got != e.ExpectPDUHex {
			t.Errorf("%s: Go encoding diverged from the committed vector:\n got %s\nwant %s", e.Name, got, e.ExpectPDUHex)
		} else {
			encOK++
		}
	}

	for _, a := range vs.ParseAccept {
		pdu := mustVecHex(t, a.PDUHex)
		b, err := Parse(pdu, timeUnix(a.NowUnixS))
		if err != nil {
			t.Errorf("%s: rejected: %v", a.Name, err)
			continue
		}
		id, _ := BundleIDOf(pdu)
		w := a.Expect
		switch {
		case b.Destination.String() != w.Destination, b.Source.String() != w.Source, b.ReportTo.String() != w.ReportTo,
			b.CreationDTNms != w.CreationDTNms, b.Sequence != w.Sequence, b.Lifetime != w.Lifetime, int(b.Hop) != w.Hop,
			hex.EncodeToString(b.Payload) != w.PayloadHex, hex.EncodeToString(id[:]) != w.BundleIDHex,
			b.PrimaryLen != w.PrimaryLen, b.ContentOff != w.ContentOff:
			t.Errorf("%s: parsed fields diverge from the committed expectations", a.Name)
		default:
			accOK++
		}
	}

	for _, r := range vs.ParseReject {
		_, err := Parse(mustVecHex(t, r.PDUHex), timeUnix(r.NowUnixS))
		if got := ErrorCode(err); err == nil || got != r.ExpectCode {
			t.Errorf("%s: code %q, want %q", r.Name, got, r.ExpectCode)
		} else {
			rejOK++
		}
	}

	for _, h := range vs.HopRewrite {
		out, err := RewriteHop(mustVecHex(t, h.InHex))
		if h.ExpectCode != "" {
			if got := ErrorCode(err); err == nil || got != h.ExpectCode {
				t.Errorf("%s: code %q, want %q", h.Name, got, h.ExpectCode)
			} else {
				hopOK++
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", h.Name, err)
			continue
		}
		if got := hex.EncodeToString(out); got != h.OutHex {
			t.Errorf("%s: rewritten PDU diverges:\n got %s\nwant %s", h.Name, got, h.OutHex)
		} else {
			hopOK++
		}
	}

	total := encOK + accOK + rejOK + hopOK
	t.Logf("byte-identity evidence: %d/%d vectors matched on the Go side (encode %d, parse_accept %d, parse_reject %d, hop_rewrite %d); the C suite runs the same set through bundle_vectors.h",
		total, len(vs.Encode)+len(vs.ParseAccept)+len(vs.ParseReject)+len(vs.HopRewrite), encOK, accOK, rejOK, hopOK)
	if len(vs.Encode) < 4 || len(vs.ParseReject) < 20 || len(vs.HopRewrite) < 3 {
		t.Fatalf("the vector set lost coverage: %d encode, %d reject, %d hop", len(vs.Encode), len(vs.ParseReject), len(vs.HopRewrite))
	}
}

func mustVecHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("vector hex: %v", err)
	}
	return b
}
