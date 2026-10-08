package link

// The deterministic artifacts of the shared link vectors: the JSON
// document and the generated C header. Both are pure functions of
// buildLinkVectorSet's output; TestLinkVectorsStable pins them.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
)

func linkJSONBytes(t *testing.T, vs *vectorSet) []byte {
	t.Helper()
	b, err := json.MarshalIndent(vs, "", "  ")
	if err != nil {
		t.Fatalf("marshal link vectors: %v", err)
	}
	return append(b, '\n')
}

// linkHeaderBytes renders the generated C header (consumed by
// esp32/components/dtn_core/host/tests/test_link.c).
func linkHeaderBytes(t *testing.T, vs *vectorSet) []byte {
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
	fmt.Fprintf(&out, `/* link_vectors.h — P3.3 node-plane link test vectors for the C host
 * suite. GENERATED from tests/vectors/link/vectors.json by the Go vector
 * test:
 *   %s
 * Do not edit by hand — regenerate (the JSON provenance field records the
 * profile derivation). Sharing one generated file is the Go<->C interop
 * contract: the handshake messages, ciphertexts and frames below were
 * PRODUCED in Go and must be reproduced byte for byte in C, and the
 * accept/reject verdicts must match exactly.
 */
#ifndef DTN_TEST_LINK_VECTORS_H
#define DTN_TEST_LINK_VECTORS_H

#include <stddef.h>
#include <stdint.h>

`, linkRegenCmd)

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

	// -- handshake ---------------------------------------------------------
	out.WriteString("/* handshake: fixed seeds/scalars in, byte-exact messages + key schedule out. */\n")
	out.WriteString("typedef struct {\n    const char *name;\n    const uint8_t *seed_a, *seed_b;       /* 32 B Ed25519 seeds */\n    const uint8_t *scalar_i, *scalar_r;    /* 32 B X25519 scalars */\n    const char *eid_a, *eid_b;\n    const uint8_t *msg1; size_t msg1_len;\n    const uint8_t *msg2; size_t msg2_len;\n    const uint8_t *msg3; size_t msg3_len;\n    const uint8_t *th1;                    /* 8 B */\n    const uint8_t *transcript_hash;        /* 32 B */\n    const uint8_t *master;                 /* 32 B */\n    const uint8_t *k_i2r, *s_i2r, *k_r2i, *s_r2i;\n} dtn_link_hs_vec;\n\n")
	for i, h := range vs.Handshake {
		sym := fmt.Sprintf("LINK_HS_%d", i)
		hexBytes(&out, sym+"_SEED_A", hexb(h.SeedAHex))
		hexBytes(&out, sym+"_SEED_B", hexb(h.SeedBHex))
		hexBytes(&out, sym+"_SCALAR_I", hexb(h.ScalarIHex))
		hexBytes(&out, sym+"_SCALAR_R", hexb(h.ScalarRHex))
		hexBytes(&out, sym+"_MSG1", hexb(h.Expect.Msg1Hex))
		hexBytes(&out, sym+"_MSG2", hexb(h.Expect.Msg2Hex))
		hexBytes(&out, sym+"_MSG3", hexb(h.Expect.Msg3Hex))
		hexBytes(&out, sym+"_TH1", hexb(h.Expect.Th1Hex))
		hexBytes(&out, sym+"_TRHASH", hexb(h.Expect.TranscriptHashHex))
		hexBytes(&out, sym+"_MASTER", hexb(h.Expect.MasterHex))
		hexBytes(&out, sym+"_K_I2R", hexb(h.Expect.KI2RHex))
		hexBytes(&out, sym+"_S_I2R", hexb(h.Expect.SI2RHex))
		hexBytes(&out, sym+"_K_R2I", hexb(h.Expect.KR2IHex))
		hexBytes(&out, sym+"_S_R2I", hexb(h.Expect.SR2IHex))
	}
	fmt.Fprintf(&out, "\nstatic const dtn_link_hs_vec LINK_HS_VECS[] = {\n")
	for i, h := range vs.Handshake {
		sym := fmt.Sprintf("LINK_HS_%d", i)
		fmt.Fprintf(&out, "    {\"%s\", %s_SEED_A, %s_SEED_B, %s_SCALAR_I, %s_SCALAR_R, \"%s\", \"%s\", %s_MSG1, sizeof(%s_MSG1), %s_MSG2, sizeof(%s_MSG2), %s_MSG3, sizeof(%s_MSG3), %s_TH1, %s_TRHASH, %s_MASTER, %s_K_I2R, %s_S_I2R, %s_K_R2I, %s_S_R2I},\n",
			h.Name, sym, sym, sym, sym, h.Expect.EIDA, h.Expect.EIDB, sym, sym, sym, sym, sym, sym, sym, sym, sym, sym, sym, sym, sym)
	}
	out.WriteString("};\n")

	// -- ccm ---------------------------------------------------------------
	out.WriteString("\n/* ccm: the §6.2 profile (16 B tag, salt‖seq nonce); sealed = ct ‖ tag. */\n")
	out.WriteString("typedef struct {\n    const char *name;\n    const uint8_t *key; size_t key_len;      /* 16 B */\n    const uint8_t *nonce; size_t nonce_len;  /* 13 B */\n    const uint8_t *aad; size_t aad_len;\n    const uint8_t *plaintext; size_t plaintext_len;\n    const uint8_t *sealed; size_t sealed_len;\n} dtn_link_ccm_vec;\n\n")
	for i, c := range vs.CCM {
		sym := fmt.Sprintf("LINK_CCM_%d", i)
		hexBytes(&out, sym+"_KEY", hexb(c.KeyHex))
		hexBytes(&out, sym+"_NONCE", hexb(c.NonceHex))
		hexBytes(&out, sym+"_AAD", hexb(c.AADHex))
		hexBytes(&out, sym+"_PT", hexb(c.PlaintextHex))
		hexBytes(&out, sym+"_SEALED", hexb(c.SealedHex))
	}
	fmt.Fprintf(&out, "\nstatic const dtn_link_ccm_vec LINK_CCM_VECS[] = {\n")
	for i, c := range vs.CCM {
		sym := fmt.Sprintf("LINK_CCM_%d", i)
		fmt.Fprintf(&out, "    {\"%s\", %s_KEY, sizeof(%s_KEY), %s_NONCE, sizeof(%s_NONCE), %s_AAD, sizeof(%s_AAD), %s_PT, sizeof(%s_PT), %s_SEALED, sizeof(%s_SEALED)},\n",
			c.Name, sym, sym, sym, sym, sym, sym, sym, sym, sym, sym)
	}
	out.WriteString("};\n")

	// -- frame encode ------------------------------------------------------
	out.WriteString("\n/* frame_encode: type + payload in, byte-exact frame out (beacons are\n * the plaintext case; the session types appear as raw frames here). */\n")
	out.WriteString("typedef struct {\n    const char *name;\n    int type;\n    const uint8_t *payload; size_t payload_len;\n    const uint8_t *frame; size_t frame_len;\n} dtn_link_frame_vec;\n\n")
	for i, f := range vs.FrameEncode {
		sym := fmt.Sprintf("LINK_FRM_%d", i)
		hexBytes(&out, sym+"_PAYLOAD", hexb(f.PayloadHex))
		hexBytes(&out, sym+"_FRAME", hexb(f.FrameHex))
	}
	fmt.Fprintf(&out, "\nstatic const dtn_link_frame_vec LINK_FRM_VECS[] = {\n")
	for i, f := range vs.FrameEncode {
		sym := fmt.Sprintf("LINK_FRM_%d", i)
		fmt.Fprintf(&out, "    {\"%s\", %d, %s_PAYLOAD, sizeof(%s_PAYLOAD), %s_FRAME, sizeof(%s_FRAME)},\n",
			f.Name, f.Type, sym, sym, sym, sym)
	}
	out.WriteString("};\n")

	// -- frame reject ------------------------------------------------------
	out.WriteString("\n/* frame_reject: malformed frames with their stable failure codes. */\n")
	out.WriteString("typedef struct {\n    const char *name;\n    const uint8_t *frame; size_t frame_len;\n    const char *expect_code; /* truncated | version | type | flags | oversize */\n} dtn_link_frame_rej_vec;\n\n")
	for i, r := range vs.FrameReject {
		hexBytes(&out, fmt.Sprintf("LINK_FREJ_%d", i), hexb(r.FrameHex))
	}
	fmt.Fprintf(&out, "\nstatic const dtn_link_frame_rej_vec LINK_FREJ_VECS[] = {\n")
	for i, r := range vs.FrameReject {
		sym := fmt.Sprintf("LINK_FREJ_%d", i)
		fmt.Fprintf(&out, "    {\"%s\", %s, sizeof(%s), \"%s\"},\n", r.Name, sym, sym, r.Code)
	}
	out.WriteString("};\n")

	// -- window ------------------------------------------------------------
	out.WriteString("\n/* window: scripted pushes with per-push verdicts and the byte-exact\n * completion contents (hex, ';'-separated, in push order). */\n")
	out.WriteString("typedef struct {\n    const uint8_t *payload; size_t len;\n    const char *verdict; /* partial | done | dup | invalid */\n} dtn_link_win_push;\n\n")
	var winPushes []byte // flattened table (rendered after the loop)
	type winRef struct{ off, n int }
	refs := make([]winRef, 0, len(vs.Window))
	for i, w := range vs.Window {
		off := len(refs) // unused; computed below
		_ = off
		start := countPushes(vs.Window[:i])
		refs = append(refs, winRef{start, len(w.Pushes)})
		for j, p := range w.Pushes {
			b, err := hex.DecodeString(p.PayloadHex)
			if err != nil {
				t.Fatalf("window %d push %d hex: %v", i, j, err)
			}
			name := fmt.Sprintf("LINK_WIN_PUSH_%d_%d", i, j)
			hexBytes(&out, name, b)
			var row bytes.Buffer
			fmt.Fprintf(&row, "    {%s, sizeof(%s), \"%s\"},\n", name, name, p.Verdict)
			winPushes = append(winPushes, row.Bytes()...)
		}
	}
	out.WriteString("\nstatic const dtn_link_win_push LINK_WIN_PUSHES[] = {\n")
	out.Write(winPushes)
	out.WriteString("};\n")
	fmt.Fprintf(&out, "\nstatic const struct {\n    const char *name;\n    long long timeout_ms;\n    int push_off, push_n;\n    const char *completions_hex; /* ';'-separated, in push order */\n} LINK_WIN_VECS[] = {\n")
	for i, w := range vs.Window {
		comp := ""
		for j, c := range w.Completions {
			if j > 0 {
				comp += ";"
			}
			comp += c
		}
		fmt.Fprintf(&out, "    {\"%s\", %d, %d, %d, \"%s\"},\n", w.Name, int64(w.TimeoutS*1000), refs[i].off, refs[i].n, comp)
	}
	out.WriteString("};\n")

	// -- replay ------------------------------------------------------------
	out.WriteString("\n/* replay: fixed session key/salt; ops are sequences with the stable\n * verdict vocabulary (the AEAD input each side rebuilds is pinned by the\n * ccm group). */\n")
	out.WriteString("typedef struct {\n    const char *name;\n    const uint8_t *key;  /* 16 B */\n    const uint8_t *salt; /* 5 B */\n    const unsigned long long *seqs;\n    const char *const *verdicts;\n    size_t n;\n} dtn_link_replay_vec;\n\n")
	for i, r := range vs.Replay {
		seqs := fmt.Sprintf("LINK_REP_%d_SEQS", i)
		fmt.Fprintf(&out, "static const unsigned long long %s[] = {", seqs)
		for j, op := range r.Ops {
			if j > 0 {
				out.WriteString(", ")
			}
			fmt.Fprintf(&out, "%dull", op.Seq)
		}
		out.WriteString("};\n")
		verds := fmt.Sprintf("LINK_REP_%d_VERDICTS", i)
		fmt.Fprintf(&out, "static const char *const %s[] = {", verds)
		for j, op := range r.Ops {
			if j > 0 {
				out.WriteString(", ")
			}
			fmt.Fprintf(&out, "\"%s\"", op.Verdict)
		}
		out.WriteString("};\n")
		hexBytes(&out, fmt.Sprintf("LINK_REP_%d_KEY", i), hexb(r.KeyHex))
		hexBytes(&out, fmt.Sprintf("LINK_REP_%d_SALT", i), hexb(r.SaltHex))
	}
	fmt.Fprintf(&out, "\nstatic const dtn_link_replay_vec LINK_REP_VECS[] = {\n")
	for i, r := range vs.Replay {
		fmt.Fprintf(&out, "    {\"%s\", LINK_REP_%d_KEY, LINK_REP_%d_SALT, LINK_REP_%d_SEQS, LINK_REP_%d_VERDICTS, %d},\n",
			r.Name, i, i, i, i, len(r.Ops))
	}
	out.WriteString("};\n")

	out.WriteString("\n#endif /* DTN_TEST_LINK_VECTORS_H */\n")
	return out.Bytes()
}

func countPushes(ws []vecWindow) int {
	n := 0
	for i := range ws {
		n += len(ws[i].Pushes)
	}
	return n
}
