package nodeid

// Shared conformance vectors for P3.1 (tests/vectors/nodeid/vectors.json) —
// the single source of truth executed by BOTH the Go suite (this test) and
// the C host suite (esp32/components/dtn_core/host/tests/test_nodeid.c via
// the generated header host/tests/nodeid_vectors.h).
//
// Provenance: offline-maintenance §3.4/§3.5 define the merge/TOFU RULES but
// carry no literal role-cert vectors (its one worked vector is a directory
// card), so these vectors were GENERATED from the rules by this test with
// the fixed RFC 8032 seeds below — noted in the JSON's provenance field.
// Regeneration is deterministic (fixed seeds, fixed wall clock, fixed
// fields); `go test ./internal/nodeid -run TestVectorsStable -regen`
// rewrites BOTH files and the committed copies must never drift.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"

	"offgrid/dtn-node/internal/bundle"
)

// Fixed seed material — RFC 8032 §7.1/§7.2/§7.3 test keys, so the vectors
// are traceable to a public source and reproducible forever.
const (
	vecAnchorSeedHex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60" // RFC 8032 §7.1 TEST1
	vecNodeSeedHex   = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb" // RFC 8032 §7.2 TEST2
	vecNode2SeedHex  = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7" // RFC 8032 §7.3 TEST3
	// vecNow is the shared wall clock of every vector (the repo fixture time).
	vecNow = int64(1791072000)
)

// JSON schema types (field order = marshal order = deterministic bytes).
type (
	vecExpected struct {
		EID         string   `json:"eid"`
		NodeKeyHex  string   `json:"node_key_hex"`
		Roles       []string `json:"roles"`
		Level       int      `json:"level"`
		IssuedTS    int64    `json:"issued_ts"`
		ExpiresTS   int64    `json:"expires_ts"`
		Seq         uint64   `json:"seq"`
		AnchorFPHex string   `json:"anchor_fp_hex"`
	}
	vecValid struct {
		CoseHex     string      `json:"cose_hex"`
		NodeSeedHex string      `json:"node_seed_hex"`
		Expected    vecExpected `json:"expected"`
	}
	vecNegative struct {
		CoseHex    string `json:"cose_hex"`
		ExpectCode string `json:"expect_code"`
		Why        string `json:"why"`
	}
	vecMerge struct {
		Name          string `json:"name"`
		CachedCoseHex string `json:"cached_cose_hex"`
		NewCoseHex    string `json:"new_cose_hex"`
		Expect        string `json:"expect"`
		ExpectRevoked bool   `json:"expect_revoked"`
	}
	vecEID struct {
		Name   string `json:"name"`
		KeyHex string `json:"key_hex"`
		FpHex  string `json:"fp_hex"`
		EID    string `json:"eid"`
	}
	vecSeeds struct {
		AnchorSeedHex string `json:"anchor_seed_hex"`
		NodeSeedHex   string `json:"node_seed_hex"`
		Node2SeedHex  string `json:"node2_seed_hex"`
	}
	vecAnchor struct {
		PubHex string `json:"pub_hex"`
		FpHex  string `json:"fp_hex"`
	}
	vectorSet struct {
		Provenance    string                 `json:"provenance"`
		RegenCommand  string                 `json:"regen_command"`
		Now           int64                  `json:"now"`
		Seeds         vecSeeds               `json:"seeds"`
		Anchor        vecAnchor              `json:"anchor"`
		EIDDerivation []vecEID               `json:"eid_derivation"`
		ValidCert     vecValid               `json:"valid_cert"`
		Negative      map[string]vecNegative `json:"negative"`
		Merge         []vecMerge             `json:"merge"`
	}
)

const vecRegenCmd = "cd node && go test ./internal/nodeid -run TestVectorsStable -regen"

// Paths resolve from THIS file's location (runtime.Caller), never from the
// test process's working directory, which the go tool does not guarantee.
func vecRoot() string {
	_, thisFile, _, _ := runtime.Caller(0)
	// vectors_test.go -> nodeid -> internal -> node -> repo root
	return filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(thisFile))))
}

func vecJSONPath() string {
	return filepath.Join(vecRoot(), "tests", "vectors", "nodeid", "vectors.json")
}

func vecHeaderPath() string {
	return filepath.Join(vecRoot(), "esp32", "components", "dtn_core", "host", "tests", "nodeid_vectors.h")
}

var regenVectors = flag.Bool("regen", false, "regenerate tests/vectors/nodeid/vectors.json and the C host header")

// buildVectorSet deterministically derives every vector from the fixed
// seeds and wall clock. Same inputs → byte-identical JSON and C header.
func buildVectorSet(t *testing.T) *vectorSet {
	t.Helper()
	must := func(kp KeyPair, err error) KeyPair {
		if err != nil {
			t.Fatalf("vector seed: %v", err)
		}
		return kp
	}
	anchor := must(NewKeyPairFromSeed(mustHex(t, vecAnchorSeedHex)))
	node := must(NewKeyPairFromSeed(mustHex(t, vecNodeSeedHex)))
	node2 := must(NewKeyPairFromSeed(mustHex(t, vecNode2SeedHex)))

	anchorFP := Fingerprint(anchor.Public)
	issued := vecNow - 3600
	expires := vecNow + 90*86400
	nodeFP := Fingerprint(node.Public)
	node2FP := Fingerprint(node2.Public)
	nodeEID := EID(nodeFP)
	node2EID := EID(node2FP)

	sign := func(c *Cert) []byte {
		t.Helper()
		b, err := signCertBytes(anchor, c)
		if err != nil {
			t.Fatalf("vector signing: %v", err)
		}
		return b
	}
	certAt := func(seq uint64, roles []string, level uint64, iss, exp int64, kp KeyPair) *Cert {
		return &Cert{Version: CertVersion, EID: EID(Fingerprint(kp.Public)), NodeKey: kp.Public,
			Roles: roles, Level: level, IssuedTS: iss, ExpiresTS: exp, Seq: seq}
	}

	// valid_cert: the provisioning ceremony's output — node, edge+relay, L1.
	validRoles := []string{RoleEdge, RoleRelay}
	valid := certAt(1, validRoles, 1, issued, expires, node)
	validCose := sign(valid)

	// Negative vectors: every one is a genuinely SIGNED cert (or a bit flip
	// with a precise reason) that MUST be rejected for the named cause.
	coseWrongEID := sign(&Cert{Version: CertVersion, EID: node2EID, NodeKey: node.Public,
		Roles: validRoles, Level: 1, IssuedTS: issued, ExpiresTS: expires, Seq: 1})
	coseExpired := sign(&Cert{Version: CertVersion, EID: nodeEID, NodeKey: node.Public,
		Roles: validRoles, Level: 1, IssuedTS: vecNow - 91*86400, ExpiresTS: vecNow - 3600, Seq: 1})
	coseFuture := sign(&Cert{Version: CertVersion, EID: nodeEID, NodeKey: node.Public,
		Roles: validRoles, Level: 1, IssuedTS: vecNow + MaxCertSkew + 1, ExpiresTS: expires, Seq: 1})
	coseUnknownRole := sign(&Cert{Version: CertVersion, EID: nodeEID, NodeKey: node.Public,
		Roles: []string{"operator"}, Level: 1, IssuedTS: issued, ExpiresTS: expires, Seq: 1})
	coseLevelMismatch := sign(&Cert{Version: CertVersion, EID: nodeEID, NodeKey: node.Public,
		Roles: []string{RoleEdge}, Level: 0, IssuedTS: issued, ExpiresTS: expires, Seq: 1})
	coseBadVersion := sign(&Cert{Version: 2, EID: nodeEID, NodeKey: node.Public,
		Roles: validRoles, Level: 1, IssuedTS: issued, ExpiresTS: expires, Seq: 1})
	coseBadSig := append([]byte(nil), validCose...)
	coseBadSig[len(coseBadSig)-1] ^= 0x01
	// wrong_anchor_fp: the kid rides UNPROTECTED, so a different kid keeps
	// the signature valid — exactly the failure the kid check must catch.
	// Rebuild the COSE array with node2's fingerprint in the kid slot and
	// the ORIGINAL signature (which covers only protected ‖ payload).
	otherFP := Fingerprint(node2.Public)
	coseWrongFP := bundle.EncodeCbor(func(e *bundle.Cbor) {
		e.Array(4)
		e.Bstr(coseProtectedHeader())
		e.MapHead(1)
		e.Uint(coseHeaderKid)
		e.Bstr(otherFP[:])
		e.Bstr(EncodeCertMap(valid))
		e.Bstr(validCose[len(validCose)-64:])
	})

	// Merge vectors: the §2.5 rules over concrete cert pairs.
	seq2 := certAt(2, []string{RoleEdge}, 1, issued+60, expires, node)
	revoked := certAt(2, nil, 0, issued+60, expires, node) // roles [] + level 0
	merge := []vecMerge{
		{
			Name:          "higher_seq_replaces",
			CachedCoseHex: hex.EncodeToString(validCose),
			NewCoseHex:    hex.EncodeToString(sign(seq2)),
			Expect:        "replace",
		},
		{
			Name:          "lower_seq_stale_dropped",
			CachedCoseHex: hex.EncodeToString(sign(seq2)),
			NewCoseHex:    hex.EncodeToString(validCose),
			Expect:        "stale_drop",
		},
		{
			Name:          "equal_seq_conflict_keeps_existing",
			CachedCoseHex: hex.EncodeToString(validCose),
			NewCoseHex: hex.EncodeToString(sign(&Cert{Version: CertVersion, EID: nodeEID, NodeKey: node.Public,
				Roles: []string{RoleEdge}, Level: 1, IssuedTS: issued + 60, ExpiresTS: expires, Seq: 1})),
			Expect: "conflict_keep",
		},
		{
			Name:          "revocation_installs_and_blocks_authority",
			CachedCoseHex: hex.EncodeToString(validCose),
			NewCoseHex:    hex.EncodeToString(sign(revoked)),
			Expect:        "replace",
			ExpectRevoked: true,
		},
	}

	neg := map[string]vecNegative{
		"bad_signature": {
			CoseHex:    hex.EncodeToString(coseBadSig),
			ExpectCode: CodeBadSignature,
			Why:        "one flipped bit in the Ed25519 signature (last bstr)",
		},
		"wrong_eid_binding": {
			CoseHex:    hex.EncodeToString(coseWrongEID),
			ExpectCode: CodeBadEIDBinding,
			Why:        "node_eid is another key's fingerprint — the §2.1 self-certification check fails",
		},
		"expired": {
			CoseHex:    hex.EncodeToString(coseExpired),
			ExpectCode: CodeExpired,
			Why:        "expires_ts is 1h before `now` — §2.5 rule 5: treated as absent",
		},
		"future_issued_beyond_skew": {
			CoseHex:    hex.EncodeToString(coseFuture),
			ExpectCode: CodeBadTimestamps,
			Why:        "issued_ts is 301s ahead of `now` (the §4.3 skew ceiling is 300)",
		},
		"unknown_role": {
			CoseHex:    hex.EncodeToString(coseUnknownRole),
			ExpectCode: CodeUnknownRole,
			Why:        "role `operator` is outside the closed §2.3 set",
		},
		"level_roles_mismatch": {
			CoseHex:    hex.EncodeToString(coseLevelMismatch),
			ExpectCode: CodeLevelRolesMismatch,
			Why:        "roles present with level 0 (0 iff roles empty, §2.2)",
		},
		"bad_version": {
			CoseHex:    hex.EncodeToString(coseBadVersion),
			ExpectCode: CodeBadVersion,
			Why:        "v = 2 is not the schema version of this spec (§2.2)",
		},
		"wrong_anchor_fp": {
			CoseHex:    hex.EncodeToString(coseWrongFP),
			ExpectCode: CodeWrongAnchorFP,
			Why:        "unprotected kid does not match SHA-256(pinned anchor pub)[0:8]",
		},
	}

	nodeKeyHex := hex.EncodeToString(node.Public)
	node2KeyHex := hex.EncodeToString(node2.Public)
	return &vectorSet{
		Provenance: "Generated by node/internal/nodeid (issue #33 P3.1) from the §3.4/§3.5 merge and " +
			"TOFU RULES of docs/offline-maintenance.md — that document defines the rules but carries no " +
			"literal role-cert vectors (its one worked vector is a directory card), so these were derived " +
			"from the rules and pinned here. Schema: docs/node-network.md §2.1-§2.5. Deterministic: fixed " +
			"RFC 8032 test seeds and a fixed wall clock; committed copies MUST NOT be hand-edited.",
		RegenCommand: vecRegenCmd,
		Now:          vecNow,
		Seeds: vecSeeds{
			AnchorSeedHex: vecAnchorSeedHex,
			NodeSeedHex:   vecNodeSeedHex,
			Node2SeedHex:  vecNode2SeedHex,
		},
		Anchor: vecAnchor{
			PubHex: hex.EncodeToString(anchor.Public),
			FpHex:  hex.EncodeToString(anchorFP[:]),
		},
		EIDDerivation: []vecEID{
			{Name: "node", KeyHex: nodeKeyHex, FpHex: hex.EncodeToString(nodeFP[:]), EID: nodeEID},
			{Name: "node2", KeyHex: node2KeyHex, FpHex: hex.EncodeToString(node2FP[:]), EID: node2EID},
		},
		ValidCert: vecValid{
			CoseHex:     hex.EncodeToString(validCose),
			NodeSeedHex: vecNodeSeedHex,
			Expected: vecExpected{
				EID: nodeEID, NodeKeyHex: nodeKeyHex, Roles: validRoles, Level: 1,
				IssuedTS: issued, ExpiresTS: expires, Seq: 1,
				AnchorFPHex: hex.EncodeToString(anchorFP[:]),
			},
		},
		Negative: neg,
		Merge:    merge,
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex constant: %v", err)
	}
	return b
}

func vecJSONBytes(t *testing.T, vs *vectorSet) []byte {
	t.Helper()
	b, err := json.MarshalIndent(vs, "", "  ")
	if err != nil {
		t.Fatalf("marshal vectors: %v", err)
	}
	return append(b, '\n')
}

// --- the generated C header -------------------------------------------------

func vecCHeaderBytes(t *testing.T, vs *vectorSet) []byte {
	t.Helper()
	cose := func(h string) []byte {
		t.Helper()
		return mustHex(t, h)
	}
	var out bytes.Buffer
	fmt.Fprintf(&out, `/* nodeid_vectors.h — P3.1 role-cert test vectors for the C host suite.
 * GENERATED from tests/vectors/nodeid/vectors.json by the Go vector test:
 *   %s
 * Do not edit by hand — regenerate (the JSON provenance field records the
 * derivation from the offline-maintenance §3.4/§3.5 rules). Sharing one
 * generated file is the Go<->C interop contract: the certs below were
 * SIGNED in Go and must verify in C, byte for byte.
 */
#ifndef DTN_TEST_NODEID_VECTORS_H
#define DTN_TEST_NODEID_VECTORS_H

#include <stddef.h>
#include <stdint.h>

#define NODEID_VEC_NOW %dll

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

	pub := mustHex(t, vs.Anchor.PubHex)
	fp := mustHex(t, vs.Anchor.FpHex)
	hexBytes(&out, "NODEID_ANCHOR_PUB", pub)
	hexBytes(&out, "NODEID_ANCHOR_FP", fp)
	fmt.Fprintf(&out, "\n/* valid_cert — Go-signed, C-verified (the interop case). */\n")
	hexBytes(&out, "NODEID_VALID_CERT", cose(vs.ValidCert.CoseHex))

	negNames := make([]string, 0, len(vs.Negative))
	for name := range vs.Negative {
		negNames = append(negNames, name)
	}
	sort.Strings(negNames)
	fmt.Fprintf(&out, "\n/* negative vectors: name -> cose bytes + expected stable failure code */\n")
	fmt.Fprintf(&out, "typedef struct {\n    const char *name;\n    const uint8_t *cose;\n    size_t len;\n    const char *expect_code;\n} dtn_nodeid_neg_vec;\n\n")
	for _, name := range negNames {
		hexBytes(&out, "NODEID_NEG_"+cSym(name), cose(vs.Negative[name].CoseHex))
	}
	fmt.Fprintf(&out, "\nstatic const dtn_nodeid_neg_vec NODEID_NEG_VECS[] = {\n")
	for _, name := range negNames {
		vec := vs.Negative[name]
		sym := "NODEID_NEG_" + cSym(name)
		fmt.Fprintf(&out, "    {\"%s\", %s, sizeof(%s), \"%s\"},\n", name, sym, sym, vec.ExpectCode)
	}
	out.WriteString("};\n")

	fmt.Fprintf(&out, "\n/* merge-rule vectors: merge cached, then new; compare outcome */\n")
	fmt.Fprintf(&out, "typedef struct {\n    const char *name;\n    const uint8_t *cached;\n    size_t cached_len;\n    const uint8_t *next;\n    size_t next_len;\n    int expect;         /* 0 replace, 1 stale_drop, 2 conflict_keep */\n    int expect_revoked; /* effective cert is a revocation record */\n} dtn_nodeid_merge_vec;\n\n")
	for i, m := range vs.Merge {
		hexBytes(&out, fmt.Sprintf("NODEID_MERGE_%d_CACHED", i), cose(m.CachedCoseHex))
		hexBytes(&out, fmt.Sprintf("NODEID_MERGE_%d_NEW", i), cose(m.NewCoseHex))
	}
	fmt.Fprintf(&out, "\nstatic const dtn_nodeid_merge_vec NODEID_MERGE_VECS[] = {\n")
	for i, m := range vs.Merge {
		cachedSym := fmt.Sprintf("NODEID_MERGE_%d_CACHED", i)
		newSym := fmt.Sprintf("NODEID_MERGE_%d_NEW", i)
		expect := map[string]int{"replace": 0, "stale_drop": 1, "conflict_keep": 2}[m.Expect]
		rev := 0
		if m.ExpectRevoked {
			rev = 1
		}
		fmt.Fprintf(&out, "    {\"%s\", %s, sizeof(%s), %s, sizeof(%s), %d, %d},\n",
			m.Name, cachedSym, cachedSym, newSym, newSym, expect, rev)
	}
	out.WriteString("};\n")

	for _, e := range vs.EIDDerivation {
		fmt.Fprintf(&out, "\n#define NODEID_EID_%s_KEY_HEX \"%s\"\n", cSym(e.Name), e.KeyHex)
		fmt.Fprintf(&out, "#define NODEID_EID_%s_FP_HEX \"%s\"\n", cSym(e.Name), e.FpHex)
		fmt.Fprintf(&out, "#define NODEID_EID_%s_EID \"%s\"\n", cSym(e.Name), e.EID)
	}

	out.WriteString("\n#endif /* DTN_TEST_NODEID_VECTORS_H */\n")
	return out.Bytes()
}

func cSym(name string) string {
	out := make([]rune, 0, len(name))
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			out = append(out, r)
		case r >= 'A' && r <= 'Z':
			out = append(out, r)
		default:
			out = append(out, '_')
		}
	}
	s := string(out)
	if len(s) > 0 && s[0] >= '0' && s[0] <= '9' {
		s = "V" + s
	}
	return upper(s)
}

func upper(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 'a' - 'A'
		}
	}
	return string(b)
}

// --- the tests --------------------------------------------------------------

// TestVectorsStable pins the committed artifacts: the deterministic builder
// must reproduce tests/vectors/nodeid/vectors.json AND the C header
// byte-for-byte. -regen rewrites both (the only sanctioned way to change
// them).
func TestVectorsStable(t *testing.T) {
	wantJSON := vecJSONBytes(t, buildVectorSet(t))
	wantHeader := vecCHeaderBytes(t, buildVectorSet(t))
	jsonPath := vecJSONPath()
	headerPath := vecHeaderPath()
	if regenVectors != nil && *regenVectors {
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
		t.Fatalf("nodeid_vectors.h drifted from vectors.json — run %s and commit", vecRegenCmd)
	}
}

// TestVectorsGoImplementation executes every committed vector against the Go
// implementation — the Go half of the shared-vector contract (row d of the
// node-network §11 matrix).
func TestVectorsGoImplementation(t *testing.T) {
	raw, err := os.ReadFile(vecJSONPath())
	if err != nil {
		t.Skipf("vectors not committed yet (%v)", err)
	}
	var vs vectorSet
	if err := json.Unmarshal(raw, &vs); err != nil {
		t.Fatalf("vectors.json: %v", err)
	}
	anchorPub, err := hex.DecodeString(vs.Anchor.PubHex)
	if err != nil {
		t.Fatalf("anchor pub: %v", err)
	}
	if err := NewPinStore().PinAnchor(anchorPub); err != nil {
		t.Fatalf("anchor pin: %v", err)
	}

	t.Run("eid_derivation", func(t *testing.T) {
		for _, e := range vs.EIDDerivation {
			key, err := hex.DecodeString(e.KeyHex)
			if err != nil {
				t.Fatalf("%s: %v", e.Name, err)
			}
			fp := Fingerprint(key)
			if got := hex.EncodeToString(fp[:]); got != e.FpHex {
				t.Errorf("%s: fingerprint %s, want %s", e.Name, got, e.FpHex)
			}
			if got := EID(fp); got != e.EID {
				t.Errorf("%s: eid %s, want %s", e.Name, got, e.EID)
			}
			if err := ValidateBinding(key, e.EID); err != nil {
				t.Errorf("%s: binding: %v", e.Name, err)
			}
		}
	})

	t.Run("valid_cert", func(t *testing.T) {
		cose := mustHex(t, vs.ValidCert.CoseHex)
		c, err := VerifyCert(cose, anchorPub, vs.Now)
		if err != nil {
			t.Fatalf("valid cert rejected: %v", err)
		}
		w := vs.ValidCert.Expected
		if c.EID != w.EID || c.Level != uint64(w.Level) || c.Seq != w.Seq ||
			c.IssuedTS != w.IssuedTS || c.ExpiresTS != w.ExpiresTS {
			t.Fatalf("fields mismatch: %s", c)
		}
		if hex.EncodeToString(c.NodeKey) != w.NodeKeyHex {
			t.Fatalf("node_key mismatch")
		}
		if len(c.Roles) != len(w.Roles) {
			t.Fatalf("roles mismatch: %v", c.Roles)
		}
		for i := range w.Roles {
			if c.Roles[i] != w.Roles[i] {
				t.Fatalf("roles mismatch: %v", c.Roles)
			}
		}
		// Determinism: re-signing the same fields must give byte-identical
		// COSE_Sign1 (Ed25519 is deterministic; the encoder is canonical).
		anchor, err := NewKeyPairFromSeed(mustHex(t, vs.Seeds.AnchorSeedHex))
		if err != nil {
			t.Fatal(err)
		}
		again, err := SignCertFull(anchor, c, vs.Now)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(again, cose) {
			t.Fatalf("re-sign is not byte-identical (%d vs %d bytes)", len(again), len(cose))
		}
		// Round-trip: parse(encode) identity for the cert map.
		if _, err := VerifyCert(again, anchorPub, vs.Now); err != nil {
			t.Fatalf("re-signed cert does not verify: %v", err)
		}
	})

	t.Run("negative", func(t *testing.T) {
		for name, vec := range vs.Negative {
			cose := mustHex(t, vec.CoseHex)
			c, err := VerifyCert(cose, anchorPub, vs.Now)
			if err == nil {
				t.Errorf("%s: accepted, want %s", name, vec.ExpectCode)
				continue
			}
			if got := ErrorCode(err); got != vec.ExpectCode {
				t.Errorf("%s: code %q, want %q (err: %v)", name, got, vec.ExpectCode, err)
			}
			if c != nil && vec.ExpectCode != CodeExpired {
				t.Errorf("%s: must not return a cert on a hard failure", name)
			}
		}
	})

	t.Run("merge_rules", func(t *testing.T) {
		for _, m := range vs.Merge {
			cache := NewCache()
			if st := cache.Merge(mustHex(t, m.CachedCoseHex), anchorPub, vs.Now); st.Outcome != OutcomeReplaced {
				t.Fatalf("%s: seeding merge gave %s, want replace", m.Name, st.Outcome)
			}
			st := cache.Merge(mustHex(t, m.NewCoseHex), anchorPub, vs.Now)
			if st.Outcome.String() != m.Expect {
				t.Errorf("%s: outcome %s, want %s", m.Name, st.Outcome, m.Expect)
			}
			if st.Revoked != m.ExpectRevoked {
				t.Errorf("%s: revoked %v, want %v", m.Name, st.Revoked, m.ExpectRevoked)
			}
			switch m.Expect {
			case "stale_drop":
				if cache.StaleDropped != 1 {
					t.Errorf("%s: stale counter = %d, want 1", m.Name, cache.StaleDropped)
				}
			case "conflict_keep":
				if cache.Conflicts != 1 {
					t.Errorf("%s: conflict counter = %d, want 1", m.Name, cache.Conflicts)
				}
			default:
				if cache.Conflicts != 0 || cache.StaleDropped != 0 {
					t.Errorf("%s: counters moved on a non-conflicting merge", m.Name)
				}
			}
			if m.ExpectRevoked {
				if _, state := cache.Effective(vs.ValidCert.Expected.EID, vs.Now); state != StateRevoked {
					t.Errorf("%s: effective state = %s, want revoked", m.Name, state)
				}
			}
		}
	})
}
