package mgmt

// Shared conformance vectors for P3.6 (tests/vectors/mgmt/vectors.json) —
// the single source of truth executed by BOTH the Go suite (this test) and
// the C host suite (esp32/components/dtn_core/host/tests/test_mgmt.c via the
// generated header host/tests/mgmt_vectors.h).
//
// The vectors cover the §8.2 pipeline verdict classes end to end: Go-SIGNED
// command objects (valid broadcast/targeted, bad signature, unknown signer,
// revoked signer, below-level, replayed seq, expired, future-issued,
// unknown command, wrong target, install_cert) with the expected verdict and
// the expected per-signer seq-table state after the decision. The C side
// replays the SAME bytes through dtn_mgmt_decide and must reach byte- and
// class-identical verdicts.
//
// Regeneration is deterministic (fixed RFC 8032 seeds, fixed wall clock):
//   cd node && go test ./internal/mgmt -run TestVectorsStable -regen
// rewrites BOTH files; the committed copies must never drift.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"offgrid/dtn-node/internal/bundle"
	"offgrid/dtn-node/internal/nodeid"
)

// Fixed seed material — the RFC 8032 test keys the nodeid vectors already
// use (traceable, reproducible), plus one deterministic fourth key for the
// unknown-signer vector.
const (
	mvecAnchorSeedHex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60" // RFC 8032 §7.1 TEST1
	mvecMgrSeedHex    = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb" // RFC 8032 §7.2 TEST2
	mvecLowSeedHex    = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7" // RFC 8032 §7.3 TEST3
	// mvecNow is the shared wall clock of every vector.
	mvecNow = int64(1791072000)
)

// outsiderSeed derives the fourth key deterministically from a label (the
// RFC 8032 catalogue has three keys; the unknown-signer vector needs a
// fourth whose cert was NEVER issued — an outsider is defined by absence).
func outsiderSeed() []byte {
	s := sha256.Sum256([]byte("offgrid-mgmt-vector-outsider-seed"))
	return s[:nodeid.SeedLen]
}

// JSON schema (field order = marshal order = deterministic bytes).
type (
	mvecCert struct {
		CoseHex string `json:"cose_hex"`
		EID     string `json:"eid"`
		Level   int    `json:"level"`
	}
	mvecCommand struct {
		Name        string            `json:"name"`
		SeedCerts   []string          `json:"seed_certs"` // certs merged into the cache first
		LastSeq     map[string]uint64 `json:"last_seq"`   // pre-state of the per-signer seq table (by cert name)
		CoseHex     string            `json:"cose_hex"`
		LocalEID    string            `json:"local_eid"`    // the receiving node's EID
		Expect      string            `json:"expect"`       // the §8.2 verdict class
		ExpectSeq   map[string]uint64 `json:"expect_seq"`   // FULL expected post-state (by cert name)
		ExpectMerge string            `json:"expect_merge"` // install_cert: fresh-cache merge outcome of args.cert ("" = n/a)
		Why         string            `json:"why"`
	}
	mgmtVectorSet struct {
		Provenance   string              `json:"provenance"`
		RegenCommand string              `json:"regen_command"`
		Now          int64               `json:"now"`
		Seeds        map[string]string   `json:"seeds"`
		AnchorPubHex string              `json:"anchor_pub_hex"`
		Certs        map[string]mvecCert `json:"certs"`
		Commands     []mvecCommand       `json:"commands"`
	}
)

const mvecRegenCmd = "cd node && go test ./internal/mgmt -run TestVectorsStable -regen"

func mvecRoot() string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))))
}

func mvecJSONPath() string {
	return filepath.Join(mvecRoot(), "tests", "vectors", "mgmt", "vectors.json")
}

func mvecHeaderPath() string {
	return filepath.Join(mvecRoot(), "esp32", "components", "dtn_core", "host", "tests", "mgmt_vectors.h")
}

var regenMgmtVectors = flag.Bool("regen", false, "regenerate tests/vectors/mgmt/vectors.json and the C host header")

// buildMgmtVectorSet deterministically derives every vector. Same inputs →
// byte-identical JSON and C header.
func buildMgmtVectorSet(t *testing.T) *mgmtVectorSet {
	t.Helper()
	must := func(kp nodeid.KeyPair, err error) nodeid.KeyPair {
		if err != nil {
			t.Fatalf("vector seed: %v", err)
		}
		return kp
	}
	seedHex := func(hx string) []byte {
		b, err := hex.DecodeString(hx)
		if err != nil {
			t.Fatalf("seed hex: %v", err)
		}
		return b
	}
	anchor := must(nodeid.NewKeyPairFromSeed(seedHex(mvecAnchorSeedHex)))
	mgr := must(nodeid.NewKeyPairFromSeed(seedHex(mvecMgrSeedHex)))
	low := must(nodeid.NewKeyPairFromSeed(seedHex(mvecLowSeedHex)))
	outsider := must(nodeid.NewKeyPairFromSeed(outsiderSeed()))

	mgrEID, err := nodeid.EIDFromPub(mgr.Public)
	if err != nil {
		t.Fatal(err)
	}
	lowEID, err := nodeid.EIDFromPub(low.Public)
	if err != nil {
		t.Fatal(err)
	}
	outsiderEID, err := nodeid.EIDFromPub(outsider.Public)
	if err != nil {
		t.Fatal(err)
	}

	issued := mvecNow - 60
	expires := issued + 3600

	// --- the certs (anchor-signed, exactly as the §2.6 ceremony emits) ---
	certCose := func(kp nodeid.KeyPair, roles []string, level uint64, seq uint64) []byte {
		t.Helper()
		eid, err := nodeid.EIDFromPub(kp.Public)
		if err != nil {
			t.Fatal(err)
		}
		cose, err := nodeid.SignCert(anchor, kp.Public, eid, roles, level, issued, expires, seq, mvecNow)
		if err != nil {
			t.Fatalf("vector cert: %v", err)
		}
		return cose
	}
	mgrCert := certCose(mgr, []string{nodeid.RoleManager}, 3, 1)
	lowCert := certCose(low, []string{nodeid.RoleManager}, 1, 1)
	lowRevoked := certCose(low, nil, 0, 2) // the §2.5 rule-4 revocation record
	operatorCert := certCose(outsider, []string{nodeid.RoleEdge}, 2, 1)

	// --- the commands (manager-signed, exactly as capsuletool admin sign emits) ---
	sign := func(signer nodeid.KeyPair, cmd string, args map[string]Arg, target string, issuedTS, expiryTS int64, seq uint64) []byte {
		t.Helper()
		cose, err := SignCommand(signer, cmd, args, target, issuedTS, expiryTS, seq)
		if err != nil {
			t.Fatalf("vector command %s: %v", cmd, err)
		}
		return cose
	}
	mgrCmd := func(cmd string, args map[string]Arg, target string, seq uint64) []byte {
		return sign(mgr, cmd, args, target, issued, expires, seq)
	}

	badSig := mgrCmd(CmdGetStatus, nil, "", 7)
	badSig[len(badSig)-1] ^= 0x01
	outsiderCmd := sign(outsider, CmdGetStatus, nil, "", issued, expires, 1)
	lowCmd := sign(low, CmdGetStatus, nil, "", issued, expires, 1)
	replay := mgrCmd(CmdTriggerSync, nil, "", 5)
	expiredCmd := sign(mgr, CmdGetStatus, nil, "", issued-7200, issued-3600, 8) // already past
	futureCmd := sign(mgr, CmdGetStatus, nil, "", mvecNow+MaxIssuedSkew+1, mvecNow+MaxIssuedSkew+3601, 9)
	unknownCmd := func() []byte {
		// An out-of-table name cannot go through SignCommand (it refuses);
		// the vector needs the raw object to prove the RECEIVER refuses too.
		c := &Command{Cmd: "reboot_node", Args: map[string]Arg{}, IssuedTS: issued, Expiry: expires, Seq: 10}
		cose, err := coseSign1(mgr, EncodeCommandMap(c))
		if err != nil {
			t.Fatal(err)
		}
		return cose
	}()
	capLowCmd := sign(low, CmdSetStoreCap, map[string]Arg{"bundles": {Kind: ArgUint, Uint: 4000}}, "", issued, expires, 3)
	targetOtherCmd := mgrCmd(CmdGetStatus, nil, outsiderEID, 11)
	installCmd := mgrCmd(CmdInstallCert, map[string]Arg{"cert": {Kind: ArgBstr, Bytes: operatorCert}}, "", 12)

	commands := []mvecCommand{
		{
			Name: "valid_broadcast", SeedCerts: []string{"mgr"},
			CoseHex: hex.EncodeToString(mgrCmd(CmdGetStatus, nil, "", 5)), LocalEID: mgrEID,
			Expect: "ok", ExpectSeq: map[string]uint64{"mgr": 5},
			Why: "an L3 manager's get_status broadcast executes and burns seq 5",
		},
		{
			Name: "valid_targeted", SeedCerts: []string{"mgr"}, LastSeq: map[string]uint64{"mgr": 5},
			CoseHex: hex.EncodeToString(mgrCmd(CmdGetStatus, nil, mgrEID, 6)), LocalEID: mgrEID,
			Expect: "ok", ExpectSeq: map[string]uint64{"mgr": 6},
			Why: "a targeted command for THIS node executes; the seq floor advances monotonically",
		},
		{
			Name: "bad_signature", SeedCerts: []string{"mgr"},
			CoseHex: hex.EncodeToString(badSig), LocalEID: mgrEID,
			Expect: "sig", ExpectSeq: map[string]uint64{},
			Why: "one flipped bit in the Ed25519 signature — silent drop, no seq burned",
		},
		{
			Name: "unknown_signer", SeedCerts: []string{"mgr"},
			CoseHex: hex.EncodeToString(outsiderCmd), LocalEID: mgrEID,
			Expect: "sig", ExpectSeq: map[string]uint64{},
			Why: "the signer has no cached role cert — no authority, no discussion (§2.5)",
		},
		{
			Name: "revoked_signer", SeedCerts: []string{"low_revoked"},
			CoseHex: hex.EncodeToString(lowCmd), LocalEID: lowEID,
			Expect: "sig", ExpectSeq: map[string]uint64{},
			Why: "the signer's cached cert is a revocation record (roles cleared) — §2.5 rule 4",
		},
		{
			Name: "below_level", SeedCerts: []string{"low"},
			CoseHex: hex.EncodeToString(capLowCmd), LocalEID: lowEID,
			Expect: "level", ExpectSeq: map[string]uint64{},
			Why: "an L1 cert against the L2 set_store_cap — dropped + counted, NO reply (the AC)",
		},
		{
			Name: "replayed_seq", SeedCerts: []string{"mgr"}, LastSeq: map[string]uint64{"mgr": 5},
			CoseHex: hex.EncodeToString(replay), LocalEID: mgrEID,
			Expect: "seq", ExpectSeq: map[string]uint64{"mgr": 5},
			Why: "seq 5 again after 5 executed — a replay; strictly monotonic per signer",
		},
		{
			Name: "expired", SeedCerts: []string{"mgr"},
			CoseHex: hex.EncodeToString(expiredCmd), LocalEID: mgrEID,
			Expect: "expired", ExpectSeq: map[string]uint64{},
			Why: "expiry already past the receiver's clock (§8.2: local-clock expiry)",
		},
		{
			Name: "future_issued", SeedCerts: []string{"mgr"},
			CoseHex: hex.EncodeToString(futureCmd), LocalEID: mgrEID,
			Expect: "expired", ExpectSeq: map[string]uint64{},
			Why: "issued_ts more than 300 s ahead of the receiver (the §4.3 skew ceiling)",
		},
		{
			Name: "unknown_cmd", SeedCerts: []string{"mgr"},
			CoseHex: hex.EncodeToString(unknownCmd), LocalEID: mgrEID,
			Expect: "unknown_cmd", ExpectSeq: map[string]uint64{},
			Why: "a name outside the frozen v1 table — drop + count, never confirm (forward compat)",
		},
		{
			Name: "targeted_other", SeedCerts: []string{"mgr"},
			CoseHex: hex.EncodeToString(targetOtherCmd), LocalEID: mgrEID,
			Expect: "target", ExpectSeq: map[string]uint64{},
			Why: "target_node names another node — §8.2: not ours to execute",
		},
		{
			Name: "install_cert", SeedCerts: []string{"mgr"}, LastSeq: map[string]uint64{"mgr": 5},
			CoseHex: hex.EncodeToString(installCmd), LocalEID: mgrEID,
			Expect: "ok", ExpectSeq: map[string]uint64{"mgr": 12}, ExpectMerge: "replace",
			Why: "L3 distributes an ALREADY ANCHOR-SIGNED operator cert; the args cert merges by the §2.5 seq rules",
		},
	}
	return &mgmtVectorSet{
		Provenance: "Generated by node/internal/mgmt (issue #33 P3.6) from the §8.1/§8.2 rules of " +
			"docs/node-network.md. Go-signed command objects and anchor-signed role certs over the fixed " +
			"RFC 8032 §7.1-§7.3 test seeds and a fixed wall clock; the C side (dtn_mgmt.c) must reach " +
			"identical verdicts on the identical bytes. Committed copies MUST NOT be hand-edited.",
		RegenCommand: mvecRegenCmd,
		Now:          mvecNow,
		Seeds: map[string]string{
			"anchor":   mvecAnchorSeedHex,
			"mgr":      mvecMgrSeedHex,
			"low":      mvecLowSeedHex,
			"outsider": hex.EncodeToString(outsiderSeed()),
		},
		AnchorPubHex: hex.EncodeToString(anchor.Public),
		Certs: map[string]mvecCert{
			"mgr":         {CoseHex: hex.EncodeToString(mgrCert), EID: mgrEID, Level: 3},
			"low":         {CoseHex: hex.EncodeToString(lowCert), EID: lowEID, Level: 1},
			"low_revoked": {CoseHex: hex.EncodeToString(lowRevoked), EID: lowEID, Level: 0},
			"operator":    {CoseHex: hex.EncodeToString(operatorCert), EID: outsiderEID, Level: 2},
		},
		Commands: commands,
	}
}

func mvecJSONBytes(t *testing.T, vs *mgmtVectorSet) []byte {
	t.Helper()
	b, err := json.MarshalIndent(vs, "", "  ")
	if err != nil {
		t.Fatalf("marshal vectors: %v", err)
	}
	return append(b, '\n')
}

// --- the generated C header ---------------------------------------------------

func mvecCHeaderBytes(t *testing.T, vs *mgmtVectorSet) []byte {
	t.Helper()
	mustHex := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatalf("vector hex: %v", err)
		}
		return b
	}
	var out bytes.Buffer
	fmt.Fprintf(&out, `/* mgmt_vectors.h — P3.6 admin-command test vectors for the C host suite.
 * GENERATED from tests/vectors/mgmt/vectors.json by the Go vector test:
 *   %s
 * Do not edit by hand — regenerate. The command objects below were SIGNED in
 * Go and must reach identical §8.2 verdicts in C (dtn_mgmt.c), byte for byte.
 */
#ifndef DTN_TEST_MGMT_VECTORS_H
#define DTN_TEST_MGMT_VECTORS_H

#include <stddef.h>
#include <stdint.h>

#define MGMT_VEC_NOW %dll

`, mvecRegenCmd, vs.Now)

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

	pub := mustHex(vs.AnchorPubHex)
	hexBytes(&out, "MGMT_ANCHOR_PUB", pub)

	certNames := make([]string, 0, len(vs.Certs))
	for name := range vs.Certs {
		certNames = append(certNames, name)
	}
	sortStrings(certNames)
	for _, name := range certNames {
		hexBytes(&out, "MGMT_CERT_"+cSym(name), mustHex(vs.Certs[name].CoseHex))
	}

	fmt.Fprintf(&out, `typedef struct {
    const char *name;
    const char *local_eid;
    const uint8_t *cose;
    size_t cose_len;
    int expect;              /* the dtn_mgmt.h verdict enum (0 ok, -1 shape, -2 sig, -3 target, -4 unknown_cmd, -5 level, -6 seq, -7 expired) */
    const char *expect_merge;/* "" = none; else the expected dtn_rolecert merge outcome */
    const char *seed_names[4];     /* NULL-terminated: certs merged into the cache first */
    const char *lseq_names[4];     /* pre-state of the seq table (paired with lseq_vals) */
    uint64_t lseq_vals[4];
    size_t lseq_count;
    const char *xseq_names[4];     /* FULL expected post-state (paired with xseq_vals) */
    uint64_t xseq_vals[4];
    size_t xseq_count;
} dtn_mgmt_vec;
`)

	// The per-vector COSE byte arrays come FIRST (a C initializer list
	// cannot contain declarations between its rows).
	for i, c := range vs.Commands {
		hexBytes(&out, fmt.Sprintf("MGMT_VEC_%d_COSE", i), mustHex(c.CoseHex))
	}

	fmt.Fprintf(&out, "\nstatic const dtn_mgmt_vec MGMT_VECS[] = {\n")
	for i, c := range vs.Commands {
		// The expect value is the C ENUM (dtn_mgmt.h's negative codes) so
		// the C test compares the verdict directly.
		expect := map[string]int{"ok": 0, "shape": -1, "sig": -2, "target": -3, "unknown_cmd": -4, "level": -5, "seq": -6, "expired": -7}[c.Expect]
		coseSym := fmt.Sprintf("MGMT_VEC_%d_COSE", i)
		var seeds, lseqN, xseqN bytes.Buffer
		for _, sc := range c.SeedCerts {
			fmt.Fprintf(&seeds, "\"%s\", ", sc)
		}
		lseqKeys := sortedKeys(c.LastSeq)
		for _, k := range lseqKeys {
			fmt.Fprintf(&lseqN, "\"%s\", ", k)
		}
		xseqKeys := sortedKeys(c.ExpectSeq)
		for _, k := range xseqKeys {
			fmt.Fprintf(&xseqN, "\"%s\", ", k)
		}
		var lseqV, xseqV bytes.Buffer
		for _, k := range lseqKeys {
			fmt.Fprintf(&lseqV, "%dull, ", c.LastSeq[k])
		}
		for _, k := range xseqKeys {
			fmt.Fprintf(&xseqV, "%dull, ", c.ExpectSeq[k])
		}
		fmt.Fprintf(&out, `    {.name = "%s", .local_eid = "%s", .cose = %s, .cose_len = sizeof(%s), .expect = %d, .expect_merge = "%s",
      .seed_names = {%s},
      .lseq_names = {%s}, .lseq_vals = {%s}, .lseq_count = %d,
      .xseq_names = {%s}, .xseq_vals = {%s}, .xseq_count = %d},
`,
			c.Name, c.LocalEID, coseSym, coseSym, expect, c.ExpectMerge,
			seeds.String(), lseqN.String(), lseqV.String(), len(c.LastSeq),
			xseqN.String(), xseqV.String(), len(c.ExpectSeq))
	}
	out.WriteString("};\n")

	fmt.Fprintf(&out, "\n/* cert name → cose bytes lookup (seed_names reference these names) */\n")
	fmt.Fprintf(&out, "typedef struct {\n    const char *name;\n    const uint8_t *cose;\n    size_t len;\n    const char *eid;\n} dtn_mgmt_cert_vec;\n\n")
	fmt.Fprintf(&out, "static const dtn_mgmt_cert_vec MGMT_CERTS[] = {\n")
	for _, name := range certNames {
		sym := "MGMT_CERT_" + cSym(name)
		fmt.Fprintf(&out, "    {\"%s\", %s, sizeof(%s), \"%s\"},\n", name, sym, sym, vs.Certs[name].EID)
	}
	out.WriteString("};\n")

	out.WriteString("\n#endif /* DTN_TEST_MGMT_VECTORS_H */\n")
	return out.Bytes()
}

// cSym renders a vector name as a C identifier (the same rule the nodeid
// vector header uses).
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
	return strings.ToUpper(s)
}

func sortedKeys(m map[string]uint64) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sortStrings(out)
	return out
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// --- the tests --------------------------------------------------------------

// TestMgmtVectorsStable pins the committed artifacts byte-for-byte; -regen
// rewrites both (the only sanctioned way to change them).
func TestMgmtVectorsStable(t *testing.T) {
	wantJSON := mvecJSONBytes(t, buildMgmtVectorSet(t))
	wantHeader := mvecCHeaderBytes(t, buildMgmtVectorSet(t))
	jsonPath := mvecJSONPath()
	headerPath := mvecHeaderPath()
	if regenMgmtVectors != nil && *regenMgmtVectors {
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
		t.Fatalf("committed vectors missing (run %s): %v", mvecRegenCmd, err)
	}
	if !bytes.Equal(gotJSON, wantJSON) {
		t.Fatalf("mgmt vectors.json drifted from the deterministic builder — run %s and commit", mvecRegenCmd)
	}
	gotHeader, err := os.ReadFile(headerPath)
	if err != nil {
		t.Fatalf("committed C header missing (run %s): %v", mvecRegenCmd, err)
	}
	if !bytes.Equal(gotHeader, wantHeader) {
		t.Fatalf("mgmt_vectors.h drifted from vectors.json — run %s and commit", mvecRegenCmd)
	}
}

// TestMgmtVectorsGoImplementation executes every committed vector against
// the Go pipeline — the Go half of the shared-vector contract (§11 row i).
func TestMgmtVectorsGoImplementation(t *testing.T) {
	raw, err := os.ReadFile(mvecJSONPath())
	if err != nil {
		t.Skipf("vectors not committed yet (%v)", err)
	}
	var vs mgmtVectorSet
	if err := json.Unmarshal(raw, &vs); err != nil {
		t.Fatalf("vectors.json: %v", err)
	}
	anchorPub, err := hex.DecodeString(vs.AnchorPubHex)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Unix(vs.Now, 0)

	for _, vec := range vs.Commands {
		t.Run(vec.Name, func(t *testing.T) {
			cose, err := hex.DecodeString(vec.CoseHex)
			if err != nil {
				t.Fatal(err)
			}
			e := newVectorEnforcer(t, anchorPub, vec.LocalEID, clock)
			for _, name := range vec.SeedCerts {
				certCose, err := hex.DecodeString(vs.Certs[name].CoseHex)
				if err != nil {
					t.Fatal(err)
				}
				if st := e.Cache.Merge(certCose, anchorPub, vs.Now); st.Outcome != nodeid.OutcomeReplaced {
					t.Fatalf("seed cert %s: %s", name, st.Outcome)
				}
			}
			for name, seq := range vec.LastSeq {
				e.mu.Lock()
				e.seqs[vs.Certs[name].EID] = seq
				e.mu.Unlock()
			}

			// Deliver the command the way the sink does: as the payload of
			// an identified bundle to the admin group (the router's verdict
			// class shows in exactly one counter).
			b, err := bundle.NewManagement(vs.Certs["mgr"].EID, AdminEID, clock.UnixMilli(), 3600, 1, cose)
			if err != nil {
				// The vector's nominal signer may be another key; derive the
				// source from the command's kid instead (the sink only needs
				// a well-formed identified bundle).
				kid, ferr := SignerFingerprint(cose)
				if ferr != nil {
					t.Fatal(ferr)
				}
				b, err = bundle.NewManagement(nodeid.EID(nodeid.Fingerprint(kid)), AdminEID, clock.UnixMilli(), 3600, 1, cose)
				if err != nil {
					t.Fatal(err)
				}
			}
			handled := e.Consume(b)
			if !handled {
				t.Fatalf("a command payload must always be consumed")
			}
			got := e.CountersSnapshot()
			expectVerdict(t, vec.Expect, got)
			// The post-state of the seq table (by cert name → EID).
			e.mu.Lock()
			have := make(map[string]uint64, len(e.seqs))
			for eid, seq := range e.seqs {
				for name, cv := range vs.Certs {
					if cv.EID == eid {
						have[name] = seq
					}
				}
			}
			e.mu.Unlock()
			if len(have) != len(vec.ExpectSeq) {
				t.Fatalf("seq table after: %v, want %v", have, vec.ExpectSeq)
			}
			for name, want := range vec.ExpectSeq {
				if have[name] != want {
					t.Fatalf("seq[%s] after = %d, want %d (table %v)", name, have[name], want, have)
				}
			}
			// install_cert: the args cert must merge into a fresh cache with
			// the recorded outcome (the C side replays the same merge).
			if vec.ExpectMerge != "" {
				cmd, err := ParseCommandShape(cose)
				if err != nil {
					t.Fatal(err)
				}
				certCose, ok := cmd.ArgBytesOf("cert")
				if !ok {
					t.Fatal("install_cert vector without a cert arg")
				}
				fresh := nodeid.NewCache()
				st := fresh.Merge(certCose, anchorPub, vs.Now)
				if st.Outcome.String() != vec.ExpectMerge {
					t.Fatalf("args cert merge = %s, want %s", st.Outcome, vec.ExpectMerge)
				}
			}
		})
	}
}

// newVectorEnforcer builds an Enforcer with a nil Inject (drops are what the
// vectors assert; nothing else may move) and a fixed clock.
func newVectorEnforcer(t *testing.T, anchorPub []byte, localEID string, now time.Time) *Enforcer {
	t.Helper()
	kp, err := nodeid.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	e := NewEnforcer(nodeid.NewCache(), anchorPub, localEID, kp)
	e.Now = func() time.Time { return now }
	// The vectors pin the §8.2 DECISION; the ok-vector executions need the
	// executors the table entries touch (get_status, install_cert — the
	// latter works through the cache alone).
	e.Exec = &Executors{Status: func() map[string]Arg { return map[string]Arg{} }}
	return e
}

// expectVerdict asserts that exactly the counter of the expected §8.2 verdict
// class moved (and, for ok, that the command was accepted).
func expectVerdict(t *testing.T, want string, got CountersSnapshot) {
	t.Helper()
	type pair struct {
		name string
		n    uint64
	}
	moves := []pair{
		{"ok", got.Accepted},
		{"shape", got.DroppedShape},
		{"sig", got.DroppedSig},
		{"target", got.DroppedTarget},
		{"unknown_cmd", got.DroppedUnknown},
		{"level", got.DroppedByLevel},
		{"seq", got.DroppedSeq},
		{"expired", got.DroppedExpired},
	}
	for _, m := range moves {
		wantN := uint64(0)
		if m.name == want {
			wantN = 1
		}
		if m.n != wantN {
			t.Fatalf("verdict %s: counter %s = %d, want %d (snapshot %+v)", want, m.name, m.n, wantN, got)
		}
	}
}
