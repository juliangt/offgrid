package directory_test

// Shared conformance vectors for P3.8 (tests/vectors/directory/vectors.json)
// — the single source of truth executed by BOTH the Go suite (this test)
// and the C host suite (esp32/components/dtn_core/host/tests/test_dirfed.c
// via the generated header host/tests/directory_vectors.h).
//
// The vectors cover the §9.3 card verification classes and the §3.4 merge
// outcomes end to end: Go-SIGNED identity cards (offline-maintenance §3.1,
// concretized per node-network §9.3) over the fixed RFC 8032 §7.1 test seed
// and a fixed wall clock — valid insert, higher-seq replace, key rotation,
// stale drop, duplicate, equal-seq conflicts (alias drift AND the changed-
// key attack: the row keeps its OLD key, the SPA continuity invariant),
// a tampered signature and a created_ts beyond the skew ceiling. The C side
// replays the SAME bytes through dtn_dirfed_merge against a fresh dtn_store
// and must reach outcome- and row-identical results.
//
// Regeneration is deterministic (fixed seeds, fixed clock, canonical
// Base64/marshal order):
//   cd node && go test ./internal/directory -run TestDirectoryVectorsStable -regen
// rewrites BOTH files; the committed copies must never drift.

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"offgrid/dtn-node/internal/directory"
	"offgrid/dtn-node/internal/nodeid"
	"offgrid/dtn-node/internal/storage"
)

const (
	dvecRegenCmd = "cd node && go test ./internal/directory -run TestDirectoryVectorsStable -regen"
	// dvecNow is the shared wall clock of every vector.
	dvecNow = int64(1791072000)
	// dvecUserSeedHex is the RFC 8032 §7.1 TEST1 seed — the same catalogue
	// key the nodeid and mgmt vectors use (traceable, reproducible).
	dvecUserSeedHex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
)

// dvecX derives one deterministic X25519 stand-in (the cards carry the key
// as data; its provenance is irrelevant to the merge rules).
func dvecX(label string) []byte {
	s := sha256.Sum256([]byte("offgrid-directory-vector-" + label))
	return s[:]
}

// JSON schema (field order = marshal order = deterministic bytes).
type (
	dvecCard struct {
		Name      string `json:"name"`
		CoseHex   string `json:"cose_hex"`
		Alias     string `json:"alias"`
		PubkeyB64 string `json:"pubkey_b64"`
		XB64      string `json:"x_b64"`
		Seq       uint64 `json:"seq"`
	}
	dvecScenario struct {
		Name            string   `json:"name"`
		SeedCards       []string `json:"seed_cards"` // merged into the fresh store first
		Card            string   `json:"card"`       // the card under test
		Expect          string   `json:"expect"`     // insert|replace|stale|duplicate|conflict|sig|skew
		ExpectEvictions int      `json:"expect_evictions"`
		ExpectAlias     string   `json:"expect_alias"` // the row state after ("" = row absent)
		ExpectXB64      string   `json:"expect_x_b64"`
		ExpectSource    int      `json:"expect_source"` // -1 = row absent
		Why             string   `json:"why"`
	}
	directoryVectorSet struct {
		Provenance   string         `json:"provenance"`
		RegenCommand string         `json:"regen_command"`
		Now          int64          `json:"now"`
		UserSeedHex  string         `json:"user_seed_hex"`
		Alias        string         `json:"alias"`
		PubkeyB64    string         `json:"pubkey_b64"`
		Cards        []dvecCard     `json:"cards"`
		Scenarios    []dvecScenario `json:"scenarios"`
	}
)

func dvecRoot() string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(thisFile))))
}

func dvecJSONPath() string {
	return filepath.Join(dvecRoot(), "tests", "vectors", "directory", "vectors.json")
}

func dvecHeaderPath() string {
	return filepath.Join(dvecRoot(), "esp32", "components", "dtn_core", "host", "tests", "directory_vectors.h")
}

var regenDirectoryVectors = flag.Bool("regen", false, "regenerate tests/vectors/directory/vectors.json and the C host header")

// buildDirectoryVectorSet deterministically derives every vector. Same
// inputs → byte-identical JSON and C header.
func buildDirectoryVectorSet(t *testing.T) *directoryVectorSet {
	t.Helper()
	seed, err := hex.DecodeString(dvecUserSeedHex)
	if err != nil {
		t.Fatalf("user seed: %v", err)
	}
	user, err := nodeid.NewKeyPairFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	pubkeyB64 := base64.StdEncoding.EncodeToString(user.Public)
	x1, x2, x3 := dvecX("x1"), dvecX("x2"), dvecX("x3")
	x1b64 := base64.StdEncoding.EncodeToString(x1)

	sign := func(name, alias string, x []byte, ts int64, seq uint64) dvecCard {
		t.Helper()
		cose, err := directory.SignCard(user, alias, x, ts, seq)
		if err != nil {
			t.Fatalf("vector card %s: %v", name, err)
		}
		return dvecCard{
			Name: name, CoseHex: hex.EncodeToString(cose), Alias: alias,
			PubkeyB64: pubkeyB64, XB64: base64.StdEncoding.EncodeToString(x), Seq: seq,
		}
	}
	cS1 := sign("seq1", "alice_77", x1, dvecNow-60, 1)
	cS2 := sign("seq2", "alice_77", x1, dvecNow-50, 2)
	cS3 := sign("seq3_rotated", "alice_77", x2, dvecNow-40, 3)
	cS3Alias := sign("seq3_alias_drift", "alice_7", x1, dvecNow-40, 3)
	cS3X := sign("seq3_key_change", "alice_77", x3, dvecNow-40, 3)
	cFuture := sign("future_skew", "alice_77", x1, dvecNow+directory.MaxCreatedSkew+1, 9)
	tampered := func() dvecCard {
		c, err := hex.DecodeString(cS1.CoseHex)
		if err != nil {
			t.Fatal(err)
		}
		// Corrupt the SIGNATURE, not the framing: decode the sig member,
		// flip one bit of the raw 64 bytes, re-encode — the mutated card is
		// still canonical Base64 end to end, so it reaches the verify step
		// (verdict "sig") instead of dying in the shape scan. (The old
		// XOR-a-trailing-byte trick broke the JSON card's closing brace.)
		s := string(c)
		const marker = `,"sig":"`
		i := strings.Index(s, marker)
		if i < 0 {
			t.Fatal("no sig member in the seed card")
		}
		sig, err := base64.StdEncoding.DecodeString(s[i+len(marker) : len(s)-2])
		if err != nil {
			t.Fatal(err)
		}
		sig[0] ^= 0x01
		mut := s[:i+len(marker)] + base64.StdEncoding.EncodeToString(sig) + s[len(s)-2:]
		return dvecCard{Name: "tampered_sig", CoseHex: hex.EncodeToString([]byte(mut)), Alias: cS1.Alias, PubkeyB64: pubkeyB64, XB64: x1b64, Seq: 1}
	}()

	cards := []dvecCard{cS1, cS2, cS3, cS3Alias, cS3X, cFuture, tampered}
	scenarios := []dvecScenario{
		{
			Name: "valid_insert", Card: "seq1", Expect: "insert",
			ExpectAlias: "alice_77", ExpectXB64: x1b64, ExpectSource: 1,
			Why: "§3.4 rule 1: absent pubkey → INSERT, alias/x25519/card from the card, source = 1",
		},
		{
			Name: "valid_replace", SeedCards: []string{"seq1"}, Card: "seq2", Expect: "replace",
			ExpectAlias: "alice_77", ExpectXB64: x1b64, ExpectSource: 1,
			Why: "§3.4 rule 2: a higher sequence replaces (re-issue, same keys)",
		},
		{
			Name: "rotation_replaces_key", SeedCards: []string{"seq2"}, Card: "seq3_rotated", Expect: "replace",
			ExpectAlias: "alice_77", ExpectXB64: base64.StdEncoding.EncodeToString(x2), ExpectSource: 1,
			Why: "§3.4 rule 2: the ONLY way a served X25519 key ever changes — a higher-sequence SIGNED record",
		},
		{
			Name: "stale_dropped", SeedCards: []string{"seq3_rotated"}, Card: "seq1", Expect: "stale",
			ExpectAlias: "alice_77", ExpectXB64: base64.StdEncoding.EncodeToString(x2), ExpectSource: 1,
			Why: "§3.4 rule 3: a lower sequence is stale — dropped, the row untouched",
		},
		{
			Name: "duplicate_noop", SeedCards: []string{"seq2"}, Card: "seq2", Expect: "duplicate",
			ExpectAlias: "alice_77", ExpectXB64: x1b64, ExpectSource: 1,
			Why: "§3.4 rule 4: byte-equal card at equal sequence → no-op",
		},
		{
			Name: "alias_drift_conflict", SeedCards: []string{"seq3_rotated"}, Card: "seq3_alias_drift", Expect: "conflict",
			ExpectAlias: "alice_77", ExpectXB64: base64.StdEncoding.EncodeToString(x2), ExpectSource: 1,
			Why: "§3.4 rule 4: equal sequence, differing bytes → keep the existing row (the attack signal)",
		},
		{
			Name: "changed_key_equal_seq", SeedCards: []string{"seq3_rotated"}, Card: "seq3_key_change", Expect: "conflict",
			ExpectAlias: "alice_77", ExpectXB64: base64.StdEncoding.EncodeToString(x2), ExpectSource: 1,
			Why: "§3.4 rule 4 at the key: a changed x25519 at equal sequence NEVER overwrites — the row keeps its OLD key and the SPA continuity path stays consistent",
		},
		{
			Name: "created_ts_skew", Card: "future_skew", Expect: "skew",
			ExpectAlias: "", ExpectXB64: "", ExpectSource: -1,
			Why: "§3.1 skew rule at merge: created_ts more than 300 s ahead of the receiver → the card never verifies",
		},
		{
			Name: "tampered_signature", Card: "tampered_sig", Expect: "sig",
			ExpectAlias: "", ExpectXB64: "", ExpectSource: -1,
			Why: "§3.4 preamble: one flipped bit in the self-signature — the card is dropped before the merge rules run",
		},
	}
	return &directoryVectorSet{
		Provenance: "Generated by node/internal/directory (issue #33 P3.8) from the §9.3 card layout and the " +
			"offline-maintenance §3.4 merge rules of docs/node-network.md. Go-signed identity cards over the fixed " +
			"RFC 8032 §7.1 test seed and a fixed wall clock; the C side (dtn_dirfed.c) must reach identical verdicts " +
			"and identical row states on the identical bytes. Committed copies MUST NOT be hand-edited.",
		RegenCommand: dvecRegenCmd,
		Now:          dvecNow,
		UserSeedHex:  dvecUserSeedHex,
		Alias:        "alice_77",
		PubkeyB64:    pubkeyB64,
		Cards:        cards,
		Scenarios:    scenarios,
	}
}

func dvecJSONBytes(t *testing.T, vs *directoryVectorSet) []byte {
	t.Helper()
	b, err := json.MarshalIndent(vs, "", "  ")
	if err != nil {
		t.Fatalf("marshal vectors: %v", err)
	}
	return append(b, '\n')
}

// --- the generated C header ---------------------------------------------------

func dvecCHeaderBytes(t *testing.T, vs *directoryVectorSet) []byte {
	t.Helper()
	mustHex := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatalf("vector hex: %v", err)
		}
		return b
	}
	var out bytes.Buffer
	fmt.Fprintf(&out, `/* directory_vectors.h — P3.8 directory-card test vectors for the C host suite.
 * GENERATED from tests/vectors/directory/vectors.json by the Go vector test:
 *   %s
 * Do not edit by hand — regenerate. The cards below were SIGNED in Go and
 * must reach identical §9.3 verdicts and §3.4 merge outcomes in C
 * (dtn_dirfed.c), byte for byte.
 */
#ifndef DTN_TEST_DIRECTORY_VECTORS_H
#define DTN_TEST_DIRECTORY_VECTORS_H

#include <stddef.h>
#include <stdint.h>

#define DVEC_NOW %dll

`, dvecRegenCmd, vs.Now)

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

	pub, err := base64.StdEncoding.DecodeString(vs.PubkeyB64)
	if err != nil {
		t.Fatal(err)
	}
	hexBytes(&out, "DVEC_USER_PUB", pub)
	// The row key as the stored Base64 TEXT (the directory table's dedup
	// key, §3.4 rule 1) — the C runner's find calls use it.
	fmt.Fprintf(&out, "#define DVEC_PUBKEY \"%s\"\n", vs.PubkeyB64)
	// The identity's x25519 (the seq1 card's) as the stored Base64 TEXT —
	// the C row-state assertions compare the store's string against it.
	fmt.Fprintf(&out, "#define DVEC_X_SEQ1 \"%s\"\n", vs.Cards[0].XB64)

	// The per-card COSE byte arrays come FIRST (a C initializer list cannot
	// contain declarations between its rows).
	for i, c := range vs.Cards {
		hexBytes(&out, fmt.Sprintf("DVEC_CARD_%d_COSE", i), mustHex(c.CoseHex))
	}

	fmt.Fprintf(&out, `
typedef struct {
    const char *name;
    const uint8_t *cose;
    size_t len;
} dtn_dirfed_card_vec;

/* card name → cose bytes lookup (card_name and seed_names resolve here). */
static const dtn_dirfed_card_vec DVEC_CARDS[] = {
`)
	for i, c := range vs.Cards {
		sym := fmt.Sprintf("DVEC_CARD_%d_COSE", i)
		fmt.Fprintf(&out, "    {\"%s\", %s, sizeof(%s)},\n", c.Name, sym, sym)
	}
	out.WriteString("};\n")

	fmt.Fprintf(&out, `
typedef struct {
    const char *name;
    const char *card_name;     /* the card under test (DVEC_CARDS lookup) */
    const char *seed_names[4]; /* NULL-terminated: cards merged into the store first */
    int expect;                /* the dtn_dirfed.h vocabulary: 0..5 merge outcomes, -1 shape, -2 sig, -3 skew */
    const char *expect_alias;  /* the row state after ("" = row absent) */
    const char *expect_x;      /* Base64 x25519 of the row after */
    int expect_source;         /* -1 = row absent; else 0|1 */
} dtn_dirfed_vec;

static const dtn_dirfed_vec DVEC_SCENARIOS[] = {
`)
	for _, sc := range vs.Scenarios {
		var seeds bytes.Buffer
		for _, s := range sc.SeedCards {
			fmt.Fprintf(&seeds, "\"%s\", ", s)
		}
		expect := map[string]int{
			"insert": 0, "replace": 1, "stale": 2, "duplicate": 3, "conflict": 4,
			"dropped_at_cap": 5, "shape": -1, "sig": -2, "skew": -3,
		}[sc.Expect]
		fmt.Fprintf(&out, `    {.name = "%s", .card_name = "%s", .seed_names = {%s}, .expect = %d,
      .expect_alias = "%s", .expect_x = "%s", .expect_source = %d},
`,
			sc.Name, sc.Card, seeds.String(), expect, sc.ExpectAlias, sc.ExpectXB64, sc.ExpectSource)
	}
	out.WriteString("};\n\n#endif /* DTN_TEST_DIRECTORY_VECTORS_H */\n")
	return out.Bytes()
}

// --- the tests --------------------------------------------------------------

// TestDirectoryVectorsStable pins the committed artifacts byte-for-byte;
// -regen rewrites both (the only sanctioned way to change them).
func TestDirectoryVectorsStable(t *testing.T) {
	wantJSON := dvecJSONBytes(t, buildDirectoryVectorSet(t))
	wantHeader := dvecCHeaderBytes(t, buildDirectoryVectorSet(t))
	jsonPath := dvecJSONPath()
	headerPath := dvecHeaderPath()
	if regenDirectoryVectors != nil && *regenDirectoryVectors {
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
		t.Fatalf("committed vectors missing (run %s): %v", dvecRegenCmd, err)
	}
	if !bytes.Equal(gotJSON, wantJSON) {
		t.Fatalf("directory vectors.json drifted from the deterministic builder — run %s and commit", dvecRegenCmd)
	}
	gotHeader, err := os.ReadFile(headerPath)
	if err != nil {
		t.Fatalf("committed C header missing (run %s): %v", dvecRegenCmd, err)
	}
	if !bytes.Equal(gotHeader, wantHeader) {
		t.Fatalf("directory_vectors.h drifted from vectors.json — run %s and commit", dvecRegenCmd)
	}
}

// dvecCardByHex decodes one committed card.
func dvecCardByHex(t *testing.T, vs *directoryVectorSet, name string) []byte {
	t.Helper()
	for _, c := range vs.Cards {
		if c.Name == name {
			raw, err := hex.DecodeString(c.CoseHex)
			if err != nil {
				t.Fatal(err)
			}
			return raw
		}
	}
	t.Fatalf("unknown card %s", name)
	return nil
}

// dvecOpenStore opens a fresh user-plane store for one scenario.
func dvecOpenStore(t *testing.T) *storage.Store {
	t.Helper()
	s, err := storage.Open(filepath.Join(t.TempDir(), "vectors.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// TestDirectoryVectorsGoImplementation executes every committed scenario
// against the Go pipeline — verification, then the §3.4 merge into a REAL
// user-plane store, then the full row state (the Go half of the shared-
// vector contract, §11 row k).
func TestDirectoryVectorsGoImplementation(t *testing.T) {
	raw, err := os.ReadFile(dvecJSONPath())
	if err != nil {
		t.Skipf("vectors not committed yet (%v)", err)
	}
	var vs directoryVectorSet
	if err := json.Unmarshal(raw, &vs); err != nil {
		t.Fatalf("vectors.json: %v", err)
	}
	cardCose := func(name string) []byte {
		for _, c := range vs.Cards {
			if c.Name == name {
				b, err := hex.DecodeString(c.CoseHex)
				if err != nil {
					t.Fatal(err)
				}
				return b
			}
		}
		t.Fatalf("unknown card %s", name)
		return nil
	}

	for _, sc := range vs.Scenarios {
		t.Run(sc.Name, func(t *testing.T) {
			s := dvecOpenStore(t)
			merge := func(cose []byte) (directory.MergeOutcome, error) {
				card, err := directory.VerifyCard(cose, vs.Now)
				if err != nil {
					return -1, err
				}
				res, err := s.MergeFederatedCard(directory.CardMerge{
					CardB64:  directory.CanonicalB64(cose),
					Raw:      cose,
					Pubkey:   card.PubkeyB64(),
					X25519:   card.X25519B64(),
					Alias:    card.Alias,
					Seq:      card.Seq,
					LastSeen: vs.Now,
				})
				if err != nil {
					return -1, err
				}
				return res.Outcome, nil
			}
			for _, name := range sc.SeedCards {
				got, err := merge(cardCose(name))
				if err != nil || got != directory.MergeInsert {
					t.Fatalf("seed card %s: %v/%v", name, got, err)
				}
			}

			cose := cardCose(sc.Card)
			got := ""
			if _, verr := directory.VerifyCard(cose, vs.Now); verr != nil {
				switch {
				case strings.Contains(verr.Error(), "ahead of the receiver"):
					got = "skew"
				case strings.Contains(verr.Error(), "signature"):
					got = "sig"
				default:
					got = "shape"
				}
			} else {
				res, err := s.MergeFederatedCard(reqOf(cose, vs.Now))
				if err != nil {
					t.Fatal(err)
				}
				got = res.Outcome.String()
			}
			if got != sc.Expect {
				t.Fatalf("verdict %s, want %s", got, sc.Expect)
			}
			// The full row state after (the part the C side must match too).
			row, err := s.DirectoryRowOf(vs.PubkeyB64)
			if err != nil {
				t.Fatal(err)
			}
			if sc.ExpectSource < 0 {
				if row != nil {
					t.Fatalf("row must be absent, got %+v", row)
				}
				return
			}
			if row == nil {
				t.Fatal("row absent")
			}
			if row.Alias != sc.ExpectAlias || row.X25519 != sc.ExpectXB64 || row.Source != sc.ExpectSource {
				t.Fatalf("row after: alias %q x %q source %d, want %q/%q/%d",
					row.Alias, row.X25519, row.Source, sc.ExpectAlias, sc.ExpectXB64, sc.ExpectSource)
			}
		})
	}
}

// reqOf builds the merge request the Federator builds (the same shape the
// production path uses).
func reqOf(cose []byte, now int64) directory.CardMerge {
	card, err := directory.ParseCard(cose)
	if err != nil {
		panic(err)
	}
	return directory.CardMerge{
		CardB64:  directory.CanonicalB64(cose),
		Raw:      cose,
		Pubkey:   card.PubkeyB64(),
		X25519:   card.X25519B64(),
		Alias:    card.Alias,
		Seq:      card.Seq,
		LastSeen: now,
	}
}
