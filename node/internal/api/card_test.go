package api

// card_test.go — the §3.2 card hook at the HTTP door (docs/node-network.md
// §9.3, offline-maintenance §3.2): blind validation ONLY (the node never
// verifies a published signature at registration, §1/§10.3), verbatim
// storage, wire-compatible absence semantics, and the emission hook the
// daemon's federation policy owns.

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"offgrid/dtn-node/internal/directory"
	"offgrid/dtn-node/internal/nodeid"
	"offgrid/dtn-node/internal/storage"
)

func cardTestUser(t *testing.T) nodeid.KeyPair {
	t.Helper()
	s := sha256.Sum256([]byte("offgrid-api-card-test-user"))
	kp, err := nodeid.NewKeyPairFromSeed(s[:])
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

func cardTestX(t *testing.T) []byte {
	t.Helper()
	s := sha256.Sum256([]byte("offgrid-api-card-test-x"))
	return s[:]
}

// postDirectory issues one POST /api/v1/directory with the canonical Host.
func postDirectory(t *testing.T, h http.Handler, body map[string]string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/directory", bytes.NewReader(raw))
	req.Host = CanonicalHost
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	if json.Unmarshal(rec.Body.Bytes(), &out) == nil {
		return rec, out
	}
	return rec, nil
}

func TestCardHookHappyPath(t *testing.T) {
	s, err := storage.Open(filepath.Join(t.TempDir(), "card.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	h := newTestHandlerWithStore(t, s)

	user := cardTestUser(t)
	x := cardTestX(t)
	pubkey := base64.StdEncoding.EncodeToString(user.Public)
	xB64 := base64.StdEncoding.EncodeToString(x)
	cose, err := directory.SignCard(user, "alice_77", x, 1791072000, 3)
	if err != nil {
		t.Fatal(err)
	}
	cardB64 := directory.CanonicalB64(cose)

	var emitted [][]byte
	h2 := newTestHandlerWithEmitter(t, s, func(card []byte) { emitted = append(emitted, card) })

	rec, body := postDirectory(t, h2, map[string]string{
		"alias": "alice_77", "pubkey": pubkey, "x25519": xB64, "card": cardB64,
	})
	if rec.Code != http.StatusOK || body["status"] != "ok" {
		t.Fatalf("register with card: %d %v", rec.Code, body)
	}
	// The response shape is UNCHANGED (§3.2 is wire-compatible).
	if len(body) != 1 {
		t.Fatalf("the register response gained members: %v", body)
	}
	// The card is stored VERBATIM.
	row, err := s.DirectoryRowOf(pubkey)
	if err != nil || row == nil {
		t.Fatalf("row: %v %v", row, err)
	}
	if row.Card.String != cardB64 || row.Source != 0 {
		t.Fatalf("stored card/source: %q/%d", row.Card.String, row.Source)
	}
	// The emitter got the exact COSE bytes (the daemon decides per its
	// federation policy whether a bundle leaves the node).
	if len(emitted) != 1 || !bytes.Equal(emitted[0], cose) {
		t.Fatalf("emitter: %d calls", len(emitted))
	}

	// The GET response is UNCHANGED: no card, no source members — the SPA
	// cannot tell a card-carrying row from a legacy one.
	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/directory", nil)
	getReq.Host = CanonicalHost
	grec := httptest.NewRecorder()
	h.ServeHTTP(grec, getReq)
	var entries []map[string]any
	if err := json.Unmarshal(grec.Body.Bytes(), &entries); err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries: %v", entries)
	}
	for _, forbidden := range []string{"card", "source"} {
		if _, has := entries[0][forbidden]; has {
			t.Fatalf("the GET response leaked the internal %q member", forbidden)
		}
	}

	// Absence clears the stored card (the §3.2 downgrade self-heal, the
	// prekeys pattern) and the emitter stays silent for card-less POSTs.
	rec, body = postDirectory(t, h2, map[string]string{
		"alias": "alice_77", "pubkey": pubkey, "x25519": xB64,
	})
	if rec.Code != http.StatusOK || body["status"] != "ok" {
		t.Fatalf("re-register without card: %d %v", rec.Code, body)
	}
	row, _ = s.DirectoryRowOf(pubkey)
	if row.Card.Valid && row.Card.String != "" {
		t.Fatalf("absence did not clear the card: %q", row.Card.String)
	}
	if len(emitted) != 1 {
		t.Fatalf("a card-less POST emitted %d time(s)", len(emitted)-1)
	}
}

func TestCardHookBlindValidation(t *testing.T) {
	s, err := storage.Open(filepath.Join(t.TempDir(), "card.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	var emitted [][]byte
	h := newTestHandlerWithEmitter(t, s, func(card []byte) { emitted = append(emitted, card) })
	user := cardTestUser(t)
	other, err := nodeid.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	x := cardTestX(t)
	pubkey := base64.StdEncoding.EncodeToString(user.Public)
	xB64 := base64.StdEncoding.EncodeToString(x)
	otherPub := base64.StdEncoding.EncodeToString(other.Public)

	good, err := directory.SignCard(user, "alice_77", x, 1791072000, 1)
	if err != nil {
		t.Fatal(err)
	}
	goodB64 := directory.CanonicalB64(good)

	cases := []struct {
		name string
		card string
	}{
		{"about_another_identity", directory.CanonicalB64(mustSignCard(t, other, "alice_77", x))}, // §3.2 equality: card.ed ≠ body.pubkey
		{"x_mismatch", directory.CanonicalB64(mustSignCard(t, user, "alice_77", cardTestX2(t)))},  // §3.2 equality: card.x ≠ body.x25519
		{"not_base64", "not base64!!"},
		{"garbage_bytes", base64.StdEncoding.EncodeToString([]byte("garbage bytes that are not cbor"))},
		{"oversize", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x84}, directory.CardMaxBytes+1))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec, body := postDirectory(t, h, map[string]string{
				"alias": "alice_77", "pubkey": pubkey, "x25519": xB64, "card": tc.card,
			})
			if rec.Code != http.StatusBadRequest || body["error"] != "invalid_card" {
				t.Fatalf("got %d %v, want 400 invalid_card", rec.Code, body)
			}
			if row, _ := s.DirectoryRowOf(pubkey); row != nil {
				t.Fatal("a rejected card stored a row")
			}
		})
	}

	// A card about a DIFFERENT identity does not become a row either (the
	// wrong-pubkey case above shares the dedup key path).
	if row, _ := s.DirectoryRowOf(otherPub); row != nil {
		t.Fatal("the other identity's card stored a row")
	}
	// The fully valid card passes the same door (control) — and ONLY it
	// reaches the emitter: every rejected card stayed at the door.
	rec, body := postDirectory(t, h, map[string]string{
		"alias": "alice_77", "pubkey": pubkey, "x25519": xB64, "card": goodB64,
	})
	if rec.Code != http.StatusOK || body["status"] != "ok" {
		t.Fatalf("control register: %d %v", rec.Code, body)
	}
	if len(emitted) != 1 {
		t.Fatalf("the emitter fired %d time(s), want exactly 1 (the control)", len(emitted))
	}
}

// newTestHandlerWithStore is newTestHandler with an explicit store.
func newTestHandlerWithStore(t *testing.T, s *storage.Store) http.Handler {
	t.Helper()
	h, err := NewWithCounters(s, nil, testBuild, testWebFS)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// newTestHandlerWithEmitter wires the §9.3 emission hook.
func newTestHandlerWithEmitter(t *testing.T, s *storage.Store, emit func([]byte)) http.Handler {
	t.Helper()
	h, err := NewWithCounters(s, nil, testBuild, testWebFS, WithDirectoryCard(emit))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func mustSignCard(t *testing.T, user nodeid.KeyPair, alias string, x []byte) []byte {
	t.Helper()
	cose, err := directory.SignCard(user, alias, x, 1791072000, 1)
	if err != nil {
		t.Fatal(err)
	}
	return cose
}

func cardTestX2(t *testing.T) []byte {
	t.Helper()
	s := sha256.Sum256([]byte("offgrid-api-card-test-x2"))
	return s[:]
}
