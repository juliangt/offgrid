# Development Plan — Off-Grid DTN Messaging System (Phase 1)

| | |
|---|---|
| **Source document** | `docs/MASTER_DEVELOPMENT_PROMPT.md` |
| **Plan version** | 1.0 |
| **Date** | 2026-10-03 |
| **Status** | Pending approval |
| **Scope** | Complete Phase 1 (Modules A–D) + preparation for Phases 2/3 |

---

## 0. Executive summary

An asynchronous, end-to-end encrypted (E2EE) messaging system will be built, operating **with no Internet, no satellites and no cellular network**. The components:

- **Fixed nodes (Module A + B):** Raspberry Pi Zero 2 W boards running an open Wi-Fi access point with a captive portal, executing a self-contained HTTP daemon in Go with SQLite, acting as blind *dead drops*. Solar power + LiFePO4 battery.
- **Data mules (Module C):** users carry other people's encrypted envelopes in their mobile browser's `IndexedDB` (capacity 50–100 envelopes) while physically moving between nodes, syncing on each portal they connect to.
- **Evolution (Module D):** the envelope format is designed from day 1 to migrate without rewrite to BLE L2CAP CoC (bitchat, Phase 2) and LoRa P2P SX1262 at 915 MHz with CBOR (Phase 3).

**Deliverables:** the Pi network configuration (hostapd, dnsmasq, iptables, power), a static Go binary with an embedded frontend, a single-file `index.html` SPA with an embedded crypto engine, the Phase 2/3 mapping documentation, and step-by-step build, run and test instructions.

**Total estimate:** 6–8 days of work spread across 5 sprints (§5).

---

## 1. Source document analysis: design decisions and critical points

This section records the detailed analysis of the master prompt. Every decision made here is binding for the implementation.

### 1.1 The same-origin trick and its consequences

`IndexedDB` is isolated per web origin (scheme + host + port). For a mule to keep its identity, inbox and transit queue while moving between nodes, **all nodes must be indistinguishable in origin**: same FQDN (`offgrid.local`), same port (8080) and same gateway IP (`10.42.0.1`).

Operational consequences:

1. **Canonical-host middleware in Go:** every request whose `Host` header is not `offgrid.local:8080` (e.g. `10.42.0.1:8080`, or any domain "spoofed" by the wildcard DNS) must answer `301 → http://offgrid.local:8080/`. The browser thus always ends up on the correct origin and storage never fragments.
2. **Mandatory exemption:** the portal-detection endpoints (`/generate_204`, `/hotspot-detect.html`) must answer `302` with an absolute `Location` **regardless of the Host** (they arrive with Host `connectivitycheck.gstatic.com`, `captive.apple.com`, etc. via the wildcard DNS) and must **not** be redirected to the canonical host first, or the OS will fail to detect the captive portal.
3. **No TLS:** a valid certificate for `offgrid.local` is impossible with the same IP on every node (and offline PKI would require client-side installation). Plain HTTP is used. This is acceptable **only because** content travels E2EE-encrypted on the client: the node (a hostile channel by design) never sees plaintext, keys, the real sender or the full recipient. TLS would add a false sense of security without protecting anything the application-layer crypto does not already protect.
4. **Risk of "accidental fragmentation":** if a user bookmarks the IP instead of the FQDN, their session would land on a different origin. Mitigation: the middleware of point 1 + always displaying the canonical URL in the UI.

### 1.2 Threat model and the honest limitation of the `dest_hint`

The master prompt requires that nodes do not know "the content, the real sender or the full identity of the recipient".

- **Content:** guaranteed by encryption (anonymous sender, see §3.4).
- **Sender:** the Ed25519 signature and the sender's alias travel **inside the ciphertext** (sign-then-encrypt). The node only sees random bytes.
- **Recipient:** the node sees `dest_hint` — since 1.6.0 a TRUNCATED EPOCH-KEYED HASH of the recipient's X25519 public key (`HKDF-SHA256(pubkey, epoch)[0:8]`, protocol §6.1) — so it can store and serve the envelopes. **Documented limitation, mitigated by rotation:** before 1.6.0 the hint was a static truncated hash, so a malicious directory-holding operator *could* recompute the hints of registered users and link envelopes to aliases permanently (the accepted Phase 1 risk). With the §6.1 rotating derivation the linkage expires at each epoch boundary: an operator recomputing hints from directory data matches only the CURRENT epoch's envelopes, never older ones; the residuals (within-epoch linking, the legacy-hint transition window until 2026-11-30, traffic analysis) are documented in `docs/protocol.md` §13.3 — hiding them would be an engineering error.

Real purpose of the `dest_hint`: (a) allowing the **mule** to identify, without decrypting, which envelopes are its own (it compares against the hint derived from its own key) and (b) dedup/cleanup on the node.

### 1.3 Crypto engine: embedded tweetnacl, not native WebCrypto

The master prompt itself offers the alternative ("or an embedded implementation of `tweetnacl.js` injected directly into the file"). **Decision: embed tweetnacl.js inline** as the single code path, for three reasons:

1. `X25519`/`Ed25519` availability in `crypto.subtle` is irregular on mobile browsers and **even worse in captive-portal mini-browsers** (Android Captive Portal WebView, iOS CNA). A single code path eliminates an entire class of bugs.
2. It guarantees identical behavior across browsers (same primitives: `crypto_box` = X25519+XSalsa20-Poly1305, `crypto_sign` = Ed25519).
3. It satisfies the zero-external-dependencies rule: tweetnacl (≈25 KB minified) is embedded literally inside `index.html`.

Entropy comes from `crypto.getRandomValues` (available in all modern WebViews, including captive ones).

### 1.4 The captive-portal mini-browser problem

When Android/iOS detect the captive portal, they open a restricted mini-browser whose storage profile **is isolated from the device's real browser**. Consequences:

- If the user only ever uses the mini-browser, everything works *inside it* as long as they keep using it, but their data may not persist reliably across sessions/nodes.
- **Mandatory UI mitigation:** a banner detecting the restrictive context with the instruction "Open this in your full browser: `http://offgrid.local:8080`" (visible, copyable URL). Recommended user flow: join the Wi-Fi → open the URL in Chrome/Safari.
- The acceptance tests (§6) explicitly cover both contexts.

### 1.5 Byte budget: Phase 1 (JSON/Base64) vs Phase 2/3 (binary)

The master prompt asks for envelopes with a standard payload of ~180–250 bytes, migratable to BLE/LoRa without rewrite.

- **Phase 1 (HTTP/Wi-Fi transport):** the envelope travels as JSON with the binary payload encoded in Base64. The **logical payload** (eph_pub 32 B + nonce 24 B + ciphertext with MAC) stays ≤ 256 bytes, meeting the target; the Base64/JSON inflation is irrelevant over Wi-Fi.
- **Phase 3 (LoRa 222 B MTU):** the same envelope in CBOR (eph 32 + nonce 24 + MAC 16 + headers) exceeds the MTU if the plaintext uses the full 128 B with signature and alias inside. **Decision:** bitchat-style 2-frame fragmentation (1 B header: `win_id` 4 bits + `idx` 2 bits + `total` 2 bits), documented in Module D. A "short message" alternative (≤ 48 B) in a single frame is documented with the exact math in `docs/protocol.md`.
- **Phase 2 (BLE L2CAP CoC):** negotiable MTU (≥ 512 B typical) → the binary CBOR envelope fits whole; the `hop_count` field (≤ 7) is reserved — always 0 in Phase 1, traveling implicitly (absent) in the JSON.

### 1.6 Raspberry Pi OS Bookworm: NetworkManager vs classic hostapd

Current Raspberry Pi OS Lite (Bookworm) images use **NetworkManager** by default, which conflicts with classic `hostapd` + `dnsmasq` (and its wpa_supplicant AP mode does not support `ap_isolate`). **Decision:**

- Disable NetworkManager during provisioning and use the classic **ifupdown + hostapd + dnsmasq + iptables (nft layer)** stack, which is exactly the one Module A's deliverables require.
- The provisioning script detects the scenario (Bookworm/NM vs legacy/dhcpcd) and acts accordingly, with a verification of the outcome at every step.

### 1.7 Consolidated protocol decisions

| Parameter | Value | Justification |
|---|---|---|
| Encryption | X25519 + XSalsa20-Poly1305 (`crypto_box`, ephemeral per message) | Sender isolation + confidentiality; standard bitchat primitives |
| Signature/identity | Ed25519 (`crypto_sign`) | Sender identity verifiable only by the recipient |
| Cryptographic order | **Sign-then-encrypt** (signature and alias INSIDE the ciphertext) | Sender anonymity against nodes and mules |
| `dest_hint` | **Rotating since 1.6.0:** first 8 B of `HKDF-SHA256(X25519_pub, epoch)` in hex (16 chars), epoch = 24 h UTC on the node clock; senders use the directory entry's server-set epoch, recipients try {legacy static, current, previous} (protocol §6.1). The legacy static form (`SHA-256` first 8 B) retires at the §6.1 deadline (2026-11-30) | Blind routing + mule self-identification; hint↔alias linkability now decays per epoch (§1.2 limitation mitigated, residual within one epoch) |
| Envelope `id` | `SHA-256(canonical JSON of v‖dest_hint‖created_at‖ttl‖payload)` in hex (64 chars) | Global dedup across nodes (`INSERT OR IGNORE`) — computed by the client |
| Plaintext limit | 128 bytes per envelope (visible counter in the UI); longer texts are split client-side into at most 16 chunk envelopes and reassembled by the recipient (protocol §4.4) | Alignment with the Phase 2/3 budget; long messages ride as ordinary envelopes |
| Delivery feedback | One optional signed "ack" envelope per delivered message, addressed back to the sender's `dest_hint` (recipients opt in per identity; acks are never acked; best-effort) | Private delivery states without any node/mule change — the ack is an ordinary envelope with a versioned inner convention (protocol §4.5) |
| In-person contact exchange | Since 1.8.0: the signed, checksummed `OFFGRID1:` QR payload (alias + Ed25519 key + X25519 key, §4.7) shown/scanned in person or pasted as text; device-local `contacts` store merged with the directory at send time, deduped by the Ed25519 key | Self-authenticating identity hand-off without typing keys and without any node/wire change; tampered payloads are rejected visibly, and a saved contact keeps mail flowing when the directory is unreachable (protocol §4.7) |
| Default TTL | 604,800 s (7 days); min 3,600; max 2,592,000 (30 days) | Envelope expiry in dead drops with limited storage |
| Mule capacity (`transit_queue`) | 100 envelopes, FIFO eviction by `created_at` | Within the required 50–100 range |
| Per-sync limits | `limit` default 50, max 200; push max 100 envelopes; body ≤ 1 MiB; `known_ids` max 500 | Protection of the open node (abuse/filling) |
| Directory | max 500 entries on GET; alias `^[A-Za-z0-9_.-]{1,24}$` | Sanitized on client and server |

---

## 2. System architecture

```
        ┌─────────────────────────┐          ┌─────────────────────────┐
        │   NODE A (Pi Zero 2 W)  │          │   NODE B (Pi Zero 2 W)  │
        │  SSID: offgrid-messages │          │  SSID: offgrid-messages │
        │  ch.6  GW 10.42.0.1     │          │  ch.6  GW 10.42.0.1     │
        │   offgrid.local:8080    │          │   offgrid.local:8080    │
        │  ┌───────────────────┐  │          │  ┌───────────────────┐  │
        │  │ hostapd (open AP) │  │          │  │  (identical)      │  │
        │  │ dnsmasq (DHCP+DNS │  │          │  │                   │  │
        │  │  wildcard→10.42.0.│  │          │  │                   │  │
        │  │ iptables 80→8080  │  │          │  └───────────────────┘  │
        │  │ dtn-node (Go+SQLi │  │          │  ┌───────────────────┐  │
        │  │  + index.html emb)│  │          │  │ dtn-node (Go+SQLi │  │
        │  └───────────────────┘  │          │  └───────────────────┘  │
        └───────────△─────────────┘          └───────────△─────────────┘
                    │ Wi-Fi (200 m)                      │ Wi-Fi
                    ▼                                    ▼
        ┌─────────────────────────────────────────────────────────┐
        │           MULE (user's mobile browser)                  │
        │  http://offgrid.local:8080  ← SAME ORIGIN ALWAYS        │
        │  IndexedDB «dtn_local_store»:                           │
        │   · identity  (X25519 + Ed25519 + alias)                │
        │   · inbox     (own decrypted messages)                  │
        │   · transit_queue (≤100 foreign envelopes carried)      │
        │  POST /api/v1/sync on page load:                        │
        │   push(transit_queue) + known_ids → pull(≤limit)         │
        │   mine(dest_hint==mine)→decrypt→inbox ; rest→transit    │
        └─────────────────────────────────────────────────────────┘
```

**Message flow (E2E):**

1. Alice registers once (alias + key pair generated on her device; private keys never leave `IndexedDB`).
2. Alice fetches the node's directory, picks Bob, writes ≤128 B. Her client: signs (Ed25519) → packs `{msg, alias, ed_pub, sig, ts}` → encrypts with an ephemeral X25519 key toward Bob's pubkey → builds the envelope with Bob's `dest_hint` → `id = SHA-256(canonical)`.
3. The envelope enters node A via `POST /api/v1/sync` (push). The node only sees random bytes and a hint.
4. Any user syncing with node A (Alice included) takes the envelope in `pull` if they do not know it → loads it into their `transit_queue` (mule).
5. That user walks to node B and syncs: the envelope is dropped (push) onto node B.
6. Bob syncs with node B, detects his own `dest_hint`, decrypts (X25519 ECDH → `crypto_box.open`), verifies Alice's Ed25519 signature, and the message lands in his `inbox`.

---

## 3. Protocol specification (executive summary)

> The complete, normative specification lives in `docs/protocol.md` (Sprint 0). This summary is binding.

### 3.1 Envelope (Phase 1, JSON)

```json
{
  "v": 1,
  "id": "b6c1…64-hex…",
  "dest_hint": "9f3ab02c1d77e4c1",
  "created_at": 1759500000,
  "ttl": 604800,
  "payload": "BASE64( eph_pub(32B) ‖ nonce(24B) ‖ box( inner_json, MAC=16B ) )"
}
```

`inner_json` (visible only after decrypting): `{"m": "text ≤128B", "a": "alias", "k": "ed25519_pub_b64", "s": "signature_b64_over_json_without_s", "t": 1759500000}`.

### 3.2 SQLite tables (`node_storage.db`)

```sql
CREATE TABLE envelopes (
  id        TEXT PRIMARY KEY,
  dest_hint TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  ttl       INTEGER NOT NULL,
  payload   TEXT NOT NULL
);
CREATE INDEX idx_envelopes_dest_hint ON envelopes(dest_hint);
CREATE INDEX idx_envelopes_expiry    ON envelopes(created_at, ttl);

CREATE TABLE directory (
  pubkey    TEXT PRIMARY KEY,   -- ed25519 (identity)
  x25519    TEXT NOT NULL,      -- encryption pubkey
  alias     TEXT NOT NULL,
  last_seen INTEGER NOT NULL
);
```

### 3.3 API (exact surface required by the master prompt)

| Method + path | Behavior |
|---|---|
| `GET /` | Serves the embedded `index.html` (`embed.FS`). Non-canonical Host → `301` to `offgrid.local:8080` |
| `GET /generate_204` | `302 → http://offgrid.local:8080/` (Android; **never** answer 204 here) |
| `GET /hotspot-detect.html` | `302 → http://offgrid.local:8080/` (iOS) |
| `GET /api/v1/directory` | Lists `alias+pubkey+x25519+last_seen` (≤500, by `last_seen DESC`) |
| `POST /api/v1/directory` | User upsert; `last_seen=now` |
| `POST /api/v1/sync` | Input `{known_ids[], push_envelopes[], limit}` → `INSERT OR IGNORE` push; SELECT live envelopes (`created_at+ttl ≥ now`) not included in `known_ids`, by `created_at DESC` `LIMIT limit` → `{status:"ok", pull_envelopes[]}` |

Cleanup worker: goroutine + `time.Ticker` every 15 min: `DELETE FROM envelopes WHERE created_at + ttl < now`.

### 3.4 Phase 2/3 mapping (Module D, documentation embedded in the code)

- **BLE (bitchat, Phase 2):** doc-comment on the Go `Envelope` type and on its JS equivalent with the JSON→CBOR table, the L2CAP CoC frame layout and the `hop_count ≤ 7` semantics (reserved field, 0 in Phase 1).
- **LoRa (SX1262, Phase 3):** CBOR size math, 222 B/frame budget and the 1 B fragment format (`win_id|idx|total`) for 2-frame messages.

---

## 4. Repository structure

```
offgrid/
├── README.md                            # overview + quick guide
├── docs/
│   ├── MASTER_DEVELOPMENT_PROMPT.md     # source (do not modify)
│   ├── DEVELOPMENT_PLAN.md              # this document
│   ├── protocol.md                      # normative Envelope spec (Sprint 0)
│   ├── BUILD.md                         # step-by-step build/run/test (Sprint 4)
│   └── hardware.md                      # solar/LiFePO4 assembly + provisioning
├── node/                                # Module B — Go daemon
│   ├── go.mod                           # module offgrid/dtn-node (Go ≥1.22)
│   ├── main.go                          # startup, flags, signals
│   ├── internal/
│   │   ├── storage/storage.go           # SQLite (modernc.org/sqlite, WAL, busy_timeout)
│   │   ├── api/handlers.go              # endpoints + canonical-host middleware + limits
│   │   ├── api/middleware.go
│   │   ├── cleanup/cleanup.go           # 15 min ticker
│   │   └── envelope/envelope.go         # Envelope type + validation + Phase 2/3 doc
│   ├── web/                             # Module C (SPA source, embedded)
│   │   ├── index.html                   # page skeleton; links css/ + js/ (CSP: 'self')
│   │   ├── css/app.css                  # all styles
│   │   └── js/                          # plain ES5 scripts, loaded in dependency order
│   │       ├── vendor/nacl.min.js       # tweetnacl 1.0.3, verbatim embed (Unlicense)
│   │       ├── constants.js … mule.js   # pure protocol engine (§5/§6/§8/§11)
│   │       ├── engine.js                # window.DTN export (headless-testable)
│   │       ├── store.js                 # IndexedDB local store
│   │       └── ui.js                    # DOM wiring (initUi)
│   ├── build.sh                         # cross-compile linux/arm64 + linux/arm
│   └── storage_test.go / api_test.go …  # unit tests
├── raspberry/                           # Module A — infrastructure
│   ├── hostapd/hostapd.conf             # → /etc/hostapd/hostapd.conf
│   ├── dnsmasq/dnsmasq.conf             # → /etc/dnsmasq.conf
│   ├── firewall/iptables.sh             # REDIRECT 80→8080, client isolation
│   ├── power/                           # config.txt (HDMI/LEDs/BT), dtn-power.service
│   ├── systemd/dtn-node.service         # daemon at /opt/dtn-node
│   └── provision.sh                     # idempotent step-by-step provisioning
└── tests/
    ├── crypto_roundtrip.mjs             # tweetnacl: encrypt/sign/verify/decrypt
    └── sync_e2e.sh                      # curl: two clients + mule against a local instance
```

---

## 5. Sprint-by-sprint implementation plan

> Order chosen so development and testing are possible **without hardware** until Sprint 3: backend first (testable with `curl` on localhost), then the frontend (testable against the local backend), then the Pi infrastructure.

### Sprint 0 — Protocol and scaffolding (0.5 day)

| # | Task |
|---|---|
| 0.1 | `git init`, `.gitignore`, folder structure of §4, minimal `README.md` |
| 0.2 | `docs/protocol.md`: normative Envelope spec — fields, derivations (`id`, `dest_hint`), sign-then-encrypt order, limits table of §1.7, Phase 1/2/3 byte math, LoRa fragment format, L2CAP layout and `hop_count` semantics |
| 0.3 | Threat model write-up (§1.2) with the `dest_hint` limitation as an accepted risk |

**Verification:** the document allows implementing Modules B and C with no pending decisions.

### Sprint 1 — Module B: Go daemon (1.5 days)

| # | Task | Key details |
|---|---|---|
| 1.1 | Go module + `internal/envelope` | `Envelope` type with validation (sizes, TTL ranges, well-formed hex/base64) and Phase 2/3 mapping doc-comments (Module D, part 1) |
| 1.2 | `internal/storage` | `modernc.org/sqlite` (pure Go, no CGO), pragmas `journal_mode=WAL`, `busy_timeout=5000`, schema of §3.2, `SetMaxOpenConns(1)` (serializes writes; trivial load for a Zero 2 W) |
| 1.3 | `internal/api` | Endpoints of §3.3 exactly; canonical-host middleware with the captive-endpoint exemption (§1.1); limits: body ≤1 MiB, push ≤100, `limit` ≤200, `known_ids` ≤500, alias sanitization |
| 1.4 | `internal/cleanup` | 15 min ticker + run at startup |
| 1.5 | `main.go` + `embed.FS` | Flags (`-addr`, `-db`), serves `web/index.html` (minimal placeholder this sprint), graceful shutdown |
| 1.6 | Unit tests | `INSERT OR IGNORE` dedup, exclusion by `known_ids`, TTL expiry in the SELECT and in the cleaner, canonical redirect, limits, correct `302` from `/generate_204` (not 204) |
| 1.7 | `build.sh` | `GOOS=linux GOARCH=arm64` (Zero 2 W, primary) and `GOARCH=arm` (32-bit fallback), static binary |

**Verification:** `go test ./...` green; `curl` against `localhost:8080` exercises the full push→pull→cleanup cycle.

### Sprint 2 — Module C: SPA + crypto engine (2 days)

| # | Task | Key details |
|---|---|---|
| 2.1 | `web/index.html` skeleton | Single file, inline HTML+CSS+JS, system typography (zero external assets), responsive, labels in English (amended from the original "labels in Spanish" decision by issue #8) |
| 2.2 | tweetnacl embedded | Full source inline + base64/hex helpers; no `eval` |
| 2.3 | `IndexedDB` layer | `dtn_local_store` v1: `identity` (singleton), `inbox`, `transit_queue`; version-based migrations |
| 2.4 | Identity | Alias registration → X25519/Ed25519 key pair generation → `POST /api/v1/directory`; **manual seed backup** (copyable text + import) to survive browser data wipes |
| 2.5 | Encrypt/decrypt | Envelope construction per §3.1 (sign → encrypt → hint → id); decryption with signature verification; silent rejection of corrupt envelopes |
| 2.6 | Mule engine | Sync on load + manual button: push `transit_queue` + `known_ids` (inbox ∪ transit ∪ seen) → pull → classify: own→decrypt→`inbox`; foreign→`transit_queue` with FIFO≤100 |
| 2.7 | Full UI | Registration screen / recipient selector (directory) / composer with 128 B counter / inbox with sender and time / telemetry panel *"Foreign envelopes in transit: X / Capacity: 100"* + last-sync status / "open it in your full browser" banner (§1.4) |
| 2.8 | `tests/crypto_roundtrip.mjs` | Deterministic round-trip in Node: two identities, send, transport, receive, verify |

**Verification:** in the development browser against `go run .`: Alice→node→(second tab with a clean profile as the mule)→simulated node→Bob decrypts. Node round-trip green.

### Sprint 3 — Module A: Raspberry Pi infrastructure (1 day)

| # | Task | Key details |
|---|---|---|
| 3.1 | `hostapd.conf` | Open AP, SSID `offgrid-messages`, channel 6, `ap_isolate=1`, `wlan0`, configurable country |
| 3.2 | `dnsmasq.conf` | DHCP `10.42.0.50–250` (12 h), options 3 and 6 → `10.42.0.1`, `address=/#/10.42.0.1`, `address=/offgrid.local/10.42.0.1`, `bind-interfaces`, `no-resolv` |
| 3.3 | `firewall/iptables.sh` | `REDIRECT 80→8080` on `wlan0` (PREROUTING), FORWARD DROP policy (client-to-client isolation reinforcing `ap_isolate`), persistence |
| 3.4 | `power/` | `config.txt`: `dtoverlay=disable-bt`, LEDs off (`act_led_trigger=none`, `act_led_activelow=on`…), `dtparam=audio=off`, HDMI off (`hdmi_blanking=2` + oneshot service `vcgencmd display_power 0`), `powersave` governor; solar sizing note (~1 W continuous) |
| 3.5 | `provision.sh` | Idempotent: detects Bookworm/NM (disables it) vs legacy; static IP `10.42.0.1/24` on `wlan0`; installs configs; `dtn-node.service` with the binary at `/opt/dtn-node`; per-step verification |
| 3.6 | `systemd/dtn-node.service` | `After=network-online.target`, `Restart=always`, `WatchdogSec`, unprivileged user + data directory permissions |

**Verification on hardware (or VM):** the phone sees the captive portal automatically on connecting; `http://offgrid.local:8080` answers; a second device cannot talk to the first; after a Pi reboot everything restores by itself.

### Sprint 4 — E2E integration, final Module D and documentation (1.5 days)

| # | Task |
|---|---|
| 4.1 | Physical two-node test: Alice→Bob message carried by a mule walking between both; verification of `IndexedDB` persistence across nodes (same origin) |
| 4.2 | Test in the captive mini-browser (Android and iOS) and with the full-browser banner |
| 4.3 | `tests/sync_e2e.sh` reproducible without hardware (two instances + `/etc/hosts`) |
| 4.4 | Complete the Phase 2/3 Mapping doc-comments in Go and JS (Module D, part 2) and their summary in `docs/protocol.md` |
| 4.5 | `docs/BUILD.md`: **step-by-step** build, deploy, run and test; `docs/hardware.md` |
| 4.6 | Final hardening: limits review, input sanitizer, binary size, cold start |

**Verification:** the §8 acceptance checklist complete.

---

## 6. Test strategy

| Level | Scope | Tool |
|---|---|---|
| Unit (Go) | Storage, dedup, TTL, `known_ids` exclusion, middleware, limits, captive endpoints | `go test ./...` |
| Unit (JS) | Crypto round-trip, `id`/`dest_hint` derivation, `transit_queue` FIFO | Node + tweetnacl (`tests/crypto_roundtrip.mjs`) |
| Integration (no hardware) | push→pull→cleanup cycle; mule simulation with two "clients" | `curl` (`tests/sync_e2e.sh`) |
| Browser | Full Alice→mule→Bob flow; responsive UI; persistent storage | DevTools + two browser profiles |
| Hardware | Auto-detected captive portal (Android/iOS), client isolation, same origin across 2 nodes, cold start, power draw | Pi Zero 2 W ×2 + real phone |
| Local adversarial | Corrupt envelopes, duplicate ids, expired TTLs, oversized body | Go tests + curl |

---

## 7. Risks and mitigations

| Risk | Prob. | Impact | Mitigation |
|---|---|---|---|
| Captive mini-browser with isolated/non-persistent storage | High | Medium | "Open in full browser" banner; documented flow; tests in both contexts (§1.4) |
| Malicious node links `dest_hint`↔alias via the directory | Medium | Medium | Documented as accepted risk; roadmap: rotating hints in Phase 2 (§1.2) |
| Identity loss on browser data wipe | Medium | High | Manual seed backup/import (task 2.4) |
| Inconsistent `X25519`/`Ed25519` in mobile WebCrypto | High | High | Embedded tweetnacl, single code path (§1.3) |
| NetworkManager (Bookworm) breaks hostapd/dnsmasq | High | High | `provision.sh` detects and disables it (§1.6) |
| User enters by IP and fragments their origin | Medium | Medium | Canonical-host middleware (§1.1) |
| LoRa envelope > 222 B in Phase 3 | Certain | Low (future) | bitchat fragmentation decided and documented (§1.5) |
| SD corruption/wear from WAL | Low | Medium | WAL + `MaxOpenConns(1)`; optional volatile journal; industrial-grade SD |
| Node filling by abuse (open AP) | Medium | Medium | Per-request limits, TTL max 30 days, 15 min cleaner, per-node envelope cap (hardening 4.6) |

---

## 8. Acceptance criteria traceability

| Master-prompt criterion | Covered by |
|---|---|
| `/etc/hostapd/hostapd.conf` (open AP, channel 6, `ap_isolate=1`) | 3.1 |
| `/etc/dnsmasq.conf` (DHCP 50–250, GW/DNS 10.42.0.1, wildcards) | 3.2 |
| `iptables` (80→8080, `/generate_204`, `/hotspot-detect.html`) | 3.3 + 1.3 (captive endpoints in Go) |
| Power optimization (HDMI, LEDs, solar/LiFePO4) | 3.4 |
| SQLite: exact tables, columns and indexes | 1.2, 3.2(spec §3.2) |
| Exact API endpoints (`GET /`, captive, directory GET/POST, sync) | 1.3, 1.5, 1.6 |
| 15-minute cleanup worker | 1.4 |
| `embed.FS` with a single `index.html` | 1.5 |
| X25519+Ed25519 client-side, server without keys | 2.2–2.5 |
| `dtn_local_store`: identity / inbox / transit_queue (50–100) | 2.3, 2.6 |
| Sync on page load + own/foreign classification | 2.6 |
| UI: registration, directory, composer, inbox, mule telemetry | 2.7 |
| bitchat L2CAP mapping (`hop_count ≤ 7`) and LoRa CBOR ≤ 222 B | 0.2, 1.1, 4.4 |
| Complete code without `// TODO` placeholders | Definition of Done per task |
| Step-by-step build/run/test instructions | 4.5 (`docs/BUILD.md`) |

**Definition of Done (each task):** final code without TODOs, associated tests green, reviewed with `gofmt`/`go vet` (Go) and tested in the target browser (JS).

---

## 9. Estimation and execution order

| Sprint | Content | Duration | Dependency |
|---|---|---|---|
| 0 | Protocol + scaffolding | 0.5 d | — |
| 1 | Go backend (Module B) | 1.5 d | 0 |
| 2 | SPA + crypto (Module C) | 2 d | 1 |
| 3 | Pi infrastructure (Module A) | 1 d | 1 (binary) |
| 4 | E2E integration + docs (Module D) | 1.5 d | 2, 3 |
| **Total** | | **6.5 d** | |

Sprints 2 and 3 can overlap (3 only needs 1's binary). Without hardware available, 3 is delivered with provisioning verified on a Raspberry Pi OS Bookworm Lite image in a VM/SD and the physical test remains a checklist ready to execute.

---

## 10. Out of scope (pointer to Phases 2/3)

- **Phase 2 (BLE):** Capacitor/Ionic app with an L2CAP CoC channel, `hop_count`, phone-to-phone gossip mesh without a node.
- **Phase 3 (LoRa):** SX1262 915 MHz bridge, CBOR, fragmentation, autonomous solar repeater.
- Rotating hints (hardened privacy), encryption ratchet, PWA/service worker, i18n, identity QR.
- All of the above already has design anchors in `docs/protocol.md` (Module D) so the Envelope never needs a rewrite.
