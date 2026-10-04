# Envelope Protocol Specification — Off-Grid DTN Messaging System

| | |
|---|---|
| **Document source** | `DEVELOPMENT_PLAN.md` (§1.1, §1.2, §1.3, §1.5, §1.7, §3) and `MASTER_DEVELOPMENT_PROMPT.md` |
| **Version** | 1.1.1 |
| **Date** | 2026-10-03 |
| **Status** | **Normative — BINDING** for all Phase 1 implementations (Modules B and C) |
| **Normative status** | **Open questions: none.** This document is self-contained: an implementer of the node daemon (Module B) or the SPA/crypto engine (Module C) needs no further decisions to produce a conforming implementation. |
| **Scope** | Envelope format, inner payload, canonical serialization, key derivations, cryptographic primitives, binding limits, node SQLite schema, node HTTP API, client (mule) behavior, same-origin policy, threat model, and the Phase 2/3 (BLE / LoRa) evolution mapping. |

The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are to be interpreted as described in RFC 2119 and RFC 8174.

---

## 1. Scope and design principles

This specification defines the wire format and behavior of an asynchronous, end-to-end encrypted (E2EE) messaging system that operates with no Internet, no cellular network and no satellites. Fixed Wi-Fi "dead-drop" nodes (Raspberry Pi Zero 2 W, open access point + captive portal) store opaque encrypted envelopes in SQLite; users' mobile browsers act as **data mules**, carrying envelopes in `IndexedDB` from node to node.

Binding design principles:

1. **Zero-trust intermediaries.** Nodes and mules are blind, untrusted channels. They MUST NOT be able to read message content, learn the sender's identity, or learn the recipient's full identity.
2. **All cryptography is client-side.** The server never holds private keys, never decrypts, never verifies signatures.
3. **Same-origin across all nodes.** Every node serves the identical web origin `http://portal.red.local:8080` at gateway IP `10.42.0.1`, so a mule's `IndexedDB` storage never fragments (§12).
4. **Evolution without rewrite.** The envelope is designed so the same semantic fields map onto BLE L2CAP CoC (Phase 2) and LoRa P2P SX1262 at 915 MHz (Phase 3) without changing the data structure (§14).

## 2. System model and vocabulary

| Term | Definition |
|---|---|
| **Node** | Raspberry Pi Zero 2 W running the Go daemon (`dtn-node`): open Wi-Fi AP + captive portal + blind SQLite dead-drop. |
| **Mule** | A user's mobile browser. On each portal it pushes the envelopes it carries and pulls new ones into its `transit_queue`. |
| **Envelope** | The atomic unit of transport. One encrypted message plus routing metadata. Immutable once created. |
| **Sender / recipient** | Two registered users. Each identity consists of an Ed25519 key pair (identity/signature), an X25519 key pair (encryption) and an alias. |
| **Directory** | Public per-node list of registered identities: alias, Ed25519 public key, X25519 public key, `last_seen`. |
| **`transit_queue`** | Mule-side `IndexedDB` store of foreign envelopes being carried. Capacity 100, FIFO eviction by `created_at`. |

Envelope lifecycle: sender constructs → pushes to node A → any mule pulls it from node A → carries it → pushes to node B → recipient pulls it from node B, recognizes its own `dest_hint`, decrypts and verifies. **Nodes never talk to each other**; all transport between nodes is physical (mules walking).

## 3. Envelope format (Phase 1, JSON)

### 3.1 Fields

The envelope travels as a single JSON object with **exactly** these fields:

| Field | Type | Binding constraint |
|---|---|---|
| `v` | integer | MUST be `1` (format version). |
| `id` | string | 64 lowercase hex characters, `^[0-9a-f]{64}$`. SHA-256 of the canonical envelope subset (§6.2). Computed by the client. |
| `dest_hint` | string | 16 lowercase hex characters, `^[0-9a-f]{16}$`. First 8 bytes of `SHA-256(recipient X25519 public key)` (§6.1). |
| `created_at` | integer | Unix seconds (UTC). MUST be `> 0` and MUST NOT be more than 300 s in the future at ingestion time. |
| `ttl` | integer | Time-to-live in seconds. MUST be within `[3600, 2592000]` (1 hour to 30 days). Default 604800 (7 days). |
| `payload` | string | Base64 (RFC 4648 standard alphabet, **with padding**). Decoded bytes: `eph_pub(32) ‖ nonce(24) ‖ box(...)`. Decoded length MUST be within `[248, 400]` bytes (derived in §8.2). |

`box` is the tweetnacl `crypto_box` output: `XSalsa20-Poly1305` ciphertext of the inner payload **with the 16-byte Poly1305 MAC appended** (tweetnacl convention). The MAC is inside `box`, not a separate field.

### 3.2 Example

A concrete, valid envelope (used as the test vector in §6.2; the payload bytes are synthetic deterministic bytes):

```json
{
  "v": 1,
  "id": "d375c17f54525e1816e5f2c01da100e17176c38fd016ea07acb5d3077eb6444f",
  "dest_hint": "9f3ab02c1d77e4c1",
  "created_at": 1759500000,
  "ttl": 604800,
  "payload": "f46MqdLy8TaHj3lnjcYvHnOuAU8lrXD/nDHUzwGAW/5rQERh00/2ez0ZkfsZz6yc2FpGq2ukrJYxb/P0OQPt6vbAt4I3TKcA21aBVxCxjX4ZZZA23cub/SQusRHDZzjPDmI3HQj6ZpTbEntNfCKagXtQY/MCjvusFuP24DZVGxRhZ0K6l1KKsV0fZ5MOgg+QfFheegNat7plIFMf1Y0TuQrii+JffAfgGh1vAWRr3OvAxWyRbH04Ofw/UBrKZLdevwAcCUcn7mgYcCrXZvSFlHavFH84Pyk2egL0mnPXubm9iMVQOraXcklUzgYVbGlme8w+0yZrDNE="
}
```

### 3.3 Encoding rules (binding)

- **Base64**: RFC 4648 standard alphabet (`+`, `/`), **with** `=` padding — the Go-`encoding/json` and tweetnacl-helper convention. Base64url is invalid.
- **Hex**: lowercase only.
- **Numbers**: JSON integers only. No floats, no exponents, no string-wrapped numbers.
- **Character encoding**: all JSON is UTF-8.

## 4. Inner payload (`inner_json`) and sign-then-encrypt

### 4.1 Schema

The decrypted `box` contains the UTF-8 bytes of `inner_json`, a JSON object with exactly these fields:

| Field | Type | Binding constraint |
|---|---|---|
| `m` | string | The message text. **≤ 128 bytes when encoded as UTF-8** (byte length, not character count — the UI shows a byte counter). |
| `a` | string | Sender alias. MUST match `^[A-Za-z0-9_.-]{1,24}$`. |
| `k` | string | Sender **Ed25519 public key**, Base64 (32 raw bytes → 44 characters). |
| `s` | string | **Ed25519 detached signature**, Base64 (64 raw bytes → 88 characters), over the signed byte string defined in §5.2. |
| `t` | integer | Unix seconds (UTC), sender-authored timestamp used for inbox display ordering. Clients SHOULD set `t = created_at`. |

```json
{"m": "Hola Bob", "a": "alice_77", "k": "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=", "s": "<88-char Base64 Ed25519 signature>", "t": 1759500001}
```

### 4.2 Order of operations — SIGN-THEN-ENCRYPT (binding)

The cryptographic order is **sign-then-encrypt**: the signature and the alias are **inside the ciphertext**.

1. Sender builds `inner_json` with fields `m`, `a`, `k`, `t` (`k` = its Ed25519 public key).
2. Sender serializes the **signed byte string** (§5.2) and signs it with its Ed25519 private key → `s`.
3. Sender adds the `s` field to `inner_json` and serializes the complete object to UTF-8 bytes.
4. Sender generates a fresh **ephemeral X25519 key pair** (`eph_pub`, `eph_sec`) — one per message.
5. Sender computes `box = crypto_box(inner_bytes, nonce, recipient_X25519_pub, eph_sec)` with a fresh 24-byte random `nonce`.
6. Sender sets `payload = Base64(eph_pub ‖ nonce ‖ box)`, derives `dest_hint` (§6.1) and `id` (§6.2).

Consequences (binding):

- Nodes and mules see only random bytes in `payload`; the sender's alias, key and signature are hidden.
- A node cannot modify `inner_json` without failing the Poly1305 MAC, and cannot forge a signature.
- Only the holder of the recipient X25519 private key can decrypt.

### 4.3 Recipient procedure

1. Compare `dest_hint` with the recipient's own hint: `hex(SHA-256(own X25519 public key)[0:8])`. If different, do not attempt decryption (mule stores the envelope instead).
2. Split `payload` into `eph_pub(32)`, `nonce(24)`, `box(rest)`.
3. `inner_bytes = crypto_box.open(box, nonce, eph_pub, own_X25519_secret)`. Any failure → **discard silently** (never surface errors that could leak information).
4. Parse `inner_json`; validate `m` ≤ 128 bytes, `a` matches the alias regex, `k`/`s` are valid Base64 lengths (44/88 chars).
5. Rebuild the signed byte string from `m`, `a`, `k`, `t` and verify `s` with `k` (Ed25519). Failure → discard silently.
6. Optionally reject as corrupt if `t` is more than 300 s in the future.
7. Store `(m, a, t)` in the inbox. The alias may be cross-checked against the directory entry for `k`.

## 5. Canonical serialization (binding)

All hashing and signing operate on **canonical JSON**: UTF-8, no BOM, no insignificant whitespace, integers in minimal decimal form (no leading zeros, no `+` sign, no fractions), no trailing newline. String escaping is minimal: `\"`, `\\`, and control characters U+0000–U+001F (short escapes `\b \f \n \r \t` where applicable, otherwise `\u00xx` with lowercase hex digits). The solidus `/` MUST NOT be escaped, and non-ASCII characters MUST be emitted as raw UTF-8 bytes (never `\uXXXX` surrogates).

**Member order is the fixed order given in this specification — it is NOT lexicographic.** This is deliberate and load-bearing:

> **Implementation warning.** Go's `encoding/json` marshals maps with sorted keys; Python's `json.dumps(sort_keys=True)` sorts alphabetically. Both produce the WRONG byte string. Serialize from a fixed-order structure (e.g., a Go struct with fields declared in the order below, or a hand-built string / ordered sequence).

### 5.1 Signed byte string (for the Ed25519 signature)

The signature covers the canonical JSON of `inner_json` **with the `s` member removed before serialization** (not set to null), keys in fixed order `m`, `a`, `k`, `t`:

```
{"m":<m>,"a":<a>,"k":<k>,"t":<t>}
```

The verifier reconstructs this exact byte string from the decrypted fields. Example (from §4.1, exact and complete):

```
{"m":"Hola Bob","a":"alice_77","k":"11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=","t":1759500001}
```

### 5.2 Hashed byte string (for the envelope `id`)

The `id` covers the canonical JSON of the envelope subset, keys in fixed order `v`, `dest_hint`, `created_at`, `ttl`, `payload` (the `id` field itself is excluded):

```
{"v":1,"dest_hint":"<dest_hint>","created_at":<created_at>,"ttl":<ttl>,"payload":"<payload>"}
```

Note the order is *not* alphabetical (`created_at` < `dest_hint` lexicographically); serializers that sort keys are non-conforming.

## 6. Key derivations

### 6.1 `dest_hint`

```
dest_hint = lowercase_hex( SHA-256( recipient X25519 public key, raw 32 bytes )[0:8] )
```

Exactly the **first 8 bytes** of the SHA-256 digest, encoded as 16 lowercase hex characters. Purpose: (a) the recipient/mule identifies its own envelopes without decrypting; (b) the node can store and serve envelopes blindly (`WHERE dest_hint = ?`); (c) dedup and cleanup on the node.

**Test vector 1** — X25519 public key of RFC 7748 §6.1 ("Alice"):

| Item | Value |
|---|---|
| X25519 public key (raw 32 B, hex) | `8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a` |
| SHA-256 (full digest) | `300c9c9603b92a4b39ed3958bf9240114804db4fd373012c0ca47432d63425ae` |
| `dest_hint` (first 8 bytes) | `300c9c9603b92a4b` |

### 6.2 Envelope `id`

```
id = lowercase_hex( SHA-256( hashed byte string of §5.2 ) )   → 64 hex chars
```

The **client** computes `id`. The **server treats `id` as an opaque deduplication key**: it performs `INSERT OR IGNORE` on it and MUST NOT reject an envelope whose `id` does not match a recomputed hash (recomputation as extra hardening is permitted but MUST NOT be required for interop).

**Test vector 2** — envelope of §3.2:

| Item | Value |
|---|---|
| Hashed byte string (§5.2, UTF-8) | `{"v":1,"dest_hint":"9f3ab02c1d77e4c1","created_at":1759500000,"ttl":604800,"payload":"f46MqdLy8TaHj3lnjcYvHnOuAU8lrXD/nDHUzwGAW/5rQERh00/2ez0ZkfsZz6yc2FpGq2ukrJYxb/P0OQPt6vbAt4I3TKcA21aBVxCxjX4ZZZA23cub/SQusRHDZzjPDmI3HQj6ZpTbEntNfCKagXtQY/MCjvusFuP24DZVGxRhZ0K6l1KKsV0fZ5MOgg+QfFheegNat7plIFMf1Y0TuQrii+JffAfgGh1vAWRr3OvAxWyRbH04Ofw/UBrKZLdevwAcCUcn7mgYcCrXZvSFlHavFH84Pyk2egL0mnPXubm9iMVQOraXcklUzgYVbGlme8w+0yZrDNE="}` (420 bytes) |
| `id` | `d375c17f54525e1816e5f2c01da100e17176c38fd016ea07acb5d3077eb6444f` |

## 7. Cryptographic primitives

### 7.1 Primitives

| Purpose | Primitive | tweetnacl API |
|---|---|---|
| Confidentiality | X25519 ECDH + XSalsa20-Poly1305 AEAD | `nacl.box` / `nacl.box.open` |
| Ephemeral key pair (one per message) | X25519 | `nacl.box.keyPair()` |
| Identity / signature | Ed25519 | `nacl.sign.keyPair()`, `nacl.sign.detached`, `nacl.sign.detached.verify` |
| Hash derivations (`id`, `dest_hint`) | SHA-256 | any constant-time-independent SHA-256 (WebCrypto `digest` is acceptable for hashing only) |

**Binding decision (Phase 1): tweetnacl.js is embedded inline in `index.html`** (~25 KB minified), as the single crypto code path. Native `crypto.subtle` is NOT used for X25519/Ed25519 because its availability and behavior are irregular in mobile browsers and worse in captive-portal mini-browsers (Android Captive Portal WebView, iOS CNA). There are no external assets, CDNs, or `eval`.

### 7.2 Entropy

All key generation and all nonces draw entropy exclusively from `crypto.getRandomValues` (available in all modern WebViews, including captive ones). Deterministic/reused nonces MUST NOT be used: `nonce` is 24 uniformly random bytes per message.

### 7.3 Key hygiene

- The ephemeral secret `eph_sec` is used once and discarded after encryption; only `eph_pub` travels.
- Recipient X25519 and Ed25519 private keys never leave the client (`IndexedDB`); only public keys are published to the directory.
- Long-term identity backup is a manual, user-triggered export/import of the secret seed (UI requirement, §11).

## 8. Binding limits

### 8.1 Limits table (normative)

| Parameter | Value | Notes |
|---|---|---|
| Plaintext message `m` | ≤ 128 bytes (UTF-8) | Byte counter visible in the UI. |
| Sender alias `a` | `^[A-Za-z0-9_.-]{1,24}$` | Enforced on client and server. |
| TTL default | 604800 s (7 days) | |
| TTL range | [3600, 2592000] s | min 1 hour, max 30 days. |
| Mule `transit_queue` capacity | 100 envelopes | FIFO eviction by `created_at` (oldest evicted first). |
| Sync `limit` | default 50, max 200 | Absent → 50; present outside 1..200 → 400. |
| Push envelopes per sync | ≤ 100 | More → 400. |
| Sync request body | ≤ 1 MiB (1,048,576 bytes) | Larger → 413. |
| `known_ids` per sync | ≤ 500 entries | More → 400. |
| **Per-node envelope cap** | **5000 envelopes** | Anti-abuse storage guard (plan §7, "Llenado del nodo por abuso"): at or over the cap every push is rejected with `429 {"status":"error","error":"node_full"}` and nothing is stored (fail closed, §10.4). Pulls keep working on a full node. A batch accepted just below the cap may overshoot it by at most one request's worth of envelopes (≤ 100). |
| Directory GET | ≤ 500 entries | 500 most recent by `last_seen DESC`. |
| Cleanup worker interval | 15 minutes | Plus one run at daemon startup. |

### 8.2 Derived payload size bounds (normative)

From the limits above, for 10-digit timestamps:

```
inner_json = 176 + M + A bytes          (M = |m|, A = |a|; fixed part: keys, k=44, s=88, t=10)
box        = inner_json + 16            (Poly1305 MAC)
payload    = 32 (eph_pub) + 24 (nonce) + box = 248 + M + A bytes   → [248, 400]
```

Worked sizes:

| Message | `inner_json` | `payload` (raw) | `payload` (Base64) | Envelope JSON (chars) |
|---|---|---|---|---|
| `m=0`, `a=0` (floor) | 176 B | 248 B | 332 | ~492 |
| `m=128`, `a=24` (max) | 328 B | 400 B | 536 | ~696 |

The master prompt's ~180–250 B payload target is met at the floor (248 B ≤ 256 B logical budget); a full 128-byte message with signature and alias inside exceeds it on purpose — that case is exactly what the Phase 3 fragmentation scheme handles (§14.3). On Wi-Fi (Phase 1) the JSON/Base64 inflation is irrelevant.

Server-side envelope validation MUST enforce: `payload` decodes from Base64 and its decoded length is within `[248, 400]` bytes. The server cannot inspect `inner_json` (encrypted) and MUST NOT try.

## 9. Node storage (SQLite)

Database file: `node_storage.db`. Schema is exactly:

```sql
CREATE TABLE envelopes (
  id        TEXT PRIMARY KEY,      -- envelope id, 64 lowercase hex chars (client-computed)
  dest_hint TEXT NOT NULL,         -- 16 lowercase hex chars
  created_at INTEGER NOT NULL,     -- unix seconds
  ttl       INTEGER NOT NULL,      -- seconds
  payload   TEXT NOT NULL          -- Base64( eph_pub || nonce || box )
);
CREATE INDEX idx_envelopes_dest_hint ON envelopes(dest_hint);
CREATE INDEX idx_envelopes_expiry    ON envelopes(created_at, ttl);

CREATE TABLE directory (
  pubkey    TEXT PRIMARY KEY,      -- ed25519 public key, Base64 (identity)
  x25519    TEXT NOT NULL,         -- X25519 public key, Base64 (encryption)
  alias     TEXT NOT NULL,
  last_seen INTEGER NOT NULL       -- unix seconds, set by the node on upsert
);
```

Pragmas and connection policy (binding):

- `PRAGMA journal_mode = WAL;` — survives power loss on solar-powered nodes; readers do not block the writer.
- `PRAGMA busy_timeout = 5000;` — milliseconds.
- **Single connection** (`SetMaxOpenConns(1)`): serializes all access; trivial load for a Zero 2 W; avoids SQLite write contention entirely.

`directory` rows are never auto-deleted in Phase 1; the 500-entry cap is applied at query time (§10.3).

## 10. Node HTTP API

### 10.1 Conventions

- Listen address defaults to `:8080`. All API request/response bodies are `application/json; charset=utf-8` (the HTML endpoint is `text/html; charset=utf-8`).
- Requests with a body MUST declare `Content-Type: application/json`, otherwise `400`.
- Body size limit for POST endpoints: 1 MiB → `413` if exceeded.
- Error responses use HTTP status codes `400` (malformed/invalid), `404` (unknown path), `405` (wrong method), `413` (body too large), `429` (node envelope cap reached, §8.1) with JSON body `{"status":"error","error":"<short_code>"}`.
- Unknown paths → `404`. There is no SPA fallback: only `GET /` serves `index.html`.

### 10.2 Canonical-host middleware

All requests whose `Host` header is not exactly `portal.red.local:8080` (case-insensitive) MUST receive:

```
301 Moved Permanently
Location: http://portal.red.local:8080{original path and query}
```

This covers direct IP access (`10.42.0.1:8080`), any spoofed domain resolved by the wildcard DNS, and bare `portal.red.local` without port. The browser always ends on the canonical origin, so `IndexedDB` never fragments.

**Mandatory exemption:** `GET /generate_204` and `GET /hotspot-detect.html` respond `302` with `Location: http://portal.red.local:8080/` **regardless of the Host header** (they arrive with Hosts like `connectivitycheck.gstatic.com`, `captive.apple.com`) and MUST NOT be redirected to the canonical host first — the OS captive-portal probe would otherwise fail to detect the portal. These endpoints MUST NOT answer `204`.

### 10.3 Endpoints (exact surface)

| Method + path | Behavior |
|---|---|
| `GET /` | Serve the embedded `index.html` (`embed.FS`). Non-canonical Host → `301` first (§10.2). |
| `GET /generate_204` | `302 → http://portal.red.local:8080/` (Android probe). Never `204`. |
| `GET /hotspot-detect.html` | `302 → http://portal.red.local:8080/` (iOS probe). |
| `GET /api/v1/directory` | `200` with a JSON array of at most 500 objects `{"alias","pubkey","x25519","last_seen"}`, ordered by `last_seen DESC` (deterministic tie-break: `pubkey ASC`). |
| `POST /api/v1/directory` | Body `{"alias","pubkey","x25519"}`. Validate alias regex and that both keys are Base64 decoding to exactly 32 bytes. Upsert keyed by `pubkey`; set `last_seen = now`. → `200 {"status":"ok"}`. Invalid → `400`. |
| `POST /api/v1/sync` | See §10.4. |

### 10.4 `POST /api/v1/sync` (exact behavior)

Request:

```json
{
  "known_ids": ["<64-hex>", ...],        // ≤ 500; each ^[0-9a-f]{64}$; duplicates harmless
  "push_envelopes": [ {envelope}, ... ], // ≤ 100; each fully valid per §10.5
  "limit": 50                             // optional; default 50; must be 1..200
}
```

Processing (in order):

1. Validate the request (limits above; any violation → `400`, the whole request is rejected — fail closed).
2. For each pushed envelope: `INSERT INTO envelopes (...) VALUES (...) ON CONFLICT(id) DO NOTHING` (`INSERT OR IGNORE`). Duplicates are silently ignored — this is the global dedup mechanism across nodes.
3. Select pull candidates:

```sql
SELECT id, dest_hint, created_at, ttl, payload FROM envelopes
WHERE created_at + ttl >= ?now
  AND id NOT IN (known_ids)
ORDER BY created_at DESC, id ASC
LIMIT ?limit;
```

4. Respond `200`:

```json
{"status": "ok", "pull_envelopes": [ {envelope}, ... ]}
```

The expiry boundary is **inclusive on the serving side** (`created_at + ttl >= now` is servable) and **exclusive on the cleanup side** (§10.6), so an envelope is either servable or deleted, never in limbo.

Clients MUST include the ids of envelopes they push in their `known_ids` so they do not re-pull their own pushes (§11).

### 10.5 Server-side envelope validation (push path)

The server MUST check, per envelope: `v == 1`; `id` matches `^[0-9a-f]{64}$`; `dest_hint` matches `^[0-9a-f]{16}$`; `created_at` is an integer `> 0` and `<= now + 300`; `ttl` is an integer within `[3600, 2592000]`; `payload` is valid padded Base64 with decoded length in `[248, 400]`. The server MUST NOT attempt decryption, MUST NOT verify signatures, and MUST NOT require `id` correctness (§6.2).

### 10.6 Cleanup worker

A goroutine with `time.Ticker` runs **every 15 minutes**, plus **once at daemon startup**:

```sql
DELETE FROM envelopes WHERE created_at + ttl < now;
```

## 11. Client (mule) behavior — Module C normative summary

- **Registration (once):** alias input (validated client-side against the alias regex) → generate Ed25519 + X25519 key pairs → publish `{"alias","pubkey","x25519"}` to `POST /api/v1/directory`. Private keys stay in `IndexedDB` (`identity` store). Manual seed backup (copyable text) and import MUST be offered to survive browser data wipes.
- **Composition:** recipient picked from the directory; text area with a visible **128-byte UTF-8 counter**; send builds the envelope exactly per §4.2/§5/§6.
- **Sync:** automatic on page load plus a manual button. Push the whole `transit_queue` and `known_ids` (union of inbox ids ∪ transit ids ∪ previously seen/dismissed ids ∪ ids just pushed), with `limit` = 50. Classify `pull_envelopes`:
  - `dest_hint == own hint` → attempt decrypt + verify (§4.3); success → `inbox`; failure → discard silently.
  - otherwise → `transit_queue`; if it would exceed **100** envelopes, evict oldest by `created_at` (FIFO).
- **UI (mandatory):** registration screen, directory recipient selector, composer with byte counter, inbox with sender alias and time, mule telemetry panel ("Foreign envelopes in transit: X / Capacity: 100") and last-sync status, and the captive-browser banner: "Open this in your full browser: `http://portal.red.local:8080`" (visible, copyable URL) — see §13.4.
- **Storage:** `IndexedDB` database `dtn_local_store` v1 with stores `identity` (singleton), `inbox`, `transit_queue`; schema migrations by version number.

## 12. Same-origin policy and the deliberate absence of TLS

`IndexedDB` is isolated per web origin (scheme + host + port). For a mule to keep its identity, inbox and transit queue while moving between nodes, **all nodes must be indistinguishable in origin**: same FQDN `portal.red.local`, same port `8080`, same gateway IP `10.42.0.1`. Binding consequences:

1. `dnsmasq` on every node answers `address=/#/10.42.0.1` and `address=/portal.red.local/10.42.0.1` (wildcard DNS).
2. The canonical-host middleware (§10.2) forces every request onto `http://portal.red.local:8080`.
3. Users who bookmark the raw IP would fragment their own origin; the middleware corrects this automatically and the UI always displays the canonical URL.

**TLS is intentionally absent.** No valid certificate can exist for `portal.red.local` when every node uses the same IP, and offline PKI would require client-side installation. HTTP plaintext is acceptable **only because** content is E2EE at the application layer: the node is a hostile blind channel that never sees plaintext, keys, the sender's identity, or the recipient's full identity. TLS would add a false sense of security without protecting anything application-layer crypto does not already protect. (Threat analysis: §13.)

## 13. Threat model

### 13.1 Trust model

Zero-trust intermediaries: **nodes and mules are blind, untrusted channels.** The only trusted endpoints are the sender's and recipient's own browsers (their private keys never leave them).

### 13.2 What each party can and cannot see

| Party | Can see | Cannot see |
|---|---|---|
| **Node** | `v`, `id`, `dest_hint`, `created_at`, `ttl`, opaque `payload`, source IP, timing/volume metadata, full directory (aliases + public keys) | Message content; sender alias and Ed25519 key (inside ciphertext); recipient identity beyond the 8-byte hint; cannot alter envelopes (Poly1305 MAC); cannot forge signatures |
| **Mule** | Same envelope metadata as the node; can identify **its own** envelopes by comparing `dest_hint` with its own hint | Content of foreign envelopes; who else is a mule for the same envelope |
| **Network observer (open Wi-Fi)** | Same metadata as the node (plaintext HTTP) | Anything inside `payload` |
| **Recipient** | Everything, after decryption + signature verification | — |

The sender is anonymous to nodes and mules because the Ed25519 signature and alias travel **inside** the ciphertext (sign-then-encrypt, §4.2).

### 13.3 Documented limitation: `dest_hint` linkability — ACCEPTED RISK (Phase 1)

Because the same node serves the **public directory** (aliases + public keys), a malicious node operator **can recompute every registered user's `dest_hint`** (`first 8 bytes of SHA-256(X25519 pubkey)`) and thereby link stored/served envelopes to aliases, and observe who picks up whom.

This is an explicitly **ACCEPTED RISK for Phase 1**: node operators are assumed *passive-curious* (they may look), not *active adversaries* (they do not attack users). Hiding this limitation would be an engineering error; it is documented here as the normative record.

**Phase 2 roadmap mitigation (design anchor, non-normative in Phase 1):** rotating hints — `hint_epoch = first 8 bytes of HKDF-SHA256(ikm = X25519 public key, salt = epoch_number, info = "offgrid-dest-hint")`. Senders embed the hint for the current epoch; nodes accept a bounded window of epochs; hint↔alias linkability then decays with epoch rotation. This changes only the hint derivation, not the envelope structure (§14.1).

### 13.4 Captive-portal mini-browser storage isolation (risk + mitigation)

When Android/iOS detect the captive portal they open a **restricted mini-browser** whose storage profile is isolated from — and often ephemeral compared to — the device's real browser. A user who only ever uses the mini-browser may lose identity/inbox data between sessions or nodes.

**Mandatory mitigation (UI):** a context-detection banner instructing: "Open this in your full browser: `http://portal.red.local:8080`" with a visible, copyable URL. The recommended user flow is: join Wi-Fi → open the URL in Chrome/Safari. Acceptance testing (Sprint 4) covers both contexts explicitly.

### 13.5 Residual risks (documented, accepted for Phase 1)

- **Replay:** a node can re-serve an old (unexpired) envelope to a mule. Harmless: mules and recipients dedup by `id`, and the MAC prevents modification.
- **Traffic analysis:** timing and volume correlation by nodes (per-alias linkability is §13.3). Accepted.
- **Directory spam / flooding:** the open AP allows anonymous directory writes; mitigated by the 500-entry GET cap, alias sanitization, per-request limits (§8.1), the 15-minute cleanup and TTL caps; further hardening in Sprint 4.
- **Identity loss:** browser data wipe destroys the identity unless the seed was backed up (§11).

## 14. Phase 2/3 evolution mapping (Module D)

### 14.1 Stability rules (what never changes)

1. **Semantic fields are frozen:** `v`, `id`, `dest_hint`, `created_at`, `ttl`, `payload` (+ reserved `hop_count`), and inner `m`, `a`, `k`, `s`, `t`. No field is ever repurposed.
2. **Sign-then-encrypt is invariant:** the signature and alias always travel inside the ciphertext on every transport.
3. **Encodings are transport-tier:** Phase 1 JSON uses hex/Base64 *text*; binary phases (Phase 2/3) use *raw bytes* in CBOR. Conversions are lossless decodings of the text forms.
4. **`hop_count` is a reserved field:** semantics = times the envelope has been relayed peer-to-peer, `0..7`; a relay drops envelopes at 7. In Phase 1 JSON the field is always **absent** (absent = 0). It never appears in Phase 1 code paths.
5. **`dest_hint` derivation is stable** through Phase 3; the rotating-hint scheme (§13.3) is a Phase 2 privacy upgrade that only swaps the derivation function.

### 14.2 Phase 2 — BLE L2CAP CoC (bitchat alignment)

Transport: Bluetooth LE Credit-Based Flow Control via a **Connection-Oriented Channel (L2CAP CoC)** opened by the Capacitor/Ionic app. Design anchors:

- One dedicated CoC per peer connection over a fixed dynamic PSM (value selected and advertised out-of-band at Phase 2 implementation time).
- **Frame layout:** `length(2 bytes, big-endian) ‖ CBOR envelope`. The L2CAP layer performs segmentation/reassembly; one envelope is one SDU.
- Negotiated MTU ≥ 512 B (typical) → the maximum binary envelope (399 B, §14.3) plus the 2-byte length prefix fits in a single SDU.
- **JSON → CBOR field table** (canonical CBOR per RFC 8949 preferred serialization: definite lengths, minimal-length headers, integer map keys in ascending order):

| CBOR key | JSON field | CBOR type | Notes |
|---|---|---|---|
| 0 | `v` | uint | constant 1 |
| 1 | `id` | bstr (32 B) | raw SHA-256 bytes (the hex string decoded) |
| 2 | `dest_hint` | bstr (8 B) | raw 8 bytes (the hex string decoded) |
| 3 | `created_at` | uint | unix seconds |
| 4 | `ttl` | uint | seconds |
| 5 | `payload` | bstr | `eph_pub ‖ nonce ‖ box` (the Base64 decoded) |
| 6 | `hop_count` | uint (0–7) | **optional**; absent = 0; incremented by each relaying peer; dropped at 7 |

- **Inner payload (Phase 2/3):** canonical CBOR map with integer keys `0=m` (tstr), `1=a` (tstr), `2=k` (bstr 32), `3=s` (bstr 64), `4=t` (uint). The Phase 2/3 signature is Ed25519 over the canonical CBOR of this map **without key 3** — the exact analogue of §5.1. The switch from canonical-JSON inner (Phases 1) to canonical-CBOR inner (Phases 2/3) is required by the LoRa byte budget below and is defined now so Phase 2 and Phase 3 share one binary format.
- **Mesh behavior:** phones gossip envelopes peer-to-peer without a node, using `hop_count` for loop/dup control and `id` for dedup.

### 14.3 Phase 3 — LoRa P2P SX1262 at 915 MHz (CBOR, 222-byte MTU)

Radio frames carry at most **222 bytes** of payload. The binary envelope is the Phase 2 CBOR map (§14.2). Exact size math, with `M = |m|`, `A = |a|` and `h(n) = 0` if `n < 24` else `1` (extra CBOR header byte for lengths ≥ 24):

```
inner_cbor  = 1 (map hdr) + (1 + h(M) + M) + (1 + h(A) + A) + 35 (k) + 67 (s) + 6 (t)
            = 111 + M + A + h(M) + h(A)
box         = inner_cbor + 16                          (Poly1305 MAC)
L (payload) = 32 (eph) + 24 (nonce) + box = 72 + inner_cbor
envelope    = 59  + (2 if L ≤ 255 else 3) + L
              └ map hdr(1) + keys(6) + v(1) + id(34) + hint(9) + ts(5) + ttl(3)
```

| Case | `inner_cbor` | `L` | Envelope (B) | Frames needed |
|---|---|---|---|---|
| `M=0`, `A=0` (floor) | 111 | 183 | **244** | 2 |
| `M=128`, `A=24` (max) | 265 | 337 | **399** | 2 |

A single radio frame (222 B) can never carry the general CBOR envelope (floor 244 B), so Phase 3 defines two modes:

**(a) Two-frame fragmentation — general mode.** The CBOR envelope is split into `total` fragments; each radio frame carries a **1-byte fragment header** followed by up to 221 bytes (222 − 1) of envelope bytes:

```
bit 7..4   bit 3..2   bit 1..0
win_id(4)  idx(2)     total(2)
```

- `win_id`: window tag (random per message) so concurrently received windows can be reassembled.
- `idx`: zero-based fragment index (0–3); `total`: fragment count (1–4). Reassembly = concatenate by `idx` order within `(win_id, total)`.
- Capacity: `2 × 221 = 442 B ≥ 399 B` → **every Phase 1-legal message fits 2 frames**; the format allows 3–4 frames for future growth.

**(b) Single frame — "short message" mode (`M ≤ 48`).** A compact binary frame with no CBOR map overhead, and without `id`, `dest_hint` or `alias`:

```
version(1) | mlen(1) | nonce(24) | eph_pub(32) | box( ts(4) ‖ k(32) ‖ s(64) ‖ m(M) ) + MAC(16)
```

Exact byte budget at the maximum short message:

| Component | Bytes |
|---|---|
| version | 1 |
| `mlen` | 1 |
| nonce | 24 |
| `eph_pub` | 32 |
| `ts` (uint32 unix seconds, big-endian) | 4 |
| `k` (sender Ed25519 public key, raw) | 32 |
| `s` (Ed25519 signature, raw) | 64 |
| `m` (UTF-8 message) | **48** |
| Poly1305 MAC | 16 |
| **Total** | **222 = MTU** ✓ |

So a short message fits one frame **iff `M ≤ 48`**; larger messages use general mode (a). Design notes (binding for Phase 3):

- `dest_hint` is omitted because radio delivery is broadcast: every receiver trial-decrypts (`crypto_box.open` fails for anyone but the recipient). The hint exists for the node's blind SQL SELECT (§6.1), which does not exist on a radio broadcast.
- `id` is omitted and recomputed as `SHA-256(frame bytes from `version` to the end)` for dedup.
- `alias` is omitted; receivers resolve the sender's alias from the directory via `k`. The signature covers `ts ‖ k ‖ m` (the exact analogue of §5.1 in binary form).
- Sign-then-encrypt is preserved: `k` and `s` remain inside the ciphertext.

### 14.4 Implementation anchors (where each mapping lives in the code)

Sprint 4 audit record: the Phase 2/3 mapping is mirrored in doc-comments at every place a developer will touch the envelope. This §14 remains the **normative source**; the code comments below are summaries and MUST NOT diverge from it — when they do, this section wins.

| Location (file + symbol) | What is anchored there |
|---|---|
| `node/internal/envelope/envelope.go` — doc comment on type `Envelope` | Complete mapping for the node implementation: frozen semantic field list, the JSON → CBOR field/type table, the L2CAP CoC frame layout (length prefix, one envelope = one SDU, MTU ≥ 512 B), `hop_count ≤ 7` reserved semantics (always 0/absent in Phase 1), the LoRa 222-byte budget with the 1-byte fragment header `win_id(4) \| idx(2) \| total(2)` and the short-message single-frame mode; references §14 as normative source. |
| `node/web/index.html` — comment block immediately above `buildEnvelope` (pure-engine section 5) | Same mapping mirrored on the client implementation that produces Phase 1 envelopes, so SPA-side changes stay aware of the frozen fields and the Phase 2/3 encodings. |
| `docs/protocol.md` §14.2 / §14.3 (this document) | Normative math the anchors summarize: CBOR size derivation, fragment capacity (`2 × 221 = 442 ≥ 399`), short-mode 222-byte table. |

## 15. Conformance checklist

**Module B (node daemon) MUST:** implement the schema and pragmas of §9; the six endpoints with the exact status codes, limits and redirect/exemption behavior of §10; envelope validation of §10.5; `INSERT OR IGNORE` dedup; the inclusive/exclusive expiry boundary of §10.4/§10.6; the 15-minute + startup cleanup; the canonical-host middleware with captive-probe exemption; no decryption, no signature verification, no `id` recomputation requirement.

**Module C (SPA) MUST:** embed tweetnacl.js inline and source all randomness from `crypto.getRandomValues` (§7); implement sign-then-encrypt with the canonical serializations of §5; derive `dest_hint` and `id` per §6; enforce every client-side limit of §8.1 (128-byte counter, alias regex, 100-envelope FIFO transit queue, known_ids composition including own pushes); implement the sync algorithm and silent-corruption handling of §11; display the canonical URL and the full-browser banner (§12, §13.4).

## Changelog

- **1.1.1 (2026-10-04, documentation migration):** documentation-only change — this file was renamed from `docs/protocolo.md` to `docs/protocol.md` and its source references updated to the renamed `DEVELOPMENT_PLAN.md` and `MASTER_DEVELOPMENT_PROMPT.md`, as part of the repository-wide English documentation migration (issue #6). No field, limit, endpoint behavior or other normative content changed.
- **1.1.0 (2026-10-03, Sprint 4):** added the per-node envelope cap of §8.1 (rejects pushes with `429 node_full` when the node holds 5000 envelopes), the corresponding `429` entry in §10.1, and the non-normative implementation-anchors table of §14.4. No existing field, limit or endpoint behavior changed; the `DEVELOPMENT_PLAN.md` §1.7 table intentionally stays untouched (its §7 already anticipates this cap as hardening 4.6).
- **1.0.0 (2026-10-03):** initial normative release.

---

*End of normative specification. Changes require a version bump of this document and a corresponding update to `DEVELOPMENT_PLAN.md` §1.7.*
