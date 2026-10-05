# Envelope Protocol Specification — Off-Grid DTN Messaging System

| | |
|---|---|
| **Document source** | `docs/DEVELOPMENT_PLAN.md` (§1.1, §1.2, §1.3, §1.5, §1.7, §3) and `docs/MASTER_DEVELOPMENT_PROMPT.md` |
| **Version** | 1.5.0 |
| **Date** | 2026-10-04 |
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
3. **Same-origin across all nodes.** Every node serves the identical web origin `http://offgrid.local:8080` at gateway IP `10.42.0.1`, so a mule's `IndexedDB` storage never fragments (§12).
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
| `v` | integer | MUST be `1` (format version; §15.1 defines version 2 and generalizes admission to a supported version set). |
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

The `m` limit binds **per envelope**. A longer text is never sent flat: the sending client splits it into several ordinary chunk envelopes that carry the pieces plus signed reassembly metadata inside the encrypted payload (§4.4). A flat inner stays exactly as specified here. Delivery acknowledgments (§4.5) additionally extend the five-member inner with `w`, `r`, `y` inside the box — also a client convention, never a format change.

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
4. Parse `inner_json`; validate `m` ≤ 128 bytes, `a` matches the alias regex, `k`/`s` are valid Base64 lengths (44/88 chars). A chunked inner additionally carries `w`, `g`, `i`, `n` and is validated per §4.4 (exact member set, `w` = `"chunk1"`, `g` = Base64 of 16 bytes, `0 ≤ i < n ≤ 16`). An ack inner additionally carries `w`, `r`, `y` and is validated per §4.5 (exact member set, `w` = `"ack1"`, `r` = 64-hex envelope id, `y` = 1, `m` = "").
5. Rebuild the signed byte string from `m`, `a`, `k`, `t` — plus `w`, `g`, `i`, `n` in the §4.4 order for a chunked inner, or `w`, `r`, `y` in the §4.5 order for an ack inner — and verify `s` with `k` (Ed25519). Failure → discard silently.
6. Optionally reject as corrupt if `t` is more than 300 s in the future.
7. Store `(m, a, t)` in the inbox. For a chunked inner, merge the chunk into the reassembly state keyed by `g` and expose ONE message when all `n` chunks arrived (§4.4). The alias may be cross-checked against the directory entry for `k`.

### 4.4 Long messages: transparent client-side chunking (issue #24)

The §8.1 plaintext limit (128 UTF-8 bytes) stays binding — **per envelope**. A longer text is split by the SENDING CLIENT into `n` ordinary envelopes, each carrying one piece of text as its `m` plus four additional members **inside the encrypted payload**. The envelope format (§3), the canonical §5.2 hashed string, the node storage (§9), the HTTP API (§10) and every node behavior are untouched: a chunk envelope **is** a v1 envelope, so envelope-id dedup (§6.2), TTL sweeps (§10.6), the mule `transit_queue` (§8.1) and blind nodes keep working unchanged. Chunking is a client convention living where the protocol is free to define anything — inside the box.

**Inner schema (chunked messages).** A chunked inner has exactly the five §4.1 members plus:

| Field | Type | Binding constraint |
|---|---|---|
| `w` | string | Inner-convention wire tag. MUST be `"chunk1"` for this convention — the §15-style versioned tag of the inner schema. A flat inner without `w` is a single-part message (§4.1, forever valid). |
| `g` | string | **Message id** shared by ALL chunks of one message: Base64 (§3.3, padded — 24 characters) of 16 random bytes from `crypto.getRandomValues` (§7.2), generated once per message. This is the stable id that identifies the MESSAGE (never a single envelope) within the chunk convention; delivery acknowledgments reference envelope ids instead (§4.5 reference rule) so flat inners need no id of their own. |
| `i` | integer | Zero-based chunk index: `0 ≤ i < n`. |
| `n` | integer | Total chunk count: `2 ≤ n ≤ 16` (a single-part message is flat, never "chunked"). |

**Signed-string rule (binding).** The signature covers everything, including the chunk metadata. The signed byte string of a chunked inner is the §5.1 string with the four members appended in fixed order `w`, `g`, `i`, `n`:

```
{"m":<m>,"a":<a>,"k":<k>,"t":<t>,"w":<w>,"g":<g>,"i":<i>,"n":<n>}
```

and the complete chunked inner serializes in fixed order `m`, `a`, `k`, `s`, `t`, `w`, `g`, `i`, `n` (the signature is computed over the string WITHOUT `s`, as in §5.1). This is a NEW canonical form for chunked messages; the §5.1 byte string of a PLAIN (non-chunked) message remains byte-identical to the construction defined in §5.1 — nothing about the flat form drifts. Worked example (exact and complete; `s` abbreviated):

```json
{"m":"Hola Bob, este mensaje viaja troceado","a":"alice_77","k":"11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=","s":"<88-char Base64 Ed25519 signature>","t":1759500001,"w":"chunk1","g":"A2aYc0XrQ0mT7oP9wK5v1g==","i":0,"n":2}
```

```
{"m":"Hola Bob, este mensaje viaja troceado","a":"alice_77","k":"11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=","t":1759500001,"w":"chunk1","g":"A2aYc0XrQ0mT7oP9wK5v1g==","i":0,"n":2}
```

Because the metadata is signed, a malicious **peer** cannot alter `g`, `i` or `n` without failing Ed25519 verification (a node or mule cannot even see them, §4.2). Module C MUST reject as corrupt (§4.3 silent discard): an unknown `w`; a `g` that is not Base64 of exactly 16 bytes; out-of-range `i` or `n`; or any inner whose member set is neither exactly the five §4.1 members nor those five plus exactly `w`, `g`, `i`, `n` — an inner with extra unknown members is corrupt by definition.

**Per-chunk text budget (binding, derived from §8.2).** The chunk metadata occupies at most **58 bytes** of `inner_json` (`,"w":"chunk1"` = 13, `,"g":"<24 chars>"` = 31, `,"i":<i>` ≤ 7, `,"n":<n>` ≤ 7), and the §8.2 envelope bound still binds per envelope:

```
inner   = 176 + M + A + 58            (M = |m| chunk text, A = |alias|)
payload = 248 + M + A + 58 ≤ 400      ⇔      M + A ≤ 94
```

So the sender splits at **94 − |alias| UTF-8 bytes of text per chunk** (the alias is ASCII-only per §4.1; an invalid alias falls back to the 24-character maximum, budget 70). Every chunk therefore also respects the §8.1 128-byte plaintext limit with room to spare, and every emitted envelope stays within the §8.2 decoded-payload bounds `[248, 400]` — a node rejects nothing new (§10.5).

**Splitting rule (sender).**

1. Split on code-point boundaries: a code point (including any surrogate pair) is NEVER split across chunks.
2. Chunks are equal-ish: each at most the sender's budget (94 − |alias| bytes), starting from the byte lower bound `ceil(|text| / budget)` and growing to the fixed point of the equal-ish retargeting (a boundary can lose up to 3 bytes to a code point that does not fit — e.g. 33 emoji = 132 bytes need three chunks of 11 emoji, not two).
3. A text that already fits one envelope is sent FLAT (§4.1, byte-identical construction).
4. All chunks share the same `created_at`, `ttl` and inner `t` (§15 invariant: no life extension, no per-chunk TTL games). The sender generates ONE random `g` per message and emits exactly one envelope per chunk, each with a fresh ephemeral key pair and nonce (§4.2).
5. Hard cap: **n ≤ 16** — a text needing more envelopes is refused by the composer. The UI previews the envelope count BEFORE sending ("will send N envelopes") and warns when N ≥ 8 (see the capacity math below). After sending, ALL chunk envelope ids join the sender's `known_ids` (§11) so it never re-pulls its own chunks.

**Reassembly (recipient).** The recipient groups arrivals by the message id `g` (SPA storage: the `inbox_parts` store, created by the additive-only, idempotent schema-version-2 migration of §15.6). Each arrival merges into the partial state for its `g`:

- Chunks may arrive in ANY order; the full text is the chunk texts concatenated in **index** order, never arrival order.
- Duplicate chunks are no-ops (first write per index wins). Upstream envelope-id dedup (§6.2, §10.4) normally absorbs re-delivery already, but the reassembler MUST tolerate it anyway.
- When all `n` chunks are held, the message is exposed as ONE inbox message (sender alias and inner `t` of the chunks) and the partial state is deleted.
- A partial renders as "message i+1/N — still traveling" and expires with its chunks: the partial's deadline is the shared `created_at + ttl` (exclusive expiry — the §10.6 boundary), swept **passively** on sync and inbox load, never by a background timer (the SPA has none).
- Two honestly signed chunks with the same `g` but conflicting metadata cannot be produced by a peer (the signature covers `g`, `i`, `n`); a sender-side anomaly simply leaves the partial incomplete, and the TTL sweep bounds its lifetime.

**Versioning (§15-style).** `w` applies the §15 versioning philosophy inside the box: `"chunk1"` is convention version 1; an inner carrying an unknown `w` is corrupt by definition and silently discarded (§4.3); a future convention bump defines `"chunk2"` and beyond without repainting `g`/`i`/`n` and without touching the envelope format or `v`.

**Mule capacity math (why the UI exposes the cost).** The cost model is honest and visible. With the alias `alice_77` (8 characters → budget 86), a 1 KiB message (1024 UTF-8 bytes) splits into **12 envelopes** — 12% of a mule's 100-envelope `transit_queue` — and the maximum message (16 chunks) occupies 16%. The composer preview shows "will send N envelopes" before sending and warns at N ≥ 8, so the occupancy of the shared mule capacity is a visible, user-approved cost rather than a hidden one; the mule telemetry panel (§11) shows the queue occupancy itself.

### 4.5 Delivery acknowledgments (issue #25)

Senders get optional, private delivery feedback: when the recipient's client has fully received a message, it emits a small signed **acknowledgment envelope** addressed back to the sender, and the sender's UI shows the message as *delivered*. **Acks need no protocol change at all**: an ack is an ordinary §3.1 v1 envelope whose inner payload follows a new inner convention — the envelope format, the canonical §5.2 hashed string, the §8 limits, node storage (§9), the HTTP API (§10) and every node/mule behavior are untouched. The ack travels to the **sender's `dest_hint`** like any other mail: the node stores it, mules carry it, and nobody learns anything a normal envelope would not reveal (§13). Like §4.4, the convention lives where the protocol is free to define anything — inside the box — and is versioned per §15 with the `w` wire tag.

**Inner schema (acks).** An ack inner has exactly the five §4.1 members plus exactly `w`, `r`, `y` (8 members; any other member set is corrupt by definition):

| Field | Type | Binding constraint |
|---|---|---|
| `w` | string | Inner-convention wire tag. MUST be `"ack1"` for this convention — the §15-style versioned tag. An inner carrying an unknown `w` is corrupt by definition and silently discarded (§4.3). |
| `r` | string | **Reference id**: the envelope `id` (§6.2, 64 lowercase hex) of the referenced message's LAST envelope — the single envelope's id for a FLAT message; the envelope id of chunk `n−1` (the final chunk, §4.4) for a CHUNKED message. The §4.4 group id `g` is deliberately NOT referenced: with `r` always an envelope id, flat inners need no id of their own, validation is one regex, and the sender can map `r` back to the message locally — the sending client keeps every emitted envelope id in its local `sent` record (§11), so the mapping never touches the network and leaks nothing. |
| `y` | integer | Ack type. MUST be `1` = **received** — the only type this convention version defines; any other value is corrupt by definition (a new type arrives with a new `w` tag). |

The five §4.1 members keep their semantics with ack-specific values: `m` MUST be `""` (acks carry no text — the §8.2 M=0 floor); `a` is the **ack author's** alias and `k` the **ack author's** Ed25519 public key — the author is the RECIPIENT of the original message, so `a` reveals to the sender only the alias it already knows from the directory (§10.3); `s` is the author's Ed25519 signature over the ack signed string below; `t` is the **ack time**, not the original's (§4.5 TTL rule).

**Signed-string rule (binding).** The signature covers everything, including the ack metadata. The signed byte string of an ack inner is the §5.1 string with the three members appended in fixed order `w`, `r`, `y`:

```
{"m":<m>,"a":<a>,"k":<k>,"t":<t>,"w":<w>,"r":<r>,"y":<y>}
```

and the complete ack inner serializes in fixed order `m`, `a`, `k`, `s`, `t`, `w`, `r`, `y` (the signature is computed over the string WITHOUT `s`, as in §5.1). These are NEW canonical forms for ack messages; the §5.1 byte string of a PLAIN message and the §4.4 string of a chunked message remain byte-identical to their constructions — nothing about them drifts. Worked example (exact and complete; `s` abbreviated):

```json
{"m":"","a":"bob_1","k":"11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=","s":"<88-char Base64 Ed25519 signature>","t":1759503601,"w":"ack1","r":"d375c17f54525e1816e5f2c01da100e17176c38fd016ea07acb5d3077eb6444f","y":1}
```

```
{"m":"","a":"bob_1","k":"11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=","t":1759503601,"w":"ack1","r":"d375c17f54525e1816e5f2c01da100e17176c38fd016ea07acb5d3077eb6444f","y":1}
```

Module C MUST reject as corrupt (§4.3 silent discard): an unknown `w`; a non-empty `m`; an `r` that is not 64 lowercase hex; a `y` other than `1`; or any inner whose member set is neither exactly the five §4.1 members, nor those five plus exactly `w`, `g`, `i`, `n` (§4.4), nor those five plus exactly `w`, `r`, `y` — an inner with extra unknown members is corrupt by definition.

**Emission rules (binding).**

1. **One ack per message.** The recipient emits at most ONE ack per delivered message: for a flat message, on decrypt + signature verification (§4.3); for a chunked message, exactly at reassembly completion (§4.4) — the partial state is deleted at completion, so a second completion (and a second ack) cannot occur. Upstream envelope-id dedup (§6.2, §10.4) absorbs re-delivery. Envelope-count overhead is thereby bounded: **≤ 1 ack envelope per delivered message** — no ack storms (§8.1 capacities are unaffected: an ack is one ordinary envelope of transit).
2. **Termination: acks are never acked.** An envelope whose inner carries `w == "ack1"` NEVER produces an ack; the receiving client of an ack records it (flips its local sent-state) and emits nothing. This is the loop-prevention rule for the symmetric case (both sides acking each other's mail): the ack chain is exactly one hop deep by construction.
3. **Addressed back to the sender, best-effort.** The ack's `dest_hint` is the SENDER's hint; the sender's X25519 public key is resolved from the directory of the node the recipient syncs with (§10.3), keyed by the Ed25519 public key the signed original carried (`k`, §4.1). A sender the directory cannot resolve simply gets no ack. Acks travel like mail and may themselves expire (TTL) or be evicted (mule FIFO, §8.1) — delivery feedback is **best-effort, never a read receipt**: silence means "unknown", not "not delivered".

**TTL alignment (binding formula).** The ack carries a TTL ≥ the original's remaining life at ack-creation time, clamped to the §8.1 range:

```
remaining = (orig.created_at + orig.ttl) − ack_time
ack_ttl   = min(TTL_MAX, max(remaining, TTL_MIN))
ack.created_at = ack_time        (NOT the original's)
```

The ack **never extends the original's life**: nothing about the original envelope is mutated or refreshed (the §15 no-refresh invariant) — the formula shapes only the NEW ack envelope, which must satisfy §8.1 on its own (servable at least `TTL_MIN`, never more than `TTL_MAX`). When the original still had `TTL_MIN` or more of life left, the ack expires no later than the original.

**Opt-in and privacy.** Acks are emitted only by the recipient's client and only while its per-identity, local-only opt-in is on (Module C default: **ON** — delivery feedback is the point of the feature). The privacy tradeoff is precise and small: with acks on, the sender learns that the recipient's device pulled the message at some point before the original's deadline expired; nodes and mules learn NOTHING beyond an ordinary envelope addressed to the sender's hint — the ack's payload is opaque (§4.2 sign-then-encrypt), its metadata is indistinguishable from any other envelope's, and no ack content may extend or refresh anything. The sender's side is symmetrical and purely local: the sender chooses whether to keep sent records and render delivery states at all; the `r` → message mapping lives only in its own `sent` store (§11, §15.6 migration), and an ack arriving for an untracked message is silently ignored.

**Forgery resistance (binding on Module C).** A node or mule cannot forge or alter an ack: the payload is MAC-protected and the signature travels inside the box (§4.2, §4.3). But the box key is public — ANYONE can craft a well-formed, self-consistently signed envelope to the sender's hint. The sender MUST therefore bind every verified ack before trusting it: the ack's `k` MUST equal the recipient Ed25519 public key recorded at send time (taken from the directory when the message was sent), and `r` MUST name a message actually sent to that recipient (`ackMatchesSent`). A mismatching, unmatchable or already-applied ack is silently ignored — ack application is idempotent. This is what makes a malicious mule (or any third party) unable to fake a "delivered" state.

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

**Chunked messages** (§4.4) use a NEW canonical form: this string with `,"w":<w>,"g":<g>,"i":<i>,"n":<n>` appended (fixed order). **Ack messages** (§4.5) likewise use this string with `,"w":<w>,"r":<r>,"y":<y>` appended (fixed order, `m` = ""). The flat form above is never altered by those extensions — plain messages sign exactly the bytes shown here.

### 5.2 Hashed byte string (for the envelope `id`)

The `id` covers the canonical JSON of the envelope subset, keys in fixed order `v`, `dest_hint`, `created_at`, `ttl`, `payload` (the `id` field itself is excluded):

```
{"v":1,"dest_hint":"<dest_hint>","created_at":<created_at>,"ttl":<ttl>,"payload":"<payload>"}
```

Note the order is *not* alphabetical (`created_at` < `dest_hint` lexicographically); serializers that sort keys are non-conforming. When `meta` is present (envelope version 2, §15.1) it is **excluded** from this byte string; format conversions MUST NOT change the resulting `id` (§15.1).

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

**Chunked inners (§4.4).** A chunked inner adds at most 58 bytes for `w`, `g`, `i`, `n` (13 + 31 + 7 + 7), so `payload = 248 + M + A + 58`; the §4.4 splitting budget (`M ≤ 94 − |alias|`) is exactly the condition that keeps every chunk envelope within `[248, 400]`. **Ack inners (§4.5)** add at most 88 bytes for `w`, `r`, `y` (11 + 71 + 6) and carry `m = ""`, so `payload = 248 + 0 + A + 88 = 336 + A ≤ 360` — every ack envelope stays within `[248, 400]`. The bounds themselves are unchanged.

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

**Storage versioning (§15).** The schema above is storage schema **version 1** (no marker: `PRAGMA user_version` = 0; every row is v1 by definition, because those builds admitted `v == 1` exclusively). §15.3 defines the explicit `user_version` marker, the forward-only migration chain (schema version 2 adds `envelopes.v`) and the downgrade-refusal rollback contract.

## 10. Node HTTP API

### 10.1 Conventions

- Listen address defaults to `:8080`. All API request/response bodies are `application/json; charset=utf-8` (the HTML endpoint is `text/html; charset=utf-8`).
- Requests with a body MUST declare `Content-Type: application/json`, otherwise `400`.
- Body size limit for POST endpoints: 1 MiB → `413` if exceeded.
- Error responses use HTTP status codes `400` (malformed/invalid), `404` (unknown path), `405` (wrong method), `413` (body too large), `429` (shed — node envelope cap reached, §8.1, or per-client admission budget exhausted, issue #16: below), `507` (storage unavailable, issue #16: below) with JSON body `{"status":"error","error":"<short_code>"}`.
- Unknown paths → `404`. There is no SPA fallback: only `GET /` serves `index.html`.
- **Per-client admission control (issue #16, additive).** Both write endpoints (`POST /api/v1/sync`, `POST /api/v1/directory`) sit behind two RAM-only, per-source-IP token budgets: a request budget (burst 60, refill 1 request per 2 s) checked **before the body is read**, and a pushed-envelope budget on sync (burst 600, refill 600 envelopes/hour) withdrawn **atomically for the whole batch** before any per-envelope validation or storage work. Exhaustion answers `429 {"status":"error","error":"rate_limited"}` with a `Retry-After` header in whole seconds (≥ 1). Budget keys derive from the network-layer source address only (`RemoteAddr`); forwarding headers MUST NOT be consulted. Budget state is ephemeral — RAM-only, dies on restart — and MUST NOT be persisted or logged per request (§13). Pull-only syncs (empty `push_envelopes`) cost nothing. The GET read path is not budgeted by the daemon — except the diagnostics endpoints of §10.7, which carry their own small per-IP budget defined there.
- **Diagnostics surface (issue #31, additive).** `GET /api/v1/health` and the operator status view `GET /status` (both §10.7) are bounded endpoints: they answer from a snapshot cached in RAM for at most one second (at most one store refresh per second, however many clients ask), sit behind a per-source-IP token budget (burst 60, refill 1 request per second; `429 rate_limited` + `Retry-After` exactly like the write budgets above; one budget shared by both paths), and carry a fixed member set with no query parameters — there is no way to make the node do per-request storage work through them.
- **Clean storage-error shed (issue #16, additive).** A push rejected because the node is at its envelope cap → `429 node_full` (§8.1, unchanged). Any other storage error on the sync push or pull path (e.g. a full SD card surfacing as ENOSPC) → `507 {"status":"error","error":"storage_unavailable"}` instead of `500`: a capacity/IO condition is expected behavior on solar-powered hardware, not an internal error. The daemon stays up and serving; pushes are accepted again once the condition clears, without a restart.

### 10.2 Canonical-host middleware

All requests whose `Host` header is not exactly `offgrid.local:8080` (case-insensitive) MUST receive:

```
301 Moved Permanently
Location: http://offgrid.local:8080{original path and query}
```

This covers direct IP access (`10.42.0.1:8080`), any spoofed domain resolved by the wildcard DNS, and bare `offgrid.local` without port. The browser always ends on the canonical origin, so `IndexedDB` never fragments.

**Mandatory exemption:** `GET /generate_204` and `GET /hotspot-detect.html` respond `302` with `Location: http://offgrid.local:8080/` **regardless of the Host header** (they arrive with Hosts like `connectivitycheck.gstatic.com`, `captive.apple.com`) and MUST NOT be redirected to the canonical host first — the OS captive-portal probe would otherwise fail to detect the portal. These endpoints MUST NOT answer `204`.

### 10.3 Endpoints (exact surface)

| Method + path | Behavior |
|---|---|
| `GET /` | Serve the embedded `index.html` (`embed.FS`). Non-canonical Host → `301` first (§10.2). |
| `GET /generate_204` | `302 → http://offgrid.local:8080/` (Android probe). Never `204`. |
| `GET /hotspot-detect.html` | `302 → http://offgrid.local:8080/` (iOS probe). |
| `GET /api/v1/directory` | `200` with a JSON array of at most 500 objects `{"alias","pubkey","x25519","last_seen"}`, ordered by `last_seen DESC` (deterministic tie-break: `pubkey ASC`). |
| `POST /api/v1/directory` | Body `{"alias","pubkey","x25519"}`. Validate alias regex and that both keys are Base64 decoding to exactly 32 bytes. Upsert keyed by `pubkey`; set `last_seen = now`. → `200 {"status":"ok"}`. Invalid → `400`. |
| `POST /api/v1/sync` | See §10.4. |
| `GET /api/v1/capabilities` | `200` with the version-advertisement document (§15.5): API generation, supported envelope-version set, storage schema version, build identifier. |
| `GET /api/v1/health` | `200` with the health snapshot document (§10.7): build identity, uptime, aggregate store figures and RAM-only counters. Budgeted and cached (§10.1, §10.7). |
| `GET /status` | The operator status view (§10.7): a server-rendered HTML page built from the same cached snapshot as `/api/v1/health`, requiring no JavaScript. Not linked from the portal (§10.7). |

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

**Version note (§15).** The `v == 1` check above is the Phase 1 baseline admission rule. Builds implementing the versioning policy of §15 admit instead `v` ∈ the supported version set (`{1, 2}`, §15.3), accept the optional unsigned `meta` member on v2 envelopes (§15.1), and serve envelopes of their stored version (§15.3). Every other check in this section is version-invariant.

### 10.6 Cleanup worker

A goroutine with `time.Ticker` runs **every 15 minutes**, plus **once at daemon startup**:

```sql
DELETE FROM envelopes WHERE created_at + ttl < now;
```

### 10.7 Health snapshot and operator status view (issue #31)

**`GET /api/v1/health`** → `200`, `application/json; charset=utf-8`, the machine-readable snapshot a deployer uses to verify a field node's wellbeing in seconds — without SSH and without learning anything about the mail it holds:

```json
{
  "status": "ok",
  "api": "v1",
  "build": "<node build identifier>",
  "envelope_versions": [1, 2],
  "schema_version": 2,
  "uptime_seconds": 1234,
  "envelopes": 87,
  "envelope_capacity": 5000,
  "directory_entries": 12,
  "db_size_bytes": 1048576,
  "last_cleanup_unix": 1759500000,
  "last_cleanup_envelopes_deleted": 3,
  "counters": {
    "pushes_accepted": 40,
    "pushes_rejected": 5,
    "pushes_rejected_by_class": {
      "invalid": 2,
      "rate_limited": 1,
      "node_full": 1,
      "storage_unavailable": 1,
      "too_large": 0
    },
    "dedup_hits": 9,
    "ttl_sweeps": 82,
    "ttl_swept_envelopes": 31
  }
}
```

| Member | Semantics |
|---|---|
| `status` | `"ok"` — a liveness statement, nothing more: the daemon answering IS the alive signal. The node has no TLS and no uplink **by design** (§12); builds MUST NOT invent health judgments beyond what is known, and MUST NOT fabricate watchdog detail (the `sd_notify` implementation holds no queryable runtime state — it sends fire-and-forget `READY=1`/`WATCHDOG=1` datagrams). |
| `api`, `build`, `envelope_versions`, `schema_version` | The §15.5 identity members, byte-identical to `GET /api/v1/capabilities` by construction (see "Two documents, one identity" below). |
| `uptime_seconds` | Seconds since the daemon process started — the same process lifetime the systemd watchdog supervises. |
| `envelopes` / `envelope_capacity` | Live envelope count (a pure `COUNT(*)`) and the §8.1 per-node cap as enforced by admission. |
| `directory_entries` | Registered directory entries (a pure `COUNT(*)`). |
| `db_size_bytes` | Database size on disk, main file plus `-wal`/`-shm` sidecars (a stale/growing WAL is a full-card symptom, `docs/hardening.md` §3). |
| `last_cleanup_unix` / `last_cleanup_envelopes_deleted` | The most recent completed §10.6 sweep (unix time and its delete count). `0` = no sweep completed since process start (the startup sweep normally sets it within seconds of boot). |
| `counters` | Process-lifetime aggregates (below). `pushes_accepted` counts sync requests that ended `200` carrying ≥ 1 pushed envelope; `pushes_rejected` counts sync requests that ended in an error, bucketed by the error code answered (`invalid` = any 400 shape, `too_large` = 413, `rate_limited`/`node_full` = the two 429 shapes, `storage_unavailable` = 507); `dedup_hits` counts envelope ids absorbed by the §10.4 `INSERT OR IGNORE` (envelope-granular); `ttl_sweeps` / `ttl_swept_envelopes` accumulate completed janitor passes. All counters reset to zero on restart — that is accepted graceful degradation, identical to the §10.1 budgets. |

**Privacy (binding, reviewed against §13).** The response, the persistence and the logs carry **aggregates only**: no envelope id, no `dest_hint`, no alias, no key, no payload fragment, no source address, no timestamp of any individual envelope. Every counter lives in RAM as an atomic integer, is never persisted, and is never logged per request — the §13.6/A7 constraint of `docs/hardening.md` applied to the diagnostics themselves. No field of the document can link envelopes to users; the store figures are pure counts that never inspect row content.

**Bounded and fast (binding).** Both diagnostics endpoints answer from a snapshot cached in RAM for at most **one second** — at most one store refresh per second, whatever the request rate, so a GET flood cannot hammer SQLite — and sit behind a per-source-IP budget (burst 60, refill 1 request/second, one budget shared by both paths; exhaustion → `429 rate_limited` + `Retry-After`, §10.1). The document is fixed-shape with no query parameters. A healthy node answers in well under 50 ms. If the store cannot be read, the endpoints shed with `507 storage_unavailable` (§10.1) instead of serving a frozen or zeroed snapshot: truthful beats available.

**Operator status view.** `GET /status` serves a small server-rendered HTML page built from the same cached snapshot, consistent with the portal's look, requiring no JavaScript (it must render on the cheap captive-portal mini-browser of any phone a field operator carries). It MUST go through the same canonical-host middleware (§10.2) and MUST NOT be linked from the portal index or its scripts — ordinary visitors are never shown operational detail; the deployer reaches it directly at `http://offgrid.local:8080/status`. The same privacy constraint applies: aggregates only.

**Two documents, one identity.** `GET /api/v1/capabilities` (§15.5) and `GET /api/v1/health` deliberately remain two documents: capabilities is the **stable negotiation contract** clients fetch, cache and act on (§15.6); health is a **volatile operational snapshot** for humans and monitoring. They are not merged because their audiences, lifecycles and cache semantics differ; instead they repeat the four shared identity members (`api`, `build`, `envelope_versions`, `schema_version`) with **identical values, guaranteed by construction** — both endpoints fill them from the same constants and sources in the daemon, so they can never diverge. Builds MUST keep this single-source property when extending either document.

## 11. Client (mule) behavior — Module C normative summary

- **Registration (once):** alias input (validated client-side against the alias regex) → generate Ed25519 + X25519 key pairs → publish `{"alias","pubkey","x25519"}` to `POST /api/v1/directory`. Private keys stay in `IndexedDB` (`identity` store). Manual seed backup (copyable text) and import MUST be offered to survive browser data wipes.
- **Composition:** recipient picked from the directory; text area with a visible **128-byte UTF-8 byte counter** (per envelope — a longer text is split into chunk envelopes per §4.4, with the envelope count previewed before sending and a warning when it would occupy a large share of a mule queue); send builds the envelope(s) exactly per §4.2/§4.4/§5/§6 and puts every emitted envelope id in `known_ids`. A per-identity, local-only delivery-feedback opt-in (default ON) gates the §4.5 behavior on both sides: emitting acks for received messages, and the composer's per-send choice to keep a local `sent` record (state `queued` → `sent` → `delivered`, honest wording — only a verified §4.5 ack says *delivered*; the record and the ack mapping live only in this device's store).
- **Sync:** automatic on page load plus a manual button. Push the whole `transit_queue` and `known_ids` (union of inbox ids ∪ transit ids ∪ previously seen/dismissed ids ∪ ids just pushed), with `limit` = 50. Classify `pull_envelopes`:
  - `dest_hint == own hint` → attempt decrypt + verify (§4.3); success → `inbox` — for a chunked inner (§4.4), merge into the reassembly state keyed by `g`: the message renders when all `n` chunks arrived, partials render as "message i+1/N — still traveling" and expire with the chunks' shared TTL (passive sweep on sync/load); for an ack inner (§4.5), bind it against the local `sent` record (signature key = the recorded recipient key, §4.5) and flip the matched message's state to `delivered` — an ack is recorded, never answered, and never lands in the inbox; failure → discard silently.
  - otherwise → `transit_queue`; if it would exceed **100** envelopes, evict oldest by `created_at` (FIFO).
- **UI (mandatory):** registration screen, directory recipient selector, composer with byte counter, inbox with sender alias and time, sent list with the per-message §4.5 delivery states, mule telemetry panel ("Foreign envelopes in transit: X / Capacity: 100") and last-sync status, and the captive-browser banner: "Open this in your full browser: `http://offgrid.local:8080`" (visible, copyable URL) — see §13.4.
- **Storage:** `IndexedDB` database `dtn_local_store` v1 with stores `identity` (singleton), `inbox`, `transit_queue`; schema migrations by version number. Store upgrades MUST be implemented as the explicit, ordered, additive-only, idempotent migrations chain formalized in §15.6 (the `onupgradeneeded` scaffold of `node/web/js/store.js`; chain: v2 adds `inbox_parts` for §4.4 partials, v3 adds `sent` for §4.5 sent-state records keyed by the ack reference id).

## 12. Same-origin policy and the deliberate absence of TLS

`IndexedDB` is isolated per web origin (scheme + host + port). For a mule to keep its identity, inbox and transit queue while moving between nodes, **all nodes must be indistinguishable in origin**: same FQDN `offgrid.local`, same port `8080`, same gateway IP `10.42.0.1`. Binding consequences:

1. `dnsmasq` on every node answers `address=/#/10.42.0.1` and `address=/offgrid.local/10.42.0.1` (wildcard DNS).
2. The canonical-host middleware (§10.2) forces every request onto `http://offgrid.local:8080`.
3. Users who bookmark the raw IP would fragment their own origin; the middleware corrects this automatically and the UI always displays the canonical URL.

**TLS is intentionally absent.** No valid certificate can exist for `offgrid.local` when every node uses the same IP, and offline PKI would require client-side installation. HTTP plaintext is acceptable **only because** content is E2EE at the application layer: the node is a hostile blind channel that never sees plaintext, keys, the sender's identity, or the recipient's full identity. TLS would add a false sense of security without protecting anything application-layer crypto does not already protect. (Threat analysis: §13.)

## 13. Threat model

### 13.1 Trust model

Zero-trust intermediaries: **nodes and mules are blind, untrusted channels.** The only trusted endpoints are the sender's and recipient's own browsers (their private keys never leave them).

### 13.2 What each party can and cannot see

| Party | Can see | Cannot see |
|---|---|---|
| **Node** | `v`, `meta` (§15.2, when present), `id`, `dest_hint`, `created_at`, `ttl`, opaque `payload`, source IP, timing/volume metadata, full directory (aliases + public keys) | Message content; sender alias and Ed25519 key (inside ciphertext); recipient identity beyond the 8-byte hint; cannot alter envelopes (Poly1305 MAC); cannot forge signatures |
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

**Mandatory mitigation (UI):** a context-detection banner instructing: "Open this in your full browser: `http://offgrid.local:8080`" with a visible, copyable URL. The recommended user flow is: join Wi-Fi → open the URL in Chrome/Safari. Acceptance testing (Sprint 4) covers both contexts explicitly.

### 13.5 Residual risks (documented, accepted for Phase 1)

- **Replay:** a node can re-serve an old (unexpired) envelope to a mule. Harmless: mules and recipients dedup by `id`, and the MAC prevents modification.
- **Traffic analysis:** timing and volume correlation by nodes (per-alias linkability is §13.3). Accepted.
- **Directory spam / flooding:** the open AP allows anonymous directory writes; mitigated by the 500-entry GET cap, alias sanitization, per-request limits (§8.1), the 15-minute cleanup and TTL caps; further hardening in Sprint 4.
- **Identity loss:** browser data wipe destroys the identity unless the seed was backed up (§11).

### 13.6 Sabotage and circumvention scenarios (issue #16)

§13.1–§13.5 cover what an adversary can **see**. This subsection covers what a hostile client — or a hostile majority of them — can **do** to the shared infrastructure, and how the system answers. The standing defenses are the four tracks of issue #16, documented in `docs/hardening.md` (design record, with per-defense regression tests) and `docs/RUNBOOK.md` (field procedures).

**Scope marking (binding).** Only the right-hand column below — the behaviors already specified in §8.1/§10/§13 — is normative for Modules B/C; the one API addition of this revision is the §10.1 admission control (`429 rate_limited` with `Retry-After`) and the clean `507 storage_unavailable` shed. Every standing-defense entry in the middle column is operational infrastructure of the reference deployment (`docs/hardening.md`): a deployment SHOULD run it, but no conforming daemon requires it — a deployment without it simply leans entirely on the normative caps of the right-hand column.

| Scenario | Standing defense (operational — `docs/hardening.md`) | What the protocol guarantees (normative) |
|---|---|---|
| Free-Internet riding (proxy/VPN/tunnel egress through the AP) | Island firewall: FORWARD DROP + named escape-route kills, `ap_isolate=1` (`docs/hardening.md` §2) | The node has no uplink and serves only the §10.3 surface; wildcard DNS answers every name with the portal IP (§12) — there is nowhere to ride to. |
| DNS tunneling / query flooding | Per-source hashlimit + sustained-rate shed of the resolver (`docs/hardening.md` §2) | The resolver has no upstream and its entire answer surface is "portal IP" (§12); every envelope's residence is bounded by `ttl` (§3.1). |
| Store flooding | Per-IP envelope budget → `429 rate_limited`; 5000-envelope cap → `429 node_full` (`docs/hardening.md` §3) | §8.1 cap with reject-newest/keep-oldest: nothing is ever evicted except by the TTL janitor (§10.6); dedup by `id` (§6.2) absorbs re-pushed floods. |
| Sync storms / connection floods | Per-IP POST budget with `Retry-After` checked before the body is read; firewall SYN hashlimit + per-source connlimit (`docs/hardening.md` §2–§3) | Fail-closed whole-request validation (§10.4 step 1); per-request byte ceilings (§8.1); the node is blind, so a request's worst-case cost is bounded and known. |
| Evil twin AP | None at the network level — no deployable network defense exists on an open SSID | Client-side crypto bounds the exposure: payloads are unreadable and unforgeable without the recipient key (§13.1, §4.2); replays are absorbed by `id` dedup (§13.5); `dest_hint` linkability is the accepted risk of §13.3. |
| Physical / power interference | Component watchdogs, `Restart=always`, the read-only-root option, and the release-kit reflash path (`docs/hardening.md` §4; `docs/RUNBOOK.md` §4) | The storage contract: WAL atomicity (§9); a corrupt database is quarantined or startup refuses loudly — never a half-broken serve (`docs/hardening.md` §7); loss is bounded to un-checkpointed writes. |
| Station saturation (association exhaustion, airtime hogging) | Association ceiling, CAKE per-host airtime fairness, per-association byte quota (`docs/hardening.md` §2) | §8.1 per-request and per-node limits bound what any single admitted request can cost the node. |

The common thread: the normative guarantees are all *blind* — caps, budgets, dedup, TTL — because per §13 the node has no user-identifying data to discriminate on. The operational defenses shed per-source at the layers where a source address still exists, but they hold their sheds in RAM/tmpfs only: nothing about a client is ever persisted (§13, A7 of `docs/hardening.md`).

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

## 15. Versioning and migration policy

This section defines how the envelope format (§3), the node storage schema (§9) and the node HTTP API (§10) evolve without breaking the running network. It generalizes the frozen-fields rule of §14.1 — stated until now only for the Phase 2/3 transport mapping — into the general rule for **every transport and every future envelope version**. Everything here is normative for node and SPA builds that implement it; builds that do not implement it remain conforming to the Phase 1 baseline (`v == 1` only) exactly as specified in §3–§11.

### 15.1 Envelope format version `v`

- `v` is the **envelope format version**. Version 1 is the format of §3 and is **frozen** as of this document.
- **Generalized freeze (binding).** In every envelope version, the fields of §3.1 (`v`, `id`, `dest_hint`, `created_at`, `ttl`, `payload`) and the inner-payload fields of §4.1 (`m`, `a`, `k`, `s`, `t`) keep their names, semantics, encodings and cryptographic scope; no field is ever repurposed, and the sign-then-encrypt order of §4.2 is invariant on every transport. This is the frozen-fields rule of §14.1 made general.

**Version 2 (defined here).** Envelope version 2 is a **strict superset** of version 1: every v1 field with unchanged name, semantics and crypto, plus exactly one new OPTIONAL top-level member:

| Field | Type | Binding constraint |
|---|---|---|
| `meta` | object | OPTIONAL; format-level metadata of the envelope **container**. MUST NOT be present on a `v == 1` envelope. First defined key: `orig_v`. Implementations MUST ignore `meta` keys they do not know (future compatible additions, §15.2). |

- **`orig_v`** (integer): the envelope version the envelope was **originally created under**. A v1→v2 conversion MUST set it to `1`. A **natively-minted** v2 envelope (created as v2 by its sender) MUST leave it **absent** — `orig_v` is meaningful only on converted envelopes.
- **`meta` is outside all cryptographic scope.** It is excluded from the §5.2 hashed byte string (hence from `id`) and it is **not signed**: the signed-then-encrypted inner `payload` bytes (§4.2) are untouched by any conversion, so adding `meta` cannot affect signature verification or decryption in any way.

**`id` stability (binding).** `id` is computed **once, at creation time**, over the canonical serialization of the core fields (§5.2) under the version rules in force at creation. Format conversion MUST NOT change `id`; the §5.2 byte string is version-invariant because it never includes `meta`. Node deduplication is therefore by `id` alone and version-agnostic: re-pushing a converted envelope is absorbed by `INSERT OR IGNORE` (§10.4) — a converted envelope cannot ride twice.

**Conversion invariants (blind, format-level only).** Any format conversion old→new MUST preserve bit-for-bit: the `payload` string and its decoded bytes, `id`, `dest_hint` (whose §6.1 derivation stays stable, §14.1), `ttl`, `created_at`, and the sender/recipient identity fields (which travel only inside the encrypted `payload`). Conversion MUST NOT refresh `ttl` or `created_at` — visiting upgraded nodes MUST NOT extend an envelope's lifetime. A conversion MAY only: change `v`; add or set `meta`; re-encode the container (e.g., a future JSON↔CBOR re-encoding per §14.2). Concretely, **v1→v2 conversion is exactly**: set `v = 2`, set `meta.orig_v = 1`, leave every other member byte-identical.

### 15.2 Compatible vs. breaking version bumps

| Bump class | Definition | Consequences |
|---|---|---|
| **Compatible** | The new format is a **strict superset** of the old, and the old→new conversion is lossless and performable **blindly** (without decrypting), by mules or nodes alike. | Nodes MUST keep admitting the previous version during an explicitly defined **support window**. v2 (§15.1) is compatible with v1. |
| **Breaking** | The change touches a frozen field (§15.1), the canonical serialization of the core fields (§5.2), or a cryptographic primitive (§7). | Requires a **coordinated protocol-phase bump** (like the Phase 1 → Phase 2 transport generations of §14) and an explicit support window after which old-format envelopes are **dropped**. A breaking bump is FORBIDDEN without a new spec phase. |

A release that introduces envelope version N MUST state explicitly (a) whether the bump is compatible or breaking and (b) which predecessor versions it retires, with their support window. During a version's support window nodes MUST admit it; after it elapses, nodes MUST reject retired versions (and drop stored ones on breaking transitions). Until such a retirement is specified, every version introduced so far stays in the supported set: builds implementing this section admit `{1, 2}` (§15.3).

### 15.3 Node admission and storage versioning

**Admission (generalizes §10.5).** A node MUST admit a pushed envelope iff `v` is in the build's **supported version set**; for builds implementing this section the set is **`{1, 2}`** (maximum advertised version: 2, §15.5). An envelope with `v` outside the set is rejected exactly like any other §10.5 validation failure (the batch fails closed, §10.4). All other §10.5 checks are version-invariant. Additional blind structural checks per admitted version:

- `v == 1`: `meta` MUST be absent.
- `v == 2`: `meta`, if present, MUST be a JSON object; `meta.orig_v`, if present, MUST be the integer `1`; unknown `meta` keys are ignored (never validated).

**Serving (pull path).** Served envelopes are complete JSON objects of their **stored version**. Schema-version-2 builds MUST include `envelopes.v` in the §10.4 selection and serve each envelope with its stored `v`; schema-version-1 builds serve the Phase 1 envelope of §3 unchanged. `meta` is admission-time container metadata and is **not persisted** (schema version 2 defines no column for it, table below): served envelopes never carry `meta`, and clients MUST NOT rely on `meta` surviving a node round-trip.

**Storage schema versioning.** The SQLite database gains explicit versioning via `PRAGMA user_version`:

| Schema version | Definition |
|---|---|
| 1 | The §9 schema as originally deployed. No marker (`user_version` = 0); all rows are v1 by definition, because those builds admitted `v == 1` exclusively. |
| 2 | The §9 schema plus column `envelopes.v INTEGER NOT NULL DEFAULT 1`, backfilled to `1` at migration (historically correct: every pre-existing row predates v2). The column is the **authoritative stored version** of each envelope from then on. |

**Migration rules (binding).** On open, if `user_version` is lower than the build's supported schema version, the daemon MUST apply the migration chain **sequentially**, each step inside a **single transaction**, and then set `user_version` to the build's schema version. Migrations MUST be transactional (idempotent-safe under crash: a crash mid-chain leaves the database at a consistent prefix of the chain, and a re-run resumes from `user_version`) and MUST NOT rewrite or re-encode stored envelope `payload` bytes. The chain is **forward-only**: schema version N+1 is defined as a delta from N only. (This mirrors the SPA's IndexedDB `onupgradeneeded` chain, §15.6.)

**Downgrade / rollback contract (binding).** A binary whose supported schema version is **lower** than the database's `user_version` MUST **refuse to start** with a clear, operator-actionable error naming both versions, and MUST leave the database file byte-untouched (no writes, no schema operations, no partial migrations). Read-only mode is explicitly NOT implemented: **refusal is the defined rollback behavior.**

### 15.4 HTTP API versioning

- `/api/v1` evolves **additively**: new endpoints, and new OPTIONAL members in responses, are non-breaking. Clients MUST ignore unknown JSON members in every API response.
- A future `/api/v2` is **reserved for breaking changes only** (new paths; `/api/v1` semantics are never mutated).
- **Deprecation:** an endpoint scheduled for removal MUST be advertised through the capabilities document (§15.5, as an additive member) for **at least one release cycle** before the release that removes it.

### 15.5 Version advertisement and negotiation: `GET /api/v1/capabilities`

New read-only endpoint (§10.3): `GET /api/v1/capabilities` → `200` with the version-advertisement document, `application/json; charset=utf-8`, subject to the same middleware as the rest of the API (§10.2):

```json
{
  "api": "v1",
  "envelope_versions": [1, 2],
  "min_envelope_version": 1,
  "max_envelope_version": 2,
  "schema_version": 2,
  "build": "<node build identifier>"
}
```

| Member | Type | Semantics |
|---|---|---|
| `api` | string | The API generation: `"v1"`. |
| `envelope_versions` | array of integers | The complete supported version set (§15.3), ascending, no duplicates. |
| `min_envelope_version` | integer | First element of `envelope_versions`. |
| `max_envelope_version` | integer | Last element of `envelope_versions`; the **negotiation ceiling** clients act on (§15.6). |
| `schema_version` | integer | The node storage schema version (§15.3). |
| `build` | string | Node build identifier; non-empty, free-form (version or VCS string). |

The exact member set on builds implementing this section is the six above; new members MAY be added additively (§15.4) and MUST be ignored by clients. The three derived members MUST stay consistent with `envelope_versions` (min = first, max = last).

**Negotiation policy (binding).** A client MUST NOT push an envelope whose `v` is greater than the node's advertised `max_envelope_version`. If capabilities cannot be obtained (endpoint absent on an older node → `404`, or any transport failure), the client MUST fall back to pushing the original, unconverted form (§15.6).

### 15.6 Mule batch conversion at upgraded nodes

**SPA storage chain (normative; formalizes §11).** The mule's `IndexedDB` database `dtn_local_store` (§11) carries its own integer version — the `DB_VERSION` / `onupgradeneeded` scaffold of `node/web/js/store.js`. That scaffold is normative: store upgrades MUST be expressed as an explicit, **ordered migrations table**; each migration MUST be **additive-only** (create stores/indexes; never mutate or delete existing records) and **idempotent**. This is the client-side analogue of the node's forward-only chain (§15.3).

**Conversion vehicle.** Every node serves the SPA same-origin at the portal origin (§12), so a mule visiting an upgraded node automatically receives upgraded client code. The updated SPA MAY convert its carried `transit_queue` envelopes from v1 to v2 before pushing — the blind transform of §15.1 (`v = 2`, `meta.orig_v = 1`, everything else preserved) — but ONLY after confirming via `GET /api/v1/capabilities` that the node advertises `max_envelope_version` ≥ 2 (§15.5). The SPA uses `max_envelope_version` to decide whether to convert.

**Where conversion happens (binding decision).** Conversion is **client-side, in the updated SPA**. The node never rewrites envelopes server-side — it is blind and stays blind (§1, §13.1). Server-side blind re-wrap remains *permitted by this policy* for future format-level transforms (the same blind operation class) but is **not part of this framework's version 1**.

**v2 envelopes at v1-only nodes (documented compatibility policy).** A v1-only node rejects a converted v2 envelope because `v = 2` is outside its supported set — this rejection is the explicit, documented policy of §15.2/§15.3, not an accident. Data does not get stuck because of the mule rules above: the mule converts only when the node advertises v2, keeps each converted envelope's original v1 form recoverable (the conversion is invertible: set `v = 1`, drop `meta`), falls back to that original form when capabilities are unobtainable (§15.5), and withholds envelopes whose `v` exceeds the node's ceiling at that node (kept in `transit_queue`; never dropped, never converted downward).

**Old mules at v2 nodes.** A mule running old client code pushes v1 envelopes to a v2 node and they are **accepted as-is**: admission is by supported set (§15.3) and there is no convert-on-write server-side (binding decision above).

### 15.7 Conformance test matrix (normative)

A build claiming conformance to this section MUST be covered by tests for each of the following; each row names the policy clause it verifies:

| # | Required coverage |
|---|---|
| a | **Schema migration preserves data:** upgrading a schema-1 database holding pre-existing envelopes keeps them intact and servable via §10.4 with unchanged contents (§15.3). |
| b | **Downgrade refusal:** starting a binary with a lower supported schema version against a newer `user_version` refuses to start, reports both versions, and leaves the database file byte-untouched (§15.3). |
| c | **v2 admission + dedup by unchanged `id`:** a v2 envelope is admitted by a §15 build; re-pushing its v1 original (same `id`) is absorbed by `INSERT OR IGNORE` — dedup is version-agnostic (§15.1, §15.3). |
| d | **Conversion fidelity:** v1→v2 conversion preserves `id`, `ttl`, `created_at`, `dest_hint` and `payload` bit-for-bit and sets `meta.orig_v = 1` (§15.1). |
| e | **TTL is not refreshed by conversion:** an envelope keeps its original `created_at`/`ttl` deadline after conversion (§15.1). |
| f | **Negotiation guard:** when the node advertises `max_envelope_version < 2` (or capabilities are unobtainable), the mule MUST NOT convert and pushes the original, unconverted form (§15.5, §15.6). |

## 16. Conformance checklist

**Module B (node daemon) MUST:** implement the schema and pragmas of §9; the nine endpoints with the exact status codes, limits and redirect/exemption behavior of §10 (including the diagnostics surface of §10.7: the health snapshot and the operator status view, aggregate-only, with RAM-only counters, the 1-second snapshot cache and the per-IP diagnostics budget); envelope validation of §10.5; the versioning policy of §15 (supported-set admission, `user_version` migration chain, downgrade refusal, capabilities advertisement); `INSERT OR IGNORE` dedup; the inclusive/exclusive expiry boundary of §10.4/§10.6; the 15-minute + startup cleanup; the canonical-host middleware with captive-probe exemption; the per-client admission control and clean storage-error shed of §10.1 (`429 rate_limited` with `Retry-After` on the write paths, `507 storage_unavailable` on sync storage errors — issue #16); no decryption, no signature verification, no `id` recomputation requirement.

**Module C (SPA) MUST:** embed tweetnacl.js inline and source all randomness from `crypto.getRandomValues` (§7); implement sign-then-encrypt with the canonical serializations of §5; derive `dest_hint` and `id` per §6; enforce every client-side limit of §8.1 (128-byte counter, alias regex, 100-envelope FIFO transit queue, known_ids composition including own pushes); implement the §4.4 long-message convention (split long texts on code-point boundaries within the per-sender budget, sign the `w`/`g`/`i`/`n` metadata, enforce the n ≤ 16 cap with a pre-send envelope-count preview, reassemble by group id `g` out-of-order and duplicate-tolerantly, render partials as "still traveling" and expire them with the chunks' shared TTL via passive sweeps, additive store migrations for the partial state); implement the §4.5 delivery-acknowledgment convention (emit at most one signed `"ack1"` ack per delivered message — flat on verified receipt, chunked exactly at reassembly completion, referencing the agreed envelope id; never ack an ack; apply the TTL formula with the ack's own `created_at`; bind every received ack to the recorded recipient key before flipping a sent record's state, silently ignoring mismatches; keep the sent history and the opt-in local-only); implement the sync algorithm and silent-corruption handling of §11; honor the mule-side rules of §15.6 (capabilities check before converting, negotiation ceiling, additive store migrations); display the canonical URL and the full-browser banner (§12, §13.4).

## Changelog

- **1.5.0 (2026-10-04, issue #25 — delivery acknowledgments):** added §4.5 "Delivery acknowledgments": optional, private delivery feedback in which the recipient's client emits ONE small signed ack envelope addressed back to the sender's `dest_hint`, and the sender's UI shows the message as delivered — with nodes and mules remaining fully blind and ZERO node changes, because an ack is an ordinary §3.1 v1 envelope whose signed-then-encrypted inner follows a new client convention. The ack inner carries exactly `w` (`"ack1"`, the §15-style versioned tag; unknown tags are corrupt), `r` (the reference id: ALWAYS a 64-hex envelope id — the single envelope's id for a flat message, the LAST chunk's (n−1) envelope id for a chunked message; the §4.4 group id is deliberately not referenced, so flat inners need no id and the sender maps `r` through its local `sent` record), `y` (type, MUST be 1 = received) plus the five §4.1 members with `m = ""`, the ack AUTHOR's `a`/`k` (the original recipient's alias and Ed25519 key) and `t` = the ack time. The signature COVERS the metadata: the §4.5 signed byte string is the §5.1 string with `w`, `r`, `y` appended in fixed order — the flat and §4.4 strings stay byte-identical. Binding rules: one ack per message (flat on verified receipt; chunked exactly once at reassembly completion, the reference being the agreed last-chunk id), termination (acks are never acked — the loop-prevention rule for symmetric acking), TTL alignment (`ack_ttl = min(TTL_MAX, max(orig_deadline − ack_time, TTL_MIN))`, ack `created_at` = ack time, the original's lifetime never mutated — no refresh), opt-in per identity, local-only, default ON (the documented tradeoff: the sender learns the recipient's device pulled the message before the original's deadline; nodes and mules learn nothing beyond an ordinary envelope), best-effort addressing (the sender's X25519 key is resolved from the node directory by the signed original's Ed25519 key; unresolvable senders get no ack; acks may themselves expire or be evicted — silence means unknown, never "not delivered"), and forgery resistance (the sender binds every verified ack to the recipient key recorded at send time before flipping its sent state — the box key is public, so the signature alone proves nothing). Overhead bounded and documented: ≤ 1 ack envelope per delivered message; ack metadata ≤ 88 inner bytes so every ack payload stays within §8.2 `[248, 400]` (max 336 + |alias| ≤ 360). Sender UI: local `sent` records (additive-only, idempotent schema-version-3 migration of §15.6, keyed by the ack reference id) with the honest state machine queued → sent ("carried by a mule") → delivered ("the recipient's device confirmed receipt"). §4.1/§4.3/§5.1/§8.2/§11 pointers added; §16 Module C conformance extended. Additive only: no frozen field, limit, canonical flat/chunked form, envelope-format or node behavior changed.

- **1.4.0 (2026-10-04, issue #24 — long-message chunking):** added §4.4 "Long messages: transparent client-side chunking": texts longer than the 128-byte plaintext limit are split entirely on the client into several ordinary protocol-conforming envelopes that the recipient reassembles into one message, with no node, mule or envelope-format change. The chunked inner carries exactly four extra members inside the box — `w` (the `"chunk1"` inner-schema wire tag, the §15-style versioned tag; unknown tags are corrupt; a flat inner without `w` stays valid forever), `g` (the stable 16-byte random message id, Base64, shared by all chunks and referenceable by future features such as acks), `i` (zero-based index) and `n` (total, 2..16) — and the signature COVERS them: the §4.4 signed byte string is the §5.1 string with the four members appended in fixed order, a new canonical form under which the plain §5.1 string remains byte-identical. Binding splitting rules: per-chunk text budget `94 − |alias|` UTF-8 bytes (derived normatively from §8.2: the metadata costs at most 58 inner bytes, so `payload = 248 + M + A + 58 ≤ 400` — every chunk envelope stays within the §8.2 bounds and nodes reject nothing new), code points never split, equal-ish chunks, shared `created_at`/`ttl`/`t` (no life extension), one envelope per chunk with fresh ephemeral keys, hard cap n ≤ 16, all chunk ids in the sender's `known_ids`. Recipient rules: reassembly by `g` out-of-order and duplicate-tolerantly (first write per index wins), one rendered message on completion, partials shown as "message i+1/N — still traveling" and expiring with the chunks' shared TTL via passive sweeps (no timers), SPA storage extended by the additive-only, idempotent schema-version-2 migration (new `inbox_parts` store, §15.6 chain). The composer previews the envelope cost before sending and warns at n ≥ 8 — with the worked capacity math (alias `alice_77`: 1 KiB = 12 envelopes = 12% of a mule's 100-envelope `transit_queue`; the 16-chunk maximum = 16%) — so the honest cost of a long message is visible, not hidden. §4.1/§4.3/§5.1/§8.2/§11 pointers added; §16 Module C conformance extended. Additive only: no frozen field, limit, canonical flat form, envelope-format or node behavior changed.

- **1.3.0 (2026-10-04, issue #31 — health diagnostics):** added §10.7 "Health snapshot and operator status view": the new `GET /api/v1/health` endpoint (machine-readable, aggregate-only snapshot — build identity, supported envelope versions, storage schema version, process uptime, live envelope count and §8.1 capacity, directory size, database size on disk, the most recent §10.6 cleanup, and process-lifetime RAM-only counters for pushes accepted/rejected with per-class breakdown, dedup hits and TTL sweeps) and the `GET /status` operator status view (server-rendered HTML from the same cached snapshot, no JavaScript, not linked from the portal, behind the same §10.2 canonical-host middleware). Both diagnostics endpoints are bounded: they answer from a snapshot cached at most one second (never one store read per request) and sit behind a per-source-IP budget (burst 60, refill 1/second, `429 rate_limited` + `Retry-After`), recorded as an explicit exception to the otherwise-unbudgeted GET read path in §10.1; an unreadable store sheds `507 storage_unavailable` instead of fabricating numbers. Privacy is normative (reviewed against §13): aggregates only, no per-envelope/per-alias/per-IP datum anywhere in the response, persistence or logs — counters are RAM-only atomics that die on restart, the same §13.6/A7 constraint the hardening defenses already obey. `capabilities` (§15.5) and `health` deliberately remain two documents (stable negotiation contract vs. volatile operational snapshot) with the four shared identity members (`api`, `build`, `envelope_versions`, `schema_version`) guaranteed identical by single-sourcing in the daemon. `status` is liveness only — no fabricated health judgments and no watchdog detail (the `sd_notify` implementation exposes no queryable state). §16 Module B conformance extended to the nine-endpoint surface. Additive only: no frozen field, limit, envelope-format or existing endpoint behavior changed.

- **1.2.1 (2026-10-04, issue #16 — defensive hardening):** added §13.6 "Sabotage and circumvention scenarios", mapping the abuse scenarios of the hardening work to the standing defenses of the reference deployment (`docs/hardening.md`, operational) and to what the protocol itself guarantees (normative). Additive API behavior on the write paths, recorded in §10.1 and verified against the node implementation (`node/internal/api/ratelimit.go`, `node/internal/api/handlers.go`): per-source-IP admission control on both POST endpoints (request budget burst 60 / refill 1 per 2 s, checked before the body is read; pushed-envelope budget burst 600 / refill 600 per hour, withdrawn per batch before any storage work) answering `429 rate_limited` with a `Retry-After` header, and storage errors on the sync push/pull path surfaced as `507 storage_unavailable` instead of `500`. Module B conformance (§16) extended accordingly. No frozen field, limit or semantics changed: `429 node_full` (§8.1) predates this revision (1.1.0); the new behaviors are admission control and error-shape changes on paths that previously either succeeded or answered `500`, and every previously specified response is unchanged. The §13 blindness constraint is restated as a constraint on the defenses themselves: budget/shed state is RAM/tmpfs-only, never persisted, never logged per request.

- **1.2.0 (2026-10-04, issue #18 — versioned evolution, Phase 1):** added §15 "Versioning and migration policy": envelope format `v` semantics with the §14.1 frozen-fields rule made general for all transports; version 2 defined as the strict v1 superset plus the optional, unsigned, `id`-excluded `meta` container object (`orig_v = 1` on converted envelopes, absent on natively-minted v2); `id` computed once at creation and immutable under conversion (dedup stays version-agnostic); compatible-vs-breaking bump rules with explicit support windows; node admission by supported version set `{1, 2}`; SQLite storage versioning via `PRAGMA user_version` with a forward-only, transactional migration chain (schema version 2 adds `envelopes.v`) and downgrade refusal as the normative rollback contract; additive `/api/v1` policy with `/api/v2` reserved for breaking changes and capabilities-advertised deprecation; the `GET /api/v1/capabilities` version-advertisement endpoint and the client negotiation rule; client-side mule v1→v2 batch conversion gated on capabilities, with the §11 store migrations formalized as an ordered, additive-only, idempotent chain; and the normative conformance test matrix (§15.7). Former §15 (Conformance checklist) is renumbered §16. Supporting pointer notes added in §3.1, §5.2, §9, §10.3, §10.5, §11 and §13.2. Additive only: no existing field, limit or endpoint behavior changed.

- **1.1.1 (2026-10-04, documentation migration):** documentation-only change — this file was renamed from `docs/protocolo.md` to `docs/protocol.md` and its source references updated to the renamed `docs/DEVELOPMENT_PLAN.md` and `docs/MASTER_DEVELOPMENT_PROMPT.md`, as part of the repository-wide English documentation migration (issue #6). No field, limit, endpoint behavior or other normative content changed.
- **1.1.0 (2026-10-03, Sprint 4):** added the per-node envelope cap of §8.1 (rejects pushes with `429 node_full` when the node holds 5000 envelopes), the corresponding `429` entry in §10.1, and the non-normative implementation-anchors table of §14.4. No existing field, limit or endpoint behavior changed; the `docs/DEVELOPMENT_PLAN.md` §1.7 table intentionally stays untouched (its §7 already anticipates this cap as hardening 4.6).
- **1.0.0 (2026-10-03):** initial normative release.

---

*End of normative specification. Changes require a version bump of this document and a corresponding update to `docs/DEVELOPMENT_PLAN.md` §1.7.*
