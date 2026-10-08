# Envelope Protocol Specification — Off-Grid DTN Messaging System

| | |
|---|---|
| **Document source** | `docs/DEVELOPMENT_PLAN.md` (§1.1, §1.2, §1.3, §1.5, §1.7, §3) and `docs/MASTER_DEVELOPMENT_PROMPT.md` |
| **Version** | 1.14.0 |
| **Date** | 2026-10-07 |
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
| **Directory** | Public per-node list of registered identities: alias, Ed25519 public key, X25519 public key, `last_seen`, the server-set hint `epoch` (§6.1, additive since 1.6.0), and the optional `prekeys` bundle (§4.6, additive since 1.7.0 — absent on entries whose owner has not published one). |
| **`transit_queue`** | Mule-side `IndexedDB` store of foreign envelopes being carried. Capacity 100, FIFO eviction by `created_at`. |

Envelope lifecycle: sender constructs → pushes to node A → any mule pulls it from node A → carries it → pushes to node B → recipient pulls it from node B, recognizes its own `dest_hint` among its §6.1 candidate set, decrypts and verifies. **Nodes never talk to each other**; all transport between nodes is physical (mules walking).

## 3. Envelope format (Phase 1, JSON)

### 3.1 Fields

The envelope travels as a single JSON object with **exactly** these fields:

| Field | Type | Binding constraint |
|---|---|---|
| `v` | integer | MUST be `1` (format version; §15.1 defines version 2 and generalizes admission to a supported version set). |
| `id` | string | 64 lowercase hex characters, `^[0-9a-f]{64}$`. SHA-256 of the canonical envelope subset (§6.2). Computed by the client. |
| `dest_hint` | string | 16 lowercase hex characters, `^[0-9a-f]{16}$`. The recipient's rotating hint — `first 8 bytes of HKDF-SHA256(X25519 public key, epoch)` (§6.1); during the §6.1 transition window the pre-1.6 static form `first 8 bytes of SHA-256(recipient X25519 public key)` is also valid. |
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

1. Compare `dest_hint` with the recipient's §6.1 candidate set: `{static legacy hint, hint(E), hint(E−1)}` (after the §6.1 transition deadline the legacy candidate is dropped, leaving `{hint(E), hint(E−1)}`). If not in the set, do not attempt decryption (mule stores the envelope instead). The comparison is purely LOCAL — the node never learns which candidate (if any) matched.
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

### 4.6 Prekey bundles — bounded forward secrecy (issue #27)

§4.2 addresses every envelope to the recipient's LONG-TERM X25519 key: an
adversary who records envelopes (dead drops, mule queues — they sit for up to
`ttl`) and LATER extracts the long-term key decrypts all of them. Zero forward
secrecy. This section adds an X3DH-flavored **prekey bundle**, published in
the node directory (§10.3 — the directory is the key server; nodes stay
blind), that bounds the damage: **captured-and-later-extracted long-term keys
no longer decrypt envelopes sent after the recipient published prekeys**, for
every envelope whose box targeted a consumed one-time prekey. The design
record with the full rationale, quantified overheads and attack analysis is
`docs/forward-secrecy.md`. Full Double Ratchet, deniable authentication and
post-compromise security beyond the prekey horizon are explicitly OUT of
scope.

**Envelope format: ZERO wire change (binding).** The envelope stays exactly
§3.1 (`payload = eph_pub ‖ nonce ‖ box`); what changes is WHICH recipient
public key the box targets and how the recipient finds the right secret. No
frozen field, canonical form, §8 limit or node behavior outside §10.3 is
touched by this section.

**The bundle (additive `prekeys` member of a directory entry, §10.3).**

```
prekeys: {
  "v": 1,                      // bundle schema version (§15-style); unknown v → bundle-less
  "spk":      "<b64 32B>",     // signed medium-term prekey public (X25519)
  "spk_sig":  "<b64 64B>",     // Ed25519 detached signature by the entry's identity key
  "ts": <unix seconds>,        // bundle publication time (the SPK TTL anchor)
  "opks": ["<b64 32B>", ...]   // one-time prekey publics, 8..16 entries
}
```

**Signed-string rule (binding).** `spk_sig` is `nacl.sign.detached` (§7) by
the entry's identity **Ed25519** key over the canonical bundle string (§5
canonical JSON, fixed member order `b`, `k`, `spk`, `ts`, `opk`):

```
{"b":1,"k":<identity Ed25519 public, Base64>,"spk":<spk>,"ts":<ts>,"opk":<count of opks>}
```

The OPK **count** — not the OPKs — is bound, so one-time-prekey replenishment
never invalidates the SPK signature; OPKs need no individual signature (they
are only extra DH inputs; the SPK signature plus the inner MAC/Ed25519
signature carry authentication). Worked vector (identity = the RFC 8032 §7.1
test key, whose public is the §4.1 example `k`; SPK = the RFC 7748 §6.1 "Bob"
X25519 public; pinned by tests/prekeys.mjs):

| Item | Value |
|---|---|
| `k` | `11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=` |
| `spk` | `3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08=` |
| `ts` / `opk` | `1791072000` / `12` |
| Canonical string (136 bytes) | `{"b":1,"k":"11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=","spk":"3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08=","ts":1791072000,"opk":12}` |
| `spk_sig` | `2TtmiNYcVcX0QpegeLuAnOCzNChs4L6z2iEu9TuuoprjZa8c5ULQtph1UWWTcrweXqs61iLEX0o2xqTVPW6HBg==` |

**Why this gives forward secrecy with no new KDF (binding statement).**
`crypto_box(inner, nonce, target_pub, eph_sec)` derives its key from
`X25519(eph_sec, target_pub)` alone (tweetnacl internals; §7). When
`target_pub` is a prekey whose secret the recipient later WIPES, the envelope
becomes unopenable by anyone holding only the long-term key — the envelope
never travels under the identity key at all. There is deliberately NO
X3DH-style concatenation/KDF of `DH(eph,OPK) ∥ DH(eph,SPK) ∥ DH(eph,identity)`:
authentication comes from the unchanged signed inner payload (§4.1–§4.3),
and tweetnacl covers every needed operation (`box`, `box.open`, `box.keyPair`,
`sign.detached(.verify)`) — no new primitives.

**Sender rules (binding).**

1. The recipient's entry carries no `prekeys`, or a member that fails the
   client-side shape check (§10.3 constraints) or whose `spk_sig` does not
   verify over the canonical string with the entry's `pubkey` → **bundle-less**:
   target the identity X25519 key (the §4.2 construction, byte-identical — the
   legacy fallback; senders verify because the node never does, §1). A failed
   signature on an otherwise well-formed entry MUST surface a warning in the
   sender's contact view (it is the doctored-bundle attack of §13.5 failing
   closed).
2. Valid bundle → prefer a ONE-TIME prekey: uniform-random choice among the
   published `opks` (§7.2 entropy); an otherwise valid bundle with empty/absent
   `opks` → the SPK.
3. `dest_hint` is UNCHANGED: `hint_E(identity_X25519_pub)` per §6.1, derived
   from the STABLE identity key — NEVER from a prekey (the directory operator
   sees prekey publications; a prekey-derived hint would rotate with
   replenishment). §14.1 rule 5 applies unchanged.

**Recipient rules (binding).**

1. Classification is unchanged (§4.3 step 1, §6.1 candidate set — all identity-key
   derivations). A hint-matching envelope is then trial-decrypted in FIXED
   order, first success wins: (a) the identity X25519 secret — the legacy path,
   a PERMANENT candidate that is never wiped (this is what keeps old-sender
   mail arriving; envelopes it opens keep NO forward secrecy, the documented
   transition tradeoff); (b) the current SPK secret; (c) each unconsumed OPK
   secret. All failures → discard silently (§4.3, unchanged).
2. **Wipe-on-use (the FS event):** the OPK secret that opened an envelope is
   wiped synchronously as part of handling the decrypt, and its public joins a
   local tombstone list (a replayed or stale bundle can never re-seed it). A
   second envelope to the same OPK is silently lost (the OPK-collision/loss
   bound of §13.5 — first delivery wins). The SPK secret is NOT wiped on use;
   its horizon is its rotation.
3. **Lifecycle (client).** Prekey secrets are fresh `crypto.getRandomValues`
   key pairs (§7.2) — NEVER derived from the identity seed — and never leave
   the device (IndexedDB store `prekeys`, additive idempotent migration v4 of
   §15.6). SPK rotates every 30 days (`ts` anchor): the client re-publishes on
   sync when stale. OPK stock replenishes below the low-water mark
   (≤ 4 remaining): a fresh batch (target 12, always within 8..16) is
   generated and re-published, and the OLD batch's secrets are wiped at
   replenish time — one batch at a time, so the published stock and the local
   secret stock stay in lockstep. Replenish rides the existing directory
   upsert (no new endpoint); it is best-effort — on failure the old stock is
   kept and the retry happens on the next sync. Mail in flight to a
   replenished-away batch is silently lost (§13.5, bounded by the low-water
   policy).
4. **Forward-secrecy horizon (honest statement, normative).** FS holds for
   envelopes addressed to OPKs whose secrets are already wiped. Envelopes
   addressed to still-held prekeys are readable by whoever later extracts the
   DEVICE store; envelopes addressed to the identity key are decryptable on
   long-term-key compromise, permanently. The horizon = OPK stock lifetime
   (consumption + low-water replenish) + SPK rotation (30 days).

**Compatibility (normative).** Old sender → new recipient: the old client
ignores the unknown `prekeys` member (§15.4) and addresses the identity key;
the recipient's identity trial path is permanent, so mail is delivered —
without FS (documented tradeoff). New sender → old recipient: an old
recipient's entry carries no `prekeys` → identity addressing → delivered. The
race "bundle published, then the recipient's client downgraded" is accepted
and documented: prekey-addressed mail to the downgraded client is silently
lost until re-addressing (a window of one publish cycle).

### 4.7 Identity QR — in-person contact exchange (issue #28)

Two people who meet in person exchange identities by showing and scanning a
QR code (alias + Ed25519 signing key + X25519 encryption key + a checksum)
instead of relying solely on the node directory or typing 44/88-character
strings. This section defines a **client-side payload convention with ZERO
wire change**: no envelope field, canonical form, §8 limit or node behavior
is touched — the payload is ordinary UTF-8 text that happens to travel as a
QR image, and the recipient's client verifies it before storing anything.
Zero external assets is binding: the QR encoder is VENDORED like tweetnacl
(`qrcode-generator` 1.4.4, MIT, embedded in `node/web/js/vendor/qrcode.js`
with a provenance header), rendering goes to a same-origin `<canvas>`, and
nothing is ever fetched from a CDN.

**Payload format (normative).** The QR text is a UTF-8 (in practice ASCII)
string:

```
OFFGRID1:<Base64(JSON)>
```

with `<Base64(JSON)>` in the §3.3 encoding (RFC 4648 standard alphabet,
with padding). The decoded JSON object has **exactly** these members, in
this fixed order:

| Member | Type | Binding constraint |
|---|---|---|
| `v` | integer | MUST be `1` (payload schema version; a §15-style versioned convention — an unknown `v` is a different spec, rejected with a visible error). |
| `alias` | string | The publisher's alias; MUST match `^[A-Za-z0-9_.-]{1,24}$` (the §8.1 alias regex). Cosmetic only (trust model below). |
| `ed` | string | The publisher's **Ed25519 public key** (identity/signature), Base64 of exactly 32 bytes (44 characters). This is the contact's IDENTITY (§4). |
| `x` | string | The publisher's **X25519 public key** (encryption), Base64 of exactly 32 bytes (44 characters). |
| `ts` | integer | Unix seconds (UTC), the payload's creation time. MUST be `> 0` and MUST NOT be more than 300 s in the importer's future (the §4.3 step 6 skew allowance). |
| `sig` | string | **Ed25519 detached signature** by the publisher's `ed` key over the canonical signed string below, Base64 of exactly 64 bytes (88 characters). |
| `crc` | string | CRC-32 of the canonical signed string, exactly 8 lowercase hex characters. Sits **outside the signature** (below). |

**Canonical signed string (binding).** The signature and the CRC both cover
the canonical JSON of the payload WITHOUT `sig` and `crc` — fixed member
order `v`, `alias`, `ed`, `x`, `ts`, serialized per §5 (UTF-8, no
whitespace, minimal escaping; the members are §8.1-ASCII and Base64, so no
escaping ever fires):

```
{"v":1,"alias":<alias>,"ed":<ed>,"x":<x>,"ts":<ts>}
```

The complete payload object serializes in the fixed order `v`, `alias`,
`ed`, `x`, `ts`, `sig`, `crc` under the same §5 rules (deterministic bytes:
rebuilding a payload from the same identity and `ts` is byte-identical).
The §5.1 flat, §4.4 chunked and §4.5 ack forms are untouched — this string
signs a CONTACT-EXCHANGE payload, never an inner payload.

**CRC-32 (binding definition).** The `crc` member is the standard CRC-32 of
IEEE 802.3 / ITU-T V.42 / zlib (reflected polynomial `0xEDB88320`, initial
value `0xFFFFFFFF`, final XOR `0xFFFFFFFF` — ISO 3309 as implemented by
zlib) computed over the UTF-8 bytes of the canonical signed string, written
as 8 lowercase hex characters. It sits OUTSIDE the signature on purpose:
it catches scan/paste corruption **instantly without cryptography**, while
a payload tampered by an adversary (who can recompute the CRC) still fails
the Ed25519 verification. Consequence, binding: a bit flip anywhere in the
canonical-covered members surfaces as a CRC mismatch; a flip in `sig`
(which the CRC does not cover) surfaces as a signature failure.

**Worked test vector** (pinned by tests/qr_identity.mjs; identity = the RFC
8032 §7.1 test key whose public is the §4.1 example `k` — the same
identity the §4.6 vector pins; X25519 key = the §11 deterministic
seed-derivation of that identity; `sig` is produced by the engine's own
vendored tweetnacl, while the CRC below was **independently cross-checked
with Python's `zlib.crc32`**):

| Item | Value |
|---|---|
| `alias` / `ts` | `alice_77` / `1791072000` |
| `ed` | `11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=` |
| `x` | `/R7hH59JUnnBjDLCUFTQ46F9eKg0kK8Chze1mEQpqVg=` |
| Canonical string (145 bytes) | `{"v":1,"alias":"alice_77","ed":"11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=","x":"/R7hH59JUnnBjDLCUFTQ46F9eKg0kK8Chze1mEQpqVg=","ts":1791072000}` |
| `crc` | `d76a4d73` |
| `sig` | `g3XAqS73T9xjotQqF3ojXed6E0E1QZHXZESdGrq1ZfHy25VNrUed1+HMaAukFPwA4sHWahn7Ag6c3XsWl4SYAA==` |
| Complete payload (357 chars) | `OFFGRID1:eyJ2IjoxLCJhbGlhcyI6ImFsaWNlXzc3IiwiZWQiOiIxMXFZQVlLeENyZlZTLzdUeVdRSE9nN2hjdlBhcGlNbHJ3SWFhUGNIVVJvPSIsIngiOiIvUjdoSDU5SlVubkJqRExDVUZUUTQ2RjllS2cwa0s4Q2h6ZTFtRVFwcVZnPSIsInRzIjoxNzkxMDcyMDAwLCJzaWciOiJnM1hBcVM3M1Q5eGpvdFFxRjNvalhlZDZFMEUxUVpIWFpFU2RHcnExWmZIeTI1Vk5yVWVkMStITWFBdWtGUHdBNHNIV2FobjdBZzZjM1hzV2w0U1lBQT09IiwiY3JjIjoiZDc2YTRkNzMifQ==` |

**Importer procedure (normative) — verify in THIS order, stopping at the
first failure:** (1) the payload starts with `OFFGRID1:` (leading/trailing
ASCII whitespace from a paste is stripped first) → `bad_prefix`; (2) the
remainder is strict §3.3 Base64 → `bad_base64`; (3) it decodes to UTF-8
JSON holding a single object → `bad_json`; (4) the member set is exactly
the seven above → `bad_members`; (5) `v == 1` → `bad_version`; (6) `alias`
matches the §8.1 regex → `bad_alias`; (7) `ed` and `x` are 44-character
Base64 decoding to exactly 32 bytes → `bad_key`; (8) `ts` is an integer
`> 0` and `≤ now + 300` → `bad_ts`; (9) `crc` is 8 lowercase hex matching
the computed CRC-32 → `bad_crc`; (10) `sig` is 88-character Base64 of 64
bytes and verifies over the canonical string with the embedded `ed` key →
`bad_signature`. On ANY failure the payload is rejected with a **VISIBLE
error naming the reason** and **NOTHING is stored**. On success the
importer holds the contact `{ed, x, alias, ts}` and persists it
(below).

**Visible rejection is a deliberate UX difference (normative).** Envelope
damage on the wire is discarded SILENTLY (§4.3) because surfacing errors
would leak information to a hostile network. The QR exchange is the exact
opposite situation: two people are standing together looking at one
screen, the payload arrives over no adversary-controlled channel, and the
user can simply show the code again. A rejection therefore names its
reason (corrupted checksum, failed signature, malformed key, …) so the
exchange can be retried on the spot.

**QR rendering (binding).** The payload is rendered with the vendored
encoder in **byte mode, ECC level M, versions 1..15** (the version-15-M
byte capacity is 412 characters; the complete payload is 345 characters at
a 1-character alias, 357 at a typical one and 377 at the 24-character
maximum — always within the cap), onto a `<canvas>` with a 4-module quiet
zone and maximum-contrast modules. The SAME payload text is always shown
next to the QR as a copyable block: the text is the universal fallback and
the paste path feeds the identical parser. NO prekeys travel in the QR:
they would roughly triple its size and hurt scan reliability — prekeys are
merged from the directory at send time instead (below).

**Contacts (device-local).** An accepted payload is stored in the SPA
`IndexedDB` store `contacts` (the §15.6 additive-only, idempotent
migration v5; DB_VERSION 5) keyed by the contact's Ed25519 public key:

```
{ ed, x, alias, added_at, source }   // source ∈ { "qr" (camera scan), "paste" }
```

Re-adding an existing contact refreshes `alias`/`x`/`source` and keeps the
original `added_at`. The recipient picker merges **local contacts ∪
directory entries, deduped by the Ed25519 key** — offline-first: contacts
are offered even when the directory fetch fails. When BOTH exist for a
key, the directory entry supplies the fresh key material (`x25519`, `epoch`,
`prekeys`) while the contact's local alias wins as the display label
(cosmetic, trust model below).

**Interplay with the directory at send time (normative).** The QR carries
identity ONLY — no §4.6 prekeys and no §6.1 epoch. At send time the sender
resolves the recipient through the merged list:

- **Directory entry available** → the entry supplies the bundle (§4.6
  sender rules: verified OPK, else SPK, else identity fallback) and the
  server-set epoch (§6.1: `dest_hint(E)` from the entry) — byte-identical
  to the pre-§4.7 send path.
- **Contact only (offline / absent from the directory)** → the box targets
  the identity X25519 key from the contact record (the §4.6 bundle-less
  fallback) and `dest_hint` is the §6.1 offline-cold STATIC hint (no
  server epoch available). The recipient recognizes the static candidate
  inside the §6.1 transition window; after `HINT_TRANSITION_DEADLINE`
  offline contact mail stops arriving until a directory is reachable —
  the documented §6.1 tradeoff, unchanged by this section.

§4.5 acks resolve the sender's X25519 key through the same merged list, so
a contact exchange completes (both directions of mail, acks included)
without any directory.

**Scanning and degradation matrix (normative).** The primary flow is: the
publisher shows the QR from the SPA on one phone; the importer scans it
from the FULL browser on the other phone. Camera scanning is feature-
detected — `BarcodeDetector` (native, Android Chrome) AND `getUserMedia` —
and needs NO vendored decoder:

| Environment | Behavior |
|---|---|
| Full browser with `BarcodeDetector` + camera (Android Chrome) | Camera scan: frames run through the native detector; a decoded payload enters the same import path as a paste. |
| iOS Safari, desktop without the API, any browser lacking either API | The scan button is hidden and an honest notice directs to the paste fallback (the payload text shown beside every QR). |
| Captive-portal mini-browsers (no `getUserMedia`, no `BarcodeDetector`) | Same notice. The feature-detect fails by construction; nothing degrades silently. |

**Trust model (normative, stated honestly).** An in-person scan is
**trust-on-sight of the person showing the code**: the importer verifies
that the payload is intact and self-signed (the signature verifies against
the embedded Ed25519 key), which detects tampering and corruption — but a
MALICIOUS publisher is not detected: scanning a stranger's QR stores
exactly the keys that QR shows, bound to nothing else. The pinned keys
govern only addressing paths that do NOT pass through a directory: when the
visited node's directory lists the same Ed25519 identity, its `x25519`,
`epoch` and `prekeys` are used (the merge rule above), so a tampered
directory entry overrides the QR's encryption key (§13.5, corrected
1.12.2). Aliases are
cosmetic and NOT unique (identity = the Ed25519 key, §4); nothing
authenticates an alias, and two people may share one. There is no
revocation in Phase 1: a contact is removed only by deleting it from the
device store, and a key swap means a different identity (a re-scan creates
a new contact record under the new key).

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

**Chunked messages** (§4.4) use a NEW canonical form: this string with `,"w":<w>,"g":<g>,"i":<i>,"n":<n>` appended (fixed order). **Ack messages** (§4.5) likewise use this string with `,"w":<w>,"r":<r>,"y":<y>` appended (fixed order, `m` = ""). The flat form above is never altered by those extensions — plain messages sign exactly the bytes shown here. The §4.6 prekey bundle signature (`spk_sig`) uses its own canonical string — fixed order `b`, `k`, `spk`, `ts`, `opk`, defined and pinned in §4.6; it signs a directory-entry member rather than an inner payload. The §4.7 identity-QR signature and CRC-32 likewise use their own canonical string — fixed order `v`, `alias`, `ed`, `x`, `ts`, defined and pinned in §4.7; none of the forms above changes.

### 5.2 Hashed byte string (for the envelope `id`)

The `id` covers the canonical JSON of the envelope subset, keys in fixed order `v`, `dest_hint`, `created_at`, `ttl`, `payload` (the `id` field itself is excluded):

```
{"v":1,"dest_hint":"<dest_hint>","created_at":<created_at>,"ttl":<ttl>,"payload":"<payload>"}
```

Note the order is *not* alphabetical (`created_at` < `dest_hint` lexicographically); serializers that sort keys are non-conforming. When `meta` is present (envelope version 2, §15.1) it is **excluded** from this byte string; format conversions MUST NOT change the resulting `id` (§15.1).

## 6. Key derivations

### 6.1 `dest_hint` — rotating derivation (issue #26, binding since 1.6.0)

Purpose (unchanged): (a) the recipient/mule identifies its own envelopes without decrypting; (b) the node can store and serve envelopes blindly (`WHERE dest_hint = ?`); (c) dedup and cleanup on the node.

**Legacy derivation (pre-1.6, retired at the transition deadline).** Version 1.0–1.5 builds addressed every envelope with a STATIC hint derived from the key alone:

```
dest_hint_legacy = lowercase_hex( SHA-256( recipient X25519 public key, raw 32 bytes )[0:8] )
```

Because the same node serves the public directory, any directory-holding operator could recompute every user's static hint forever and link stored envelopes to aliases (the §13.3 accepted risk). 1.6.0 replaces addressing with a time-bounded derivation; the legacy form survives only as a recognition candidate during the transition window below.

**Rotating derivation (binding for senders since 1.6.0).**

```
E                 = floor( unix_seconds / 86400 )                     — the hint EPOCH (24 h, UTC)
salt(E)           = E as 8-byte big-endian unsigned integer
OKM               = HKDF-SHA256( ikm  = recipient X25519 public key, raw 32 bytes
                                 salt = salt(E)
                                 info = "offgrid-dest-hint"
                                 L    = 32 )                          — RFC 5869, extract-then-expand
dest_hint(E)      = lowercase_hex( OKM[0:8] )                        — 16 lowercase hex chars
```

HKDF-SHA256 is implemented exactly per RFC 5869 on top of the same embedded SHA-256 as every other §6 derivation (no new vendored library; L = 32 is a single expansion block). `hint(E)` and `hint(E′)` for E ≠ E′ are computationally independent — but the epoch is a PUBLIC counter and the HKDF input key is the user's PUBLIC directory key, so a directory holder can derive a user's hint for ANY epoch, past or future. Rotation therefore does not make linking infeasible: it forces per-candidate-epoch recomputation instead of one computation forever, and it bounds the retroactive value of hints when a user's key is acquired AFTER envelopes were deposited. The honest statement of what rotation buys, and what it does not, is §13.3 (corrected 1.12.2 by the issue-#14 audit). The envelope format is untouched: `dest_hint` keeps its name, encoding and `^[0-9a-f]{16}$` admission regex, and the node NEVER validates a hint against the key it addresses (it cannot — it does not know under which epoch a hint was derived). §14.1 stability rule 5 applies to this derivation as it does to the static one. The hint is derived from the recipient's STABLE identity X25519 public key in every case — including §4.6 prekey-addressed envelopes, whose box targets a prekey while `dest_hint` still comes from the identity key (a prekey-derived hint would rotate with replenishment and MUST NOT be used).

**Epoch sources (binding; nodes have no NTP — the NODE's clock is the shared reference).**

- **Sender:** the EPOCH MEMBER OF THE DIRECTORY ENTRY it is sending to (§10.3 — the server sets `epoch = floor(now / 86400)` at every upsert). Per-entry is the freshest server-side truth about that recipient; the sender MUST NOT substitute its own clock. A sender whose directory cannot be read (offline-cold) or whose entry predates 1.6 (`epoch` absent, or the migrated `0`) falls back to the legacy static hint — exactly what pre-1.6 senders emit.
- **Recipient:** recognizes the candidate set `{static legacy hint, hint(E), hint(E−1)}`, where E = the highest epoch the client has observed from NODE data this session (any directory entry's `epoch`, or the capabilities document's `hint_epoch_current`, §15.5), falling back to the device clock when offline-cold. Recognition is purely local; no node or mule learns which candidate matched. After the transition deadline the legacy candidate is dropped from the set (below).
- **Consequence (documented honestly):** an envelope is deliverable while it is at most one epoch older than the recipient's freshest observation. Mail in transit across exactly one epoch boundary arrives; mail that sits in a store for more than two epochs without the recipient syncing is silently unrecognizable when they finally do — the privacy/availability trade the rotation buys (residence in that tail is bounded by TTL, §10.6).

**Transition window (legacy compatibility, normative).** Old senders (pre-1.6 SPA builds, e.g. a stale cached copy) still address with the §6.1 static hint, and every 1.6+ recipient therefore keeps the static hint in its candidate set until a fixed spec deadline:

```
HINT_TRANSITION_DEADLINE = 1795996800   (= 2026-11-30T00:00:00Z, ≈ TTL_MAX after fleet rollout)
```

The static hint stays in the candidate set exactly while `now < HINT_TRANSITION_DEADLINE`; from that instant on (inclusive) new SPA builds STOP recognizing the static hint: mail from a pre-1.6 sender to a 1.6+ recipient sent at or after the deadline silently fails to arrive. This is the documented, accepted cost — a stale SPA refreshes its code from any node it visits (§15.6: same origin, embedded SPA), so the practical exposure is days, not the window's length. The deadline is a named constant in the client engine and MUST NOT be recomputed from any clock.

**Anti-abuse interplay (unchanged, stated explicitly).** Rotating hints do not change any §8.1/§10.1 cap: a push with an arbitrary `dest_hint` is already bounded by the per-IP request and pushed-envelope budgets and the 5000-envelope store cap; admission still accepts every well-formed `^[0-9a-f]{16}$` hint regardless of any key or epoch relationship (§10.5 — the node stays blind, §13).

**Test vector 1 (legacy static form)** — X25519 public key of RFC 7748 §6.1 ("Alice"); pins the pre-1.6 derivation that remains a recognition candidate during the window:

| Item | Value |
|---|---|
| X25519 public key (raw 32 B, hex) | `8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a` |
| SHA-256 (full digest) | `300c9c9603b92a4b39ed3958bf9240114804db4fd373012c0ca47432d63425ae` |
| `dest_hint_legacy` (first 8 bytes) | `300c9c9603b92a4b` |

**Test vector 2 (rotating, worked end to end)** — same key, epoch `20730` (the epoch containing 2026-10-04, the date of this revision):

| Item | Value |
|---|---|
| X25519 public key (raw 32 B, hex) — the HKDF `ikm` | `8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a` |
| Epoch `E` | `20730` |
| `salt` (E as 8-byte big-endian, hex) | `00000000000050fa` |
| `info` (UTF-8 bytes) | `"offgrid-dest-hint"` |
| PRK = HMAC-SHA256(salt, ikm) | `0800cfc9f40483614fa9b330f76bbd9ce148db549d46ffe62a01ef6fb7e491d3` |
| OKM (L = 32) | `cdfbc410643a67f1bec3c873d4deb87e9b314e8a76136285bde522eb7ff4925e` |
| `dest_hint(E = 20730)` (OKM[0:8]) | `cdfbc410643a67f1` |
| `dest_hint(E − 1 = 20729)` (same recipe, salt `00000000000050f9`) | `5459d1d4328608b5` |

Conformance implementations MUST reproduce both vectors. The RFC 5869 §Appendix A test cases (at minimum Case 1: `ikm` = 0x0b×22) additionally pin the HKDF primitive itself in the test suite (tests/hint_rotation.mjs).

### 6.2 Envelope `id`

```
id = lowercase_hex( SHA-256( hashed byte string of §5.2 ) )   → 64 hex chars
```

The **client** computes `id`. The **server treats `id` as an opaque deduplication key**: it performs `INSERT OR IGNORE` on it and MUST NOT reject an envelope whose `id` does not match a recomputed hash (recomputation as extra hardening is permitted but MUST NOT be required for interop).

**Test vector 3** — envelope of §3.2:

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
| Hash derivations (`id`, legacy `dest_hint`) | SHA-256 | any constant-time-independent SHA-256 (WebCrypto `digest` is acceptable for hashing only) |
| Rotating `dest_hint` derivation (§6.1, 1.6.0) | HKDF-SHA256 (RFC 5869) over the same embedded SHA-256 | none (tweetnacl has no HKDF): a small client-side construction on the vendored hash — extract then expand, no new vendored library |

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
| Directory GET | ≤ 500 entries | 500 most recent by `last_seen DESC`. NOTE (§4.6, since 1.7.0): an entry MAY carry the additive `prekeys` bundle, bounded by the node at 2048 bytes (2 KiB) per entry — worst-case response ≈ 500 × (entry + 2 KiB) ≈ 1 MiB; with the shipped target stock (12 OPKs, ≈ 750 B bundles) the realistic worst case is ≈ 0.45 MiB. No pagination in Phase 1. |
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
  last_seen INTEGER NOT NULL,      -- unix seconds, set by the node on upsert
  epoch     INTEGER NOT NULL DEFAULT 0, -- server-set hint epoch, floor(last_seen / 86400) (§6.1)
  prekeys   TEXT                   -- optional §4.6 bundle as published (JSON), NULL when absent (1.7.0)
);
```

Pragmas and connection policy (binding):

- `PRAGMA journal_mode = WAL;` — survives power loss on solar-powered nodes; readers do not block the writer.
- `PRAGMA busy_timeout = 5000;` — milliseconds.
- **Single connection** (`SetMaxOpenConns(1)`): serializes all access; trivial load for a Zero 2 W; avoids SQLite write contention entirely.

`directory` rows are never auto-deleted in Phase 1; the 500-entry cap is applied at query time (§10.3). The `epoch` column is set exclusively by the node at upsert (`floor(now / 86400)`, §6.1) — the POST body shape carries no epoch and clients cannot influence it. The `prekeys` column (§4.6, since 1.7.0) stores the client-published bundle VERBATIM after blind shape validation (§10.3); the node never verifies its signature (§1) and never mutates it. Upsert semantics: a POST carrying a valid `prekeys` member stores it; a POST WITHOUT `prekeys` clears the column to NULL — a legacy client re-publishing an identity therefore removes any stale bundle, so senders fall back to identity addressing instead of aiming at OPKs the reverted client no longer holds (the documented downgrade self-heal, §4.6). Clients that publish a bundle re-publish it on every upsert (registration, import, replenish).

**Storage versioning (§15).** The schema above is storage schema **version 4**. §15.3 defines the explicit `user_version` marker, the forward-only migration chain (schema version 2 adds `envelopes.v`; version 3 adds `directory.epoch` backfilled `0`; version 4 adds the nullable `directory.prekeys` TEXT column — additive, no row is rewritten) and the downgrade-refusal rollback contract.

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
| `GET /guide` | Serve the embedded end-user quick-start guide (issue #23, since 1.10.0): a script-free `text/html` page (its own stylesheet `/css/guide.css`, a `@page`/`@media print` layout that prints the core flow on one A4/Letter sheet) rendering the same text as `docs/quick-start.md`, with the real SPA screenshots served from `/img/guide/`. It is PUBLIC and linked from the portal footer ("Guide") — the one portal-visible addition of the guide work; the operator view `GET /status` (§10.7) stays linked from nowhere. No operational data is exposed (§13). `Cache-Control: no-cache`; non-canonical Host → `301` first (§10.2). |
| `GET /css/…`, `GET /js/…`, `GET /manifest.json`, `GET /icons/…`, `GET /img/…` | Embedded same-origin static assets (the portal's stylesheet, its ES5 scripts, the §12.1 web app manifest, its PNG icons, and since 1.10.0 the guide's stylesheet and screenshots under `img/guide/`), served by exact path from the go:embed'ed web root: `200` with the asset's content type (`text/css`, `text/javascript`, `application/manifest+json`, `image/png`) and `Cache-Control: no-cache` (a node is updated as a whole binary); unknown asset paths → JSON `404`, wrong methods → JSON `405` + `Allow: GET` (§10.1). Non-canonical Host → `301` first (§10.2). |
| `GET /generate_204` | `302 → http://offgrid.local:8080/` (Android probe). Never `204`. |
| `GET /hotspot-detect.html` | `302 → http://offgrid.local:8080/` (iOS probe). |
| `GET /api/v1/directory` | `200` with a JSON array of at most 500 objects `{"alias","pubkey","x25519","last_seen","epoch"}`, ordered by `last_seen DESC` (deterministic tie-break: `pubkey ASC`). `epoch` is additive since 1.6.0 (§15.4): the server-set §6.1 hint epoch of the entry's last upsert; older clients ignore it. `prekeys` is additive since 1.7.0 (§4.6): the entry's published bundle VERBATIM (blind-validated at POST time, §10.3), present only when the row holds one; older clients ignore it. |
| `POST /api/v1/directory` | Body `{"alias","pubkey","x25519"}` (unchanged since pre-1.6 — no epoch field: the node sets it server-side, §6.1), plus an OPTIONAL `prekeys` member since 1.7.0 (§4.6): when present, it is blind-validated — `v == 1`; `spk` Base64 of exactly 32 bytes; `spk_sig` Base64 of exactly 64 bytes; `ts` integer > 0; `opks` an array of 8..16 Base64 strings each decoding to exactly 32 bytes; the whole serialized member ≤ 2048 bytes — and stored verbatim; unknown members inside `prekeys` are ignored (§15.4). The node does NOT verify `spk_sig` (§1 blindness: never verifies signatures — clients verify, §4.6). Any violation → `400 {"status":"error","error":"invalid_prekeys"}`; a POST without `prekeys` stores NULL (clears any previous bundle, §9 — the downgrade self-heal). Validate alias regex and that both keys are Base64 decoding to exactly 32 bytes. Upsert keyed by `pubkey`; set `last_seen = now` and `epoch = floor(now / 86400)`. → `200 {"status":"ok"}`. Invalid → `400`. |
| `POST /api/v1/sync` | See §10.4. |
| `GET /api/v1/capabilities` | `200` with the version-advertisement document (§15.5): API generation, supported envelope-version set, storage schema version, build identifier, plus the additive §6.1 members `hint_epoch_seconds` and `hint_epoch_current`. |
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
2. For each pushed envelope: `INSERT INTO envelopes (...) VALUES (...) ON CONFLICT(id) DO NOTHING` (`INSERT OR IGNORE`). Duplicates are silently ignored — this is the global dedup mechanism across nodes. The `directory` table is never consulted on this path: an envelope whose `dest_hint` addresses no registered identity is stored, served and expired exactly like any other (§10.5 — unknown-recipient behavior, binding).
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

**Unknown-recipient behavior (binding; issue #37).** The push path NEVER consults the `directory` table: no step of §10.4 reads it, and no future revision may add such a read. `dest_hint` is a one-way 8-byte hash derivation (§6.1), not a directory key — the node cannot know which recipient (if any) a hint addresses and MUST NOT try to. An envelope whose `dest_hint` corresponds to no registered identity is therefore handled by exactly the machinery any other envelope gets:

- **STORED** exactly like any other envelope (§10.4 step 2 — same code path, same caps, same response);
- **SERVED** to any puller, while the envelope is live: the §10.4 step 3 select carries NO hint parameter — every mule pulls every live envelope it does not already know, up to `limit` — so no hint-scoped query exists for a node to observe (corrected 1.12.2; the pre-audit wording misdescribed the select as hint-scoped);
- **EXPIRED** by the §10.6 TTL janitor if never claimed — expiry is the DTN equivalent of "return to sender".

Rejection and bounce are FORBIDDEN. Senders are anonymous to nodes (sign-then-encrypt, §4.2), so there is no sender identity to bounce an "unknown recipient" to; and any observable difference between a push whose hint addresses a registered user and one that does not would hand every client of the open AP a **recipient-existence oracle** — an information leak with no honest remedy (§13.2, §13.5). There is deliberately NO such difference: admission is hint-shape-only (§6.1 anti-abuse note), the `200` response is identical in status code, member set and `"status"` value whatever the hint addresses, and signature verification remains exclusively the recipient's post-decryption job (§4.3). This behavior is pinned normatively here and by the §15.7 row q conformance test (`TestUnknownRecipientStoredServedExpired`, `node/internal/api/unknown_recipient_test.go`) so that no future change can tighten it into a recipient-existence check.

**Version note (§15).** The `v == 1` check above is the Phase 1 baseline admission rule. Builds implementing the versioning policy of §15 admit instead `v` ∈ the supported version set (`{1, 2}`, §15.3), accept the optional unsigned `meta` member on v2 envelopes (§15.1), and serve envelopes of their stored version (§15.3). Every other check in this section is version-invariant.

### 10.6 Cleanup worker

A goroutine with `time.Ticker` runs **every 15 minutes**, plus **once at daemon startup**:

```sql
DELETE FROM envelopes WHERE created_at + ttl < now;
```

### 10.7 Health snapshot and operator status view (issues #31 and #36)

**`GET /api/v1/health`** → `200`, `application/json; charset=utf-8`, the machine-readable snapshot a deployer uses to verify a field node's wellbeing in seconds — without SSH and without learning anything about the mail it holds:

```json
{
  "status": "ok",
  "api": "v1",
  "build": "<node build identifier>",
  "envelope_versions": [1, 2],
  "schema_version": 4,
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
  },
  "battery": {
    "charge_state": "discharging",
    "soc_percent": 42,
    "soc_source": "voltage",
    "voltage_volts": 12.4,
    "current_amps": -0.35,
    "capacity_wh": 128,
    "dod_floor_percent": 20,
    "alert_band": "HEALTHY",
    "autonomy_hours": 6.5,
    "autonomy_nights": 0.27,
    "autonomy_basis": "measured",
    "health_percent": null
  },
  "system": {
    "load1": 0.1, "load5": 0.2, "load15": 0.3,
    "cpu_saturated": false,
    "mem_total_bytes": 524288000,
    "mem_used_bytes": 209715200,
    "mem_available_bytes": 314572800,
    "disk_total_bytes": 17179869184,
    "disk_free_bytes": 1073741824,
    "disk_used_bytes": 16106127360,
    "disk_free_low": false,
    "soc_temp_celsius": 47.5,
    "cpu_throttled": false,
    "system_uptime_seconds": 7200
  },
  "software": {
    "schema_version_on_disk": 4,
    "pending_migration": false
  },
  "store": {
    "expiring_within_1h": 1,
    "expiring_within_6h": 4,
    "expiring_within_24h": 17,
    "active_clients": 2,
    "counters_delta": {
      "window_hours": 6.0,
      "pushes_accepted": 12,
      "pushes_rejected": 1,
      "dedup_hits": 3,
      "ttl_swept_envelopes": 8
    }
  },
  "projections": {
    "samples": 360,
    "window_hours": 6.0,
    "enough_data": true,
    "pushes_per_day": 48,
    "expiries_per_day": 32,
    "db_growth_bytes_per_day": 8388608,
    "battery_drain_wh_per_day": 120.0,
    "days_to_envelope_capacity": 102.4,
    "days_to_disk_full": 1200.0,
    "store_equilibrium": "growing",
    "battery_net": null
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

**The issue-#36 members (additive per §15.4; clients MUST ignore unknown members).** All five are present at all times — the member set is fixed even when the underlying hardware is not:

- **N/A convention (binding):** an unavailable datum is JSON `null` — a whole member object (`"battery": null` when no sensor answered, or the endpoint is served by a build with the sampler disabled) or an individual field inside one (`"soc_temp_celsius": null` on a host without a thermal zone). `null` is never rendered as `0` anywhere, and `0` is never fabricated for something unmeasured.
- **`battery`** — the node's power state, from the reading chain **I2C sensor → `power_supply` sysfs → voltage estimate → unknown**. No reader is ever a hard dependency: without `-battery-i2c` the chain starts at sysfs; with no source at all the whole member is `null`. `charge_state` is `charging`/`discharging`/`idle`; `current_amps` is battery-centric (positive = charging). `soc_percent` carries its provenance in `soc_source`: `coulomb` (a BMS-published `capacity` — the most accurate figure this node can show) or `voltage` (derived from pack voltage against the configured full/empty anchors). **Accuracy limit (binding for the page):** a LiFePO4 4S pack discharges on a nearly flat curve, so `voltage`-derived SoC is COARSE — mid-range readings can be off by tens of percent — and the status page must say so next to the number. `autonomy_hours`/`autonomy_nights` project the runtime from the current SoC down to the DoD floor at the measured draw when a current sensor exists (`autonomy_basis: "measured"`), else at the nominal ~1 W design load of `docs/hardware.md` §1 (`"nominal"`); they are `null` without a configured `-battery-capacity-wh`. `health_percent` (state of health / cycle wear) is `null` unless a BMS publishes full-vs-design capacity — a voltage-only setup cannot measure wear and MUST NOT fake it. `alert_band` is one word: `CHARGING` (recovering, regardless of SoC), `HEALTHY` (SoC ≥ 30), `LOW` (SoC < 30 — below the overnight floor that `docs/hardware.md` §8 uses as the field acceptance rule) or `CRITICAL` (SoC ≤ the DoD floor, default 20% per `docs/hardware.md` §2.2, overridable by `-battery-dod-floor`). `null` = unknown (unless charging).
- **`system`** — CPU load averages (1/5/15 min) from `/proc/loadavg` plus the coarse `cpu_saturated` indicator (15-min load at or above the core count); memory total/used/available from `/proc/meminfo` (available = the kernel's own estimate); `disk_*` = the filesystem holding the database (one `statfs`), with `disk_free_low` = true below **50 MiB free** (the documented floor: the whole dataset is ≤ 5 MB hot data plus WAL sidecars, so less than 50 MiB free means something else is eating the card); `soc_temp_celsius` from the first `/sys/class/thermal` zone; `cpu_throttled` from `vcgencmd get_throttled` **only when the binary exists in PATH** (never a requirement); `system_uptime_seconds` from `/proc/uptime`. Every collector is feature-detected: a macOS dev box or a container reports the missing pieces as `null` and never fails a request.
- **`software`** — display-only identity beyond the §15.5 members: `schema_version_on_disk` (the on-disk `PRAGMA user_version`) and `pending_migration` (true iff the marker diverges from the build's `storage.SchemaVersion`). In normal operation the §15.3 migration completes before the daemon serves, so the flag reads `false`; a `true` on a running node means the store marker moved after boot — diagnose before touching anything. No update checking: the node has no uplink.
- **`store`** — `expiring_within_1h/6h/24h`: cumulative TTL-expiry buckets (an envelope counts in the X-hour bucket iff it is still live at sampling time — the §10.4 inclusive boundary — and expires strictly before now+X; at exactly +1 h it sits in the 6 h bucket), so an operator can predict the store draining; each is three pure `COUNT`s over the expiry index that never inspect row content. `active_clients` is the aggregate count of distinct source addresses with write-path activity (sync/directory POSTs) in the trailing **15 minutes** — the ONLY output of a capped RAM-only tracker that the API feeds at the exact points where the per-IP budgets already handle the key; no key, address or per-client datum ever leaves it, nothing is persisted, and the diagnostics GETs deliberately do not count (the operator polling the page is the observer, not a session). `counters_delta` repeats the `counters` members as deltas over the sampling window (`window_hours`, below) — `null` before the minimum-data rule is satisfied.
- **`projections`** — sliding-window rates (`pushes_per_day`, `ttl`-`expiries_per_day`, `db_growth_bytes_per_day`, `battery_drain_wh_per_day`, the last positive when draining) and derived projections (`days_to_envelope_capacity` at the current gross intake — net growth plus TTL expiry — toward the §8.1 cap; `days_to_disk_full` at the current DB growth from the last known free space; `store_equilibrium`: `growing`/`shrinking`/`steady` by net envelope growth against a ±1 envelope/day deadband; `battery_net`: `net_positive`/`starving`/`steady` over a multi-day window). Every number is computed from a fixed-capacity RAM-only ring of once-per-minute samples; **persistence was the alternative and was rejected** — daily rollups would buy projections that survive a reboot at the cost of writing operational state to the SD card; RAM-only was chosen, consistent with the §31 counters, and a reboot therefore clears every projection (the page says so).

**Minimum-data rule (binding).** No rate or projection is ever extrapolated from nothing: numeric `projections` members are `null` and `enough_data` is `false` until the ring holds **≥ 2 samples spanning ≥ 30 minutes**; `battery_net` additionally requires a **≥ 24-hour** window (one cloudy afternoon must not read as starvation). The status page renders the honest string **"not enough data yet"** in place of every such figure. With `enough_data: true`, a still-null member means "no fill/drain projected at the current rates" (e.g. a shrinking store never projects days-to-capacity; unknown free space keeps days-to-disk-full null).

**Privacy (binding, reviewed against §13).** The response, the persistence and the logs carry **aggregates only**: no envelope id, no `dest_hint`, no alias, no key, no payload fragment, no source address, no timestamp of any individual envelope. Every counter lives in RAM as an atomic integer, is never persisted, and is never logged per request — the §13.6/A7 constraint of `docs/hardening.md` applied to the diagnostics themselves. The issue-#36 members add only node-local electrical/thermal measurements (a battery reading describes the PACK, never a user), more aggregate counters, and the one active-clients integer whose tracker provably emits nothing but the count (reviewed by tests). No field of the document can link envelopes to users; the store figures are pure counts that never inspect row content.

**Bounded and fast (binding).** Both diagnostics endpoints answer from a snapshot cached in RAM for at most **one second** — at most one store refresh per second, whatever the request rate, so a GET flood cannot hammer SQLite — and sit behind a per-source-IP budget (burst 60, refill 1 request/second, one budget shared by both paths; exhaustion → `429 rate_limited` + `Retry-After`, §10.1). The document is fixed-shape with no query parameters. All issue-#36 sampling (file reads, sensor reads, `vcgencmd`, the expiry-bucket `COUNT`s) runs on a **background timer, once per minute** — the request path never samples `/proc`, never executes `vcgencmd`, never touches a sensor — so the page stays cheap on a Pi Zero W and cannot perturb the numbers it reports. A healthy node answers in well under 50 ms. If the store cannot be read, the endpoints shed with `507 storage_unavailable` (§10.1) instead of serving a frozen or zeroed snapshot: truthful beats available.

**Operator status view.** `GET /status` serves a small server-rendered HTML page built from the same cached snapshot, consistent with the portal's look, requiring no JavaScript (it must render on the cheap captive-portal mini-browser of any phone a field operator carries). It carries the issue-#36 cards — Power & battery (with the accuracy statement and the band definitions), System, Software identity, Store (expiring buckets, users, active clients, window deltas) and Load projections (each line labelled with its window and the "projection" wording) — and renders the literal `N/A` for every datum the node cannot observe. It MUST go through the same canonical-host middleware (§10.2) and MUST NOT be linked from the portal index or its scripts — ordinary visitors are never shown operational detail; the deployer reaches it directly at `http://offgrid.local:8080/status`. The same privacy constraint applies: aggregates only.

**Two documents, one identity.** `GET /api/v1/capabilities` (§15.5) and `GET /api/v1/health` deliberately remain two documents: capabilities is the **stable negotiation contract** clients fetch, cache and act on (§15.6); health is a **volatile operational snapshot** for humans and monitoring. They are not merged because their audiences, lifecycles and cache semantics differ; instead they repeat the four shared identity members (`api`, `build`, `envelope_versions`, `schema_version`) with **identical values, guaranteed by construction** — both endpoints fill them from the same constants and sources in the daemon, so they can never diverge. Builds MUST keep this single-source property when extending either document.
## 11. Client (mule) behavior — Module C normative summary

- **Registration (once):** alias input (validated client-side against the alias regex) → generate Ed25519 + X25519 key pairs → generate the initial §4.6 prekey stock (1 SPK + a target-12 OPK batch, fresh `crypto.getRandomValues` pairs) → publish `{"alias","pubkey","x25519","prekeys"}` to `POST /api/v1/directory` (the bundle is omitted only if its generation fails — a bundle-less registration stays conforming). Private keys stay in `IndexedDB` (`identity` store; prekey secrets in the `prekeys` store, §15.6 migration v4). Manual seed backup (copyable text) and import MUST be offered to survive browser data wipes; import re-publishes a fresh bundle (the old stock is unrecoverable and its OPKs are tombstoned by the fresh publication).
- **Composition:** recipient picked from the merged recipient list — the node directory ∪ the device-local contacts of §4.7, deduped by the Ed25519 key (offline-first: a contact remains sendable with the §6.1 offline-cold static hint when the directory is unreachable); text area with a visible **128-byte UTF-8 byte counter** (per envelope — a longer text is split into chunk envelopes per §4.4, with the envelope count previewed before sending and a warning when it would occupy a large share of a mule queue); send builds the envelope(s) exactly per §4.2/§4.4/§4.5/§4.6/§5/§6 — the box targets the recipient's §4.6 prekey (random OPK, else SPK) when their entry carries a valid, signature-verified bundle, else the identity X25519 key (legacy fallback; an invalid bundle surfaces a warning in the contact view) — and puts every emitted envelope id in `known_ids`. A per-identity, local-only delivery-feedback opt-in (default ON) gates the §4.5 behavior on both sides: emitting acks for received messages, and the composer's per-send choice to keep a local `sent` record (state `queued` → `sent` → `delivered`, honest wording — only a verified §4.5 ack says *delivered*; the record and the ack mapping live only in this device's store).
- **In-person contact exchange (§4.7, since 1.8.0):** the Contacts tab renders the owner's signed OFFGRID1 payload as a QR code on a `<canvas>` (vendored encoder, zero external assets) with the same payload as copyable text; the add-contact flow accepts a camera scan (native `BarcodeDetector`, feature-detected) or a pasted payload through the SAME parser — every rejection is VISIBLE with its reason and stores nothing — and saved contacts merge with the directory at send time per §4.7.
- **Sync:** automatic on page load plus a manual button. Push the whole `transit_queue` and `known_ids` (union of inbox ids ∪ transit ids ∪ previously seen/dismissed ids ∪ ids just pushed), with `limit` = 50. Classify `pull_envelopes` against the §6.1 candidate set `{static legacy hint (before the transition deadline), hint(E), hint(E−1)}` — E = the highest epoch observed from node data this session (capabilities `hint_epoch_current`, directory entry epochs), device clock when offline-cold:
  - `dest_hint` in the candidate set → attempt decrypt + verify (§4.3) with the §4.6 trial order (identity secret, then SPK secret, then each unconsumed OPK secret — first success wins; the OPK secret that opened an envelope is wiped synchronously, §4.6); success → `inbox` — for a chunked inner (§4.4), merge into the reassembly state keyed by `g`: the message renders when all `n` chunks arrived, partials render as "message i+1/N — still traveling" and expire with the chunks' shared TTL (passive sweep on sync/load); for an ack inner (§4.5), bind it against the local `sent` record (signature key = the recorded recipient key, §4.5) and flip the matched message's state to `delivered` — an ack is recorded, never answered, and never lands in the inbox; failure → discard silently.
  - otherwise → `transit_queue`; if it would exceed **100** envelopes, evict oldest by `created_at` (FIFO).
  - AFTER pulls: §4.6 replenish — if the SPK is stale (> 30 days on the bundle `ts` anchor) or the unconsumed OPK stock is at/below the low-water mark (≤ 4), generate the fresh batch, re-POST the own directory entry with the new `prekeys` bundle, and swap the local stock (old batch secrets wiped); best-effort — a failed replenish keeps the old stock and retries on the next sync.
- **Addressing (§6.1, since 1.6.0):** the composer derives the recipient's hint from the directory ENTRY's server-set `epoch` — `dest_hint(E)` with E = `entry.epoch` — never from the device clock; an entry without an epoch (pre-1.6 node, or a migrated `0`) falls back to the legacy static hint. Acks (§4.5) are addressed the same way, from the sender's entry in the directory being read.
- **UI (mandatory):** registration screen, directory recipient selector, composer with byte counter, inbox with sender alias and time, sent list with the per-message §4.5 delivery states, mule telemetry panel ("Foreign envelopes in transit: X / Capacity: 100") and last-sync status, and the captive-browser banner: "Open this in your full browser: `http://offgrid.local:8080`" (visible, copyable URL) — see §13.4.
- **Storage:** `IndexedDB` database `dtn_local_store` v1 with stores `identity` (singleton), `inbox`, `transit_queue`; schema migrations by version number. Store upgrades MUST be implemented as the explicit, ordered, additive-only, idempotent migrations chain formalized in §15.6 (the `onupgradeneeded` scaffold of `node/web/js/store.js`; chain: v2 adds `inbox_parts` for §4.4 partials, v3 adds `sent` for §4.5 sent-state records keyed by the ack reference id, v4 adds `prekeys` for the §4.6 stock record — SPK secret, unconsumed OPK secrets, tombstones, v5 adds `contacts` for the §4.7 in-person identities keyed by the Ed25519 key).

## 12. Same-origin policy and the deliberate absence of TLS

`IndexedDB` is isolated per web origin (scheme + host + port). For a mule to keep its identity, inbox and transit queue while moving between nodes, **all nodes must be indistinguishable in origin**: same FQDN `offgrid.local`, same port `8080`, same gateway IP `10.42.0.1`. Binding consequences:

1. `dnsmasq` on every node answers `address=/#/10.42.0.1` and `address=/offgrid.local/10.42.0.1` (wildcard DNS).
2. The canonical-host middleware (§10.2) forces every request onto `http://offgrid.local:8080`.
3. Users who bookmark the raw IP would fragment their own origin; the middleware corrects this automatically and the UI always displays the canonical URL.

**TLS is intentionally absent.** No valid certificate can exist for `offgrid.local` when every node uses the same IP, and offline PKI would require client-side installation. HTTP plaintext is acceptable **only because** content is E2EE at the application layer: the node is a hostile blind channel that never sees plaintext, keys, the sender's identity, or the recipient's full identity. TLS would add a false sense of security without protecting anything application-layer crypto does not already protect. (Threat analysis: §13.)

### 12.1 Installability without a service worker — PWA-lite (issue #29, since 1.9.0)

The portal ships the metadata browsers need to pin it to a home screen, so a user keeps an **"Offgrid" icon** instead of typing `http://offgrid.local:8080` — the pinned icon also stores the canonical origin itself, reducing the bookmark-by-raw-IP fragmentation risk of this section (the §10.2 middleware still corrects host drift):

- **Web app manifest**, `GET /manifest.json` (§10.3): `name` "Offgrid Messages", `short_name` "Offgrid", `start_url` "/", `scope` "/", `display` "standalone", `theme_color` `#0b6e4f`, `background_color` `#f4f6f8`, `icons` 192 px + 512 px (`purpose` `"any maskable"` — the motif stays inside the maskable safe zone, so circular crops clip background only). `start_url` and `scope` are deliberately RELATIVE and never name a host: the origin is identical on every node (this section), so ONE pinned icon opens the portal on any node — and the icon's stored origin is the canonical one.
- **Icons**, `GET /icons/icon-192.png`, `/icons/icon-512.png` (plus `icon-180.png` for the iOS meta tag), self-hosted PNGs embedded in the node binary (§10.3): zero external requests — the page CSP (`img-src 'self'`) stays closed.
- **iOS metadata** (iOS Safari ignores the manifest): `apple-mobile-web-app-capable`, `apple-mobile-web-app-status-bar-style`, `apple-mobile-web-app-title` and `apple-touch-icon` in the portal HTML. Android Chrome installs from the manifest; both open the pinned app with the standalone look on the same origin, so IndexedDB never fragments (§12, §13.4).
- **An honest install hint in the UI** (the §13.4 banner pattern): shown only in a full browser on a platform that can actually pin — Android ("browser menu → Add to Home screen") and iOS Safari ("Share → Add to Home Screen") — with exact per-OS wording mirrored in the quick-start guide; silent in captive mini-browsers, WebView-like environments, on desktops, and once dismissed (persisted device-local).

**What this is NOT (binding honesty statement).** This is PWA-lite — a manifest, icons and display metadata, NOT a full PWA. Service workers are unavailable on insecure non-localhost origins, and plain HTTP is a deliberate §12 decision, so a service-worker offline shell (cached app shell, offline messaging, background sync) is architecturally unreachable in Phase 1. The icon opens the portal when the device is on the node's Wi-Fi; **it is a shortcut, not an offline app** — the UI says exactly that. The manifest carries no service-worker member, and the hint does not hijack `beforeinstallprompt`.

**Decision path for a future phase.** The service-worker offline shell becomes possible only when one of these triggers fires: (a) TLS is revisited — per-node self-signed certificates with explicit user trust, which reverses a §12 tradeoff AND changes the origin scheme (https), fragmenting every existing device's IndexedDB unless a migration is designed first; or (b) a Phase 2 native application (§14) ships a real app shell. Until then, the manifest of this subsection is the installability ceiling, by design.

## 13. Threat model

### 13.1 Trust model

Zero-trust intermediaries: **nodes and mules are blind, untrusted channels.** The only trusted endpoints are the sender's and recipient's own browsers (their private keys never leave them).

### 13.2 What each party can and cannot see

| Party | Can see | Cannot see |
|---|---|---|
| **Node** | `v`, `meta` (§15.2, when present), `id`, `dest_hint`, `created_at`, `ttl`, opaque `payload`, source IP, timing/volume metadata, full directory (aliases + public keys, including §4.6 prekey publics) | Message content; sender alias and Ed25519 key (inside ciphertext); recipient identity beyond the 8-byte hint; which hints address registered users (the push path never consults the directory, §10.5 — no recipient-existence oracle exists); cannot alter envelopes (Poly1305 MAC); cannot forge signatures |
| **Mule** | Same envelope metadata as the node; can identify **its own** envelopes by comparing `dest_hint` with its §6.1 candidate set (§11) | Content of foreign envelopes; who else is a mule for the same envelope |
| **Network observer (open Wi-Fi)** | Same metadata as the node (plaintext HTTP) | Anything inside `payload` |
| **Recipient** | Everything, after decryption + signature verification | — |

The sender is anonymous to nodes and mules because the Ed25519 signature and alias travel **inside** the ciphertext (sign-then-encrypt, §4.2).

### 13.3 `dest_hint` linkability — narrowed by rotation since 1.6.0 (issue #26); directory-holder linkage remains PERMANENT (corrected 1.12.2, issue #14)

**The hole (pre-1.6, historical record).** Because the same node serves the **public directory** (aliases + public keys) and the pre-1.6 `dest_hint` was STATIC (`first 8 bytes of SHA-256(X25519 pubkey)`, former §6.1), a malicious node operator could recompute every registered user's hint once and forever, link every stored or served envelope to its alias, and observe who picks up whom. That was documented as an ACCEPTED RISK for Phase 1 (operators assumed passive-curious); this subsection records its closure.

**The fix (normative since 1.6.0).** Envelope addressing now uses the rotating derivation of §6.1: `hint(E) = first 8 bytes of HKDF-SHA256(ikm = X25519 public key, salt = epoch, info = "offgrid-dest-hint", L = 32)`, with E the server-set epoch of the directory entry on send. Senders derive the hint from directory data (the directory publishes the current epoch alongside the keys, §10.3) and recipients recognize a two-epoch candidate set {hint(E), hint(E−1)} locally (§11) — fully compatible with blindness: the node never learns anything new, hints still look random, admission still accepts any well-formed 16-hex hint, and the node cannot tell which epoch (or derivation) a given hint came from.

**What the mitigation actually buys (corrected 1.12.2 by the issue-#14 audit — the pre-audit wording of this paragraph overstated the mitigation).** The epoch is a public counter and the derivation input is the user's PUBLIC directory key, so a directory holder can recompute a user's hint for ANY epoch. Every envelope carries `created_at` in plaintext (§3.1), which names the deposit epoch exactly (the hint epoch itself is the recipient entry's epoch at send time and may lag it — but sweeping candidate epochs back over the TTL horizon, or further, is a handful of cheap HKDF evaluations per user). A directory-holding operator can therefore link EVERY stored envelope to its alias, permanently: rotation does NOT confine linkage to the current epoch, and it does not decay for an operator that keeps records. What rotation genuinely buys: (a) the pre-1.6 attack — one static hash per user, valid forever, computed once — now requires per-envelope, per-epoch recomputation (a work-factor increase, not a closure); (b) a hint alone reveals nothing: envelopes deposited where the recipient's key is NOT yet held (e.g. at a node whose directory lacks the recipient) become linkable only after a later key acquisition, and then only for the epochs the acquirer recomputes — so retroactive linking after a LATE directory acquisition is bounded in practice instead of free. Within a single node — where the operator holds the directory from the start — the honest summary is that envelope-to-alias linkage by the operator is permanent, exactly as before 1.6.0, and remains an accepted risk (§13.5).

**Residual risks, stated honestly (accepted):**

1. **Linking is not epoch-confined (corrected 1.12.2).** For any live envelope, a directory holder recomputing hints over the candidate epochs — named exactly by the envelope's plaintext `created_at`, in practice bounded by the TTL horizon — links it to the alias. The pre-audit claim that linkage "decays with epoch rotation" overstated the mitigation; the corrected statement above is the record.
2. **The operator sees the directory epochs — and every other epoch.** `epoch` is public per entry (it must be, that is the mechanism), and nothing in the derivation is secret beyond the public key itself: the operator can derive `hint(E′)` for ANY epoch E′. Rotation does not hide WHICH epochs are live, and it does not expire an operator's ability to link.
3. **The transition window re-introduces the static hint.** Until HINT_TRANSITION_DEADLINE (§6.1, 2026-11-30T00:00:00Z) the legacy static hint remains a recognition candidate, so envelopes addressed by pre-1.6 senders remain permanently linkable for their TTL, as before. After the deadline the static candidate is dropped and pre-1.6 senders' mail no longer arrives (§6.1) — their SPA refreshes from any visited node, so the practical exposure is days.
4. **Timing/volume correlation is untouched.** An operator watching pickups live (pull source, timing, volume per hint) can correlate across epochs by observation rather than derivation; §13.5's traffic-analysis acceptance covers that side and rotation does not change it.

Reference: the mitigation THIS section describes is normative — §6.1 (derivation, epochs, window), §10.3 (directory epoch), §10.5/§8.1 (unchanged blind admission and caps), §11 (candidate-set recognition), §15.5 (capabilities advertisement), §15.7 g–i (conformance coverage).

### 13.4 Captive-portal mini-browser storage isolation (risk + mitigation)

When Android/iOS detect the captive portal they open a **restricted mini-browser** whose storage profile is isolated from — and often ephemeral compared to — the device's real browser. A user who only ever uses the mini-browser may lose identity/inbox data between sessions or nodes.

**Mandatory mitigation (UI):** a context-detection banner instructing: "Open this in your full browser: `http://offgrid.local:8080`" with a visible, copyable URL. The recommended user flow is: join Wi-Fi → open the URL in Chrome/Safari. Acceptance testing (Sprint 4) covers both contexts explicitly. The full-browser banner is complemented by the §12.1 install hint, which is silent in the mini-browser itself — pinning is exactly what it cannot do.

### 13.5 Residual risks (documented, accepted for Phase 1)

- **Recipient-existence probing (closed by design, issue #37):** because the sync push path never consults the directory (§10.5) and an unknown-`dest_hint` envelope is stored, served and TTL-expired exactly like any other — with a response indistinguishable in status, shape and value — a hostile client of the open AP cannot probe a node for "which hints have registered recipients": the answer surface is empty by construction. This is a standing constraint on future work, not a one-off: the update-staging and directory-federation endpoints of issue #37 verify their OWN artifacts (a release-capsule signature, an identity-card signature) and MUST NOT add any discrimination to the envelope path (their design record: `docs/offline-maintenance.md`).

- **Replay (corrected 1.12.2 — the pre-audit wording understated the window):** node-side dedup (`INSERT OR IGNORE` by `id`, §10.4) covers only the CURRENT store. The §10.6 janitor's deletions are not remembered, `created_at` carries no freshness floor (§10.5 bounds it only above), and admission therefore accepts envelopes that are already past their deadline — they are stored (occupying §8.1 cap headroom until the next sweep) but never served, because the §10.4 inclusive boundary excludes them from the first pull. A station that captures an envelope (any station may pull the whole blind dead-drop, §13.2) can consequently re-inject it at any LATER time, at any node: while still unexpired it rides again for its remaining TTL. A recipient that has seen the id absorbs it (client `seen_ids`/inbox dedup, §11), but a freshly initialized or seed-restored client cannot distinguish a replayed message from late mail — the old text reappears in its inbox, and a replayed ack re-applies an idempotent delivery state. Impact is bounded to re-delivery confusion and storage-headroom nibbling: the MAC and signature still bind content and no third party gains readability. A replay of a §4.6 prekey-addressed envelope whose OPK was already consumed fails the trial decrypt outright (the secret was wiped) — strictly stronger than dedup alone. Accepted residual: a blind node cannot keep a global memory of expired ids without unbounded state.
- **Traffic analysis:** timing and volume correlation by nodes (per-alias linkability is §13.3 — rotation raises the recomputation work factor; linkage by a directory holder remains permanent, see the 1.12.2 correction). A chunked message (§4.4) is additionally visible AS a group: its 2..16 envelopes share `dest_hint`, `created_at` and `ttl`, exposing the message's size band and chunk count to any node or mule; a §4.5 ack, addressed back to the sender's hint, lets an observer correlate the original's pickup. All accepted.
- **Directory spam / flooding:** the open AP allows anonymous directory writes; mitigated by the 500-entry GET cap, alias sanitization, per-request limits (§8.1), the 15-minute cleanup and TTL caps; further hardening in Sprint 4.
- **Identity loss:** browser data wipe destroys the identity unless the seed was backed up (§11).
- **Forward-secrecy horizon of §4.6 (accepted, stated honestly):** envelopes addressed to the identity X25519 key — all mail from old senders during the transition, and all fallback mail after a missing/invalid/tampered bundle — keep ZERO forward secrecy: a later long-term-key extraction decrypts them. Mail to still-held prekeys is safe against long-term-key extraction but not against device-store extraction. The horizon is OPK stock lifetime + SPK rotation (§4.6).
- **OPK loss windows (§4.6, accepted):** two senders picking the same one-time prekey deliver only the first envelope (the secret wipes on use; the second is silently lost) — bounded by the 8..16 stock; replenishment replaces the whole OPK batch, so mail in flight to the previous batch is silently lost; the low-water policy (replenish only at ≤ 4 remaining) keeps these windows short. Such losses are indistinguishable from ordinary DTN loss (TTL expiry, mule FIFO).
- **Doctored bundles (closed by the §4.6 signature):** a malicious node serving a sender a bundle it generated itself fails the client-side `spk_sig` verification — the sender falls back to identity addressing and the UI surfaces a warning. The signature does NOT close the pre-existing hole that a directory entry's `x25519` member can be swapped — and, corrected 1.12.2, the swap does not even require controlling the node: `POST /api/v1/directory` is unauthenticated (§10.3), so ANY station of the open AP can republish a victim's `pubkey` bound to attacker key material and receive the victim's prekey-addressed mail (directory entries are not authenticated end-to-end in Phase 1). Closing that (proof-of-possession or key transparency) is out of scope.
- **The node serves the client code (stated explicitly since 1.12.2; accepted).** Every byte of the SPA arrives from the untrusted node over plaintext HTTP (§12 same-origin — there is no out-of-band code channel in Phase 1). A malicious or compromised node can serve a modified client that exfiltrates the seed and secrets of every user who registers, imports a seed, or unlocks on it; no client-side cryptography defends against the client itself having been replaced. Practical mitigations are operational: the served crypto embeds carry recorded SHA-256 hashes with an offline re-verification recipe (an engine swap is detectable by a paranoid user on any terminal), and signed/native application distribution is the structural closure reserved for §14. Until then, registering on a node of doubtful provenance means trusting its operator with the identity created there (§13.6 evil-twin row).
- **QR-pinned keys defer to the directory (stated explicitly since 1.12.2).** A §4.7 contact record pins the Ed25519 identity, but when the visited node's directory ALSO lists that identity, the entry supplies the encryption material (`x25519`, `epoch`, `prekeys` — §4.7 merge rule); the QR-scanned `x` is used only when the directory lacks the entry. Because an honest directory and an honest QR always derive from the same seed and agree, a divergence between a pinned contact's `x` and a directory `x25519` is by construction the tamper signal of the bullet above — and the shipped client resolves it SILENTLY in the directory's favor. The in-person QR exchange therefore authenticates the identity binding, not the encryption path travelled through a directory; `docs/offline-maintenance.md` §3.5 specifies the pin-and-warn refinement that makes the divergence visible (future work).

### 13.6 Sabotage and circumvention scenarios (issue #16)

§13.1–§13.5 cover what an adversary can **see**. This subsection covers what a hostile client — or a hostile majority of them — can **do** to the shared infrastructure, and how the system answers. The standing defenses are the four tracks of issue #16, documented in `docs/hardening.md` (design record, with per-defense regression tests) and `docs/RUNBOOK.md` (field procedures).

**Scope marking (binding).** Only the right-hand column below — the behaviors already specified in §8.1/§10/§13 — is normative for Modules B/C; the one API addition of this revision is the §10.1 admission control (`429 rate_limited` with `Retry-After`) and the clean `507 storage_unavailable` shed. Every standing-defense entry in the middle column is operational infrastructure of the reference deployment (`docs/hardening.md`): a deployment SHOULD run it, but no conforming daemon requires it — a deployment without it simply leans entirely on the normative caps of the right-hand column.

| Scenario | Standing defense (operational — `docs/hardening.md`) | What the protocol guarantees (normative) |
|---|---|---|
| Free-Internet riding (proxy/VPN/tunnel egress through the AP) | Island firewall: FORWARD DROP + named escape-route kills, `ap_isolate=1` (`docs/hardening.md` §2) | The node has no uplink and serves only the §10.3 surface; wildcard DNS answers every name with the portal IP (§12) — there is nowhere to ride to. |
| DNS tunneling / query flooding | Per-source hashlimit + sustained-rate shed of the resolver (`docs/hardening.md` §2) | The resolver has no upstream and its entire answer surface is "portal IP" (§12); every envelope's residence is bounded by `ttl` (§3.1). |
| Store flooding | Per-IP envelope budget → `429 rate_limited`; 5000-envelope cap → `429 node_full` (`docs/hardening.md` §3) | §8.1 cap with reject-newest/keep-oldest: nothing is ever evicted except by the TTL janitor (§10.6); dedup by `id` (§6.2) absorbs re-pushed floods. |
| Sync storms / connection floods | Per-IP POST budget with `Retry-After` checked before the body is read; firewall SYN hashlimit + per-source connlimit (`docs/hardening.md` §2–§3) | Fail-closed whole-request validation (§10.4 step 1); per-request byte ceilings (§8.1); the node is blind, so a request's worst-case cost is bounded and known. |
| Evil twin AP | None at the network level — no deployable network defense exists on an open SSID | Client-side crypto bounds the exposure ONLY while the client code itself is genuine — and the code is served by the very node under attack (§12 same-origin): an evil twin can serve a modified SPA that harvests the identities of users who register or unlock on it (accepted residual, §13.5). Payloads remain unreadable and unforgeable without the recipient key (§13.1, §4.2); replays are absorbed by `id` dedup (§13.5); `dest_hint` linkability is the residual-risk record of §13.3. |
| Physical / power interference | Component watchdogs, `Restart=always`, the read-only-root option, and the release-kit reflash path (`docs/hardening.md` §4; `docs/RUNBOOK.md` §4) | The storage contract: WAL atomicity (§9); a corrupt database is quarantined or startup refuses loudly — never a half-broken serve (`docs/hardening.md` §7); loss is bounded to un-checkpointed writes. |
| Station saturation (association exhaustion, airtime hogging) | Association ceiling, CAKE per-host airtime fairness, per-association byte quota (`docs/hardening.md` §2) | §8.1 per-request and per-node limits bound what any single admitted request can cost the node. |

**Resource exhaustion as censorship (stated honestly, added 1.12.2 by the issue-#14 audit).** The caps above are availability shields, not anti-censorship tools: a blind node cannot distinguish junk from mail, so it cannot prefer one over the other. A single hostile station acting entirely within the per-IP envelope budget (burst 600, refill 600/hour, §10.1) can deposit 5000 max-TTL junk envelopes in well under a day; with the store at cap, every further push — including all legitimate mail — is rejected `429 node_full`, and the junk ages out only through its own TTL (§10.6). One fill therefore holds a node's mailbox shut to NEW mail for up to TTL_MAX (30 days), is repeatable to sustain itself, and scales linearly with colluding stations; the keep-oldest policy is the one mitigation (mail already deposited stays servable — what a fill denies is new mail). The same blindness exposes mule resources: a hostile node can hand a visiting mule 100 valid-shaped garbage envelopes, evicting the cargo the mule actually carried (FIFO, §8.1), and grow the mule's `seen_ids` dedup memory; carried-mail loss is indistinguishable from ordinary DTN loss. This is an accepted residual of the shared finite store, not a defect a conforming build can close.

The common thread: the normative guarantees are all *blind* — caps, budgets, dedup, TTL — because per §13 the node has no user-identifying data to discriminate on. The operational defenses shed per-source at the layers where a source address still exists, but they hold their sheds in RAM/tmpfs only: nothing about a client is ever persisted (§13, A7 of `docs/hardening.md`).

## 14. Phase 2/3 evolution mapping (Module D)

### 14.1 Stability rules (what never changes)

1. **Semantic fields are frozen:** `v`, `id`, `dest_hint`, `created_at`, `ttl`, `payload` (+ reserved `hop_count`), and inner `m`, `a`, `k`, `s`, `t`. No field is ever repurposed.
2. **Sign-then-encrypt is invariant:** the signature and alias always travel inside the ciphertext on every transport.
3. **Encodings are transport-tier:** Phase 1 JSON uses hex/Base64 *text*; binary phases (Phase 2/3) use *raw bytes* in CBOR. Conversions are lossless decodings of the text forms.
4. **`hop_count` is a reserved field:** semantics = times the envelope has been relayed peer-to-peer, `0..7`; a relay drops envelopes at 7. In Phase 1 JSON the field is always **absent** (absent = 0). It never appears in Phase 1 code paths.
5. **`dest_hint` derivation is stable** through Phase 3. The rotating-hint scheme (§6.1) — originally sketched as a Phase 2 privacy upgrade — shipped as the normative Phase 1 derivation in 1.6.0; only the derivation function changed (the envelope format did not, §14.1 rule 1), and the rotating derivation is now itself frozen: later phases swap it only via a new breaking-bump generation per §15.2.

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
| 3 | The §9 schema plus column `directory.epoch INTEGER NOT NULL DEFAULT 0` (§6.1, issue #26) — the server-set hint epoch the directory publishes, backfilled to `0` at migration. `0` (epoch-zero, 1970) is deliberately stale: an unrefreshed entry makes senders fall back to the legacy static hint until its owner re-publishes (§6.1). Purely additive: no envelope column, row or payload byte is touched. |
| 4 | The §9 schema plus nullable column `directory.prekeys TEXT` (§4.6, issue #27) — the client-published prekey bundle as published (blind-validated JSON, §10.3), NULL when the entry carries none. Migration 3→4 is `ALTER TABLE ... ADD COLUMN prekeys TEXT`: every pre-existing row reads NULL (bundle-less), no row content is rewritten, and the first upsert of each client decides its bundle from then on. Purely additive. |

**Migration rules (binding).** On open, if `user_version` is lower than the build's supported schema version, the daemon MUST apply the migration chain **sequentially**, each step inside a **single transaction**, and then set `user_version` to the build's schema version. Migrations MUST be transactional (idempotent-safe under crash: a crash mid-chain leaves the database at a consistent prefix of the chain, and a re-run resumes from `user_version`) and MUST NOT rewrite or re-encode stored envelope `payload` bytes. The chain is **forward-only**: schema version N+1 is defined as a delta from N only. (This mirrors the SPA's IndexedDB `onupgradeneeded` chain, §15.6.)

**Downgrade / rollback contract (binding).** A binary whose supported schema version is **lower** than the database's `user_version` MUST **refuse to start** with a clear, operator-actionable error naming both versions, and MUST leave the database file byte-untouched (no writes, no schema operations, no partial migrations). Read-only mode is explicitly NOT implemented: **refusal is the defined rollback behavior.**

### 15.4 HTTP API versioning

- `/api/v1` evolves **additively**: new endpoints, and new OPTIONAL members in responses, are non-breaking. Clients MUST ignore unknown JSON members in every API response.
- **Designed-but-unbuilt endpoints (issue #37).** The update-staging endpoint and the directory-federation endpoints sketched for the offline-island maintenance work (`POST /api/v1/update/stage`; `GET /api/v1/directory/deltas`; `POST /api/v1/directory/federate`) follow this additive policy when they land. Their complete design — capsule format and signing ritual, merge policy, caps and budgets, trust model — is `docs/offline-maintenance.md` (design record, non-normative until its follow-up issues implement it). None of them may weaken the §10.5 unknown-recipient guarantee: the envelope path stays directory-blind.
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
  "schema_version": 4,
  "build": "<node build identifier>",
  "hint_epoch_seconds": 86400,
  "hint_epoch_current": 20730
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
| `hint_epoch_seconds` | integer | **Additive since 1.6.0 (§15.4, issue #26).** The §6.1 epoch length in seconds (86400). A pre-1.6 node omits it; clients MUST treat absence as "this node does not publish hint epochs" and fall back to the legacy static hint (§6.1). |
| `hint_epoch_current` | integer | **Additive since 1.6.0 (§15.4, issue #26).** The node's current hint epoch, `floor(node now / hint_epoch_seconds)` — the same server clock that stamps directory entries (§10.3). Recipients use it (with directory entry epochs) as the freshest observation for the §6.1 candidate set; senders prefer the per-entry epoch. |

The exact member set on builds implementing this section is the eight above; new members MAY be added additively (§15.4) and MUST be ignored by clients. The three derived members MUST stay consistent with `envelope_versions` (min = first, max = last). The two §6.1 members MUST stay consistent with the directory's server-set epochs by construction (both derive from the node clock).

**Negotiation policy (binding).** A client MUST NOT push an envelope whose `v` is greater than the node's advertised `max_envelope_version`. If capabilities cannot be obtained (endpoint absent on an older node → `404`, or any transport failure), the client MUST fall back to pushing the original, unconverted form (§15.6).

### 15.6 Mule batch conversion at upgraded nodes

**SPA storage chain (normative; formalizes §11).** The mule's `IndexedDB` database `dtn_local_store` (§11) carries its own integer version — the `DB_VERSION` / `onupgradeneeded` scaffold of `node/web/js/store.js`. That scaffold is normative: store upgrades MUST be expressed as an explicit, **ordered migrations table**; each migration MUST be **additive-only** (create stores/indexes; never mutate or delete existing records) and **idempotent**. This is the client-side analogue of the node's forward-only chain (§15.3). Chain: v2 adds `inbox_parts` (§4.4), v3 adds `sent` (§4.5), v4 adds `prekeys` (§4.6), v5 adds `contacts` (§4.7, keyPath `ed`).

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
| g | **Hint rotation at the epoch boundary with in-flight delivery (§6.1):** an envelope addressed with `dest_hint(E)` is still classified as the recipient's own and delivered after the recipient's observed epoch advances to E+1 (the candidate set covers exactly one boundary crossing); HKDF-SHA256 is pinned against the RFC 5869 test cases and the §6.1 worked vectors. |
| h | **Legacy candidate recognition (§6.1 transition window):** before `HINT_TRANSITION_DEADLINE` the recipient's candidate set includes the static legacy hint, so a pre-1.6-addressed envelope is delivered like any other; the directory GET exposes `epoch` and the capabilities document the two additive members. |
| i | **Candidate-set drop after the transition deadline (§6.1):** at any clock past `HINT_TRANSITION_DEADLINE` the static legacy hint leaves the candidate set — a legacy-addressed envelope is no longer recognized (stored as foreign cargo, never decrypted); the rotating candidates are unaffected. |
| j | **Capture-then-extract fails for consumed OPKs (§4.6):** an envelope addressed to a one-time prekey decrypts through the recipient's trial path exactly once — the OPK secret is wiped on use — after which decryption fails BOTH for the full local state and for an attacker holding ONLY the extracted long-term identity secret; the §4.6 bundle canonical string and its Ed25519 signature match the worked vector. |
| k | **Replenish keeps the stock healthy (§4.6):** a stock at/below the low-water mark (or a stale SPK) triggers regeneration on sync — a fresh signed bundle is published via the ordinary directory upsert, the local stock is swapped, the old batch's secrets are wiped, and mail already addressed to a wiped OPK no longer decrypts; a failed replenish keeps the old stock. |
| l | **Tampered bundle falls back (§4.6):** an entry whose `spk_sig` does not verify (or whose shape is invalid) is treated as bundle-less — the sender addresses the identity key (mail still delivered) and the UI surfaces a warning; the node itself never verifies signatures (§1) and rejects blind-shape violations with `400 invalid_prekeys`. |
| m | **Prekey migration both directions (§4.6):** an old-client envelope addressed to the identity key of a prekey-published recipient is delivered through the permanent identity trial path (no forward secrecy — documented); a new-client sender facing an entry WITHOUT `prekeys` falls back to identity addressing and delivers; a storage schema 3→4 migration preserves every directory row (prekeys backfilled NULL). |
| n | **In-person contact exchange without a directory (§4.7):** two clients import each other's OFFGRID1 payloads into their contacts, the directory endpoints stay EMPTY throughout, and a message exchange completes BOTH ways on the §6.1 offline-cold static hint with the §4.6 identity fallback; a tampered payload (byte damage inside the CRC-covered region) is rejected with the visible `bad_crc` reason and stores nothing; the canonical string, CRC-32 and Ed25519 signature match the §4.7 worked vector; and the shipped encoder's matrix round-trips through an independent QR decoder across versions 1-15 (byte mode, ECC M). |
| o | **Add-to-home-screen installability within the no-TLS constraint (§12.1):** `/manifest.json` serves with the `application/manifest+json` content type and carries exactly the §12.1 members (`start_url` "/" and `scope` "/" RELATIVE — no hardcoded host anywhere; `display` "standalone"; icons 192+512 with purpose "any maskable") and no service-worker member; the icons serve as `image/png` with the exact advertised pixel dimensions (PNG magic + IHDR parsed); the portal HTML carries the manifest link, `theme-color` and the iOS meta tags; and NO external URL appears in the manifest, the icons or the portal HTML (zero external assets, CSP `img-src 'self'` intact); the canonical-host 301 covers the new paths. |
| p | **End-user quick-start guide served by the node (§10.3):** `GET /guide` serves the embedded script-free HTML page (`text/html; charset=utf-8`, `Cache-Control: no-cache`, no `<script>` anywhere, closed CSP without `script-src`) carrying the 10 numbered steps, the glossary, the expectations box and the troubleshooting list; `/css/guide.css` carries the `@page`/`@media print` two-column layout; every `/img/guide/*.png` referenced by the page serves as `image/png` (unknown → JSON 404, POST → 405); the portal footer links `/guide` labeled "Guide" while `/status` stays unlinked; NO external URL appears in the guide HTML beyond the canonical origin; the canonical-host 301 covers the new paths. |
| q | **Unknown-recipient behavior (§10.5, issue #37):** on a node whose directory table is EMPTY throughout, a well-formed envelope whose `dest_hint` corresponds to no directory entry (none exist) is accepted `200` and stored; a pull presenting that `dest_hint` receives it byte-identical (all six fields, `payload` included); after the TTL deadline the §10.6 boundary deletes it and it is no longer served; and the `200` response to the push is indistinguishable in status code, response member set and `"status"` value from the same push repeated after the directory has been populated — no response element differentiates a known-addressed from an unknown-addressed envelope. Pinned by `TestUnknownRecipientStoredServedExpired` (`node/internal/api/unknown_recipient_test.go`). |

## 16. Conformance checklist

**Module B (node daemon) MUST:** implement the schema and pragmas of §9 (storage schema version 4, including the §6.1 `directory.epoch` column set server-side at upsert and the §4.6 nullable `directory.prekeys` column with the §15.3 migration chain — 3→4 purely additive); the endpoints with the exact status codes, limits and redirect/exemption behavior of §10 (including the diagnostics surface of §10.7: the health snapshot and the operator status view, aggregate-only, with RAM-only counters, the 1-second snapshot cache and the per-IP diagnostics budget — plus, since 1.11.0, the five issue-#36 members served under the null N/A convention from a once-per-minute RAM-only sampler with the binding minimum-data rule, the background-only sampling and the aggregate-only active-clients tracker; and since 1.10.0 the public end-user guide `GET /guide` of §10.3, script-free and carrying no operational data); the embedded static-asset surface of §10.3 (css/js/manifest.json/icons/img: exact-path serving, the closed content-type allow-list, `Cache-Control: no-cache`, fail-closed startup on a broken embed — including a missing §12.1 manifest or icons tree, or a missing guide page); envelope validation of §10.5 (blind: no hint-vs-key or hint-vs-epoch validation, ever); the §10.3 blind `prekeys` admission (shape only — v, Base64 lengths, opks count 8..16, ts > 0, ≤ 2048 bytes; NO signature verification ever; absent member clears the column); the versioning policy of §15 (supported-set admission, `user_version` migration chain, downgrade refusal, capabilities advertisement including the additive §6.1 members); `INSERT OR IGNORE` dedup; the inclusive/exclusive expiry boundary of §10.4/§10.6; the 15-minute + startup cleanup; the canonical-host middleware with captive-probe exemption; the per-client admission control and clean storage-error shed of §10.1 (`429 rate_limited` with `Retry-After` on the write paths, `507 storage_unavailable` on sync storage errors — issue #16); no decryption, no signature verification, no `id` recomputation requirement, and no directory consultation anywhere on the envelope path — an unknown-`dest_hint` envelope is stored, served and TTL-expired exactly like any other, with a response indistinguishable from a known-addressed one (§10.5, §15.7 row q).

**Module C (SPA) MUST:** embed tweetnacl.js inline and source all randomness from `crypto.getRandomValues` (§7); implement sign-then-encrypt with the canonical serializations of §5; derive `dest_hint` and `id` per §6 — the §6.1 rotating derivation for the EPOCH OF THE DIRECTORY ENTRY on send, the static legacy form only as a pre-1.6/degraded fallback, and HKDF-SHA256 exactly per RFC 5869 on the vendored SHA-256 — always from the STABLE identity key, never from a prekey (§4.6); recognize its own mail by the §6.1 candidate set {legacy (before the deadline), hint(E), hint(E−1)} with E the highest server-observed epoch, dropping the legacy candidate from clock `HINT_TRANSITION_DEADLINE` on; implement the §4.6 prekey lifecycle: generate and publish the bundle at registration (canonical string, `spk_sig` with the identity Ed25519 key), verify a peer's bundle shape AND signature before prekey-addressing (random OPK, else SPK, else identity fallback with a UI warning on a failed signature), keep `dest_hint` identity-derived, trial-decrypt in the fixed order identity → SPK → unconsumed OPKs, wipe the OPK secret synchronously on use (tombstoning its public), replenish below the low-water mark / on stale SPK during sync (best-effort re-POST, atomic stock swap, old-batch wipe), and keep prekey secrets device-local in the additive v4 `prekeys` store (never derived from the identity seed); enforce every client-side limit of §8.1 (128-byte counter, alias regex, 100-envelope FIFO transit queue, known_ids composition including own pushes); implement the §4.4 long-message convention (split long texts on code-point boundaries within the per-sender budget, sign the `w`/`g`/`i`/`n` metadata, enforce the n ≤ 16 cap with a pre-send envelope-count preview, reassemble by group id `g` out-of-order and duplicate-tolerantly, render partials as "still traveling" and expire them with the chunks' shared TTL via passive sweeps, additive store migrations for the partial state); implement the §4.5 delivery-acknowledgment convention (emit at most one signed `"ack1"` ack per delivered message — flat on verified receipt, chunked exactly at reassembly completion, referencing the agreed envelope id; never ack an ack; apply the TTL formula with the ack's own `created_at`; bind every received ack to the recorded recipient key before flipping a sent record's state, silently ignoring mismatches; keep the sent history and the opt-in local-only); implement the sync algorithm and silent-corruption handling of §11; honor the mule-side rules of §15.6 (capabilities check before converting, negotiation ceiling, additive store migrations); implement the §4.7 identity-QR exchange (build the signed OFFGRID1 payload with the §4.7 canonical string, CRC-32 and Ed25519 signature, render it to a `<canvas>` via the vendored encoder at versions 1-15 ECC M with the payload also shown as copyable text, verify an incoming payload in the exact §4.7 order rejecting VISIBLELY with the reason and storing NOTHING on any failure, keep contacts in the additive v5 `contacts` store keyed by the Ed25519 key with source "qr"/"paste", merge contacts ∪ directory at send time deduped by key with the directory supplying fresh key material, feature-detect `BarcodeDetector` + `getUserMedia` for scanning and direct every unsupported environment to the paste fallback); display the canonical URL and the full-browser banner (§12, §13.4), and surface the dismissible §12.1 install hint in full browsers on pinnable platforms only (Android/Chrome menu, iOS Share-sheet wording) with the §12.1 honesty rule — the icon is a shortcut, not an offline app — silent in captive mini-browsers and everywhere the instruction cannot work.

**RFC 4838 alignment.** Offgrid implements the DTN *architecture* of RFC 4838 — store-carry-forward over persistent storage, endpoint naming decoupled from topology, self-declared message lifetimes, delivery over opportunistic contacts — and deliberately does not implement the IETF Bundle Protocol (RFC 5050 / RFC 9171) or BPSec (RFC 6257 / RFC 9172). The concept-by-concept alignment audit against RFC 4838 (§3.1–§3.14, §4, §5, §6, §8), with the full mapping table, per-concept verdicts, the deviation register (intentional vs unintentional, with follow-up proposals) and the wording corrections applied to `README.md`, is **`docs/rfc4838-alignment.md`** (issue #40). That audit is informational: it changes no requirement of this specification.

## 17. Annex: node plane (normative in docs/node-network.md)

Phase 3's node-to-node plane (issue #33: LoRa/TCPCL bundles between nodes, link sessions, management roles and levels, software updates and directory federation) is specified in its own normative module, **`docs/node-network.md`** (versioned independently of this document). This annex records the boundary; it changes nothing else here.

- **The user-plane formats of this document stay byte-frozen.** The envelope format and its frozen fields (§3/§14.1/§15.1), the canonical serializations (§5), the key derivations (§6), the binding limits (§8), the node storage (§9) and the HTTP API (§10) are untouched by the node plane and are never reinterpreted by it.
- **The node plane consumes this specification only through frozen surfaces:** the §14.2 CBOR envelope travels verbatim as the mail-bundle payload (an envelope crossing the node plane in either direction does so byte-unmodified — same `id`, same TTL, no life extension); the node plane's window framing mirrors the §14.3(a) grammar as its own format without modifying the §14.3 user-plane bytes; envelope admission and serving (§10.5/§15.3) gain no node-plane reads, fields or exceptions.
- **Amendments live in the node-plane document, not here.** The two recorded decisions issue #33 amends — `docs/rfc4838-alignment.md` §8 (its user-plane verdict is untouched) and `docs/offline-maintenance.md` §2.8 (no-LoRa-capsule relaxed to budgeted) — are recorded in `docs/node-network.md` §1.3 with owner approval dated 2026-10-07.
- **Evolution:** future node-plane changes land in `docs/node-network.md` under its own versioning; this document only gains additive annexes of this kind. A node-plane change that would require touching a frozen section here is a breaking bump under §15.2 and is FORBIDDEN without a new spec phase.

## Changelog

- **1.14.0 (2026-10-07, issue #33 P3.6 — node-plane management, additive diagnostics member):** the node-plane management plane landed in its normative home (`docs/node-network.md` v1.6.0, §8 — command object, enforcement pipeline, telemetry replies, sink consumption; this annex boundary of §17 is unchanged), and the only touch on THIS document is additive under §15.4: `GET /api/v1/health` (§10.7) gains one fixed top-level member, `node_plane` — null when the daemon runs with the node plane off (the binding N/A convention, exactly like the issue-#36 members), and otherwise aggregates only: the provisioned role/level from the node's role certificate, the §8.2 management counters (`commands_accepted`, the `dropped_*` classes, reply counters), the §2.5 cert merge counters, the node-plane bundle store fill/cap and the peer/session counts. No EIDs, no fingerprints, no addresses, no timestamps of individuals — the same §13 aggregates-only constraint the §10.7 privacy rules already bind, reviewed and asserted by tests (`node/internal/api/nodeplane_test.go`). No envelope field, limit, canonical form, existing endpoint behavior or conformance requirement changed; §3–§15 content is untouched.

- **1.13.0 (2026-10-07, issue #33 P3.0 — node-plane annex):** appended §17 "Annex: node plane (normative in docs/node-network.md)": the Phase 3 node-to-node plane (issue #33) is specified in its own normative module `docs/node-network.md` v1.0.0, this document's user-plane formats stay byte-frozen, the node plane consumes only the frozen surfaces (the §14.2 envelope verbatim as mail-bundle payload, the §14.3 window grammar mirrored node-plane-side, §10.5/§15.3 admission untouched), and the two owner-approved recorded-decision amendments named by issue #33 (rfc4838-alignment §8 — verdict untouched for the user plane; offline-maintenance §2.8 — no-LoRa-capsule relaxed to budgeted) are recorded in the node-plane document, not here. No envelope field, limit, canonical form, endpoint behavior or conformance requirement changed; the header version and this entry are the only edits to existing content.

- **1.12.2 (2026-10-06, issue #14 — threat-model audit corrections):** documentation-only honesty corrections from the Phase 3 protocol audit (`docs/security-audit.md` §3). NO envelope field, limit, canonical form, endpoint behavior or conformance requirement changed. **§13.3 is corrected:** the pre-audit claim that rotating hints confine directory-operator linkability to the current epoch ("linkability decays with epoch rotation") was an overstatement — the epoch is a public counter, the derivation input is the public directory key, and every envelope carries `created_at` in plaintext, so a directory holder can recompute a user's hint for ANY candidate epoch cheaply; directory-holder linkage is PERMANENT (as it was before 1.6.0). What rotation actually buys — a per-epoch work factor instead of one computation forever, and a bound on retroactive linking when a key is acquired after deposition — is now the binding statement, and §6.1's derivation paragraph is corrected accordingly. **§13.5:** the replay bullet is corrected (node dedup covers the live store only — janitor deletions are not remembered and `created_at` has no freshness floor, so captured envelopes are re-injectable after eviction; already-expired re-injections are stored but never served; fresh/restored clients cannot distinguish replayed mail; pinned by the new `TestExpiredEnvelopeAdmittedNeverServed`); the traffic-analysis residual is extended (chunk groups share `dest_hint`/`created_at`/`ttl`, exposing message size bands; acks correlate pickup); the doctored-bundles bullet records that the directory-entry `x25519` swap does not require controlling the node (the unauthenticated §10.3 POST puts it within reach of any station); two residuals are stated explicitly for the first time — the node serves the client code (a modified SPA harvests the identities of users who register on it; engine-hash re-verification is the practical check) and QR-pinned encryption keys defer to the directory (a diverging directory `x25519` — the tamper signal — is resolved silently in the directory's favor by the §4.7 merge rule; pinned by tests/qr_identity.mjs (e)). **§13.6** gains the resource-exhaustion-as-censorship statement (a budget-compliant fill of the 5000-envelope store holds NEW mail off a node for up to TTL_MAX; mule transit-queue stuffing) and the evil-twin row now conditions "client-side crypto bounds the exposure" on the client code being genuine. **§4.7**'s trust model notes that directory key material overrides a QR-pinned contact's `x25519`. **§10.5**'s unknown-recipient bullet now describes the pull select accurately (it carries no hint parameter; no hint-scoped query exists to observe). The remaining documentation divergence found by the audit — the shipped per-node directory row cap (5000, `429 node_full`) is not yet reflected in §8.1/§9/§10.3 — is recorded in `docs/security-audit.md` (PROTO-08) and deferred to the next spec revision that touches those contracts.

- **1.12.1 (2026-10-05, issue #40 — RFC 4838 alignment audit cross-reference):** documentation-only. §16 (Conformance checklist) gains a closing paragraph stating that Offgrid implements the DTN *architecture* of RFC 4838 (store-carry-forward, endpoint naming, message lifetimes, opportunistic contacts) and deliberately not the IETF Bundle Protocol (RFC 5050 / RFC 9171) or BPSec (RFC 6257 / RFC 9172), and cross-referencing the new informational audit document `docs/rfc4838-alignment.md` (per-concept mapping table, verdicts, deviation register). No normative sentence changed: no envelope field, limit, canonical form, endpoint behavior or conformance requirement is touched, and the §3.2 example envelope (parsed verbatim by tests/sync_e2e.sh) is byte-identical. The document header version is corrected to 1.12.1 by this entry.

- **1.12.0 (2026-10-05, issue #37 — unknown-recipient behavior pinned normatively; offline-maintenance design cross-referenced):** added the **§10.5 "Unknown-recipient behavior" binding statement**: the sync push path NEVER consults the `directory` table; `dest_hint` is a one-way hash derivation (§6.1), not a directory key; an envelope whose `dest_hint` addresses no registered identity is STORED (§10.4 step 2, identical code path and caps), SERVED to any puller presenting that hint (§10.4 step 3), and EXPIRED by the §10.6 janitor if never claimed — rejection and bounce are FORBIDDEN (senders are anonymous to nodes, §4.2: nothing to bounce to), because any observable difference between a known-addressed and an unknown-addressed push would hand every client of the open AP a recipient-existence oracle (an information leak with no honest remedy). There is NO such difference by construction: admission is hint-shape-only, the `200` response is identical in status code, member set and `"status"` value whatever the hint addresses, and signature verification remains exclusively the recipient's post-decryption job (§4.3). This pins behavior the node has had since 1.0.0 so no future revision can tighten it into a recipient-existence check; the conformance test is §15.7 row q (`TestUnknownRecipientStoredServedExpired`, `node/internal/api/unknown_recipient_test.go`). Supporting pointers: §10.4 step 2 (the directory is never consulted), §13.2 node row (cannot learn which hints address registered users), §13.5 (recipient-existence probing closed by design — a standing constraint on the issue-#37 staging/federation endpoints), §16 Module B (no directory consultation anywhere on the envelope path), §15.4 (the designed-but-unbuilt issue-#37 endpoints and their design record `docs/offline-maintenance.md`). No envelope field, limit, canonical form or existing endpoint behavior changed — the statement makes existing, tested behavior normative. (The document header version, stale at 1.9.0 since the 1.10.0/1.11.0 revisions, is corrected to 1.12.0 by this entry.)

- **1.11.0 (2026-10-05, issue #36 — field-node status page: battery autonomy, system resources, store aggregates, load projections):** extended §10.7 (formerly the #31 health snapshot) into a complete field-node status surface, additive only. `GET /api/v1/health` gains five fixed members — `battery`, `system`, `software`, `store`, `projections` — governed by the binding **N/A convention** (an unavailable datum is JSON `null`, never `0`, never a guess; a whole member is `null` when its subsystem is absent). `battery` reads through the chain **I2C sensor (INA219/INA260-class, pure-Go SMBus over `/dev/i2c-N`, enabled only by the explicit `-battery-i2c`/`-battery-addr` flags) → Linux `power_supply` sysfs → coarse voltage estimate (configured full/empty anchors; the page MUST state the LiFePO4-4S flat-curve accuracy limit) → honest unknown**, carrying charge state, SoC with its provenance (`coulomb`/`voltage`), pack voltage, battery-centric current, the configured capacity, the alert band (`CHARGING`/`HEALTHY`/`LOW`/`CRITICAL`: LOW below the 30% overnight floor of `docs/hardware.md` §8, CRITICAL at the 20% DoD floor of §2.2, overridable), and the autonomy projection in hours and 24-hour nights down to the DoD floor at the measured draw (a coulomb counter) or the nominal ~1 W design load (`docs/hardware.md` §1) — `null` without `-battery-capacity-wh`; `health_percent` stays `null` without a full-vs-design BMS. `system` carries `/proc/loadavg` (plus the ≥-cores saturation indicator), `/proc/meminfo` memory, one `statfs` of the database volume (with the 50 MiB free-space floor warning), the first `/sys/class/thermal` temperature, `vcgencmd get_throttled` **only when the binary exists**, and `/proc/uptime` — every collector feature-detected, `null` elsewhere, never a request failure. `software` adds the display-only `schema_version_on_disk` (§15.3 `user_version`) and `pending_migration` (no update checking, ever). `store` adds the cumulative 1 h/6 h/24 h TTL-expiry buckets (pure `COUNT`s over the expiry index), the **aggregate-only `active_clients`** count (distinct write-path sources over a trailing 15 minutes, held in a capped RAM-only tracker fed exactly where the §10.1 budgets already handle the key; no key ever leaves it; diagnostics GETs do not count), and `counters_delta` (windowed request-counter deltas). `projections` computes once-per-minute-sampled sliding-window rates (pushes, TTL expiries, DB growth, battery drain per day) and the derived days-to-envelope-capacity, days-to-disk-full, store equilibrium (±1 envelope/day deadband) and multi-day battery net judgment — all from fixed-capacity RAM-only ring buffers (persistence rejected on purpose: nothing operational is written to disk; a reboot clears projections), under the binding **minimum-data rule**: `enough_data: false` and all-null until ≥ 2 samples span ≥ 30 minutes (battery net needs ≥ 24 h), rendered on the page as "not enough data yet" — never extrapolated from nothing. All new sampling runs on a background timer (default 60 s), never per request; the 1-second snapshot cache, the per-IP diagnostics budget, the 507 shed and the §13 aggregates-only constraint are unchanged and re-reviewed. `GET /status` extends to the same cards with `N/A` rendering everywhere. Battery flags are optional (`-battery-capacity-wh`, `-battery-dod-floor`, `-battery-full-v/-empty-v`); with none set the battery member is `null` — a stock Pi Zero W with zero extra hardware renders every section sensibly. Additive only: no frozen field, limit, canonical form or existing endpoint behavior changed.

- **1.10.0 (2026-10-05, issue #23 — end-user quick-start guide, printable and served by the node):** added the field-facing documentation surface the issue asked for, with ZERO protocol change (no envelope field, limit, canonical form, §8 cap or existing endpoint behavior touched). `docs/quick-start.md` is the new translatable master text: a non-technical, end-user-tone guide (each numbered step ≤ 2 short sentences, no idioms, translator note in the header — the installer's default region is Spanish-speaking; the UI is English-only today) answering the four documented onboarding confusions — the captive mini-browser vs. the full browser at `http://offgrid.local:8080` (§13.4), the seed as the identity (lost seed = lost account), delivery riding with people (TTL expiry 7 days, mule-dependent latency), and foreign envelopes as the mule engine working (§11) — with 10 numbered steps (join Wi-Fi → full browser → §12.1 home-screen icon → register → seed backup → §4.7 in-person QR contact or directory → compose with the §4.4 envelope-count preview → §4.5 queued/sent/delivered states → inbox + still-traveling partials → be a mule), a "what to expect" box (people are the transport; envelope-count cost against the 100-envelope mule queue; 7-day expiry; privacy ends at the recipient's device), a troubleshooting top-5 (portal does not open; opened by IP → the §10.2 redirect and origin fragmentation; lost seed; full 100-envelope transit queue; nothing arrives) and a 10-word glossary. The node serves the same guide at the new public endpoint `GET /guide` (§10.3): the embedded script-free `web/guide.html` (closed CSP — `default-src 'none'; style-src 'self'; img-src 'self'` — no JavaScript at all, like the §10.7 operator view but PUBLIC and linked from the portal footer "Guide", the one portal-visible addition; `/status` stays unlinked), its own stylesheet `web/css/guide.css` with an `@page`/`@media print` two-column layout that prints the 10-step core flow on ONE A4/Letter sheet (expectations + troubleshooting + glossary on the second sheet; 2 printed pages max), and 7 REAL SPA screenshots (register with the §13.4 banner, seed backup, composer with the byte/envelope counter, sent list with the delivered state, inbox, mule telemetry with foreign envelopes in transit, contacts QR) captured from the real portal served by a real dev daemon on the canonical origin and embedded under `web/img/guide/` (quantized PNGs ≤ 720 px wide, 325 KiB total — asserted < 600 KiB by the suite). Static serving extends the §10.3 asset row with the `img/` tree (exact-path, `image/png`, JSON 404/405, `Cache-Control: no-cache`) and startup fails closed on a missing `guide.html`. §15.7 row p, §16 Module B conformance extended. Additive only; the end-to-end acceptance (a first-time user completes register → send → receive with the guide alone) is validated in the issue #20 field test.

- **1.9.0 (2026-10-04, issue #29 — add-to-home-screen manifest, PWA-lite within the no-TLS constraint):** added §12.1 "Installability without a service worker — PWA-lite": the portal becomes installable/pinnable so a user keeps an "Offgrid" icon instead of typing `http://offgrid.local:8080` — with the honest boundary stated normatively: a full PWA (service-worker offline shell, background sync) is architecturally unreachable in Phase 1 because service workers are unavailable on insecure non-localhost origins and plain HTTP is a deliberate §12 decision, so the icon is a SHORTCUT, not an offline app. What ships is PWA-lite, all embedded and same-origin (§10.3 static-asset row added, covering css/js/manifest.json/icons: exact-path serving, `text/css`/`text/javascript`/`application/manifest+json`/`image/png` content types, `Cache-Control: no-cache`, JSON 404/405 like every other path, §10.2 redirect first): a web app manifest `/manifest.json` (name "Offgrid Messages", short_name "Offgrid", `start_url` "/" and `scope` "/" deliberately RELATIVE — the origin is identical on every node, so ONE pinned icon opens the canonical origin anywhere, no hardcoded host, no storage fragmentation; `display` "standalone"; `theme_color` `#0b6e4f`/`background_color` `#f4f6f8` from the portal palette; icons 192+512 with `purpose` `"any maskable"`, motif inside the maskable safe zone; NO service-worker member, no `beforeinstallprompt` hijacking), self-hosted PNG icons `/icons/icon-192.png` + `/icons/icon-512.png` (+ `icon-180.png` for iOS, which ignores the manifest) generated deterministically by `tools/gen_icons.mjs` and committed (envelope glyph on the accent background, readable at 48 px, zero external requests — CSP `img-src 'self'` intact), the iOS meta tags (`apple-mobile-web-app-capable`, `apple-mobile-web-app-status-bar-style`, `apple-mobile-web-app-title`, `apple-touch-icon`) plus the manifest link and `theme-color` in the portal HTML, and a dismissible install hint in the UI following the §13.4 banner pattern: per-platform wording (Android: browser menu → "Add to Home screen"; iOS Safari: Share → "Add to Home Screen"), persisted dismissal in the device-local meta store, silent in captive mini-browsers, WebView-like environments and on desktops, with the honesty note verbatim ("The icon opens the portal when you are on the node's Wi-Fi — it is a shortcut, not an offline app."). The decision path for a future phase is recorded: the SW offline shell becomes possible only if TLS is revisited (per-node self-signed + user trust — which reverses a §12 tradeoff AND changes the origin scheme, fragmenting existing IndexedDB without a designed migration) or a Phase 2 native app (§14) ships a real shell. §13.4 pointer, §15.7 row o (manifest members + relative start_url + icon dimensions + no-external-URLs + canonical 301), §16 Module B (static-asset surface) and Module C (hint) conformance extended. Additive only: no frozen field, limit, envelope-format, hint-derivation or existing endpoint behavior change; tests/pwa_assets.mjs added and sync_e2e.sh extended (Makefile `test`, docs/BUILD.md §4).

- **1.8.0 (2026-10-04, issue #28 — identity QR, in-person contact exchange):** added §4.7 "Identity QR — in-person contact exchange": two people who meet exchange identities by showing and scanning a QR code (alias + Ed25519 signing key + X25519 encryption key + a checksum) instead of relying solely on the node directory or typing key strings — a CLIENT-SIDE payload convention with ZERO wire change (no envelope field, canonical form, §8 limit or node behavior touched). The QR text is `OFFGRID1:<Base64(JSON)>` (§3.3 Base64) where the JSON object carries exactly `v` (1), `alias` (§8.1 regex), `ed` (the publisher's Ed25519 identity key — the contact's identity), `x` (the X25519 encryption key), `ts` (unix seconds, ≤ 300 s in the future per the §4.3 skew), `sig` (Ed25519 detached signature by the publisher's `ed` key) and `crc` (8 lowercase hex). The signature AND the CRC-32 cover the NEW canonical signed string `{"v":1,"alias":<alias>,"ed":<ed>,"x":<x>,"ts":<ts>}` (fixed member order, §5 rules; §5.1 pointer added); the CRC is the standard IEEE 802.3/zlib CRC-32 and sits OUTSIDE the signature deliberately — scan/paste corruption surfaces instantly as a CRC mismatch while tampering still fails the Ed25519 check. Worked vector pinned (identity = the RFC 8032 §7.1 key, 145-byte canonical string, crc `d76a4d73` INDEPENDENTLY cross-checked with Python's zlib.crc32, 357-character payload). Importer procedure normative in ten ordered steps (prefix → Base64 → JSON → member set → version → alias regex → key lengths → ts → CRC → signature); every failure is rejected with a VISIBLE error naming the reason and NOTHING is stored — the documented, deliberate opposite of the §4.3 silent discard (an in-person exchange has the user looking at the screen; envelope damage stays silent). Rendering: the vendored `qrcode-generator` 1.4.4 (MIT, `node/web/js/vendor/qrcode.js` with provenance header — zero external assets, same vendor discipline as tweetnacl) renders byte mode, versions 1..15, ECC level M to a `<canvas>` with a 4-module quiet zone; the maximum identity payload (377 chars at a 24-char alias) fits version 15 and NO prekeys travel in the QR (they would triple its size). Contacts are device-local: the additive-only, idempotent IndexedDB migration v5 adds the `contacts` store (§15.6 chain, DB_VERSION 5) keyed by the contact's Ed25519 key — `{ed, x, alias, added_at, source ("qr"|"paste")}` — and the recipient picker merges contacts ∪ directory DEDUPED by the Ed25519 key, offline-first (contacts are offered even when the directory fetch fails; the directory supplies the fresh key material — §4.6 bundle and §6.1 epoch — when an entry exists, while a contact-only recipient is addressed with the §4.6 identity fallback and the §6.1 offline-cold static hint). Scanning feature-detects the native `BarcodeDetector` + `getUserMedia` (Android Chrome — the realistic full-browser side; NO vendored decoder) and every unsupported environment (iOS Safari, desktop, captive mini-browsers) shows an honest notice directing to the paste fallback, which feeds the identical parser. Trust model normative: an in-person scan is trust-on-sight of the person showing the code (tampering and corruption are detectable; a malicious publisher is not — scanning a stranger's QR stores exactly the keys it shows); aliases are cosmetic and not unique (identity = the Ed25519 key); no revocation in Phase 1. §11 client summary extended (merged recipient picker, Contacts tab, camera/paste import), §15.6 chain extended to v5, §15.7 row n (the directory-free two-way exchange, the visible tamper rejection and the encoder's round-trip through an independent QR decoder across versions 1-15), §16 Module C conformance extended. Additive only: no frozen field, limit, canonical inner form, envelope-format or hint-derivation change; tests/qr_identity.mjs added to the suite (Makefile `test`, docs/BUILD.md §4).

- **1.7.0 (2026-10-04, issue #27 — prekey bundles, forward secrecy):** added §4.6 "Prekey bundles — bounded forward secrecy": a later compromise of a user's long-term X25519 key no longer decrypts envelopes that were captured earlier and addressed to a CONSUMED one-time prekey. The envelope format is untouched (zero wire change — the §3.1 payload stays `eph_pub ‖ nonce ‖ box`): each client publishes an additive `prekeys` member in its directory entry — `v` (1), `spk` (signed medium-term X25519 prekey, rotated every 30 days on the `ts` anchor), `spk_sig` (Ed25519 detached signature by the entry's identity key over the NEW canonical bundle string `{"b":1,"k":<k>,"spk":<spk>,"ts":<ts>,"opk":<count>}`, fixed member order, worked vector pinned with the RFC 8032/RFC 7748 test keys), and `opks` (8..16 one-time prekey publics, target stock 12). Senders verify shape AND signature client-side (the node never verifies, §1) and target a random OPK, else the SPK, else the identity X25519 key (legacy fallback — also the behavior for missing or tampered bundles, the latter surfacing a UI warning; the signature closes the malicious-node doctored-bundle attack); `dest_hint` stays derived from the STABLE identity key (§6.1 note). Recipients trial-decrypt in fixed order identity → SPK → unconsumed OPKs (first success wins; identity remains a PERMANENT candidate, so old-sender mail keeps arriving without forward secrecy — the documented transition tradeoff) and WIPE the OPK secret synchronously on use — the forward-secrecy event, with a tombstone list preventing re-seeding; the second envelope to a consumed OPK is silently lost (bounded by the 8..16 stock). Lifecycle: prekey secrets are fresh random pairs (never derived from the identity seed), device-local in the additive idempotent IndexedDB migration v4 (`prekeys` store: SPK secret, unconsumed OPK secrets, tombstones); replenish runs inside the sync flow below the low-water mark (≤ 4 remaining) or on stale SPK — fresh batch, best-effort re-POST of the own entry, atomic stock swap, old-batch secrets wiped (in-flight mail to a replenished batch is silently lost, bounded by the low-water policy). Node changes are additive and blindness-preserving: storage schema VERSION 4 (forward-only migration 3→4 adds nullable `directory.prekeys TEXT` — pre-existing rows read NULL, nothing rewritten; downgrade refusal unchanged), POST /api/v1/directory accepts the OPTIONAL `prekeys` member with BLIND shape validation (`v == 1`, Base64 32/64-byte `spk`/`spk_sig`, ts > 0, 8..16 OPKs of 32 bytes, whole member ≤ 2048 bytes → else `400 invalid_prekeys`; NO signature verification), a POST without `prekeys` clears the column (the downgrade self-heal), and GET /api/v1/directory returns the bundle verbatim when present (§8.1 NOTE: ≤ 2 KiB per entry, worst-case 500-entry response ≈ 1 MiB). tweetnacl fit: `crypto_box`'s internal `X25519(eph, target)` alone provides the FS property once the target prekey secret is wiped — no new KDF, no new primitives (design record: `docs/forward-secrecy.md`). §5.1 pointer, §8.1 note, §9/§10.3/§11 client summary, §13.2/§13.5 residual risks (identity-key mail stays FS-free; OPK loss windows; doctored bundles), §15.3 row 4, §15.5/§10.7 examples at schema_version 4, §15.7 rows j–m, §16 Module B/C conformance extended. Additive only: no frozen field, §8 limit (beyond the documented GET-size NOTE), canonical inner form, envelope-format or hint-derivation change.

- **1.6.0 (2026-10-04, issue #26 — rotating `dest_hint`):** replaced the static `dest_hint` addressing (first 8 bytes of `SHA-256(X25519 pubkey)` — permanently linkable by any directory-holding node operator, the former §13.3 accepted risk) with a time-bounded derivation: `dest_hint(E) = lowercase_hex(HKDF-SHA256(ikm = X25519 public key (raw 32 B), salt = E as 8-byte big-endian, info = "offgrid-dest-hint", L = 32)[0:8])`, with E = `floor(unix_seconds / 86400)` a 24-hour UTC epoch defined on the NODE's clock (nodes have no NTP; the node is the shared reference). Senders derive the hint from the directory ENTRY's server-set `epoch` (per-entry = freshest truth); recipients recognize the candidate set {static legacy hint, hint(E), hint(E−1)} locally — E the highest epoch observed from node data (capabilities/directory), device clock offline-cold — so exactly one epoch boundary is crossed without message loss. Transition window: the legacy static hint stays a recognition candidate until the fixed spec deadline `HINT_TRANSITION_DEADLINE = 1795996800` (2026-11-30T00:00:00Z, ≈ TTL_MAX after rollout), after which new builds stop recognizing it and pre-1.6 senders' mail no longer arrives (documented honestly; their SPA refreshes from any visited node, so the practical exposure is days). Node changes are additive and blindness-preserving: storage schema VERSION 3 (`PRAGMA user_version`, forward-only migration step 2→3 adds `directory.epoch INTEGER NOT NULL DEFAULT 0` — backfilled 0 is deliberately stale, meaning "legacy addressing" until re-publication; the §15.3 chain, downgrade refusal and the no-payload-rewrite rule unchanged), the directory upsert stamps `last_seen = now` AND `epoch = floor(now / 86400)` server-side (POST body shape unchanged — clients cannot influence the epoch), `GET /api/v1/directory` returns the additive `epoch` member (§15.4: unknown members ignored by old clients), and `GET /api/v1/capabilities` gains the additive members `hint_epoch_seconds` (86400) and `hint_epoch_current`. HKDF-SHA256 is implemented exactly per RFC 5869 on the already-vendored SHA-256 (HMAC-SHA256 built on it; no new vendored library — tweetnacl has no HKDF); §6.1 pins a full worked vector (key, epoch, PRK, OKM, hint) plus the previous-epoch hint, and the RFC 5869 Appendix A cases pin the primitive. §13.3 is rewritten from "ACCEPTED RISK" to the post-fix residual record: an operator recomputing hints from directory data can match envelopes of the CURRENT epoch only, never older ones — linkability decays with epoch rotation; residuals stated honestly (within-epoch linking, public directory epochs, transition-window legacy hints, untouched timing analysis). §8 limits, the envelope format (§3/§14.1 frozen fields), the canonical forms (§5) and every chunking/ack convention (§4.4/§4.5 strings byte-identical) are unchanged; admission still accepts any `^[0-9a-f]{16}$` hint with no hint-vs-key validation (the node cannot know a hint's epoch), and rotating hints change NO §8.1/§10.1 cap. §15.7 gains rows g (rotation across a boundary with in-flight delivery + RFC 5869/§6.1 vector pinning), h (legacy candidate recognition before the deadline) and i (candidate-set drop after the deadline); §16 Module B/C conformance extended. Old envelopes remain valid until TTL expiry sweeps them; old clients keep working during the transition window per the §18/§15 compatibility policy.

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
