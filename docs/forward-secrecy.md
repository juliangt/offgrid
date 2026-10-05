# Forward Secrecy via Prekey Bundles — Design Record (issue #27)

| | |
|---|---|
| **Issue** | #27 — forward secrecy for the inner payload |
| **Status** | Implemented; the normative text lives in `docs/protocol.md` §4.6 (spec **1.7.0**). This document is the design record: why the scheme looks the way it does, the exact derivations, the quantified overheads and the honest limits. Where this record and the spec disagree, the spec wins. |
| **Scope** | Bounded, asynchronous forward secrecy (FS) via an X3DH-flavored prekey bundle published in the node directory. Full Double Ratchet is explicitly OUT of scope, as are deniable authentication and post-compromise security beyond the prekey horizon. |

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119/8174 where
this record restates normative behavior.

---

## 1. The problem

Current construction (§4.2 of the pre-1.7 spec): every message is encrypted
with `crypto_box(inner, nonce, recipient_LONG_TERM_X25519_pub, eph_sec)` — a
per-message ephemeral on the sender side only. The recipient secret is the
long-term identity X25519 key and never changes. Consequence: an adversary who
records envelopes sitting in dead drops or mule queues (they sit for up to
`ttl`, 30 days by default) and LATER extracts the recipient's long-term X25519
secret decrypts every captured envelope. There is zero forward secrecy.

The fix pattern is the Signal/X3DH "prekey" idea, adapted to a world with no
online key server: the closest thing to a key server here is the node's public
directory (§10.3), which is already the publish/read point for identity keys.

## 2. Threat model recap (see §13 of the spec)

Nodes and mules are hostile, blind channels: they record everything, can serve
stale or doctored directory entries, and may later be physically extracted
(database seized). The long-term identity seed is the asset whose compromise we
bound the damage of. We do NOT defend against an adversary who extracts
IndexedDB secrets from the recipient's own device (that keychain holds the
prekey secrets too) — the goal is strictly: **captured traffic must not become
readable after a LATER compromise of the long-term key**.

## 3. The scheme in one paragraph

Each client publishes, inside its directory entry (additive member `prekeys`),
a bundle: one **signed medium-term prekey (SPK)** — an X25519 key pair rotated
every 30 days — plus a stock of **one-time prekeys (OPKs)**, 8..16 X25519 key
pairs whose secrets are wiped the moment an envelope opens through them. A
sender encrypts the inner payload to ONE key chosen from the recipient's
bundle — a random OPK when available, else the SPK — instead of to the
long-term identity key. The envelope format is untouched: the box simply
targets a different public key. The recipient recognizes its mail by the
unchanged §6.1 `dest_hint` (still derived from the STABLE identity key), then
trial-decrypts with its identity secret (legacy path, kept forever), its SPK
secret, and each unconsumed OPK secret — first success wins, and the secret
that opened the envelope is wiped synchronously. That wipe IS the
forward-secrecy event: afterwards, no amount of long-term-key compromise
opens that envelope.

## 4. Bundle schema (published, additive `prekeys` member)

```json
prekeys: {
  "v": 1,                     // bundle schema version (§15-style; unknown v → treat entry as bundle-less)
  "spk":      "<b64 32B>",    // signed medium-term prekey public (X25519)
  "spk_sig":  "<b64 64B>",    // Ed25519 detached signature by the entry's identity key
  "ts": <unix seconds>,       // bundle publication time (the SPK TTL anchor)
  "opks": ["<b64 32B>", ...]  // one-time prekey publics, 8..16 entries
}
```

Binding constraints (the node validates this shape blindly, clients enforce it
too): `v == 1`; `spk` is Base64 (§3.3 padded standard alphabet) of exactly 32
bytes; `spk_sig` Base64 of exactly 64 bytes; `ts` an integer > 0; `opks` an
array of 8..16 Base64 strings each decoding to exactly 32 bytes; the whole
serialized member ≤ 2048 bytes (the node rejects oversize bundles with
`400 invalid_prekeys`). Unknown members inside `prekeys` are ignored (§15.4
additive policy). A `prekeys` member that fails the shape check is stored
never — the node answers 400; a `prekeys` member received in a directory GET
that fails the CLIENT-side shape or signature check is treated as absent
(bundle-less → identity fallback) by senders.

### 4.1 The signature and its canonical string

The signature binds the medium-term prekey to the directory entry's identity
key. Signed byte string — canonical JSON per §5 (UTF-8, fixed member order,
integers in minimal decimal form, minimal escaping — Base64 values need no
escaping):

```
{"b":1,"k":<identity Ed25519 public, Base64>,"spk":<spk, Base64>,"ts":<ts>,"opk":<count of opks>}
```

Signed with `nacl.sign.detached` by the identity **Ed25519** secret key (the
same key that signs inner payloads, §5.1). `k` is included so a bundle cannot
be replayed across identities; `ts` anchors rotation; the OPK **count** (not
the OPKs themselves) is bound because OPK stock rotates independently of the
SPK — re-binding each OPK would make OPK replenishment invalidate the SPK
signature. OPKs need no individual signature (standard X3DH reasoning: an OPK
is only ever an extra DH input; tampering with it can at worst break
decryption for that envelope, never authenticate an attacker — the SPK
signature plus the MAC cover authentication).

**Worked vector** (pinned by tests/prekeys.mjs; identity = the RFC 8032 §7.1
test key, whose public is the §4.1 example `k`; SPK = the RFC 7748 §6.1 "Bob"
X25519 public):

| Item | Value |
|---|---|
| identity Ed25519 public `k` | `11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=` |
| `spk` | `3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08=` |
| `ts` | `1791072000` |
| `opk` | `12` |
| Canonical string (136 bytes) | `{"b":1,"k":"11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=","spk":"3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08=","ts":1791072000,"opk":12}` |
| `spk_sig` | `2TtmiNYcVcX0QpegeLuAnOCzNChs4L6z2iEu9TuuoprjZa8c5ULQtph1UWWTcrweXqs61iLEX0o2xqTVPW6HBg==` |

Changing any byte of the canonical string (e.g. `ts → 1791072001`) fails
`nacl.sign.detached.verify`.

### 4.2 Why the FS property needs no new KDF — the tweetnacl fit

The "X3DH flavor" of this scheme comes entirely from WHICH key the box
targets, not from any new derivation. tweetnacl's `crypto_box(m, nonce,
target_pub, eph_sec)` performs X25519(eph_sec, target_pub) internally and
feeds it (with the ephemeral public) into XSalsa20-Poly1305 — i.e. the shared
secret is exactly `DH(eph, chosen_target)`. When `chosen_target` is a prekey
whose secret is later wiped, the box becomes unopenable by anyone who holds
only `DH(eph, identity)` material — which is all a long-term-key extractor
can derive, because the envelope never travels under the identity key at all.
There is deliberately NO concatenation/KDF of `DH(eph,OPK) ∥ DH(eph,SPK) ∥
DH(eph,identity)` as in full X3DH: that construction exists in Signal to
authenticate an interactive session and to survive identity-key replacement;
here the envelope is a single asynchronous box, authentication comes from the
signed inner payload (§4.1–§4.3, unchanged), and simplicity is worth more
than session ratcheting. tweetnacl covers everything needed — `box`,
`box.open`, `box.keyPair`, `sign.detached`, `sign.detached.verify`; no new
primitives, no new vendored code. Trial-decrypt cost: an envelope for a
stocked recipient costs at most `1 + 1 + 16` failing/succeeding `box.open`
calls (identity, SPK, ≤ 16 OPKs) — microseconds in JS, trivial next to the
IndexedDB I/O around it.

## 5. Sender rules (binding)

1. Resolve the recipient's directory entry (§10.3). Read `prekeys`.
2. Bundle validity, client-side: shape per §4 above AND `spk_sig` verifies
   over the canonical string with the entry's `pubkey` (the sender checks the
   signature because the node is blind and never verifies — §1; this is what
   closes the malicious-node-serves-a-doctored-bundle attack, §8.1 below).
   Invalid or missing → **bundle-less**: target the identity X25519 key
   (legacy addressing, byte-identical to the pre-1.7 construction).
3. Valid bundle → prefer a ONE-TIME prekey: uniform-random choice among the
   published `opks` (rejection sampling over `crypto.getRandomValues`).
   If `opks` is empty/absent on an otherwise valid bundle → the SPK.
4. Build the envelope exactly per §4.2 with
   `recipient_key = chosen prekey public`. `dest_hint` and `id` are
   UNCHANGED: `dest_hint = hint_E(identity_X25519_pub)` per §6.1 — derived
   from the STABLE identity key, never from a prekey (the directory operator
   sees prekey publications too; a prekey-derived hint would rotate with
   replenishment and give a hint table a second life).
5. The sender never learns whether the target OPK was later consumed; mail to
   a consumed/rotated OPK is silently lost (§8.2) — bounded and accepted.

## 6. Recipient rules (binding)

1. Classification is unchanged: a pulled envelope is "mine" iff its
   `dest_hint` is in the §6.1 candidate set {static legacy hint (window),
   hint(E), hint(E−1)} — all derived from the identity X25519 public.
2. Trial-decrypt in FIXED order, first success wins:
   1. identity X25519 secret (the legacy path — permanent candidate; this is
      what makes old-sender mail keep arriving, §7);
   2. current SPK secret;
   3. each unconsumed OPK secret.
   All failures → discard silently (§4.3, unchanged).
3. **Wipe-on-use:** the secret that opened the envelope is wiped
   synchronously as part of handling the decrypt — an OPK secret is deleted
   from the device's prekey store and its public joins a tombstone list (so a
   replayed/stale bundle can never re-add it). This is the FS event. The
   SPK secret is NOT wiped on use (it is medium-term by design; its FS
   horizon is its rotation, §9).
4. The decrypted result records locally which key opened it
   (`identity` | `spk` | the OPK's public key) for the store update and for
   tests; it never travels on the wire.

## 7. Compatibility (normative in spec §4.6)

| Direction | What happens | Result |
|---|---|---|
| Old sender → new recipient | The old client ignores the unknown `prekeys` member (§15.4) and addresses the identity X25519 key. The recipient's identity trial path is permanent. | Delivered; NO forward secrecy for that envelope (honest tradeoff, documented). |
| New sender → old recipient | The old recipient's entry carries no `prekeys` → bundle-less → identity addressing. | Delivered. The race "bundle published, then recipient downgraded" is accepted: the downgraded client still holds its SPK/OPK secrets? No — a DOWNGRADED (old-code) client never had prekey secrets; a bundle whose owner reverted is one whose OPKs are unusable. Mail sent prekey-addressed to a reverted client is silently lost until re-addressing; the window is one publish cycle. Accepted and documented. |
| Tampered bundle (client-side sig check fails) | Sender treats the entry as bundle-less (identity fallback) and the UI surfaces a warning in the contact view. | Delivered, no FS, visible warning. |

## 8. Attack analysis

### 8.1 Malicious node serving doctored bundles

A malicious node can serve a sender a bundle whose `spk`/`opks` it generated
itself, hoping mail lands under keys it holds. The sender's signature check
fails (the node cannot forge Ed25519 over the canonical string) → identity
fallback + UI warning. Mail still flows (availability preserved) with no FS
against the long-term key, and the operator's tampering is detectable by the
client. Residual, pre-existing and unchanged: the node can already swap the
`x25519` member of any entry (directory entries are not authenticated
end-to-end in Phase 1 — §13); the bundle signature does not close that hole,
and closing it (key transparency) is out of scope.

A node serving a STALE (older, still-validly-signed) bundle can only cause
mail to target OPKs the recipient may have already consumed/rotated → silent
loss (§8.2), never decryption by the node.

### 8.2 OPK collision and in-flight loss

Two senders may pick the same OPK (only 8..16 choices, chosen without
coordination). First delivery wipes the secret; the second envelope trial
fails and is silently lost. Loss is bounded by stock size (the probability
scales with concurrent senders ÷ stock) and self-heals at replenish. Related,
honest: replenishment REPLACES the whole OPK batch (one batch at a time, the
published stock and the local secret stock stay in lockstep), so an envelope
in flight addressed to the previous batch when replenishment lands is lost
silently. Mitigation is policy, not crypto: replenish only below the
low-water mark, so the expected loss window is short relative to delivery
time. These losses are indistinguishable from ordinary DTN loss (TTL expiry,
mule FIFO) — the system's baseline is best-effort mail.

### 8.3 Replay

Replaying an already-consumed OPK envelope fails the trial (secret wiped) and
is discarded silently — strictly better than the legacy path, where replay is
absorbed only by envelope-id dedup (§13.5).

### 8.4 What the signature does NOT give

No deniability properties are claimed or lost (the inner payload keeps the
§4.2 sign-then-encrypt construction); no PCS: once an attacker holds the
long-term key AND a live prekey secret, mail until the next rotation is
readable. The horizon is §9.

## 9. Forward-secrecy horizon (honest statement)

- Envelopes addressed to CONSUMED OPKs: safe forever after the wipe — this is
  the acceptance criterion (capture-then-extract fails).
- Envelopes addressed to still-held OPKs/SPK: readable by whoever later
  obtains the device store; readable by a long-term-key extractor only while
  the box target secret is held — prekey secrets do NOT derive from the
  identity seed (fresh `crypto.getRandomValues` per key), so extracting the
  long-term key alone never opens a prekey envelope.
- Envelopes addressed to the identity key (old senders, fallbacks): zero FS,
  permanently.
- Horizon = OPK stock lifetime (consumption + low-water replenish) + SPK
  rotation (30 days). A recipient that stops syncing keeps its stock on the
  published directory; its FS horizon freezes there.

## 10. Lifecycle state machine

States of the device-local prekey store (one record, `IndexedDB` store
`prekeys`, created by the additive idempotent DB migration v4, §15.6):

```
ABSENT  (fresh identity / no bundle yet)
  │ registration or first sync
  ▼
ACTIVE ── spk = {pub, sec, published_at}        opks = [{pub, sec}, ...]
  │         tombstones = [pub, ...]             (secrets never leave the device)
  │
  ├─ decrypt opens through opk P ──► wipe sec(P), tombstone += P   (per envelope, synchronous)
  │
  ├─ sync-time check (after pulls):
  │     spk stale (now − published_at > 30 d) OR #opks ≤ 4 (low-water)
  │     → generate fresh batch (new SPK pair if stale, new OPK batch)
  │     → re-POST own directory entry (alias, keys, prekeys)
  │     → on 200: swap local stock atomically, wipe ALL old batch secrets
  │       on failure: keep old stock, retry next sync (best-effort)
  ▼
ACTIVE (rotated)
```

Replenish rides the existing directory upsert (no new endpoint). OPK stock
target: 12 (mid-range of the 8..16 admission window). Old OPK secrets are
wiped at replenish time, not at use time, when they leave the published stock
— one batch at a time keeps published stock and secret stock identical, so
"which OPKs could still open mail" has a single answer on the device.

## 11. Quantified overheads

**Bundle row size** (the serialized `prekeys` member):
`187 + 47·n − 1` bytes for n OPKs (fixed part 187: `"v":1` + `"spk"`(44-char
b64) + `"spk_sig"`(88-char b64) + `"ts"` + framing; each OPK entry is a
44-char b64 string plus quotes and a comma).

| n | bundle bytes |
|---|---|
| 8 | 562 |
| 12 (target) | 750 |
| 16 | 938 |

Node admission cap: 2048 bytes — comfortable headroom over the 938-byte
worst case. Per directory row the bundle adds ≤ 2 KiB (enforced) ≈ 750 B
(typical).

**Directory GET size** (§8.1 note): the 500-entry cap is unchanged. Worst
case 500 × (entry ≈ 120 B + bundle ≤ 2 KiB) ≈ **1.0 MiB**; with the shipped
target stock the realistic worst case is 500 × ≈ 0.87 KiB ≈ **0.44 MiB**.
Documented honestly in §8.1; no compression, no pagination in Phase 1 (mules
fetch on Wi-Fi, and the response is already capped by the entry limit).

**Registration overhead**: one identity now also generates 1 SPK + 12 OPK
pairs (13 × `nacl.box.keyPair()` ≈ negligible) and the POST body grows by
≈ 750 B — far under the 1 MiB body cap.

**Replenish frequency**: a batch of 12 with low-water 4 triggers after ~8
consumptions, i.e. roughly every 8 received messages; a burst that delivers
≥ 8 messages in one sync replenishes once per sync = ONE extra directory
POST (≈ 1 KiB) per sync worst case. SPK rotation adds at most one replenish
per 30 days beyond that.

**Node storage**: 500 rows × ≤ 2 KiB ≈ ≤ 1 MiB extra SQLite bytes worst case —
noise against the 5000-envelope × ~0.7 KiB envelope store.

## 12. Storage lifecycle (client, §15.6 chain)

`DB_VERSION` 3 → 4: new object store `prekeys` (single record keyed
`"stock"`), strictly additive — no existing store or record is touched. The
record holds: `spk {pubB64, secret, published_at}`, `opks [{pubB64, secret}]`
(unconsumed only — the store IS the "local secret stock"), `tombstones
[pubB64]` (consumed/rotated pubs, so a stale published bundle can never
re-seed a wiped OPK). Secrets are `Uint8Array`s from `crypto.getRandomValues`
(§7.2), never derived from the identity seed, never leaving the device.
Wipe-on-use and replenish-swap run inside readwrite transactions (atomic;
crash leaves either old or new stock, never a mix).

## 13. Test coverage (acceptance mapping)

| Acceptance criterion | Where |
|---|---|
| Capture-then-extract long-term key cannot decrypt post-prekey mail | tests/prekeys.mjs (FS proof: OPK-addressed envelope + identity-secret-only decrypt → fail; post-wipe full state → fail); sync_e2e.sh §16 (served bytes, real daemons) |
| Registration/directory overhead quantified | this document §11; spec §8.1 NOTE; sync_e2e.sh asserts the round-tripped bundle size ≤ 2 KiB |
| Migration old↔new both directions | tests/prekeys.mjs interop legs; sync_e2e.sh legacy + old-client legs |
| Node blind validation matrix, oversize 400, GET round-trip | node/internal/api/api_test.go (TestDirectoryPrekeys*), storage_test.go (TestSchemaV3MigratesToV4PreservesDirectory) |
| Selection (OPK > SPK > identity), trial order, wipe-on-use, replenish, tampered-sig fallback, bundle signature vector | tests/prekeys.mjs |
| Chunking + acks over prekey-addressed envelopes | tests/prekeys.mjs integration cases |

## 14. Explicitly out of scope

Full Double Ratchet (no per-message DH ratchet, no skipped-key store);
deniable authentication; post-compromise security beyond the prekey horizon;
authenticating directory entries end-to-end (key transparency); message-format
changes of any kind (the envelope stays byte-compatible §3.1; prekeys change
only which public key the box targets).
