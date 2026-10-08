# Node Network Specification — Off-Grid DTN Node Plane (issue #33)

| | |
|---|---|
| **Version** | 1.6.0 |
| **Date** | 2026-10-07 |
| **Status** | **Normative — BINDING for all Phase 3 node-plane implementations (P3.1–P3.9).** The user-plane formats of `docs/protocol.md` §3–§15 remain byte-frozen and untouched; this document governs only the node plane defined below. |
| **Scope** | The two-plane model, node identity/roles/authority, the Offgrid BPv7 profile (RFC 9171 subset) with measured byte budgets, the LoRa convergence layer (radio plan, MAC, link security), forwarding and storage, the management plane, updates and directory federation over the plane, and the node-plane threat-model delta. |
| **Source of the byte math** | Every byte and airtime number in §4–§6 is measured by `node/internal/bundle/spike.go` (issue #33 P3.0) and pinned by its tests; re-run `go test ./internal/bundle -run TestSpike -v` to reproduce the tables. |
| **Related** | #33 (this), #37/#39 (ESP32 platform — the fleet baseline), #37 (`docs/offline-maintenance.md` — capsules, staging, directory cards), #40 (`docs/rfc4838-alignment.md` §8 — amended §1.3), #32 (Phase 2 BLE), #22 (apply/rollback) |

The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are to be interpreted as described in RFC 2119 and RFC 8174.

---

## 1. Scope: the two-plane model

The network has two planes with different trust models. The split is the design: it lets nodes talk to each other **without** touching any property the Phase 1 security posture rests on.

| | **User plane (existing, frozen)** | **Node plane (this document)** |
|---|---|---|
| Carries | User mail envelopes | Bundles between nodes: mail, management, updates, directory records |
| Endpoint identity | Key possession only (`dest_hint`), sender/recipient never on the wire | Pseudonymous node EIDs derived from node keys (`dtn://og.<fingerprint>/`, §2.1) |
| Blindness | Nodes stay blind mailboxes (protocol §1/§13) | Nodes are identified, authenticated peers |
| Crypto | Sign-then-encrypt E2EE inside every envelope (§4.2, invariant) | Authenticated encrypted link sessions (§6) + COSE-signed management objects (§8) |
| Wire format | §14.2/§14.3 CBOR envelope + 1-byte fragment header — **byte-frozen** | Offgrid BPv7 profile, RFC 9171 subset (§3) |
| Threat | protocol §13 | §10 (additive delta only) |

### 1.1 What is pinned and untouched

The node plane MUST NOT change: the envelope format and its frozen fields (§14.1/§15.1), sign-then-encrypt (§4.2), the blind dead-drop semantics (§10.4/§10.5), the §14.3 short-message and 2-frame window formats, the mule model, the HTTP API surface (§10.3 — additive members only), and the staging/anti-rollback/federation semantics of `docs/offline-maintenance.md` §2.4/§2.6 and §3.4. A mail envelope crossing the node plane in either direction MUST do so byte-unmodified (same `id`, same TTL — no life extension); this is the §33 acceptance gate and §11 pins it.

### 1.2 Relationship to the user plane

The user plane's §14.2 CBOR envelope is the mail-bundle payload of this plane (§3.3), carried verbatim. Envelope `id` dedup (§6.2/§10.4) remains authoritative end-to-end; the bundle-layer `bundle_id` (§3.5) dedups node-plane relaying only and adds no identity field the user plane does not already expose.

### 1.3 Amendments to recorded decisions (owner-approved 2026-10-07)

1. **`docs/rfc4838-alignment.md` §8** declared the project "architecture-conformant, protocol-independent" and rejected Bundle Protocol adoption. That verdict stays true **for the user plane** and is untouched. The amendment is node-plane-only: the node plane speaks a frozen BPv7 profile — exactly the audit's named honest path ("a convergence-layer-style gateway speaking BP at the edge"). Mail bundles travel with `source`/`report-to` = `dtn:none`, so the bundle layer carries no identity the user plane doesn't already expose.
2. **`docs/offline-maintenance.md` §2.8** said "no LoRa capsule transport, ever in this design". Amended: capsules **MAY** ride the node plane under the §9 admission budgets, with Wi-Fi remaining the bulk path. The capsule format v1 (§2.1), staging semantics (§2.4), signature verification and anti-rollback policy (§2.6) of that document are reused **verbatim**; only the delivery path is extended. (That document is a design record; its code does not exist yet — this spec references the design, not an implementation.)

## 2. Node identity, roles and authority

### 2.1 Self-certifying node EID

A node's identity is an Ed25519 key pair (`node_key`). Its EID is derived — never chosen:

```
fingerprint = lowercase_hex( SHA-256(node_key public)[0:8] )    — 16 hex chars
node EID    = dtn://og.<fingerprint>/
```

The EID is pseudonymous (a key fingerprint) and rotatable only by rekeying (which is a new identity, §2.5). Verifiers MUST check the binding: the EID's `<fingerprint>` MUST equal `SHA-256(node_key)[0:8]` of the certified key. Key rotation produces a new EID and requires a new role certificate (§2.4).

### 2.2 Role certificate

A node's authority is proven by a **role certificate**: a CBOR map wrapped in a **COSE_Sign1** (RFC 9052) signed by the **anchor key** (the offline trust root, §2.3). Schema, fixed key order:

| CBOR key | Field | Type | Constraint |
|---|---|---|---|
| 0 | `v` | uint | MUST be `1` (cert schema version; unknown `v` → invalid). |
| 1 | `node_eid` | tstr | `dtn://og.<fp>/`, self-certification check of §2.1 MUST pass. |
| 2 | `node_key` | bstr(32) | Ed25519 public key. |
| 3 | `roles` | array of tstr | Non-empty set of §2.3 roles; `[]` marks a REVOCATION record. |
| 4 | `level` | uint | Authority ceiling 0–3 (§2.4). MUST be `0` when `roles` is empty. |
| 5 | `issued_ts` | uint | Unix seconds; `> 0`, ≤ verifier now + 300 (the §4.3 skew rule). |
| 6 | `expires_ts` | uint | Unix seconds; MUST be `> issued_ts`. |
| 7 | `seq` | uint ≥ 1 | Monotonic per-`node_eid` issue sequence; the merge ordering key (§2.5). |

COSE_Sign1 parameters: protected `{1: -8}` (EdDSA); unprotected `{4: bstr(8)}` carrying the anchor key's fingerprint (`SHA-256(anchor public)[0:8]`) for key selection among pinned anchors. The signature is made and verified over the COSE_Sign1 Sig_structure per RFC 9052. A conforming node stores only certs it has verified against a pinned anchor public key.

### 2.3 Roles (provisioned, signed, static in v1)

| Role | Function |
|---|---|
| `edge` | Serves users (the protocol §1 portal). Default. |
| `relay` | Store-and-forward only; duty-cycled; the solar repeater. No portal. |
| `bridge` | Runs ≥ 2 convergence layers; translates planes (LoRa ↔ Wi-Fi ↔ serial). |
| `manager` | Management authority in the field: issues policy, sends commands, aggregates telemetry. |
| `anchor` | Offline trust root: signs role certificates + release capsules. **Never a network node.** |

### 2.4 Authority levels (a ceiling carried per cert)

| Level | Name | Example authority |
|---|---|---|
| L0 | telemetry | read health/counters/peers/route summary |
| L1 | operations | force janitor pass, drain mail queue, set radio quiet hours, trigger sync |
| L2 | administration | set policy (caps, TTL clamps, budgets), radio params, federation on/off, enable network staging |
| L3 | ownership | issue/revoke role certificates (seq bump), key rotation, factory reset |

A signer's effective authority is the `level` of its own cached role certificate; a command is executed only when `level ≥` the command's requirement (§8.2). Roles and levels are orthogonal: a `manager` with L1 can run operations but not policy.

### 2.5 Anti-rollback and revocation — the merge rules (offline-maintenance §3.4, verbatim adaptation)

There is **no online CRL** — on an island, none can exist. Revocation and rollback resistance are merge rules over `seq`, applied identically to certs received by any path (direct contact, epidemic sync, provisioning):

1. A verified cert with `seq` **higher** than the cached one for the same `node_eid` replaces it.
2. `seq` lower than cached: stale — drop silently, count (`rolecert_stale_dropped`, RAM-only).
3. **Equal `seq`, differing bytes**: keep the existing cert, count `rolecert_conflicts`. Equal-sequence ties NEVER overwrite (first verified claim wins) — there is no honest reason for one anchor to issue two different certs at one sequence; the tie is an **attack signal**, not a race.
4. **Revocation** is a higher-`seq` cert with `roles` cleared (`[]`) and `level` 0. Nodes MUST NOT open link sessions carrying management traffic with a revoked node and MUST NOT honor its commands; mail bundles remain receivable (they are opaque, §3.3).
5. Expired certs (`expires_ts < now`) are treated as absent: no authority, no management session; the node itself MAY keep forwarding mail.

### 2.6 Provisioning ceremony (P3.1)

Identity is provisioned, never improvised on the node, and never a side effect of an upgrade — the same offline-first shape as the release key (offline-maintenance §2.2). The ceremony, per node, with `capsuletool` (`node/cmd/capsuletool` in the daemon module; deterministic, scriptable, no network):

1. **Anchor keygen (once per island, air-gapped):** `capsuletool anchor keygen --out anchor/` — writes `anchor.seed` (mode 0600, the second crown jewel beside the release key; two offline copies, same discipline as offline-maintenance §2.2) and `anchor.pub` (the value every node pins).
2. **Node keygen:** `capsuletool rolecert keygen --out nodeA/` — the node's `node.seed` (0600) and `node.pub`.
3. **Request (the thing the anchor operator reviews):** `capsuletool rolecert request --seed nodeA/node.seed --roles edge,relay --level 1` — prints the unsigned payload fields; the EID is already fixed here because it is the key's fingerprint (§2.1).
4. **Offline sign:** `capsuletool rolecert sign --anchor-seed anchor/anchor.seed --node-pub nodeA/node.pub --roles edge,relay --level 1 --seq 1 --out nodeA/node_cert.cbor` (defaults: `issued_ts` = now, `expires_ts` = now + 90 days; explicit timestamps keep the ceremony deterministic). `capsuletool rolecert verify --anchor-pub anchor/anchor.pub --in nodeA/node_cert.cbor` closes the loop on the signer's side.
5. **Kit:** the operator kit carries `nodeid/{node.seed, node_cert.cbor, anchor.pub}` into the provisioning tree.
6. **Pi install:** `raspberry/provision.sh` gains step `install_nodeid` — idempotent, root-owned (`/opt/dtn-node/nodeid/`, `node.seed` 0600, cert and `anchor.pub` 0644); an ABSENT kit is a loud SKIP naming this ceremony (the node boots without a role cert: mail works, management does not, §10); a PARTIAL kit fails the install. The upgrade subset (`install.sh --upgrade`) deliberately does NOT run this step — rotation is a re-issue at `seq+1` through THIS ceremony, never a file swap (the offline-maintenance §2.2.3 idempotence rule). The files land root-owned; granting the daemon user read access to its own identity is P3.2+ daemon wiring, not silently widened here.
7. **ESP32:** the same three files become the NVS provisioning payload at flash time. P3.1 lands the seam — the `dtn_nodeid_store` vtable (load/save 32-byte seed + cert blob, RAM reference implementation, host-tested) in `dtn_core`; the NVS driver itself is hardware bring-up work (P3.3+/field), stated here so nobody mistakes the seam for the flash driver.

The C side (`esp32/components/dtn_core/`: `dtn_nodeid`, `dtn_rolecert`, `dtn_cbor`, `dtn_ed25519` over the embedded public-domain TweetNaCl, `dtn_sha256`) is a VERIFY-ONLY consumer: it verifies certs against pinned anchors and applies the §2.5 merge rules, but never signs. Go and C are pinned to the same vectors (`tests/vectors/nodeid/vectors.json`, shared with the C suite through a generated header); the merge/TOFU rules derive from offline-maintenance §3.4/§3.5, which defines the rules but carries no literal role-cert vectors — noted in the vector file's provenance field.

## 3. Bundle layer: the Offgrid BPv7 profile

A **frozen profile of RFC 9171** (Bundle Protocol v7) — not a new protocol, not full BP. The profile rules:

- **P-1 Structure.** A bundle is a CBOR sequence of exactly two blocks: primary block ‖ payload block. Serialization is canonical CBOR (RFC 8949 preferred serialization: shortest-form heads, definite lengths). Every block ends with a CRC-16/X.25 (CRC type code 1, the BPv7 "CRC-16" variant: reflected poly `0x8408`, init `0xFFFF`, xorout `0xFFFF`).
- **P-2 No extension blocks in v1.** No BPSec, no previous-node, no bundle-age, no bundle-layer fragmentation (hop-level fragmentation belongs to each convergence layer, §5.4). BPSec (RFC 9172/9173) is deferred, format-compatible: management bundles are COSE-signed in-payload and link sessions provide hop-by-hop confidentiality/integrity.
- **P-3 Primary block.** `[7, flags=0, crcType=1, destination, source, report-to, [creationDTNms, sequence], lifetime]` + CRC. Flags are `0` in v1 (no fragment, no administrative-record bit — management payloads are COSE objects, deliberately not BP admin records). The creation timestamp is DTN time (ms since 2000-01-01Z) of the envelope's `created_at`; the sequence is `0` for mail bundles and a per-source monotonic counter for identified bundles.
- **P-4 Mail bundles are anonymous.** `destination = dtn:og-mail`, `source = dtn:none` (CBOR `null`), `report-to = dtn:none`, payload = **one §14.2 CBOR envelope verbatim** behind the hop octet (§3.4). The group EID `dtn:og-mail` (no authority) is encoded `["", "og-mail"]`. The bundle layer adds zero identity fields the user plane doesn't already expose.
- **P-5 Management/update bundles are identified.** `source = dtn://og.<fp>/` of the issuing node, `destination` = the target node EID or a well-known group EID (`dtn://og-admin/` for commands, §8.1), `report-to = dtn:none`, payload = hop octet ‖ COSE_Sign1 (role certs, admin commands, telemetry) or hop octet ‖ raw self-signed record bytes (directory cards, §9.3) or hop octet ‖ capsule chunk (§9.1). These are the only bundles whose metadata names a node.
- **P-6 Lifetime = envelope TTL.** For mail, `lifetime` MUST equal the envelope `ttl` and the creation timestamp MUST derive from its `created_at`; admission keeps the ≤ 300 s future-skew rule (a bundle whose creation timestamp is more than 300 s ahead of the receiver MUST be dropped). Expiry is local: `creation + lifetime` against the receiver's clock. No life extension, ever.
- **P-7 Identity.** `bundle_id = SHA-256(PDU)` where PDU = the payload content after the hop octet. Dedup key only; the envelope `id` remains authoritative for mail end-to-end (§1.2).

### 3.1 Hop limit — the hop octet (pinned)

The §14.1 rule-4 semantics (`hop_count ≤ 7`, drop at 7) map onto a **1-byte hop octet prepended to every bundle payload**: profile ADU = `hop(0x00–0x07) ‖ PDU`. A relaying node MUST increment the octet and rewrite it in place (the payload block's length is unchanged; its CRC-16 MUST be recomputed) and MUST drop the bundle when the octet reaches 7. RFC 9171's own hop-count extension block (§4.4.1) was rejected because its canonical encoding costs 7–10 B — over twice the ≤ 3 B budget issue #33 sets — and it would be the only extension block in an otherwise extension-free profile, reopening exactly the parser surface P-2 closes. BPv7 leaves payload content to the application, so the octet is a profile ADU convention, not a wire-format deviation: a mail bundle's payload is `[hop ‖ envelope]` and the envelope stays byte-unmodified at offset 1. The octet is the profile's only mutable field — relays touch one byte plus a fixed-position CRC and nothing else — and dedup excludes it (P-7), so hop rewrites never break `bundle_id`. Cost: exactly 1 B; frozen. Hop state is per-bundle and therefore survives store-and-forward across contacts, unlike any link-layer counter.

### 3.2 What the profile deliberately does not do

No custody, no status-report generation at the bundle layer (telemetry replies are §8.3 application objects), no bundle priority on the wire (§7.3), no bundle-layer fragmentation (the LoRa CL's window mechanism and TCPCL's segmentation own that), no multicast. Anything not frozen here follows RFC 9171 as written where it does not conflict.

## 4. Byte budget (measured)

All numbers in this section are the output of `node/internal/bundle/spike.go` (P3.0); the test `TestSpikeDump` prints the exact encodings below. Primary block, anonymous mail bundle (35 B):

```
89                                array(9)
07 00 01                          version 7, flags 0, CRC type 1
82 60 67 "og-mail"                destination dtn:og-mail          (10 B)
f6                                source dtn:none
f6                                report-to dtn:none
82 1b 000000bd3f8faf 00           creation [DTN ms, seq 0]         (11 B)
1a 00093a80                       lifetime 604800                  (5 B)
42 912c                           CRC-16                           (3 B)
```

Full hex (`created_at` = the §3.2 example's 1759500000, ttl 604800):

```
890700018260676f672d6d61696cf6f6821b000000bd3f8faf00001a00093a80  (+32)
42912c
```

Identified management primary block (both EIDs = `dtn://og.<fp>/`, 68 B) — the destination/source EIDs cost 22 B each (`82 73 "og.<16hex>" 60`):

```
8907000182736f672e303132333435363738396162636465666082736f672e30  (+32)
31323334353637383961626364656660f6821b000000bd3f8faf00011a00093a  (+64)
80425019
```

### 4.1 Overhead and frame fit

The payload block costs 10 B of framing (array head 1, type/number/flags/CRC-type 4, content-bstr header 2–3, CRC 3) plus the 1 B hop octet. The node-plane window mechanism mirrors the frozen §14.3(a) grammar — a 1-byte header `win_id(4)|idx(2)|total(2)`, 221 B of bundle bytes per 222 B frame, `total ≤ 4` — as its own profile (§5.4); the §14.3 user-plane bytes are not touched.

| Payload carried | Bundle (B) | Fixed overhead (B) | Frames (≤ 4) | Window capacity (B) |
|---|---|---|---|---|
| Envelope 244 B (§14.3 floor) | 290 | 46 | **2** | 442 |
| Envelope 399 B (§14.3 max) | 446 | 47 | **3** | 663 |
| COSE_Sign1 floor 93 B (§8 mgmt) | 172 | 79 | **1** | 221 |
| Capsule chunk 200 B (§9.1) | 279 | 79 | **2** | 442 |
| Directory card 1024 B (worst, §9.3) | 1104 | 80 | 5 | — refused |

**Budget assertions (all confirmed by measurement):**

- Mail-bundle overhead ≤ 80 B: **met — 46–47 B** (primary 35 B + payload framing 10–11 B + hop 1 B). The issue's §2.5 estimate (primary ≈ 35–50 B + payload ≈ 8 B + CRC) is confirmed.
- A 399 B envelope fits ≤ 3 LoRa frames: **met — exactly 3 frames** (446 ≤ 663). Honest detail: it **misses 2 frames by 4 B** (442 < 446) — the issue's softer claim "most mail bundles fit 2 frames" holds for every envelope ≤ 396 B; only the largest envelopes (397–399 B) take the third frame, which carries 4 B. No discrepancy with the issue's exit criterion; the 2-frame estimate was optimistic for the maximum envelope and this record corrects it.
- The `total ≤ 4` window ceiling is real headroom, not slack: a 1024 B worst-case directory card (5 frames) does not fit, and the LoRa CL MUST refuse it (§9.3) rather than grow the window.

## 5. Radio plan: the LoRa convergence layer

### 5.1 Channel profile

The node plane runs its **own channel profile** — separate sync word and SF/BW from the future §14.3 user/mail radio profile — so the two frame grammars never share a carrier and never parse each other's bytes (issue #33 decision 4, adopted §12). Pinned defaults:

| Parameter | Value |
|---|---|
| Radio | Semtech SX1262-class (the #39 ESP32-S3 + SX1262 reference, §12.3) |
| Sync word | `0x2F4F` (2-byte, private). The user/mail profile MUST use a different value. |
| Default modulation | **SF7 / BW125**, CR 4/5, explicit header, LoRa PHY CRC on, preamble 8 |
| Default band | 902–928 MHz (US/AR); EU profile 869.525 MHz-class sub-band, duty-budgeted |
| MAC | v1, this section (raw LoRa P2P has no IETF standard — RFC 8376 confirms the gap; LoRaWAN is rejected: star-of-stars needs a gateway + network server, islands need P2P) |

### 5.2 Regulatory matrix (kept general and honest)

| Region | Band | Regime | Facts the MAC relies on |
|---|---|---|---|
| US | 902–928 MHz | FCC Part 15.247 | No duty-cycle limit; power/EIRP ceilings and the certification class of a raw-LoRa emitter (digital-modulation vs DTS readings) are module-certification facts, confirmed against the chosen module in P3.3 before field use. |
| AR | 902–928 MHz | ENACOM Q2-60.14 (FCC-aligned) | Same practical profile as US; regional power ceiling per the ENACOM text (≈ FCC class). |
| EU | 863–870 MHz | ETSI EN 300 220 | Duty-cycled sub-bands (typically 1 %; the 869.4–869.65 MHz sub-band allows 10 %) with ERP ceilings per sub-band; the MAC's duty budget (§5.3) is mandatory here, not optional. |

The installer's existing `--country` parameter selects the profile. Nothing in this table is a compliance claim; it is the set of facts the MAC must respect, and the certification work belongs to P3.3.

### 5.3 Airtime (measured) and MAC v1

Standard SX126x formula (Tsym = 2^SF/BW; preamble 8 + 4.25; Npayload = 8 + ⌈(8·PL − 4·SF + 28 + 16·CRC − 20·IH)/(4·(SF − 2·DE))⌉·(CR+4); CR 4/5, CRC on, explicit header; DE per the 16 ms symbol rule). Measured at a 222 B frame and at the real 279 B chunk-bundle split (221 + 58 B):

| Profile | T_air 222 B frame | Chunk bundle (279 B, 2 fr) | 1.5 MB ESP32 image (7500 chunk bundles) | 11 MB Pi capsule (55000) |
|---|---|---|---|---|
| SF7 / BW125 | 348 ms | 461 ms | **58 min** continuous | 7.0 h |
| SF9 / BW125 | 1.107 s | 1.477 s | 3.1 h | 22.6 h |
| SF11 / BW250 | 1.845 s | 2.462 s | 5.1 h | 37.6 h |

**Drift vs the issue §2.9 estimates (0.47 / 1.1 / 2.1 s):** SF9 matches (1.107 ≈ 1.1 s). SF7 measures **26 % faster** than estimated (0.348 vs 0.47 s). SF11/BW250 measures 12 % faster than estimated (1.845 vs 2.1 s) — the estimate corresponds to DE=1 (2.21 s), a conservative planning figure. The binding numbers are the formula values above (pinned by `TestSpikeAirtimeTable`). Effective raw rates: ≈ 5.1 / 1.6 / 0.96 kbit/s. Under a 10 % duty budget multiply the transfer times by ~10: the §2.9 conclusion stands with honest numbers — **ESP32-class firmware (1.5 MB) is practical over LoRa** (58 min continuous at SF7; ~10 h duty-cycled: one long night or two), **Pi-sized capsules are Wi-Fi/mule-first** (11 MB ≈ 7 h continuous ≈ 3 days duty-cycled at SF7), and delta capsules remain the answer for Pi binaries over radio, not a v1 concern.

**MAC v1 (ours by necessity):**

- **CAD listen-before-talk + randomized backoff.** A node performs channel-activity detection before every transmission; on busy it backs off exponentially (base 250 ms, doubling, ceiling 8 s) with random jitter, then retries. No ACK slot, no retransmit protocol — loss is tolerated by design (store-and-forward; §7), retries cost airtime and battery.
- **Airtime budgets.** Per-contact budgets (§7.4) plus a rolling per-region duty budget (default 10 %/hour; EU sub-band rules are stricter and win). Management traffic (§8) preempts mail preempts bulk — as local queue discipline only (§7.3).
- **Wake/beacon windows for solar repeaters.** Repeaters deep-sleep and wake for short CAD listens (period ≤ 5 s; a 128 ms CAD every 2 s ≈ 6 % RX duty). Peers SHOULD learn a repeater's observed windows and concentrate transmission there (contact-history bookkeeping, §7.5). Energy facts the plan relies on: SX1262 RX ≈ 4.2–4.6 mA, TX +22 dBm ≈ 118 mA; the MCU's deep sleep dominates the energy budget, so RX cadence — not TX power — is the repeater's lever. Exact cadences are field-tuned in P3.3/P3.9; the bounds above are the v1 envelope.

### 5.4 Node-plane frame and window formats

Link frame (byte layout frozen, 1.3.0): `link_header(1) ‖ payload ‖ [AEAD tag]` (the AEAD is §6's session).

- **Header — 1 byte, big-endian bit order:** `version(2) | type(3) | flags(3)` in bits 7–6 / 5–3 / 2–0. `version = 1` (other values fail closed). `type`: 0 = `beacon`, 1 = `session`, 2 = `mail-win`, 3 = `bundle-frag` (4–7 fail closed). `flags = 0` in v1 (nonzero fails closed).
- **Payload budget — 222 B of PLAINTEXT per frame** (1.3.0 correction: this sentence said ≤ 220 B in 1.2.0; the bundle-frag window needs 1 B of window header + 221 B of window content, and §4.1's capacity table freezes 221 B/frame — the correct budget is 222, not 220). Session-protected types carry the §6.2 nonce on the wire: `header ‖ nonce(13) ‖ ciphertext ‖ tag(16)`, so the **on-air maximum is 1 + 13 + 222 + 16 = 252 B** — inside the SX126x 255-byte radio limit, with the header byte as the AEAD's associated data. Beacons are plaintext with fixed content: `beacon_version(1) = 1 ‖ sender fingerprint(8)` — §6.1's "links without a verified session carry nothing but beacons".
- **Window header** — bundle chunks ride as `bundle-frag` payloads with a per-bundle window header of the **§14.3(a) grammar**: 1 byte `win_id(4) | idx(2) | total(2)` (bits 7–4 / 3–2 / 1–0), ≤ 221 B of bundle bytes per frame, at most 4 frames per window. Encoding pin (1.3.0): the 2-bit `total` field carries **total − 1** (0–3 ⇔ counts 1–4) — the grammar's "fragment count (1–4)" does not fit 2 bits raw, and no user-plane byte implementation exists to contradict it. A partial window expires with the bundle's TTL; retransmit policy is absent by design (§1 of issue #33). An IDENTICAL retransmission of an already-seen index is the redundancy mechanism and is absorbed idempotently; a repeated index with DIFFERING bytes is corruption and is refused — and a lost frame never corrupts sibling windows.

### 5.5 The serial convergence layer and the radio HAL (P3.3)

**Serial CL (the §3 bridge leg).** The bridge daemon talks to its radio head over a serial/io channel carrying the SAME §5.4 link frames. Framing, frozen: `[len: 2 bytes, big-endian] ‖ [link frame]` — the length covers the frame only, and values above the implementation bound (1024 B) fail closed. The prefix exists because a UART stream has no frame boundaries (radio bursts provide them for free over the air). The writer serializes (one write of prefix ‖ frame); the reader is a single read loop. Go: `node/internal/serialcl`; the radio head's C counterpart speaks the identical prefix + frame bytes (pinned by the shared link vectors, §11 row f).

**Radio HAL.** `dtn_radio` (in `dtn_core`) is a callback vtable — `init/send/recv/cad/sleep` — that the MAC (§5.3) and the link layer are written against. The **sx126x REGISTER-LEVEL driver port (BSD LoRaMac-node) is deferred to hardware bring-up**: register sequences are unverifiable in this environment, and unverifiable radio code has no place in the portable core. The host suite drives the whole MAC/link stack through two in-memory channel implementations of the same vtable (`loopback` and a `lossy` channel with scripted per-frame drops and CAD busy windows); the real sx126x adapter lands as one more implementation of the vtable, with the §1 bench tests (2 units, attenuator + distance) as the field acceptance gate.

## 6. Link security

### 6.1 The EDHOC-shaped handshake

An EDHOC-shaped minimal exchange (RFC 9528 as **normative reference**, RFC 9529 traces as vector reference), implemented on mbedTLS primitives — full EDHOC libraries remain research-grade (uoscore-uedhoc, edhoc-rs; tracked, revisit). Shape, frozen:

- **msg1** = `[1(suite), 1(X25519), g_x(32), c_i]` — **38 B** (`c_i = 0` pinned; v1 links are pairwise).
- **msg2** = `[g_y(32), c_r, ct2]` with `ct2 = AEAD(K2, th1(8) ‖ id_cred_r(8) ‖ sig_r(64))` — **134 B** (`c_r = 1` pinned).
- **msg3** = `[ct3]` with `ct3 = AEAD(K3, id_cred_i(8) ‖ sig_i(64))` — **91 B**.

Every message fits **one** 221 B frame — under the < 3-frames bound with ≥ 2.4× margin (issue exit criterion met). Construction pins (1.3.0, all derived from the frozen shapes above): `th1 = SHA-256(msg1)[0:8]`; `id_cred = SHA-256(node_key)[0:8]` (§2.1's fingerprint); `K2 = HKDF-SHA256(dh, salt = SHA-256(msg1), info = "offgrid-link-v1 k2")` and `K3 = HKDF-SHA256(dh, salt = SHA-256(msg1 ‖ g_y), info = "offgrid-link-v1 k3")`; the ct nonces follow the §6.2 length profile with the handshake salt `SHA-256("offgrid-link-v1-handshake")[0:5]` and the message number as the sequence; each ct is AAD-bound to the exact message bytes preceding its CBOR head. **Signature transcript (corrected 1.3.0):** the 1.2.0 sentence "signatures over the transcript (th1 ‖ both EIDs)" is internally impossible in a three-message exchange — the responder must sign BEFORE the initiator's EID reaches it in msg3. The frozen implementation is the union across the two signatures: `sig_r` = Ed25519 over `th1 ‖ EID_r`, `sig_i` = Ed25519 over the FULL transcript `th1 ‖ EID_r ‖ EID_i`. The wire layout is untouched (38/134/91 B stands).

Both sides verify the peer's `node_key` against its **cached role certificate** (§2.2) or pin it on first contact (**TOFU + loud warning**, the offline-maintenance §3.5 pattern): an EID whose key changes without a higher-seq cert fails the session, loudly (`nodeid.ErrPeerKeyChanged`). Fail-closed: links without a verified session carry nothing but beacons; a failed handshake leaves no session and no retained key material.

### 6.2 Traffic keys, replay, rekey

- **HKDF-SHA256** over the X25519 shared secret with the transcript hash as salt and `"offgrid-link-v1"` as info → a master secret; per-direction keys via HKDF-Expand with direction labels.
- **AEAD:** AES-CCM-128 (13-byte nonce = 5-byte session salt ‖ 8-byte big-endian per-direction sequence; 16-byte tag). ChaCha20-Poly1305 MAY be used on hosts without AES acceleration — same key schedule, same sequence discipline.
- **Sequence numbers are monotonic per direction and persisted** (flash on ESP32) so restarts do not rewind. Writers checkpoint every 32nd packet; after an unclean restart the sender resumes at last-persisted + 32 and the receiver's replay window (≥ 32) absorbs the gap. Replayed or reordered-beyond-window frames are dropped and counted.
- **Rekey** at 2^20 packets or 24 h, whichever first; sessions survive repeater reboots via the persisted state above.
- **IP plane:** TCPCLv4 (RFC 9174) with its native TLS 1.3 (RFC 9846) via mbedTLS — same node identity, same certificates, mTLS optional-but-defined. The pinned subset of RFC 9174 and the exact TLS/pinning model are §6.3 (below); the Go implementation is `node/internal/tcpcl` (P3.4).
- **Mail stays E2EE regardless:** the §14.3b trial-decrypt broadcast model is unchanged on this plane; channel crypto protects metadata and management traffic and defends user privacy in depth, never instead of §4.2.

### 6.3 TCPCLv4 (the Wi-Fi plane) — the pinned RFC 9174 subset (1.4.0)

`node/internal/tcpcl` (Go, stdlib-only: `crypto/tls` implements TLS 1.3 per RFC 8446, carried forward by RFC 9846) implements a faithful SUBSET of RFC 9174. Nothing below invents message types or session semantics; where the RFC offers options, the minimal conforming path is pinned as follows.

**Messages implemented** (RFC section in parentheses): the `dtn!` contact header with version 4 and the CAN_TLS flag (`0x01`) (§4.2); SESS_INIT (§4.6); XFER_SEGMENT / XFER_ACK / XFER_REFUSE (§5.2.2/§5.2.3/§5.2.4, flags END=`0x01`, START=`0x02`); KEEPALIVE (§5.1.1, the single `0x04` octet); SESS_TERM with the REPLY flag and the Table-9 reason codes (§6.1); MSG_REJECT (§5.1.2). **There is no XFER_INIT in RFC 9174** — a transfer STARTS with the START flag on its first XFER_SEGMENT and ENDS with the END flag on its last; the extension-length fields are implemented exactly as mandated (U32 items length on every START segment and on SESS_INIT).

**Session establishment mode (as the RFC actually specifies it, §4.2–§4.6):** a PLAINTEXT contact-header exchange happens first (the active peer — the TCP dialer — sends its header, the passive answers, §4.3); Enable TLS is the logical AND of both CAN_TLS flags; when true, an in-band TLS upgrade runs BEFORE any other message (§4.4.3) with the active peer in the TLS client role; after TLS, SESS_INIT flows from BOTH entities (Figure 17). TLS is not TLS-first, and there is no opportunistic plaintext mode: this profile pins the RFC §4.3 RECOMMENDED policy — TLS REQUIRED, a peer without CAN_TLS is terminated with SESS_TERM "Contact Failure" (TLS stripping is not ours to tolerate). Version: v4 only; no fallback ladder — a decodable header with version ≠ 4 draws the passive side's contact header echo + SESS_TERM "Version mismatch" (§4.3); an undecodable magic closes the TCP connection without a SESS_TERM (§6.1).

**Negotiated parameters (§4.6/§4.7):** keepalive = the minimum of the two announcements (zero disables keepalives; default advertised 30 s — the RFC's recommended floor; idle termination at exactly 2× the negotiated interval, §5.1.1, → SESS_TERM "Idle timeout"). Segment MRU (advertised default 256 KiB) and Transfer MRU (default 64 MiB) are taken from the peer's announcement as-is; our sending chunk is 64 KiB (§9.1) clamped by the peer's Segment MRU. Parameters never change mid-session (§4.7).

**Transfers:** transfer IDs follow the RFC's default algorithm (§5.2.1): sender-allocated, first 0, +1 each, unique per direction; a sender-side exhaustion of the 64-bit space terminates with "Resource Exhaustion". NO segment interleaving (§5.2.2): one in-flight transfer per direction per session; concurrency is multiple sessions (tested). The Transfer Length Extension (item type `0x0001`, §5.2.5.1/§8.4) rides multi-segment STARTs and is absent from single-segment ones ("SHOULD NOT"); on receive the announced total is AUTHORITATIVE — a mismatch refuses with "Not Acceptable". ACK discipline (§5.2.3): every segment is acknowledged cumulatively after it is fully processed; the END segment is acknowledged only after the bundle validated AND the sink accepted it, so a sender never observes a completed transfer the receiver actually refused. Refusals: budget/MRU → "No Resources" (preemptive, before the bytes arrive, when the sender announced the total — §5.2.4's preemptive-refuse path); malformed profile bundle → "Not Acceptable" (§5.2.4's inspected-data case) + the `malformed_bundles` counter; unknown CRITICAL extension item → "Extension Failure" (§5.2.5); new transfer during Ending → "Session Terminating" (§6.1). Segments of an already-refused transfer are consumed and re-refused (crossing refusals, §5.2.4).

**Fail-closed admission:** every completed transfer MUST parse as an Offgrid BPv7 profile bundle (§3, the P-6 skew rule against the receiver's clock) before it reaches the sink; anything else is refused and counted. The framing reader enforces hard caps BEFORE trusting any length (node ID ≤ 1 KiB, extension items ≤ 4 KiB, segment data ≤ the receiver's advertised Segment MRU) — a hostile peer cannot buy memory with a length field; an oversized segment is a protocol violation, never an allocation. Unknown message type → MSG_REJECT "Message Type Unknown" + TCP close (§5.1.2); an XFER_ACK for an unknown transfer ID → MSG_REJECT "Message Unexpected" (§5.1.2's named case).

**Session security (the §6.2 item-4 contract, pinned):** TLS 1.3 only (RFC 8446, carried forward by RFC 9846), via Go's `crypto/tls` on the Pi/PC side (mbedTLS on ESP32, same certificates, later phase). Each node presents a SELF-SIGNED X.509 v3 certificate binding its Ed25519 node key — CN and URI SAN both carry the EID (the RFC 9174 NODE-ID lives in the SAN, §4.4.1; the BundleEID otherName form has no `crypto/x509` equivalent and is not needed; EKU carries clientAuth+serverAuth per §4.4.2's interoperability note; keyUsage digitalSignature). There is no CA on an island: crypto/tls's PKIX chain verification is REPLACED — never skipped — by the §6.1 TOFU pin over the leaf certificate's public key, which IS the node key: the same PinStore, the same first-contact recording, the same loud `nodeid.ErrPeerKeyChanged` on change; the EID re-derived from the key MUST equal the certificate's SAN (the §2.1 binding, fail-closed) and MAY be asserted per dial (`ExpectedPeer`). mTLS is REQUIRED by default (§4.4.3's "the active entity SHALL supply a certificate"); OPTIONAL is the defined relaxation — the server verifies the client certificate WHEN PRESENTED and counts the session in `unauthenticated_peers` otherwise (§7.12.1-shaped). A non-empty SESS_INIT node ID that differs from the TLS-certified identity kills the session (the impostor case of §4.4.4). The SESS_INIT node ID is always our EID (26 bytes); no SNI (island addressing, no resolved DNS names); no session resumption.

**Budget (§7.4):** the per-contact byte budget (default 64 MiB, configurable; a config constant, not a promise) is enforced at the SESSION layer on BOTH directions: ingress over-budget → XFER_REFUSE "No Resources" (before the bytes arrive when announced); egress over-budget → the sender DEFERS (`ErrBudgetDeferred`, the P3.5 queue retries next contact). Only bundle PDU bytes count. Counters are exposed (`tcpcl.Counters`: sessions in/out, bundles/bytes in/out, refusals in/out, budget refusals/deferrals, malformed bundles, pin rejections, protocol errors, keepalive timeouts, unauthenticated peers) — RAM-only, the §10.7 discipline.

**Termination (§6.1, both paths):** graceful — SESS_TERM (REPLY=0) → the peer answers with identical content and REPLY=1, enters Ending (new transfers refused both directions, in-progress ones may finish), the connection closes bounded by the linger; the original terminator emits the TLS closure alert with its close (crypto/tls does this in `Close`). Abrupt — a best-effort SESS_TERM then an immediate TCP close (the RFC's unclean path); peers observe either a clean end or a loud failure, never a silent half-open.

**P3.4 honesty note:** this phase's integration gate is the Go loopback suite (§11 row h — two full stacks over 127.0.0.1 ephemeral ports). The daemon wiring is OPTIONAL and OFF by default (`-tcpcl`, nodeplane boot in `node/nodeplane.go`): when on, it serves sessions into the `BundleSink` seam and dials configured peers; the sink was a validate-and-count STUB logged as "forwarding pending until P3.5" — the real bundle store and the epidemic sync landed with P3.5 (§7.1/§7.5), and the bash-level gate is the additive `tests/node_plane_e2e.sh` (the three-daemon multi-hop E2E; the `sync_e2e.sh` TCPCL extension named here in 1.4.0 became that dedicated file instead — same conventions, its own port range). The TOFU pin store is checkpointed (atomic 0600 rename) every minute and at shutdown; a crash since the last checkpoint re-TOFUs — stated, not hidden.


## 7. Forwarding and storage

### 7.1 Controlled epidemic contact sync v1

On every contact (LoRa beacon window or TCPCL connect) peers exchange compressed summaries of stored `bundle_id`s, compute diffs, and transfer within per-contact budgets. Summaries are Bloom filters over 32-byte `bundle_id`s: **4096 bits (512 B), k = 4** — false-positive rate ≈ 0.1 % at 200 entries, ≈ 2 % at 500; false "have" answers cost one missed transfer that the next contact repairs, never corruption. Summary bundle: 591 B → 3 frames. This is RFC 4838's opportunistic-contact model with flooding made frugal.

**The v1 handshake rides the bundle plane (1.5.0, pinned).** TCPCL carries bundles and nothing else — no new convergence-layer message exists. On every established session each side sends its summary AS a bundle: the §3 P-5 identified shape with `source` = the sender's node EID and `destination` = the PEER's node EID, payload content = `sync-version(1) ‖ summary(512 B)` behind the hop octet (513 B; 591 B as a bundle, 3 frames — the §7.1 budget row holds). The receiver's sink recognizes that shape (destination = its own EID, version byte, exact length), routes it to the sync engine instead of the store, and answers with its diff — ordinary profile bundles, in the §7.3 priority order, within the §7.4 budget. Everything on the wire stays exactly §3; the summary bundle is consumed, never stored (its short lifetime covers the waylaid-relay case). The hash derivation is frozen for both implementations: for i in 0..3, `index_i = big-endian_u32( SHA-256(i ‖ bundle_id)[0:4] ) mod 4096`, bit `index/8`, mask `1 << (index mod 8)`; the filter is **unsalted** — the inputs are opaque SHA-256 digests (P-7), so a summary reveals set membership of opaque digests only, and a peer that already knows an id can test membership (inherent to any epidemic diff); payload bytes never appear. Go: `node/internal/forward/sync.go`; C: `dtn_epidemic.c` — byte-pinned by the shared vectors of `tests/vectors/forward/`. Contacts are episodic: a session is held for the exchange and terminated; cargo arriving between contacts rides the next one (the wake-window model, §5.3).

### 7.2 Expiry and loop control

Dedup by `bundle_id` (P-7); drop at the hop-octet ceiling (7); TTL expiry identical to envelope semantics (P-6). Replication depth is bounded by hop + TTL, not by a routing algorithm (PRoPHET, RFC 6693, is the named upgrade path if island metrics show epidemic waste — deferred with measurements required first, §12.5).

### 7.3 Priority = local queue discipline only

**management > mail > bulk (updates)** — a local scheduling policy, never a wire field. BPv7 has no primary priority field and the profile deliberately does not add one; consistent with protocol §13's traffic-analysis stance, the wire cannot observe a node's queue order.

### 7.4 Per-contact budgets (binding defaults)

| Plane | Budget |
|---|---|
| LoRa contact, mail | ≤ 64 frames |
| LoRa contact, bulk (updates) | only while the mail queue is empty; ≤ 512 frames |
| TCPCL contact, bulk | ≤ 64 MiB (config constant, not a promise) |

### 7.5 Bundle store

The store reuses the existing storage engines with its own namespace: SQLite WAL on Pi (own `bundles` table: `bundle_id` PK, canonical blob, hop, expires_at) and the `dtn_store` log on ESP32 (own log region), with the same caps/budget/janitor patterns as the envelope store. Caps: Pi default 5000 bundles; the ESP32 cap is whatever its 4 MB-flash partition budget honestly allows and is **reported via capabilities, never fabricated** (the #39 §2/§7 pattern). Contact history per peer (fingerprint-level, no content) feeds the §5.3 wake-window scheduling; full Contact Graph Routing stays out.

**Admission pipeline and eviction (1.5.0, pinned).** Admission = profile Parse (fail-closed; the P-6 skew rule runs against the receiver's clock) → the §3.1 hop ceiling (a bundle AT hop 7 is dead cargo for a v1 relay: dropped, counted, acknowledged — P3.6's consumption path sinks destination-bound bundles before this rule) → local expiry (`expires_at = creation + lifetime` against the local clock, evaluated at admission; already-expired cargo is never stored) → dedup by `bundle_id` (P-7; the hop-rewritten copy dedups too) → classification (the v1 EID rules of the implementations: destination `dtn://og-admin/` → management; `dtn:none` → `dtn:og-mail` → mail; everything else bulk; P3.6/P3.7 extend). At cap the policy is **refuse-newest-for-oldest-expiring, priority-aware**: the evictee comes from the lowest-priority class at-or-below the newcomer's importance and is the soonest-expiring row of that class (deterministic tie-breaks: received_at, then id — Go and C evict in identical order, pinned by the shared vectors); a bulk arrival can never evict mail or management, and a full store holding only higher-priority classes refuses the newcomer (`at_cap`, the envelope store's reject-newest stance). Every admission path is counted (accepted / dup / expired / hop-capped / at-cap / evicted), RAM-only per §10.7. Implementations: `node/internal/forward/store.go` (SQLite WAL, own database file — the user-plane schema chain is never touched) and `dtn_bundlestore.c` (CRC-framed log + RAM index, the `dtn_store` pattern); both run the shared vectors of `tests/vectors/forward/` (byte-exact Bloom summaries, identical diff outcomes, step-identical admission verdicts and survivor sets).

## 8. Management plane

### 8.1 Admin command bundles

An admin command is an identified bundle (§3.4) to the well-known EID `dtn://og-admin/`, payload = **COSE_Sign1** (signed by the issuing node's `node_key`) over the CBOR map — **fixed key order 0..5, canonical encoding (1.6.0 precision; the layout is frozen exactly as the implementations emit it)**:

| CBOR key | Field | Type |
|---|---|---|
| 0 | `cmd` | tstr |
| 1 | `args` | map |
| 2 | `target_node` | tstr (node EID) |
| 3 | `issued_ts` | uint |
| 4 | `expiry` | uint |
| 5 | `seq` | uint, monotonic per signer |

COSE_Sign1 parameters are the §2.2 cert's: protected `{1: -8}` (EdDSA), unprotected `{4: bstr(8)}` carrying the **signer's own fingerprint** — the handle the enforcement pipeline resolves against the §2.5 cache (§8.2); the signer's authority is its cached role certificate's level ceiling, never anything the payload names. `target_node` is the receiving node's EID, or the empty string for a **broadcast to the og-admin group subscribers** (§8.5). `args` is a canonical CBOR map (keys ascending bytewise, ≤ 8 pairs) whose values are limited to the closed set **uint | tstr | bstr** — anything else fails the shape check (fail-closed, both implementations). Timestamps: `issued_ts ≤` verifier now + 300 (the §4.3 skew) and `0 < expiry − issued ≤ 86400` (**24 h validity bound, v1**); a command is expired when verifier `now ≥ expiry`. Signing is deterministic (Ed25519) through the shared Sig_structure of RFC 9052 §4.4.

**The v1 command table (frozen; an unknown name is dropped + counted, never confirmed — forward compatibility):**

| Command | Level | Executor semantics |
|---|---|---|
| `get_status` | L0 | Aggregate node-plane health: role, level, bundle-store fill/cap, peer count (§10.7 rules — aggregates only). Reply. |
| `force_janitor` | L1 | One bundle-store janitor pass now (§7.5 expiry). Reply carries the swept count. |
| `trigger_sync` | L1 | Dial the configured peers at the next opportunity (the §7.1 contact model; no new wire mechanism). |
| `set_quiet_hours` | L1 | Store-only policy object (enabled, start/end minutes-of-day) — the radio applies it at hardware bring-up (P3.3+). |
| `set_store_cap` | L2 | Apply a new bundle-store cap (§7.5; the enforced number is the reported one, cut both ways). |
| `set_budgets` | L2 | Per-contact budget policy (`contact_mib`); applies to sessions opened after the change. |
| `set_dial_interval` | L2 | Opportunistic dial cadence policy (seconds); the dial loop re-reads it per contact. |
| `federation_on` / `federation_off` | L2 | The stored federation flag P3.8 consumes. |
| `install_cert` | L3 | Carries an **ALREADY ANCHOR-SIGNED role cert** (`args` = `{cert: bstr(COSE_Sign1)}`); the executor feeds it to the §2.5 cache, where the seq merge rules decide. **Issuance stays an offline anchor ceremony (§2.6) — this command only distributes/installs** (revocation propagates island-wide exactly this way, §2.5 rule 4). |
| `factory_reset_node_plane` | L3 | Clears NODE-PLANE state: the bundle store and the learned TOFU peer pins. **NEVER the user-plane mail** (a different database, never opened), never the pinned anchor or node identity (provisioning-ceremony state — a re-install, not a runtime command). Wiring MUST log it loudly. |

### 8.2 Enforcement pipeline (normative order)

A receiving node processes an admin bundle only when it is the payload's `target_node` (or the command class is a documented broadcast, e.g. policy to `edge` nodes), in THIS order: **shape** (the exact §8.1 object) → resolve the signer's `node_key` from the kid fingerprint to a cached, unexpired, unrevoked role certificate (§2.5 effective state) → **verify the COSE_Sign1 with that certified key** → target gate → command-table lookup → `level ≥` the command's requirement (the v1 table above) → **`seq` freshness per signer (strictly monotonic; a replayed or lower seq is dropped + counted)** → `issued_ts`/`expiry` sanity against the LOCAL clock → execute. The per-signer floor moves at execution ("must exceed the last executed"), so a command dropped by a later gate never burns its `seq`.

**Any failure: drop silently + increment the matching RAM counter — no error packets to strangers** (the §13.6 refusal-to-confirm pattern). The counter set (§10.7 discipline: RAM-only, die with the process, aggregates only) is pinned: `commands_accepted`, `dropped_shape`, `dropped_sig` (unknown/revoked/expired signer or bad signature), `dropped_target`, `dropped_unknown`, `dropped_bylevel`, `dropped_seq`, `dropped_expired`, plus the reply counters of §8.3 and the §2.5 cert merge counters (`rolecert_stale_dropped`, `rolecert_conflicts`) — the whole set is served by the node's status surface (§10.7's additive `node_plane` member).

Freshness state is per-signer-per-node and RAM-only; the 24 h validity bound and command expiry bound any post-restart replay window. An operator consequence of strict monotonicity over an epidemic network: **a signer MUST NOT hold more than one command in flight** — sync delivers without ordering, and the stale arrival is (correctly) refused island-wide.

### 8.3 Telemetry replies

Replies adapt the RFC 9713 status-report **shape** (no IANA registration; private profile): an identified bundle back to the manager's EID (the command bundle's `source`), payload = COSE_Sign1 over `{0: reply_to (bstr 32 = the command's bundle_id — the P-7 digest of the payload after the hop octet), 1: code (uint), 2: data (map)}` — **fixed key order 0..2, args-map rules of §8.1, signed by the EXECUTING node's `node_key`** (kid = its fingerprint; a manager verifies a replier's signature when the replier's cert is cached). Codes: `0` = executed, `1` = an authorized command whose local execution failed (never a silent lie); pipeline drops NEVER reply. Data is **aggregate only** — the §10.7 privacy rules apply verbatim (no envelope ids, no hints, no aliases, no per-client data); when in doubt, less. A reply rides the ordinary bundle plane (identified bundle, lifetime ≤ 1 h, contact-scoped telemetry), and a consumed copy is re-admitted into the consumer's store so P-7 dedup and the §7.1 summaries converge — a consumed bundle must never become a perpetual redelivery.

### 8.4 No consensus, no election in v1

Roles are provisioned facts, eventually consistent, signed. Auto-election (battery/connectivity-weighted manager promotion) is an explicitly deferred future spike — partitioned DTNs make online consensus a liability, not a feature (§12.7).

### 8.5 Sink consumption and propagation (1.6.0, pinned)

A received, profile-valid bundle whose destination is THIS node's EID or `dtn://og-admin/` is offered to the management plane **BEFORE the forward store** (and before the §3.1 hop ceiling — a hop-7 broadcast command still executes where it arrived; only its further relay dies there). The router discriminates the three §8 payload classes by the inner map's pair count (all fix uint keys 0..n−1: 8 = a §2.2 cert, 6 = a §8.1 command, 3 = a §8.3 reply); anything else is NOT management cargo and falls through to the store unchanged (P3.5 behavior — P3.8's directory cards land in that slot).

- **Commands** run the §8.2 pipeline. Admin-group copies (and bare certs) are **re-admitted into the store after consumption** — the epidemic sync then propagates them island-wide: every node reaches its own verdict (dedup bounds re-transfer; seq freshness bounds re-execution; TTL bounds residence). This is how revocation propagates with NO online server (§2.5 rule 4 + the L3 `install_cert` row of §8.1). Locally targeted copies are re-admitted too, so the consumer's summaries cover them (no perpetual redelivery, §8.3).
- **Bare certs** (a COSE_Sign1 cert payload, e.g. a revocation riding og-admin) merge into the §2.5 cache directly — the verification-failure counters are the record; nothing is ever surfaced to the sender.
- **Replies** addressed to this node are consumed (counted, observed) and re-admitted for convergence (§8.3).
- The issuing node consumes its own broadcast through the same sink path at injection (an og-admin broadcast includes the issuer); peers never echo it back — their §7.1 diffs see it already covered.

## 9. Updates and directory over the plane

### 9.1 Capsules as bulk bundles

Capsule format v1 (`docs/offline-maintenance.md` §2.1) is frozen and unchanged. The sender chunks it into identified bundle payloads: **≈ 200 B per chunk on LoRa** (a 279 B, 2-frame bundle per chunk — loss of one window wastes ≤ 2 frames of airtime), **64 KiB per chunk on TCPCL**. The receiver reassembles and hands the **byte-exact capsule** to the existing staging path (offline-maintenance §2.4): signature verification against the pinned release key, anti-rollback (`409 stale` semantics, §2.6), atomic stage, apply via the #22 machinery (Pi) or `esp_ota_ops` A/B + health gate + rollback (ESP32, #39). **Zero new trust surface**: the network is one more entry point beside the operator laptop and the mule — exactly what offline-maintenance §2.3 predicted. Capsule metadata gains `arch` ∈ {`armv6`, `armv7`, `arm64`, `esp32s3`, `esp32`} (an additive extension of the §2.1.2 metadata block; consumers MUST ignore unknown `arch` values).

### 9.2 Bandwidth honesty

The §5.3 table is the binding accounting: ESP32 1.5 MB ≈ 58 min continuous at SF7 (~10 h at a 10 % duty budget — practical overnight/duty-cycled); Pi 11 MB ≈ 7 h continuous at SF7 (~3 days duty-cycled — **Wi-Fi/mule-first**, LoRa as patient opportunistic backfill). These correct the issue's §2.9 row (55 min) with measured overhead-inclusive numbers.

### 9.3 Directory federation

`docs/offline-maintenance.md` §3's signed identity cards and delta semantics become identified bundle payloads node-to-node (BRIDGE↔BRIDGE; MANAGER seeds): payload = hop octet ‖ the card's canonical JSON bytes verbatim (≤ 1024 B per that spec), merged with the **§3.4 rules verbatim** (§2.5 of this document applies the same discipline to role certs). The mule ferry stays as the zero-infrastructure fallback; both paths converge on the same signed-card semantics. Honest bound: the realistic ≈ 370 B card rides in 3 frames; the 1024 B worst-case card (5 frames) **exceeds the 4-frame LoRa window and MUST be refused by the LoRa CL** — worst-case cards are Wi-Fi/mule-first, exactly like Pi capsules.

## 10. Threat-model delta (additive to protocol §13)

| New exposure | Assessment / mitigation |
|---|---|
| Node pseudonyms + pairwise traffic timing become observable | New by design; bounded: EIDs are key fingerprints (pseudonymous, rotatable by rekeying), mail bundles are anonymous (`dtn:none`), user-plane blindness untouched (§1.1). |
| Node key compromise | Bounded by the node's role level (an `edge` can't issue commands; a `manager` can — that's the point). Revocation = higher-seq cert (§2.5); propagation rides the same epidemic sync. |
| Anchor key compromise | Total — same as release-key compromise today (offline-maintenance §2.7 already accepts and mitigates: air-gapped, two offline copies). Role certs add a second crown jewel under the identical ceremony. |
| Session crypto breaks (e.g., bad handshake) | Fail-closed: links without a verified session carry nothing but beacons; handshake vectors pinned by tests (§11, RFC 9529 traces as reference). |
| Sybil / rogue node joins the plane | A node without a valid role cert can gossip mail bundles (useful, harmless — they are opaque) but gets no management authority and no session with management traffic; TOFU pinning makes first-contact substitution loud (§6.1). |
| Replay across links | Per-direction persisted sequence numbers (§6.2); `bundle_id`/envelope-`id` dedup absorbs re-delivery (the §5.10 audit analysis holds per plane). |
| Epidemic congestion / update floods | Per-contact budgets (§7.4), local priority queues (§7.3), store caps (§7.5) — the §8.1/§10.1 patterns generalized. |

**User-plane regression is a hard gate:** every phase ships with `make test`, `tests/sync_e2e.sh`, `make chaos` green and the envelope bytes untouched. (CI note: `test.yml` is manual-dispatch only per `AGENTS.md` — run the suite locally before every PR.)

## 11. Conformance matrix (normative, §15.7-style)

A build claiming conformance to this specification MUST be covered by tests for each row. Planned file names for phases that have not landed yet are marked *(to land in P3.x)*.

| # | Required coverage | Test |
|---|---|---|
| a | Byte budgets of §4: mail overhead ≤ 80 B; 399 B envelope ≤ 3 frames; frame-fit table; handshake < 3 frames; capsule chunk 2 frames; 1024 B card refused | `node/internal/bundle/spike_test.go` (this phase) |
| b | LoRa airtime formula and §5.3 table values | `node/internal/bundle/spike_test.go` (`TestSpikeAirtimeTable`, this phase) |
| c | Profile codec: canonical CBOR vectors (incl. the §4 hex), CRC-16/X.25 catalogue value, fail-closed parse of malformed bundles | `node/internal/bundle/bundle_test.go` + `node/internal/bundle/vectors_test.go` (`TestCrossImplementationByteIdentity`, this phase); `esp32/components/dtn_core/host/tests/test_bundle.c` (`test_cross_implementation_byte_identity`, this phase) — the 40 shared vectors of `tests/vectors/bundle/vectors.json` (via the generated `host/tests/bundle_vectors.h`) run on BOTH suites: byte-identical encodings Go↔C, identical parse verdicts and stable failure codes. RFC 9171 (nor any published erratum/companion — verified 2026-10-07) provides NO byte-level example bundles, so the vectors are profile-derived (§3 rules + §4's measured encodings); the optional µD3TN interop spot-check stays deferred (AGPLv3 forbids code linkage anyway) |
| d | Role-cert verification, self-certifying EID binding, seq merge rules incl. equal-seq attack signal and revocation (§2.5) | `node/internal/nodeid/{rolecert,cache,pinstore,nodeid}_test.go` (this phase); `esp32/components/dtn_core/host/tests/test_nodeid.c` (this phase) — both run every shared vector of `tests/vectors/nodeid/vectors.json` |
| e | Provisioned Pi and ESP32 both boot with EID + cert | `node/cmd/capsuletool/main_test.go` (the §2.6 ceremony end-to-end, this phase); `raspberry/provision.sh install_nodeid` (kit install, structure-checked, absent kit = loud SKIP, this phase); the on-hardware boot legs (Pi daemon reading its identity, ESP32 NVS payload at flash time) are P3.2+/P3.3 field bring-up |
| f | Handshake vectors (RFC 9529-shaped traces); replay rejected via persisted sequences; TOFU change fails loudly | `node/internal/link` tests: `TestHandshakeHappyPath` / `TestHandshakeFailClosed` / `TestSessionCheckpointAndRestart` / `TestSessionRoundtripAndReplay` / `TestCrossImplementationLinkVectors` (P3.3); `esp32/components/dtn_core/host/tests/test_link.c` (`test_link_vectors_handshake` / `test_link_vectors_replay`, P3.3) — both suites run the 28 shared vectors of `tests/vectors/link/vectors.json` (via the generated `host/tests/link_vectors.h`): byte-identical handshake messages, ciphertexts and frames, and identical accept/reject verdicts. The official crypto anchors are pinned directly on both sides: RFC 3610 (Go, variable-tag engine), RFC 5869 cases 1–3 (both), RFC 7748 §6.1 (both), RFC 8032 §7.1 (Go `crypto/ed25519` per P3.1; C sign path added P3.3), FIPS 197 C.1 (C). TOFU: an authenticated identity under an unexpected EID fails the session with `nodeid.ErrPeerKeyChanged` (`TestHandshakeFailClosed/expected_peer_change_fails_loudly`, mirrored by the C responder's id_cred-vs-pinned-key gate) |
| f2 | §5.4 frame + window: byte layout, fail-closed parse, interleaved reassembly; a lost frame never corrupts sibling windows; duplicate-index discipline | `node/internal/link`: `TestFrameSealOpen` / `TestFrameFailClosed` / `TestWindowSplitJoin` / `TestWindowInterleavedWithLoss` / `TestWindowRefusals` (P3.3); `host/tests/test_link.c` (`test_link_vectors_frame` / `test_link_vectors_window`, P3.3); the lossy-channel end-to-end cases run the whole stack over the fake radios: `host/tests/test_mac.c` (`test_link_lossy_e2e` — 3 interleaved windows, scripted drops, redundancy 2) and `node/internal/serialcl` (`TestBridgeRoundTripWithHandshakeAndLoss` — handshake + bundle-frag window through a lossy serial pipe) |
| f3 | MAC v1 (§5.3): CAD LBT + exponential randomized backoff, rolling duty budget, per-contact budgets, wake/beacon-window scheduling | `host/tests/test_mac.c`: `test_mac_backoff` / `test_mac_duty` / `test_mac_contact_budget` / `test_mac_beacon_windows` (P3.3 — deterministic via the injected fake clock/rand and the scripted fake channel) |
| g | Multi-hop A→B→C delivery: envelope bytes unmodified, hop octet honored and capped at 7, dup-safe | `tests/node_plane_e2e.sh` (the bash gate: three daemons on a line topology, capsuletool injection, SQLite-asserted stores, hop 0→1→2, dup absorbed — P3.5) and `node/internal/forward/integration_test.go` (`TestMultiHopDelivery` — three FULL stacks with real SQLite stores over loopback: byte-unmodified envelope at offset 1, same bundle_id, creation/lifetime identical — no life extension, hop 0→2, dup injection deduped at B, the A↔C↔A loop terminating with zero transfers on the converged re-contact, and the §3.1 ceiling dropping a hop-6 bundle's forwarding at B; P3.5) |
| g2 | §7.5 bundle store: admission pipeline (parse, hop ceiling, local expiry, dedup, classification), the priority-aware eviction order, cap honesty, janitor; budgets bound a hostile peer | `node/internal/forward/store_test.go` (`TestClassifyPinsTheEIDRules`, `TestStoreAdmissionPipeline`, `TestStoreExpiryAndJanitor`, `TestStorePriorityAwareEviction`, `TestStoreEvictionWithinClassIsSoonestExpiring`, `TestStorePersistAcrossReopen`, `TestStoreRefusesNewerSchema`, `TestStoreCapIsReportedHonestly`) + `node/internal/forward/integration_test.go` (`TestContactBudgetBindsHostilePeer` — a peer flooding beyond the §7.4 contact budget is refused "No Resources", the store bound holds, and the session survives for a graceful §6.1 farewell); `esp32/components/dtn_core/host/tests/test_forward.c` (`test_store_semantics` — cap honesty, classification, persist/dedup across reopen, byte-exact fetch, janitor); BOTH suites run the 2 store scenarios of `tests/vectors/forward/vectors.json` (7 admission steps: accepted/dup incl. the hop-rewritten copy/expired/hop-capped/at-cap, the priority eviction order, survivor sets byte-identical Go↔C via the generated `host/tests/forward_vectors.h`); the ESP32 cap parameter is constructor-honest (`dtn_bundlestore_cap` returns what the board passed, never fabricated) |
| g3 | §7.1 epidemic sync v1: Bloom summary bytes, diff outcomes, the §7.3 priority discipline, the summary-as-bundle handshake | `node/internal/forward`: `sync_test.go` (`TestBloomShapeAndMembership`, `TestBloomFalsePositiveRateBound`, `TestMissingComputesTheTransferList`, `TestSummaryPDUCodecRoundTrip`, `TestSendQueuePriorityDiscipline`, `TestSendQueueBulkBacklogDoesNotStarveManagement` — a bulk backlog never delays a management bundle by more than one transfer window, §7.3), `vectors_test.go` (`TestForwardVectorsStable`/`TestForwardVectorSmoke`), and the handshake legs of `integration_test.go` (`TestMultiHopDelivery` — the summary exchange over real sessions); `esp32/components/dtn_core/host/tests/test_forward.c` (`test_epidemic_vectors`); BOTH suites run the 5 bloom + 3 diff vectors of `tests/vectors/forward/vectors.json` byte-identically Go↔C (unsalted SHA-256-derived indexes, §7.1's frozen derivation) |
| h | Budget-gated TCPCLv4 transfer with TLS 1.3 and pinned node certs — the §6.3 pinned RFC 9174 subset, end to end | `node/internal/tcpcl`: `wire_test.go` (golden bytes for the contact header, SESS_INIT, XFER_SEGMENT single/multi with the Transfer Length Extension, XFER_ACK, XFER_REFUSE, SESS_TERM, MSG_REJECT, KEEPALIVE + the fail-closed length caps) and `session_test.go`: `TestFirstContactTofuPin` / `TestPinChangeFailsLoudly` / `TestExpectedPeerMismatchFails` / `TestSESSInitNodeIDMismatchFails` (TOFU + the loud identity gates), `TestNoTLSIsRefused` / `TestVersionMismatchTermIsSent` (the §4.3 negotiation verdicts), `TestMTLSRequiredDemandsClientCert` / `TestMTLSOptionalAcceptsUncertifiedClient` (both §6.2-item-4 modes), `TestTransferRoundTripAndReassembly` / `TestSequentialTransfersNoInterleaving` (§5.2.2: NO in-session interleaving — concurrency is multiple sessions, `TestIntegrationParallelSessions`), `TestMalformedBundleRefused` / `TestTransferMRURefused` (fail-closed admission + the authoritative length extension), `TestBudgetIngressRefused` / `TestBudgetEgressDeferred` (the §7.4 gate on both directions), `TestUnknownTransferAckIsMessageUnexpected` / `TestUnknownMessageTypeRejected` (§5.1.2), `TestKeepaliveFlowAndIdleTimeout` (§5.1.1: keepalives seen, silence terminated at 2×), `TestGracefulTermination` / `TestEndingRefusesNewTransfers` / `TestCloseIsUncleanTermination` (§6.1 both paths), `TestGoroutineBudgetSettles` (the leak assertion); `integration_test.go`: `TestIntegrationFullContact` (the two-stack loopback gate: TLS both ways, valid + malformed + budget exhaustion + graceful SESS_TERM); the identity plane: `node/internal/nodeid/cert_test.go` (`TestSelfSignedX509Binding` — the §6.2 item-4 certificate) — all (P3.4). Daemon wiring: `node/main_test.go` (`TestNodePlaneDisabledIsNoop` / `TestNodePlaneRequiresSeed` / `TestNodePlaneEndToEnd` — config-gated listener + the P3.5 store behind the sink + the §7.1 summary sent + pin checkpoint + WAL commit on close); `capsuletool cert` (`TestCertCommand`) and `capsuletool bundle` (`TestBundleMake`, P3.5). Honest boundary, updated P3.5: the bash-level gate is `tests/node_plane_e2e.sh` (row g) — the 1.4.0 note named a `sync_e2e.sh` extension; the landed form is that dedicated additive file, same conventions, its own port range |
| i | Level-gated command enforcement: below-level command dropped + counted; L3 lifecycle issue→use→revoke→observe island-wide | `node/internal/mgmt`: `mgmt_test.go` (`TestBelowLevelDropsSilently` — an L1 cert against the L2 `set_store_cap`: dropped + `dropped_bylevel`, NO reply, NO executed executor, `TestPipelineVerdictClasses` — every §8.2 drop class with the exact per-class counter), `vectors_test.go` (`TestMgmtVectorsGoImplementation` — the 12 shared vectors of `tests/vectors/mgmt/vectors.json`, Go-signed, verdict + seq-table state pinned), and `integration_test.go` (`TestL3LifecycleIslandWide` — three FULL stacks over TCPCL loopback with real SQLite stores and the REAL `capsuletool` driving the offline anchor ceremony: issue → operate → `install_cert` distribution (op cert + a new manager's cert, merged everywhere by the §2.5 seq rules with zero conflict signals) → anchor revocation → the revoked manager's next command dropped + counted on every node with zero replies — NO online server anywhere); `esp32/components/dtn_core/host/tests/test_mgmt.c` (`test_mgmt_vector_verdicts` — the same 12 vectors byte-identically Go↔C via the generated `host/tests/mgmt_vectors.h`, verdicts AND per-signer seq-table states, plus `install_cert`'s args-cert merge through the §2.5 rules) |
| j | Capsule chunking over both CLs; reassembly hands a byte-exact capsule to staging; stale capsule refused | P3.7 tests (extends the offline-maintenance staging vectors) |
| k | Directory cards/deltas as bundles with §3.4 merge rules verbatim | P3.8 tests (reuses the offline-maintenance federation vectors) |
| l | Passive capture of the node-plane radio reveals no plaintext mail and no plaintext management | `node/internal/mgmt/integration_test.go` (`TestPassiveCaptureRevealsNoPlaintext` — a full management exchange over TLS-wrapped TCPCLv4 sessions through a byte-recording TCP proxy: the captured stream contains no command names and no marker plaintext, while the receiving node provably executed both commands) |
| m | User-plane regression: §14/§15 surfaces byte-unchanged | existing `make test` / `tests/sync_e2e.sh` / `make chaos` (every phase) |

**P3.3 hardware bring-up boundary (honest deferral).** Everything above runs host-tested on both implementations. Explicitly DEFERRED to hardware bring-up (P3.3 field work / P3.9): the sx126x register-level driver as a `dtn_radio` vtable implementation (§5.5 — the BSD LoRaMac-node port, unverifiable on the host); the two-unit bench radio tests (attenuator + distance, §1's AC); the ESP32 NVS persistence of the §6.2 sequence checkpoints and node identity behind the landed `dtn_session_store` / `dtn_nodeid_store` seams (RAM reference implementations are host-tested); and the real UART transport under the §5.5 length prefix (the Go side is net.Pipe/bytes-tested; the C side is the radio head's flash-time wiring).

**P3.6 hardware bring-up boundary (honest deferral).** The management plane is host-tested end to end on both implementations (§11 rows i/l): Go signs, enforces, replies and revokes island-wide over real TCPCL/TLS sessions with real stores; C decides every shared vector identically. Explicitly DEFERRED to hardware bring-up: the ESP32 executor wiring (P3.7/P3.9 feed `dtn_mgmt_decide`'s verdicts into the radio MAC's dial/janitor handles — the decision function, the §2.5 cache feed and the seq table are landed and host-tested); the radio quiet-hours application of `set_quiet_hours` (the policy store is real, the radio is P3.3+); and the ESP32's NVS-backed own-cert provisioning at flash time (the §2.6 seam is the landed `dtn_nodeid_store`).

**P3.5 hardware bring-up boundary (honest deferral).** The C forwarding core is host-tested (`dtn_bundlestore` + `dtn_epidemic` over the shared vectors, §11 rows g2/g3), and the Go daemon runs the full engine behind `-tcpcl`. Explicitly DEFERRED to hardware bring-up (the relay firmware autonomy of P3.3/P3.9): the ESP32 task wiring that feeds `dtn_bundlestore_admit` from the LoRa MAC's receive path and drives the §7.1 exchange from beacon windows (the contact scheduler is the §5.3 MAC's wake-window logic; the seam is the `dtn_radio`/MAC vtable already landed); the ESP32's honest bundle cap VALUE (a flash-partition budget decision taken at firmware bring-up against the real partition table — the parameter and its honest reporting exist now, the number waits for hardware); and the epidemic exchange over the LoRa link sessions at MAC airtime budgets (the budget table of §7.4 rows 1–2 binds it; integration is P3.9 field work).

## 12. Resolved decisions (issue #33 §5, recorded ADOPTED)

| # | Decision | Status | Rationale |
|---|---|---|---|
| 1 | Node-plane wire format: **BPv7 profile (RFC 9171 subset)** | **ADOPTED** | Validated here: overhead 46–47 B ≤ 80 B; 399 B envelope = 3 frames ≤ the exit bound. RFC vectors, µD3TN interop path, a real network layer; the custom-header fallback was not needed. |
| 2 | Link handshake: **EDHOC-shaped minimal exchange on mbedTLS primitives** (RFC 9528 reference, RFC 9529 vectors) | **ADOPTED** | Standards alignment with a migration path; PSK-only rejected (no PFS). Measured messages 38/134/91 B — single-frame each. |
| 3 | Repeater hardware: **ESP32-S3 + SX1262** | **ADOPTED** | #39 made S3 the fleet baseline; SX1262 TX ≈ 118 mA / RX ≈ 4.3 mA fits the solar budget; Pi HAT stays a documented alternative. |
| 4 | Radio plan: **separate channel profile** (own sync word + SF/BW) | **ADOPTED** | Frame-grammar isolation; independent duty budgets; §14.3 stays frozen without disambiguation hacks (§5.1). |
| 5 | Routing: **epidemic v1; PRoPHET deferred behind island metrics** | **ADOPTED** | RFC 6693 is experimental and its state costs airtime; measure first (§7.2). |
| 6 | BPSec: **deferred** (COSE-in-payload now) | **ADOPTED** | Byte budget + draft churn; format-compatible to add later (P-2). |
| 7 | Manager auto-election: **deferred** (provisioned roles in v1) | **ADOPTED** | Consensus in a partitioned DTN is a liability; revisit only with a concrete deployment need (§8.4). |

Owner sign-off for these decisions is recorded by implementation proceeding on this document per the issue's P3.0 row.

---

## Changelog

- **1.6.0 (2026-10-07, issue #33 P3.6):** the management plane, additive to §8, §11 and §10.7's status surface. §8.1 gains the frozen exact command-object layout (fixed key order 0..5; COSE parameters identical to the §2.2 cert with the kid = the SIGNER's fingerprint; canonical args maps over the closed value set uint | tstr | bstr; issued-skew ≤ 300 s and the v1 **24 h validity bound**) and the **frozen v1 command table** — eleven commands from L0 `get_status` to L3 `install_cert` (distributes an ALREADY anchor-signed cert; issuance stays an offline ceremony) and `factory_reset_node_plane` (node-plane state only, never user-plane mail, loud). §8.2 pins the enforcement order exactly as implemented (shape → §2.5-effective signer from the kid → signature with the CERTIFIED key → target → table → level → per-signer seq freshness with the floor moved at execution → local-clock expiry), the full RAM counter set (`commands_accepted` / `dropped_shape` / `dropped_sig` / `dropped_target` / `dropped_unknown` / `dropped_bylevel` / `dropped_seq` / `dropped_expired` + the reply and §2.5 cert merge counters) and the operator's one-command-in-flight discipline over an ordered-nothing epidemic network. §8.3 pins the reply object (fixed keys 0..2, signed by the executor, codes 0/1, drops never reply, aggregate-only data, ≤ 1 h lifetime, re-admission for summary convergence). New §8.5: the sink consumption contract — bundles to this node or `dtn://og-admin/` are consumed BEFORE the forward store (and before the §3.1 hop ceiling), the three payload classes discriminated by inner-map pair count (8 cert / 6 command / 3 reply; anything else falls through to the store), consumed copies re-admitted so the §7.1 epidemic sync propagates commands, certs and revocations island-wide with NO online server. Implementations: `node/internal/mgmt` (command/reply objects, the Enforcer, the §8.1 executors over the §7.5 store and the dial loop, the RAM policy store) wired behind the daemon's `-tcpcl-anchor-pub`/`-tcpcl-node-cert` flags (fail-closed: no anchor = no management plane; `/status` gains the additive `node_plane` member under the §10.7 N/A convention — role/level from the provisioned cert, the mgmt + cert merge counters, store fill/cap, peer/session counts, and deliberately NO EIDs, fingerprints or addresses); `capsuletool admin sign|show`; the C mirror `dtn_mgmt` (the §8.2 DECIDE function, the per-signer seq table, `dtn_cbor_peek` added to the reader) fed by the rolecert cache for install_cert. Shared vectors `tests/vectors/mgmt/vectors.json` (via the generated `host/tests/mgmt_vectors.h`): 12 Go-signed commands — valid broadcast/targeted, bad signature, unknown signer, revoked signer, below-level, replayed seq, expired, future-issued, unknown cmd, wrong target, install_cert — verdicts AND seq-table states byte-identical Go↔C. §11 rows i/l carry the real test names (below-level drop + the full L3 island-wide lifecycle over three TCPCL stacks with the real capsuletool ceremony; the passive-capture proof over a recording TCP proxy). No §1–§7 rule changed; the user plane is untouched (the §10.7 diagnostics member is additive-only under protocol.md §15.4, noted as protocol.md 1.14.0).
- **1.5.0 (2026-10-07, issue #33 P3.5):** the forwarding engine, additive to §7 and §11. New §7.1 note: the v1 sync handshake rides the BUNDLE plane — no new TCPCL message exists; the summary travels as a §3 P-5 identified bundle (dest = the peer EID, payload = `sync-version(1) ‖ Bloom(512 B)`), consumed by the receiver's sink, never stored; the Bloom hash derivation is frozen (`index_i = BE_u32(SHA-256(i ‖ id)[0:4]) mod 4096`, unsalted — the privacy stance: inputs are opaque P-7 digests); contacts are episodic (held for the exchange, terminated; cargo between contacts rides the next one). New §7.5 note: the admission pipeline (Parse fail-closed, the §3.1 hop ceiling as a counted drop, local expiry at admission, P-7 dedup absorbing the hop-rewritten copy, the v1 EID classification — `dtn://og-admin/` management, anonymous→`dtn:og-mail` mail, everything else bulk; P3.6/P3.7 extend) and the eviction policy: refuse-newest-for-oldest-expiring, priority-aware — lowest-priority class first, soonest-expiring within it, deterministic tie-breaks, a bulk arrival never evicts mail/management, nothing is traded down (full higher-priority store → `at_cap` refusal). Implementations: `node/internal/forward` (store.go: SQLite WAL in its own database file, own `bundles` table and `user_version`; sync.go: the Bloom/diff/queue/engine over the §6.3 sessions via a new additive `Config.OnEstablished` hook — no wire byte added; the §7.4 egress budget defers to the next contact) and the C mirrors `dtn_bundlestore.c` (CRC-framed log + RAM index, the `dtn_store` pattern; the constructor's cap is the board's honest number, reported by `dtn_bundlestore_cap`) + `dtn_epidemic.c`. Shared vectors `tests/vectors/forward/vectors.json` (via the generated `host/tests/forward_vectors.h`) run on BOTH suites: 5 byte-exact Bloom sets, 3 diff outcomes, 2 store scenarios (12 admission steps with identical verdicts and survivor sets). Daemon wiring: the P3.4 stub sink is replaced (store + engine + routing sink; `-tcpcl-store`, `-tcpcl-store-cap`, `-tcpcl-dial-interval`, `-tcpcl-debug` flags; the bundle janitor on the §10.6 cadence; graceful shutdown closes the store; counters stay internal RAM-only — `/status` additions remain P3.6's). New gates: the Go integration suite (`node/internal/forward/integration_test.go` — the A→B→C AC, loop termination, hostile-peer budget bound), the additive `tests/node_plane_e2e.sh` (three daemons on a line topology with `capsuletool bundle make`/`bundle send` — the one-shot TCPCLv4 client with TOFU pinning — wired into `make test` at ~15 s and available alone as `make test-node-plane`), and `-race` on the tcpcl+forward packages. §11 rows g (real names), g2/g3 (new), and the row-h boundary note updated; the P3.5 hardware bring-up boundary recorded (ESP32 task wiring, the honest cap value, LoRa-side exchange — deferred to P3.3+/P3.9). No §3–§6 rule changed; the user plane is untouched (its envelope stores stay empty in the E2E, asserted).
- **1.4.0 (2026-10-07, issue #33 P3.4):** the TCPCLv4 Wi-Fi plane, additive to §6.2. New §6.3 pins the implemented RFC 9174 subset and every chosen option: the establishment mode exactly as the RFC specifies (plaintext contact headers with the CAN_TLS flag first, TLS negotiated by the AND of the flags, the in-band TLS upgrade before any other message with the active peer as TLS client, SESS_INIT from both entities); the message set (contact header §4.2, SESS_INIT §4.6, XFER_SEGMENT/ACK/REFUSE §5.2, KEEPALIVE §5.1.1, SESS_TERM §6.1 with the REPLY flag, MSG_REJECT §5.1.2 — and the record that RFC 9174 has no XFER_INIT: a transfer starts with the START flag); transfer-ID semantics and the no-interleaving rule with concurrency via multiple sessions; the Transfer Length Extension as authoritative on receive; the END-ack-only-after-validation ACK discipline; TLS 1.3 (RFC 8446, carried forward by RFC 9846) REQUIRED with the self-signed Ed25519 node certificate (CN + URI SAN = the EID; the BundleEID otherName form documented as not needed), the §6.1 TOFU pin over the leaf public key (same PinStore, same loud `ErrPeerKeyChanged`), mTLS required-by-default / optional-but-defined (§7.12.1-shaped, counted), and PKIX verification replaced (never skipped) by the pin check; the §7.4 per-contact budget enforced on ingress (refuse "No Resources") and egress (defer); keepalive with the idle timeout at exactly 2×; fail-closed framing caps; §6.1 termination on both paths. Implementations: `node/internal/tcpcl` (wire codec with golden-byte tests, session engine, TLS/pinning, listener/dialer, counters), `node/internal/nodeid` gains the X.509 cert builder (`SelfSignedX509`, `CertNodeKey`, `CertCoversEID`, `CertFingerprintHex`), `capsuletool cert`, and the daemon's OPTIONAL `-tcpcl*` wiring (OFF by default; the sink is an honestly-labeled validate-and-count stub until P3.5). §11 row h carries the real test names. No §3–§6.1 rule changed; the LoRa plane and the user plane are untouched.
- **1.3.0 (2026-10-07, issue #33 P3.3):** the LoRa link layer, the MAC and the convergence layers, additive to §5/§6/§11. §5.4's byte layout is frozen exactly (header `version(2)|type(3)|flags(3)`, types beacon/session/mail-win/bundle-frag, flags 0 in v1) with TWO honest corrections: the frame payload budget is **222 B of plaintext** (1.2.0 said ≤ 220 B — the bundle-frag window's 1 + 221 B needs 222, and §4.1's capacity table was already frozen at 221 B/frame), giving a 252 B on-air maximum inside the SX126x 255-byte limit (header ‖ nonce(13) ‖ ciphertext ‖ tag(16)); and the window header's 2-bit `total` field is pinned as **total − 1** (the grammar's "fragment count (1–4)" does not fit 2 bits raw). §6.1's signature transcript is corrected: `sig_r` covers `th1 ‖ EID_r` and `sig_i` the full `th1 ‖ EID_r ‖ EID_i` — the literal "both EIDs" for BOTH signatures was internally impossible (the responder signs before msg3 carries the initiator's EID); wire sizes unchanged at 38/134/91 B, now pinned by the implementation plus the handshake constants (`c_i = 0`, `c_r = 1`, the K2/K3 HKDF labels, the handshake AEAD salt). New §5.5: the serial convergence layer's frozen `[len:2 BE] ‖ [link frame]` prefix and the `dtn_radio` HAL with the sx126x register-driver deferral stated normatively (host tests drive the stack through in-memory loopback/lossy channels instead). §11 rows f/f2/f3 carry the real test names: `node/internal/link`, `node/internal/serialcl` and `dtn_core`'s `test_link.c`/`test_mac.c` execute the 28 shared vectors of `tests/vectors/link/vectors.json` byte-identically Go↔C (handshake with fixed ephemerals/seeds, CCM, frame, window, replay) with identical accept/reject verdicts, plus the official RFC anchors (3610/5869/7748/8032/FIPS-197) and the lossy-channel end-to-end cases over the fake radios; the hardware bring-up boundary (sx126x register driver, 2-unit bench tests, ESP32 NVS persistence behind the landed store seams, the real UART) is recorded honestly as deferred. Implementations: `node/internal/link` (AES-CCM-128, HKDF-SHA256, the EDHOC-shaped handshake, sessions with persisted checkpoints + replay windows, frames, window reassembly), `node/internal/serialcl`, the C mirrors in `dtn_core` (`dtn_ccm`, `dtn_hkdf`, `dtn_session`, `dtn_frame`, `dtn_mac`, `dtn_radio` + host fakes; the trimmed TweetNaCl's Ed25519 SIGN path re-enabled for the handshake, public-domain attribution unchanged). No §3/§4 budget changed; §1–§2 rules untouched.
- **1.2.0 (2026-10-07, issue #33 P3.2):** the BPv7 profile codec, additive. `node/internal/bundle/bundle.go` (Encode/Parse/RewriteHop/BundleIDOf, the NewMail/NewManagement constructors, the §3 P-1..P-7 validation table with stable failure codes, the canonical re-encode check; the CBOR reader promoted from nodeid into the package as `bundle.CborReader`) and the C mirror in `dtn_core` (`dtn_bundle.c/h` + the new canonical-CBOR writer `dtn_cbor_writer.c/h`); shared conformance vectors `tests/vectors/bundle/vectors.json` executed by BOTH suites (§11 row c updated to the real test names) — 40 vectors byte-identical Go↔C (encode, parse-accept, parse-reject, hop-rewrite); §4's budgets re-pinned as exact codec numbers (290/446/172 B, 46–47 B mail overhead); the RFC 9171 vector provenance recorded honestly in §11 (no official byte-level examples exist; the µD3TN interop spot-check stays deferred). No §3 rule changed.
- **1.1.0 (2026-10-07, issue #33 P3.1):** node identity and provisioning, additive. New §2.6 provisioning ceremony (offline anchor → node keygen → request → offline sign → kit → `provision.sh install_nodeid`; ESP32 NVS payload named as P3.3+ hardware work over the landed `dtn_nodeid_store` seam); P3.1 implementations: `node/internal/nodeid` (self-certifying EIDs, COSE_Sign1 role certs per §2.2, the §2.5 cache with counters, the TOFU pin store with `Marshal` persistence) and the verify-only C counterpart in `dtn_core` (`dtn_nodeid`/`dtn_rolecert`/`dtn_cbor`/`dtn_ed25519`/`dtn_sha256` + the embedded public-domain TweetNaCl trim); shared conformance vectors `tests/vectors/nodeid/vectors.json` executed by BOTH suites (§11 rows d/e updated to the real test names); `capsuletool` (`anchor keygen`, `rolecert keygen/request/sign/verify/id`). No §1–§2.5 rule changed; matrix rows d/e renamed, nothing dropped.
- **1.0.0 (2026-10-07, issue #33 P3.0):** initial normative release. Two-plane model with the rfc4838-alignment §8 and offline-maintenance §2.8 amendments (§1); self-certifying EIDs, role-cert schema, roles/levels, seq merge rules (§2); the Offgrid BPv7 profile freeze with the 1-byte hop-octet hop-limit mechanism (§3); measured byte budgets — mail bundle overhead 46–47 B (≤ 80 B budget), 399 B envelope in 3 frames, management overhead 79 B fixed, handshake messages 38/134/91 B (§4, §6); radio plan with region matrix and measured airtime table incl. drift record vs the issue estimates (§5); EDHOC-shaped link security (§6); epidemic forwarding, budgets, shared stores (§7); management plane (§8); capsules and directory over the plane with honest bandwidth accounting (§9); threat-model delta (§10); conformance matrix (§11); the seven issue §5 decisions recorded ADOPTED (§12). Byte math measured by `node/internal/bundle/spike.go` and pinned by its tests.

---

*End of the node-plane specification. Changes require a version bump of this document; user-plane changes remain governed by `docs/protocol.md` §15 exclusively.*
