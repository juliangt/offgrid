# Node Network Specification — Off-Grid DTN Node Plane (issue #33)

| | |
|---|---|
| **Version** | 1.2.0 |
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

Link frame: `[link header: version | type (mail-win | bundle-frag | session | beacon) | flags] [payload ≤ 220 B] [AEAD tag]` (the AEAD is §6's session). Bundle chunks ride as `bundle-frag` payloads with a per-bundle window header of the **§14.3(a) grammar — 1 byte `win_id(4)|idx(2)|total(2)`, ≤ 221 B payload/frame, total ≤ 4** — defined here as the node plane's own window format (the §14.3 user-plane bytes are not touched; the separate sync word of §5.1 removes any ambiguity). Partial windows expire with the bundle's TTL; retransmit policy is absent by design (§1 of issue #33).

## 6. Link security

### 6.1 The EDHOC-shaped handshake

An EDHOC-shaped minimal exchange (RFC 9528 as **normative reference**, RFC 9529 traces as vector reference), implemented on mbedTLS primitives — full EDHOC libraries remain research-grade (uoscore-uedhoc, edhoc-rs; tracked, revisit). Shape, frozen:

- **msg1** = `[1(suite), 1(X25519), g_x(32), c_i]` — **38 B**.
- **msg2** = `[g_y(32), c_r, ct2]` with `ct2 = AEAD(K2, th1(8) ‖ id_cred_r(8) ‖ sig_r(64))` — **134 B**. `sig_r` is Ed25519 over the transcript (`th1 ‖ both EIDs`); `id_cred_r` = `SHA-256(node_key)[0:8]`.
- **msg3** = `[ct3]` with `ct3 = AEAD(K3, id_cred_i(8) ‖ sig_i(64))` — **91 B**.

Every message fits **one** 221 B frame — under the < 3-frames bound with ≥ 2.4× margin (issue exit criterion met). Both sides verify the peer's `node_key` against its **cached role certificate** (§2.2) or pin it on first contact (**TOFU + loud warning**, the offline-maintenance §3.5 pattern): an EID whose key changes without a higher-seq cert fails the session, loudly. Fail-closed: links without a verified session carry nothing but beacons.

### 6.2 Traffic keys, replay, rekey

- **HKDF-SHA256** over the X25519 shared secret with the transcript hash as salt and `"offgrid-link-v1"` as info → a master secret; per-direction keys via HKDF-Expand with direction labels.
- **AEAD:** AES-CCM-128 (13-byte nonce = 5-byte session salt ‖ 8-byte big-endian per-direction sequence; 16-byte tag). ChaCha20-Poly1305 MAY be used on hosts without AES acceleration — same key schedule, same sequence discipline.
- **Sequence numbers are monotonic per direction and persisted** (flash on ESP32) so restarts do not rewind. Writers checkpoint every 32nd packet; after an unclean restart the sender resumes at last-persisted + 32 and the receiver's replay window (≥ 32) absorbs the gap. Replayed or reordered-beyond-window frames are dropped and counted.
- **Rekey** at 2^20 packets or 24 h, whichever first; sessions survive repeater reboots via the persisted state above.
- **IP plane:** TCPCLv4 (RFC 9174) with its native TLS 1.3 (RFC 9846) via mbedTLS — same node identity, same certificates, mTLS optional-but-defined.
- **Mail stays E2EE regardless:** the §14.3b trial-decrypt broadcast model is unchanged on this plane; channel crypto protects metadata and management traffic and defends user privacy in depth, never instead of §4.2.

## 7. Forwarding and storage

### 7.1 Controlled epidemic contact sync v1

On every contact (LoRa beacon window or TCPCL connect) peers exchange compressed summaries of stored `bundle_id`s, compute diffs, and transfer within per-contact budgets. Summaries are Bloom filters over 32-byte `bundle_id`s: **4096 bits (512 B), k = 4** — false-positive rate ≈ 0.1 % at 200 entries, ≈ 2 % at 500; false "have" answers cost one missed transfer that the next contact repairs, never corruption. Summary bundle: 591 B → 3 frames. This is RFC 4838's opportunistic-contact model with flooding made frugal.

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

## 8. Management plane

### 8.1 Admin command bundles

An admin command is an identified bundle (§3.4) to the well-known EID `dtn://og-admin/`, payload = **COSE_Sign1** (signed by the issuing node's `node_key`) over the CBOR map:

| CBOR key | Field | Type |
|---|---|---|
| 0 | `cmd` | tstr |
| 1 | `args` | map |
| 2 | `target_node` | tstr (node EID) |
| 3 | `issued_ts` | uint |
| 4 | `expiry` | uint |
| 5 | `seq` | uint, monotonic per signer |

### 8.2 Enforcement pipeline (normative order)

A receiving node processes an admin bundle only when it is the payload's `target_node` (or the command class is a documented broadcast, e.g. policy to `edge` nodes), in THIS order: verify COSE_Sign1 → resolve the signer's `node_key` to a cached, unexpired role certificate → check the cert grants `manager` (or the command's class) and `level ≥` the command's requirement (§2.4 table) → check `seq` freshness per signer (must exceed the last executed) → check `issued_ts`/`expiry` sanity → execute. **Any failure: drop silently + increment a RAM counter (`mgmt_dropped`); no error packets to strangers** — the §13.6 refusal-to-confirm pattern.

### 8.3 Telemetry replies

Replies adapt the RFC 9713 status-report **shape** (no IANA registration; private profile): an identified bundle back to the manager's EID, payload = COSE_Sign1 over `{0: reply_to (bstr 32 = the command's bundle_id), 1: code (uint), 2: data (map)}`. Data is **aggregate only** — the §10.7 privacy rules apply verbatim (no envelope ids, no hints, no aliases, no per-client data).

### 8.4 No consensus, no election in v1

Roles are provisioned facts, eventually consistent, signed. Auto-election (battery/connectivity-weighted manager promotion) is an explicitly deferred future spike — partitioned DTNs make online consensus a liability, not a feature (§12.7).

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
| f | Handshake vectors (RFC 9529-shaped traces); replay rejected via persisted sequences; TOFU change fails loudly | `node/internal/nodesec/handshake_test.go` *(P3.3)*; `dtn_core` link-session tests *(P3.3)* |
| g | Multi-hop A→B→C delivery: envelope bytes unmodified, hop octet honored and capped at 7, dup-safe | `tests/node_network_e2e.sh` *(P3.5)* |
| h | Budget-gated TCPCLv4 transfer with TLS 1.3 and pinned node certs | `node/internal/tcpcl` tests *(P3.4)* |
| i | Level-gated command enforcement: below-level command dropped + counted; L3 lifecycle issue→use→revoke→observe island-wide | `node/internal/mgmt/cmd_test.go` *(P3.6)* |
| j | Capsule chunking over both CLs; reassembly hands a byte-exact capsule to staging; stale capsule refused | P3.7 tests (extends the offline-maintenance staging vectors) |
| k | Directory cards/deltas as bundles with §3.4 merge rules verbatim | P3.8 tests (reuses the offline-maintenance federation vectors) |
| l | Passive capture of the node-plane radio reveals no plaintext mail and no plaintext management | P3.6 capture test |
| m | User-plane regression: §14/§15 surfaces byte-unchanged | existing `make test` / `tests/sync_e2e.sh` / `make chaos` (every phase) |

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

- **1.2.0 (2026-10-07, issue #33 P3.2):** the BPv7 profile codec, additive. `node/internal/bundle/bundle.go` (Encode/Parse/RewriteHop/BundleIDOf, the NewMail/NewManagement constructors, the §3 P-1..P-7 validation table with stable failure codes, the canonical re-encode check; the CBOR reader promoted from nodeid into the package as `bundle.CborReader`) and the C mirror in `dtn_core` (`dtn_bundle.c/h` + the new canonical-CBOR writer `dtn_cbor_writer.c/h`); shared conformance vectors `tests/vectors/bundle/vectors.json` executed by BOTH suites (§11 row c updated to the real test names) — 40 vectors byte-identical Go↔C (encode, parse-accept, parse-reject, hop-rewrite); §4's budgets re-pinned as exact codec numbers (290/446/172 B, 46–47 B mail overhead); the RFC 9171 vector provenance recorded honestly in §11 (no official byte-level examples exist; the µD3TN interop spot-check stays deferred). No §3 rule changed.
- **1.1.0 (2026-10-07, issue #33 P3.1):** node identity and provisioning, additive. New §2.6 provisioning ceremony (offline anchor → node keygen → request → offline sign → kit → `provision.sh install_nodeid`; ESP32 NVS payload named as P3.3+ hardware work over the landed `dtn_nodeid_store` seam); P3.1 implementations: `node/internal/nodeid` (self-certifying EIDs, COSE_Sign1 role certs per §2.2, the §2.5 cache with counters, the TOFU pin store with `Marshal` persistence) and the verify-only C counterpart in `dtn_core` (`dtn_nodeid`/`dtn_rolecert`/`dtn_cbor`/`dtn_ed25519`/`dtn_sha256` + the embedded public-domain TweetNaCl trim); shared conformance vectors `tests/vectors/nodeid/vectors.json` executed by BOTH suites (§11 rows d/e updated to the real test names); `capsuletool` (`anchor keygen`, `rolecert keygen/request/sign/verify/id`). No §1–§2.5 rule changed; matrix rows d/e renamed, nothing dropped.
- **1.0.0 (2026-10-07, issue #33 P3.0):** initial normative release. Two-plane model with the rfc4838-alignment §8 and offline-maintenance §2.8 amendments (§1); self-certifying EIDs, role-cert schema, roles/levels, seq merge rules (§2); the Offgrid BPv7 profile freeze with the 1-byte hop-octet hop-limit mechanism (§3); measured byte budgets — mail bundle overhead 46–47 B (≤ 80 B budget), 399 B envelope in 3 frames, management overhead 79 B fixed, handshake messages 38/134/91 B (§4, §6); radio plan with region matrix and measured airtime table incl. drift record vs the issue estimates (§5); EDHOC-shaped link security (§6); epidemic forwarding, budgets, shared stores (§7); management plane (§8); capsules and directory over the plane with honest bandwidth accounting (§9); threat-model delta (§10); conformance matrix (§11); the seven issue §5 decisions recorded ADOPTED (§12). Byte math measured by `node/internal/bundle/spike.go` and pinned by its tests.

---

*End of the node-plane specification. Changes require a version bump of this document; user-plane changes remain governed by `docs/protocol.md` §15 exclusively.*
