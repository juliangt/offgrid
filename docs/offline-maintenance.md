# Offline Island Maintenance — Design Record (issue #37)

| | |
|---|---|
| **Version** | 1.0.0 |
| **Date** | 2026-10-05 |
| **Status** | **Design record — complete and implementable, NON-NORMATIVE until its follow-up issues land.** The one part of #37 that is already normative (the unknown-recipient conformance pin) lives in `docs/protocol.md` §10.5 / §15.7 row q, not here. The key words **MUST**, **MUST NOT**, **SHOULD**, **MAY** (RFC 2119/8174) mark decisions that the implementing issues are bound to; they become normative for Modules B/C as each lands. |
| **Owns** | The **distribution and trust** problem of issue #37: how software releases and directory changes *enter* an island whose nodes never touch the Internet, and who is allowed to say so. The *application* mechanics of an upgrade (backup, migration, health gate, rollback) are #22's — this document reuses them, never redefines them. |
| **Related** | #37 (this), #22 (`raspberry/upgrade.sh` apply/rollback machinery), #28 (identity QR — the strong bootstrap), #26 (rotating `dest_hint` — the privacy mitigation), #16 (rate-budget patterns), #31/#36 (health/status surface), #18/protocol §15.5 (capabilities `build`), #33 (LoRa — capsules explicitly excluded) |

---

## Contents

- §1 Problem statement
- §2 Workstream 1 — signed release capsule
  - §2.1 Capsule format (byte-exact) · §2.2 Release key and offline signing ritual · §2.3 Entry points · §2.4 Staging endpoint · §2.5 Apply policy · §2.6 Anti-rollback policy and counters · §2.7 Threat-model delta · §2.8 Out of scope
- §3 Workstream 2 — directory propagation
  - §3.1 Signed identity card · §3.2 Registration gains the card · §3.3 Federation protocol · §3.4 Node merge policy and eviction · §3.5 Key continuity / TOFU · §3.6 Privacy accounting · §3.7 Mule UX — the directory ferry
- §4 Phasing — follow-up issues
- §5 What is already pinned today

---

## 1. Problem statement

### 1.1 The island model

A deployment is an island: fixed Wi-Fi nodes that are **never connected to the Internet, by design** (protocol §2, §12; the AP firewall kills every escape route — `docs/hardening.md` §2). The only transport between nodes is physical: users' browsers acting as data mules (protocol §11). Every capability that today requires "download the new release" therefore does not exist and cannot exist on the node. Two things must nonetheless keep evolving for years: the node software itself, and the recipient directory users register into.

### 1.2 Today's physical-only update paths

| Path | Mechanism | Cost |
|---|---|---|
| Reflash (`docs/RUNBOOK.md` §4.6) | `raspberry/install.sh` from a release bundle; the node holds no secrets, so a card swap is a full reset | Physical access + a fresh card; loses nothing but takes the node down for minutes |
| In-place upgrade (#22, `docs/BUILD.md` §5 Path 4, `docs/RUNBOOK.md` §4.8) | `install.sh --upgrade --offline /media/usb` — the operator carries the bundle TO the node on a USB stick; `raspberry/upgrade.sh` backs up, swaps, health-gates, auto-rolls-back | Physical access to **every** node, once per release |

Both are safe and both are tested (`tests/upgrade_e2e.sh` drives the real library rootlessly). Neither scales to an island of N nodes spread over kilometers: an operator must physically reach every node for every release. **One node upgraded is one node upgraded; the release does not travel.**

### 1.3 The directory gap

The directory is per-node and disconnected (protocol §2, §9, §10.3): `POST /api/v1/directory` upserts into the local SQLite table; mules carry only envelopes; nodes never talk to each other. A user who registers on node A is invisible to node B — and a sender can only compose to a recipient whose X25519 key is in *their* node's directory (protocol §4.3, Q3 of #37). Today the only fix is re-registering at every node a user visits. The in-person QR exchange (#28, protocol §4.7) fixes it pairwise — two people meet — but nothing propagates an identity to nodes neither party ever visited. **This is the real user-visible gap #37 names.**

### 1.4 What is already solved and is NOT redesigned here

- **SPA distribution rides the daemon** (protocol §15.6): the client code is embedded in the binary (`embed.FS`) and served same-origin, so delivering one `dtn-node` binary updates the SPA on every node it reaches and every mule that visits. Only the daemon binary needs a distribution story. Workstream 1 is exactly that story.
- **Outdated-node detection** has a hook: `GET /api/v1/capabilities` advertises `build` (protocol §15.5, #18). The capsule design adds the machine-comparable `release` integer next to it (§2.4.3).
- **Unknown-recipient envelopes** are correct today and are now pinned normatively: the push path never consults the directory; unknown-`dest_hint` envelopes are stored, served, TTL-expired — never rejected (`docs/protocol.md` §10.5, §15.7 row q, test `TestUnknownRecipientStoredServedExpired`). §5 of this document records the pin; no code changes.

---

## 2. Workstream 1 — signed release capsule

### 2.1 Capsule format (byte-exact)

A **release capsule** is a single self-describing binary file: one `dtn-node` payload binary for one target architecture, a metadata block, and an Ed25519 signature over both. Format version 1 is defined here and frozen under the same philosophy as protocol §14.1/§15: fields are never repurposed; compatible bumps only append.

#### 2.1.1 Byte layout

```
offset   size        field
0        8           magic   "OFGRIDUP" (ASCII, exactly these 8 bytes)
8        2           format  big-endian uint16, MUST be 1
10       4           mlen    big-endian uint32, metadata length M in bytes
14       M           metadata  UTF-8 canonical JSON, fixed member order (§2.1.2)
14+M     P           payload   the release binary, byte-exact
14+M+P   64          sig     Ed25519 detached signature (below)
```

Total size = `14 + M + P + 64`. With today's release binaries (10.8–11.3 MB per `node/build.sh` targets) and M ≈ 350 bytes, a capsule is ≈ 11 MB — the numbers every bound in this section is sized against.

#### 2.1.2 Metadata block

Canonical JSON per protocol §5 (UTF-8, no whitespace, integers minimal, **fixed member order — never sorted**), exactly these members in exactly this order:

| # | Member | Type | Constraint |
|---|---|---|---|
| 1 | `v` | integer | MUST be `1` (capsule format version). |
| 2 | `release` | integer | The **monotonic release version** — the sole ordering key for the anti-rollback rule (§2.6). MUST be ≥ 1. Derived from semver as `major*1_000_000 + minor*1_000 + patch` (v1.12.0 → `1012000`); the formula is frozen for format version 1, a different scheme bumps `v`. |
| 3 | `semver` | string | Display tag (e.g. `"v1.12.0"`). Cosmetic; MUST agree with `release` (the signer tool asserts it), never used for ordering. |
| 4 | `vcs` | string | Git revision of the build (the `git describe` output `build.sh` already stamps into `main.build`). |
| 5 | `arch` | string | `"armv6"` \| `"armv7"` \| `"arm64"` — the `build.sh` target of the payload, matching the consumer board's `uname -m` mapping (`install.sh` lines: aarch64→arm64, armv7l→armv7, armv6l→armv6). |
| 6 | `min_upgrade_from` | integer | The oldest `release` this capsule may upgrade. A node running `release < min_upgrade_from` MUST refuse to stage (it needs the migration path of a reflash, #22's downgrade-refusal logic made explicit before the fact). |
| 7 | `spa_embedded` | boolean | MUST be `true`: the payload embeds the SPA (`go:embed` web root). A daemon without the portal would strand every mule's client code (protocol §15.6). |
| 8 | `payload_sha256` | string | 64 lowercase hex, SHA-256 of the payload bytes. Gives staging a precise "corrupted payload" diagnosis before any cryptography, and gives apply a cheap integrity re-check. |
| 9 | `payload_bytes` | integer | `P`, the exact payload length in bytes. MUST equal the actual remaining bytes between the metadata block and the signature (length-coherence check). |
| 10 | `created_at` | integer | Unix seconds at signing time; `> 0`, ≤ now + 300 at staging (the §4.3/§10.5 skew rule). |

`M` MUST be ≤ 1024 bytes (enforced at staging; future additive members — protocol §15.4 style: unknown members MUST be ignored by verifiers, but the SIGNATURE still covers them verbatim — share the budget).

#### 2.1.3 Signature (binding)

`sig` = Ed25519 detached signature, made with the release **private** key, over the byte string `metadata ‖ payload` (the verbatim M metadata bytes followed by the P payload bytes). Verification reconstructs the same byte string from the parsed offsets — nothing is canonicalized or re-serialized before hashing, so verification is byte-exact by construction. A future format version 2 MAY change what is signed; version 1 never will.

#### 2.1.4 Implementation home

Shared code in `node/internal/capsule` (parse/verify/build — used by both the signer tool and the staging endpoint so they cannot diverge), plus a thin command `node/cmd/capsuletool` (`keygen`, `sign`, `verify`, `inspect`) built by the same module. Conformance vectors (the §2.1 layout with a synthetic 1 KB payload, plus one real signature) are pinned by the implementing issue's Go test, in the style of protocol §6's test vectors.

### 2.2 Release key and offline signing ritual

The Ed25519 release keypair is **crown-jewel infrastructure** (§2.7). The public half is not secret — only its integrity matters; the private half never touches a networked machine.

1. **Generation.** On an air-gapped machine: `capsuletool keygen --priv release_key.priv --pub release_key.pub` (32-byte Ed25519 seed; `release_key.priv` written mode 0600). Two USB copies of the private key in separate physical locations; a record of the public key's fingerprint (`sha256sum release_key.pub`) in the operator's deployment log.
2. **Signing ceremony.** Per release, on the air-gapped machine: bring in the release binaries + `SHA256SUMS` (verify checksums), run
   `capsuletool sign --priv release_key.priv --arch arm64 --release 1012000 --semver v1.12.0 --vcs <rev> --min-upgrade-from 1009000 --bin dtn-node-linux-arm64 --out offgrid-update-1012000-arm64.capsule`
   (one capsule per target arch), then `capsuletool verify --pub release_key.pub <file>` for every artifact, and record the capsule fingerprints in the release notes. The capsule is the ONLY artifact that travels — the private key stays put.
3. **Public-key pinning at provisioning (the exact integration points).**
   - `release_key.pub` ships inside the release bundle (next to `SHA256SUMS`), so a kit-provisioned node pins it during the checksum-verified install.
   - **`raspberry/install.sh`** gains `--release-key FILE` (optional): validates the file is 44-char Base64 decoding to exactly 32 bytes, fail-closed otherwise.
   - **`raspberry/provision.sh`** gains one step, `install_release_key`, listed in BOTH `STEPS` selectors (the fresh-install list and #22's upgrade subset — currently `preflight static_ip install_configs install_binary enable_units field_hardening persist_firewall`, `upgrade.sh` line ~387): it copies the key from the resolved bundle to **`/opt/dtn-node/release-key.pub`** (mode 0644, `root:root` — the same policy `install_binary` applies to the daemon).
   - **Idempotence rule:** a routine `--upgrade` installs the pinned key only if absent; an EXPLICIT `--release-key` overwrites it. Key rotation is a deliberate operator ceremony (generate new keypair → re-pin on each node with `--release-key`, or reflash §4.6) — never a side effect of upgrading.
4. **Rotation and leak recovery** (stated now, so it is never improvised): if `release_key.priv` leaks, every provisioned node will accept attacker-signed capsules as genuine — a full software-supply-chain compromise of the island. Recovery is physical by necessity: generate a new keypair, re-pin the new public key on every node (`install.sh --release-key` or reflash §4.6). Nothing else — no network revocation — exists on an island. This asymmetry (cheap to compromise, expensive to recover) is why the ceremony in (1)–(2) is offline-first and two-copy.

### 2.3 Entry points

Any device that can join a node's AP can deliver a capsule. Both entry points deliver **the same artifact to the same endpoint** (`POST /api/v1/update/stage`, §2.4) — format and verification are entry-point-agnostic by construction:

1. **Drive-by laptop:** the operator downloads the capsule once (any one-time Internet access), joins each node's AP in turn, and POSTs the file (curl or the SPA's file-picker control).
2. **Mule device:** the capsule is loaded onto a phone that already walks the island as a data mule; its browser POSTs the stored file to each visited node (the SPA's "load an update" control, a plain `<input type=file>` → `fetch` POST — no native app, works on every full browser; silent in captive mini-browsers per the §13.4 banner rule).

The capsule does NOT ride the envelope store, the transit queue, or LoRa (§2.8): it is a direct Wi-Fi delivery to the staging endpoint, carried by the same physical movement as mules.

### 2.4 Staging endpoint

**`POST /api/v1/update/stage`** — new endpoint under `/api/v1`, additive per protocol §15.4 (no existing endpoint changes). It is the only new write surface of Workstream 1.

#### 2.4.1 Authentication model

There are no accounts, tokens or sessions: **the capsule's signature IS the credential.** The endpoint verifies the Ed25519 signature against the pinned `/opt/dtn-node/release-key.pub`. Holders of the release private key are exactly the people allowed to offer software; everyone else's capsules fail verification and are counted (§2.6.2). A node whose key file is missing (never pinned, pre-capsule install) answers `503 update_key_unpinned` — staging is unavailable, not misbehaving; the operator pins a key per §2.2.3.

#### 2.4.2 Request/response shape

- Request body: the RAW capsule bytes. Content-Type MUST be `application/octet-stream` (a deliberate, documented exception to the §10.1 JSON-body convention — the body is not JSON and MUST NOT be parsed as any).
- Body cap: **48 MiB + 64 KiB** → `413 body_too_large` beyond. Implemented as a route-scoped wrapper (the global §10.1 1 MiB `limitBody` middleware stays untouched for every other route). Today's payloads are ≈ 11 MB; the cap admits ~4× growth and is a config constant, not a promise.
- Budgets (issue-#16 pattern, `ratelimit.go`, RAM-only, keyed by source IP, `429 rate_limited` + `Retry-After`): the staging route rides the shared POST request budget (burst 60, refill 1/2 s) AND a dedicated **capsule budget: burst 2, refill 1 per hour per IP** — staging is rare and each attempt costs the node an 11 MB read + an Ed25519 verification.
- Success: `200 {"status":"ok","release":<N>}`. Failures (each recorded in the §2.6.2 counters): `400 invalid_capsule` (magic/version/length/shape), `400 corrupted_capsule` (size or SHA-256 mismatch vs metadata), `400 bad_capsule_signature` (Ed25519 failure), `409 stale_capsule` (anti-rollback, §2.6.1), `400 too_old_capsule` (`release < min_upgrade_from` — the node needs a reflash path, not this capsule).

#### 2.4.3 Where the node learns its own `release`

`node/build.sh` gains one ldflags stamp next to the existing `main.build`: `-X main.releaseVersion=<release integer>`, threaded to an additive `release` member (integer; `0` on builds that predate capsules) in `GET /api/v1/capabilities` and the health snapshot (the §10.7 "two documents, one identity" single-source rule applies). The running binary knows its own release in-process; no file, no probe.

#### 2.4.4 Staging semantics (binding order)

1. Read the body under the cap; parse magic/format/mlen; coherence-check `payload_bytes` and `payload_sha256` (`400 corrupted_capsule` on mismatch).
2. Verify the signature against the pinned key (`400 bad_capsule_signature`).
3. Enforce the monotonic rule of §2.6.1 against `max(running release, staged release)` (`409 stale_capsule`), then the `min_upgrade_from` floor (`400 too_old_capsule`).
4. Write the capsule to **`/var/lib/dtn-node/staged/update.capsule`**: write to `update.capsule.tmp` in the same directory, `fsync` the file, `os.Rename` over the target (atomic — a power cut mid-staging leaves either the old or the new capsule, never a half file), `fsync` the directory. Only ONE capsule is staged at a time; a strictly newer capsule replaces it (the rule of step 3 makes replacements monotone).
5. Answer `200` with the staged `release`. The staged capsule is NEVER applied mid-traffic — apply happens at boot or on explicit operator command (§2.5). The health/status surface reports `update.staged_release` (§2.6.2; the #31 "staged update pending" hook).

### 2.5 Apply policy

Apply reuses #22's machinery verbatim — the same functions `install.sh --upgrade` runs, driven by two new entry points. Nothing in this workstream re-implements backup, swap, gating or rollback.

| Step | Reused primitive (`raspberry/upgrade.sh`) | Notes |
|---|---|---|
| Extract + pre-verify | `node/internal/capsule` Verify (signature, `payload_sha256`) | Fresh eyes at apply time; the capsule on disk may have rotted |
| Probe expectations | `upgrade_probe_staged` | Runs the extracted binary against a throwaway DB on loopback; yields build + schema_version for the gate |
| Backup | `upgrade_backup_generation` (+ `upgrade_prune_generations`, keep 3) | Store + previous binary into `/var/lib/dtn-node/backups/upgrade-<ts>-<build>/` BEFORE anything is touched |
| Swap | `upgrade_swap_binary` (or `provision.sh install_binary` for ownership) | Binary only; the SPA is inside it |
| Gate | `upgrade_health_gate` (+ `upgrade_health_once`) | HTTP 200 + `status: ok` + build identity + schema_version + live `user_version` |
| Rollback on ANY failure | `upgrade_auto_rollback` → `upgrade_rollback_generation` | The displaced store preserved as `pre-restore-*` evidence |

Two apply triggers, both **never mid-traffic**:

1. **At boot.** A new oneshot unit `dtn-update-apply.service` (`Before=dtn-node.service`, `After=local-fs.target`): if a capsule is staged, pre-verify, probe, stop (a no-op before first start), back up, swap; then record expectations in `staged/update.json` and exit. `dtn-node` starts with the new binary and its migrations run on open (§15.3). A second oneshot `dtn-update-verify.service` (`After=dtn-node.service`) polls `upgrade_health_gate` against the recorded expectations and invokes `upgrade_auto_rollback` on failure — the #22 sequence, split around the boot so the gate sees a live service.
2. **On operator command.** `sudo ./install.sh --apply-staged` runs the full `upgrade_node()` path with the extracted payload as the binary source (service running: stop → backup → swap → start → gate → auto-rollback). This is `upgrade_node` with a different binary source and is nearly free to implement; it is also the manual retry after a boot-time gate failure.

Honest residual: if the boot-time verify unit itself cannot run (power cut in the seconds-long window), `dtn-node` runs the new binary ungated — the systemd watchdog still supervises liveness, and the next operator command or boot retries the gate. Accepted; the alternative (no unattended apply) defeats the feature.

### 2.6 Anti-rollback policy

**The tension:** #22's rollback is a safety feature (restore the previous binary + store, `docs/RUNBOOK.md` §4.8); uncontrolled version wind-back is a downgrade attack (re-expose a patched node to a fixed vulnerability).

**The policy (binding):**

1. **Operator-initiated local rollback stays allowed, unchanged:** `install.sh --rollback` (with `--from NAME`) remains the documented recovery path, physical access implied, `pre-restore-*` evidence discipline unchanged. A node MAY run old software if its operator says so.
2. **Network-offered capsules are held to a stricter rule — monotonic at staging:** a capsule whose `release` ≤ `max(running release, staged release)` is rejected `409 stale_capsule` and NEVER staged, whatever its signature. Genuine-old capsules are refused exactly like forged ones; replaying last year's release at a node does not wind it back.
3. `release < min_upgrade_from` is refused `400 too_old_capsule`: the gap is too wide for the migration chain to be trusted blind — the node takes the reflash path (§4.6) where the store is expected to be rebuilt.

#### 2.6.2 Counters and surfacing

The additive **`update` member** of the health snapshot / status view (single-sourced from the same snapshot, §10.7; counts are RAM-only atomics that reset on restart — the same accepted degradation as every §10.7 counter; the staged file itself is the durable record):

```json
"update": {
  "release": 1012000,
  "staged_release": null,
  "applied_release": null,
  "capsules_accepted": 0,
  "capsules_rejected_stale": 0,
  "capsules_rejected_signature": 0,
  "capsules_rejected_malformed": 0
}
```

| Member | Semantics |
|---|---|
| `release` | This build's own release integer (ldflags; `null` on pre-capsule builds — the N/A convention of §10.7). |
| `staged_release` | `null` = nothing staged; else the staged capsule's release. A public software fact, same class as capabilities' `build` (the #31 "staged update pending" hook). |
| `applied_release` | The release of the last capsule apply that passed its gate this process lifetime; `null` when none. |
| `capsules_accepted` / `capsules_rejected_*` | Staging outcomes, classified exactly like the push counters (§10.7): `stale` = 409, `signature` = 400 bad_capsule_signature, `malformed` = 400 invalid/corrupted/too_old. |

`GET /status` renders them on the Software identity card ("Staged update: none / release N — pending, applies at next boot"; "Capsules rejected (stale): 3"). The privacy rule of §10.7 holds: software facts and aggregate counts only — no IP, no timing, no per-client datum.

### 2.7 Threat-model delta (Workstream 1)

Hostile mules can now OFFER capsules to any node they visit. The outcomes, in the §13 style:

| Adversary action | Outcome |
|---|---|
| Forge a capsule (bad signature) | Rejected `400 bad_capsule_signature` at staging, counted; nothing written. Forging an Ed25519 signature over attacker-chosen bytes is assumed infeasible (protocol §7). |
| Replay an old-but-genuine capsule | Rejected `409 stale_capsule` (monotonic rule); counted. Replay is the capsule analogue of envelope replay (§13.5), closed differently: dedup cannot apply, so the version ordering does. |
| Offer a genuine capsule with `release < min_upgrade_from` | Rejected `400 too_old_capsule`; the reflash path is the only route across a too-wide gap. |
| Deliver a genuine-but-bad release (signing mistake, supply-chain compromise upstream of the key) | NOT preventable by any island mechanism — mitigated only by the staged apply + health gate + automatic rollback of #22, which bounds the blast radius to nodes that apply it and restores them without data loss. Capsules never auto-forward (nodes never talk, §2), so a bad release does not worm through the island; it only reaches nodes a mule deliberately visits. |
| Steal `release_key.priv` | Total software compromise: every provisioned node accepts the attacker's capsules as genuine. Recovery is physical re-pinning (§2.2.4). The key never lives on a networked machine; two offline copies; the public half is not secret. |
| Observe staging traffic | An anonymous POST over the open AP, like every other write (§13.2): the counters aggregate only; no IP, no identity, no per-request log line. |

### 2.8 Explicitly out of scope

- **Raspberry Pi OS packages stay frozen.** Unattended security-only upgrades (the `raspberry/` provisioning baseline) continue as-is; an air-gapped island accepts frozen OS packages for now. Capsules update exactly one thing: the `dtn-node` binary.
- **No LoRa capsule transport, ever in this design:** the 222-byte MTU of protocol §14.3 makes an 11 MB payload ~50,000 frames. Capsules ride Wi-Fi only. (#33's LoRa may carry *directory deltas* one day — within its CBOR mapping — not software.)
- **No multi-binary capsules, no delta patches** (format version 1 is single-payload by design; a delta format would be `v = 2` with its own trust analysis).
- **No auto-rollback scheduling, no update windows** beyond "boot or operator command": island nodes are solar-powered, not maintenance-window-driven.

---

## 3. Workstream 2 — directory propagation

### 3.1 Signed identity card (the "record")

A **directory record** (identity card) is a small SELF-SIGNED record binding an alias to both of a user's public keys, issued by the user's own client. It is the federation unit: mules carry cards, nodes merge them.

#### 3.1.1 Canonical form and signature (binding)

Canonical serialization follows protocol §5 exactly (UTF-8, no whitespace, fixed member order, minimal escaping — the members are §8.1-ASCII and Base64, so no escaping ever fires). The **signed byte string** is:

```
{"v":1,"alias":<alias>,"ed":<ed>,"x":<x>,"ts":<ts>,"seq":<seq>}
```

`sig` = Ed25519 detached signature by the card's OWN identity key `ed` over that string. The complete card serializes in fixed order `v`, `alias`, `ed`, `x`, `ts`, `seq`, `sig`.

| Member | Constraint |
|---|---|
| `v` | MUST be `1` (card schema version; a §15-style versioned convention — an unknown `v` makes the card invalid). |
| `alias` | MUST match `^[A-Za-z0-9_.-]{1,24}$` (the §8.1 alias regex). |
| `ed` | The user's **Ed25519 identity public key** — the contact's identity (§4.7), Base64 of exactly 32 bytes (44 chars). |
| `x` | The user's **X25519 encryption public key**, Base64 of exactly 32 bytes (44 chars). |
| `ts` | Issue time, unix seconds: `> 0`, and ≤ merge time + 300 (the §4.3 skew rule). |
| `seq` | Monotonic per-identity issue sequence, integer ≥ 1. The client keeps a counter in its identity store and increments it on every re-issue (registration, key rotation, alias change). This is the ordering key for the merge policy (§3.4). |
| `sig` | Ed25519 detached signature, Base64 of exactly 64 bytes (88 chars). |

The whole serialized card MUST be ≤ **1024 bytes** at every admission point (the `maxPrekeysBytes` pattern; the realistic card is ≈ 370 bytes). There is deliberately NO `crc` member (the §4.7 QR has one for scan corruption; cards travel over TCP and fail the signature anyway).

#### 3.1.2 Worked test vector

Same identity as protocol §4.6/§4.7 (RFC 8032 §7.1 test key; X25519 = the §11 deterministic seed derivation), pinned by the implementing suite against the vendored tweetnacl:

| Item | Value |
|---|---|
| `alias` / `ts` / `seq` | `alice_77` / `1791072000` / `1` |
| `ed` | `11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=` |
| `x` | `/R7hH59JUnnBjDLCUFTQ46F9eKg0kK8Chze1mEQpqVg=` |
| Canonical signed string (153 bytes) | `{"v":1,"alias":"alice_77","ed":"11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=","x":"/R7hH59JUnnBjDLCUFTQ46F9eKg0kK8Chze1mEQpqVg=","ts":1791072000,"seq":1}` |
| `sig` | `+ZQ/Mk1S6ouEM+jHGTZTe0hP8FEvQ+5rw71Ef3jlW/zrif+nmnp2F90RMlFIwRuBtfa1UCL9soGz95pkBwzADA==` |

Relation to §4.7: the card carries the same identity data as the OFFGRID1 QR payload plus `seq`. They stay deliberately separate formats: the QR is an in-person transport (CRC for camera corruption, no sequence), the card is the federation unit (sequence for merge ordering, no CRC). A QR scan never produces a card; the client mints its own.

### 3.2 Registration gains the card (wire-compatible)

`POST /api/v1/directory` gains one OPTIONAL member, **`card`** — additive per protocol §15.4, exactly the pattern `prekeys` set in 1.7.0:

- **Blind validation** (the node never verifies a message signature, and does not verify the card's either at THIS door — §3.4 does that at merge time): exact member set; `v == 1`; alias regex; `ed`/`x` Base64 → 32 bytes; `ts` integer > 0; `seq` integer ≥ 1; `sig` Base64 → 64 bytes; whole member ≤ 1024 bytes; **plus two blind consistency equalities:** `card.ed == body.pubkey` and `card.x == body.x25519` (pure shape equality — a card about a different identity than the entry it rides is malformed). Any violation → `400 {"status":"error","error":"invalid_card"}`; absence stores NULL (legacy clients unaffected).
- **Storage:** stored VERBATIM in a new nullable column. Storage schema version **5** (protocol §15.3 chain, purely additive, no row rewritten):

```sql
ALTER TABLE directory ADD COLUMN card   TEXT;                       -- the card as published
ALTER TABLE directory ADD COLUMN source INTEGER NOT NULL DEFAULT 0; -- 0 = local upsert, 1 = federation merge
```

- `GET /api/v1/directory` serves the additive `card` member verbatim when the row holds one (§8.1 NOTE grows accordingly: ≈ +370 B/entry worst case, same order as the prekeys NOTE). The client mints the card at registration and re-publishes it on every upsert (§11 registration/replenish flow), so a refreshed entry always carries its current card.

### 3.3 Federation protocol (mule-carried)

Two new OPTIONAL endpoints, additive per protocol §15.4. Design driver: **the mule cannot key state per node** — every node serves the identical origin `offgrid.local:8080` on purpose (protocol §12), so a mule literally cannot tell which node it is talking to. The delta cursor is therefore CONTENT-derived, not node-keyed: a unix-seconds high-water mark over the server-set `last_seen` values.

| Endpoint | Shape | Notes |
|---|---|---|
| `GET /api/v1/directory/deltas?since=<unix-seconds>` | `200 {"status":"ok","since":<echo>,"more":<bool>,"records":[{"card":<card>,"last_seen":<int>,"epoch":<int>}, ...]}` | Returns rows with `last_seen > since` holding a card, ordered `last_seen ASC, pubkey ASC`, capped at **100 records** per response; `more` says whether a follow-up with the returned batch's highest `last_seen` will yield more. `since` absent → defaults to `now − 30 days` (first visit on a wiped device: bounded backfill, not the whole table). Cursor is echoed to keep the loop honest. Rows without a card (legacy or card-less registrations) are skipped — federation carries only signed records. |
| `POST /api/v1/directory/federate` | Body `{"records":[<card>, ...]}` → `200 {"status":"ok","accepted":<n>,"rejected":<m>}` | ≤ **100 cards** per batch (more → `400 too_many_records`, whole batch fails closed, §10.4 style). Cards are verified and merged per §3.4; per-card verification failures drop the card and count toward `rejected` WITHOUT failing the batch — a mixed batch of 99 good + 1 forged is 99 accepted, 1 rejected, `200`. Shape-violating batches (wrong envelope, > 100) → `400 invalid_card` / `400 too_many_records`. |

**Caps and budgets** (mirroring the envelope paths, issue-#16 pattern):

| Guard | Value | Rationale |
|---|---|---|
| Deltas response cap | 100 records | Bounds each SQLite read and each response (≤ 100 × ~0.5 KiB ≈ 50 KiB). |
| Delta GET budget | per-IP burst 30, refill 1/s, RAM-only (`429 rate_limited` + `Retry-After`) | It is a read, but a paging one — bounded like the diagnostics GETs of §10.7, not free like the single-shot directory GET. |
| Federate record budget | per-IP burst 300, refill 300 records/hour (whole-batch, withdrawn atomically before any verification work) | Half the envelope push quota (600/h): records are denser and cheaper, but the same "one station cannot own the path" logic applies. |
| Batch body size | rides the existing 1 MiB cap | 100 cards ≈ 40 KiB; the cap is never the binding constraint. |
| Mule ferry store cap | **500 records** in the SPA `directory_ferry` store — records count against their OWN cap, never the 100-envelope `transit_queue` (explicit #37 requirement) | FIFO eviction by fetch time, the transit-queue pattern. |

### 3.4 Node merge policy and eviction

Merge happens on the receiving node at `POST /api/v1/directory/federate`. **This is the one place a node verifies a signature, and it deserves the sentence:** protocol §1 blindness is an ENVELOPE-path rule — it keeps the node unable to read, judge or discriminate the mail it relays. Directory cards are public, self-signed records the node merges into its own public serving data (the node already displays this data, §10.3); verifying a card's self-signature protects the node's own public data from poisoning and preserves nothing that was opaque. The envelope path NEVER gains a lookup or a verification (§10.5 pin).

Ordered rules, per card (each card verified FIRST with its own `ed` key over the §3.1.1 string; verification failure → drop the card, count it in the response's `rejected`, continue the batch):

1. **Dedup key is the pubkey.** Look up `directory` by `pubkey = card.ed`. Absent → INSERT: `alias`/`x25519` from the card, `last_seen = now`, `epoch = floor(now/86400)` (server-set as always — clients never influence time, §6.1), `card` stored verbatim, `source = 1`.
2. **Present, `card.seq >` stored `seq`** (a row whose `card` is NULL has implied seq 0): replace `alias`, `x25519`, `card` (and refresh `last_seen`/`epoch`). This is the only way a served X25519 key ever changes: across a HIGHER-SEQUENCE SIGNED record. Key rotation now propagates island-wide; nothing mutates on an unverified claim.
3. **Present, `card.seq <` stored `seq`:** stale — drop silently, RAM counter `federation_stale_dropped`.
4. **Present, equal `seq`:** byte-equal card → no-op, counter `federation_duplicates`; differing content → **keep the existing row**, counter `federation_conflicts`. Equal-sequence ties NEVER overwrite (the first verified claim wins) — there is no honest reason for one identity to issue two different cards at the same sequence, so the tie is treated as an attack signal, not a race.
5. **Source promotion:** a LOCAL upsert (the user actually visited and POSTed) sets `source = 0` and follows §3.2's rules; a federated merge on a row that is `source = 0` updates keys/card per rules 2–4 but keeps `source = 0` — presence at this node is a local fact, key truth is a sequence fact.

**Eviction policy (the 500-entry serving cap, consistent with today's `last_seen DESC`):**

- The serving cap is UNCHANGED: `GET /api/v1/directory` = 500 rows by `last_seen DESC, pubkey ASC` (§10.3). Federated rows compete by `last_seen` like everyone; users re-publish on every visit, refreshing their row to the top.
- A new **hard table cap of 2000 rows** (4× the serving window) bounds DB growth from an open federation input. When rule 1's INSERT would exceed it: evict the `source = 1` rows with the OLDEST `last_seen` first (exactly the serving-cap ordering, applied to the eviction); counter `federation_evictions`. `source = 0` rows are NEVER auto-evicted — Phase 1's "directory rows are never auto-deleted" (§9) now holds for local rows unconditionally and for federated rows until pressure. If no federated row is evictable, the insert proceeds (soft cap for locals) and the count surfaces on `/status` so the operator sees the shape.
- RAM-only counters `federation_accepted`, `federation_stale_dropped`, `federation_duplicates`, `federation_conflicts`, `federation_evictions`, served as an additive `federation` member of the health snapshot (§10.7 rules: aggregates only, reset on restart).

### 3.5 Key continuity / TOFU (SPA)

The node-level seq rule (§3.4) protects the DIRECTORY. The user-level anchor is the device-local contact (§4.7): **a known alias presenting a different key is surfaced as a WARNING, never silently replaced.**

- When the recipient picker (contacts ∪ directory, deduped by key) observes two key sets under one alias — a local contact vs. a directory entry with a different `ed` — the SPA renders a continuity warning on the contact and on the compose screen ("alias `bob` is now associated with a different key on this node's directory — verify in person before sending"). The contact record itself is NEVER overwritten by directory data: QR-scanned or pasted contacts keep their keys; the directory supplies only fresh material (§4.7) for recipients the user has NOT pinned locally. (Design intent for THIS workstream, which refines today's shipped §4.7 behavior: currently the directory entry's `x25519` overrides a pinned contact's `x` for any identity the directory lists, silently — precedence pinned by the issue-#14 audit, protocol §13.5 spec 1.12.2 and tests/qr_identity.mjs (e); the pin-and-warn behavior is specified here and lands with the federation issues.)
- QR exchange (#28) is the strong bootstrap: an in-person scan is trust-on-sight of a physical person; federation is the convenience path that spreads what someone vouched for by showing their screen. A federated key change for a QR-pinned contact is the loudest warning the SPA can make.
- Mis-binding an alias to an attacker's key (directory poisoning) is THE attack this workstream invites: the defense is exactly this division — signed records bound the node's data (only the identity's own key can advance its sequence), and the SPA makes key changes visible instead of silent.

### 3.6 Privacy accounting

**The trade-off, stated plainly:** today a hostile node operator can link `dest_hint` → alias for every user in its directory — permanently, not epoch-confined (§13.3, spec 1.12.2; #26 rotation raises the per-epoch work factor, it does not decay linkage). A federated directory converges the island's identity data onto every node: an operator could recompute hints for users who NEVER VISITED its node — linkability widens from per-node to island-wide.

| Party | What federation lets it learn | What it still cannot learn |
|---|---|---|
| Node operator | The converged public directory: aliases, keys, server-set epochs of users who registered anywhere a mule visited — including users who never connected to this node. Can recompute `hint(E)` — or any candidate epoch, per the §13.3 correction of spec 1.12.2 — for all of them (§13.3 residuals unchanged in kind, widened in scope: directory-holder linkage is permanent, not epoch-confined). | Message content; sender identities (inside ciphertext, §4.2); which epoch a stored hint came from without recomputation; anything about users whose records never reached it. |
| Mule | The same public directory graph (it pulls and pushes it); with hostile intent, it can also drop or withhold records (availability attack only — verified signatures make poisoning impossible beyond §3.4 tie rules). | Anything inside envelopes; which records a given node lacked. |
| Hostile node (merge-side) | Nothing new: it verifies signatures, applies seq rules, and its counters are aggregates. It can DROP incoming records or refuse delta reads — censorship, visible nowhere but in slower convergence. | Cannot forge a card (needs the identity's Ed25519 key); cannot rewind a sequence (rule 2 only advances). |

Mitigations, in order of importance: (1) **#26 rotating hints remain a mitigation in degree, not in kind** — per the §13.3 correction (spec 1.12.2), a directory holder can recompute a user's hint for ANY candidate epoch (the epoch is a public counter, `created_at` rides in plaintext), so envelope-to-alias linkage is permanent; rotation forces per-epoch recomputation and bounds retroactive linking only after a LATE directory acquisition. Federation therefore widens an already-permanent capability — from a node's own registrants to island-wide — rather than opening a new class. (2) **Deltas are capped and pulled only as needed** (100/req, 300/h/IP, `since`-bounded): no node can force-feed the island a full directory at once, and a mule spreads records only where it actually travels. (3) Records carry public data only — alias, keys, server-set timestamps — never inbox, never hints, never message metadata. (4) The registration flow says what the directory is (public, per node); the ferry UI (§3.7) says what the mule carries. An island that finds the trade unacceptable stops at §3.2: cards publish, mules stay dumb, federation endpoints stay unimplemented — the design degrades to today's behavior by omission.

### 3.7 Mule UX — the directory ferry

A small "Directory ferry" surface in the SPA, consistent with the existing mule telemetry panel ("Foreign envelopes in transit: X / Capacity: 100", §11):

- Panel: **"Directory records in transit: X / Capacity: 500"**, plus records fetched / records pushed / conflicts seen (the node-reported `rejected` count) and last-ferry-sync time. Own telemetry, own store — the envelope numbers and the record numbers never mix.
- Behavior: automatic, part of the existing sync flow — AFTER the envelope sync, pull deltas (`since` = the ferry store's high-water `last_seen`); carry in `directory_ferry`; on the NEXT visited node, push the batch. Failed pushes keep the records and retry (the prekeys-replenish pattern, §4.6). FIFO eviction at 500, by fetch time.
- Storage: additive, idempotent IndexedDB migration **v6** adds `directory_ferry` (keyPath `ed`, plus the ferry cursor high-water in the meta record) — the §15.6 chain continues (v2 inbox_parts, v3 sent, v4 prekeys, v5 contacts → v6 directory_ferry). DB_VERSION 6.
- The staging endpoint of Workstream 1 gets its operator-facing twin here too: a "Load a node update" file-picker control (visible only where a file system makes sense — hidden in captive mini-browsers, the §13.4 banner rule), POSTing the picked file raw to `/api/v1/update/stage` and rendering the exact error short codes of §2.4.2.

---

## 4. Phasing — concrete follow-up issues (do NOT create from this document mechanically; re-check #37 first)

Ordered; each is independently landable and keeps the full suite green. Additive-only per protocol §15.4 throughout.

| # | Follow-up issue | Scope | Acceptance criteria |
|---|---|---|---|
| 1 | `feat: capsule format v1 + capsuletool` | `node/internal/capsule` (parse/build/verify), `node/cmd/capsuletool` (keygen/sign/verify/inspect), layout vectors | Go test pins the §2.1.1 byte layout (synthetic payload), a real §2.1.3 signature, and every rejection class (bad magic, bad version, length-coherence, SHA-256 mismatch, signature failure); `capsuletool sign` output round-trips through `verify` and `inspect`. |
| 2 | `feat: pin the release public key at provisioning` | `install.sh --release-key`, `provision.sh install_release_key` step in both STEPS lists, key shipped in the bundle | Fresh install pins `/opt/dtn-node/release-key.pub` (0644 root:root); a malformed `--release-key` file fails the install loudly; a routine `--upgrade` neither needs nor overwrites the key; `tests/upgrade_e2e.sh` extends to cover the new step rootlessly. |
| 3 | `feat: staging endpoint POST /api/v1/update/stage` | Endpoint + capsule per-IP budget + route-scoped body cap + `update` health member + `release` capabilities member (ldflags in `build.sh`) | Staging tests reject bad signature, replayed old version (409), corrupted payload, oversized body (413), unpinned key (503); success stages atomically (tmp+fsync+rename); the `update` counters surface on `/api/v1/health` and `/status`; budgets answer `429 rate_limited` with `Retry-After`. |
| 4 | `feat: capsule apply wiring (boot + operator command)` | `dtn-update-apply.service` + `dtn-update-verify.service` units, `install.sh --apply-staged` | Apply at boot swaps and gates using ONLY #22 primitives (`upgrade_backup_generation`, `upgrade_swap_binary`, `upgrade_probe_staged`, `upgrade_health_gate`, `upgrade_auto_rollback`); a gate failure rolls the node back with zero envelope loss (extend `tests/upgrade_e2e.sh` to drive the boot sequence rootlessly); `install.sh --apply-staged` reuses `upgrade_node` end-to-end. |
| 5 | `feat: identity card + registration member (schema v5)` | Card minting in the SPA engine, `card` member on directory POST (blind validation incl. the two equalities), migration 4→5 (`card TEXT`, `source INTEGER`), GET serves `card` | The §3.1.2 vector is pinned by a Go test AND an `.mjs` engine test; `400 invalid_card` on every shape violation and on the ed/x equalities; legacy POSTs without `card` behave byte-identically to today; migration preserves every row. |
| 6 | `feat: directory federation endpoints` | `GET /api/v1/directory/deltas`, `POST /api/v1/directory/federate`, merge policy §3.4, eviction, budgets, `federation` counters | Merge tests: insert, higher-seq replace, stale drop, equal-seq tie keeps existing + counts conflict, forged signature drops the card only; eviction prefers oldest federated and never touches local rows; budgets `429`; two fresh daemons converge through a scripted ferry (the Go-level half of the #37 E2E). |
| 7 | `feat: SPA directory ferry + key-continuity warning` | `directory_ferry` store (migration v6), ferry panel + telemetry, TOFU warning, "Load a node update" control | `.mjs` suite: ferry fill/evict at 500, delta loop against a dev daemon, the warning fires for an alias-key mismatch and never mutates the pinned contact; QR-pinned contact survives a federated key change untouched. |
| 8 | `test: E2E two nodes + one mule directory convergence` | `tests/sync_e2e.sh` leg (or a sibling script): node A + node B + a ferry role between them | #37's acceptance case, end to end: a user registered ONLY on node A becomes composable from node B after the mule walks once; a key rotation on A reaches B with a higher-seq card; the SPA warning fires on a hostile same-seq card. |

RUNBOOK/BUILD operator documentation ships with issues 2–4 (the ceremony of §2.2 → `docs/RUNBOOK.md` §4.9; `capsuletool` → `docs/BUILD.md` §5), not in a docs-only pass.

## 5. What is already pinned today

- **The unknown-recipient conformance pin (#37's node-side item) is DONE and normative:** `docs/protocol.md` §10.5 ("Unknown-recipient behavior"), cross-referenced from §10.4 step 2, §13.2 (node row), §13.5 (recipient-existence probing closed by design), §15.7 row q and §16 Module B. The test is `TestUnknownRecipientStoredServedExpired` and `TestUnknownRecipientResponseIndistinguishable` in `node/internal/api/unknown_recipient_test.go`: stored, served byte-identical, TTL-expired, directory table empty throughout, responses indistinguishable in status/member-set/status-value whether or not the directory has entries. No future PR may tighten admission into a recipient-existence check without breaking a normative row and a test.
- **#22 apply/rollback machinery** (`raspberry/upgrade.sh`): the exact functions §2.5 reuses, already driven rootlessly by `tests/upgrade_e2e.sh` — backup generations (keep 3), staged-binary probe, health gate (build + schema + live `user_version`), automatic rollback with `pre-restore-*` evidence.
- **#28 identity QR** (protocol §4.7): the strong bootstrap; its trust-on-sight model and device-local `contacts` store are what §3.5's warnings anchor to.
- **#26 rotating `dest_hint`** (protocol §6.1): the mitigation that bounds §3.6's widened linkability to within-epoch.
- **#16 admission-control pattern** (`node/internal/api/ratelimit.go`): the per-IP RAM-only token budgets §2.4.2 and §3.3 copy.
- **#31/#36 diagnostics surface** (protocol §10.7): the snapshot, budget and N/A conventions the `update`/`federation` members ride; the "staged update pending" hook #31 asked for lands in §2.6.2.
- **#18/§15.5 capabilities `build`**: the outdated-node detection hook; §2.4.3 adds the machine-comparable `release` integer beside it.
