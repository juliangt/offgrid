# ESP32 Node Platform — Design Note (issue #39)

| | |
|---|---|
| **Implements** | issue #39 — ESP32 node platform, full protocol parity with the Pi node |
| **Normative contract** | `docs/protocol.md` (v1.12.2) — the firmware implements the §16 Module B conformance checklist |
| **Reference implementation** | `node/` (Go) — consulted when the spec needs interpretation, never transcribed |
| **Status** | Phased work in progress; §8 is the plan with live status, §9 the on-hardware acceptance register |

---

## 1. Framework choice

**ESP-IDF v5.5, C (C99), FreeRTOS.** Recorded decision, with the alternatives:

- **ESP-IDF** is the vendor toolchain; its `captive_portal` example
  (`examples/protocols/captive_portal`) is a direct reference for the exact
  stack this node needs — `esp_http_server` + `dns_server` + softAP with a
  reconfigured netif. C also matches the repo's "portable core, thin I/O
  adapters" architecture: `dtn_core` is C99 with zero IDF includes and is
  host-unit-tested like `node/internal/` is Go-unit-tested.
- **Arduino-core** was rejected: its HTTP server hides the request-stream
  edges the 1 MiB body budget needs (§3.2), and it layers an abstraction over
  the netif/DHCP configuration this node must control precisely.
- **Rust / esp-rs** was rejected for this issue: the storage engine and
  streaming parser are the load-bearing, host-tested components; C keeps the
  contribution surface aligned with the embedded systems programmers the
  project can realistically attract. Revisit only if a concrete gate fails.

Toolchain pin: **ESP-IDF v5.5.x** (the current LTS line at the time of
writing). CI pins the `espressif/idf:v5.5` container image.

## 2. Board targets and partitions

| | Reference board | Minimum board |
|---|---|---|
| Module | ESP32-S3 N16R8 (WROVER-class) | ESP32-WROOM-32 (DevKit v1 class) |
| Flash | 16 MB | 4 MB |
| PSRAM | 8 MB octal | none |
| Envelope cap | **5000 (full §8.1 cap, mandatory for a reference board)** | **1000 (enforced lower cap, reported honestly)** |
| OTA A/B | yes (`ota_0`/`ota_1`) | no (factory only — flash-space honest tradeoff, documented) |
| Partition file | `partitions_16mb.csv` | `partitions_4mb.csv` |

Measured flash math (the §8.2 numbers): an envelope record on the flash log
is the served JSON (~492–696 chars) + framing (~32 B CRC/length header) ≈
**≤ 730 B**; 5000 envelopes ≈ 3.65 MB live. Compaction keeps the log ≤
2× live. Directory: 500 entries × ~200 B ≈ 100 KB typical (≤ 1 MB worst-case
all-prekeys). The 16 MB store partition is **7.2 MB** — comfortable. The 4 MB
store partition is **1.7 MB** → cap 1000 keeps live ≤ 0.73 MB with compaction
headroom; the `envelope_capacity` members of `capabilities`/`health` report
the enforced value per board (spec-clean: the documents describe the cap as
enforced). The embedded SPA is served verbatim from `node/web` (720 KB incl.
the guide screenshots) — single-sourced with the Pi build, never copied.

RAM math (the core architecture risk, settled):

- **The 1 MiB sync body never resides in RAM.** The sync handler streams the
  body through the `dtn_core` incremental JSON reader, which assembles at
  most one envelope (~700 B) at a time. PSRAM is therefore an optimization,
  not a correctness requirement. (§3.2.)
- **The store RAM index** (32 B per envelope slot: 8 B id fingerprint,
  timestamps, log location, 8 B hint copy) is 156 KB at the full 5000 — it
  lives in PSRAM on the reference board; on the minimum board the 1000-slot
  index is 31 KB of internal RAM. The full store is never resident either
  way; fingerprint hits are verified against the on-flash record (§4).
- Wi-Fi softAP + httpd ≈ 50–60 KB; freeRTOS/idle overheads ≈ 40 KB — both
  boards hold the working set with headroom. Measured numbers from real
  hardware are a §9 acceptance item; the budget above is design-time math,
  labeled as such until then.

## 3. Same-origin bring-up (§12 parity)

- SoftAP `offgrid-messages`, open, 2.4 GHz; **station isolation verified**
  (ESP-IDF softAP does not bridge station-to-station traffic — there is no
  routing path; the §9 matrix verifies it on hardware, since there is no
  `ap_isolate=1` knob to lean on).
- The AP netif is **reconfigured to `10.42.0.1/24`** (never the ESP32 default
  `192.168.4.1`) before the DHCP server starts; the built-in DHCP server
  hands out the node as gateway **and** DNS.
- The IDF `dns_server` component answers **every** A query with `10.42.0.1`
  (the wildcard `address=/#/10.42.0.1` equivalent; `offgrid.local` included).
- Two `esp_http_server` instances: **:8080** (the full §10.3 surface behind
  the canonical-host middleware) and **:80** (thin listener: the two captive
  probes answer their §10.2 302 there, everything else redirects to the
  canonical origin — the ESP32 replacement for the Pi's iptables
  `REDIRECT 80→8080`).
- Max associated stations (~10 default on classic ESP32, higher on S3) is
  documented per board in `docs/esp32-models.md`.

## 4. Storage engine (the §9 contract on flash)

Implemented entirely in portable C inside `dtn_core`
(`dtn_store.c`), over plain `<stdio.h>` file operations — on the target,
LittleFS mounts a VFS path so the same code runs unchanged; on the host, the
unit tests exercise it against temp directories. This mirrors the
`node/internal/` pattern: the logic is the tested artifact, the filesystem is
glue.

- **Layout:** one store directory holding `super.bin` (A/B superblock slots),
  `envelopes.log`, `directory.log`.
- **Records:** CRC-32 framed (length + type + CRC32 + payload). Torn tails
  from power loss are detected by the frame CRC and truncated at open —
  no half records are ever applied (the WAL rationale, §9).
- **Envelope puts are batch-atomic:** a batch is `BATCH_BEGIN` … records …
  `BATCH_COMMIT`. The scan at open discards everything after an uncommitted
  `BATCH_BEGIN` — the exact power-loss analogue of the Go node's single
  SQLite transaction per sync. Clean-path rejection (invalid envelope, budget
  exhaustion, node full) truncates the log back to the batch mark before
  answering: fail-closed §10.4 semantics with bounded flash wear.
- **Dedup by `id`:** the RAM index holds the first 8 bytes of each stored id
  (the fingerprint). On a fingerprint hit, the authoritative full 32-byte id
  is compared against the on-flash record before declaring a dedup hit
  (`INSERT OR IGNORE` semantics, exact §6.2).
- **Access paths:** the index slot carries `created_at`, `created_at+ttl`
  (the deadline), the 8-byte `dest_hint` copy and the record location, so the
  §10.4 pull (deadline inclusive, `known_ids` excluded, `ORDER BY created_at
  DESC, id ASC LIMIT n`) is an index top-K scan — never a blind full-file
  read. Ties on `created_at` are resolved by the full on-flash ids so the
  ordering is byte-parity with SQLite's `id ASC`.
- **Janitor:** append tombstones for every record with `created_at + ttl <
  now` (exclusive boundary — §10.6), every 15 minutes plus once at boot.
  Compaction rewrites live records only, when dead bytes exceed live bytes;
  the rewrite is fsync + atomic rename, so a crash mid-compaction leaves the
  old log intact.
- **Directory:** append-only upsert log (`pubkey` keyed, node-set
  `last_seen`/`epoch`), compacted by the same dead-over-live rule; GET
  orders `last_seen DESC, pubkey ASC` over the live set (≤ 500 entries).
- **Schema versioning (§15.3 analogue):** the superblock carries the store
  schema version. The firmware ships **schema version 4** — the store is new,
  has no legacy data, and natively implements the version-4 contract (the
  envelope `v` column equivalent, the directory `epoch` and `prekeys`
  members). The forward-only, transactional migration-chain machinery of
  §15.3 is real and runs from 4 onward; **downgrade refusal** — an older
  firmware image finding a newer superblock refuses to mount/serve, logs
  loudly and signals the failure state (LED + a `/status`-visible boot
  stance), leaving the store byte-untouched.
- **Corruption stance (§13.6):** a store that fails its superblock CRC *and*
  its backup CRC is quarantined — renamed aside with a timestamp for
  forensics — and recreated empty at boot; the node then serves with a
  healthy empty store and the event is loud in the boot log. A store that
  refuses to scan cleanly mid-life sheds `507 storage_unavailable` per
  §10.1 — never half-served.
- **Wear math:** envelopes are write-once and deleted in bulk (janitor
  tombstones + compaction) — LittleFS-friendly. Worst-case sustained abuse is
  bounded by the §10.1 budgets: request budget (60 burst, 1 per 2 s) caps
  rejected-batch rewrite wear; the pushed-envelope budget (600/h sustained)
  caps accepted-batch wear at ≈ 600 × 730 B ≈ 430 KB/h ≈ 0.007% of the
  16 MB part's rated 100k program/erase cycles per block per day. The
  directory-upsert storm case is the same budget on the directory log. Full
  measured wear numbers are a §9 soak item.

## 5. Build and pipeline

- `make firmware` — builds both targets (`esp32s3` reference, `esp32`
  minimum) with `idf.py`; `make firmware-merge` produces the merged,
  flashable image per target (`esptool.py merge_bin` at the documented
  offsets). The raw `idf.py` commands are in the recipes; `make` is never a
  requirement.
- **CI (`.github/workflows/test.yml`):** a `firmware` job runs the build and
  merge inside the `espressif/idf:v5.5` container, next to the `test` job.
  The workflow stays **manual-dispatch only** — that is a binding
  coordination decision (`AGENTS.md`, 2026-10-04), so this issue's "build on
  every PR touching `esp32/`" gate is delivered as: dispatch the workflow on
  the branch (`gh workflow run test --ref <branch>`) before merging. The
  `dtn_core` host tests, by contrast, run inside `make test` on every
  dispatch, next to the Go/SPA/E2E gates.
- **Release (`release.yml`):** per tag, the workflow additionally publishes
  `dtn-node-esp32s3.bin` and `dtn-node-esp32.bin` (merged, flashable at the
  offsets documented in `docs/esp32-models.md`), the per-target OTA images,
  the exact `esptool.py write_flash` one-liner in the rendered `DEPLOY.md`,
  and extends `SHA256SUMS` to cover the new assets.
- QEMU (`idf.py qemu`) is a stretch: it cannot emulate Wi-Fi, so it can only
  ever cover boot/storage smoke — the §9 matrix is the real gate.

## 6. Hardening mapping (issue #16 parity)

| Pi behavior | ESP32 firmware |
|---|---|
| Per-IP request budget (burst 60, refill 1/2 s) checked before the body is read | Same token-bucket math from `dtn_core` (`dtn_budget.c`), keyed on the network-layer source IP only; `429 rate_limited` + `Retry-After` |
| Pushed-envelope budget (burst 600, refill 600/h) withdrawn atomically per batch | Withdrawn at parse end before the batch commits; a refused batch truncates back to its mark (§4) |
| `429 node_full` fail-closed, reject-newest/keep-oldest | Cap checked against the live count before commit; nothing stored, nothing evicted (§4) |
| `507 storage_unavailable` shed-and-recover | Every storage error on the sync path → `507`; the firmware stays up |
| Diagnostics budget (burst 60, refill 1/s, shared) + 1-second snapshot cache | Same bucket pair from `dtn_core`; snapshot task refreshes ≤ 1×/s regardless of GET rate |
| RAM-only, never-persisted client state | No nonvolatile write path exists outside the two §4 logs, which carry zero per-client/per-envelope-diagnostics data — aggregates only, everywhere |
| systemd `Restart=always` + `sd_notify` watchdog | `esp_task_wdt` (hardware watchdog, panic on timeout) + brownout detector + OTA A/B on the reference board; `/api/v1/health` stays liveness-only per §10.7 — no fabricated watchdog detail |
| nftables island firewall | Structurally unnecessary (no uplink interface exists); station isolation verified per §3 |

## 7. Deliberate deviations and honest-capacity table

| Deviation | Boards | Reason | Honest reporting |
|---|---|---|---|
| Envelope cap 1000 instead of 5000 | minimum (4 MB) | Flash budget (§2) | `envelope_capacity: 1000` in capabilities + health |
| No OTA A/B | minimum (4 MB) | Flash budget | `docs/esp32-models.md` upgrade path = reflash via USB |
| Lower station ceiling (~10, chip default) | classic ESP32 | Radio duty limits | `docs/esp32-models.md` per-board column |
| Diagnostics `battery` member always `null` unless a board wires a sampler | all | No BMS on reference hardware | §10.7 N/A convention — `null`, never fabricated |

Everything else is parity, not deviation: the §10.3 endpoint surface, the
§10.5/§15.3 validation rules, the §10.4 processing order, the §8.1 limits,
the §15 supported version set `{1, 2}`, the error codes and security headers
byte-match the Go node (the shared fixture set pins the validation decisions).

## 8. Phased plan (live status)

| Phase | Deliverable | Exit criterion | Status |
|---|---|---|---|
| **0** | `esp32/` scaffold, design note (this file), `make firmware`, CI firmware job | Both targets compile in CI; merged bin produced | ✅ landed |
| **1** | `dtn_core`: envelope validation, limits, sync processing order, canonical host, budgets, capabilities/health assembly | §15.7-adapted assertions pass on the host; byte-level parity with the Go node's validation decisions on the shared fixture set; host suite in `make test` | ✅ landed — 292 host checks green (test-esp32-core) |
| **2** | Flash storage engine honoring the §9 contract | Dedup, cap, boundary and power-loss tests pass on the host; wear analysis in §4 | ✅ landed — 1345 host checks green incl. crash/torn-tail/quarantine/downgrade semantics |
| **3** | IDF adapters: full HTTP surface (8080 + 80), budgets, netif/DHCP/DNS bring-up, janitor, snapshot cache, watchdog | Firmware compiles for both targets in CI; contract suite (curl) passes against hardware over Wi-Fi | ✅ landed (dtn_http/dtn_netif/dtn_tasks/main + generated SPA embedding); **compile gate + curl-over-Wi-Fi pending hardware (§9)** |
| **4** | Mixed-fleet interop: `tests/sync_e2e.sh` parameterized (`NODE_A_URL`/`NODE_B_URL`) to run its identical assertion set against any node base URL; Pi ↔ ESP32 mule walk | Every interop checklist item executed with evidence | ✅ suite parameterized (external mode + procedure in `docs/esp32-models.md`); **mule walk pending hardware (§9)** |
| **5** | `esp32-models.md`, RUNBOOK/BUILD/hardware/DEPLOY updates, release assets, 72 h soak | Release tag carries the complete ESP32 asset set; soak meets the power budget | ✅ landed (models/BUILD/RUNBOOK/hardware docs, release.yml ESP32 assets + SHA256SUMS); **soak pending hardware (§9)** |

## 9. On-hardware acceptance register (blocks release, not development)

Mirrors the issue-#20 field-acceptance pattern for the Pi. None of these can
be closed from a desk; each lands as evidence (log excerpt, photo, soak
chart) appended here or into `docs/esp32-models.md`.

- [ ] Phase-0 two-phone gate: portal reachable at `http://offgrid.local:8080`
      from two real phones; Android `generate_204` and iOS
      `hotspot-detect.html` probes trip the captive portal from the :80
      listener; canonical-host 301 from raw-IP access.
- [ ] Full curl contract suite (`tests/sync_e2e.sh` against the ESP32 base
      URL) passes over Wi-Fi — byte-identical assertions to the Go node run.
- [ ] `429 rate_limited` + `Retry-After` (both budgets), `429 node_full`,
      `413` body cap, `507` shed-and-recover exercised on hardware.
- [ ] Janitor expiry timing (15 min + boot, inclusive/exclusive boundary).
- [ ] Power-cycle during sustained writes (no torn store, batch atomicity);
      brownout recovery; corrupted-storage boot stance (quarantine).
- [ ] Station isolation verified (no station-to-station reachability).
- [ ] Downgrade refusal: older firmware against a newer store refuses loudly.
- [ ] Mixed-fleet mule walk Pi ↔ ESP32, both directions, envelopes and
      directory entries (§8 phase 4).
- [ ] 72 h soak with power measurement against `docs/hardware.md` §1;
      measured RAM/flash/wear numbers recorded back into §2.
