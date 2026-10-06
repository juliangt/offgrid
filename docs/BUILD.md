# Build, Deploy and Run Guide

Step-by-step instructions to build, test, run and deploy the off-grid DTN node (Module B daemon + Module C SPA) and its Raspberry Pi infrastructure (Module A). For the wire protocol see `docs/protocol.md`; for the power budget and wiring see `docs/hardware.md`.

## 1. Prerequisites

| Tool | Version | Used for |
|---|---|---|
| Go | ≥ 1.22 (verified with go1.27.1) | node daemon build and unit tests |
| Node.js | ≥ 18 (verified with v22.19.0) | the headless SPA suites (`tests/*.mjs`) only; nothing in the product needs Node |
| bash | ≥ 3.2 (any) | `node/build.sh`, `tests/sync_e2e.sh`, `tests/hardening_structure.sh`, the chaos suite (`tests/chaos/`), `raspberry/provision.sh`, `raspberry/install.sh` |
| make | any | the one-command entries `make test` / `make chaos` / `make build` (optional: every recipe is a plain shell command listed below) |
| curl | any | `tests/sync_e2e.sh`, the chaos suite, deployment verification |
| sqlite3 | any (CLI) | `tests/sync_e2e.sh` §15 coverage: schema-1 fixture crafting, migration and downgrade-refusal assertions (with `shasum`/`sha256sum` for the §15.7 b byte fingerprint); chaos suite: corrupt-database and flooded-store fixtures (with `truncate`/`dd`) |
| git | any | checking out this repository |

No C toolchain is needed: the daemon uses the pure-Go SQLite driver (`modernc.org/sqlite`), so `CGO_ENABLED=0` builds are fully static.

## 2. Local build

```bash
cd node
./build.sh
```

The script cross-compiles fully static binaries (`-trimpath -ldflags "-s -w"`, CGO disabled). Outputs, all gitignored (measured with go1.27.1, darwin/arm64 host):

| Output | Target (see `docs/pi-models.md`) | Size |
|---|---|---|
| `node/dtn-node-linux-arm64` | Pi Zero 2 W, 3, 4, 400, 5, CM4/CM5 (64-bit OS) | 10,682,528 bytes (~10.2 MiB) |
| `node/dtn-node-linux-armv7` | Pi 2, or a 64-bit board running a 32-bit OS | 11,141,280 bytes (~10.6 MiB) |
| `node/dtn-node-linux-armv6` | **Pi Zero W** (baseline), Pi 1, CM1 (32-bit OS only) | 11,141,280 bytes (~10.6 MiB) |
| `node/dtn-node-dev` | host OS/arch (development) | 10,751,314 bytes (~10.3 MiB) |

The ARMv6 build matters: the Zero W's ARM1176 core cannot execute a GOARM=7
binary (it aborts with `Illegal instruction`), so the baseline board needs
its own target. `raspberry/provision.sh` maps `uname -m` to the right file
(`aarch64`→arm64, `armv7l`→armv7, `armv6l`→armv6).

The web SPA travels inside the binary via `go:embed`: `node/web/` holds the `index.html` skeleton, the `css/app.css` stylesheet and the plain ES5 scripts under `js/` (vendored tweetnacl, protocol engine, IndexedDB store, UI wiring), all served same-origin by the node. A deployed node is still exactly one file plus its SQLite database.

## 3. Run locally (no hardware)

```bash
cd node
go run . -addr :8080 -db /tmp/x.db
# or, after ./build.sh:
./dtn-node-dev -addr :8080 -db /tmp/x.db
```

The daemon listens on all interfaces of port 8080 and stores envelopes in `/tmp/x.db` (SQLite, WAL mode; the file is created on first start).

**Browser testing tip (canonical origin).** The canonical-host middleware redirects any request whose `Host` header is not `offgrid.local:8080` to `http://offgrid.local:8080/` (protocol spec §10.2), so a browser opened at `http://localhost:8080` or `http://127.0.0.1:8080` lands on the canonical origin immediately. For the most faithful experience — a real `IndexedDB` under the exact production origin — add one line to `/etc/hosts`:

```
127.0.0.1	offgrid.local
```

then open **http://offgrid.local:8080**. Use two browser profiles (one as Alice, one as Bob/mule) to exercise the full send → carry → receive flow, exactly as `tests/crypto_roundtrip.mjs` does headlessly.

Flags:

- `-addr` — listen address, default `:8080`.
- `-db` — SQLite database path, default `node_storage.db`. Since Sprint 4 the parent directory is created automatically if missing (cold start on a fresh filesystem), so `-db /var/lib/dtn-node/node_storage.db` works on a stock system.
- Battery configuration (issue #36, all optional — the `/status` battery card renders N/A for whatever is not configured; the reading chain degrades I2C sensor → `power_supply` sysfs → voltage estimate → unknown and is never a startup dependency): `-battery-i2c /dev/i2c-1` enables an INA219/INA260-class sensor on that bus (pure-Go SMBus; disabled when omitted), `-battery-addr 0x40` its 7-bit address; `-battery-capacity-wh 128` declares the pack capacity in Wh (autonomy stays N/A without it); `-battery-dod-floor 20` overrides the depth-of-discharge floor in % SoC (default 20, `docs/hardware.md` §2.2 — the CRITICAL alert boundary); `-battery-full-v 13.6` / `-battery-empty-v 12.0` anchor the coarse voltage→SoC estimate for a 4S LiFePO4 pack (`docs/hardware.md` §9 resting voltages).

## 4. Run all tests

One command from the repository root (the exact sequence below, wrapped):

```bash
make test
```

The explicit steps, for CI copies and non-make shells (the same sequence
`make test` wraps):

```bash
# 1. Go unit tests (storage, api, envelope, sdnotify — including the fuzz
#    targets' seed corpora)
cd node && go test ./... -count=1 && cd ..

# 2. Crypto round-trip against the SPA engine (scripts in index.html order)
node tests/crypto_roundtrip.mjs

# 3. §4.6 prekey bundles and forward secrecy: canonical bundle string and
#    worked vector, selection/trial order, wipe-on-use, replenish,
#    compatibility both directions, chunking/acks over prekey envelopes
node tests/prekeys.mjs

# 4. §6.1 rotating dest_hint: HKDF vectors, candidate set, transition window
node tests/hint_rotation.mjs

# 5. SPA layout contract: referenced assets, CSP, load order, DTN API surface
node tests/spa_structure.mjs

# 6. PWA-lite assets (issue #29, §12.1): manifest members, relative
#    start_url/scope, maskable icon dimensions (PNG IHDR parse), iOS meta
#    tags, zero external URLs anywhere
node tests/pwa_assets.mjs

# 7. SPA §15 versioning policy: negotiation guard, blind v1→v2 conversion,
#    pull-path stored versions, store migration chain
node tests/version_migration.mjs

# 8. §4.4 long-message convention: split, signed chunk metadata, reassembly
node tests/chunking.mjs

# 9. §4.5 delivery-acknowledgment convention: ack construction, TTL formula,
#    sender-side bind
node tests/acks.mjs

# 10. §4.7 identity QR: worked vector (canonical string, CRC-32, Ed25519
#     signature), every tamper class with its reason, encoder round-trip
#     through an independent QR decoder across versions 1-15, recipient
#     merge (contacts ∪ directory), the §15.6 migration v5 step
node tests/qr_identity.mjs

# 11. SPA security hardening (issue #14 Phase 2): offline re-verification of
#     the vendored-tweetnacl/qrcode provenance hashes, nonce/ephemeral
#     freshness, the receive-path §6.2 envelope-id check (outer-field tamper
#     detection), the hostile-envelope battery (no crash, no store, no own-
#     classification), no key material on any wire object, and the static
#     source-hygiene contract (no XSS sink, no storage/logging/exfil
#     channel, fixed same-origin routes, closed CSP without data:)
node tests/spa_security.mjs

# 12. Full E2E: five daemons + mule walks with curl, §4.6 forward-secrecy
#     and §4.7 offline contact-exchange legs included (starts/stops its own
#     servers)
bash tests/sync_e2e.sh

# 13. Pi hardening structure (issue #16 Track 1): rootless --print/--dry-run
#     assertions on the generated firewall ruleset, tc shaping stream and
#     shield scripts (no hardware, no root)
bash tests/hardening_structure.sh

# 14. Node upgrade + rollback E2E (issue #22): the real raspberry/upgrade.sh
#     library — the code `install.sh --upgrade` / `--rollback` run on a Pi —
#     driven rootlessly against a temp "node" with a REAL populated store:
#     v1-era store migration on populated data, backup generation rotation,
#     health-gate success path, forced-failure automatic rollback, zero
#     envelope loss at every phase
bash tests/upgrade_e2e.sh

# 15. Issue-#20 field equivalents: the software-verifiable half of
#     docs/field-test.md — seed backup/restore round trip, one store across
#     two nodes (identity + inbox + transit survive), health/status agreement
#     within the documented cache window, and the fabrication guard on the
#     field-test scaffold (no pre-filled results). Needs go; owns
#     127.0.0.1:18201-18202.
node tests/field_equiv.mjs

# 16. docs/install-node.md structure (issue #35): the builder's guide exists
#     with all 10 required sections, the TOC anchors match the real headings
#     (GitHub's anchor algorithm), every relative doc link resolves to a file
#     and every cross-file heading fragment matches the target file, the
#     README wiring and the hardware.md forward pointer are in place, the
#     guide's key numbers agree with hardware.md (1 W, 0.90 buck, 0.80 DoD,
#     12.8 V, 20 W, both fuse ratings, the 0 °C charge ban, the 30% overnight
#     floor), every environment subsection carries its ASCII diagram, and the
#     glossary covers the unavoidable terms
node tests/install_node_structure.mjs
```

Expected outputs (assertion counts move as suites grow — the shape is what
matters):

1. `go test ./... -count=1` — one `ok` line per package:

   ```
   ok  	offgrid/dtn-node
   ok  	offgrid/dtn-node/internal/api
   ok  	offgrid/dtn-node/internal/envelope
   ok  	offgrid/dtn-node/internal/health
   ok  	offgrid/dtn-node/internal/power
   ok  	offgrid/dtn-node/internal/sdnotify
   ok  	offgrid/dtn-node/internal/status
   ok  	offgrid/dtn-node/internal/storage
   ok  	offgrid/dtn-node/internal/sysres
   ```

2. The crypto test ends with:

   ```
   PASS: 44 assertions against the SPA engine (index.html script order)
   ```

3. The prekey test ends with:

   ```
   PASS: 52 assertions on the §4.6 prekey bundles and forward secrecy (index.html script order)
   ```

4. The hint-rotation test ends with:

   ```
   PASS: 44 assertions on the §6.1 rotating dest_hint (index.html script order)
   ```

5. The structural test ends with:

   ```
   PASS: 195 structural assertions on the SPA layout
   ```

6. The PWA-lite asset test (issue #29, protocol §12.1) ends with:

   ```
   PASS: 46 assertions on the §12.1 PWA-lite assets
   ```

7. The versioning test ends with:

   ```
   PASS: 78 assertions on the SPA §15 versioning policy (index.html script order)
   ```

8. The chunking test ends with:

   ```
   PASS: 62 assertions on the §4.4 chunking convention (index.html script order)
   ```

9. The acks test ends with:

   ```
   PASS: 54 assertions on the §4.5 delivery-acknowledgment convention (index.html script order)
   ```

10. The identity-QR test ends with:

    ```
    PASS: 72 assertions on the §4.7 identity QR, contacts and offline exchange (index.html script order)
    ```

11. The security-hardening test (issue #14 Phase 2) ends with:

    ```
    PASS: 277 security-hardening assertions on the SPA engine and sources
    ```

12. The E2E script ends with:

    ```
    e2e: summary: 348 passed, 0 failed
    e2e: RESULT: PASS
    ```

    It builds the dev binary itself, starts its daemons on `127.0.0.1:18091`-`18095` (override with `PORT_A` / `PORT_B` / `PORT_C` / `PORT_E` / `PORT_D`, defaults `18091` / `18092` / `18093` / `18094` / `18095`) inside a temporary workdir which is always cleaned up. It simulates the complete mule journey — Alice → node A → mule → node B → Bob — and asserts payload byte integrity via sha256, dedup, TTL filtering, limit rejections and the canonical-host/captive-probe redirect pair, plus the §15 coverage: versioned admission and version-agnostic dedup in both orders (§15.7 c/d/e), the capabilities document (§15.5), schema migration of a crafted schema-1 database through the full chain to version 4 (§15.7 a) and downgrade refusal with a byte fingerprint (§15.7 b — these last two need the `sqlite3` CLI and `shasum`/`sha256sum`), the §4.6 prekey legs: bundle registration and verbatim directory round-trip, prekey-addressed delivery with wipe-on-use, the captured-traffic forward-secrecy proof, both legacy interop directions and the stale-SPK replenish (§15.7 j–m), the §4.7 identity-QR legs: a two-way OFFGRID1 payload exchange into the contacts (the directory endpoints stay EMPTY the whole time), the tampered-payload visible rejection storing nothing, the offline static-hint contact delivery in both directions and both inboxes verified — and the §12.1 PWA-lite legs (§15.7 o): the manifest's exact members with a relative `start_url`, the icons' PNG magic + IHDR dimensions, the portal HTML's manifest link + iOS meta tags + honest no-offline note, and zero external URLs anywhere.

13. The Pi hardening test ends with 197 assertions and:

   ```
   hardening: summary: 197 passed, 0 failed
   hardening: RESULT: PASS
   ```

   It needs no root, no hardware and no network: it asserts the anti-circumvention hardening of issue #16 Track 1 ("the AP is not free Internet") on the GENERATED artifacts — `bash -n` over every provisioning script; hostapd `ap_isolate=1` plus the control socket; dnsmasq's authoritative wildcard for the portal with the query log confined to tmpfs; the complete firewall ruleset via `raspberry/firewall/iptables.sh --print` (rootless rule-generation separation): FORWARD policy DROP with every rule scoped to the client subnet, the explicit VPN/DoT/proxy/DNS-egress escape-route kills, per-source DNS/ICMP rate limits, portal connlimit + SYN hashlimit on 8080, the captive-portal REDIRECT and the runtime shield chains; the tc cake shaping stream (`traffic-shaping.sh --dry-run`: dual-dsthost egress, IFB-mirrored dual-srchost ingress); and both shields' dry-run behavior against synthetic fixtures (shed the flooder/quota hog/connection hoarder, keep honest clients, never emit or persist DNS names or MACs). The Track 3 section (issue #16, hostile clients + node hardening) extends the same artifact-level approach: the firewall's client→tcp/22 INPUT kill (explicit drop by default, `ALLOW_SSH=1` opt-in accept); the daemon unit's hardening set (unprivileged `User=`, `ProtectSystem=strict` + `ReadWritePaths`, `Restart=always`, `WatchdogSec`, `RestrictSUIDSGID`, `MemoryDenyWriteExecute`); the sshd drop-in (keys only, no root login) and `harden-ssh.sh`'s validate-before-install; the read-only-root twins (`--dry-run`/`--status`, the durable `/var/lib/dtn-node` bind-mount inside the generated initramfs script, the rollback twin); the network watchdog (per-component restart plan, restart-storm guard gating, tmpfs budget state); and the counters-only telemetry (one aggregated integer line, no IP/MAC ever leaves the parsers, `all_sta` never invoked).

   The design behind these artifact assertions — the adversarial assumptions, the per-defense mapping with regression tests, the deliberate non-defenses and the shed → survive → self-recover contract — is `docs/hardening.md`.

14. The node upgrade E2E ends with:

    ```
    upgrade: summary: 67 passed, 0 failed
    upgrade: RESULT: PASS
    ```

    It sources `raspberry/upgrade.sh` — the very library `install.sh --upgrade` and `--rollback` execute on a Pi — binds every `DTN_*` path into a temporary "node" and overrides the three `upgrade_svc_*` systemd seams with plain background-process management, so the exact field code runs here rootlessly against real files and real daemons (on `127.0.0.1:18101`, disjoint from the E2E's `18091-18095` and the chaos suite's `18095-18099`). It needs `go`, `curl` and the `sqlite3` CLI. The legs: structural pins on the field wiring (`install.sh` modes, the binding stop → backup → swap → start → gate order, the provision.sh `STEPS` subset selector, the Makefile + docs wiring); two binaries from the current tree with distinct `-ldflags -X main.build=` ids; a v1-era store crafted with the §9 schema verbatim (`user_version` 0, no `envelopes.v` / `directory.epoch` / `directory.prekeys`) populated with 3 envelopes + 2 directory rows; the deployed release migrating that populated store through the real §15.3 chain (everything keeps being served: ids, byte-identical payloads, epoch-0 directory backfill); the upgrade success path through the library (backup generation with db + previous binary + `MANIFEST.txt`, prune, binary swap, health gate on build identity + schema_version, zero envelope loss, the write path accepts new mail); backup rotation (4 generations → keep 3, explicit `KEEP=1`); the FAILED-migration rollback (store marker forced to 99, the swapped daemon refuses to start naming both versions, the gate fails, `upgrade_auto_rollback` restores the previous binary + db backup and the node serves the full ledger again with the refused store kept as `pre-restore-<UTC>` evidence); and the negative gates (wrong expected build / schema fail an otherwise healthy node).

15. The install-node guide structure test (issue #35) ends with:

    ```
    PASS: <n> assertions on docs/install-node.md structure, anchors and cross-links
    ```

    It is pure file-structure checking (no daemon, no network): the guide's
    10 required sections and key subsections, TOC anchors vs real headings
    via GitHub's anchor algorithm (both directions), every relative link
    resolving with its cross-file heading fragment validated against the
    target file, the README (docs table + solar paragraph) and hardware.md
    forward-pointer wiring, the number-consistency pins against
    `docs/hardware.md` (1 W, 0.90, 0.80, 12.8 V, 14.6 V, 20 W, 5.1 V, 15 A,
    2 A, 0 °C, 30%), the per-environment ASCII diagrams and the glossary.

Lint gates (as used in CI of record): `gofmt -l .` and `go vet ./...` inside `node/` must produce no output/errors — `make lint` wraps them.

All of section 4 runs on demand in CI (`.github/workflows/test.yml`,
ubuntu-latest: setup-go pinned by `node/go.mod`, Node 22, `make test` then
`make chaos`, minimal `contents: read` permissions). Since the 2026-10-04
decision the workflow is **manual-dispatch only** (`gh workflow run test`
optionally with `--ref <branch>`) — it no longer runs on push or pull
request, so the suite MUST be run locally (this section) before opening a
PR; see `AGENTS.md`. The chaos suite has its own section below.

## 5. Deploy to a Raspberry Pi (Zero W or newer)

The supported range and the per-model matrix (OS image, binary, Wi-Fi
caveats, power notes) live in `docs/pi-models.md`; the provisioning is
identical on every board and idempotent, and it never starts services
mid-run: **the reboot is the activation step**. Run any of the paths below
from a LOCAL console (keyboard + monitor or serial), not over an
SSH session on NetworkManager-managed Wi-Fi — the script disables and masks
NetworkManager (binding decision, `docs/DEVELOPMENT_PLAN.md` §1.6).

### Path 1 — one-line online install (recommended)

On the Pi (fresh Raspberry Pi OS **Lite**, with Internet once):

```bash
curl -fsSL https://raw.githubusercontent.com/juliangt/offgrid/main/raspberry/install.sh \
  | sudo bash -s -- --country AR
```

`raspberry/install.sh` detects the board and userland ISA, downloads the
matching release binary plus the provisioning tree of the same release tag
(checksum-verified against the release `SHA256SUMS`), and hands over to
`provision.sh`. Add `--reboot` to activate unattended; otherwise press ENTER
at the final prompt. Pin a version with `--ref vX.Y.Z`.

### Path 2 — offline install from a USB stick or the SD card (no Internet)

Copy a release's assets (`dtn-node-linux-*`, `SHA256SUMS`,
`raspberry-<tag>.tar.gz`) onto a USB stick or the SD card's FAT partition,
mount it on the Pi, then:

```bash
sudo ./install.sh --offline /media/usb --country AR   # checksum-verified too
```

### Path 3 — manual build + copy

1. **Build the deployment binaries** (on any machine, from step 2):

   ```bash
   cd node && ./build.sh   # emits arm64, armv7 and armv6 — provision.sh picks
   ```

2. **Copy the binary and the infrastructure tree to the Pi** (from your workstation; replace the hostname/IP and identity):

   ```bash
   scp node/dtn-node-linux-arm64 pi@<pi-address>:/tmp/   # armv6/armv7 for those boards
   scp -r raspberry pi@<pi-address>:/tmp/
   ```

3. **Provision as root on the Pi**, choosing the regulatory country of the deployment site (defaults to `AR`; `ALLOW_SSH=1` optionally keeps SSH reachable from AP clients):

   ```bash
   sudo -i
   cp /tmp/dtn-node-linux-arm64 /tmp/raspberry/node/dtn-node-linux-arm64   # path provision.sh expects: raspberry/../node/
   cd /tmp/raspberry
   COUNTRY=AR ./provision.sh
   reboot
   ```

   `provision.sh` (10 verified steps) detects the board model and userland ISA, masks NetworkManager and installs the classic ifupdown stack, installs `hostapd`/`dnsmasq`/`iptables` plus the watchdog probe tools, sets the static `10.42.0.1/24` on `wlan0`, installs the configs and unit files (on single-core ARMv6 boards the daemon's watchdog ceiling is relaxed to 60 s), creates the unprivileged `dtn` user with `/var/lib/dtn-node` (0750), installs the matching binary at `/opt/dtn-node/dtn-node`, enables every unit, and runs the Track-3 field hardening (keys-only sshd drop-in, journald made volatile, security-only unattended upgrades — the read-only root stays an explicit operator step, OFF by default) — verifying each step with `[OK]`/`[FAIL]` and failing fast.

### Path 4 — upgrade a deployed node (no reflash, no data loss; issue #22)

An already-provisioned node gets a new release in place: the envelope store,
the directory and the provisioning are kept, the binary and the changed
configs are swapped, and the node only declares success after a health gate.
`install.sh --upgrade` uses the SAME bundle resolution as the fresh paths —
`--offline DIR` (USB stick, no Internet, checksum-verified) and `--ref TAG`
(online, pinned) both work, exactly as in Paths 1–2:

```bash
sudo ./install.sh --upgrade --offline /media/usb   # from a release bundle
sudo ./install.sh --upgrade --ref vX.Y.Z           # online, pinned tag
sudo ./install.sh --rollback                       # back to the previous release
sudo ./install.sh --rollback --from upgrade-<ts>-<id>   # a specific generation
```

The upgrade sequence (binding order, `raspberry/upgrade.sh`):

1. **Preflight** — refuses a never-provisioned box (no `dtn-node.service`
   unit or no binary = use Paths 1–3), notes the current build identity and
   the store's `PRAGMA user_version`, and probes the STAGED binary against a
   throwaway database to learn the exact expectations the health gate must
   demand (its build id + `schema_version`).
2. **Stop** `dtn-node`.
3. **Backup generation FIRST, before anything is touched** — the SQLite main
   file + any `-wal`/`-shm` sidecars + the previous binary + a `MANIFEST.txt`
   (old build, old `user_version`, sha256s) go into
   `/var/lib/dtn-node/backups/upgrade-<UTC ts>-<build>/`; the rotation keeps
   the last 3 generations and prunes older ones. Because the backup happens
   BEFORE the new binary ever opens the database, even a failed migration is
   recovered by a plain file restore (the forward-only migration chain of
   `docs/protocol.md` §15.3 refuses a binary-only downgrade — the documented
   recovery is `--rollback`, which restores binary AND database together).
4. **Idempotent provisioning subset** — `provision.sh` re-runs only the steps
   that can carry changed files (configs, binary, units, hardening), via its
   `STEPS=` selector; every step is idempotent and network-free, and
   `install_file` replaces only differing files (keeping the previous one as
   `.dtn-bak`). No apt, no NetworkManager surgery, no reboot.
5. **Start + health gate** — poll `GET /api/v1/health` (the §10.7 document)
   until: HTTP 200, `"status":"ok"`, the serving `build` member equals the
   staged binary's id, `schema_version` matches it, and (when the `sqlite3`
   CLI is present) the live `PRAGMA user_version` equals the served
   `schema_version` — i.e. the migrations really landed. Budget: 120 s.
6. **Success, or automatic rollback** — ANY failure (provisioning error,
   daemon that will not start, gate timeout) stops the service, restores the
   generation (binary + database; the displaced store is kept as
   `/var/lib/dtn-node/pre-restore-<UTC>/` evidence), restarts, re-verifies
   health against the OLD expectations and reports loudly. `install.sh
   --rollback` is the same machinery invoked by hand (it lists the
   generations and restores the chosen — default latest — one through the
   same gate).

**Offline USB checklist for a field upgrade.** On a connected machine:
(1) `cd node && ./build.sh`; (2) download / assemble the release bundle onto
a USB stick — `dtn-node-linux-arm64` (the board's artifact,
`docs/pi-models.md` §1), `SHA256SUMS`, `raspberry-<tag>.tar.gz`; (3) on the
Pi, mount the stick and run the `--upgrade --offline /media/usb` command
above (same `--country` as the original provisioning, plus `--allow-ssh` if
the deployment deliberately re-opens client SSH); (4) read the `upgrade:`
log lines — the gate verdict names the serving build — and finish with the
verify trio below. `--reboot` is a fresh-install-only flag: the service
restart IS the activation step of an upgrade.

The automated acceptance test of all of the above is `bash
tests/upgrade_e2e.sh` (step 14 of §4): it sources `raspberry/upgrade.sh`,
drives the very same functions rootlessly against a temp "node" and asserts
migration-on-populated-store, backup rotation, gate success, forced-failure
rollback and ZERO envelope loss at every phase.

**Verify after reboot — all paths.** From a laptop/phone joined to the `offgrid-messages` open AP:

   ```bash
   # Portal answers on the canonical origin (host header override):
   curl -H 'Host: offgrid.local:8080' http://10.42.0.1:8080/
   # Captive-portal probe via the firewall redirect (port 80 -> 8080):
   curl -s -o /dev/null -w '%{http_code}\n' http://10.42.0.1/generate_204   # -> 302
   # Any other hostname is wildcard-resolved by dnsmasq to the node:
   curl -s -o /dev/null -w '%{http_code}\n' http://anything.example/        # -> 301
   ```

   On the Pi itself:

   ```bash
   systemctl status dtn-node           # active (running), sd_notify READY=1
   hostapd_cli -i wlan0 all_sta        # lists associated stations
   journalctl -u dtn-node -b           # daemon logs; janitor runs at startup
   ```

   A phone connected to the SSID should pop the captive portal on its own and land on `http://offgrid.local:8080`; two clients must not be able to reach each other (`ap_isolate=1` + FORWARD DROP); a second reboot must restore everything by itself.

## 6. Troubleshooting

| Symptom | Checks and fixes |
|---|---|
| `dtn-node` dies instantly with `Illegal instruction` in `journalctl -u dtn-node` | The binary does not match the board's ISA: a GOARM=7 (`armv7`) binary on an ARMv6 board (Zero W, Pi 1) or an arm64 binary on a 32-bit OS. Reinstall with the correct `dtn-node-linux-*` artifact (`uname -m` → armv6l/armv7l/aarch64; `docs/pi-models.md` §1) — `install.sh` picks it automatically. |
| `hostapd` fails to start (`systemctl status hostapd`) | `journalctl -u hostapd -b`. In order: (1) `rfkill list wifi` — unblock with `rfkill unblock wifi`; (2) `country_code` in `/etc/hostapd/hostapd.conf` must be a valid two-letter code matching the site's regulations, or the driver refuses the interface; (3) the Wi-Fi driver must support AP mode on `wlan0` (the on-board Pi radio does; USB dongles often do not — `docs/pi-models.md` §3); (4) confirm `DAEMON_CONF="/etc/hostapd/hostapd.conf"` in `/etc/default/hostapd` and that the unit is not `masked`. |
| `dnsmasq` fails: port 53/67 already in use | `journalctl -u dnsmasq -b` shows `address already in use`. Another resolver (e.g. `systemd-resolved` on non-Pi OS images) owns the port: disable it (`systemctl disable --now systemd-resolved`) or remove its stub config; on the Pi this is rare because provision.sh already masks NetworkManager. Our `dnsmasq.conf` uses `bind-interfaces`, so a clash is always a real port conflict, not a wildcard bind. |
| `dtn-node` unit keeps restarting | `journalctl -u dtn-node -b`. Under systemd the unit runs `Type=notify` with `WatchdogSec=`; the daemon pings `WATCHDOG=1` at half the interval (see `internal/sdnotify`). Restarts with `missed watchdog ping` entries mean the process was starved: check for CPU throttling, an overloaded SD card (see `docs/hardware.md` §5), or a dying battery browning out the SoC (check `vcgencmd get_throttled` and the power budget). |
| Browser opens the portal but the app loses data between nodes | You are inside the OS captive-portal mini-browser, whose storage profile is isolated and often ephemeral (spec §13.4). Copy the URL shown in the banner — `http://offgrid.local:8080` — and open it in Chrome/Safari; only the full browser gives persistent `IndexedDB` under the shared origin. |
| `curl` to `http://10.42.0.1:8080/` answers `301` | Expected: the canonical-host middleware redirects every non-canonical Host (spec §10.2). Verify with the `Host: offgrid.local:8080` header as in step 5, or follow redirects in a browser — you will end up on the canonical origin by design. |
| Envelope pushed but never pulled | TTL may have expired: pulls serve only `created_at + ttl >= now` (spec §10.4) and the janitor deletes expired rows every 15 minutes. Check `created_at` of the envelope and the node's clock (`date -u`) — a node with a wrong clock silently filters valid mail. |

## 7. Cold start and data layout

- Database default location on a provisioned node: `/var/lib/dtn-node/node_storage.db` (plus `-wal`/`-shm` while running), owned `dtn:dtn`, mode 0750 on the directory.
- On first start the daemon creates the database file and its parent directory if missing and logs it, applies the schema of spec §9 idempotently, runs the expired-envelope sweep once, then binds the socket and announces readiness.
- Backup = stop the unit and copy the three files (or use `sqlite3 .backup`). Envelope data is disposable by design (E2EE dead drop), the directory table is the only state worth keeping. The automated version of this — generationed backups + a health gate + tested rollback — is the upgrade path of §5 Path 4 (`docs/RUNBOOK.md` §4.8).

## 8. Chaos suite

`make chaos` (or `bash tests/chaos/run_all.sh`) is the failure-injection harness of issue #16 Phase 4, Track 4: it breaks the node ON PURPOSE, one injection per script, and asserts the three chaos properties — **degrade** (clean shed, never chaos), **auto-recover** (ready again without operator help) and **honest data expectations** (stored legitimate envelopes survive byte-identical, or the loss is explicitly accepted and evidenced). The authoritative failure-mode matrix — one row per (component × failure), with the injection, expected behavior, data expectation and verifying artifact per row — lives in `tests/chaos/FAILURE_MATRIX.md`. Rows that cannot be automated (AP process death, power yanks, SD pulls — hardware by nature) point at the FIELD procedures section of that same document and are manual by design. The field-operations half — reading the counters-only telemetry, detecting abuse, and the quarantine/remount/reflash procedures that matrix references — is `docs/RUNBOOK.md`.

The automated scripts, in `run_all.sh` order (each also runs standalone; they own `127.0.0.1` ports `18095-18099`, disjoint from the E2E's `18091-18094`):

| Script | Injection | Core assertions |
|---|---|---|
| `chaos_kill_mid_sync.sh` | SIGKILL mid-sync under a background flood of 100-envelope POSTs | ready again, zero `.corrupt-*` (WAL atomicity), seeded envelopes byte-identical, fresh sync works |
| `chaos_corrupt_db.sh` | db truncated to 30% / garbage header / `-wal` truncated after SIGKILL | the `storage.Open` contract: quarantine `.corrupt-<ts>` + rebuilt store serving (or loud non-zero exit without side effects) — never a half-broken serve; healthy main db never quarantined; pushes accepted again |
| `chaos_full_disk.sh` | 8 MiB loopback volume filled to ENOSPC while the daemon runs on it | push sheds cleanly in the 507/429 family, daemon alive, read path serves, no quarantine; pushes accepted again once space is freed |
| `chaos_restart_under_load.sh` | 6 concurrent workers (valid + junk + pull-only) while the daemon is SIGTERM-restarted 4 times | only the clean answer set (200/400/413/429/507), zero hangs (hard curl timeouts), connection drops confined to restart windows, seeded data survives |
| `chaos_janitor_flood.sh` | store crafted to the 5000-row cap (4500 expired + 500 live) + background writer hammering during startup | §10.6 sweep completes within a bounded time under write pressure (not starved), expired purged, live kept byte-identical, capacity reclaimed |
| `chaos_fuzz_parsers.sh` | Go native fuzzing of the parsers (`FuzzParseEnvelope`, `FuzzSyncHandler`, committed in-package) | untrusted bytes → decode/validation error or 200 — never a panic, never a 5xx; seed corpora run under plain `go test` |

**SKIP semantics.** A script whose injection the host cannot perform prints `SKIP: <reason>` lines and exits 0 — a skip NEVER fails the run (`run_all.sh` aggregates them into its summary as `PASS (N skip(s))`). This is the platform escape hatch: the full-disk injection needs volume tooling (macOS: `hdiutil`, rootless; Linux: `sudo` + `losetup` + `mkfs.ext*`, present on CI runners), the corrupt/janitor scripts need the `sqlite3` CLI and `truncate`. The four core scripts (kill, corrupt, restart, janitor) have no such dependency and must actually PASS everywhere.

**Exit codes and determinism.** Every script follows the `tests/sync_e2e.sh` PASS/FAIL counter style, exits 0 all-pass / 1 any-fail, builds its own daemon binary into a temp dir, and cleans up after itself via EXIT traps (daemons killed, volumes detached, temp dirs removed) even on failure.

**Field chaos.** The hardware half of the discipline — repeated power yanks, reboot storms, a hostile station saturating the AP while a legitimate mule syncs, SD pull mid-write, hostapd/dnsmasq process death — is manual by nature and recorded in the FIELD section of `tests/chaos/FAILURE_MATRIX.md`, each procedure with its pass/degrade/fail template. Run it on real hardware before any deployment; the automated suite above is the machine-checked subset of the same matrix.
