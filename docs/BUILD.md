# Build, Deploy and Run Guide

Step-by-step instructions to build, test, run and deploy the off-grid DTN node (Module B daemon + Module C SPA) and its Raspberry Pi infrastructure (Module A). For the wire protocol see `docs/protocol.md`; for the power budget and wiring see `docs/hardware.md`.

## 1. Prerequisites

| Tool | Version | Used for |
|---|---|---|
| Go | ≥ 1.22 (verified with go1.27.1) | node daemon build and unit tests |
| Node.js | ≥ 18 (verified with v22.19.0) | `tests/crypto_roundtrip.mjs`, `tests/spa_structure.mjs` and `tests/version_migration.mjs` only; nothing in the product needs Node |
| bash | ≥ 3.2 (any) | `node/build.sh`, `tests/sync_e2e.sh`, `tests/hardening_structure.sh`, `raspberry/provision.sh`, `raspberry/install.sh` |
| curl | any | `tests/sync_e2e.sh`, deployment verification |
| sqlite3 | any (CLI) | `tests/sync_e2e.sh` §15 coverage only: schema-1 fixture crafting, migration and downgrade-refusal assertions (with `shasum`/`sha256sum` for the §15.7 b byte fingerprint) |
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

## 4. Run all tests

From the repository root:

```bash
# 1. Go unit tests (storage, api, envelope, sdnotify)
cd node && go test ./... -count=1 && cd ..

# 2. Crypto round-trip against the SPA engine (scripts in index.html order)
node tests/crypto_roundtrip.mjs

# 3. SPA layout contract: referenced assets, CSP, load order, DTN API surface
node tests/spa_structure.mjs

# 4. SPA §15 versioning policy: negotiation guard, blind v1→v2 conversion,
#    pull-path stored versions, store migration chain
node tests/version_migration.mjs

# 5. Full E2E: two daemons + mule walk with curl (starts/stops its own servers)
bash tests/sync_e2e.sh

# 6. Pi hardening structure (issue #16 Track 1): rootless --print/--dry-run
#    assertions on the generated firewall ruleset, tc shaping stream and
#    shield scripts (no hardware, no root)
bash tests/hardening_structure.sh
```

Expected outputs:

1. `go test ./... -count=1` — one `ok` line per package (the `main` package has no test files):

   ```
   ok  	offgrid/dtn-node/internal/api
   ok  	offgrid/dtn-node/internal/envelope
   ok  	offgrid/dtn-node/internal/sdnotify
   ok  	offgrid/dtn-node/internal/storage
   ```

2. The crypto test ends with:

   ```
   PASS: 44 assertions against the SPA engine (index.html script order)
   ```

3. The structural test ends with:

   ```
   PASS: 97 structural assertions on the SPA layout
   ```

4. The versioning test ends with:

   ```
   PASS: 71 assertions on the SPA §15 versioning policy (index.html script order)
   ```

5. The E2E script ends with 84 assertions and:

   ```
   e2e: summary: 84 passed, 0 failed
   e2e: RESULT: PASS
   ```

   It builds the dev binary itself, starts two daemons on `127.0.0.1:18091` and `127.0.0.1:18092` (override with `PORT_A` / `PORT_B`; the extra §15 nodes use `PORT_C` / `PORT_E`, defaults `18093` / `18094`) inside a temporary workdir which is always cleaned up. It simulates the complete mule journey — Alice → node A → mule → node B → Bob — and asserts payload byte integrity via sha256, dedup, TTL filtering, limit rejections and the canonical-host/captive-probe redirect pair, plus the §15 coverage: versioned admission and version-agnostic dedup in both orders (§15.7 c/d/e), the capabilities document (§15.5), schema migration of a crafted schema-1 database (§15.7 a) and downgrade refusal with a byte fingerprint (§15.7 b — these last two need the `sqlite3` CLI and `shasum`/`sha256sum`).

6. The Pi hardening test ends with 197 assertions and:

   ```
   hardening: summary: 197 passed, 0 failed
   hardening: RESULT: PASS
   ```

   It needs no root, no hardware and no network: it asserts the anti-circumvention hardening of issue #16 Track 1 ("the AP is not free Internet") on the GENERATED artifacts — `bash -n` over every provisioning script; hostapd `ap_isolate=1` plus the control socket; dnsmasq's authoritative wildcard for the portal with the query log confined to tmpfs; the complete firewall ruleset via `raspberry/firewall/iptables.sh --print` (rootless rule-generation separation): FORWARD policy DROP with every rule scoped to the client subnet, the explicit VPN/DoT/proxy/DNS-egress escape-route kills, per-source DNS/ICMP rate limits, portal connlimit + SYN hashlimit on 8080, the captive-portal REDIRECT and the runtime shield chains; the tc cake shaping stream (`traffic-shaping.sh --dry-run`: dual-dsthost egress, IFB-mirrored dual-srchost ingress); and both shields' dry-run behavior against synthetic fixtures (shed the flooder/quota hog/connection hoarder, keep honest clients, never emit or persist DNS names or MACs). The Track 3 section (issue #16, hostile clients + node hardening) extends the same artifact-level approach: the firewall's client→tcp/22 INPUT kill (explicit drop by default, `ALLOW_SSH=1` opt-in accept); the daemon unit's hardening set (unprivileged `User=`, `ProtectSystem=strict` + `ReadWritePaths`, `Restart=always`, `WatchdogSec`, `RestrictSUIDSGID`, `MemoryDenyWriteExecute`); the sshd drop-in (keys only, no root login) and `harden-ssh.sh`'s validate-before-install; the read-only-root twins (`--dry-run`/`--status`, the durable `/var/lib/dtn-node` bind-mount inside the generated initramfs script, the rollback twin); the network watchdog (per-component restart plan, restart-storm guard gating, tmpfs budget state); and the counters-only telemetry (one aggregated integer line, no IP/MAC ever leaves the parsers, `all_sta` never invoked).

Lint gates (as used in CI of record): `gofmt -l .` and `go vet ./...` inside `node/` must produce no output/errors.

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
- Backup = stop the unit and copy the three files (or use `sqlite3 .backup`). Envelope data is disposable by design (E2EE dead drop), the directory table is the only state worth keeping.
