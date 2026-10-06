# Field Operator Runbook — Off-Grid DTN Node

| | |
|---|---|
| **Version** | 1.2.0 |
| **Date** | 2026-10-05 |
| **Audience** | Whoever can physically reach a deployed node (local console or keyboard on the Pi). Every command below runs on the node unless stated otherwise; access is by console, not SSH — the firewall drops client→tcp/22 by default (`docs/hardening.md` §2). |
| **Scope** | Reading the telemetry, detecting abuse, restoring a node in minutes, escalation. Design and rationale: `docs/hardening.md`. Build/deploy and the after-reboot verification commands: `docs/BUILD.md` §5. Normative protocol: `docs/protocol.md`. |

## 1. The privacy line (read first)

The node is a blind relay (`docs/protocol.md` §13) and its defenses inherit that constraint: **no IP address, MAC address, DNS name or alias is recorded anywhere you can read** — not on the SD card, not in the journal, not in the shield state (all of it lives in tmpfs `/dev/shm` and dies at reboot; `docs/hardening.md` A7). Telemetry is counters-only by construction (`raspberry/hardening/dtn-telemetry.sh` never calls `hostapd_cli all_sta`; its awk parsers emit integers and discard everything else).

This means abuse detection works like a water meter, not a CCTV camera: you can see THAT the square is being abused and roughly how much, never WHO. Do not improvise identity into the system — do not enable persistent DNS query logs, do not add per-IP logging, do not export `dnsmasq.leases` off the node. A "better observable" node is a privacy regression, not an improvement.

## 2. Reading the telemetry

The collector runs every 5 minutes (`dtn-telemetry.timer`, `OnUnitActiveSec=5min`), writing one line to the volatile journal and to the latest-snapshot file:

```bash
cat /dev/shm/dtn-telemetry.summary              # latest snapshot (tmpfs)
journalctl -u dtn-telemetry -b                  # one line per sample since boot
sudo /usr/local/sbin/dtn-telemetry.sh           # sample right now (also refreshes the snapshot)
```

Line format (labels + integers, or `na` = "could not look this run"):

| Field | Meaning | "Abuse in progress" threshold |
|---|---|---|
| `stations` | Associated stations (one integer from `hostapd_cli status`, `num_stations`) | Pinned at the ceiling `max_num_sta=20` (`raspberry/hostapd/hostapd.conf`) → association exhaustion |
| `dns_shed_active` | DROP rules currently in the `DTN_DNSBL` chain = sources being shed right now | Any value > 0 = sustained DNS abuse (shed fires at ≥ 20 q/s over 3 windows, or ≥ 80 q/s instantly) |
| `dns_shed_packets` | Packets dropped by those rules | Growing fast between samples = active flooding; shed expires after 600 s (`DNS_COOLDOWN_SECONDS`) |
| `dns_streaks` | Sources above the shield threshold, not yet shed (confirmation windows) | > 0 = abuse building; the shield acts in ≤ 3 windows |
| `dns_blacklist` | Blacklist entries in the shield's tmpfs state | Historical depth of DNS abuse this uptime |
| `station_cooldowns` | Stations deauthed in the last 900 s (`STATION_COOLDOWN_SECONDS`) | > 0 = a station moved > 64 MiB in one association or held > 64 connections — the quota shed did its job |
| `portal_dropped` | NEW connections to 8080 dropped by the SYN hashlimit (30/min, burst 60 per source) — the firewall's stand-in for "requests were shed at the door" | Any growth between samples = someone hammered the portal (monotonic since boot) |
| `acc_packets` / `acc_bytes` | Total client traffic through the `DTN_ACC` accounting rule since boot | Growth far beyond mule scale — a full mule sync is ~210 KiB, the entire 5000-envelope store is ~3.5 MiB — means volume abuse |
| `daemon_429` / `daemon_507` | Always `na`, **by design**: the daemon logs no per-request lines (a request line would carry IPs, §13) | — |

Consequence of the last row: **iptables counters are the source of truth** for request-level shedding. There is no "429 storm" to grep for in `journalctl -u dtn-node` — do not look for one, and do not add per-request logging to create one.

### 2.1 Node health from a phone or laptop (no console)

The daemon serves its own aggregate health picture (`docs/protocol.md` §10.7), so the first look at a suspicious node needs no console at all — connect to the AP and, from any browser:

```text
http://offgrid.local:8080/status        ← operator view (server-rendered, no JS)
```

That page is deliberately **not linked from the public portal** (visitors never see operational detail); type the URL. It shows, all as aggregates: liveness (`status: ok` = the process the watchdog supervises is answering), build, uptime, envelopes held vs. the 5000 capacity, directory entries, database size on disk (a growing figure past a few MiB = WAL pressure — full-card symptom), the last TTL cleanup, and the since-boot counters (pushes accepted/rejected with rejection classes, dedup hits, TTL sweeps). If the page or its JSON twin fails with `507 storage_unavailable`, the daemon is up but cannot read its store — go to §4.1 (reboot), then §4.3 (quarantine evidence). The power, system, store-drain and projection cards the page grew in issue #36 are read in §2.2 ("reading the status page before a site visit").

From a console the machine-readable twin answers the same numbers:

```bash
curl -s -H 'Host: offgrid.local:8080' http://10.42.0.1:8080/api/v1/health
```

Reading the counters: `node_full` rejections climbing means the store hit the 5000 cap (§3 row below — the janitor reclaims it, do nothing); `rate_limited` climbing means someone is hammering the write path (the §2 `portal_dropped` firewall counter is its network-layer twin); `dedup_hits` climbing alone is normal mule traffic re-offering known mail. Both diagnostics endpoints are rate-limited per client (burst 60, `429` beyond) and cached server-side for one second — a fast poll cannot hurt the node, and there is nothing to tune. Like everything else here, the page carries **aggregates only**: no ids, no hints, no aliases, no addresses — never add any.

### 2.2 Reading the status page before a site visit (issue #36)

Since the #36 extension the page (and its `/api/v1/health` twin) also answers the field questions: power, temperature, storage headroom and load trajectory. What each thing means and what to do:

**Power & battery card.** The charge state (`charging`/`discharging`/`idle`), a state-of-charge percentage with its source, pack voltage/current, an alert band and an autonomy projection in hours and "nights of autonomy" (24-hour nights, counted down to the 20% depth-of-discharge floor).

- `CHARGING` — the panel is winning. Nothing to do.
- `HEALTHY` — at or above 30% state of charge. That 30% line is the same overnight floor `docs/hardware.md` §8 uses as the acceptance rule for leaving a node unattended: a node that never dips below it overnight passes.
- `LOW` — below 30%. Not a fault by itself, but the margin is gone: check the panel for shading/dirt and the season's sun before walking away.
- `CRITICAL` — at or below the 20% DoD floor. The node is living on its protection margin; visit soon (panel, wiring, or load above the ~1 W design figure — `docs/hardware.md` §9).
- **Accuracy honesty:** a voltage-derived percentage is COARSE (a LiFePO4 4S pack holds a nearly flat voltage through the middle of its discharge — the page says so next to the number). Trust the trend and the band, not the exact digit. A coulomb-counting BMS (shown as source "BMS coulomb count") is precise; battery wear (`health_percent`) reads N/A on voltage-only setups by design.
- **N/A** — no battery sensor configured or reachable. The node runs fine; you just cannot see the battery. Wiring an INA219/INA260 (the `docs/hardware.md` §3 optional part) and passing `-battery-i2c /dev/i2c-1 -battery-capacity-wh <pack Wh>` fills the card.

**System card.** Load average with a saturation word (saturated = the 15-minute load reached the core count), memory used/available, disk used/free on the database volume, SoC temperature, throttling, system uptime. `disk_free_low` means under 50 MiB free — the whole store is ≤ 5 MB hot data, so something else is eating the card; that is a full-card symptom worth acting on. Throttling observed with a cool SoC usually means undervoltage (wiring, buck converter). `N/A` entries are the parts the host cannot measure (a stock Pi OS Lite without `vcgencmd` shows the throttle line as N/A — installing nothing is fine).

**Software identity card.** The running build, the envelope versions it accepts, the storage schema version this build carries, the schema version actually on disk, and whether a migration is pending. In normal operation on-disk == build and the flag reads `no`. A `YES` means the store's marker moved after boot — capture `journalctl -u dtn-node -b` and §4.3 evidence before touching anything. There is no update checking: the node has no uplink by design.

**Store card.** Envelopes held vs the 5000 capacity, the **expiring-within 1 h / 6 h / 24 h buckets** (a preview of the store draining — the janitor reaps them automatically), registered users, **active clients** (distinct portal sessions with write activity over the last 15 minutes; a count only — the node keeps no identity there), database size, last cleanup.

**Load projections card.** Pushes/day, TTL expiries/day, database growth/day, battery drain/day, and the derived projections: days to envelope capacity, days to disk-full, whether the store is growing/shrinking/steady, and whether the battery is net-positive or slowly starving over the multi-day window. Two honest limits:

- **"not enough data yet"** is the page's way of refusing to guess: projections are computed from an in-RAM rolling window sampled once a minute, and until that window holds at least two samples over thirty minutes (a full day for the battery verdict) there is no number. It is normal right after a reboot — it is not a fault.
- Every projection is labelled with its window and is the recent past continued forward — **a projection, never a promise**. A reboot clears the window by design (nothing operational is ever written to disk).

**Before a site visit, the one-minute check is:** `status: ok` + build identity (§2.1) → battery band not CRITICAL and autonomy in nights, not hours → disk free not low, temp not throttling → store not pinned at capacity with `days_to_disk_full` far away → projections not starving. Anything N/A is absence of a sensor, not a failure — match it against what the node physically has installed.

## 3. Detecting abuse (symptom → likely cause → check → action)

| Symptom | Likely cause | Check | Action |
|---|---|---|---|
| AP invisible / portal won't load | A component died after a clean boot (brcmfmac wedge, dnsmasq OOM) | `journalctl -u dtn-network-watchdog -b` — the watchdog probes hostapd, dnsmasq and dtn-node every 2 min and restarts only what failed | Wait ≤ 2–4 min: recovery is automatic (`docs/hardening.md` §4). If it flaps, see §4.4 |
| Portal slow for EVERYONE | One station saturating airtime or sockets | `station_cooldowns` (the 64 MiB/association shed), `acc_bytes` growth rate, `portal_dropped` | Let the shields work — the shed is per-station, never AP-wide. If honest syncs still fail, record it (FIELD-5, §5) |
| Clients see `429 node_full` | Store at the 5000-envelope cap (`docs/protocol.md` §8.1) | `http://offgrid.local:8080/status` shows `envelopes` vs capacity from any connected device (§2.1); on the console: `sudo sqlite3 /var/lib/dtn-node/node_storage.db 'SELECT COUNT(*) FROM envelopes;'` (if the `sqlite3` CLI is present); `journalctl -u dtn-node -b` shows the janitor's sweeps | Nothing: the TTL janitor (every 15 min, §10.6) reclaims capacity on its own — the flood loses the race by design. NEVER delete the database to "fix" it |
| DNS-tunneling suspicion (quirky client behavior, query storms) | A device is abusing the resolver | `dns_shed_active > 0` or `dns_shed_packets` growing; `journalctl -u dtn-dns-shield -b` logs each shed as `shed <source> — <reason>` without names | Nothing to do: shed lasts 600 s, re-offenders re-qualify. The resolver answers every name with the portal IP only (`raspberry/dnsmasq/dnsmasq.conf`: `no-resolv`, zero upstreams) — there is no tunnel to the outside to close |
| Portal unreachable but stations associated | Daemon wedged or down | `systemctl status dtn-node` — `Type=notify`, `WatchdogSec=30`, `Restart=always` means systemd has already restarted it; check restart count | If restarts keep climbing, §4.4; else §4.1 |

## 4. Restoring a node in minutes

### 4.1 Reboot first

The standing rule: **`sudo reboot` before any diagnosis.** Every unit is enabled at boot and the reboot is the activation step (`docs/BUILD.md` §5); all tmpfs shed state resets (a reboot IS the big reset — also for the watchdog's restart budget). After it comes back, run the §5 verification trio of `docs/BUILD.md`:

```bash
curl -H 'Host: offgrid.local:8080' http://10.42.0.1:8080/        # portal HTML
curl -s -o /dev/null -w '%{http_code}\n' http://10.42.0.1/generate_204   # 302
systemctl status dtn-node                                        # active, READY=1
```

### 4.2 Unit checks (the hardened stack)

```bash
systemctl status dtn-node hostapd dnsmasq dtn-firewall
systemctl list-timers 'dtn-*'     # dns-shield 1min, station-shield 2min, watchdog 2min, telemetry 5min
journalctl -u dtn-node -b         # lifecycle lines only — no per-request lines, by design
```

`dtn-node` restarting a few times with watchdog-miss entries after a dirty cut is normal convergence (`Restart=always`, `docs/hardening.md` §4); the storage layer has already handled itself (next section).

### 4.3 Quarantine events (corrupt-DB evidence)

A dirty cut or a dying card can leave the daemon quarantining a corrupt database on boot: the file is renamed and a fresh store is built (never a half-broken serve — `docs/hardening.md` §3). Look for it:

```bash
sudo ls -l /var/lib/dtn-node/*.corrupt-*
```

Decide **keep-inspect vs delete**: KEEP the `.corrupt-*` files and capture `journalctl -u dtn-node -b` if you are recording a field failure (§5) — they are the only evidence of what was lost. Otherwise, once noted, they can be deleted: the daemon never touches them again, and everything in them is gone by definition (quarantine = loss with evidence, `tests/chaos/FAILURE_MATRIX.md` rows 3–4).

### 4.4 Watchdog storm markers

The network watchdog restarts a failed component at most 3 times per hour (`MAX_RESTARTS_PER_HOUR=3`), then stops and says so:

```bash
journalctl -t dtn-network-watchdog -b | grep 'budget exhausted'
# "component hostapd.service unhealthy; restart budget exhausted (3/3 per 3600s) — needs manual attention"
```

This marker is the "needs a human" signal: the node gave up honestly instead of looping. Follow §4.1 (reboot), and if the marker returns after a clean reboot, treat it as a hardware fault (§5) — typically the radio or the SD card.

### 4.5 Config changes under a read-only root

Check the state first: `sudo /usr/local/sbin/dtn-enable-readonly-root.sh --status` (default is OFF). If it reports **ACTIVE** (root shows as `overlay`; verify the durable data dir with `mount | grep /var/lib/dtn-node`), a durable config change is a **remount cycle**, not a file edit — a live edit only writes the RAM layer and evaporates at the next power cut:

```bash
sudo /usr/local/sbin/dtn-disable-readonly-root.sh && sudo reboot   # 1. back to plain ext4
# ... make the change, verify it ...                               # 2. edit (e.g. hostapd country)
sudo /usr/local/sbin/dtn-enable-readonly-root.sh && sudo reboot    # 3. re-arm; verify with --status
```

Repository sources of the twins: `raspberry/hardening/enable-readonly-root.sh` / `disable-readonly-root.sh` (installed under the `dtn-` prefix by `raspberry/provision.sh`).

### 4.6 The 5-minute reflash

A dead card, a trashed install, or "just start over" — reprovision from the release kit (`raspberry/install.sh`, checksum-verified against the release `SHA256SUMS`); the node holds no secrets, so nothing is mourned:

```bash
# Online (once):
curl -fsSL https://raw.githubusercontent.com/juliangt/offgrid/main/raspberry/install.sh \
  | sudo bash -s -- --country AR
# Offline (release assets on a USB stick / the SD FAT partition):
sudo ./install.sh --offline /media/usb --country AR
```

Pin a version with `--ref vX.Y.Z`; add `--allow-ssh` only if this deployment deliberately re-opens client SSH. The reboot at the end is the activation step. Card choice and flashing guidance: `docs/hardware.md` §5/§7.

### 4.7 Power-off procedure (solar units)

Planned stop: `sudo poweroff` — a clean close checkpoints the WAL; then let the panel run the controller idle (or use the controller's LOAD switch / cover the panel per `docs/hardware.md`). A dirty yank is survivable by design (`tests/chaos/FAILURE_MATRIX.md` row 12) but is never the shutdown procedure when a planned stop is possible.

### 4.8 Upgrading a deployed node (and rolling one back)

The non-destructive upgrade of issue #22 (`docs/BUILD.md` §5 Path 4) replaces the binary and re-runs the idempotent provisioning subset WITHOUT a reflash: the envelope store, the directory and the provisioning are kept, and the machine only declares success after a health gate. On the Pi:

```bash
sudo ./install.sh --upgrade --offline /media/usb   # release bundle on a USB stick (field default)
sudo ./install.sh --upgrade --ref vX.Y.Z           # online, pinned release tag
```

**Pre-upgrade checklist** (a node is a remote island — carry the bundle AND the undo path):

1. Note the current state, from any connected device or the console: `http://offgrid.local:8080/status` (§2.1) — liveness, build, store size — and on the console `systemctl status dtn-node` (nothing flapping, §4.2). An upgrade of a wedged node starts with §4.1 (reboot first), not with a new binary.
2. Charge/size the power budget: the upgrade stops `dtn-node` for the backup + swap (seconds to a couple of minutes) and the gate adds up to 120 s — no planned power cut in that window (solar units: §4.7).
3. Bring the release bundle (`dtn-node-linux-*` for the board's ISA + `SHA256SUMS` + `raspberry-<tag>.tar.gz`, checksum-verified) and enough free space on the data card for a backup generation (store size + binary, kept ×3 — see retention below).
4. Know the undo before you need it: after a successful upgrade the previous binary + store sit in `/var/lib/dtn-node/backups/upgrade-<UTC ts>-<build>/` — the rollback command is `sudo ./install.sh --rollback` (default: latest generation; `--from NAME` picks one).

**What the health gate means.** After the swap the installer polls `GET /api/v1/health` (§10.7) for up to 120 s and only declares success when: HTTP 200, `"status":"ok"`, the serving `build` member is the staged binary's id (the swap really took), `schema_version` matches it, and — when the `sqlite3` CLI is present — the live store `PRAGMA user_version` equals the served `schema_version` (the §15.3 migrations really landed). `upgrade:` log lines narrate every verdict; a green run ends `UPGRADE OK: build=<id> schema_version=<n>`.

**Automatic rollback.** ANY failure — provisioning error, daemon that refuses to start, gate timeout — triggers the rollback by itself: stop → restore the generation (binary + database; the displaced store is preserved as `/var/lib/dtn-node/pre-restore-<UTC>/` evidence, §4.3 discipline) → restart → re-verify health against the OLD expectations. The run ends loudly with `upgrade aborted; the node was rolled back`. If even the rolled-back node fails the gate, the log says `ROLLBACK INCOMPLETE` — treat it as a §4.1/§4.3 case and escalate (§5).

**Manual rollback.** Same machinery, invoked by hand (e.g. a release misbehaves hours later):

```bash
sudo ./install.sh --rollback                        # list generations, restore the latest
sudo ./install.sh --rollback --from upgrade-<ts>-<build>   # restore a specific generation
```

This is ALSO the documented recovery for a binary-only downgrade: the forward-only migration chain refuses to start on an older schema (`docs/protocol.md` §15.3, refusal naming both versions) — do NOT swap binaries again, run `--rollback`, which restores binary AND database together.

**Retention.** Backup generations live under `/var/lib/dtn-node/backups/`, named `upgrade-<UTC ts>-<build>` (they sort in creation order), and the rotation keeps the LAST 3 — every successful upgrade prunes older ones. Three generations cover a release hop and its rollback-of-the-rollback; when disk pressure matters, prune by hand the same way (delete whole generation directories, never files inside them). The `pre-restore-*` evidence dirs are kept until you decide otherwise (§4.3: keep when recording a field failure, delete once noted).

## 5. Escalation — what the field CANNOT fix

| Not fixable in the field | The honest answer |
|---|---|
| Physical damage (enclosure, wiring, panel, battery) | Swap the part per `docs/hardware.md`; nothing on the node is worth forensics — it is blind |
| SD card end-of-life (repeat quarantines after §4.1, watchdog storm markers on a clean boot) | Reflash a fresh industrial card, §4.6 — the accepted worst case (`tests/chaos/FAILURE_MATRIX.md` row 13) |
| Radio-level attack (deauth flooding, jamming) | Wait it out — the node keeps itself up and re-forms when the attacker leaves (`docs/hardening.md` §6) |
| A "fail" verdict on any FIELD procedure | Stop, capture `journalctl -b -1` and any `/var/lib/dtn-node/.corrupt-*` files, and report it as a real finding — do not patch on the bench and move on |

**Recorded-failure discipline:** every field exercise (power yanks, reboot storms, hostile-station saturation, SD pulls, component kills — `tests/chaos/FAILURE_MATRIX.md` FIELD-1…6) gets one line per repetition in its template, verdict **pass / degrade / fail** exactly as defined there. Field rows feed the same matrix as the automated suite; a matrix that only ever passes tells you nothing.
