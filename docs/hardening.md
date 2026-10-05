# Defensive Hardening Design — Adversarial Assumptions and Defenses (issue #16)

| | |
|---|---|
| **Version** | 1.0.0 |
| **Date** | 2026-10-04 |
| **Status** | Design record of issue #16 ("Defensive hardening: assume hostile users"), Tracks 1–4. Descriptive for the reference deployment; wherever it touches Module B/C wire behavior, `docs/protocol.md` is the normative source. Field procedures live in `docs/RUNBOOK.md`; the failure-mode matrix that proves the contract is `tests/chaos/FAILURE_MATRIX.md`. |
| **Scope** | The four defense tracks — network/AP shields (`raspberry/firewall/`, Track 1), daemon admission control (`node/internal/`, Track 2), OS/node hardening (`raspberry/hardening/`, Track 3) and the chaos discipline that verifies them (`tests/chaos/`, Track 4) — mapped to the adversarial assumptions each answers, plus the deliberate non-defenses and the three-layer failure contract. |

**Reading map.** Each document owns one layer of the story; none duplicates another:

| Question | Document |
|---|---|
| What is the wire contract the defenses must not break? | `docs/protocol.md` (normative; §13 threat model, §13.6 sabotage scenarios) |
| Why does each defense exist, what enforces it, what proves it? | this document |
| How do I read the counters and run the field procedures? | `docs/RUNBOOK.md` |
| How do I build, deploy and run the suites? | `docs/BUILD.md` |
| What happens to the data in every failure mode? | `tests/chaos/FAILURE_MATRIX.md` (authoritative per-row contract) |

## 1. Adversarial assumptions

Every defense below exists because of one of these numbered assumptions. They are stated as facts about the deployment, not as risks to be argued away.

| # | Assumption | Consequence for the design |
|---|---|---|
| A1 | **Every client is an attacker.** The AP is open (`wpa=0`, `macaddr_acl=0` in `raspberry/hostapd/hostapd.conf`); anyone in radio range associates with zero credentials. | Nothing a client sends is ever trusted: every packet is classified by firewall rule, every API write is budgeted, every envelope is re-validated server-side. |
| A2 | **The AP is not free Internet.** The node is an island with no uplink; the only legitimate client activity is DHCP, DNS answered by the node, and HTTP to the portal on tcp/8080 (`docs/protocol.md` §10.2). | Anything else a client attempts — proxies, VPNs, DoT/DoH, tunneling — is abuse by definition and is dropped, not merely unsupported (`raspberry/firewall/iptables.sh`, FORWARD DROP + named escape-route kills). |
| A3 | **Clients WILL flood, degrade and sabotage** — SYN floods, connection hoarding, query floods, store flooding, malformed-parser garbage. | Every shared resource (radio airtime, dnsmasq, the SQLite store, the portal's socket table) has a shed mechanism that costs the attacker more than the defender. |
| A4 | **Hostile stations can be the majority.** A village square has no membership test; the honest mule may be 1 of 20 associations. | Sheds are per-source and individual (one iptables rule, one 802.11 deauthentication), never AP-wide: the honest minority keeps full service (`dtn-station-shield.sh`, per-IP token buckets). |
| A5 | **Power cuts are routine** (solar + LiFePO4, dirty cuts, `docs/hardware.md`); **SD wear and corruption happen** (`docs/hardware.md` §5). | WAL-mode SQLite, corrupt-DB quarantine, `Restart=always`, the read-only-root option, and journald made volatile — recovery is the normal path, not an exception handler. |
| A6 | **Evil twins exist.** Anyone can broadcast `offgrid-messages` and serve `http://offgrid.local:8080`. | No network-level identity is ever relied upon; exposure is bounded client-side (§6.2 below) — the envelope crypto does not care which AP served it. |
| A7 | **Defenders get NO user-identifying data to work with.** Blind-node privacy (`docs/protocol.md` §13) is a constraint ON the defenses, not just a property: the node must repel attackers while never persisting IPs, MACs, DNS names or per-request attribution. | All shed state lives in tmpfs (`/dev/shm`) and dies at reboot; telemetry is counters-only (`dtn-telemetry.sh`); shields parse raw feeds through awk programs that emit integers and discard everything else. Detection is deliberately short-memory. |
| A8 | **Nobody is on call.** A field unit has zero manual SSH; a wedge that needs a human is an outage. | Components self-heal: systemd watchdog on the daemon, the per-component network watchdog, and the reboot-is-the-activation-step provisioning discipline. |

## 2. Track 1 — the AP is not free Internet (network shields)

All artifacts live under `raspberry/firewall/` (+ `raspberry/hostapd/`, `raspberry/dnsmasq/`); `raspberry/provision.sh` installs and enables them; `raspberry/firewall/iptables.sh --print` and every shield's `--dry-run` are the rootless inspection surface.

| Adversarial scenario | Defense | Implementation (file, symbol/threshold) | Regression test | Matrix row |
|---|---|---|---|---|
| Client-to-client L2/L3 attacks | `ap_isolate=1` + FORWARD policy DROP, zero ACCEPT rules | `raspberry/hostapd/hostapd.conf` `ap_isolate=1`; `iptables.sh` `:FORWARD DROP` | `tests/hardening_structure.sh` §2, §4 | — (L3 asserted directly) |
| Free-Internet riding (any uplink/proxy/VPN escape) | Named per-route kills + blanket subnet drop over FORWARD DROP: tcp 22/23/1080/3128/443/8080, DoT 853 tcp+udp, DNS egress 53 tcp+udp, IKE 500/4500, OpenVPN 1194 tcp+udp, WireGuard 51820, L2TP 1701, PPTP 1723 + GRE | `raspberry/firewall/iptables.sh` `build_ruleset` FORWARD section (comments `track1:*-kill`) | `tests/hardening_structure.sh` §4 (per-port assertions) | — (asserted directly) |
| DNS query flooding / tunneling | Per-source hashlimit (25 q/s, burst 50) at packet speed; sustained sub-ceiling abuse shed by rate counters over dnsmasq's tmpfs query log (shed ≥ 20 q/s over 3 windows, or ≥ 80 q/s instantly, 600 s cooldown) | `iptables.sh` `DNS_HL_RATE_QPS=25`; `raspberry/firewall/dns-shield.sh` `DNS_SHED_QPS=20`, `DNS_SHED_FAST_FACTOR=4`, `DNS_SHED_WINDOWS=3`, `DNS_COOLDOWN_SECONDS=600` → `DTN_DNSBL` chain | `tests/hardening_structure.sh` §3 (tmpfs log, `no-resolv`, zero `server=`) + §6 (flooder shed, quiet client kept, names never printed) | — (asserted directly) |
| SYN flood / connection hoarding on the portal | NEW-connection hashlimit (30/min, burst 60) + connlimit 32 per source on 8080 | `iptables.sh` `PORTAL_SYN_RATE_PER_MIN=30`, `PORTAL_SYN_BURST=60`, `PORTAL_CONN_LIMIT=32` | `tests/hardening_structure.sh` §4 | 7 (restart under load), FIELD-5 |
| ICMP tunnels / ping floods | Fragmented ICMP dropped outright; per-source hashlimit 5/s (burst 10) | `iptables.sh` `ICMP_HL_RATE_QPS=5` (INPUT + FORWARD) | `tests/hardening_structure.sh` §4 | — |
| One station hogging bytes or sockets | Per-association byte quota 64 MiB (rx+tx), 64-connection cap per source, hostapd deauth (reason 2), 900 s cooldown; DTN_ACC per-source counters as the no-hostapd fallback | `raspberry/firewall/station-shield.sh` `STATION_QUOTA_BYTES=67108864`, `STATION_MAX_CONNS=64`, `STATION_COOLDOWN_SECONDS=900`; graceful skip when `hostapd_cli` is absent | `tests/hardening_structure.sh` §7 (hog + hoarder shed, honest mule kept, graceful degradation) | FIELD-5 |
| One station starving everyone's airtime | CAKE per-host fairness: 25 mbit `dual-dsthost` egress on wlan0, IFB-mirrored ingress `dual-srchost` | `raspberry/firewall/traffic-shaping.sh` `CAKE_EGRESS_BANDWIDTH`/`CAKE_INGRESS_BANDWIDTH=25mbit` | `tests/hardening_structure.sh` §5 (`--dry-run` tc stream) | FIELD-5 |
| Association exhaustion (ghost-station storm) | Hard ceiling of 20 concurrent stations; the rest fail closed at L2 before generating a single IP packet | `raspberry/hostapd/hostapd.conf` `max_num_sta=20` | — (assertion gap: no test pins `max_num_sta`; the `hostapd.conf` comment carries the rationale) | FIELD-5 |
| Client reaches the operator's sshd | Explicit client→tcp/22 INPUT DROP by default (`ALLOW_SSH=1` opt-in accept); keys-only sshd drop-in behind it | `iptables.sh` `track3:ssh-never-reachable-from-clients`; `raspberry/hardening/sshd-hardening.conf` | `tests/hardening_structure.sh` §9a/§9b | — |

### 2.1 Every network-side budget in one table

| Guard | Threshold (per source unless noted) | Set by | Enforced by |
|---|---|---|---|
| DNS query rate | 25 q/s sustained, burst 50 | `iptables.sh` `DNS_HL_RATE_QPS` / `DNS_HL_BURST` | firewall hashlimit DROP (packet speed) |
| DNS sustained abuse | ≥ 20 q/s over 3 windows, or ≥ 80 q/s in one window; 600 s cooldown | `dns-shield.sh` `DNS_SHED_QPS=20`, `DNS_SHED_FAST_FACTOR=4`, `DNS_SHED_WINDOWS=3`, `DNS_COOLDOWN_SECONDS=600` | `DTN_DNSBL` DROP rule per shed source |
| Portal NEW connections | 30/min sustained, burst 60 | `iptables.sh` `PORTAL_SYN_RATE_PER_MIN` / `PORTAL_SYN_BURST` | firewall hashlimit DROP on tcp/8080 ctstate NEW |
| Portal concurrent connections | 32 | `iptables.sh` `PORTAL_CONN_LIMIT` | connlimit DROP, mask 32 |
| ICMP | 5 echo/s, burst 10; fragmented ICMP dropped outright | `iptables.sh` `ICMP_HL_RATE_QPS` / `ICMP_HL_BURST` | hashlimit + `-f` DROP (INPUT and FORWARD) |
| Station bytes | 64 MiB (rx+tx) per association epoch | `station-shield.sh` `STATION_QUOTA_BYTES=67108864` | hostapd deauth, reason 2, 900 s cooldown |
| Station connections | 64 concurrent | `station-shield.sh` `STATION_MAX_CONNS=64` | hostapd deauth |
| Airtime share | 25 mbit ceiling, per-host fairness both directions | `traffic-shaping.sh` `CAKE_EGRESS_BANDWIDTH` / `CAKE_INGRESS_BANDWIDTH` | cake `dual-dsthost` (egress) / `dual-srchost` (ingress via ifb0) |
| Associated stations | 20 total (node-wide, not per source) | `hostapd.conf` `max_num_sta` | L2 association refusal |
| Client→tcp/22 | dropped (unless `ALLOW_SSH=1`) | `iptables.sh` `ALLOW_SSH` | INPUT DROP / opt-in accept |

The ordering invariant `DNS_SHED_QPS (20) < DNS_HL_RATE_QPS (25)` is load-bearing: above the hashlimit ceiling packets die before dnsmasq logs them, so the shield's log-based counters would never see the excess (`dns-shield.sh` header).

## 3. Track 2 — the daemon sheds by itself

Defense in depth: `node/internal/api/ratelimit.go` assumes the network shields were bypassed or misconfigured. Everything is RAM-only, keyed by source IP from `RemoteAddr` alone (`clientKey`; `X-Forwarded-For` is never consulted — `TestRateLimiterIgnoresForwardedFor`).

| Adversarial scenario | Defense | Implementation (file, symbol/threshold) | Regression test | Matrix row |
|---|---|---|---|---|
| POST flood (json-parse CPU exhaustion) | Per-IP request budget: burst 60, refill 1 request/2 s, checked before the body is read; exhaustion → `429 rate_limited` + `Retry-After` | `node/internal/api/ratelimit.go` `postRequestBurst`, `withRequestBudget`, `writeRateLimited`; wired in `handlers.go` `New` | `node/internal/api/flood_test.go` `TestFloodSyncStormSingleStationIsolated`, `TestRateLimiterTokenBucketMath`, `TestRateLimiterRetryAfterHeaderSane` | 7 |
| Store flooding by one station (under the request budget) | Per-IP envelope budget: burst 600, refill 600/hour, whole batch withdrawn atomically before any validation/storage; pull-only syncs cost nothing | `ratelimit.go` `syncEnvelopeBurst`, `syncEnvelopeRefillPerHour`; check in `handlers.go` `handleSync` | `flood_test.go` `TestFloodPerIPEnvelopeQuotaIsolation` | 8, FIELD-5 |
| Store flooding by many stations | Global 5000-envelope cap (§8.1 `429 node_full`, reject-newest/keep-oldest — eviction belongs only to the TTL janitor) | `node/internal/storage/storage.go` `maxEnvelopes`, `ErrCapacity`; mapping in `handlers.go` `handleSync` | `flood_test.go` `TestFloodJunkEnvelopesStoreCapHolds`; `tests/chaos/chaos_janitor_flood.sh` | 8 |
| Full disk (ENOSPC under fire) | Storage errors surface as `507 storage_unavailable`, daemon stays alive, read path serves; pushes accepted again once space is freed, no restart | `handlers.go` `handleSync` (507 on insert and pull errors); `chaos_full_disk.sh` assertion | `flood_test.go` `TestFloodStorageUnavailableMapsTo507`; `tests/chaos/chaos_full_disk.sh` | 6 |
| Corrupt database (power cut / wear scar) | SQLITE_CORRUPT/NOTADB → quarantine as `<db>.corrupt-<ts>` (+ sidecars), fresh rebuild, keep serving — never a half-broken serve; WAL guard: `wal_autocheckpoint(1000)` + 64 MiB sidecar warning | `storage.go` `Open`, `quarantineCorruptDatabase`, `isSQLiteCorruption`, `maxWALWarnBytes = 64 << 20` | `tests/chaos/chaos_corrupt_db.sh`; `tests/sync_e2e.sh` §15.7 a/b fixtures | 3, 4, 5, 12 |
| Malformed-envelope floods | Native fuzzing of the parse/validate/handler stack: bytes → decode/validation error or clean 200, never a panic/5xx | `node/internal/envelope/fuzz_test.go` `FuzzParseEnvelope`; `node/internal/api/fuzz_test.go` `FuzzSyncHandler` | `tests/chaos/chaos_fuzz_parsers.sh` | 9 |
| Spoofed-source bucket exhaustion | Bucket map bounded: lazy eviction at 4096 entries, 10 min idle TTL | `ratelimit.go` `bucketEvictionFloor`, `bucketIdleTTL`, `sweepIdle` | `flood_test.go` `TestRateLimiterIdleBucketEviction` | — |

### 3.1 Every daemon-side budget in one table

| Budget | Value | Set by | Answered with |
|---|---|---|---|
| POST requests per source IP | burst 60, refill 1 per 2 s | `ratelimit.go` `postRequestBurst`, `postRequestRefillInterval` | `429 rate_limited` + `Retry-After` (checked before the body is read) |
| Pushed envelopes per source IP | burst 600, refill 600/hour | `ratelimit.go` `syncEnvelopeBurst`, `syncEnvelopeRefillPerHour` | `429 rate_limited` (batch withdrawn atomically, nothing half-spent) |
| Node envelope cap (global) | 5000 stored | `storage.go` `maxEnvelopes` | `429 node_full` (§8.1; reject-newest/keep-oldest) |
| Request body | 1 MiB | `api/middleware.go` `MaxBodyBytes` | `413 body_too_large` |
| Bucket map size | 4096 entries, 10 min idle TTL | `ratelimit.go` `bucketEvictionFloor`, `bucketIdleTTL` | lazy eviction (spoofed-source flood bounded) |
| Envelope validation | payload [248, 400] B, TTL [3600, 2592000] s, `created_at <= now + 300` | `envelope.go` `Validate` | `400 invalid_envelope` (whole batch, fail closed) |

Sizing rationale is in the code comments (`ratelimit.go` header): a legitimate visit spends ~10 requests; six full-capacity syncs always fit the envelope budget; one station filling the whole store needs > 8 hours — the global cap plus the TTL janitor win that race by design.

## 4. Track 3 — the node survives its environment and its operator's absence

Artifacts under `raspberry/hardening/` (+ `raspberry/systemd/dtn-node.service`); installed and enabled by `provision.sh` step 8; every script carries `--dry-run` (rootless) and refuses non-root apply.

| Adversarial scenario | Defense | Implementation (file, symbol) | Regression test | Matrix row |
|---|---|---|---|---|
| SSH as the way in (brute force, root login) | Keys only, no root, no forwarding, tight auth limits; config validated with `sshd -t` before install | `raspberry/hardening/sshd-hardening.conf` (`PermitRootLogin no`, `PasswordAuthentication no`, `MaxAuthTries 3`, `MaxStartups 3:30:10`, `LoginGraceTime 20`); `harden-ssh.sh` | `tests/hardening_structure.sh` §9a | — |
| Daemon compromise / privilege escape | Unprivileged `dtn` account (nologin), full systemd sandbox, W^X, memory cap | `raspberry/systemd/dtn-node.service` (`User=dtn`, `ProtectSystem=strict` + `ReadWritePaths=/var/lib/dtn-node`, `NoNewPrivileges`, `RestrictSUIDSGID`, `MemoryDenyWriteExecute`, `MemoryMax=192M`, `RestrictAddressFamilies`); account repair in `harden-services.sh` | `tests/hardening_structure.sh` §9c/§9d | — |
| SD wear by logging | journald volatile + 16 MB cap — the only high-volume writer never touches the card | `harden-services.sh` (`Storage=volatile`, `SystemMaxUse=16M`) | `tests/hardening_structure.sh` §9d | — |
| Unpatched vulnerabilities, drift by feature updates | Security-only unattended-upgrades (no automatic reboots; the daemon is not an apt package — updates are manual via `raspberry/install.sh`) | `harden-upgrades.sh` (`52dtn-security-only.conf`, `Automatic-Reboot "false"`) | `tests/hardening_structure.sh` §9e | — |
| Physical tampering with a mounted unit | Overlayfs read-only root (default OFF, operator opt-in), `/var/lib/dtn-node` bind-mounted from the real ext4 root so the database stays durable; rollback twin; `--status` inspection | `enable-readonly-root.sh` / `disable-readonly-root.sh` (init-bottom `dtn-overlayroot`, `initramfs-dtn`, kernel-upgrade regen hook) | `tests/hardening_structure.sh` §9f | FIELD-6 (companion) |
| Component death after a clean boot (brcmfmac wedge, dnsmasq OOM, crash loop) | Per-component probes + restart, capped at 3/hour/component; budget exhaustion drops a journald marker instead of looping | `dtn-network-watchdog.sh` (`MAX_RESTARTS_PER_HOUR=3`, `STORM_WINDOW_SECONDS=3600`, `logger -t dtn-network-watchdog`); timer every 2 min | `tests/hardening_structure.sh` §9g (per-component plan, storm guard) | 10, 11, FIELD-1/2 |
| Zero visibility into a hostile square | Counters-only telemetry, one aggregated line per 5 min — never `all_sta`, IPs/MACs/names discarded inside the parsers; output lands in the volatile journal + `/dev/shm/dtn-telemetry.summary` | `dtn-telemetry.sh` (collectors `collect_*`, fields `stations` … `daemon_507=na`) | `tests/hardening_structure.sh` §9h (no IP/MAC in output, `all_sta` never invoked) | — (consumed by `docs/RUNBOOK.md`) |
| Dirty power cut mid-write | `Type=notify` + `WatchdogSec=30`, `Restart=always`/`RestartSec=5`; WAL replay + ext4 journal replay on boot; watchdog pings via `node/internal/sdnotify` | `raspberry/systemd/dtn-node.service`; `node/internal/storage/storage.go` (`Open` boot path) | `tests/hardening_structure.sh` §9c; `tests/chaos/chaos_kill_mid_sync.sh` | 1, 2, 12, FIELD-3/4 |

## 5. Track 4 — the executable proof

`make chaos` (`tests/chaos/run_all.sh`, ports 18095–18099; platform-missing injections SKIP) runs one injection per script; `make test` runs the full suite; `.github/workflows/test.yml` runs both in CI. The authoritative per-row contract is `tests/chaos/FAILURE_MATRIX.md` (13 automated rows + FIELD-1…6).

| Proof | Artifact | What it pins |
|---|---|---|
| Kill mid-sync / mid-write | `tests/chaos/chaos_kill_mid_sync.sh` | WAL atomicity: zero `.corrupt-*`, seeded envelopes byte-identical (rows 1–2) |
| Corruption family | `tests/chaos/chaos_corrupt_db.sh` | Quarantine + rebuild + serve, healthy db never quarantined (rows 3–5) |
| Full disk | `tests/chaos/chaos_full_disk.sh` | 507/429 shed family, daemon alive, recovery without restart (row 6) |
| Restart under load | `tests/chaos/chaos_restart_under_load.sh` | Only 200/400/413/429/507 in live windows, no hangs, no 5xx storm (row 7) |
| Store at cap + startup janitor | `tests/chaos/chaos_janitor_flood.sh` | Sweep completes under write pressure, live mail never eaten (row 8) |
| Parser fuzzing | `tests/chaos/chaos_fuzz_parsers.sh` (`FUZZTIME`, default 20 s/target) | No panic, no 5xx from untrusted bytes (row 9) |
| Structural hardening | `tests/hardening_structure.sh` (197 assertions, rootless, artifact-level) | Every Track 1/3 claim above, on the generated artifacts |
| Protocol E2E | `tests/sync_e2e.sh` (84 assertions) | Limit rejections, redirect pair, §15 versioning incl. downgrade refusal |
| Field procedures | `tests/chaos/FAILURE_MATRIX.md` FIELD-1…6 | Hardware-only injections, pass/degrade/fail recording (rows 10–13) |

Entry points (all rootless; `make` is a wrapper, every recipe is a plain shell command):

| Entry point | Runs |
|---|---|
| `make test` | go test + 3 headless SPA tests + `tests/sync_e2e.sh` + `tests/hardening_structure.sh` (the CI sequence) |
| `make chaos` | `tests/chaos/run_all.sh` — all six injection scripts, SKIP-where-unplatformable |
| `make fuzz` | `tests/chaos/chaos_fuzz_parsers.sh` only (`FUZZTIME`, default 20 s/target) |
| `make lint` | `gofmt -l` (no output allowed) + `go vet ./...` in `node/` |
| CI | `.github/workflows/test.yml` — lint, `make test`, `make chaos` on every push/PR |

## 6. What we deliberately do NOT defend

Honest limits. Each item names the residual risk and the recovery story — an accepted exposure with a plan beats a pretended guarantee.

- **Open 802.11 physics.** Deauthentication flooding, RF jamming and pure airtime saturation at the radio layer are not fixable in software on an open AP: an attacker with a radio can deny the medium itself. *Residual risk:* a sustained physical-layer attack keeps every client off. *Recovery:* CAKE (`traffic-shaping.sh`) bounds what one associated station can do to the others; the shields and watchdog keep the node itself up; when the attacker leaves, every unit re-forms the AP and reassociates without intervention (FIELD-1/FIELD-5 verify the recovery path).
- **TLS absence** (`docs/protocol.md` §12). Deliberate: no certificate can exist for a shared origin, and the payload is E2EE regardless. *Residual risk:* a network observer sees full envelope metadata (sizes, timing, `dest_hint`s, directory) — nothing more. *Recovery:* none needed; there is no key material on the wire to protect.
- **Evil-twin exposure is bounded by client-side crypto** (`docs/protocol.md` §13.1). A twin AP (or a twin node) can collect, replay and withhold envelopes, and can recompute the CURRENT epoch's `dest_hint`s from the public directory (`docs/protocol.md` §13.3 — since 1.6.0 hints rotate per epoch, so the linkage decays at every boundary; residuals: within-epoch linking and the §6.1 transition-window legacy hints). It cannot read, modify or forge them: the Poly1305 MAC + Ed25519 signature verify on the recipient's device and everything else fails closed. *Residual risk:* metadata harvesting and selective service denial by whoever runs the twin. *Recovery:* client-side — dedup by `id` absorbs replays; TTL caps how long a withheld envelope matters; users move to a genuine node.
- **Physical access.** Anyone who opens the enclosure owns the SD card and the console. The read-only root raises the cost of a drive-by tamper; it cannot stop an attacker with the unit on a bench. *Residual risk:* total, including storage replacement. *Recovery:* the node holds no secrets (blind by design, §13.1) — reprovision from the release kit and move on (`docs/RUNBOOK.md` §4.6).
- **Supply chain.** Release binaries are checksum-verified against the release `SHA256SUMS` (`raspberry/install.sh`), and a provisioned node has no uplink, so post-provision supply-chain attack requires physical access (previous bullet). *Residual risk:* a compromised build host — out of scope for a field node; verify checksums at install time.

## 7. The three-layer failure contract

Every failure mode in `tests/chaos/FAILURE_MATRIX.md` is specified as the same three layers, in order:

| Layer | Meaning | Where it lives |
|---|---|---|
| **Shed** | Overload and abuse are refused cleanly, per-source, with honest error shapes — never chaos: firewall DROPs and hashlimits at the door (`iptables.sh`), `429 rate_limited` / `429 node_full` / `507 storage_unavailable` / `400` / `413` at the API (`ratelimit.go`, `handlers.go`), individual deauthentications (`station-shield.sh`). The honest client next to the attacker keeps full service. | Track 1 + Track 2 |
| **Survive** | Whatever happens, the node never serves a half-broken state and never loses ACKed data silently: WAL atomicity, corrupt-DB quarantine-or-refuse, `Restart=always` + watchdog pings, read-only-root option with the durable data-dir bind-mount. | Track 2 + Track 3 |
| **Self-recover** | Nobody powers cycles a field unit: systemd restarts the daemon, the network watchdog restarts the AP stack per component (budget-capped), timers resume, all shed state (tmpfs) resets, and the worst case is a 5-minute reflash from the release kit. | Track 3 (+ `docs/RUNBOOK.md`) |

The executable proof of this contract is the chaos suite: rows 1–9 of `tests/chaos/FAILURE_MATRIX.md` assert shed + survive + auto-recover on every automated injection, and FIELD-1…6 do the same on real hardware before any deployment. A defense whose failure mode is not a row of that matrix is not a defense — it is a hope.

## 8. Install map and firing cadence

Everything is installed and enabled by `raspberry/provision.sh` (idempotent; the reboot is the activation step). Repo path → provisioned path → what fires it:

| Repo artifact | Provisioned as | Fired by | Cadence |
|---|---|---|---|
| `raspberry/firewall/iptables.sh` | `/usr/local/sbin/dtn-firewall.sh` | `dtn-firewall.service` (oneshot, `Before=dtn-node.service`); safe to re-run by hand | boot |
| `raspberry/firewall/traffic-shaping.sh` | `/usr/local/sbin/dtn-traffic-shaping.sh` | `dtn-traffic-shaping.service` (oneshot) | boot |
| `raspberry/firewall/dns-shield.sh` | `/usr/local/sbin/dtn-dns-shield.sh` | `dtn-dns-shield.timer` (`OnBootSec=90s`) | every 60 s |
| `raspberry/firewall/station-shield.sh` | `/usr/local/sbin/dtn-station-shield.sh` | `dtn-station-shield.timer` (`OnBootSec=3min`) | every 2 min |
| `raspberry/hardening/dtn-network-watchdog.sh` | `/usr/local/sbin/dtn-network-watchdog.sh` | `dtn-network-watchdog.timer` (`OnBootSec=4min`) | every 2 min |
| `raspberry/hardening/dtn-telemetry.sh` | `/usr/local/sbin/dtn-telemetry.sh` | `dtn-telemetry.timer` (`OnBootSec=6min`) | every 5 min |
| `raspberry/hardening/harden-ssh.sh` (+ `sshd-hardening.conf`) | `/usr/local/sbin/dtn-harden-ssh.sh` | `provision.sh` step 8 (apply-once; idempotent) | provisioning |
| `raspberry/hardening/harden-services.sh` | `/usr/local/sbin/dtn-harden-services.sh` | `provision.sh` step 8 | provisioning |
| `raspberry/hardening/harden-upgrades.sh` | `/usr/local/sbin/dtn-harden-upgrades.sh` | `provision.sh` step 8 | provisioning |
| `raspberry/hardening/enable-readonly-root.sh` / `disable-readonly-root.sh` | `/usr/local/sbin/dtn-enable-readonly-root.sh` / `dtn-disable-readonly-root.sh` | never automatic — explicit operator opt-in (default OFF) | operator |
| `raspberry/systemd/dtn-node.service` | `/etc/systemd/system/dtn-node.service` | boot (`WantedBy=multi-user.target`), plus systemd's own `WatchdogSec=30` in-process | always |

Runtime state (all tmpfs, all dies at reboot — assumption A7): `DTN_DNSBL` chain (flushed by every firewall run), `DTN_ACC` counters (per-lease rules fed by the station shield), `/dev/shm/dtn-dns-queries.log`, `/dev/shm/dtn-dns-shield.state`, `/dev/shm/dtn-station-shield.state`, `/dev/shm/dtn-network-watchdog.state`, `/dev/shm/dtn-telemetry.summary`. The only durable state on the node is the database directory `/var/lib/dtn-node` (0750 `dtn:dtn`) — everything an attacker or a shield did evaporates with the power cut that ends the day.
