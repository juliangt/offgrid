# Failure-mode matrix — chaos engineering (issue #16, Phase 4, Track 4)

The chaos discipline of this repository in one table: for every (component ×
failure) pair, WHAT injects it, WHAT the node must do (always **degrade +
auto-recover** for anything automatable), WHAT happens to the data (honest,
no fairy tales), and WHERE the behavior is verified.

Reading guide:

- **Injection** is either an automated script under `tests/chaos/` (runs on
  macOS dev machines and Linux CI/Pi alike; every script builds its own
  daemon binary, owns ports `18095-18099`, and cleans up after itself) or a
  FIELD-n procedure of the [Field chaos section](#field-chaos-manual-hardware-procedures)
  below — those are manual by nature, run on real hardware before any
  deployment, and recorded with the pass/degrade/fail template given there.
  `run_all.sh` runs every automated row in order (`make chaos`).
- **Expected behavior** follows the degrade contract of issue #16 Tracks 1-3:
  the node sheds cleanly (§10.1 error shapes, 429/507 families, per-IP
  budgets), stays up or comes back on its own, and never serves a half-broken
  state. Anything less is a FAIL of the named artifact — and if a chaos run
  exposes a REAL daemon bug, stop and report it instead of patching daemon
  code inside a chaos commit.
- **Data expectation** uses exactly two honest categories:
  - *survives* — stored, legitimate (already-ACKed) envelopes MUST come back
    byte-identical; the verifying artifact asserts it by payload sha256;
  - *accepted loss* — the failure mode may legitimately destroy data. A
    **quarantine counts as loss WITH evidence preserved**: every envelope in
    the `.corrupt-<ts>` file is gone forever, but the file stays on disk as
    operator-recoverable evidence (runbook of a later phase covers examining
    and discarding it). Un-ACKed in-flight writes are always accepted loss
    (no client ever saw a 200 for them).

## Automated matrix

| # | Component | Failure mode | Injection | Expected behavior | Data expectation | Verifying artifact |
|---|---|---|---|---|---|---|
| 1 | daemon | Daemon killed mid-sync (SIGKILL while large sync POSTs are in flight) | Automated: background flood of 100-envelope §10.4 POSTs, SIGKILL at a random (30-300) ms moment, restart on the same database | Ready again; store NOT corrupted (zero `.corrupt-*` — SQLite WAL atomicity); a fresh sync (push + pull) works immediately after restart | Seeded (ACKed) envelopes **survive** byte-identical; the never-ACKed in-flight batch is **accepted loss** (may or may not have landed — the client saw no ack either way) | `tests/chaos/chaos_kill_mid_sync.sh` |
| 2 | daemon | Daemon killed mid-write (SIGKILL with committed-but-uncheckpointed frames in the WAL) | Automated: push envelopes, SIGKILL (no graceful checkpoint), then a restart — also exercised as the setup of matrix row 5 | Restart replays the valid WAL prefix; daemon ready on the same database; SQLite atomicity means no torn rows, no quarantine | Checkpointed envelopes **survive**; the un-checkpointed tail is **accepted loss** (explicitly: it exists only in the killed process's WAL) | `tests/chaos/chaos_corrupt_db.sh` (wal-kind setup) + `tests/chaos/chaos_restart_under_load.sh` (SIGTERM windows) |
| 3 | SQLite | Database file truncated (power loss / flash wear scar) | Automated: db file cut to 30% offline, daemon started against it | The `storage.Open` contract (issue #16 Phase 2): SQLITE_CORRUPT → quarantine the file and sidecars as `<db>.corrupt-<ts>`, create a fresh database, continue startup, serve; NEVER a half-broken serve; the only other legal outcome is a loud non-zero exit WITHOUT side effects | Everything the corrupt file held is **accepted loss** — quarantine = loss with evidence preserved; the rebuilt store accepts pushes again | `tests/chaos/chaos_corrupt_db.sh` (truncate kind) |
| 4 | SQLite | Database header overwritten with garbage (bit rot / partial overwrite) | Automated: first 32 bytes of the db replaced with junk offline | Same contract as row 3 with SQLITE_NOTADB: quarantine + fresh rebuild + serve (or clean non-zero refusal, no side effects) | Same as row 3: **accepted loss**, `.corrupt-*` evidence kept; rebuilt store accepts pushes again | `tests/chaos/chaos_corrupt_db.sh` (garbage kind) |
| 5 | SQLite | WAL sidecar truncated mid-frame (dirty power during write, then damage) | Automated: SIGKILL a daemon with committed-but-uncheckpointed envelopes, truncate `-wal` to 30% | Clean recovery: SQLite replays the valid prefix; the HEALTHY main database is NEVER quarantined; daemon ready and serving; pushes work again | Checkpointed (ACKed) envelopes **survive** byte-identical; the truncated WAL tail is **accepted loss** (no quarantine, hence no `.corrupt-*` evidence — the loss is bounded by what was not yet checkpointed) | `tests/chaos/chaos_corrupt_db.sh` (wal kind) |
| 6 | storage | Full disk during write (abuse-filled / worn-out SD) | Automated: 8 MiB loopback volume (macOS `hdiutil` rootless; Linux sudo loop mount), daemon's db on it, volume filled to ENOSPC | Push fails CLEANLY in the shed family — 507 `storage_unavailable` (or 429 at cap/budget); daemon stays ALIVE; read path still serves (capabilities + pull-only sync → 200); SQLite FULL is not corruption (zero `.corrupt-*`); once space is freed pushes are accepted again on the SAME database, no restart needed | Nothing stored is lost (the failed batch was never ACKed — **accepted loss** of the rejected pushes only); stored envelopes untouched | `tests/chaos/chaos_full_disk.sh` (SKIPs cleanly where volume tooling is unavailable) |
| 7 | daemon | Restart under load (graceful SIGTERM while N clients hammer) | Automated: 6 concurrent workers (valid pushes + malformed junk + pull-only syncs) while the daemon is SIGTERM-restarted 4 times | Every live-window request answered from the clean set only: 200 or 400/413/429/507 — NO 5xx storm, no panics; connection drops/refusals confined to the restart windows and never hanging (hard curl timeouts); ready again within a bounded window every time | Seeded (ACKed) envelopes **survive** all restarts byte-identical, store never quarantined; only never-ACKed in-flight requests of a window are **accepted loss** | `tests/chaos/chaos_restart_under_load.sh` |
| 8 | storage | Store flooded to its cap + startup janitor (§10.6) | Automated: 5000-row schema-2 fixture (4500 long-expired + 500 live) crafted offline, daemon started against it while a background writer hammers pushes | At the cap pushes are refused (429 `node_full`, reject-newest/keep-oldest); the startup sweep completes within a bounded time DESPITE the write pressure (TTL eviction not starved by writes); capacity reclaimed: fresh pushes accepted and served afterwards | Expired envelopes are **accepted loss** (the janitor's whole job); live, unexpired envelopes **survive** byte-identical (id set + payload sha asserted — the janitor must never eat live mail) | `tests/chaos/chaos_janitor_flood.sh` |
| 9 | daemon | Malformed envelope flood (parser fuzzing) | Automated: Go native fuzzing, committed in-package: `FuzzParseEnvelope` (§10.5/§15.3 parse+validate path) and `FuzzSyncHandler` (full POST /api/v1/sync stack); seed corpora run under plain `go test` | Untrusted bytes produce only a decode/validation error or a clean 200 — NEVER a panic, NEVER a 5xx (the only legal non-OK statuses are 400/413); a fuzz crash is a REAL bug: stop and report (the crashing input lands in the package `testdata/fuzz/`) | Nothing is stored for rejected input (**no loss** — rejected batches fail closed before a single insert); accepted envelopes stay valid through the marshal round trip | `tests/chaos/chaos_fuzz_parsers.sh` (FUZZTIME env, default 20s per target) + `node/internal/envelope/fuzz_test.go`, `node/internal/api/fuzz_test.go` |
| 10 | Wi-Fi (AP) | hostapd process death (AP disappears mid-mule-sync) | FIELD-1 (manual) + automated shield: the Track-3 `dtn-network-watchdog.timer` restarts the component per its plan | Degrade: the AP vanishes, in-flight mule syncs drop, clients disassociate; auto-recover: watchdog re-forms the AP, stations reassociate, the portal answers again | Node data unaffected (no envelope loss — the sync client retries); **no loss** beyond the in-flight request of the dead moment | FIELD-1 below (manual recording template); watchdog plan pinned by `tests/hardening_structure.sh` |
| 11 | DHCP-DNS | dnsmasq death (no leases, no wildcard DNS) | FIELD-2 (manual) + automated shield: the same Track-3 watchdog restarts dnsmasq per its plan | Degrade: new stations cannot join (no DHCP) and names do not resolve; the daemon itself keeps serving any client that still has its IP; auto-recover: watchdog restarts dnsmasq, leases reissue | Node data unaffected; **no loss** | FIELD-2 below; watchdog plan pinned by `tests/hardening_structure.sh` |
| 12 | power | Power cut at a random moment (dirty solar cuts, routine) | FIELD-3 (manual: repeated timed yanks) — the daemon-level equivalent is automated as rows 1/2/5 (SIGKILL = power cut for the process) | On boot the unit starts on its own (systemd `Restart=always` + Type=notify watchdog); storage side: exactly the row 3/4/5 contract — clean start, or quarantine + rebuild, never a half-broken serve | Last seconds of un-checkpointed writes are **accepted loss**; everything checkpointed **survives** or is quarantined as **loss with evidence**; WAL + the §15.3 migration chain make the boot deterministic | FIELD-3 below; daemon-side: `chaos_corrupt_db.sh`, `chaos_kill_mid_sync.sh` |
| 13 | SD card | SD card pulled mid-write (field servicing gone wrong) | FIELD-4 (manual) | On the next boot with a re-seated card: the row 3/4/5 contract (worst case quarantine + rebuild); with a destroyed card: reprovision from scratch (the one-file-binary deploy of docs/BUILD.md §5) | Worst case the whole store AND directory are **accepted loss** (quarantine evidence only if the fs survived); this is the accepted worst-case of a blind relay node — no backup exists on the node itself | FIELD-4 below; post-pull behavior: `chaos_corrupt_db.sh` |

## Field chaos — manual hardware procedures

These five procedures are **manual by nature** — they need a real Pi, a real
radio, a real power switch and hands. No script in `tests/chaos/` runs them,
and none of the automated assertions above substitutes for them: the
automated suite simulates the PROCESS and STORAGE consequences of each
failure (SIGKILL, ENOSPC, corrupt files) on a dev machine; the field
procedures verify the WHOLE stack — boot chain, watchdogs, AP reformation,
radio behavior — on the hardware that will actually sit in a field.

Run each procedure before any deployment and after any provisioning change.
Record one line per repetition using the templates below — pass / degrade /
fail has exactly this meaning:

- **pass** — the expected behavior column of matrix rows 10-13 happened
  (degrade was clean, auto-recover happened unaided, data expectation held);
- **degrade** — recovery happened, but late, noisy, or aided (e.g. watchdog
  needed its second attempt, AP re-formed after > 60 s, one manual
  intervention that the runbook sanctions);
- **fail** — the node stayed down, served a half-broken state, or lost data
  beyond the stated expectation. A fail is a REAL finding: stop, capture
  `journalctl -b -1` and any `.corrupt-*` files, and report it.

### FIELD-1 — AP process death (hostapd killed; matrix row 10)

Setup: provisioned Pi, one station (phone/laptop) associated and holding the
portal. Procedure: `sudo systemctl kill --signal=SIGKILL hostapd` (the
watchdog treats it as death), note the time, then every 10 s try to
reassociate and load `http://offgrid.local:8080`.

```
FIELD-1 hostapd death  date: ______  board: ______  build: ______
  rep 1: killed __:__  AP back __:__ (after __ s)  portal ok: Y/N  verdict: pass/degrade/fail
  rep 2: ...
  notes (watchdog log lines, deauth storms, seconds-to-reassociate):
```

### FIELD-2 — dnsmasq death (matrix row 11)

Setup: as FIELD-1. Procedure:
`sudo systemctl kill --signal=SIGKILL dnsmasq`; verify an already-associated
station with a static-served lease can still reach the portal by IP
(degraded-but-up), then watch the watchdog restore DNS/DHCP and a fresh
station join.

```
FIELD-2 dnsmasq death  date: ______  board: ______  build: ______
  rep 1: killed __:__  dnsmasq back __:__ (after __ s)  joined-by-name ok: Y/N  by-IP during outage ok: Y/N  verdict: pass/degrade/fail
  notes:
```

### FIELD-3 — power cut at a random moment, repeated (matrix row 12)

Setup: provisioned Pi, one mule mid-sync (a push loop running). Procedure:
yank power at random moments (mid-push, mid-boot, idle) — 5 repetitions
minimum; restore power each time and DO NOT touch the node until it either
serves the portal or stays dead for 3 minutes. After each boot: check
`journalctl -u dtn-node -b`, count `.corrupt-*` files in `/var/lib/dtn-node`,
pull the store and compare against the pre-cut pull (the mule's ACKed
envelopes are the survival set).

```
FIELD-3 power yank x N  date: ______  board: ______  build: ______
  rep 1: cut during ______  boot-to-portal ____ s  .corrupt-*: ___  seeded envelopes: ___/___  verdict: pass/degrade/fail
  rep 2: ...
  totals: boots ___  clean boots ___  quarantines ___  data lost beyond expectation: Y/N
```

### FIELD-4 — reboot storm (matrix row 12 companion)

Procedure: force `sudo reboot` the moment the node becomes reachable, 5
times in a row (the watchdog's restart-storm guard gets exercised on the
systemd unit side too). Assert every boot completes to a serving portal and
the store stays servable.

```
FIELD-4 reboot storm  date: ______  board: ______  build: ______
  rep 1: boot ____ s  portal ok: Y/N  store ok: Y/N  verdict: pass/degrade/fail
  rep 2: ...
```

### FIELD-5 — hostile station saturating the AP while a legitimate mule syncs (matrix rows 7/10 companion)

Setup: provisioned Pi; the mule phone holds the portal; a second "hostile"
device floods it (parallel HTTP POSTs of junk + a bandwidth hog). Procedure:
while the hostile station hammers, the mule performs a NORMAL visit — load,
register, push its transit queue, pull. The mule's visit must still succeed
(maybe slower); the hostile push flood must end in the shed families (429
rate_limited / node_full).

```
FIELD-5 hostile station vs honest mule  date: ______  board: ______  build: ______
  mule visit: completed Y/N   time ____ s (baseline ____ s)   envelopes pushed ___/___
  hostile flood: shed codes observed: ____________   mule ever refused: Y/N
  verdict: pass/degrade/fail
```

### FIELD-6 — SD pull mid-write (matrix row 13)

Procedure: with a push loop running, power off, pull the SD card, re-seat it,
power on. Record which of the three outcomes happened: clean boot /
quarantine + rebuilt store (`.corrupt-*` present) / card dead (reprovision).
This is the only procedure whose "fail the store" outcome is STILL a pass of
the procedure — the matrix accepts total card loss; what is NOT acceptable is
a boot into a half-broken serve.

```
FIELD-6 SD pull mid-write  date: ______  card: ______  build: ______
  outcome: clean boot / quarantined (.corrupt-* count __) / card dead (reprovisioned)
  post-recovery store serves: Y/N   verdict: pass/degrade/fail
```

## Coverage summary

| Matrix rows | Automated (machine-checked) | Field (manual, this document) |
|---|---|---|
| daemon | 1, 2, 7, 9 | 5 |
| SQLite / storage | 3, 4, 5, 6, 8 | 6 |
| Wi-Fi (AP) / DHCP-DNS | — (watchdog plans pinned by `tests/hardening_structure.sh`) | 1, 2 |
| power / SD | — (daemon-level equivalents: rows 1/2/5) | 3, 4, 6 |
