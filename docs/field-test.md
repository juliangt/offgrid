# Field Acceptance Test — Protocol and Report (issue #20)

| | |
|---|---|
| **Status** | **PROTOCOL READY — EXECUTION PENDING.** This document was prepared as an executable protocol plus an empty report scaffold by an automated agent on 2026-10-05. Every result cell below is **PENDING** until a human executes it on real hardware. Nothing is pre-checked; no physical result in this file has been observed by anyone. |
| **Scope** | Issue #20: full-system acceptance on real hardware — two-node physical mule walk, real-device captive-portal matrix, seed backup/restore on a real device, client isolation, cold start, RF coexistence, power draw — plus the quick-start guide validation (#23), the upgrade/rollback drill (#22) and operator-status agreement (#31), exercised on a real Pi. |
| **Rule of evidence** | A case passes only if the named observation was made on the named hardware on the recorded date, by the person who signs. Anything not observed stays PENDING. The software half of this issue (what IS verifiable without hardware) is automated as `tests/field_equiv.mjs` — run `make test`; it does NOT substitute for this session. |

## 0. How to run this session

1. Assemble the kit (`make field-kit` prints this checklist; see `docs/BUILD.md` §5 for the release USB kit).
2. Execute the cases in order T1 → T10 (T5/T7 need the power bench; they can run on a separate day).
3. After each case: fill its Result line and the results matrices in §12; add defect-log rows in §13 (one row per deviation, with a GitHub issue link).
4. Verdicts: **pass** (expected observation made), **degrade** (system worked, worse than documented — record numbers), **fail** (expected observation not made). Anything else is PENDING, not a pass.
5. Severity: **MVP-blocking** (the issue's own acceptance scope cannot be signed off without a fix) vs **follow-up** (recorded, scheduled, does not block #20).
6. When everything is filled: sign §14. Only the signed document closes issue #20.

## 1. Prerequisites — hardware and materials

| Item | Quantity | Notes |
|---|---|---|
| Raspberry Pi Zero 2 W (or Zero W) node, provisioned per `docs/BUILD.md` §5, current release | 2 | node A and node B; record build id from `/status` on each |
| USB power supply or bench PSU for the nodes | 2 | one must be interruptible (switch/connector) for T5 |
| Solar + battery bench (`docs/hardware.md` §4) or battery-only supply | 1 | for T5 (cold start) and T7 (24 h figure if run) |
| USB power meter (or INA219/INA260 shunt) | 1 | for T7; must show volts + amps |
| Android phone (any recent, Chrome) | 1 | the device-matrix device |
| iPhone (any recent, Safari) | 1 | the device-matrix device |
| Third phone OR a laptop browser (mule) | 1 | T1 mule; a laptop on the AP works |
| Laptop with `curl`, `ssh` and a terminal | 1 | health/status probes, sha256 cross-check |
| Release USB kit (`docs/BUILD.md` §5 Path 4 checklist) | 1 | `dtn-node-linux-*` (board's ISA) + `SHA256SUMS` + `raspberry-<tag>.tar.gz` |
| Printed: `docs/quick-start.md` (end-user guide) | 2 copies | T8; also served by every node at `http://offgrid.local:8080/guide` |
| Printed: this document | 2 copies | fill the paper copy, transcribe |
| Wi-Fi environment | — | two spots 30–200 m apart (or separated by walls) for the two nodes; no other Internet needed |

Before starting: both nodes booted, portal answering on `http://offgrid.local:8080` from a phone, `GET /api/v1/health` → `"status":"ok"` on both. Record in §14: date, location, node serials/build ids, phone models/OS versions, meter model.

---

## T1 — Two-node physical mule walk

**Goal.** The issue's core journey: Alice registers at node A and sends; a mule's phone carries the envelope physically from node A to node B; Bob receives at node B with payload integrity proven by display equality and a sha256 cross-check.

**Setup.**
- Node A and node B powered, 30–200 m apart (or separated so each node's AP does NOT reach the other's clients — partial RF overlap is allowed, that is T6's business).
- Phone A (Alice), mule phone (or laptop browser), phone B (Bob). Bob's identity must exist before Alice sends: both phones at node A first (Bob registers there, Alice picks him from the directory), then Bob walks to node B with his identity intact (same origin `http://offgrid.local:8080` — this is also T2c evidence).
- Laptop on node A's Wi-Fi for the health probes and the hash.

**Steps.**
1. Node A: Bob registers alias `bob_<n>`, saves his seed on paper (T3 will use it). Alice registers alias `alice_<n>`. From the laptop: `curl -s -H 'Host: offgrid.local:8080' http://<node-A-IP>:8080/api/v1/health` → record `directory_entries` (expect 2) and `envelopes` (expect 0).
2. Alice writes the test payload: a short sentence plus a random token, e.g. `field walk test 7KQ-4XP2-2026`. She writes the EXACT text on paper. Compute the reference digest on the laptop: `printf '%s' 'field walk test 7KQ-4XP2-2026' | shasum -a 256` → record.
3. Alice sends it to Bob (New message tab → To: `bob_<n>` → Sign and send). Her sent list shows "queued", then "sent" after her automatic sync. Laptop: node A `/api/v1/health` → `envelopes` incremented by 1, `counters.pushes_accepted` ≥ 1.
4. Mule joins node A's AP, opens `http://offgrid.local:8080` in its full browser (register any throwaway alias — a mule needs an identity to sync), taps **Sync now**. The telemetry panel must show "Foreign envelopes in transit: 1" (or more if others sent too).
5. Mule physically walks to node B (leave node A's range), joins node B's AP, opens the portal (same URL), taps **Sync now**. Telemetry drops to 0 carried.
6. Laptop at node B: `/api/v1/health` → `envelopes` incremented (the drop-off), `counters.pushes_accepted` incremented.
7. At node B, Bob opens the portal in his full browser (identity restored from step 1 — same alias in the Identity tab), taps **Sync now**. Inbox shows the message. Bob copies the EXACT text to paper.
8. Compute the received digest: `printf '%s' '<bob's transcribed text>' | shasum -a 256` → compare with step 2's digest.
9. Optional (best-effort, not gating): leave delivery confirmations ON; after Bob's sync, the ack travels mule → node A → Alice syncs at node A again; her sent list may show "delivered". Record what actually happened.

**Expected.** Step 4 shows 1 carried; step 7 shows the message in Bob's inbox; step 8 digests are IDENTICAL; the displayed text on both ends is byte-identical to Alice's paper text; no error banners.

**Result:** [ ] pass  [ ] degrade  [ ] fail  (date: ______, executor: ______)
**Notes:** ______________________________________________________________

## T2 — Real-device captive-portal matrix

**Goal.** One Android + one iOS device, each in (a) the OS captive mini-browser and (b) the full browser, at `http://offgrid.local:8080`; verify the full-browser banner flow and that a full-browser identity survives node changes (the software half of this is `tests/field_equiv.mjs` §C).

**Setup.** Node A and node B up. Both phones factory-fresh in browser data (or a wipe step from T3 available). The portal's captive banner is the `#banner-captive` element ("Open this in your full browser") — spec §13.4.

**Steps (run the sub-table once per device).**
1. **Captive mini-browser.** Forget the network first, then join `offgrid-messages`; when the OS pops the mini-window: does the portal render? Does the banner "Open this in your full browser" appear, with the address `http://offgrid.local:8080` and a working Copy button? Register is NOT required here.
2. **Full browser.** Open Chrome (Android) / Safari (iOS) yourself, type `http://offgrid.local:8080`. Register alias, pass through the "Save your backup seed" screen (tick the box), land in the app.
3. **Banner suppression.** In the FULL browser the captive banner must NOT appear; the portal footer "Guide" link opens `/guide`.
4. **PWA-lite.** Add to Home screen (Android: menu ⋮ → Add to Home screen; iOS: Share → Add to Home Screen). The icon opens the portal to the app.
5. **Identity survives node changes.** Walk the phone from node A into node B's range, join node B's AP, open the portal (full browser or the home-screen icon): Identity tab must show the SAME alias and the SAME `dest_hint` as at node A; inbox/contacts still present; **Sync now** works against node B.
6. **Captive mini-browser is ephemeral (expected, honest boundary).** Inside the mini-browser only, register a throwaway alias, close the mini-window, re-join: the registration may be gone (isolated/ephemeral storage profile, spec §13.4). Record what happened — do not fail the case for this; it is the documented reason the banner exists.

**Per-device sub-table (fill one per phone).**

| Check | Android (model/OS: ______) | iOS (model/OS: ______) |
|---|---|---|
| Captive mini-browser renders the portal | PENDING | PENDING |
| Banner + Copy shown in mini-browser | PENDING | PENDING |
| Full browser: register + seed screen completes | PENDING | PENDING |
| No captive banner in full browser; /guide opens | PENDING | PENDING |
| Home-screen icon opens the app | PENDING | PENDING |
| Identity (alias + dest_hint) survives node A → node B | PENDING | PENDING |
| Mini-browser registration ephemeral (expected) | PENDING | PENDING |

**Result:** [ ] pass  [ ] degrade  [ ] fail  (date: ______, executor: ______)
**Notes:** ______________________________________________________________

## T3 — Seed backup/restore on a real device

**Goal.** The issue's seed item: wipe a phone's browser data, restore from the paper seed, get the SAME identity back — same `dest_hint` in the Identity tab — and the inbox re-registers on the node (directory upsert resent, as `tests/field_equiv.mjs` §A–B asserts headlessly).

**Setup.** One phone with a registered identity at node A whose seed was written on paper in T1/T2 (the seed is the Base64 text under "Save your backup seed", or later Identity tab → "Show seed").

**Steps.**
1. Record the pre-wipe state: Identity tab → alias, `dest_hint`, Ed25519/X25519 keys (copy to paper). Send one message to this device from a second identity; note the inbox count.
2. **Wipe.** Android: Chrome → Settings → Privacy → Clear browsing data → "Clear data" incl. site settings/cookies (or: App info → Storage → Clear data). iOS: Settings → Apps → Safari → Clear History and Website Data. Confirm the portal at `http://offgrid.local:8080` now shows the registration screen again (empty state) and the old inbox is gone.
3. **Restore.** On the registration screen use the "restore your identity" card: paste the paper seed into "Backup seed (Base64)", re-enter the SAME alias, tap "Import identity".
4. **Verify.** Identity tab: `dest_hint` and both keys are IDENTICAL to step 1. Inbox: the pre-wipe message rows are GONE (expected — the seed restores the identity, not the wiped local store; the honest boundary). Directory: the node lists the alias again with the same keys (`curl -s -H 'Host: offgrid.local:8080' http://<node-A-IP>:8080/api/v1/directory` — the upsert is resent by the import).
5. **Receive.** Second identity sends a new message; this device taps Sync now → the new message arrives and opens (same keys → prekey/legacy mail still addressed correctly).

**Expected.** Same `dest_hint` and keys after restore; directory entry re-published (same alias + pubkey); new mail arrives; old local history stays gone (accepted, by design).

**Result:** [ ] pass  [ ] degrade  [ ] fail  (date: ______, executor: ______)
**Notes:** ______________________________________________________________

## T4 — Client isolation on a live node

**Goal.** Two associated clients cannot reach each other (defense in depth: `ap_isolate=1` at L2 + the firewall's FORWARD policy DROP at L3 — `raspberry/hostapd/hostapd.conf`, `raspberry/firewall/iptables.sh`), while the node and portal stay reachable.

**Setup.** One node; two clients (two phones, or a phone + a laptop) associated to `offgrid-messages`. Get each client's DHCP IP from the phone's Wi-Fi details (typically `10.42.0.x`). The laptop is the most capable prober; use it for the command lines.

**Steps (from client 1, against client 2's IP; then swap).**
1. `ping -c 3 -W 2 <client2-ip>` → expect 100% packet loss.
2. TCP probes against the other client: `nc -vz -w 2 <client2-ip> 8080`, and any port the other client actually serves if known (e.g. a phone hotspot/airdrop port is out of scope — only probes toward the other AP client count) → expect connection refused/timeout.
3. From client 1's browser, try `http://<client2-ip>:8080/` → expect no answer.
4. **Control (the point of the case):** during the same minute, client 1 opens `http://offgrid.local:8080/` and `curl -s -H 'Host: offgrid.local:8080' http://10.42.0.1:8080/api/v1/health` → portal + health answer normally.
5. From the node console (if a keyboard/screen is attached): `hostapd_cli -i wlan0 all_sta` lists BOTH stations (isolation is enforced while both are associated — the probe results above are the evidence, this line corroborates association).

**Expected.** All client-to-client probes fail; node/portal probes succeed throughout.

**Result:** [ ] pass  [ ] degrade  [ ] fail  (date: ______, executor: ______)
**Notes:** ______________________________________________________________

## T5 — Cold start (power yank) on the power bench

**Goal.** The issue's cold-start item: cut power mid-write and at rest; the node must come back serving the portal with the store intact (or quarantined with evidence — never half-broken). This is the hardware twin of chaos rows 1/2/5 and FIELD-3 of `tests/chaos/FAILURE_MATRIX.md` (row 12); read that procedure and its template first.

**Setup.** Node on battery/bench supply through an interruptible switch. Populate the store FIRST: push a known set of envelopes (e.g. two phones exchange several messages through the node, or `tests/sync_e2e.sh`-style curl pushes from the laptop — record the count from `/api/v1/health` → `envelopes` = N).

**Steps (5 repetitions minimum, FIELD-3 discipline).**
1. Cut A: yank power DURING a push loop (a phone or curl is mid-`POST /api/v1/sync`).
2. Cut B: yank at rest (idle, nothing in flight).
3. Each cut: restore power after ~5 s, then DO NOT TOUCH the node until it either serves the portal or stays dead 3 minutes.
4. After each boot: from a client, portal loads; `curl -s -H 'Host: offgrid.local:8080' http://10.42.0.1:8080/api/v1/health` → `"status":"ok"`; record `envelopes` and `uptime_seconds`; record boot-to-portal seconds.
5. On the console: `journalctl -u dtn-node -b` (clean startup log, watchdog READY), `ls /var/lib/dtn-node` (any `.corrupt-*` quarantine files?), `vcgencmd get_throttled` (no brownout flags).
6. Data expectation: the checkpointed set survives byte-identical (pull the store and compare the pre-cut ids, e.g. re-sync a phone and check its inbox); the last seconds of un-checkpointed writes are ACCEPTED LOSS by design (row 12) — record exactly what was lost, if anything.

**Expected.** Every boot self-starts all units (no operator help), portal serves, health `ok`; either zero `.corrupt-*` or a quarantine with the evidence dir preserved (the documented row-3/4/5 contract); losses confined to the accepted in-flight window and recorded honestly.

**Result:** [ ] pass  [ ] degrade  [ ] fail  (date: ______, executor: ______)
**Notes:** ______________________________________________________________

## T6 — RF coexistence check (two nodes, same default channel)

**Goal.** The issue's coexistence item: two nodes within PARTIAL RF range, both on the shipped default channel 6 (`raspberry/hostapd/hostapd.conf`) — document the observed impact honestly, and record what the channel-planning guidance (`docs/hardware.md` §10) prescribes for the deployment.

**Setup.** Node A and node B on channel 6, placed so a phone at the midpoint (or a few meters apart with a wall between) sees BOTH SSIDs weakly. A stopwatch and a phone.

**Steps.**
1. Baseline (node B powered OFF): phone on node A — time "Sync now" with a loaded transit queue (~10 envelopes from T1 leftovers) and time a cold portal load. Record RSSI if the phone shows it.
2. Power node B ON (same channel). Repeat the same timings from the same spot; also join node B and repeat toward it. Record: association stalls, retry loops, portal-load and sync deltas.
3. Walk test: walk phone from node A's range to node B's; note reassociation time and whether the portal pops normally.
4. Record the deployment verdict against `docs/hardware.md` §10: co-channel nodes in partial range share airtime (expected degradation mode); for THIS deployment, either the nodes are far enough (record the evidence) or the plan changes (adjacent nodes on 1/6/11, or co-channel pairs geographically separated) — write the chosen plan down.
5. If any channel change is made NOW: change `/etc/hostapd/hostapd.conf`, reboot, and RE-RUN this whole case (and T1) on the new plan.

**Expected.** No failure of function — both portals always serve eventually; any airtime/throughput degradation is RECORDED with numbers (sync seconds, portal-load seconds, observed RSSI), and the written channel plan follows §10.

**Result:** [ ] pass  [ ] degrade  [ ] fail  (date: ______, executor: ______)
**Notes:** ______________________________________________________________

## T7 — Power draw against the ~1 W target

**Goal.** The issue's power item: measure the node against the ~1 W continuous design target (`docs/hardware.md` §1) and fill the §9 measured-vs-expected table.

**Setup.** USB power meter between the supply/buck output and the Pi (or an INA219/INA260 shunt on the 5 V feed). Node provisioned and trimmed (the `raspberry/power/` measures active: HDMI off, LEDs off, Bluetooth disabled, `powersave` governor).

**Steps.**
1. **Idle, no clients:** node up, no associated stations (`hostapd_cli -i wlan0 all_sta` empty). Wait 2 min, record V, A, W.
2. **One client browsing:** a phone loads the portal and clicks through tabs; record the burst and the settle value.
3. **Sync burst:** a phone (or curl loop) pushes ~100 envelopes; record peak W and duration above idle.
4. **24 h average (if the session allows):** leave the meter logging a full day; else record the session average and mark the 24 h cell PENDING for a follow-up.
5. Fill `docs/hardware.md` §9 for THIS deployment (copy the numbers into the notes line below too). If the 24 h average exceeds ~200 mA @ 5 V (≈ 1 W): the finding is a defect row (severity depends on margin) and `docs/hardware.md` §2 must be re-run with the measured number.

| Phase | Expected (`docs/hardware.md` §9) | Measured (V / A / W) |
|---|---|---|
| Idle, trimmed, no clients | 80–150 mA @ 5 V | PENDING |
| One client browsing the portal | 200–400 mA @ 5 V (bursts) | PENDING |
| Sync burst (100-envelope push) | < 1 s above idle | PENDING |
| Session average | — | PENDING |
| 24 h average | ≤ 200 mA @ 5 V ≈ 1 W | PENDING |

**Result:** [ ] pass  [ ] degrade  [ ] fail  (date: ______, executor: ______)
**Notes:** ______________________________________________________________

## T8 — Quick-start guide validation with a first-time user (issue #23's deferred criterion)

**Goal.** A non-technical user completes registration → send → receive using ONLY the printed `docs/quick-start.md` (or `/guide`) — the #23 acceptance criterion that explicitly defers to this field test. The operator observes and stays silent unless safety is at risk.

**Setup.** One node, one first-time user (not on the project), one printed guide, one phone. A second device/identity prepared as the correspondent. A stopwatch.

**Steps.**
1. Hand over the paper guide and the phone. Start the clock. Say nothing unless the user is stuck > 10 min on one step (then record it as a guide defect, help minimally).
2. Observe the user through the guide's steps: join Wi-Fi → open the FULL browser → register → save the seed on paper → add the correspondent (QR or directory pick) → send a message → receive the reply (correspondent replies via the node) → notice the "Foreign envelopes in transit" panel.
3. Record: total time, per-step hesitations, every moment the guide was wrong/ambiguous/missing something, every word the user misread.
4. The user answers (out loud, recorded in notes): "What does the seed do?" and "What does the transit counter mean?" — the guide's job is that these are answerable.

**Expected.** Completion unaided within ~15 minutes, seed written down, message received; guide defects logged (they are follow-up issues against `docs/quick-start.md` / `/guide`, with quotes).

**Result:** [ ] pass  [ ] degrade  [ ] fail  (date: ______, executor: ______)
**Notes:** ______________________________________________________________

## T9 — Upgrade and rollback drill on hardware (issue #22 machinery, now on a real Pi)

**Goal.** Exercise `install.sh --upgrade` from the release USB kit over the real node — health gate included — then the (forced/hand-invoked) rollback drill, exactly as `docs/BUILD.md` §5 Path 4 and `docs/RUNBOOK.md` §4.8 prescribe. `tests/upgrade_e2e.sh` already runs this library rootlessly; this case proves it on the Pi.

**Setup.** A provisioned node (staging unit — do not run forced-failure drills on a deployed village node). The release USB kit mounted on the Pi (e.g. `/media/usb`). Pre-upgrade checklist per RUNBOOK §4.8: `/status` snapshot (build, envelopes count E), `systemctl status dtn-node` healthy, disk space for a backup generation.

**Steps.**
1. Record pre-state: build id + `envelopes` = E + `directory_entries` from `/api/v1/health`.
2. `sudo ./install.sh --upgrade --offline /media/usb --country <CC>` → read the `upgrade:` lines; the run must end `UPGRADE OK: build=<new id> schema_version=<n>`.
3. Verify: `/api/v1/health` serves the NEW build id, `envelopes` still E (zero loss), a mail push succeeds (write path alive), `ls /var/lib/dtn-node/backups/` shows the generation with `MANIFEST.txt`.
4. **Rollback drill:** `sudo ./install.sh --rollback` → the previous build is restored through the same gate; `/api/v1/health` serves the OLD build id; `envelopes` still E; portal serves.
5. (Staging only, optional deeper drill): run the upgrade with a deliberately broken bundle (truncated tarball) → the automatic rollback must fire on its own and end `upgrade aborted; the node was rolled back`, with the node healthy on the old release and `/var/lib/dtn-node/pre-restore-<UTC>/` evidence present.

**Expected.** Upgrade success ends in the documented `UPGRADE OK` verdict with the gate passing on build identity + schema; zero envelope loss at every phase; rollback restores the previous release cleanly.

**Result:** [ ] pass  [ ] degrade  [ ] fail  (date: ______, executor: ______)
**Notes:** ______________________________________________________________

## T10 — Operator status agreement during the walk

**Goal.** The issue's instrumentation item: `GET /status` and `GET /api/v1/health` agree with reality (envelope counts, counters, directory) during the T1 walk. The software half (counts vs pushes on real daemons) is asserted by `tests/field_equiv.mjs` §C; here it is checked by eye on hardware.

**Setup.** The T1 session. A laptop (or either phone's browser — `/status` renders with zero JavaScript on purpose) polling both nodes at each phase.

**Steps.** At each phase below, fetch on BOTH nodes involved: `/status` (human view) and `/api/v1/health` (JSON), and tick agreement:
1. **Before anything:** both nodes `status=ok`, `envelopes=0`, `directory_entries` matches who registered so far (0).
2. **After Alice's send:** node A `envelopes=1`, `counters.pushes_accepted` ≥ 1, `directory_entries=2`; node B untouched (`envelopes=0`).
3. **After the mule picks up (node A) and drops off (node B):** node B `envelopes` +1, `counters.pushes_accepted` +1; node A keeps its copy (store-and-forward — a pull does NOT delete).
4. **After Bob's pull:** node B `envelopes` unchanged (dead drop: envelopes expire via TTL/janitor, not on pull); both endpoints show the SAME snapshot values (they share one cached source) and `/status` HTML matches the JSON numbers.
5. Record any disagreement (e.g. counts off by more than the explained in-flight window, `/status` stale, values that contradict the physical event) as a defect row.

**Expected.** Both endpoints agree with each other and with the physical counts at every phase, within the documented semantics (store-and-forward, TTL expiry, RAM-only counters reset on restart).

**Result:** [ ] pass  [ ] degrade  [ ] fail  (date: ______, executor: ______)
**Notes:** ______________________________________________________________

---

## 12. Results matrices — PENDING, to be filled during the field session

**Verdict summary (one row per case).**

| Case | Verdict (pass/degrade/fail) | Date | Executor | Defect rows |
|---|---|---|---|---|
| T1 mule walk | PENDING | PENDING | PENDING | PENDING |
| T2 device matrix | PENDING | PENDING | PENDING | PENDING |
| T3 seed restore | PENDING | PENDING | PENDING | PENDING |
| T4 client isolation | PENDING | PENDING | PENDING | PENDING |
| T5 cold start | PENDING | PENDING | PENDING | PENDING |
| T6 coexistence | PENDING | PENDING | PENDING | PENDING |
| T7 power draw | PENDING | PENDING | PENDING | PENDING |
| T8 quick-start validation | PENDING | PENDING | PENDING | PENDING |
| T9 upgrade/rollback drill | PENDING | PENDING | PENDING | PENDING |
| T10 operator status | PENDING | PENDING | PENDING | PENDING |

**Device × browser × case detail.**

| Device | Browser | Cases run | Observations |
|---|---|---|---|
| Android: ______ | captive mini-browser | PENDING | PENDING |
| Android: ______ | Chrome (full) | PENDING | PENDING |
| iOS: ______ | captive mini-browser | PENDING | PENDING |
| iOS: ______ | Safari (full) | PENDING | PENDING |

## 13. Defect log

One row per deviation. Severity: **MVP-blocking** (blocks the #20 sign-off) or **follow-up** (recorded, scheduled). Link the GitHub issue created for each.

| ID | Case | Severity | Description | Issue link |
|---|---|---|---|---|
| — | — | — | *(empty — nothing observed yet; this table is filled only from real executions)* | — |

## 14. Sign-off — left EMPTY until the physical session happens

This block is intentionally blank. It is signed only by the people who executed the cases above on the hardware, after every Result line and matrix cell is filled.

- Session date: ______  Location: ______
- Node A (board / serial / build): ______  Node B (board / serial / build): ______
- Phones (model / OS): ______  Mule client: ______  Power meter model: ______
- Executed by (name / signature): ______
- Witnessed by (name / signature): ______
- Owner acceptance (name / signature / date): ______
- Issue #20 may be closed only when this section is signed and every case above has a verdict.
