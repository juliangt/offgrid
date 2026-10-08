# Field Acceptance Test — Protocol and Report (issue #20)

| | |
|---|---|
| **Status** | **PROTOCOL READY — EXECUTION PENDING.** This document was prepared as an executable protocol plus an empty report scaffold by an automated agent on 2026-10-05. Every result cell below is **PENDING** until a human executes it on real hardware. Nothing is pre-checked; no physical result in this file has been observed by anyone. |
| **Scope** | Issue #20: full-system acceptance on real hardware — two-node physical mule walk, real-device captive-portal matrix, seed backup/restore on a real device, client isolation, cold start, RF coexistence, power draw — plus the quick-start guide validation (#23), the upgrade/rollback drill (#22) and operator-status agreement (#31), exercised on a real Pi. Extended 2026-10-07 by issue #33 P3.9 with §15 — the Phase 3 node-plane session (cases N1–N14: bench radio tier, multi-hop field tier, solar repeater soak): protocol only, every result PENDING until executed on hardware. |
| **Rule of evidence** | A case passes only if the named observation was made on the named hardware on the recorded date, by the person who signs. Anything not observed stays PENDING. The software half of this issue (what IS verifiable without hardware) is automated as `tests/field_equiv.mjs` — run `make test`; it does NOT substitute for this session. |

## 0. How to run this session

1. Assemble the kit (`make field-kit` prints this checklist; see `docs/BUILD.md` §5 for the release USB kit).
2. Execute the cases in order T1 → T10 (T5/T7 need the power bench; they can run on a separate day).
3. After each case: fill its Result line and the results matrices in §12; add defect-log rows in §13 (one row per deviation, with a GitHub issue link).
4. Verdicts: **pass** (expected observation made), **degrade** (system worked, worse than documented — record numbers), **fail** (expected observation not made). Anything else is PENDING, not a pass.
5. Severity: **MVP-blocking** (the issue's own acceptance scope cannot be signed off without a fix) vs **follow-up** (recorded, scheduled, does not block #20).
6. When everything is filled: sign §14. Only the signed document closes issue #20.

The Phase 3 node-plane session (§15, issue #33 P3.9) is a SEPARATE session with its own kit (§15.2), its own results matrices (§15.6) and its own sign-off (§15.8); the T-cases and the N-cases do not gate each other. Its cases require the P3.3 hardware bring-up — read §15's boundary statement before planning it.

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

This table is the issue-#20 session's kit and stays as-is. The Phase 3 node-plane session does not extend it — its own prerequisites table is §15.2.

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

---

## 15. Phase 3 node-plane session — issue #33 P3.9 (protocol; execution pending)

**BOUNDARY — read this before planning anything else.** Every case in this section requires the **P3.3 hardware bring-up**: the sx126x register-level driver ported as a `dtn_radio` vtable implementation (`docs/node-network.md` §5.5 — the BSD LoRaMac-node port, unverifiable on the host), the ESP32 NVS persistence of the §6.2 sequence checkpoints and the node identity behind the landed `dtn_session_store` / `dtn_nodeid_store` seams, and the real UART under the §5.5 length prefix. Until that lands, the node-plane acceptance criteria are enforced by the **host suites** — the C host suite (`make test-esp32-core`, `esp32/components/dtn_core/host/run_tests.sh`), the three-daemon bash gate `tests/node_plane_e2e.sh`, and the Go integration tests (`node/internal/forward/integration_test.go`, `node/internal/mgmt/integration_test.go`, `node/internal/tcpcl/integration_test.go`, `node/internal/capsule/capsule_loopback_test.go`) — and **this section is the on-site execution protocol, NOT a claim of results.** Every Result line and every matrix cell below is PENDING; nothing here has been observed by anyone. The §0 rule of evidence applies unchanged, and the §0 verdict/severity vocabulary applies with one mapping: a defect here is **P3.9-blocking** (the issue-#33 P3.9 row cannot be signed without it) or **follow-up**.

### 15.1 Scope — the issue-#33 §4 acceptance items and their cases

| §4 acceptance item (issue #33) | Case(s) |
|---|---|
| Envelope injected at A reaches C through B (2-hop relay) byte-unmodified; same `id`, same TTL, no life extension; hop octet honored and capped | N6 |
| Passive capture reveals no plaintext mail, no plaintext management; replayed session frames rejected (persisted sequences) | N7 (field), N4 (bench) |
| A command signed below its required level is dropped and counted | N8 |
| A valid L3 role-cert lifecycle (issue → operate → revoke → observe island-wide) with no online server | N9 |
| An ESP32 firmware capsule crosses the plane, applies with gate+rollback intact; a stale capsule is refused over the network | N10 |
| A user registered only on A becomes composable from C via directory federation (§3.4 merge rules, SPA continuity identical) | N11 |
| Contact budgets bound a single peer's share; bulk never starves mail | N12, N13 |
| Original §1 ACs: multi-km crossing; lost-frame recovery; repeater full solar cycle | N6; N3; N14 |
| User-plane regression (`make test`, `tests/sync_e2e.sh`, `make chaos`) | NOT a field case — the host suites enforce it every phase (§15 boundary above; §11 row m of `docs/node-network.md`) |

Bench tier N1–N5 closes the P3.3 exit criteria on real radios; field tier N6–N13 and the soak N14 close the P3.9 row.

### 15.2 Prerequisites — the Phase 3 kit

| Item | Quantity | Notes |
|---|---|---|
| ESP32-S3 + SX1262 radio head (Heltec WiFi LoRa 32 V3 / LILYGO T3-S3 class, or discrete E22 module + S3 — the §12 decision-3 reference hardware of `docs/node-network.md`, §5.1) | 3 | two field units + the bench capture/replay spare (the §11 P3.3 boundary note's "extra units"); flashed with the node-plane firmware (relay/bridge variant) built per `docs/esp32-design.md` §5 |
| Coax attenuator kit (30–70 dB step) + U.FL/IPEX→SMA pigtails | 1 | the bench tier's loss control (N1–N5); the boards' PCB antennas are not connectorized — the pigtails are mandatory for the attenuator path |
| Pi bridge node, provisioned per `docs/BUILD.md` §5 with the node-plane flags (`-tcpcl*`, nodeid kit per `docs/node-network.md` §2.6) | 2 | rig = head + Pi; the §2.3 `bridge` role; the portal answers on each |
| Solar repeater kit per `docs/hardware.md` §2/§3 (20 W panel, LiFePO4 4S 12.8 V 10 Ah + BMS, controller with the LiFePO4 4S profile and low-temp charge cutoff, buck, fusing), assembled per `docs/install-node.md` §6 | 1 | the repeater R (the §2.3 `relay` role); head + power stack in one IP65+ box |
| Power instrumentation: INA219/INA260 shunt on the load feed (or the controller's telemetry) + a timestamped logger | 1 | N14's power log; `docs/hardware.md` §9 is the template |
| UART/USB serial adapter | 1 | head consoles on the bench; the N14 failure-capture convention |
| Phone with a recent browser (the portal) | 1 | N6's optional continuation leg, N11's compose check |
| Laptop with `capsuletool`, `sqlite3`, `curl` built per `docs/BUILD.md` §2 | 1 | injection, store assertions, ceremony driving |
| Identity kit from the §2.6 anchor ceremony: `anchor.seed` (air-gapped, travels ONLY to the N9 issue/revoke steps), node seeds + certs for A, C, the manager M (an L2 and an L1 cert), the flooding peer F, the fresh node X; `anchor.pub` pinned everywhere | 1 set | provisioned before leaving; `capsuletool rolecert verify` passes for every cert against the pinned anchor |
| Printed: this document (§15) and `docs/node-network.md` §5–§9 | 2 copies each | fill the paper copy, transcribe |
| Sites: A, B, C km-scale apart in a line (each leg ≥ 1 km, clear-ish path), B with open sky for the panel | — | record coordinates/distances in §15.8; no Internet needed anywhere |

Before starting: every head boots and beacons on its serial console; every rig's `/status` serves the `node_plane` member; `capsuletool rolecert verify --anchor-pub anchor/anchor.pub --in <cert>` passes for the whole cast; the bench rigs complete N1 before any field travel. Record in §15.8: date(s), location, head serials, firmware build ids, Pi build ids, anchor fingerprint (`SHA-256(anchor.pub)[0:8]`), meter model.

### 15.3 Bench tier — cases N1–N5 (one room + the attenuator)

**Shared bench setup.** Two heads (A-bench, B-bench) on USB power, serial consoles open, on the node-plane channel profile: sync word `0x2F4F`, SF7 / BW125, 915 MHz (`docs/node-network.md` §5.1). The rigs (Pi + head) where a case needs stores or injection; heads alone where it needs only the radio. The 222 B frame is ≈ 348 ms of airtime at SF7/BW125 (§5.3) — keep bench transmissions sparse and respect the duty budget even on the bench.

### N1 — Bench handshake: session established, link margin measured, fail-closed below it

**Goal.** Two units establish a §6.1 link session over the air; the attenuator finds the link margin; below it the link degrades to beacons only and carries nothing (fail-closed).

**Setup.** Two heads, back-to-back (~2 m) first. Attenuator in the path of one head's pigtail (or physical separation into other rooms when the pigtail path is not wired).

**Steps.**
1. Back-to-back: power both. Consoles show beacons (type 0, plaintext, `beacon_version=1 ‖ fingerprint(8)` — §5.4's beacon content, nothing else) and then the CAD-driven handshake: msg1 38 B, msg2 134 B, msg3 91 B — one frame each (§6.1). Record RSSI/SNR and that a session was established.
2. Insert 30 dB attenuation (or move to another room): the session re-establishes. Step in 10 dB increments to the failure point. Record the last-good setting — **the link-margin datum** for the field tier.
3. One step beyond the last-good setting: record what the link carries. Expected: beacons only; handshake attempts fail closed; no session, no payload (§6.1's rule — links without a verified session carry nothing but beacons).
4. Record any handshake that ever completed with corrupted bytes (must be zero — the AEAD and the transcript check fail closed).

**Expected.** Session established down to the recorded margin; below it beacons only; zero corrupted-session completions.

**Result:** [ ] pass  [ ] degrade  [ ] fail  (date: ______, executor: ______)
**Notes:** ______________________________________________________________

### N2 — A mail envelope crosses the bench link byte-unmodified (the §1 AC at bench scale)

**Goal.** The original §1 acceptance criterion's transport half: a mail bundle injected at rig A arrives at rig B byte-unmodified — same `bundle_id`, same payload bytes, same lifetime (no life extension).

**Setup.** Full rigs (Pi bridge + head each) through N1's last-good attenuator setting. Laptop with `capsuletool` and `sqlite3`. The bundle store is the `-tcpcl-store` SQLite file (on a provisioned rig: `/var/lib/dtn-node/node_storage_bundles.db`).

**Steps.**
1. Mint the cargo on the laptop: `capsuletool bundle make --out cargo.pdu --payload-text "bench crossing <TOKEN> <DATE>"` → record the printed `bundle_id=` and `shasum -a 256 cargo.pdu`. (The bench mints the anonymous P-4 mail bundle directly; the byte-fidelity claim here is about the transport — exactly what `tests/node_plane_e2e.sh` asserts host-side with the same tool.)
2. Inject at rig A over its Wi-Fi/loopback TCPCL: `capsuletool bundle send --host <A>:<tcpcl-port> --pdu cargo.pdu --seed nodeA/node.seed --pins pins` (one-shot contact, TOFU pin).
3. Confirm A's store: `sqlite3 <A store> "SELECT hop, lifetime, lower(hex(pdu)) FROM bundles WHERE bundle_id='<id>';"` → hop 0; record the hex.
4. Let the LoRa leg run (A's head ↔ B's head within the beacon/contact discipline). Then confirm B's store with the same query: hop 1; the hex equals A's with ONLY the first (hop) byte changed 0→1; the bytes after the hop octet are byte-identical to `cargo.pdu`; `lifetime` and the creation timestamp are identical to A's row — no life extension.
5. Optional margin check: repeat once at 6 dB beyond the last-good setting; record whether fidelity held.

**Expected.** Same `bundle_id` in both stores; hop 0→1; payload bytes byte-identical; creation/lifetime identical.

**Result:** [ ] pass  [ ] degrade  [ ] fail  (date: ______, executor: ______)
**Notes:** ______________________________________________________________

### N3 — A lost frame window does not corrupt sibling bundles

**Goal.** The §1 original AC's loss half: a window that loses a frame is dropped as a partial and expires with the bundle's TTL; bundles in flight around it are untouched (§5.4's window rules — a lost frame never corrupts sibling windows; the MAC has NO retransmit by design).

**Setup.** The N2 rigs driven at a deliberately marginal link (1–2 steps above N1's failure point) so real frame loss occurs, or the attenuator stepped across the threshold during the contact. Three cargo bundles with distinct payload texts, small enough that all three ride one contact within the §7.4 mail budget (≤ 64 frames per LoRa contact).

**Steps.**
1. Inject bundles K1, K2, K3 back-to-back at A in one contact window (N2's mechanism).
2. Record the loss actually observed (from the consoles: which window lost frames — the MAC's CAD/backoff and the marginal link provide the loss; nothing is scripted).
3. Let the epidemic sync redeliver on the NEXT contact (loss costs delay only — store-and-forward, §7).
4. After convergence: all three bundles present at B, each passing N2's byte-fidelity check; B's store holds ONLY complete, profile-valid rows — a partial window left no residue row, no garbage bundle, and no corruption inside the sibling windows that shared the contact.
5. Record the counters (the §10.7 RAM-only drop/partial classes) from B's `/status`.

**Expected.** The lost window's bundle simply arrives on a later contact, byte-identical; siblings never corrupted; the partial expired silently and was counted.

**Result:** [ ] pass  [ ] degrade  [ ] fail  (date: ______, executor: ______)
**Notes:** ______________________________________________________________

### N4 — A replayed session frame is rejected (persisted sequence numbers)

**Goal.** §6.2's replay discipline observed on real air: a verbatim retransmission of a recorded session frame is dropped + counted; a restart never rewinds the replay window.

**Setup.** The third head flashed with the bench capture/replay firmware (the P3.3 harness's sniffer build): it records raw on-air frames and retransmits one verbatim on command. It cannot decrypt anything — record that its captures show only header/nonce/ciphertext/tag.

**Steps.**
1. Run a normal session A↔B carrying a bundle (N2's cargo) while the capture head records the on-air frames.
2. Command the capture head to retransmit one recorded session frame VERBATIM (same nonce, same tag — a true replay). B's console/counters: the frame is dropped and counted (the §6.2 replay-window drop class); the session continues; A's subsequent frames are still accepted.
3. Optional one-byte probe: replay a frame with one ciphertext byte flipped → AEAD verification fails closed, same drop class, no state disturbance.
4. **Restart leg:** power-cycle B mid-session. After reboot B rejoins and A's frames (sequence advanced) are accepted: the sender resumed at last-persisted + 32 and B's replay window (≥ 32) absorbed the gap (§6.2). Then replay a PRE-restart recorded frame: dropped + counted. B must never accept a pre-restart sequence again.
5. Record every drop in the counters and every acceptance in the contact log.

**Expected.** Every replay (verbatim or corrupted) dropped + counted, zero state disturbance; the session survived the restart with no replay-window rewind; no sequence ever accepted twice.

**Result:** [ ] pass  [ ] degrade  [ ] fail  (date: ______, executor: ______)
**Notes:** ______________________________________________________________

### N5 — Profile separation: the node plane and the (future) §14.3 user/mail profile never hear each other

**Goal.** Decision 4 of `docs/node-network.md` §12 observed on hardware: the node-plane frame grammar and the future §14.3 user/mail radio grammar never share a carrier and never parse each other's bytes (§5.1 — separate sync word + SF/BW).

**Steps (two stages, honestly).**
1. **Stage 1 — now (the §14.3 user/mail radio profile does not exist yet).** Record the pins from the firmware config on every unit: sync word `0x2F4F`, SF7/BW125, and the §5.4 fail-closed frame gates (version ≠ 1, type 4–7, flags ≠ 0 all refuse to parse). Feed a deliberately malformed frame to a bench receiver via the capture head: refused + counted, no state change.
2. **Stage 2 — when the §14.3 user/mail radio profile lands (a later issue's hardware).** Re-run this case with BOTH profiles active in the same room, traffic flowing on both: a node-plane unit must show zero parses of user-profile frames and vice versa (each radio hears only its own sync word); neither side's counters move for the other's traffic.
3. Until stage 2 is runnable, record this case's verdict from stage 1 alone and write "stage 2 re-run pending <issue>" in the notes. Never mark the coexistence half as observed before it ran.

**Expected.** Stage 1: pins recorded, malformed frames fail closed. Stage 2 (when runnable): total carrier isolation in both directions.

**Result:** [ ] pass  [ ] degrade  [ ] fail  (date: ______, executor: ______)
**Notes:** ______________________________________________________________

### 15.4 Field tier — cases N6–N13 (multi-hop A→B→C over km-scale links)

**Shared field setup.** Sites A, B, C km-scale apart in a line. **B is the solar repeater R** (the `relay` role, §2.3 — store-and-forward only, duty-cycled, no portal). **A and C are bridge rigs** (portal + radio head each, Wi-Fi up locally). The island's identity is provisioned; TOFU pins recorded at first contact; quiet hours off for the session. N1's link margin and N4's replay discipline are the calibration behind every case here. Contacts between rigs happen when the repeater's wake windows align (§5.3) — waiting is the DTN working as designed; record the waits.

### N6 — 2-hop relay: A → B → C byte-unmodified, hop octet 0 → 2, across km-scale legs

**Goal.** The §4 AC: an envelope injected at A reaches C through B byte-unmodified — same `id`, same TTL, no life extension; the hop octet honored (0→1→2). This is also the §1 original multi-km crossing.

**Steps.**
1. At A: mint the cargo — `capsuletool bundle make --out km.pdu --payload-text "field km <TOKEN>" --ttl 604800` → record `bundle_id=`, the payload sha256, the ttl.
2. Inject: `capsuletool bundle send --host <A>:<tcpcl-port> --pdu km.pdu --seed nodeA/node.seed --pins pins`. A's store: the hop-0 row (N2's query). Record the inject time.
3. Wait for the A↔B contact (repeater wake window). B's store: hop 1, same `bundle_id`. Record the contact time and both heads' RSSI/SNR. Wait for B↔C. C's store: hop 2, same `bundle_id`; the `pdu` hex equals A's with only the hop byte 0→2; `lifetime` and creation identical. Record the contact time.
4. Record the full timeline (inject → A→B contact → B→C contact), the leg distances, and the radio characterizations — this is the field record the byte math of §5.3 stands on.
5. Optional (best-effort, not gating — the §1 original AC's continuation into the Wi-Fi/mule network): a phone on C's portal pulls the message (the bridge's plane-translation delivery, §2.3's bridge leg). Record what actually happened; if that delivery path is not live in the firmware at session time, record the leg PENDING with C's store evidence from step 3 — the verdict rests on steps 1–4, never on the assumption.

**Expected.** Same `bundle_id` at all three stores; hop exactly 0→1→2; payload bytes byte-identical; creation/lifetime identical; both km legs crossed through the repeater with no operator action beyond waiting for contacts.

**Result:** [ ] pass  [ ] degrade  [ ] fail  (date: ______, executor: ______)
**Notes:** ______________________________________________________________

### N7 — Passive capture of the node-plane radio

**Goal.** The §4 AC: a passive capture reveals no plaintext mail and no plaintext management commands; replayed session frames are rejected under field conditions (N4's method, field link).

**Setup.** The capture head at a location that hears the A↔B or B↔C link, recording for the duration of a window in which (a) a mail bundle crosses (N6's or a fresh one) and (b) a management command executes (N8/N9's cargo). The capturing laptop greps the recordings afterward.

**Steps.**
1. Capture the window(s) containing both cargo classes.
2. Search the capture for: the mail payload text and its sha256; every command name used (`set_store_cap`, `set_budgets`, `federation_on`, `install_cert`, …); aliases; EID strings beyond the 8-byte beacon fingerprints. ALL must be absent — the capture may contain only link headers, the handshake's public parts, nonces, ciphertext, tags, and beacons (`beacon_version=1 ‖ fingerprint(8)`, §5.4).
3. Prove processing happened anyway: the executing nodes' `/status` (`node_plane` member, the §10.7 aggregate counters) ticked for both cargo classes WHILE the capture stayed clean.
4. Optional: N4's replay probe against the field link — dropped + counted.

**Expected.** Zero plaintext of either class in the capture; zero EID leakage beyond beacon fingerprints; processing provably happened; any replay probe dropped + counted.

**Result:** [ ] pass  [ ] degrade  [ ] fail  (date: ______, executor: ______)
**Notes:** ______________________________________________________________

### N8 — A command signed below its required level is dropped and counted

**Goal.** The §4 AC's enforcement half: an L1-signed L2 command never executes anywhere, and the refusal is silent — counted, never answered (the §13.6 refusal-to-confirm pattern, §8.2).

**Setup.** The manager M carries an **L1** cert (issue it at the anchor ceremony with `--level 1`). The target is node C. A control signer with an L2 cert exists for step 4.

**Steps.**
1. Sign the below-level command: `capsuletool admin sign --seed nodeM/node.seed --cmd set_store_cap --args '{"cap":4000}' --target <C's EID> --seq 1 --out below.pdu`.
2. Inject at A (N6's mechanism); the epidemic sync carries it toward C.
3. On C: the command NEVER executes — `/status` → `node_plane` counters: `dropped_bylevel` incremented, `commands_accepted` unchanged, and NO reply bundle appears anywhere on the plane (A and B's stores carry no reply cargo).
4. Control: the same command signed by the L2 signer executes — `commands_accepted` increments and the cap actually changes (visible in the `node_plane` status member). This proves the step-3 refusal was the level gate, not broken plumbing.
5. Restore the cap with the L2 signer afterwards.

**Expected.** Below-level: silent drop + `dropped_bylevel`, no reply, no state change. The L2 control executes normally.

**Result:** [ ] pass  [ ] degrade  [ ] fail  (date: ______, executor: ______)
**Notes:** ______________________________________________________________

### N9 — The L3 ceremony island-wide: issue → operate → revoke, no online server

**Goal.** The §4 AC's lifecycle half: a full role-cert lifecycle (issue → operate → revoke → observe revocation via seq bump) works across the island with the anchor OFFLINE except at the two signing moments, and zero online infrastructure (§2.5 rule 4 + the §8.5 sink propagation).

**Steps.**
1. **Issue (offline, air-gapped):** `capsuletool rolecert keygen --out nodeX/`; `capsuletool rolecert sign --anchor-seed anchor/anchor.seed --node-pub nodeX/node.pub --roles manager --level 2 --seq 1 --out nodeX/node_cert.cbor`; `capsuletool rolecert verify --anchor-pub anchor/anchor.pub --in nodeX/node_cert.cbor`. The anchor machine goes back in its bag.
2. **Distribute:** `capsuletool admin sign --seed <an L3 or the provisioning manager>/node.seed --cmd install_cert --args '{"cert":"<base64 of nodeX/node_cert.cbor>"}' --target "" --seq <next>` — inject at A; the §8.5 sink + §7.1 epidemic sync distributes the cert island-wide (B and C merge it by the §2.5 seq rules; record `rolecert_conflicts` = 0 everywhere).
3. **Operate:** X signs a valid L2 command (`set_budgets`) and injects it at A — it executes at the target (record `commands_accepted`).
4. **Revoke (offline again):** the anchor signs X's cert at `--seq 2 --roles none --level 0` (the §2.5 rule-4 revocation record); distribute it the SAME way (a bare cert or `install_cert`).
5. **Observe island-wide:** X's next command is dropped + counted (`dropped_sig` — revoked signer) on EVERY node it reaches; no reply anywhere. The revocation crossed the whole island through the epidemic plane with no server and no mule.
6. Record the sequence numbers observed in each node's status (seq 1 accepted, seq 2 revoked) and the conflict counters (stay 0).

**Expected.** Full lifecycle with the anchor touched twice, offline; revocation observable island-wide via the seq bump; the revoked node keeps forwarding mail (harmless, opaque — §2.5 rule 4) but holds no authority anywhere.

**Result:** [ ] pass  [ ] degrade  [ ] fail  (date: ______, executor: ______)
**Notes:** ______________________________________________________________

### N10 — An ESP32 capsule crosses the plane; the stale capsule is refused

**Goal.** The §4 AC: a capsule crosses the node plane and lands byte-exact in the staging path with the #37/#22 gate+rollback semantics intact; an old (anti-rollback) capsule is refused over the network exactly as over Wi-Fi staging (§9.1/§9.4 of `docs/node-network.md`).

**Setup.** `capsuletool` with the release kit's `release.seed`/`release.pub`; a synthetic blob for the functional crossing and (optionally) the real `dtn-node-esp32s3.bin` from `make firmware-merge` (~1.5 MB) for the bandwidth datum; updates policy ON at the receiving bridge C (the `-tcpcl-updates*` admission policy); the T9 drill machinery available for the apply leg.

**Steps.**
1. Sign: `capsuletool capsule sign --priv release/release.seed --arch esp32s3 --release <NEXT> --semver <tag> --bin firmware.bin --out update.capsule`; `capsuletool capsule verify --pub release/release.pub --in update.capsule`; record sha256 + the `capsuletool capsule show` fingerprint.
2. **Functional crossing (same-day):** sign a tiny capsule (`--payload-text`, a few chunks) and send it to C over the plane (injection at A, the chunk transport rides toward C per §9.4 — 200 B chunks on LoRa, 64 KiB on TCPCL). At C: reassembly completes; the byte-exact capsule lands staged at `/var/lib/dtn-node/staged/update.capsule` (sha256 = step 1); zero `tmp` residue in the staging dir.
3. **Bandwidth datum (overnight, optional but valuable):** the full-size image rides the LoRa contacts A→B→C while the session sleeps elsewhere; record elapsed time against the §9.2 accounting (1.5 MB ≈ 58 min continuous at SF7, ~10 h at a 10 % duty budget). Record the actuals in the notes.
4. **Apply leg:** apply stays the operator-gated #22 path (§9.4's deliberate NOT-in-v1 of auto-apply): run the T9-style upgrade against the staged capsule — health gate on, automatic rollback intact. If an ESP32 receiver with the OTA A/B bring-up is in the island, record its apply + health gate + rollback as the second receiver form; if not, record which receiver form executed (honestly).
5. **Stale refusal:** sign a capsule at `--release <OLDER>` (below the anti-rollback floor) and send it again. C consumes + counts it (the Stale counter — the §9.4 refusal mapping: no error packets) and NEVER stages it; the step-2 staged file is untouched; `capsuletool capsule verify` on the staged file still passes.

**Expected.** Byte-exact staging; apply through the documented gate+rollback machinery on the receiver form that ran; the stale capsule refused exactly as the Wi-Fi staging path refuses it — silently, counted, never staged.

**Result:** [ ] pass  [ ] degrade  [ ] fail  (date: ______, executor: ______)
**Notes:** ______________________________________________________________

### N11 — Directory federation: registered only on A, composable from C

**Goal.** The §4 AC: a user registered ONLY on node A becomes composable from node C via node-plane directory federation, with the §3.4 merge rules and the SPA continuity warnings behaving identically (§9.3 of `docs/node-network.md`).

**Setup.** Federation policy ON at the island (`federation_on` via the L2 command, or the boot flag); a fresh user identity U registered at A's portal with its signed card stored (the §3.2 registration hook — the portal mints the card at registration; no operator action).

**Steps.**
1. On A's portal: register U (alias + seed on paper, the T1/T3 discipline).
2. A's store: the card rides as a `dtn://og-dir/` bundle (bulk class, 7-day lifetime); record its presence and A's `federation_accepted` counter.
3. Wait for the epidemic sync A→B→C (the N6 contact discipline; record the waits).
4. On C: `curl -s -H 'Host: offgrid.local:8080' http://<C-IP>:8080/api/v1/directory` lists U — same alias, same keys, indistinguishable from a locally registered row (§9.3's property). Record C's `federation_accepted` (and that `federation_conflicts` stayed 0).
5. From a phone on C's portal: open Compose and select U (or address the QR-equivalent path) — the compose flow and its continuity warnings must behave exactly as they do for a locally registered contact. Record what the UI showed.
6. The crafted merge-rule probes (equal-seq byte-conflict attack signal, lower-seq stale drop) are HOST assertions (`docs/node-network.md` §11 row k, `tests/vectors/directory/`) — on site, record the organic counters only; do not hand-craft cards in the field.

**Expected.** U registered only at A is selectable and composable from C with no mule and no operator; the row is indistinguishable on the wire and in the directory; the counters show the federation path with zero conflicts.

**Result:** [ ] pass  [ ] degrade  [ ] fail  (date: ______, executor: ______)
**Notes:** ______________________________________________________________

### N12 — A contact budget bounds a flooding peer

**Goal.** The §4 AC's bound half: any single peer's share of airtime/storage is bounded by the §7.4 contact budgets — enforced, observable, and non-destructive to the rest of the island.

**Setup.** A FOURTH rig F (your own hardware — never a stranger's node) provisioned as `edge`, configured to generate bulk filler bundles far beyond the §7.4 budget against C.

**Steps.**
1. F floods C: inject filler bulk bundles continuously across several contacts.
2. Observe C across the flood: ingress beyond the contact budget is refused (the §7.4 gate — refuse-then-defer, never an unbounded receive); the refusals are counted (the budget counters of the `node_plane` status member); C's store stays within its cap; no memory growth.
3. The island's OTHER traffic is unaffected during the flood: an A→C mail bundle (N2/N6's mechanism) still crosses within its own contact window while F is being bounded.
4. The session with F survives the bound (graceful — §6.1/§6.3: bounded, not banned). Record frames/bytes transferred vs refused for F, and the mail window's completion time from step 3.

**Expected.** F's share never exceeds the configured budget; the flood is refused + counted; the rest of the island's traffic completes normally; the session ends cleanly.

**Result:** [ ] pass  [ ] degrade  [ ] fail  (date: ______, executor: ______)
**Notes:** ______________________________________________________________

### N13 — Bulk update traffic never starves mail

**Goal.** The §4 AC's priority half: with a bulk transfer in flight, mail still crosses within its own window — management > mail > bulk as the LOCAL queue discipline (§7.3), and on LoRa bulk rides only while the mail queue is empty (§7.4 row 2).

**Setup.** A bulk stream toward C in flight (N10's overnight capsule or N12's filler). A small mail bundle at A for C, injected mid-stream.

**Steps.**
1. Start the bulk stream toward C; confirm chunks are flowing (C's store/class counters).
2. Mid-stream, inject one small mail bundle at A (N2's mechanism).
3. Observe: the mail bundle leaves A within the current window — the bulk defers and resumes after (record the ordering from the store `received_at` rows and the counters; on LoRa the observable is that the mail window completed while the bulk contact was deferred to its next window).
4. Confirm the bulk stream completed afterwards (or continued honestly within budgets) and no wire-level reordering anomaly was observable to any peer — queue discipline is local and invisible on the wire by design (§7.3).

**Expected.** Mail crosses in one window despite the bulk backlog; bulk resumes after; no peer-observable reordering artifact.

**Result:** [ ] pass  [ ] degrade  [ ] fail  (date: ______, executor: ______)
**Notes:** ______________________________________________________________

### 15.5 Solar repeater soak — case N14 (72 h, unattended)

### N14 — 72 h solar soak of the repeater (the §1 original full-cycle AC)

**Goal.** The repeater R runs unattended on solar for 72 h through the §5.3 wake/beacon cadence, survives the full charge/discharge cycle, and resumes sessions from persisted sequence state — no replay-window rewind — with the power log archived as evidence.

**Setup.** R assembled per `docs/install-node.md` §6 and mounted per `docs/hardware.md` §6 (panel tilt/orientation, battery shaded, glands + drip loops). Power instrumentation logging from before boot: INA219/INA260 on the load feed (or the controller's telemetry), timestamped. A peer rig (the field A) within km-range for contact logging. Bench pre-checks per `docs/hardware.md` §4/§7: controller shows the 4S LiFePO4 profile, buck 5.1 V ± 0.1 V verified BEFORE the head is connected, low-temp charge cutoff confirmed if the site can see ≤ 0 °C.

**Steps.**
1. Pre-soak: battery full; R boots unattended (watchdog + brownout config live per the ESP32 bring-up); beacons on the §5.3 cadence (CAD listen period ≤ 5 s — a 128 ms CAD every 2 s ≈ 6 % RX duty is the v1 envelope). Record the configured cadence from the firmware config — this is the field-tuning datum §5.3 defers to P3.9.
2. Start BOTH logs and leave: the power log (V/A at battery and load) and A's contact log (windows heard, sessions established, bundles crossed — trickle one small mail bundle per contact to keep the §6.2 sequence checkpoints advancing).
3. Leave BOTH strictly unattended for 72 h covering ≥ 2 full nights (charge days / discharge nights). No remote saves, no reboots, no interventions.
4. Optional honest stress: cover the panel for one afternoon to force a deeper discharge cycle; record it in the notes.
5. Read-only checks during the soak (from the logs, never touching R): overnight state of charge never under 30 % (`docs/hardware.md` §8's floor); daytime net-positive charge by evening.
6. Post-soak: R is alive and serving; the contact log shows sessions resumed after every sleep/restart; cross-check with N4's method that no frame from before any restart was ever accepted — the sender resumed at last-persisted + 32 and the receiver's window absorbed the gap (§6.2). No replay-window rewind, ever.
7. Fill the repeater's rows of the `docs/hardware.md` §9-style table from the power log (idle/wake-window/TX-burst averages; the 72 h Ah figure) and archive the log with this report.
8. **Failure-capture convention:** if R dies or hangs at ANY point — do NOT reboot blindly. Photograph the rig and the controller LEDs; pull the power log around the failure minute; capture the serial console (the UART adapter) and any coredump the bring-up provides; record the exact timestamp, weather, and the last successful contact. Only THEN recover, and open a §15.7 defect row with severity by cause (a power-cause death that the sizing should have survived is P3.9-blocking; a single unexplained hang with clean evidence is at least follow-up with the log attached).

**Expected.** 72 h unattended, zero operator saves; SoC never under the 30 % floor; every session resumed from persisted state with no replay rewind; the power log archived and the §9-style rows filled; the observed cadence recorded for the §5.3 field tuning.

**Result:** [ ] pass  [ ] degrade  [ ] fail  (date: ______, executor: ______)
**Notes:** ______________________________________________________________

### 15.6 Results matrices — PENDING, to be filled during the Phase 3 session

**Verdict summary (one row per case).**

| Case | Verdict (pass/degrade/fail) | Date | Executor | Defect rows |
|---|---|---|---|---|
| N1 bench handshake + link margin | PENDING | PENDING | PENDING | PENDING |
| N2 bench envelope byte-unmodified | PENDING | PENDING | PENDING | PENDING |
| N3 lost-frame isolation | PENDING | PENDING | PENDING | PENDING |
| N4 replay rejected + restart resume | PENDING | PENDING | PENDING | PENDING |
| N5 profile separation | PENDING | PENDING | PENDING | PENDING |
| N6 2-hop km relay (A→B→C) | PENDING | PENDING | PENDING | PENDING |
| N7 passive capture clean | PENDING | PENDING | PENDING | PENDING |
| N8 below-level drop | PENDING | PENDING | PENDING | PENDING |
| N9 L3 lifecycle island-wide | PENDING | PENDING | PENDING | PENDING |
| N10 capsule crossing + stale refusal | PENDING | PENDING | PENDING | PENDING |
| N11 directory composable from C | PENDING | PENDING | PENDING | PENDING |
| N12 contact budget bound | PENDING | PENDING | PENDING | PENDING |
| N13 mail not starved by bulk | PENDING | PENDING | PENDING | PENDING |
| N14 72 h solar soak | PENDING | PENDING | PENDING | PENDING |

**Measured data the report owes the spec (fill from the notes/logs).**

| Datum | Case | Measured |
|---|---|---|
| Bench link margin (last-good attenuation / RSSI / SNR) | N1 | PENDING |
| A→B and B→C contact latencies + RSSI/SNR (km legs) | N6 | PENDING |
| Capsule crossing elapsed time (vs the §9.2 accounting) | N10 | PENDING |
| Repeater wake-window cadence as deployed | N14 | PENDING |
| Repeater 72 h energy figures (Ah, overnight SoC minimum) | N14 | PENDING |

### 15.7 Defect log (Phase 3 session)

One row per deviation, §13's discipline with the P3.9 severity mapping (see the boundary statement): **P3.9-blocking** (the issue-#33 P3.9 row cannot be signed without a fix) or **follow-up** (recorded, scheduled). Link the GitHub issue created for each.

| ID | Case | Severity | Description | Issue link |
|---|---|---|---|---|
| — | — | — | *(empty — nothing observed yet; this table is filled only from real executions)* | — |

### 15.8 Sign-off — left EMPTY until the Phase 3 physical session happens

This block is intentionally blank. It is signed only by the people who executed the cases above on the hardware, after every Result line and matrix cell is filled.

- Session date(s): ______  Location(s) / site distances: ______
- Radio heads (board / serial / firmware build): A ______  B ______  capture/replay unit ______
- Bridge rigs (Pi serial / build): A ______  C ______  Repeater R (head serial / power-stack BOM): ______
- Anchor fingerprint (first 8 bytes of SHA-256 of the pinned anchor public key): ______
- Meter / shunt model, power-log file reference: ______
- Executed by (name / signature): ______
- Witnessed by (name / signature): ______
- Owner acceptance (name / signature / date): ______
- The issue-#33 P3.9 row may be closed only when this section is signed and every case above has a verdict.
