# Hardware Guide — Solar-Powered DTN Node (Raspberry Pi Zero W or newer)

Power budget, sizing math, wiring, parts and assembly for one fixed node. The software side of a node is documented in `docs/BUILD.md`; the radio/network configuration lives in `raspberry/` (`hostapd`, `dnsmasq`, firewall, `provision.sh`). The power-trim measures referenced here (HDMI off, LEDs off, Bluetooth disabled, `powersave` governor) are already applied by `raspberry/power/` and `provision.sh`. Which board model to pick, and the per-model power/performance notes, are in `docs/pi-models.md` — the baseline is the Pi Zero W, and every figure below holds for it (it idles slightly below the Zero 2 W).

Building your first node end to end? This file is the sizing reference, not a tutorial. The step-by-step companion — component shopping with budget tiers, battery and panel choices in plain language, bench assembly and per-environment deployment (forest, mountain, desert, coastal) — is [`docs/install-node.md`](install-node.md), which links back here for every calculation it uses.

## 1. Design target: ~1 W continuous

After the power trim, the node is designed around a **1 W continuous electrical load** at the Pi (5 V × ~200 mA average, dominated by the Wi-Fi radio beaconing in AP mode plus the Go daemon, which idles at negligible CPU on a Zero W or Zero 2 W). Everything in this guide sizes the energy system so the load never browns out, including through multi-day overcast weather. Larger boards (Pi 3/4/5) run the same node at a higher idle draw — feed the measured number into §2 instead of 1 W if you deploy one.

## 2. Sizing math (worked example)

### 2.1 Daily energy

```
E_load   = 1.0 W × 24 h                       = 24.0 Wh/day   (at the Pi)
E_batt   = E_load / η_buck                    = 24.0 / 0.90   = 26.7 Wh/day (drawn from the battery)
E_design = ROUND UP                           = 28   Wh/day   (adds cabling/measurement margin)
```

`η_buck ≈ 0.90` is the 12.8 V → 5 V converter efficiency at a light load; charge-controller and wiring losses are covered by the round-up.

### 2.2 Battery capacity (LiFePO4)

```
Wh_batt = E_design × autonomy_days / DoD
        = 28 Wh × 3 days / 0.80               = 105 Wh
```

- **autonomy_days = 3** — bridges the longest typical overcast spell at the deployment latitude; increase to 4–5 for cloudy maritime climates (and re-check the panel below).
- **DoD = 0.80** — LiFePO4 tolerates deep discharge, but stopping at 20% remaining roughly doubles cycle life.
- **Recommended pack: LiFePO4 4S, 12.8 V nominal, 10 Ah = 128 Wh** (~18% margin over 105 Wh). A 4S (12.8 V) pack keeps the Pi fed through a simple high-efficiency buck; a single 3.2 V cell would require a boost converter instead and 40 Ah cells to reach the same Wh.

### 2.3 Solar panel

```
W_panel = E_design / (PSH_worst_month × derate)
        = 28 Wh / (3.5 h × 0.75)              = 10.7 W  → choose 20 W
```

- **PSH_worst_month** = peak-sun-hours of the WORST month at the site (look it up for your coordinates — e.g. Global Solar Atlas or NASA POWER; 3.5 h is a temperate-latitude winter example; tropical sites see 4–5, high latitudes can drop below 1).
- **derate = 0.75** — soiling, temperature coefficient, controller/wiring losses and panel aging combined.
- **20 W** gives ~2× headroom over the computed 10.7 W: it lets the battery recover to full within one sunny day even after a cloudy streak, and compensates for flat-ish mounting. Take the nearest standard size ≥ the computed value with this margin.

## 3. Recommended bill of materials

| Item | Spec | Notes |
|---|---|---|
| Solar panel | 20 W, 12 V nominal, Voc < 25 V | Rigid panel with MC4 or solder tails; mount facing the worst-month sun |
| Battery | LiFePO4 4S 12.8 V 10 Ah (128 Wh) with integrated BMS | Never substitute Li-ion without redoing §2.2 (energy density vs DoD and cold behavior differ) |
| Charge controller | PWM or small MPPT with an explicit **LiFePO4 4S profile and low-temperature charge cutoff** | The low-temp cutoff is mandatory if the site can see ≤ 0 °C (see §7) |
| Buck converter | 12.8 V → 5 V, ≥ 3 A, low quiescent current (< 1 mA) | Powers the Pi via USB-C cable or the 5 V/GND GPIO pins |
| Fuse + holders | 2 A inline fuse on the LOAD output | Sized for the buck input current with margin |
| Cabling | 18 AWG for battery/panel runs under 2 m | MC4 pairs or soldered + heatshrink; no crimp-only joints |
| MicroSD | **Industrial / high-endurance**, 8–16 GB is plenty | See §6 for the WAL write-amp rationale |
| Enclosure | IP65+ UV-stable box with cable glands | See §7 |
| (Optional) | INA219/INA260 or a USB power meter | To fill in the §9 measurement table |

## 4. Wiring diagram

```
        ┌──────────────┐         ┌────────────────────────────┐         ┌───────────────────────┐
        │ Solar panel  │         │ Charge controller          │         │ Battery               │
        │ 20 W, 12 V   │         │ (LiFePO4 4S profile,       │         │ LiFePO4 4S 12.8 V     │
        │              │         │  low-temp charge cutoff)   │         │ 10 Ah (128 Wh) + BMS  │
        │        (+) ──┼────────►│ PV+                BAT+ ◄──┼─────────┤ (+) via 15 A fuse     │
        │        (−) ──┼────────►│ PV−                BAT− ◄──┼─────────┤ (−)                   │
        └──────────────┘         │                            │         └───────────────────────┘
                                 │              LOAD+ ────────┼──►[2 A fuse]──┐
                                 │              LOAD− ────────┼──►────────────┤
                                 └────────────────────────────┘               │
                                                                              ▼
                                                    ┌──────────────────┐   ┌──────────────────────┐
                                                    │ Buck converter   │   │ Raspberry Pi         │
                                                    │ 12.8 V → 5 V/3A  ├──►│ 5V (pin 2) + GND(6)  │
                                                    │ (or USB-A out)   │   │ or USB-C             │
                                                    └──────────────────┘   └──────────────────────┘
```

Wiring rules:

1. **Connect the battery to the controller FIRST**, the panel second, the load last (standard controller order; the controller detects system voltage from the battery).
2. Fuse every wire leaving the battery (+) — 15 A on the battery main, 2 A on the LOAD feed to the buck.
3. Verify the buck output is **5.1 V ± 0.1 V with a multimeter BEFORE connecting the Pi**; adjust its trim pot unloaded if needed.
4. Keep the panel leads out of the enclosure or gland-sealed; drip loop every cable entering the box.

## 5. MicroSD card guidance

- Use an **industrial or "high-endurance" rated card** (pSLC/MLC or endurance-class TLC). Consumer cards are specified for sequential media workloads, not for the small random writes a database produces.
- The node runs SQLite in **WAL mode** (`PRAGMA journal_mode=WAL`, spec §9): every insert transaction appends to the `-wal` file and checkpoints periodically, roughly doubling write volume versus a plain journal and adding frequent small synchronous writes. The dataset itself is tiny (hard cap of 5000 envelopes × ≤ 1 KB ≈ ≤ 5 MB hot data, spec §8.1), so total write volume is modest — but it is written **every day, forever**, which is what wears consumer cards.
- The daemon serializes all access through a single connection (`SetMaxOpenConns(1)`), so there are no fsync storms from concurrency; WAL + single connection is the write-minimizing profile already.
- Extra hardening on the OS side (optional): run journald with `Storage=volatile` in `/etc/systemd/journald.conf` so logs stop hitting the card; the daemon's own log output goes to journald.

## 6. Enclosure and thermal notes

- **IP65 or better**, UV-stable plastic or fiberglass, with cable glands (not drilled loose holes) and a small drain hole at the lowest point.
- **Battery inside the enclosure, shaded**: LiFePO4 chemistry must not be **charged** below 0 °C (metallic lithium plating) — the enclosure's thermal mass plus the controller's low-temperature charge cutoff covers this; in climates with hard freezes, insulate the battery compartment or bury the battery portion below the frost line. Discharge down to −20 °C is fine.
- **Pi and buck inside the same box**: a Zero W or Zero 2 W dissipates < 1 W and needs no heatsink if the box is not in direct sunlight; mount the box in the shade of the panel or face it away from the afternoon sun. Leave 1–2 cm of air above the buck converter.
- **Panel mount**: tilt ≈ site latitude (or latitude + 15° for a winter-biased fixed mount), oriented toward the worst-month sun, above the height of grass/snow, so it also shades the enclosure.

## 7. Assembly and first boot, step by step

1. **Flash** Raspberry Pi OS **Lite** onto the industrial SD with the official Imager — **32-bit for a Zero W / Pi 1 / plain Zero** (ARMv6 has no 64-bit mode), 64-bit for every newer board (`docs/pi-models.md` §5). Enable SSH only if you plan the ALLOW_SSH=1 variant; the node does not need it.
2. **Bench-wire** the system per §4 with the Pi DISCONNECTED. Power from the battery alone and verify: controller recognizes 4S LiFePO4 profile, buck output 5.1 V ± 0.1 V.
3. **Bench-boot the Pi** (from its buck or a bench USB supply) with keyboard + monitor or a serial console. Do not run `provision.sh` over NetworkManager Wi-Fi — the script disables and masks NetworkManager by design (`docs/DEVELOPMENT_PLAN.md` §1.6).
4. Copy the cross-compiled binary and the `raspberry/` tree to the Pi and run, as root, from the local console (details in `docs/BUILD.md` §5):

   ```bash
   COUNTRY=AR ./provision.sh    # 9 verified steps, [OK]/[FAIL], fail-fast
   reboot                        # the activation step
   ```

5. **First-boot checklist** (bench, before final mounting):
   - [ ] `systemctl status dtn-node` — active, `sd_notify READY=1`, no restarts.
   - [ ] `systemctl status hostapd dnsmasq dtn-firewall dtn-power` — all active.
   - [ ] Phone joins `offgrid-messages`, captive portal pops up on its own and lands on `http://offgrid.local:8080`.
   - [ ] `hostapd_cli -i wlan0 all_sta` lists the phone as an associated station.
   - [ ] `curl -H 'Host: offgrid.local:8080' http://10.42.0.1:8080/` from a client answers the portal HTML.
   - [ ] Two clients cannot ping each other (`ap_isolate=1` + FORWARD DROP).
   - [ ] `poweroff`, power from the PANEL only in daylight, boot again: everything restores by itself.
6. **Final mount**: panel per §6, enclosure sealed with glands and drip loops, log the date, COUNTRY used and the BOM serial numbers on the inside lid.

## 8. Energy acceptance test

Before leaving a new node unattended, run it **a full day on panel+battery** and confirm the controller shows net-positive charge by evening and never dips under 30% state of charge overnight. If it fails, the usual culprits are: panel partially shaded during part of the day, PSH overestimated for the season, or measured load above 1 W (see §9).

## 9. Measured-vs-expected current table (template)

Fill this in per deployment (values at the buck output unless stated; use a USB power meter or an INA219/INA260 shunt). If the 24 h average exceeds ~200 mA @ 5 V (≈ 1 W), revisit §2 with the measured number.

| Measurement point | Expected (typical) | Measured | Notes |
|---|---|---|---|
| Whole node idle, trimmed (LEDs/HDMI/BT off), no clients | 80–150 mA @ 5 V | ______ | governor `powersave`, AP beaconing included |
| Pi with one client browsing the portal | 200–400 mA @ 5 V (bursts) | ______ | radio TX dominated; short duration |
| Sync burst (100-envelope push) | < 1 s above idle | ______ | negligible at envelope volumes |
| Buck quiescent draw (Pi detached) | 0.1–1 mA @ 12.8 V | ______ | select a low-Iq converter |
| Charge controller quiescent | 1–5 mA @ 12.8 V | ______ | subtract from harvest in §2.3 if large |
| Cold night minimum battery voltage | ≥ 12.0 V (4S, 80% DoD floor ≈ 12.2 V under load) | ______ | below 11.6 V: discharge protection nearing |
| **24 h average** | **≤ 200 mA @ 5 V ≈ 1 W** | ______ | the §2 sizing input |

## 10. Channel planning (2.4 GHz, issue #20 T6)

Every node ships on **channel 6** by default (`raspberry/hostapd/hostapd.conf`: `channel=6`). Two nodes whose coverage areas partially overlap **on the same channel share one airtime domain**: 802.11 carriers sense per channel, so co-channel APs in partial range steal airtime from each other (slower associations, retry loops, slower portal loads at the midpoint) — no function is lost, but the degradation is real and was accepted in the design on the assumption that nodes are deployed far apart.

Deployment guidance:

1. **Plan adjacent nodes on 1/6/11** (the three non-overlapping 2.4 GHz channels). A chain A → B → C assigns 1 / 6 / 11 so no two reachable-from-one-spot nodes share a channel.
2. **Co-channel pairs are fine only when geographically separated** — far enough that no client location hears both beacons weakly (the failure mode is the *partial* overlap, not the distance itself).
3. After ANY channel change: edit `/etc/hostapd/hostapd.conf`, reboot, and re-run the coexistence case (T6 of `docs/field-test.md`) plus the mule walk (T1) on the new plan before leaving the node unattended.
4. Record the chosen per-node channel in the deployment log — the §12 matrices of `docs/field-test.md` are the place the observed evidence lives.

## ESP32 power profile (issue #39 addendum)

The ESP32 node is an AP-first platform: **deep sleep is not applicable**
(the access point is always on). Budget planning mirrors §1's ~1 W rule of
thumb: Wi-Fi TX dominates (modem-sleep is limited while stations are
associated); the S3 reference board adds octal PSRAM draw. Measured
numbers land in `docs/esp32-design.md` §2/§9 with the 72 h soak. The
hardware watchdog + brownout detector replace the Pi's systemd
supervision; there is no SD card to corrupt and no filesystem remount
cycle.
