# Node Installation Guide — From Shopping Cart to a Solar Node in the Field

| | |
|---|---|
| **Audience** | A person with basic DIY skills who has never built anything electronic. No electronics or networking experience is assumed. If you can use a screwdriver, a wire stripper and a multimeter, you can build this node. |
| **What you get** | One weatherproof, solar-powered Wi-Fi mailbox (the "node") that stores encrypted messages for passing phones. It runs itself after deployment. |
| **Time** | Shopping: one order plus shipping. Bench build: 4–8 hours. Bench validation: one sunny day on panel + battery. Deployment: 2–4 hours. |
| **Budget** | Roughly USD 130–480 (EUR 130–470) for parts depending on the tier you pick (§2). Tools add USD 40–90 if you own none (§1.2). |
| **Style** | Short sentences. Every technical word is explained at first use and again in the glossary (§10.3). Written with the translation effort of issue #30 in mind. |
| **Companion docs** | This guide explains and links. It does not re-derive the math: [`hardware.md`](hardware.md) stays the sizing reference. If this guide and `hardware.md` ever disagree, `hardware.md` wins — report the gap. |

<!-- PHOTO: the finished node — panel on its mount above a closed enclosure
     strapped to a post, for the top of this guide. -->

## Contents

1. [Prerequisites and skill map](#1-prerequisites-and-skill-map)
   - [1.1 Skills you need](#11-skills-you-need)
   - [1.2 Tools](#12-tools)
   - [1.3 Time and money](#13-time-and-money)
   - [1.4 Which existing doc covers what](#14-which-existing-doc-covers-what)
2. [Component shopping guide](#2-component-shopping-guide)
   - [2.1 The three budget tiers](#21-the-three-budget-tiers)
   - [2.2 Substitutions: what can vary, what must never vary](#22-substitutions-what-can-vary-what-must-never-vary)
   - [2.3 Where to buy and how to sanity-check a listing](#23-where-to-buy-and-how-to-sanity-check-a-listing)
3. [Build alternatives: pick your path](#3-build-alternatives-pick-your-path)
   - [3.1 Comparison table](#31-comparison-table)
   - [3.2 Path A: off-the-shelf power station in a box](#32-path-a-off-the-shelf-power-station-in-a-box)
   - [3.3 Path B: the standard build](#33-path-b-the-standard-build)
   - [3.4 Path C: DIY cell pack with a BMS](#34-path-c-diy-cell-pack-with-a-bms)
4. [Batteries: chemistry, compatibility and runtime](#4-batteries-chemistry-compatibility-and-runtime)
   - [4.1 The four chemistries in plain language](#41-the-four-chemistries-in-plain-language)
   - [4.2 Compatibility rules](#42-compatibility-rules)
   - [4.3 Runtime table: capacity vs days of autonomy](#43-runtime-table-capacity-vs-days-of-autonomy)
   - [4.4 Safe handling](#44-safe-handling)
5. [Solar panels](#5-solar-panels)
   - [5.1 Panel types](#51-panel-types)
   - [5.2 Sizing intuition: one worked example](#52-sizing-intuition-one-worked-example)
   - [5.3 Orientation and tilt](#53-orientation-and-tilt)
   - [5.4 Shading and soiling](#54-shading-and-soiling)
   - [5.5 Series or parallel](#55-series-or-parallel)
6. [Assembly, step by step](#6-assembly-step-by-step)
   - [6.1 Before you wire anything](#61-before-you-wire-anything)
   - [6.2 Wire the power system on the bench](#62-wire-the-power-system-on-the-bench)
   - [6.3 Flash the OS](#63-flash-the-os)
   - [6.4 Install the node software](#64-install-the-node-software)
   - [6.5 Bench validation checklist](#65-bench-validation-checklist)
7. [Outdoor deployment by environment](#7-outdoor-deployment-by-environment)
   - [7.1 Weatherproofing basics](#71-weatherproofing-basics)
   - [7.2 Forest](#72-forest)
   - [7.3 Mountain and alpine](#73-mountain-and-alpine)
   - [7.4 Desert](#74-desert)
   - [7.5 Coastal and wetland](#75-coastal-and-wetland)
8. [Maintenance and periodic checks](#8-maintenance-and-periodic-checks)
   - [8.1 Inspection schedule](#81-inspection-schedule)
   - [8.2 Battery aging signs](#82-battery-aging-signs)
   - [8.3 SD card health](#83-sd-card-health)
9. [Troubleshooting](#9-troubleshooting)
10. [Appendix: printable checklists and glossary](#10-appendix-printable-checklists-and-glossary)
    - [10.1 Printable shopping checklist](#101-printable-shopping-checklist)
    - [10.2 Printable field-deployment checklist](#102-printable-field-deployment-checklist)
    - [10.3 Glossary: the words you cannot avoid](#103-glossary-the-words-you-cannot-avoid)

---

## 1. Prerequisites and skill map

### 1.1 Skills you need

You already need:

- Careful following of numbered steps, in order.
- Safe use of a screwdriver, wire strippers and a utility knife.
- Reading a multimeter display (a one-button skill: touch the probes, read the number — §6.2 walks you through it).

You will learn on the way (each is one small skill, and §6 explains it):

- Crimping two MC4 connectors (or skip it: buy pre-crimped panel leads).
- Soldering two wires and shrinking a sleeve over them.
- Flashing a microSD card with a click-through app.

You do NOT need: electronics design, networking administration or programming.
The installer configures the whole network side by itself. When the node
boots, its Wi-Fi network and its web page simply appear.

### 1.2 Tools

| Tool | Needed? | Notes |
|---|---|---|
| Multimeter | Yes | Any basic one (DC volts). ~USD 15–40 / EUR 15–40. |
| Wire stripper + cutter | Yes | ~USD 8–15. |
| Phillips screwdrivers (small + medium) | Yes | Enclosure and controller terminals. |
| USB power meter | Recommended | Plugs between buck and Pi, shows volts/amps. ~USD 10–20. |
| MC4 crimping tool | Only if you crimp your own MC4s | Or buy panel leads pre-crimped (§2.1). ~USD 15–25. |
| Soldering iron 30–60 W + heatshrink | For Path B/C wiring | Only for joints not already MC4 (§6.2 step 8). |
| Cordless drill + step drill bit | If your enclosure has no gland holes | Glands need round holes; a step bit cracks plastic less. |
| Laptop + microSD card reader | Yes | For flashing the OS. |
| Utility knife, tape, marker, zip ties | Yes | General. |

### 1.3 Time and money

- **Shipping is the long pole.** Order everything in one go (§10.1 checklist).
  Nothing is exotic; every part class below is stocked by the shops in §2.3.
- **Bench build:** 4–8 hours spread over an afternoon. Do not rush §6.2 — the
  one irreversible mistake class here is reversed polarity, and the fuse is
  the only thing standing between a mistake and a dead battery.
- **Validation:** one full day on panel + battery before the node leaves the
  house. This is the acceptance rule of [`hardware.md`](hardware.md#8-energy-acceptance-test)
  and it is not optional: it is what tells you the node survives a night.
- **Deployment:** 2–4 hours on site plus the walk back.

Budget: the electronics land between USD 130 and USD 480 (EUR 130–470)
depending on the tier (§2.1). These are estimates, not quotes.

### 1.4 Which existing doc covers what

This guide links instead of repeating. The map:

| Your question | Go to |
|---|---|
| Which Raspberry Pi board should I buy? | [`pi-models.md`](pi-models.md) (baseline: Pi Zero W) |
| How much battery and panel do I need — the math? | [`hardware.md`](hardware.md#2-sizing-math-worked-example) §2 |
| The exact parts list and wiring diagram | [`hardware.md`](hardware.md#3-recommended-bill-of-materials) §3–§4 |
| Which microSD card, and why | [`hardware.md`](hardware.md#5-microsd-card-guidance) §5 |
| Enclosure and heat notes | [`hardware.md`](hardware.md#6-enclosure-and-thermal-notes) §6 |
| Installing the software (all three ways) | README "one command" + [`BUILD.md`](BUILD.md#5-deploy-to-a-raspberry-pi-zero-w-or-newer) §5 |
| Running and upgrading a deployed node | [`RUNBOOK.md`](RUNBOOK.md#4-restoring-a-node-in-minutes) §4 |
| What the end users do with the node | [`quick-start.md`](quick-start.md) |
| The on-hardware acceptance protocol | [`field-test.md`](field-test.md) |
| How the messages work inside | [`protocol.md`](protocol.md) |

Out of scope for this guide: LoRa backhaul and solar repeaters (Phase 3,
issue #33) and Bluetooth LE (Phase 2, issue #32). Everything here covers the
Phase 1 Wi-Fi node only.

---

## 2. Component shopping guide

### 2.1 The three budget tiers

Three ways to buy the same node. The **recommended tier is the baseline** of
[`hardware.md`](hardware.md#3-recommended-bill-of-materials) §3 and the rest
of this guide follows it. All prices are **estimates for generic component
classes** (checked October 2026, rounded); they drift with markets and
regions. Do not treat them as quotes, and do not buy on price alone — read
§2.3 first.

**Tier 1 — minimal** (works, thinner margins):

| Part | Class / spec | Est. USD | Est. EUR |
|---|---|---|---|
| Raspberry Pi Zero W | baseline board, on-board Wi-Fi ([`pi-models.md`](pi-models.md)) | 15 | 16 |
| microSD 16 GB industrial / "high endurance" | see [`hardware.md`](hardware.md#5-microsd-card-guidance) §5 | 10–15 | 10–16 |
| Solar panel 10 W, 12 V nominal, Voc < 25 V | rigid monocrystalline | 20–30 | 20–32 |
| LiFePO4 4S 12.8 V **6 Ah** (~77 Wh) with BMS | built-in BMS required | 30–55 | 30–58 |
| Charge controller 10 A PWM with LiFePO4 profile **and low-temp charge cutoff** | see §2.2 — non-negotiable features | 12–20 | 12–21 |
| Buck converter 12 V → 5 V, ≥ 3 A, low quiescent current (< 1 mA) | feeds the Pi | 8–15 | 8–16 |
| Enclosure IP65 with cable glands + small fuses and holders | 15 A and 2 A | 12–20 | 12–21 |
| Cable 18 AWG (red/black, ~5 m), MC4 pairs, heatshrink | runs under 2 m | 15–25 | 15–26 |
| **Total** | | **~122–195** | **~129–206** |

**Tier 2 — recommended** (the [`hardware.md`](hardware.md#3-recommended-bill-of-materials) §3 BOM):

| Part | Class / spec | Est. USD | Est. EUR |
|---|---|---|---|
| Raspberry Pi Zero W | baseline board | 15 | 16 |
| microSD 16 GB industrial / "high endurance" | | 10–15 | 10–16 |
| Solar panel **20 W**, 12 V nominal, Voc < 25 V | rigid monocrystalline — the ~2× headroom of [`hardware.md`](hardware.md#23-solar-panel) §2.3 | 25–45 | 26–48 |
| LiFePO4 4S 12.8 V **10 Ah** (128 Wh) with BMS | the §2.2-recommended pack | 45–80 | 48–85 |
| Charge controller 10 A PWM or small MPPT, LiFePO4 profile **and low-temp cutoff** | | 15–35 | 16–37 |
| Buck converter 12.8 V → 5 V, ≥ 3 A, low quiescent (< 1 mA) | | 8–15 | 8–16 |
| Enclosure IP65+, UV-stable, with glands + drain hole | | 15–30 | 16–32 |
| Cable 18 AWG, MC4 pairs, 15 A + 2 A fuses and holders, heatshrink | | 20–30 | 21–32 |
| USB power meter (bench validation) | | 10–20 | 11–21 |
| **Total** | | **~163–300** | **~174–319** |

**Tier 3 — robust** (harsh sites, minimal visits, years of margin):

| Part | Class / spec | Est. USD | Est. EUR |
|---|---|---|---|
| Raspberry Pi Zero 2 W (or Zero W) | [`pi-models.md`](pi-models.md) — same node, more headroom | 15–18 | 16–19 |
| microSD 16 GB industrial (pSLC/MLC class) | | 12–25 | 13–27 |
| Solar panel **50 W**, 12 V nominal, Voc < 25 V | rigid monocrystalline | 45–90 | 48–96 |
| LiFePO4 4S 12.8 V **20 Ah** (~256 Wh) with BMS | | 70–120 | 75–128 |
| Charge controller 10 A **MPPT** with LiFePO4 profile and low-temp cutoff | | 25–60 | 27–64 |
| Buck converter 12.8 V → 5 V, ≥ 3 A, low quiescent (< 1 mA) | | 10–20 | 11–21 |
| Enclosure IP66/67 fiberglass or thick UV-stable polycarbonate, glands, drain | | 30–80 | 32–85 |
| Mount: steel pole + U-bolts or wall brackets, 316 stainless hardware | | 20–50 | 21–53 |
| DC surge protector (SPD) on the panel line + spare fuses | storm-prone sites | 10–25 | 11–27 |
| Cable 16–18 AWG UV-rated, MC4, adhesive-lined heatshrink | | 25–40 | 27–43 |
| INA219/INA260 measurement module (optional logging) | [`hardware.md`](hardware.md#9-measured-vs-expected-current-table-template) §9 | 3–8 | 3–9 |
| **Total** | | **~265–486** | **~284–520** |

Money-saving honest notes: the battery is the biggest line — buy capacity for
your real worst month (§4.3), not for pride. The panel and controller are the
two places where a too-cheap part silently costs you days of downtime later
(§9, "battery never full").

### 2.2 Substitutions: what can vary, what must never vary

| Part | OK to substitute with | Must NEVER be substituted with |
|---|---|---|
| Board | Any Pi with on-board Wi-Fi ([`pi-models.md`](pi-models.md)); other boards need a USB Wi-Fi dongle that supports AP mode | A board whose radio cannot do AP mode (most USB dongles) — the node IS an access point |
| Panel | Flexible or folding (§5.1) with their caveats | A "panel" that is really a battery charger toy with < 5 W real output |
| Battery capacity | Any capacity that satisfies §4.3 for your worst month | — (capacity is a free choice; chemistry is not, next row) |
| Battery chemistry | LiFePO4 only in this guide. Li-ion or lead-acid require re-doing the math of [`hardware.md`](hardware.md#22-battery-capacity-lifepo4) §2.2 and changing the controller profile (§4.2) | A pack without a BMS; mixing old and new packs; mixing chemistries (§4.2) |
| Charge controller | PWM or MPPT, 10 A class | **Any controller without an explicit LiFePO4 4S (14.6 V absorption) profile** — it will cook or starve the pack. **Any controller without a low-temperature charge cutoff for sites that can reach 0 °C / 32 °F** — charging a frozen LiFePO4 cell permanently damages it (metal plates form inside; [`hardware.md`](hardware.md#6-enclosure-and-thermal-notes) §6) |
| Buck converter | Any 5 V converter, ≥ 3 A, **quiescent current under 1 mA** | A converter with sleepy-logout high idle draw (it drains the battery while the Pi sleeps — the node never sleeps, but a 10 mA idle is 0.3 Wh/day wasted); a bare USB car charger of unknown quality |
| Fuses | Correct-rating blade or ceramic fuses in holders | **No fuse at all.** A shorted 128 Wh battery can melt wiring and start a fire. The fuse is the cheapest fire insurance in the build |
| microSD | Industrial / high-endurance 8–16 GB | A consumer card "because it was in a drawer" — the node writes small amounts every day forever, and consumer cards die of it ([`hardware.md`](hardware.md#5-microsd-card-guidance) §5) |
| Enclosure | Any IP65+ UV-stable box (plastic, fiberglass, metal) with real cable glands | A lunch box, an ABS project box in direct sun (goes brittle in one season), or a sealed box with drilled-but-unglanded holes |
| Cable | 18 AWG (0.75 mm²) or thicker copper for runs under 2 m | Thinner wire on battery or panel runs — voltage drop and heat |

### 2.3 Where to buy and how to sanity-check a listing

Where to buy, in rough order of trust for this build:

1. **Electronics distributors** (Mouser, Digi-Key, Farnell, Reichelt, TME…)
   for the controller, buck converter, fuses, glands, cable. Data sheets are
   real and searchable.
2. **Solar specialists** (offline-grid or caravan/marine solar shops) for the
   panel, battery and controller — they stock LiFePO4-profile controllers as
   a matter of course.
3. **General marketplaces** for the board, the SD card, the enclosure and
   boxes of MC4 parts. Fine for commodity parts; risky for the battery and
   the controller (see the checks below).

Sanity checks before you click buy:

- **Battery — weigh the Wh.** Real LiFePO4 stores roughly 90–120 Wh per kg.
  A "12.8 V 100 Ah" pack that weighs 2 kg is a lie; a 10 Ah (128 Wh) pack
  should weigh around 1.2–1.5 kg. The listing must state a **BMS is
  integrated**, the **4S / 12.8 V nominal / 14.6 V charge** figures, and a
  cycle-life figure (≥ 2000 cycles at 80% discharge is the normal honest
  claim for LiFePO4).
- **Controller — read the manual, not the ad.** The product page must name
  LiFePO4 (or "lithium iron phosphate", 14.6 V) in its battery-type menu,
  and the manual must list a **low-temperature charging cutoff** (charging
  stops below ~0 °C). If the manual is not findable, assume the feature is
  absent.
- **Panel — check Voc and do the area math.** Open-circuit voltage (Voc,
  printed on the back) must stay **under your controller's PV input limit**
  and under 25 V in this build. One square meter of panel is at most ~220 W
  in the real world: a "200 W" panel the size of a laptop is fiction. A
  20 W panel has cells of roughly 0.1 m².
- **microSD — "high endurance" must be written on the card.** Marketing
  words like "ultra" mean nothing; endurance-class lines from the major
  brands state TB-written ratings or "high endurance" explicitly.
- **Everything else** — check the connector names (MC4, JST, screw
  terminal) against what arrives; adapters are cheap but each one is a
  future failure point.

---

## 3. Build alternatives: pick your path

Three honest paths from parts to a node. Pick in the table below, then read
only your path's short section — every path ends at the same software steps
(§6.3–§6.5).

### 3.1 Comparison table

| | Path A: power station in a box | Path B: standard build | Path C: DIY cell pack |
|---|---|---|---|
| Electronics cost (this node) | USD 90–180 | USD 130–300 | USD 100–250 |
| Skill needed | None beyond §1.1 | The skills of §1.1, learned on the way | All of Path B + spot-welding or confident high-current soldering |
| Build time | 1–2 hours | 4–8 hours | 8–16 hours |
| Autonomy at ~1 W | Whatever the bought unit holds; usually overpriced per Wh | Sized exactly (§4.3): 2–6+ days | Best Wh per dollar; sized exactly |
| Weather resilience | Depends wholly on the bought unit's IP rating | Fully under your control | Fully under your control |
| Serviceability | Swap the whole box; no part-level repair | Every part replaceable in the field | Best at cell level; worst at pack-build quality risk |
| Cold sites (≤ 0 °C) | Usually NOT safe (no low-temp charge cutoff inside; §3.2) | Safe if the controller has the cutoff | Safe if the BMS has low-temp charge protection |
| Fire risk | Lowest (certified unit) | Low (one pack, fused, profiled) | Highest at build time; equal after a good build |

**Choose Path A if…** you need one node, this week, at a frost-free site, and
you accept paying per-Wh premium for zero build risk.
**Avoid Path A if…** the site ever freezes, or the node must run for years
unattended — most all-in-one units cannot charge and power a load at the same
time, and their built-in panels are far too small (see §3.2).

**Choose Path B if…** this is your first build. It is the documented
baseline: [`hardware.md`](hardware.md) sizes it, this guide assembles it,
and every part is replaceable in the field.
**Avoid Path B if…** you will not solder or crimp at all — then Path A.

**Choose Path C if…** you already have the tools, you enjoy it, and you are
building several nodes (the per-Wh saving is real at volume).
**Avoid Path C if…** this is your first battery build — a mistake here is a
fire risk, and the saving over Path B is small for one node.

### 3.2 Path A: off-the-shelf power station in a box

The idea: a commercial "solar generator" or a large solar power bank provides
5 V USB; a Raspberry Pi sits in a small IP65 box next to it.

Honest limits, before you fall for the marketing:

- **The built-in panels are decoration at this load.** A power bank's flip-out
  3–5 W panel harvests at best ~15–25 Wh/day in good sun; the node needs
  ~27 Wh/day from the battery ([`hardware.md`](hardware.md#21-daily-energy)
  §2.1) — before clouds. You need a real external panel plugged in.
- **Many units cannot pass through** (charge the battery and power the USB
  output at the same time). The node must run 24/7. Check the manual for
  "pass-through charging" or "UPS mode" BEFORE buying.
- **Cold kills this path.** Power banks use Li-ion (NMC) cells and almost
  none cut off charging below 0 °C. At a freezing site this path can quietly
  destroy its own battery (§4.2). Frost-free sites only.
- **Weather rating:** the unit itself is rarely more than IP54; the Pi's box
  does not protect the battery.

Extra parts: Pi + SD + small IP65 box + short USB cable (USD ~45–70) on top
of the power station (USD ~60–120 for something with ≥ 100 Wh and real
pass-through) and one 20 W panel with the right plug.

Procedure: flash and install the Pi exactly as §6.3–§6.5 (bench first), power
it from the unit's USB-A, wire the panel to the unit's input, deploy both
boxes with the unit sheltered from rain and sun. Validate with §6.5, then
watch one full cycle before walking away (§7).

### 3.3 Path B: the standard build

This is the path the whole guide documents: the recommended tier of §2.1,
the bill of materials of [`hardware.md`](hardware.md#3-recommended-bill-of-materials)
§3, the wiring of §4, the assembly of §6 and the deployment of §7. Go there.
If you read only one path section, this sentence is it.

### 3.4 Path C: DIY cell pack with a BMS

The idea: buy bare LiFePO4 cells (32700 or 32140 size are the friendly big
format), a 4S BMS board, and assemble your own 12.8 V pack. Cheapest per Wh,
full control of capacity — and the pack build is the one step where real
danger lives.

Honest caveats:

- Use a **spot welder for nickel-strip connections**. Soldering directly on
  cell bodies overheats them; if you must solder, it takes a hot iron, flux,
  and speed — it is a learned skill, not a first project. (Large 32700 cells
  with stud terminals or compression holders soften this.)
- The **BMS must match the chemistry (LiFePO4, 4S)** and must have a
  **low-temperature charge cutoff** for freezing sites; its continuous
  current rating ≥ 10 A (yours will draw under 1 A; margin is free).
- Balance the cells before final assembly (most BMS boards balance slowly —
  let the finished pack sit on the bench connected to the controller for a
  week and check cell voltages with the BMS app or a multimeter before
  trusting it).
- A home pack has no certification, no drop testing, no warranty. House it
  in its own rigid, vented, insulated sub-compartment inside the enclosure.

Everything downstream is identical to Path B: the pack is "a 12.8 V LiFePO4
battery with BMS" as far as the controller and this guide are concerned.
Size its Ah with §4.3.

---

## 4. Batteries: chemistry, compatibility and runtime

### 4.1 The four chemistries in plain language

| | **LiFePO4** (this guide) | Li-ion (NMC/LCO — phones, laptops, power banks) | Lead-acid (car/boat) | NiMH (AA rechargeables) |
|---|---|---|---|---|
| Energy (Wh per kg) | ~90–120 | ~150–250 | ~30–50 | ~60–120 |
| Usable share (depth of discharge) | 80% is normal, gentle | 50–80%, ages fast when deep | Only ~50% if you want it to last | 60–80% |
| Cycle life (to 80% capacity) | 2000–5000+ | 300–1000 | 200–500 | 300–1000 |
| Cold | Discharges to −20 °C (less capacity when icy); **must never be CHARGED below 0 °C** | Same charge ban, weaker discharge in cold too | Loses much capacity in cold; tolerant of abuse | Works in cold; ages in heat |
| Fire risk | Lowest of the lithium family | Highest — this is the chemistry in battery fires on the news | Low (but acid and explosive gas while charging) | Low |
| Disposal | Growing recycling network; hazardous waste point | Hazardous waste point, same | Well-established return chain | Hazardous waste point |

Translation: **LiFePO4 wins on the two things a left-alone field node cares
about — cycle life and abuse tolerance — and loses only on weight per Wh,
which does not matter on a pole.** That is why [`hardware.md`](hardware.md)
sizes everything around it. Li-ion packs more energy per kilo (irrelevant
here), dies sooner, and is the fire-prone one. Lead-acid is cheap and heavy
and short-lived; NiMH is a household format, not a 25 Wh-class one.

### 4.2 Compatibility rules

These rules are the difference between a node that runs for years and one
that dies quietly. They are the "must never" column of §2.2, explained:

1. **The charge controller profile must match the chemistry.** The controller
   charges to a fixed voltage: 14.6 V for LiFePO4 4S, ~12.6 V for lead-acid
   absorption, 12.0–12.6 V for Li-ion 3S. Wrong profile in either direction
   breaks things: a lead-acid profile **undercharges** a LiFePO4 pack (maybe
   60% of its capacity, forever — the "battery never full" symptom in §9);
   an aggressive Li-ion/boost profile **overcharges** a pack meant for less,
   which is how lithium packs swell and catch fire. Setting the profile is a
   menu choice on the controller — set it BEFORE first power-up (§6.2 step 4).
2. **Every lithium battery needs its BMS** (Battery Management System) — the
   small board inside the pack that disconnects it before over-charge,
   over-discharge, short circuit, and (if you bought one that does) freezing.
   Pack without BMS = no protection = do not connect it, ever.
3. **Never mix old with new, or one chemistry with another.** An old pack
   drags a new pack down to its own capacity, wastes the new one, and a
   series/parallel mix of mismatched cells creates a permanent invisible
   current between them. One pack per node; replace whole, recycle whole.
4. **Never charge lithium below 0 °C.** Below freezing, charging plates
   metallic lithium inside the cell — permanent, and it is the mechanism
   behind swollen packs. This is why the low-temp charge cutoff on the
   controller is **mandatory at any site that can reach 0 °C / 32 °F**
   ([`hardware.md`](hardware.md#6-enclosure-and-thermal-notes) §6), and why
   Path A is frost-free-only. Discharging below 0 °C is fine (LiFePO4 down
   to −20 °C).
5. **The DoD floor is a lifespan promise, not a suggestion.** The design
   stops at 20% remaining ([`hardware.md`](hardware.md#22-battery-capacity-lifepo4)
   §2.2) because stopping there roughly doubles cycle life. The controller's
   low-voltage disconnect does this automatically — do not "temporarily"
   raise it.

### 4.3 Runtime table: capacity vs days of autonomy

The node draws ~1 W at the Pi (5 V × ~200 mA, [`hardware.md`](hardware.md#1-design-target-1-w-continuous)
§1). The buck converter loses ~10% on the way down from 12.8 V (efficiency
0.90, [`hardware.md`](hardware.md#21-daily-energy) §2.1), so each day costs
24 Wh ÷ 0.90 ≈ 26.7 Wh from the battery. And the design only ever uses 80%
of the pack (the DoD floor of §4.2 rule 5). So:

```
days of autonomy = pack Wh × 0.80 (DoD) × 0.90 (buck) ÷ 24 Wh/day
```

| LiFePO4 4S 12.8 V pack | Energy | Days of autonomy (this formula) |
|---|---|---|
| 4 Ah | 51 Wh | 1.5 days |
| 6 Ah | 77 Wh | 2.3 days |
| **10 Ah (recommended)** | **128 Wh** | **3.8 days** |
| 18 Ah | 230 Wh | 6.9 days |
| 30 Ah | 384 Wh | 11.5 days |
| 50 Ah | 640 Wh | 19.2 days |

Real life is worse than the table, in known ways:

- **Age:** after the pack's rated cycles it still works but holds ~80%. A
  3-year-old 128 Wh pack behaves like ~100 Wh.
- **Cold:** near 0 °C a LiFePO4 delivers noticeably less (plan ×0.85); deep
  in a sub-zero night (−10 °C and below) plan ×0.7.
- **Standing losses:** the controller and buck together idle-burn roughly
  0.5–2 Wh/day ([`hardware.md`](hardware.md#9-measured-vs-expected-current-table-template)
  §9 measures yours). That is already covered by the design round-up for the
  recommended tier, but a huge pack chasing "30 days of autonomy" is really
  chasing the standing losses too.
- Rule of thumb for a plan you can trust: **multiply the table number by
  0.7–0.8** for a cold site or a pack older than two years. The recommended
  128 Wh pack is honestly a 3-day pack at a cold site — exactly the design
  target of [`hardware.md`](hardware.md#22-battery-capacity-lifepo4) §2.2.
- And the deployment acceptance rule stays stricter than all of this: after
  a full day on sun, the battery must not dip below **30% overnight**
  ([`hardware.md`](hardware.md#8-energy-acceptance-test) §8). If it does,
  §9 troubleshooting, "battery never full".

### 4.4 Safe handling

- **Charging:** only through the controller with the right profile (§4.2).
  Never raw from a panel, never from an unregulated supply. Never below
  0 °C (rule 4).
- **Shorts are instant.** A battery with 128 Wh can deliver hundreds of amps
  into a dropped wrench or a ring. **Take off rings and bracelets** when
  working near the battery terminals, keep one terminal covered until the
  last moment, and the 15 A main fuse goes in as one of the FIRST steps
  (§6.2), not the last.
- **Storage:** store packs around half charge (SoC ~50%, ~13.0–13.2 V for
  4S LiFePO4), dry, off concrete is folklore — dry and room temperature is
  what matters. Top them to ~50% every 6 months of storage.
- **End of life:** a pack that has swollen, smells sweet-solvent, or ran
  hot: do not charge it again, do not puncture it, move it outdoors onto
  bare ground or a ceramic/metal tray away from anything flammable, and
  take it to a battery recycling point (the shop where you bought it must
  take it back in the EU; hazardous-waste points elsewhere).
- **Transport:** LiFePO4 under 100 Wh travels as ordinary "lithium battery"
  cargo — tape the terminals, keep it in its box. Li-ion power banks and
  packs are airline-restricted (carry-on only, Wh limits); LiFePO4 at
  128 Wh may need airline approval — check before flying with one. A frozen
  site favors LiFePO4 again: discharging is fine at −20 °C, and the pack
  that must never freeze is the one being charged, which is the controller's
  job (§4.2 rule 4).
- **If a lithium pack ever catches fire:** you cannot blow it out. Smother a
  small pack with dry sand, or let it burn out on bare ground. Water does
  not stop the reaction (it cools neighbors); never carry a burning pack
  indoors. This is one more reason the whole power system lives in its own
  enclosure, outdoors, on a pole — not in a house.

---

## 5. Solar panels

### 5.1 Panel types

| Type | Choose it for | Honest downsides |
|---|---|---|
| **Rigid monocrystalline** (glass, aluminum frame) | Default. Best watts per dollar, 20+ year life, survives hail and brushing | Heavy-ish, rigid mount needed |
| Flexible (plastic-faced) | Curved surfaces, stealth mounts, weight limits (backpack, tent, boat) | Runs hot (loses power), dies in 3–7 years under sun, easy to scratch and to steal; MUST have airflow underneath |
| Folding portable | Seasonal or trial nodes, nodes you carry out and back each time | Must be unpacked/aimed by hand each visit; a theft magnet; connectors work loose |

Default recommendation: **rigid monocrystalline, 12 V nominal** — that is
what [`hardware.md`](hardware.md#3-recommended-bill-of-materials) §3 specs.

### 5.2 Sizing intuition: one worked example

The full math lives in [`hardware.md`](hardware.md#2-sizing-math-worked-example)
§2 — here is the intuition with the same numbers:

1. The node eats **24 Wh/day** at the Pi, **≈ 26.7 Wh/day** out of the
   battery (buck efficiency 0.90), rounded up to **28 Wh/day** of design
   energy ([`hardware.md`](hardware.md#21-daily-energy) §2.1).
2. Sun is measured in **peak sun hours (PSH)** — the hours per day of
   full-strength sun, averaged over a month. You care about the WORST month
   at your site: 3.5 h is a temperate-latitude winter; look yours up
   (Global Solar Atlas, NASA POWER) — it is one number you should not guess.
3. Real panels underperform their sticker (heat, dirt, wiring, aging) by
   about 25% — the derate 0.75 in [`hardware.md`](hardware.md#23-solar-panel)
   §2.3:

```
needed panel W  = 28 Wh ÷ (3.5 h × 0.75)  ≈ 10.7 W  →  buy 20 W
```

Why the recommended answer is **20 W and not 10 W** — the ~2× headroom:

- PSH is an **average**: one real week of storm is below it, and the panel
  must refill the battery after the storm, not just break even on the day.
- Flat-ish or compromised mounting loses 10–30% (§5.3).
- The panel ages ~0.5–1% per year; soiling between your visits (§5.4) costs
  more.
- The headroom turns "the battery slowly dies over winter" into "the
  battery refills in one sunny day" — which is the difference between a
  node you service twice a year and one you dig out of the snow.

### 5.3 Orientation and tilt

- **Face the equator** (south in the northern hemisphere, north in the
  southern). East or west costs ~10–20%; it is acceptable only when the
  shade of the site forces it.
- **Tilt ≈ your latitude** for a fixed year-round mount. If you cannot
  visit in winter, use **latitude + 15°** — a steeper panel favors the low
  winter sun, sheds snow, and self-cleans rain better
  ([`hardware.md`](hardware.md#6-enclosure-and-thermal-notes) §6).
- If you do visit twice a year: latitude − 15° for the summer half,
  latitude + 15° for the winter half.
- **Above the grass and the snow**: the panel sees the site's weeds in
  July and the snowline in January — mount high enough for both, which
  also puts it above small critters.

### 5.4 Shading and soiling

- **Partial shade is not proportional.** A panel is cells in series: shade
  one cell and the whole string can fall to near zero, like kinking one
  point of a garden hose. A branch shadow at noon can cost more than its
  own area times ten. Bypass diodes soften this in blocks of cells — do
  not count on it.
- **Site selection beats diodes.** Visit the site at the worst month's
  midday (and ideally mid-morning) and look at the shadows BEFORE mounting.
  For tree sites this is the single most important decision — see §7.2.
- **Soiling:** dust, pollen, bird droppings and leaves cost 5–25% depending
  on region (more in deserts and under birds). Rain cleans tilted panels
  mostly by itself; plan a wipe-down at every visit (§8.1). Bird droppings
  are the worst offender — one opaque blob can shut down a cell block.

### 5.5 Series or parallel

Keep it simple: **one panel**. This node needs 10–50 W and single panels
exist in every size.

If you truly need two panels: wire them **in parallel** (positive to
positive, negative to negative, via MC4 Y-branches). Parallel keeps the
voltage at the controller's happy 12 V-class input and halves the pain of
partial shading (each panel contributes on its own). Series would stack the
voltages toward the controller's PV input limit — with the Voc < 25 V rule
of §2.3 there is no headroom for it, and one shaded panel in a series string
drags the whole string (§5.4). Never mix panels of different models or
sizes in either wiring.

---

## 6. Assembly, step by step

This is Path B (the standard build of §3.3). Steps 1–8 wire and validate the
power system with the Pi DISCONNECTED; steps 9–13 add software. Estimated
total: one afternoon plus one validation day.

### 6.1 Before you wire anything

1. Unbox everything and check it against the §10.1 checklist.
2. Measure the battery voltage with the multimeter: a resting 4S LiFePO4
   shows **12.8–13.4 V** (storage charge ~13.0 V). Under 12.0 V: charge it
   first with a proper LiFePO4 charger, or return it.
3. In daylight, measure the panel: **Voc within a volt or two of the label,
   and above it** (a "20 W 12 V" panel shows ~21–24 V open-circuit). Far
   below the label = shaded spot or a bad panel.
4. Identify the controller's terminals: PV+ / PV− (from panel), BAT+ / BAT−
   (battery), LOAD+ / LOAD− (switched output). Set its **battery type to
   LiFePO4 / 14.6 V** now, with nothing connected — some controllers only
   accept the type change before first battery connection.
5. **Take off rings and bracelets** (§4.4).

### 6.2 Wire the power system on the bench

The order below is the standard controller order — **battery first, panel
second, load last** ([`hardware.md`](hardware.md#4-wiring-diagram) §4), and
the teardown order is exactly reversed. The controller detects the system
voltage from the battery, and a panel connected to a controller with no
battery is how controllers die.

```
 step 1:  BATTERY (+) --15 A fuse--> CONTROLLER BAT+     (first!)
          BATTERY (-) -----------------> CONTROLLER BAT-

 step 2:  PANEL (+) --MC4--> CONTROLLER PV+              (second)
          PANEL (-) --MC4--> CONTROLLER PV-

 step 3:  CONTROLLER LOAD+ --2 A fuse--> BUCK IN+
          CONTROLLER LOAD- ------>      BUCK IN-

 step 4:  BUCK OUT (5.1 V) ---> (Pi connects only in 6.4, after step 7)
```

1. **Battery to controller.** Connect the 15 A fuse holder in the battery's
   positive lead BEFORE the controller terminal (the fuse protects the
   wire, so it sits near the battery). Then BAT−, then BAT+. The controller
   screen should wake up.
2. **Set the battery type** to LiFePO4 (if you have not in 6.1 step 4).
   Confirm the display shows ~12.8–13.4 V.
3. **Panel to controller**, PV− first, then PV+, MC4s clicking together.
   In room light the PV voltage reading appears. Cover the panel with a
   cardboard sheet while wiring if it is midday sun (panels are live in
   light).
4. **Confirm the charge behavior**: with the panel lit, the controller
   shows a charging state and the battery voltage rises slightly. On
   controllers with a display, check the LiFePO4 profile is still the
   selected one.
5. **Buck to controller LOAD.** Wire LOAD+ through the 2 A fuse holder to
   the buck's IN+, LOAD− to IN−. Why LOAD and not straight from the
   battery: the controller's load output disconnects at the DoD floor
   (§4.2 rule 5) — that is what protects the battery on a long dark
   streak. Keep this wiring.
6. **Set the buck output BEFORE the Pi exists in the circuit.** Power the
   system from battery + panel, multimeter on the buck output: adjust its
   trim potentiometer until it reads **5.1 V ± 0.1 V** unloaded
   ([`hardware.md`](hardware.md#4-wiring-diagram) §4 rule 3). A Pi fed 6 V
   is a dead Pi; this one measurement is not skippable.
7. **Joints and connectors.** MC4 where panel meets everything (they seal
   against weather). Inside the box: screw terminals tightened, or
   soldered + heatshrink. **No bare twisted joints, no crimp-only joints**
   ([`hardware.md`](hardware.md#3-recommended-bill-of-materials) §3).
   Wiggle-test every wire; something loose now is something rebooting in
   the rain later (§9).
8. Let it all run an hour on the bench. Touch-check: the fuse holders and
   wires stay cold, the buck may be warm (never hot).

<!-- PHOTO: the wired bench system before the Pi is connected — battery,
     controller with 15 A/2 A fuses visible, panel leads with MC4, buck
     with multimeter showing 5.1 V. -->

### 6.3 Flash the OS

1. On your laptop, install the official **Raspberry Pi Imager**.
2. Choose **Raspberry Pi OS Lite** — 32-bit for a Pi Zero W / Pi 1 (their
   cores cannot run 64-bit code, [`pi-models.md`](pi-models.md#1-support-matrix)
   §1); 64-bit for Zero 2 W and everything newer.
3. In Imager's settings: set nothing mandatory. Enable SSH only if you
   plan the `ALLOW_SSH=1` variant — the node does not need it.
4. Write to the industrial SD (§2.1) — this is the card the node will run
   on for years; it is worth the extra dollars now
   ([`hardware.md`](hardware.md#5-microsd-card-guidance) §5).

### 6.4 Install the node software

Keep the Pi on the bench with keyboard + monitor (or serial console) for
this — **do not** run the installer over Wi-Fi: provisioning replaces the
network stack by design ([`pi-models.md`](pi-models.md#5-which-os-image-exactly)
§5).

1. Put the flashed SD in the Pi, connect its screen and keyboard, then
   connect the Pi's power — from the buck's 5 V output (USB-C or the 5 V +
   GND pins, [`hardware.md`](hardware.md#3-recommended-bill-of-materials)
   §3) or temporarily from any phone charger. It boots to a login.
2. Run the one-command installer (needs Internet once — phone tethering
   counts):

   ```bash
   curl -fsSL https://raw.githubusercontent.com/juliangt/offgrid/main/raspberry/install.sh \
     | sudo bash -s -- --country AR
   ```

   Replace `AR` with your two-letter country code (Wi-Fi regulations).
   No Internet at the bench? Prepare a USB stick with the release assets
   and run `sudo ./install.sh --offline /media/usb --country AR`
   ([`BUILD.md`](BUILD.md#5-deploy-to-a-raspberry-pi-zero-w-or-newer) §5,
   Path 2). Prefer to build and copy by hand? Path 3 of the same section.
3. Confirm the installer's 10 steps all show `[OK]`, press ENTER at the
   final prompt — **the reboot is the activation step** — and let it
   reboot.
4. After reboot, from the Pi's console:

   ```bash
   systemctl status dtn-node hostapd dnsmasq dtn-firewall dtn-power
   ```

   all should be `active` ([`hardware.md`](hardware.md#7-assembly-and-first-boot-step-by-step)
   §7 first-boot checklist). The Pi's Wi-Fi is now the node's access point:
   **its own network name `offgrid-messages` appears.**

### 6.5 Bench validation checklist

Do not let the node leave the house until every line passes. From a phone:

- [ ] The Wi-Fi network `offgrid-messages` is visible and joins without a password.
- [ ] The captive portal pops up on its own — or you open your **full browser** at `http://offgrid.local:8080` and the page loads.
- [ ] Register a test identity (§quick-start steps 1–5 of [`quick-start.md`](quick-start.md)).
- [ ] With a SECOND phone on the same Wi-Fi: register another identity, send a test message from one to the other, tap "Sync now" on both — the message arrives.
- [ ] The two phones cannot see each other's traffic (that is `ap_isolate` doing its job; you simply notice there is no "local network" anything between them).

From the Pi's console:

- [ ] `systemctl status dtn-node` — active, no restarts.
- [ ] `curl -H 'Host: offgrid.local:8080' http://10.42.0.1:8080/` prints portal HTML.
- [ ] `hostapd_cli -i wlan0 all_sta` lists your phone.

The energy half of validation is the **§8 acceptance rule** of
[`hardware.md`](hardware.md#8-energy-acceptance-test): leave the whole
system — panel, controller, battery, Pi — running for one full day on a
window sill or balcony. By evening the controller must show net-positive
charge, and the battery must not dip below 30% overnight. Write down the
evening/ morning battery percentages; they are your baseline for §8
maintenance.

Then: `sudo poweroff`, pack the parts, and deploy (§7).

---

## 7. Outdoor deployment by environment

### 7.1 Weatherproofing basics

These apply in every environment; the per-environment sections add the rest.

**IP ratings explained.** "IP65" = Ingress Protection, digit 1 (0–6) for
solids: 6 = dust-tight. Digit 2 (0–9) for liquids: 4 = splashes, 5 = low
pressure jets, 6 = heavy seas, 7 = brief immersion. **IP65 is the floor for
this node.** The rating only holds if every hole is sealed: a box with a
drilled hole is a box with a hole.

- **Cable glands**, not drilled loose holes: a gland is a threaded fitting
  with a rubber ring that clamps the cable and seals the hole. Match gland
  size to cable thickness (a too-thin cable in a big gland does not seal —
  wrap tape around the cable to bulk it up).
- **Drip loops**: every cable entering the box sags DOWN below its gland
  before rising to it, so water running along the cable drips off the loop
  instead of following the cable in. No exceptions.
- **Drain hole**: a 3–4 mm hole at the box's lowest point
  ([`hardware.md`](hardware.md#6-enclosure-and-thermal-notes) §6) lets the
  condensation that ALWAYS happens inside escape. Down-facing glands plus a
  drain hole beat a "perfectly sealed" box.
- **UV-stable enclosure**: sun eats plastic. Look for "UV-stabilized",
  "polycarbonate/ABS", fiberglass, or metal. Cheap styrene goes yellow and
  brittle in one season.
- **Mount the box in the panel's shade**, facing away from the afternoon
  sun ([`hardware.md`](hardware.md#6-enclosure-and-thermal-notes) §6) — the
  Pi and battery want to be cool, and the panel roof is free shade.
- **Grounding**: this system is low-voltage DC in plastic, and does not
  need an earth for the electronics. On a metal pole in open terrain or
  lightning country, bond the panel frame and pole to a ground rod (thick
  bare wire) so a strike has a path around, not through, the electronics;
  add a DC surge protector on the panel line (Tier 3, §2.1). Full lightning
  protection is out of scope; §9 covers "node dead after storm" honestly.
- **Concealment and anti-theft**: muted paint (brown, grey, bark), no
  logos, mount below ridge lines and outside sightlines from paths; the
  panel is the visible part — that is fine, panels are the least valuable
  part to steal. Put the expensive parts (battery) inside the box, and
  accept that a really determined thief wins: deploy the tier the site
  can afford to lose (§2.1). Do not post geotagged photos of a new node
  online while it is still shiny.
- **Log the install** on the inside lid: date, `COUNTRY` used, serial
  numbers, and the bench-validation percentages of §6.5
  ([`hardware.md`](hardware.md#7-assembly-and-first-boot-step-by-step) §7
  step 6).

**Every deployment ends with the walk-away test:** mount, seal, power from
panel alone in daylight (unplug the battery — the node must boot on its
own), reconnect, and run the §6.5 checklist once more from a phone at the
worst spot for signal. Leave only after a full pass.

### 7.2 Forest

**Failure modes:** canopy shade (the big one), humidity and mold, rodents
and insects eating cables, falling branches, and tree growth swallowing your
mount.

Extra parts: 2× wide (25–38 mm) **polyester tree straps** (never rope-on-
bark, never nails or screws into a living tree — they wound it and the tree
grows over them), spiral **rodent-proof conduit** or braided steel sleeve
for the ground-level cable run, rubber/EPDM buffer strip between hardware
and bark, silica-gel canister in the box, and a small bag of zip ties for
tidying.

Mounting procedure:

1. **Pick the sun gap first, the tree second.** The panel needs the worst
   month's midday sun: visit around midday in that season, hold your hand
   up, and look for the brightest open patch near the trail — forest
   interiors are hopeless, edges and gaps are the sites. A phone sun-survey
   app shows the sun path per season if you cannot return in winter.
2. Choose a **healthy tree** (no dead branches above — "widow-makers" fall
   in storms), trunk ≥ 20 cm diameter, on the gap's edge.
3. Strap the panel (or its small frame) to the trunk with the two straps,
   above head height and above snow/grass (§5.3), with the rubber strip
   between strap and bark; leave a hand-width of slack — trunks grow.
   Tilt: strap over a wedge block or a natural lean; even ~10–15° beats
   vertical for rain shedding and winter sun.
4. Box below the panel in its shade, glands down, drain hole down, drip
   loop on every cable (§7.1). The conduit goes on every cable within
   reach of the ground or of climbing rodents.
5. Re-tension the straps and re-check the gap every 6–12 months — trees
   grow, gaps close, straps relax (§8.1).

```
            ~ ~ ~ canopy ~ ~ ~
         (the sun GAP must be above
          the panel at midday, worst month)
                 \
           +-------------+
           |    PANEL    |  tilted ~10-15 deg or more,
           +-------------+  wedge block or natural lean
             ||       ||
       strap ||       || strap      2 wide polyester straps,
          ___||_______||___         rubber buffer, NO nails
         |      tree       |
         |     trunk       |
          ----------------
           +-----------+
           | enclosure |  below the panel, in its shade,
           +-----------+  glands down, drain hole down
                 |
                 (   drip loop (§7.1)
                 |
           (((o)))  rodent-proof conduit on the low run
```

### 7.3 Mountain and alpine

**Failure modes:** sub-zero battery charging (§4.2 rule 4 — the mandatory
low-temp cutoff), wind and snow load, brutal UV at altitude, and the site
being unreachable for months.

Extra parts: charge controller **with low-temperature charge cutoff —
non-negotiable here** (§2.2), closed-cell foam or PP-board insulation wrap
for the battery plus its own sub-compartment in the box (the box gives
thermal mass; the foam slows the deep-freeze), steel pole ≥ 25 mm with
U-bolts, rock anchors or a ballast of stones/concrete, guy-wire kit for
exposed summits, 316 stainless hardware, and a steeper panel mount
(latitude + 15°, §5.3) so snow slides off.

Mounting procedure:

1. Site: full winter-midday sun; on a summit that is easy, in a valley look
   at the winter shadow line. Check the site is reachable in the season
   you plan to service it — a node behind a spring snowdrift is a dead
   node until July (plan the §8.1 visits around access, not the calendar).
2. Pole into rock (anchor + epoxy or wedge anchor into solid stone) or a
   cairn/ballast base where digging is impossible; guy wires on exposed
   ridges. The pole stands the box above the snowpack you actually see in
   spring photos of the site, plus 50 cm.
3. Battery insulated inside the box (foam wrap, own compartment, away from
   the box wall that faces the wind). Discharge to −20 °C is fine
   ([`hardware.md`](hardware.md#6-enclosure-and-thermal-notes) §6); the
   insulation plus thermal mass keeps the pack above the freeze longer,
   and the controller's cutoff covers the rest.
4. Panel at latitude + 15° or near-vertical facing the winter sun: steep
   sheds snow, catches the low sun, and honestly you are sizing for winter
   anyway (§5.2). Torque every clamp — alpine wind is a fatigue test.
5. UV: everything exposed is UV-rated by design (§2.1); check straps and
   cable jackets at every visit and at any sign of chalking/cracks,
   replace.

```
        winter sun (low)          wind ------>
              \  \  \
         +--------------------+
         |        PANEL       |  tilt latitude + 15 deg
         +--------------------+  (steep: snow slides off)
            //            \\
      U-bolt //            \\ U-bolt  316 stainless,
          ||||              ||||      torqued; guy wires
          ||||              ||||      on exposed ridges
       ~~~~ steel pole ~~~~
       (top of the spring snowpack + 50 cm)
          +-----------+
          | enclosure |
          | +-------+ |
          | |battery| |  foam-wrapped, own compartment,
          | +-------+ |  away from the wind-facing wall
          +-----------+
       #### rock anchor / ballast base ####
```

### 7.4 Desert

**Failure modes:** extreme heat (electronics and battery age fast; panel
loses voltage when hot), fine dust, huge day/night temperature swings
(loosens clamps, cracks cheap solder joints), and the panel cooking its own
underside.

Extra parts: light-colored or reflective enclosure (or a small shade roof
over it), **vent membranes** (Gore-Tex-style breather valves) if you vent at
all — they let hot air pressure out and block dust; if you cannot get
membranes, stay fully sealed and rely on the shade plus thermal mass (the
venting-vs-dust trade-off: a dusty vent is a sand door, a sealed box in the
sun is an oven — shade the box and you can keep it sealed), fine stainless
mesh over any opening, UV-rated (PV-wire class) cable for anything exposed,
extra cable slack as thermal expansion loops, and a cleaning kit (soft
brush) in the car.

Mounting procedure:

1. Site: open sun is trivial in a desert; the enemy is heat and sand drift.
   Mount the panel high enough that blowing sand does not bury its lower
   edge, and where the afternoon sun does not hit the enclosure (panel as
   the roof, §7.1).
2. Panel raised 10–15 cm above its mount rail: airflow under the panel
   recovers a real slice of the power heat steals (hot panels are
   measurably weaker; §5.2's derate already assumes some of this).
3. Enclosure in panel shade, light-colored, sealed, glands down, drain
   hole up-mounted on the side (sand falls down; a bottom drain hole in
   loose sand invites the dune in — side-mounted low still drains).
4. Leave a visible slack loop in every outdoor cable: a 40 °C night-to-day
   swing moves a 1 m cable by millimeters, every day, forever — tight
   cables fatigue and crack at the glands.
5. Clean the panel at every visit and schedule §8.1 checks around sand
   seasons; dust storms can cut output by half in one afternoon.

```
       sun (very high, very hot)
            \   |   /
        +-----------------+
        |      PANEL      |  raised 10-15 cm: AIR FLOWS
        +-----------------|  underneath (hot panel = less W)
           ||          ||
      U-bolts to a steel pole or a ground frame
                |
          +-----------+
          | enclosure |  light-colored, in the panel's
          | (sealed,  |  shade; vent membranes if you
          |  membrane)|  vent at all (dust vs heat, §7.4)
          +-----------+
       ~ ~ ~ drifting sand ~ ~ ~
       mount above drift height; side drain hole
```

### 7.5 Coastal and wetland

**Failure modes:** salt spray corrodes everything (stainless included, given
time), driving rain finds any imperfect gland, and flooding/drowning is the
node's certain death.

Extra parts: **316 (A4) stainless** for every screw, clamp and bracket (304
stainless and galvanized steel rust through in months near salt water),
adhesive-lined (marine) heatshrink on every splice, dielectric grease on
every contact and terminal, IP66/67 enclosure, and a pole mount measured
against the water, not the map.

Mounting procedure:

1. Site: above the flood line — for coasts, the highest storm-surge line
   plus a meter; for wetlands, the high-water mark plus 50 cm and out of
   the reeds (reeds grow INTO boxes through any gap, and beaver/bird
   platforms are more creative than you want).
2. Pole (or wall) mount, everything stainless, every contact greased,
   every splice adhesive-heatshrunk, glands facing DOWN and away from the
   prevailing wind-driven rain, drip loops extra deep (§7.1).
3. Panel: standard tilt; salt film builds fast — add a fresh-water rinse
   to the §8.1 monthly habit where you can.
4. Inspect for rust bloom at every visit; catch it with a wire brush and
   grease before it becomes structural. Expect the enclosure screws (not
   the box) to be the first casualty — keep spares.

```
    driving rain and salt wind -------->
        +-------------+
        |    PANEL    |   316 stainless fasteners only
        +-------------+
            ||      ||
            ||      ||    steel pole, high above the
            ||      ||    flood / storm-surge line
         +-----------+
         | enclosure |   IP66/67, adhesive-lined
         +-----------+   heatshrink, greased contacts
              |
              (    extra-deep drip loop
              |
   ~~~~~~ highest water line ~~~~~~~
   (mount well above it; reeds kept cut back)
```

---

## 8. Maintenance and periodic checks

### 8.1 Inspection schedule

The node is designed to be ignored; these visits keep that promise true.

**Every visit (or monthly where easy):**

- Wipe the panel (water + soft cloth; never scrape).
- Look at the controller: charge state by day, battery % by evening.
  Compare with your §6.5 baseline numbers — a slow slide is §8.2 beginning.
- Glance at: glands seated, box undamaged, drip loops intact, cables not
  chewed, straps tight (forest), clamps tight (desert/alpine), no rust
  bloom (coastal).
- Vegetation: has anything grown into the sun path since last time?

**Seasonally (2× per year):**

- Re-tension tree straps / U-bolts; re-check tilt and azimuth against §5.3.
- Battery minimum voltage on a dark morning vs the table in §4.3.
- Open the box (dry day): no condensation pools, no insect nests, silica
  gel still dry, drain hole clear, connectors tight, no corrosion.
- Clean the SD situation: confirm no repeat `.corrupt-*` quarantine files
  on the console (`sudo ls -l /var/lib/dtn-node/*.corrupt-*`,
  [`RUNBOOK.md`](RUNBOOK.md#43-quarantine-events-corrupt-db-evidence) §4.3).

**Annually:** walk the full §6.5 validation checklist again (a phone check
costs nothing and catches the slow rot), and re-read the `/status` page
counters for the year's shape ([`RUNBOOK.md`](RUNBOOK.md#2-reading-the-telemetry)
§2.1).

### 8.2 Battery aging signs

In order of appearance:

1. Evening charge % slightly lower each month at the same weather.
2. Dark-morning voltage lower than it was (vs §4.3's table) — capacity is
   shrinking; recompute autonomy with §4.3's age factor (×0.8).
3. Voltage sags visibly under the tiny node load where it never used to.
4. Swelling, sweet-solvent smell, or heat: **stop, do not charge again,
   replace** (§4.4). Never puncture or "drain" a swollen pack.

Replace whole packs, never mix old with new (§4.2 rule 3). The old pack
goes to a battery recycling point (§4.4).

### 8.3 SD card health

The SD card is the node's only wearing part ([`hardware.md`](hardware.md#5-microsd-card-guidance)
§5: the database writes a little, every day, forever). Watch for:

- Repeat quarantine events (§8.1 seasonal check) after a clean reboot —
  the card is dying; reflash a fresh industrial card
  ([`RUNBOOK.md`](RUNBOOK.md#46-the-5-minute-reflash) §4.6).
- Watchdog "budget exhausted" markers on a clean boot
  ([`RUNBOOK.md`](RUNBOOK.md#44-watchdog-storm-markers) §4.4) — same
  conclusion.
- The `/status` page's database size ([`RUNBOOK.md`](RUNBOOK.md#2-reading-the-telemetry)
  §2.1) — a size growing past a few MiB signals WAL pressure; the full
  operational drill (telemetry, abuse, restore) is the runbook's job, not
  this guide's.

---

## 9. Troubleshooting

Symptom-first, causes ordered by how often they are actually the cause.

**No boot (Pi LED dark).**

1. No 5 V reaching the Pi: measure the buck output (§6.2 step 6). If ~0 V,
   check the 2 A fuse, then the buck input side, then the controller LOAD
   output (its low-voltage disconnect may have cut a depleted battery —
   that is §"battery never full" below, not a broken buck).
2. Battery flat or disconnected: measure at the controller's BAT terminals
   (§4.3 voltages).
3. Bad cable between buck and Pi: swap it.
4. (Power present but no HDMI picture: this is a headless server — check
   §6.5 from a phone instead. The LED, not a monitor, is the boot indicator.)

**Random reboots / brownouts.**

1. Undervoltage: buck set below ~4.9 V (re-do §6.2 step 6), or a long/thin
   USB cable dropping volts — shorten or thicken it.
2. Battery sagging below the controller's disconnect at night (cold +
   small pack + §4.3's real-world factors): the LOAD output blinks off at
   the DoD floor — recompute §4.3 for the site.
3. Extra hardware on the Pi drawing past the 1 W design (a USB drive, a
   camera): remove it or re-size the system with [`hardware.md`](hardware.md#2-sizing-math-worked-example)
   §2 using the measured number.
4. Loose terminal on the battery or LOAD line: wiggle-test with the §6.5
   checklist running.

**AP not visible (`offgrid-messages` missing).**

1. Wait 5 minutes after power-up first: the watchdog
   ([`RUNBOOK.md`](RUNBOOK.md#3-detecting-abuse-symptom--likely-cause--check--action) §3) restarts a
   fallen component automatically within 2–4 minutes.
2. From the console: `journalctl -u hostapd -b` — an invalid country code
   or `rfkill` block are the classic causes ([`BUILD.md`](BUILD.md#6-troubleshooting)
   §6).
3. Watchdog "budget exhausted" marker ([`RUNBOOK.md`](RUNBOOK.md#44-watchdog-storm-markers)
   §4.4): clean reboot once; if it returns, the radio (or card) is the
   suspect — §8.3.
4. Radio physically dead (lightning, moisture): replace the board.

**Portal loads but sync fails / messages do not travel.**

1. The phone is inside the OS's captive-portal mini-browser: open the full
   browser at `http://offgrid.local:8080` — this is quick-start
   troubleshooting step 1 for end users ([`quick-start.md`](quick-start.md)),
   and it is the same for you.
2. Node clock wrong (`date -u` on the console): a wrong clock silently
   filters "expired" mail ([`BUILD.md`](BUILD.md#6-troubleshooting) §6).
3. Store at the 5000-envelope cap: check `/status`
   ([`RUNBOOK.md`](RUNBOOK.md#2-reading-the-telemetry) §2.1) — the janitor
   reclaims it on its own; wait, never delete the database.

**Battery never reaches full.**

1. Panel shaded part of the day (new branch, new building, seasonal sun):
   re-do the §5.4 site check — this is the #1 real-world cause.
2. PSH overestimated for the season or soiling: wash the panel; recompute
   §5.2 with the real worst-month number.
3. Wrong controller profile (lead-acid profile undercharging the pack,
   §4.2 rule 1): set LiFePO4.
4. Failing battery (§8.2): measure the dark-morning voltage.
5. Corroded/loose MC4: wiggle + measure, replace the pair.

**Node dead after a storm.**

1. Fuses did their job: check the 15 A battery fuse first, then the 2 A.
   Replace with the same ratings only (§2.2).
2. Water ingress: open the box on a dry day, dry everything, find the
   path (gland, crack, capillary wicking), re-seal; if the Pi got wet,
   power it only after days of drying — then expect the worst and §8.3.
3. Surge-killed buck or controller: the panel line is the usual entry —
   replace the dead part (they are the cheapest parts in the box; the SPD
   of Tier 3 §2.1 exists for exactly this).
4. SD corruption from the power cut: the daemon quarantines a corrupt
   store by design ([`RUNBOOK.md`](RUNBOOK.md#43-quarantine-events-corrupt-db-evidence)
   §4.3) — keep the evidence, reflash if repeats (§4.6).
5. If all parts bench-test fine (§6.2 steps 1–7), suspect the cable run
   itself — storm-flicked branches love antenna-like cables.

---

## 10. Appendix: printable checklists and glossary

Both checklists print on one A4/Letter page each (short lines, no tables
spanning pages — same printable approach as [`quick-start.md`](quick-start.md)).

### 10.1 Printable shopping checklist

```
OFFGRID NODE — SHOPPING CHECKLIST          tier: [ ] minimal [ ] recommended [ ] robust
────────────────────────────────────────────────────────────────────────────────────
BOARD & BRAIN
[ ] Raspberry Pi Zero W (or newer, on-board Wi-Fi — pi-models.md)
[ ] microSD 16 GB, "industrial" or "high endurance" ON THE LABEL

POWER
[ ] Solar panel ___ W (12 V nominal, rigid mono; Voc < 25 V; §5.2 says ~20 W)
[ ] LiFePO4 4S 12.8 V ___ Ah, WITH BMS built in  (§4.3 says ~10 Ah for 3 days)
[ ] Charge controller 10 A, menu lists LiFePO4 14.6 V, manual lists
    LOW-TEMPERATURE CHARGE CUTOFF          <- the two non-negotiables (§2.2)
[ ] Buck converter 12 V -> 5 V, >= 3 A, idle < 1 mA

BOX & WIRING
[ ] Enclosure IP65+, UV-stable, with cable glands      [ ] drain hole planned
[ ] Cable 18 AWG red/black, ~5 m                       [ ] 4+ MC4 pairs
[ ] Fuse holder + 15 A fuse (battery main)             [ ] Fuse holder + 2 A fuse (load)
[ ] Heatshrink assortment                              [ ] zip ties, tape

BENCH (one-time tools, §1.2)
[ ] Multimeter            [ ] wire stripper     [ ] screwdrivers PH1/PH2
[ ] USB power meter       [ ] MC4 crimper or pre-crimped leads
[ ] soldering iron + heatshrink (if not pre-made)

SITE-SPECIFIC EXTRAS (§7)
[ ] forest: 2 tree straps 25-38 mm, rodent conduit, rubber buffer, silica gel
[ ] alpine: low-temp cutoff controller (mandatory), foam for battery, pole +
    U-bolts 316 stainless, guy kit, steep mount
[ ] desert: vent membranes or fully sealed plan, UV-rated cable, spare slack,
    cleaning brush, light-colored box
[ ] coastal: 316 stainless hardware, adhesive heatshrink, dielectric grease,
    IP66/67 box

SANITY BEFORE PAYING (§2.3)
[ ] battery Wh matches its weight (~100 Wh/kg) and BMS stated
[ ] controller MANUAL (not the ad) shows LiFePO4 + low-temp cutoff
[ ] panel Voc on the label < controller PV limit, area plausible for its W
────────────────────────────────────────────────────────────────────────────────────
```

### 10.2 Printable field-deployment checklist

```
OFFGRID NODE — FIELD DEPLOYMENT            site: ______________  date: __________
────────────────────────────────────────────────────────────────────────────────────
SITE (§7: your environment's section)
[ ] worst-month midday sun observed at the exact spot (§5.4)
[ ] mount above grass / snow / sand / water line, as the site demands
[ ] falling-branch / flood / drift check done
[ ] concealment decided (muted box, below sightlines, no geotags yet)

MOUNT (§7.1)
[ ] panel tilted ~ latitude (winter-biased +15 deg if no winter visit)
[ ] panel faces the equator; nothing shaded at any hour of the visit
[ ] enclosure in the panel's shade, glands DOWN, drain hole clear
[ ] drip loop on EVERY cable entering the box
[ ] straps/clamps tensioned; tree straps have growth slack; no nails in trees
[ ] rodent conduit / guy wires / stainless + grease, per environment

ELECTRICAL (§6)
[ ] battery fuse (15 A) and load fuse (2 A) both present
[ ] controller profile = LiFePO4; charge LED active in daylight
[ ] connectors dry-seated; no bare copper anywhere

POWER-ON & VALIDATE (§6.5 + hardware.md §8)
[ ] boot on PANEL ONLY (battery unplugged)  -> AP appears  -> battery reconnected
[ ] phone joins `offgrid-messages`, portal opens (full browser)
[ ] second phone: register both, send + sync a message BOTH WAYS
[ ] evening: controller shows net-positive charge  -> note %: ______
[ ] next morning: battery % (must be > 30)  -> note %: ______

LOG (inside the lid + your own notebook)
[ ] date, COUNTRY code, board/battery/panel serials
[ ] site photo (no geotags in the file), bench percentages of §6.5
[ ] planned revisit date (§8.1: monthly / seasonal / after storm season)
────────────────────────────────────────────────────────────────────────────────────
```

### 10.3 Glossary: the words you cannot avoid

Plain English, one line each. The doc that uses a word links back here.

- **BMS (Battery Management System)** — the small board inside a lithium
  battery that disconnects it before over-charge, over-discharge or a
  short. A lithium pack without a BMS must never be connected.
- **Buck converter** — the little module that turns the battery's ~12.8 V
  into the 5 V the Pi eats, wasting only ~10% on the way.
- **DoD (Depth of Discharge)** — how much of the battery you use. "80% DoD"
  means stopping with 20% still inside; stopping there roughly doubles the
  battery's life.
- **IP rating** — the two-digit seal quality of a box: first digit against
  dust (6 = tight), second against water (5 = jets, 6 = heavy seas,
  7 = brief dunking). "IP65" = dust-tight + jet-proof.
- **MC4** — the standard click-together weatherproof plug pair used on
  solar panel cables.
- **MPPT** — a charge-controller type that squeezes a bit more power out
  of the panel (worth it on big or cold sites; a plain PWM controller is
  fine at this node's size).
- **PSH (Peak Sun Hours)** — the number of hours per day of
  full-strength sun, averaged over a month. The sizing math uses the WORST
  month's number.
- **PWM** — the simpler charge-controller type; it connects the panel to
  the battery through a fast switch. Cheaper, fine at 20 W.
- **SoC (State of Charge)** — the battery's fuel gauge: "SoC 30%" means
  30% of the energy is still in the pack. The acceptance rule is that the
  node never goes below 30% overnight.
- **Voc (Open-Circuit Voltage)** — the voltage a panel shows with nothing
  connected. Your controller's input limit must be above the panel's Voc —
  under 25 V in this build.

---

*Master guide: `docs/install-node.md` (issue #35). Sizing reference:
[`hardware.md`](hardware.md) — where the two disagree, `hardware.md` wins.
This guide covers the Phase 1 Wi-Fi node; Phase 2 BLE (issue #32) and
Phase 3 LoRa backhaul (issue #33) will extend it later.*
