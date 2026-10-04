# Per-Model Deployment Guide — Every Raspberry Pi as a DTN Node

One daemon, one network stack, every board. This matrix maps each Raspberry
Pi variant to the OS image to flash, the `node/build.sh` binary to install
and the caveats that apply. The installation itself is identical everywhere:
`provision.sh` detects the board (`/proc/device-tree/model`) and the userland
ISA (`uname -m`), picks the right binary and installs the same
hostapd + dnsmasq + firewall + power-trim stack on all of them.

The **baseline target is the Raspberry Pi Zero W**: the cheapest board that
carries the full node (on-board Wi-Fi AP, 512 MB RAM) at the lowest power
draw. Every newer Pi runs the same node with more headroom.

## 1. Support matrix

| Board | SoC (ISA) | `uname -m` | OS image to flash | Binary | On-board Wi-Fi | Node class |
|---|---|---|---|---|---|---|
| **Pi Zero W / WH** | BCM2835 (ARMv6) | `armv6l` | OS **Lite 32-bit** (required) | `dtn-node-linux-armv6` | Yes (802.11n) | Baseline |
| Pi 1 A/B/A+/B+, CM1 | BCM2835 (ARMv6) | `armv6l` | OS **Lite 32-bit** | `dtn-node-linux-armv6` | **No — USB adapter** | Baseline |
| Pi Zero (v1.2/1.3) | BCM2835 (ARMv6) | `armv6l` | OS **Lite 32-bit** | `dtn-node-linux-armv6` | **No — USB adapter** | Baseline |
| Pi 2 B v1.1 | BCM2836 (ARMv7) | `armv7l` | OS Lite 32-bit | `dtn-node-linux-armv7` | **No — USB adapter** | Low |
| Pi 2 B v1.2 | BCM2837 (ARMv8) | `armv7l` (32-bit OS) or `aarch64` | OS Lite (either) | `armv7` / `arm64` | **No — USB adapter** | Low |
| Pi Zero 2 W | BCM2710A1 (ARMv8) | `aarch64` (64-bit OS) or `armv7l` | OS Lite **64-bit** (recommended) | `dtn-node-linux-arm64` | Yes (802.11n) | Low |
| Pi 3 B / B+ / A+ | BCM2837/2837B0 (ARMv8) | `aarch64` | OS Lite 64-bit | `dtn-node-linux-arm64` | Yes (802.11n/ac on B+) | Medium |
| Pi 4 B / Pi 400 | BCM2711 (ARMv8) | `aarch64` | OS Lite 64-bit | `dtn-node-linux-arm64` | Yes (802.11ac) | High |
| Pi 5 | BCM2712 (ARMv8) | `aarch64` | OS Lite 64-bit (Bookworm) | `dtn-node-linux-arm64` | Yes (802.11ac) | High |
| CM3 / CM3+ (wireless variants) | BCM2837 (ARMv8) | `aarch64` | OS Lite 64-bit | `dtn-node-linux-arm64` | Only `-W` variants | Medium |
| CM4 / CM5 | BCM2711/2712 (ARMv8) | `aarch64` | OS Lite 64-bit | `dtn-node-linux-arm64` | Only Wi-Fi SKUs | High |

Rules that hold for every row:

- **ARMv6 boards (Pi Zero W, Pi 1, CM1, plain Zero) can only run a 32-bit
  OS**, which reports `armv6l`; they must get the `armv6` binary. A GOARM=7
  binary aborts there with `Illegal instruction`.
- A 64-bit-capable board **flashed with a 32-bit OS** reports `armv7l` and
  gets the `armv7` binary — both combinations work; pick one OS and stay
  with it.
- The node constant set is identical everywhere: open AP `offgrid-messages`
  on channel 6, gateway `10.42.0.1/24`, canonical origin
  `http://offgrid.local:8080` (protocol spec §12). A mule must not be
  able to tell which board model is behind the SSID.

## 2. Installation

Identical on every model — see `docs/BUILD.md` §5 for the full walkthrough.

1. **Online, one line** (on the Pi, needs Internet once):

   ```bash
   curl -fsSL https://raw.githubusercontent.com/juliangt/offgrid/main/raspberry/install.sh \
     | sudo bash -s -- --country AR
   ```

2. **Offline, USB stick / SD card** (copy the release assets onto the drive,
   then on the Pi):

   ```bash
   sudo ./install.sh --offline /media/usb --country AR
   ```

3. **Manual** (build + `scp` + `provision.sh`): `docs/BUILD.md` §5.

In all three cases provisioning never starts services: **the reboot is the
activation step**, and the post-reboot checklist is `docs/BUILD.md` §5.4.

## 3. Wi-Fi caveats per board

- **On-board radios** (Zero W, Zero 2 W, 3/3B+/3A+, 4/400, 5, `-W` compute
  modules) are brcmfmac devices: they support AP mode, `ap_isolate=1` and the
  fixed channel 6 configuration as shipped — no extra firmware steps.
- **Boards without on-board Wi-Fi** (Pi 1/2, plain Zero, non-Wi-Fi CM SKUs)
  need a USB Wi-Fi adapter that (a) supports **master (AP) mode**, (b) is
  driven by an **nl80211** driver, and (c) lands on `wlan0`. Check a candidate
  before buying/deploying:

  ```bash
  iw list | grep -A8 'Supported interface modes'   # must list "* AP"
  ```

  Chipsets known to work well with hostapd on Raspberry Pi OS include the
  Atheros ath9k_htc family and several RTL8188/8192-based adapters; avoid
  adapters that only do P2P-GO (many Realtek client-focused dongles). If the
  adapter enumerates as something other than `wlan0`, rename it with a
  systemd `.link` file or udev rule — `hostapd.conf`, the ifupdown stanza and
  the firewall rules all reference `wlan0` by design.
- **Dual-band radios** (3B+, 4, 5): the node stays on 2.4 GHz channel 6 for
  maximum client compatibility and wall penetration; do not "upgrade" the
  config to 5 GHz — clients discover the portal through the captive-probe
  flow and older phones are 2.4 GHz-only.

## 4. Performance and power expectations

The daemon does no cryptography (all crypto is client-side) and its dataset
is tiny (≤ 5000 envelopes ≈ ≤ 5 MB, spec §8.1), so even the single-core
ARMv6 baseline serves portal pages and sync bursts comfortably; the watchdog
ceiling is relaxed from 30 s to 60 s on these boards by `provision.sh`
because one core is more easily starved than four.

| Board class | Example | Typical draw, node trimmed (HDMI/LEDs/BT off) | Sync burst feel |
|---|---|---|---|
| Baseline (ARMv6, 1 core) | **Zero W**, Pi 1 | ~0.6–0.8 W idle; ~1 W with clients | instant for portal; a 100-envelope push in ~1–2 s |
| Low (4× A53, 512 MB) | Zero 2 W, Pi 2 v1.2 | ~0.7–0.9 W idle; spikes ~2 W | instant; push well under 1 s |
| Medium | Pi 3, CM3 | ~1.2–2 W idle | instant |
| High | Pi 4/400, 5, CM4/CM5 | ~2–3 W idle | instant (headroom unused by Phase 1) |

For the solar + LiFePO4 sizing, `docs/hardware.md` §2 uses a 1 W design
load: it covers the **Zero W and Zero 2 W directly**; bigger boards raise the
`E_load` input of the same formulas (a Pi 4 node roughly doubles the panel
and battery sizing, with no benefit for the Phase 1 workload). Always fill in
the `docs/hardware.md` §9 measurement table for the actual board deployed.

Notes on the power-trim snippet (`raspberry/power/config.txt.snippet`): lines
that have no counterpart on a given board (`dtparam=audio=off` on Pi 5, which
has no analog audio; the LED dtparams on Pi 5, which has a single power LED;
`dtoverlay=disable-bt` on boards without the BT controller it targets) are
ignored harmlessly by the firmware — the same snippet ships to every model.

## 5. Which OS image, exactly

- **Raspberry Pi OS Lite** (no desktop) — the node is headless; the desktop
  stack would fight hostapd for the radio and waste the power budget.
- **Bookworm** (current stable) — what `provision.sh` expects: it switches
  NetworkManager to the classic ifupdown stack when present (plan §1.6).
- **32-bit** for ARMv6 boards (Zero W, Pi 1, CM1, plain Zero — there is no
  64-bit option); **64-bit** for everything else.
- Flash with the official Raspberry Pi Imager; enable SSH in the Imager's
  customization only if you plan the `ALLOW_SSH=1` variant — the node itself
  does not need it. Run the installer from a LOCAL console (keyboard +
  monitor or serial), not over NetworkManager Wi-Fi: provisioning disables
  and masks NetworkManager by design.
