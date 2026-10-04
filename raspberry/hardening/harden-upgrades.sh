#!/usr/bin/env bash
# harden-upgrades.sh — self-applying SECURITY patches for the off-grid DTN
# dead-drop node (Module A, issue #16 Track 3).
# Repo path : raspberry/hardening/harden-upgrades.sh
# Install   : /usr/local/sbin/dtn-harden-upgrades.sh (provision.sh, step 8)
# Idempotent: package state and config files are check-then-act.
#
# Usage:
#   dtn-harden-upgrades.sh            apply (root)
#   dtn-harden-upgrades.sh --dry-run  print exactly what apply WOULD do — no
#                                     packages, no config writes (rootless-
#                                     safe; what tests/hardening_structure.sh
#                                     exercises)
#
# THE TRADE-OFF (stated so a future reader can re-litigate it): a solar field
# node has no operator on call, so CVE fixes must install THEMSELVES or they
# will not happen. But this node is also a working appliance whose protocol
# and binary are versioned artifacts (docs/protocol.md §15): an unattended
# FEATURE update could change behavior mid-deployment and fragment the fleet.
# The configuration below therefore takes ONLY the Debian/Raspberry Pi
# security pools ("SECURITY-ONLY"): the base OS, hostapd, dnsmasq and the
# kernel get vulnerability fixes automatically; the dtn-node daemon itself is
# NOT an apt package and is never touched — its updates stay MANUAL via
# raspberry/install.sh (or node/build.sh + provision.sh), which is the
# intentional upgrade path for everything that speaks the protocol.
#
# What the operator gives up with security-only: non-security bugfix releases
# (e.g. a dnsmasq regression fix without a CVE) wait for the next manual
# maintenance visit. Accepted: a parked, isolated AP regresses far less often
# than it gets CVE'd.

set -euo pipefail

APT_CONF_DIR="${APT_CONF_DIR:-/etc/apt/apt.conf.d}"
SECURITY_OVERRIDE="${APT_CONF_DIR}/52dtn-security-only.conf"
AUTO_UPGRADES="${APT_CONF_DIR}/20auto-upgrades"

DRY_RUN=0
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        -h | --help)
            sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//; /^$/d; /Usage:/q' | head -n 20
            exit 0
            ;;
        *)
            echo "harden-upgrades: ERROR: unknown option '$arg' (usage: harden-upgrades.sh [--dry-run])" >&2
            exit 1
            ;;
    esac
done

log() { echo "harden-upgrades: $*"; }
die() { echo "harden-upgrades: ERROR: $*" >&2; exit 1; }

if [ "$DRY_RUN" = "1" ]; then
    if command -v dpkg >/dev/null 2>&1 && dpkg -s unattended-upgrades >/dev/null 2>&1; then
        log "[dry-run] unattended-upgrades package already installed"
    else
        log "[dry-run] would install package: unattended-upgrades"
    fi
    log "[dry-run] would write $SECURITY_OVERRIDE (security-only Origins-Pattern via #clear + label=Debian-Security / Raspberry Pi security pools)"
    log "[dry-run] would ensure $AUTO_UPGRADES carries Update-Package-Lists=1 + Unattended-Upgrade=1"
    log "[dry-run] would enable apt-daily-upgrade.timer + unattended-upgrades.service (activation: reboot, per provisioning discipline)"
    exit 0
fi

[ "$(id -u)" -eq 0 ] || die "must run as root (installs packages and writes /etc/apt); try --dry-run"

# --- 1. package ---------------------------------------------------------------

if command -v dpkg >/dev/null 2>&1 && dpkg -s unattended-upgrades >/dev/null 2>&1; then
    log "unattended-upgrades package already installed"
else
    if ! command -v apt-get >/dev/null 2>&1; then
        die "apt-get not found: this script targets Raspberry Pi OS (Debian)"
    fi
    DEBIAN_FRONTEND=noninteractive apt-get install -y unattended-upgrades >/dev/null
    log "installed unattended-upgrades"
fi
dpkg -s unattended-upgrades >/dev/null 2>&1 || die "post-check failed: unattended-upgrades not installed"

# --- 2. security-only override ------------------------------------------------
#
# File number >50 so it parses AFTER the stock 50unattended-upgrades. APT
# config lists are last-writer-wins per slot, so this file first #clears the
# Origins-Pattern the distro shipped (apt.conf(5)'s directive for wiping a
# list) and then pins exactly the pools below. That makes the effective
# origin set deterministic regardless of what the stock
# 50unattended-upgrades enables by default (it has changed across releases;
# the field unit must not depend on it).
#
# Origins kept:
#   * Debian security pool (label=Debian-Security, matched by codename so it
#     tracks ${distro_codename}-security automatically) — base OS + the
#     packages Debian ships;
#   * the Raspberry Pi archive by site — the firmware/kernel/hostapd packages
#     that matter on a Pi come from archive.raspberrypi.com, not from Debian,
#     and skipping them would leave exactly the radios unpatched.
# Everything else (backports, stable-updates feature streams, proposed) is
# deliberately NOT in the list: see the trade-off note in the header.
mkdir -p "$APT_CONF_DIR"
cat > "$SECURITY_OVERRIDE" <<'EOF'
// Managed by raspberry/hardening/harden-upgrades.sh (issue #16 Track 3).
// SECURITY-ONLY override — see that script's header for the trade-off.
// The #clear wipes any Origins-Pattern from 50unattended-upgrades so the
// list below is the complete, deterministic origin set.
#clear Unattended-Upgrade::Origins-Pattern;
Unattended-Upgrade::Origins-Pattern {
    "origin=Debian,codename=${distro_codename},label=Debian-Security";
    "site=archive.raspberrypi.com";
};
// A field node reboots on the OPERATOR's schedule only (power is scarce and
// the reboot is this node's activation step — never let a package bump
// reboot the AP under users).
Unattended-Upgrade::Automatic-Reboot "false";
// Keep unused packages: disk is plentiful (8-16 GB, docs/hardware.md), and
// removals are the riskier half of an unattended run on an isolated node.
Unattended-Upgrade::Remove-Unused-Dependencies "false";
Unattended-Upgrade::Remove-New-Unused-Dependencies "false";
EOF
log "security-only override written: $SECURITY_OVERRIDE"

# --- 3. periodic enablement ---------------------------------------------------
#
# 20auto-upgrades is what turns the apt daily timers into actual upgrade
# runs (the package ships it only in interactive installs). Write it only
# when missing or wrong — never clobber an operator's deliberate choices.
expected_20='APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";'
if [ -f "$AUTO_UPGRADES" ] && cmp -s <(printf '%s\n' "$expected_20") "$AUTO_UPGRADES"; then
    log "$AUTO_UPGRADES already enables daily unattended upgrades"
else
    if [ -f "$AUTO_UPGRADES" ]; then
        cp -a "$AUTO_UPGRADES" "$AUTO_UPGRADES.dtn-bak"
        log "backed up existing $AUTO_UPGRADES to $AUTO_UPGRADES.dtn-bak"
    fi
    printf '%s\n' "$expected_20" > "$AUTO_UPGRADES"
    log "periodic upgrade switch written: $AUTO_UPGRADES"
fi

# --- 4. enable the machinery (activation = next reboot, like every unit here)

systemctl enable apt-daily-upgrade.timer >/dev/null 2>&1 || true
systemctl enable unattended-upgrades.service >/dev/null 2>&1 || true
log "enabled: apt-daily-upgrade.timer + unattended-upgrades.service (they run from the next boot on)"

log "OK — security patches apply themselves; protocol/binary updates stay manual via install.sh"
