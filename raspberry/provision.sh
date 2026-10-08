#!/usr/bin/env bash
# provision.sh — idempotent provisioning of a Raspberry Pi as an
# off-grid DTN dead-drop node (Module A, Sprint 3).
# Supports every Pi with on-board Wi-Fi (Zero W, Zero 2 W, 3A+/3B+, 4, 400,
# 5); boards without on-board Wi-Fi (Pi 1/2, most CM variants) work the same
# through an AP-capable USB Wi-Fi adapter on wlan0 (docs/pi-models.md).
# Install path: run ON THE PI as root (or via sudo). Also committed here for
# review. Config files are read from this script's directory tree:
#
#   hostapd/hostapd.conf        -> /etc/hostapd/hostapd.conf
#   dnsmasq/dnsmasq.conf        -> /etc/dnsmasq.conf
#   firewall/iptables.sh        -> /usr/local/sbin/dtn-firewall.sh
#   firewall/dns-shield.sh      -> /usr/local/sbin/dtn-dns-shield.sh
#   firewall/station-shield.sh  -> /usr/local/sbin/dtn-station-shield.sh
#   firewall/traffic-shaping.sh -> /usr/local/sbin/dtn-traffic-shaping.sh
#   firewall/dtn-firewall.service -> /etc/systemd/system/dtn-firewall.service
#   firewall/dtn-traffic-shaping.service -> /etc/systemd/system/dtn-traffic-shaping.service
#   firewall/dtn-dns-shield.service -> /etc/systemd/system/dtn-dns-shield.service
#   firewall/dtn-dns-shield.timer   -> /etc/systemd/system/dtn-dns-shield.timer
#   firewall/dtn-station-shield.service -> /etc/systemd/system/dtn-station-shield.service
#   firewall/dtn-station-shield.timer   -> /etc/systemd/system/dtn-station-shield.timer
#   power/config.txt.snippet    -> appended to /boot/firmware/config.txt (Bookworm)
#                                  or /boot/config.txt (legacy), once only
#   power/dtn-power.service     -> /etc/systemd/system/dtn-power.service
#   systemd/dtn-node.service    -> /etc/systemd/system/dtn-node.service
#   hardening/sshd-hardening.conf -> /usr/local/sbin/dtn-sshd-hardening.conf
#                                  (staged; harden-ssh.sh installs it to
#                                  /etc/ssh/sshd_config.d/00-dtn-hardening.conf)
#   hardening/harden-ssh.sh     -> /usr/local/sbin/dtn-harden-ssh.sh (run in step 8)
#   hardening/harden-services.sh -> /usr/local/sbin/dtn-harden-services.sh (step 8)
#   hardening/harden-upgrades.sh -> /usr/local/sbin/dtn-harden-upgrades.sh (step 8)
#   hardening/dtn-network-watchdog.sh -> /usr/local/sbin/dtn-network-watchdog.sh
#   hardening/dtn-network-watchdog.service -> /etc/systemd/system/
#   hardening/dtn-network-watchdog.timer   -> /etc/systemd/system/
#   hardening/dtn-telemetry.sh  -> /usr/local/sbin/dtn-telemetry.sh
#   hardening/dtn-telemetry.service -> /etc/systemd/system/
#   hardening/dtn-telemetry.timer   -> /etc/systemd/system/
#   hardening/enable-readonly-root.sh  -> /usr/local/sbin/dtn-enable-readonly-root.sh
#                                         (staged only — NEVER run by provision,
#                                         see the Track 3 note below)
#   hardening/disable-readonly-root.sh -> /usr/local/sbin/dtn-disable-readonly-root.sh
#   ../node/dtn-node-linux-arm64|armv7|armv6 -> /opt/dtn-node/dtn-node
#                                 (picked by uname -m: aarch64/armv7l/armv6l)
#   nodeid/node.seed           -> /opt/dtn-node/nodeid/node.seed (0600, optional
#                                 node-identity kit; absent kit = explicit SKIP,
#                                 docs/node-network.md §2.6)
#   nodeid/node_cert.cbor      -> /opt/dtn-node/nodeid/node_cert.cbor (0644)
#   nodeid/anchor.pub          -> /opt/dtn-node/nodeid/anchor.pub (0644)
#
# DESIGN RULES
#   * Strictly idempotent: every step first checks whether its result already
#     holds and verifies it afterwards ([OK]/[FAIL] per step, fail-fast).
#   * NEVER starts the portal services. A reboot is the activation step: it
#     brings up hostapd + dnsmasq + dtn-firewall + dtn-node + dtn-power in the
#     boot order already encoded in the unit files, without tearing down the
#     operator's console mid-run.
#   * Run this from a LOCAL console (keyboard+monitor or serial), not over a
#     NetworkManager-managed Wi-Fi session: on Bookworm the script stops and
#     masks NetworkManager, which would drop such a session.
#
# Customization:
#   COUNTRY=AR ./provision.sh   # regulatory country written into hostapd.conf
#   ALLOW_SSH=1 ./provision.sh  # firewall accepts SSH from AP clients (off by default)
#
# Issue #16 Track 3 note: the read-only-root feature is deliberately NOT
# wired here (it changes the boot path and every later config change needs a
# remount cycle). It is an explicit operator step on the provisioned Pi:
#   sudo /usr/local/sbin/enable-readonly-root.sh   # then reboot; --dry-run/--status available
# (enable-readonly-root.sh / disable-readonly-root.sh live in
# raspberry/hardening/ and are documented for manual deployment — their
# default is OFF.)
#
# See docs/DEVELOPMENT_PLAN.md §1.6 (NetworkManager vs classic stack — BINDING
# DECISION), §5 Sprint 3 and docs/protocol.md §12 (canonical origin).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

COUNTRY="${COUNTRY:-AR}"
export ALLOW_SSH="${ALLOW_SSH:-0}"
NODE_USER="dtn"
NODE_GROUP="dtn"
DATA_DIR="/var/lib/dtn-node"
INSTALL_DIR="/opt/dtn-node"
# Detected in preflight; consulted by the unit-file generator (watchdog
# ceiling) and by install_binary (binary selection).
BOARD_MODEL="unknown"
BOARD_ARCH="$(uname -m)"

log() { echo "provision: $*"; }
die() { echo "provision: ERROR: $*" >&2; exit 1; }

# verify DESC CMD [ARGS...] — run CMD silently; print [OK] or [FAIL] and abort.
verify() {
    local desc="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        echo "[OK]   $desc"
    else
        echo "[FAIL] $desc" >&2
        exit 1
    fi
}

# verify_not DESC CMD [ARGS...] — inverse: CMD must FAIL for the step to pass.
verify_not() {
    local desc="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        echo "[FAIL] $desc" >&2
        exit 1
    else
        echo "[OK]   $desc"
    fi
}

# install_file SRC DEST MODE — copy SRC to DEST (with MODE) unless DEST is
# byte-identical; back up a differing DEST to DEST.dtn-bak first. Fails the
# whole script on any real error (set -e); a no-op just logs [SKIP].
install_file() {
    local src="$1" dest="$2" mode="$3"
    if [ -f "$dest" ] && cmp -s "$src" "$dest"; then
        echo "[SKIP] $dest already up to date"
        return 0
    fi
    if [ -f "$dest" ]; then
        cp -a "$dest" "$dest.dtn-bak"
        log "backed up existing $dest to $dest.dtn-bak"
    fi
    install -m "$mode" "$src" "$dest"
}

# --- step 1: preflight --------------------------------------------------------

preflight() {
    log "step 1/11: preflight"
    verify "running as root" test "$(id -u)" -eq 0
    verify "Raspberry Pi hardware" grep -q "Raspberry Pi" /proc/device-tree/model
    verify "OS release file present" test -f /etc/os-release
    BOARD_MODEL="$(tr -d '\0' < /proc/device-tree/model)"

    # The kernel reports the userland ISA, which is what the binary must
    # match (a 64-bit board flashed with a 32-bit OS reports armv7l here, a
    # Zero W / Pi 1 always armv6l).
    case "$BOARD_ARCH" in
        aarch64 | armv7l | armv6l) ;;
        *) die "unsupported architecture '$BOARD_ARCH' (need aarch64, armv7l or armv6l)" ;;
    esac
    log "board: $BOARD_MODEL (userland: $BOARD_ARCH)"

    # shellcheck disable=SC1091  # /etc/os-release is a standard conformance file
    . /etc/os-release
    log "detected Raspberry Pi OS codename: ${VERSION_CODENAME:-unknown}"

    # The regulatory country must be a clean two-letter code: it is spliced
    # into hostapd.conf with sed below.
    if ! [[ "$COUNTRY" =~ ^[A-Z]{2}$ ]]; then
        die "COUNTRY='$COUNTRY' is invalid: pass a two-letter code, e.g. COUNTRY=AR"
    fi
    verify "preflight complete" true
}

# --- step 2: NetworkManager -> classic ifupdown stack (Bookworm only) ---------

# BINDING DECISION (plan §1.6): Bookworm's NetworkManager cannot run the
# hostapd+dnsmasq classic stack (and its wpa_supplicant AP mode has no
# ap_isolate), so it is disabled and masked and ifupdown is installed instead.
# Legacy (dhcpcd-based) images already use the classic stack: nothing to do.
disable_networkmanager() {
    log "step 2/11: network manager selection"
    if ! systemctl cat NetworkManager.service >/dev/null 2>&1; then
        log "no NetworkManager unit: legacy stack in place, nothing to do"
        verify_not "NetworkManager absent" systemctl cat NetworkManager.service
        return 0
    fi
    log "NetworkManager found — disabling and masking it (plan §1.6)"
    log "WARNING: if your session rides on an NM-managed interface it will drop NOW."
    systemctl disable --now NetworkManager.service
    systemctl mask NetworkManager.service
    DEBIAN_FRONTEND=noninteractive apt-get install -y ifupdown >/dev/null
    verify "NetworkManager masked" test "$(systemctl is-enabled NetworkManager.service 2>/dev/null)" = "masked"
    verify "ifupdown installed" dpkg -s ifupdown
}

# --- step 3: packages ---------------------------------------------------------

install_packages() {
    log "step 3/11: packages"
    apt-get update -qq >/dev/null
    # hostapd (AP), dnsmasq (DHCP+DNS), iptables (firewall), iw (used by the
    # post-up power_save line in interfaces.d/wlan0).
    DEBIAN_FRONTEND=noninteractive apt-get install -y hostapd dnsmasq iptables iw >/dev/null
    # dnsutils + curl (issue #16 Track 3): the network watchdog's probes —
    # a dig against the node's own AP address and the canonical-origin
    # captive-probe curl — and the operator checklist's verification tools.
    DEBIAN_FRONTEND=noninteractive apt-get install -y dnsutils curl >/dev/null
    # Optional persistence: when present, dtn-firewall.sh saves rules.v4 for
    # netfilter-persistent to replay at boot; otherwise dtn-firewall.service
    # re-applies the rules itself on every boot.
    if ! dpkg -s netfilter-persistent >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y netfilter-persistent iptables-persistent >/dev/null 2>&1 \
            || log "netfilter-persistent unavailable; dtn-firewall.service will re-apply rules at boot"
    fi
    verify "hostapd installed" dpkg -s hostapd
    verify "dnsmasq installed" dpkg -s dnsmasq
    verify "iptables installed" dpkg -s iptables
    verify "iw installed" dpkg -s iw
    verify "dnsutils installed (watchdog dig probe)" dpkg -s dnsutils
    verify "curl installed (watchdog portal probe)" dpkg -s curl
    # Raspberry Pi OS ships hostapd masked (it would conflict with the default
    # client mode); unmask so it can be enabled for boot.
    systemctl unmask hostapd
    verify "hostapd not masked" test "$(systemctl is-enabled hostapd.service 2>/dev/null)" != "masked"
    if command -v rfkill >/dev/null 2>&1; then
        rfkill unblock wifi
        verify "wifi rfkill-unblocked" rfkill list wifi
    else
        log "rfkill not installed: nothing to unblock"
    fi
}

# --- step 4: static IP on wlan0 ------------------------------------------------

# The node is 10.42.0.1/24 on every deployment — a fixed constant of the
# same-origin design (docs/protocol.md §12: all nodes must share the
# gateway IP). Wi-Fi power save stays OFF for AP beacon stability.
static_ip() {
    log "step 4/11: static IP 10.42.0.1/24 on wlan0"
    local tmp
    tmp="$(mktemp)"
    cat > "$tmp" <<'EOF'
# Managed by provision.sh (off-grid DTN node). Static address of the isolated
# AP subnet; 10.42.0.1 is the router and DNS that dnsmasq advertises and the
# gateway IP of the canonical origin (docs/protocol.md §12).
auto wlan0
iface wlan0 inet static
    address 10.42.0.1/24
    # AP stability: the radio must never enter power-save (dropped beacons).
    post-up iw dev wlan0 set power_save off
EOF
    install_file "$tmp" /etc/network/interfaces.d/wlan0 0644
    rm -f "$tmp"
    verify "wlan0 stanza installed" grep -q "address 10.42.0.1/24" /etc/network/interfaces.d/wlan0

    # Canonical minimal /etc/network/interfaces: loopback + source the .d dir.
    # This also removes any legacy wlan0 stanza (e.g. dhcpcd/wpa-roam lines)
    # that would fight the static config; the original is kept as .dtn-bak.
    tmp="$(mktemp)"
    cat > "$tmp" <<'EOF'
# Managed by provision.sh (off-grid DTN node): loopback only; wlan0 is
# configured in /etc/network/interfaces.d/wlan0.
auto lo
iface lo inet loopback

source /etc/network/interfaces.d/*
EOF
    install_file "$tmp" /etc/network/interfaces 0644
    rm -f "$tmp"
    verify "interfaces sources .d directory" grep -q "source /etc/network/interfaces.d" /etc/network/interfaces

    # IPv6 is DISABLED on the client-facing interfaces (audit finding PI-01,
    # docs/security-audit.md §4). The canonical origin is IPv4 by design
    # (10.42.0.1, docs/protocol.md §12) and the entire Track-1 shield set —
    # the per-source DNS/ICMP/portal hashlimits, the connlimit and the
    # DTN_DNSBL shed chain — is iptables (IPv4) only. With IPv6 left enabled,
    # wlan0 auto-configures a link-local address and an associated station
    # could reach dnsmasq and the portal daemon over fe80::/10, which NO
    # firewall rule sees: every per-source shed bypassable. `default` covers
    # interfaces created after this file loads; wlan0/eth0 are named because
    # they typically already exist (per-interface settings win at load time).
    # Loopback keeps its IPv6 (nothing in this repo uses ::1, but disabling
    # the whole stack is a bigger hammer than the finding needs).
    tmp="$(mktemp)"
    cat > "$tmp" <<'EOF'
# Managed by provision.sh (off-grid DTN node) — audit finding PI-01.
# IPv6 off on every client-facing interface: the island is IPv4-only
# (canonical origin 10.42.0.1, protocol §12) and the Track-1 shields are
# IPv4-only, so a live link-local address would be an unaudited side door.
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.wlan0.disable_ipv6 = 1
net.ipv6.conf.eth0.disable_ipv6 = 1
EOF
    install_file "$tmp" /etc/sysctl.d/99-dtn-island.conf 0644
    rm -f "$tmp"
    verify "sysctl: IPv6 disabled on wlan0 (no unshielded v6 side door)" \
        grep -q '^net\.ipv6\.conf\.wlan0\.disable_ipv6 = 1$' /etc/sysctl.d/99-dtn-island.conf
    verify "sysctl: IPv6 disabled by default for future interfaces" \
        grep -q '^net\.ipv6\.conf\.default\.disable_ipv6 = 1$' /etc/sysctl.d/99-dtn-island.conf
    # Apply now when the interfaces already exist (the reboot would load the
    # file anyway; loading early closes the pre-reboot window). Missing
    # interfaces (a Pi without Ethernet) are tolerated: the file persists and
    # applies at boot for the ones that exist.
    sysctl -q -p /etc/sysctl.d/99-dtn-island.conf >/dev/null 2>&1 || \
        log "sysctl apply deferred (an interface may not exist yet): the file loads at reboot"

    # wpa_supplicant must not grab wlan0 back (client mode or wpa-roam hooks).
    if systemctl cat 'wpa_supplicant@.service' >/dev/null 2>&1; then
        systemctl disable wpa_supplicant.service >/dev/null 2>&1 || true
        systemctl mask 'wpa_supplicant@wlan0.service'
        verify "wpa_supplicant@wlan0 masked" \
            test "$(systemctl is-enabled 'wpa_supplicant@wlan0.service' 2>/dev/null)" = "masked"
    else
        log "wpa_supplicant not installed: nothing to mask"
    fi
    # Legacy images run dhcpcd, which would also fight the static address.
    systemctl disable --now dhcpcd.service >/dev/null 2>&1 || true
}

# --- step 5: config files -------------------------------------------------------

install_configs() {
    log "step 5/11: config files"
    local tmp
    tmp="$(mktemp)"

    # hostapd with the deployment country spliced in (defaults to AR).
    sed "s/^country_code=.*/country_code=${COUNTRY}/" "$SCRIPT_DIR/hostapd/hostapd.conf" > "$tmp"
    install_file "$tmp" /etc/hostapd/hostapd.conf 0644
    rm -f "$tmp"
    verify "hostapd.conf installed" grep -q "^ssid=offgrid-messages$" /etc/hostapd/hostapd.conf
    verify "hostapd country_code=${COUNTRY}" grep -q "^country_code=${COUNTRY}$" /etc/hostapd/hostapd.conf

    install_file "$SCRIPT_DIR/dnsmasq/dnsmasq.conf" /etc/dnsmasq.conf 0644
    verify "dnsmasq.conf installed" grep -q "^address=/#/10.42.0.1$" /etc/dnsmasq.conf

    install_file "$SCRIPT_DIR/firewall/iptables.sh" /usr/local/sbin/dtn-firewall.sh 0755
    verify "dtn-firewall.sh installed" test -x /usr/local/sbin/dtn-firewall.sh

    # Issue #16 Track 1 shields and shaping: installed next to dtn-firewall.sh
    # in /usr/local/sbin, wired to systemd below. All three are --dry-run /
    # --print capable and never mutate anything outside the kernel + tmpfs.
    install_file "$SCRIPT_DIR/firewall/dns-shield.sh" /usr/local/sbin/dtn-dns-shield.sh 0755
    verify "dtn-dns-shield.sh installed" test -x /usr/local/sbin/dtn-dns-shield.sh
    install_file "$SCRIPT_DIR/firewall/station-shield.sh" /usr/local/sbin/dtn-station-shield.sh 0755
    verify "dtn-station-shield.sh installed" test -x /usr/local/sbin/dtn-station-shield.sh
    install_file "$SCRIPT_DIR/firewall/traffic-shaping.sh" /usr/local/sbin/dtn-traffic-shaping.sh 0755
    verify "dtn-traffic-shaping.sh installed" test -x /usr/local/sbin/dtn-traffic-shaping.sh

    # Fire the firewall once now: it is session-safe (it only adds accepts and
    # a REDIRECT — nothing is dropped, the INPUT policy is left untouched), it
    # validates the ruleset on real hardware and, when netfilter-persistent is
    # present, it saves /etc/iptables/rules.v4 in the same stroke. The portal
    # services themselves stay stopped.
    /usr/local/sbin/dtn-firewall.sh
    verify "REDIRECT hook active" iptables -t nat -C PREROUTING -i wlan0 -j DTN_PORTAL
    verify "REDIRECT 80->8080 active" iptables -t nat -C DTN_PORTAL -p tcp --dport 80 -j REDIRECT --to-ports 8080
    verify "FORWARD policy DROP" test "$(iptables -S FORWARD | head -n 1)" = "-P FORWARD DROP"
    verify "shield chains created" iptables -nL DTN_DNSBL

    # Traffic shaping: applied now only if the AP interface already exists
    # (session-safe — qdiscs on wlan0 do not touch an operator's console);
    # otherwise dtn-traffic-shaping.service puts it in place at boot.
    if command -v tc >/dev/null 2>&1 && ip link show wlan0 >/dev/null 2>&1; then
        /usr/local/sbin/dtn-traffic-shaping.sh
        verify "cake qdisc active on wlan0" bash -c 'tc qdisc show dev wlan0 | grep -q cake'
    else
        log "wlan0/tc not available during provisioning: shaping applies at boot (dtn-traffic-shaping.service)"
    fi

    # Boot config snippet: Bookworm mounts the firmware partition at
    # /boot/firmware, legacy images at /boot. Append once, marker-guarded.
    local boot_cfg
    if [ -d /boot/firmware ]; then
        boot_cfg="/boot/firmware/config.txt"
    else
        boot_cfg="/boot/config.txt"
    fi
    verify "boot config present" test -f "$boot_cfg"
    if grep -q "dtn-node power snippet" "$boot_cfg"; then
        echo "[SKIP] $boot_cfg already carries the power snippet"
    else
        {
            echo ""
            echo "# --- dtn-node power snippet (added by provision.sh) ---"
            cat "$SCRIPT_DIR/power/config.txt.snippet"
        } >> "$boot_cfg"
        verify "power snippet appended" grep -q "dtn-node power snippet" "$boot_cfg"
    fi

    # The daemon unit is generated from its template so the watchdog ceiling
    # can be tuned per board class. On a single-core ARMv6 board (Pi Zero W,
    # Pi 1) the 15 s ping cadence (WatchdogSec/2) can be starved during a GC
    # + SQLite checkpoint burst, so the ceiling is doubled there; the
    # template value (30 s) stays for every multi-core board.
    local node_unit_tmp
    if [ "$BOARD_ARCH" = "armv6l" ]; then
        node_unit_tmp="$(mktemp)"
        sed 's/^WatchdogSec=30$/# Doubled for this single-core ARMv6 board (provision.sh): the\n# WatchdogSec\/2 ping cadence needs headroom against GC + checkpoint bursts.\nWatchdogSec=60/' \
            "$SCRIPT_DIR/systemd/dtn-node.service" > "$node_unit_tmp"
        log "single-core board: WatchdogSec relaxed to 60 in the installed unit"
    else
        node_unit_tmp="$SCRIPT_DIR/systemd/dtn-node.service"
    fi
    install_file "$node_unit_tmp" /etc/systemd/system/dtn-node.service 0644
    if [ "$node_unit_tmp" != "$SCRIPT_DIR/systemd/dtn-node.service" ]; then
        rm -f "$node_unit_tmp"
    fi
    install_file "$SCRIPT_DIR/firewall/dtn-firewall.service" /etc/systemd/system/dtn-firewall.service 0644
    install_file "$SCRIPT_DIR/firewall/dtn-traffic-shaping.service" /etc/systemd/system/dtn-traffic-shaping.service 0644
    install_file "$SCRIPT_DIR/firewall/dtn-dns-shield.service" /etc/systemd/system/dtn-dns-shield.service 0644
    install_file "$SCRIPT_DIR/firewall/dtn-dns-shield.timer" /etc/systemd/system/dtn-dns-shield.timer 0644
    install_file "$SCRIPT_DIR/firewall/dtn-station-shield.service" /etc/systemd/system/dtn-station-shield.service 0644
    install_file "$SCRIPT_DIR/firewall/dtn-station-shield.timer" /etc/systemd/system/dtn-station-shield.timer 0644
    install_file "$SCRIPT_DIR/power/dtn-power.service" /etc/systemd/system/dtn-power.service 0644
    # Issue #16 Track 3: field hardening (run in step 8) + the self-healing
    # watchdog and the counters-only telemetry, wired as units/timers like
    # the Track-1 shields above.
    install_file "$SCRIPT_DIR/hardening/sshd-hardening.conf" /usr/local/sbin/dtn-sshd-hardening.conf 0644
    install_file "$SCRIPT_DIR/hardening/harden-ssh.sh" /usr/local/sbin/dtn-harden-ssh.sh 0755
    install_file "$SCRIPT_DIR/hardening/harden-services.sh" /usr/local/sbin/dtn-harden-services.sh 0755
    install_file "$SCRIPT_DIR/hardening/harden-upgrades.sh" /usr/local/sbin/dtn-harden-upgrades.sh 0755
    install_file "$SCRIPT_DIR/hardening/dtn-network-watchdog.sh" /usr/local/sbin/dtn-network-watchdog.sh 0755
    install_file "$SCRIPT_DIR/hardening/dtn-network-watchdog.service" /etc/systemd/system/dtn-network-watchdog.service 0644
    install_file "$SCRIPT_DIR/hardening/dtn-network-watchdog.timer" /etc/systemd/system/dtn-network-watchdog.timer 0644
    install_file "$SCRIPT_DIR/hardening/dtn-telemetry.sh" /usr/local/sbin/dtn-telemetry.sh 0755
    install_file "$SCRIPT_DIR/hardening/dtn-telemetry.service" /etc/systemd/system/dtn-telemetry.service 0644
    install_file "$SCRIPT_DIR/hardening/dtn-telemetry.timer" /etc/systemd/system/dtn-telemetry.timer 0644
    # Read-only root: staged for the operator, NEVER applied here (default
    # OFF — see the Track 3 note in this file's header).
    install_file "$SCRIPT_DIR/hardening/enable-readonly-root.sh" /usr/local/sbin/dtn-enable-readonly-root.sh 0755
    install_file "$SCRIPT_DIR/hardening/disable-readonly-root.sh" /usr/local/sbin/dtn-disable-readonly-root.sh 0755
    verify "dtn-node.service installed" test -f /etc/systemd/system/dtn-node.service
    verify "dtn-firewall.service installed" test -f /etc/systemd/system/dtn-firewall.service
    verify "dtn-traffic-shaping.service installed" test -f /etc/systemd/system/dtn-traffic-shaping.service
    verify "dtn-dns-shield.service installed" test -f /etc/systemd/system/dtn-dns-shield.service
    verify "dtn-dns-shield.timer installed" test -f /etc/systemd/system/dtn-dns-shield.timer
    verify "dtn-station-shield.service installed" test -f /etc/systemd/system/dtn-station-shield.service
    verify "dtn-station-shield.timer installed" test -f /etc/systemd/system/dtn-station-shield.timer
    verify "dtn-power.service installed" test -f /etc/systemd/system/dtn-power.service
    verify "dtn-harden-ssh.sh installed" test -x /usr/local/sbin/dtn-harden-ssh.sh
    verify "dtn-harden-services.sh installed" test -x /usr/local/sbin/dtn-harden-services.sh
    verify "dtn-harden-upgrades.sh installed" test -x /usr/local/sbin/dtn-harden-upgrades.sh
    verify "dtn-sshd-hardening.conf staged" test -f /usr/local/sbin/dtn-sshd-hardening.conf
    verify "dtn-network-watchdog.sh installed" test -x /usr/local/sbin/dtn-network-watchdog.sh
    verify "dtn-network-watchdog.service installed" test -f /etc/systemd/system/dtn-network-watchdog.service
    verify "dtn-network-watchdog.timer installed" test -f /etc/systemd/system/dtn-network-watchdog.timer
    verify "dtn-telemetry.sh installed" test -x /usr/local/sbin/dtn-telemetry.sh
    verify "dtn-telemetry.service installed" test -f /etc/systemd/system/dtn-telemetry.service
    verify "dtn-telemetry.timer installed" test -f /etc/systemd/system/dtn-telemetry.timer
    verify "dtn-enable-readonly-root.sh staged (OFF by default)" test -x /usr/local/sbin/dtn-enable-readonly-root.sh
    verify "dtn-disable-readonly-root.sh staged" test -x /usr/local/sbin/dtn-disable-readonly-root.sh

    # Older Debian hostapd.service units have no default DAEMON_CONF; newer
    # ones do. Setting it explicitly works everywhere and matches our path.
    if grep -q '^DAEMON_CONF=' /etc/default/hostapd 2>/dev/null; then
        sed -i 's|^DAEMON_CONF=.*|DAEMON_CONF="/etc/hostapd/hostapd.conf"|' /etc/default/hostapd
    else
        echo 'DAEMON_CONF="/etc/hostapd/hostapd.conf"' >> /etc/default/hostapd
    fi
    verify "hostapd DAEMON_CONF set" grep -q '^DAEMON_CONF="/etc/hostapd/hostapd.conf"$' /etc/default/hostapd
}

# --- step 6: service user, data dir and binary ----------------------------------

install_binary() {
    log "step 6/11: service user, data dir and binary"
    if id "$NODE_USER" >/dev/null 2>&1; then
        echo "[SKIP] user $NODE_USER already exists"
    else
        useradd --system --home-dir "$DATA_DIR" --no-create-home --shell /usr/sbin/nologin "$NODE_USER"
    fi
    verify "user $NODE_USER exists" id "$NODE_USER"

    install -d -m 0750 -o "$NODE_USER" -g "$NODE_GROUP" "$DATA_DIR"
    verify "data dir 0750 $NODE_USER:$NODE_GROUP" \
        test "$(stat -c '%a %U %G' "$DATA_DIR")" = "750 $NODE_USER $NODE_GROUP"

    # Pick the cross-compiled binary matching this Pi's userland ISA
    # (validated in preflight; matches node/build.sh output names).
    local bin_src
    case "$BOARD_ARCH" in
        aarch64) bin_src="$SCRIPT_DIR/../node/dtn-node-linux-arm64" ;;
        armv7l) bin_src="$SCRIPT_DIR/../node/dtn-node-linux-armv7" ;;
        armv6l) bin_src="$SCRIPT_DIR/../node/dtn-node-linux-armv6" ;;
        *) die "unsupported architecture $BOARD_ARCH: build on the Pi or copy binaries from node/build.sh output" ;;
    esac
    log "installing $bin_src for $BOARD_MODEL ($BOARD_ARCH)"
    verify "binary exists at $bin_src" test -f "$bin_src"
    install -m 0755 -o root -g root "$bin_src" "$INSTALL_DIR/dtn-node"
    verify "binary installed 0755 root" test "$(stat -c '%a %U' "$INSTALL_DIR/dtn-node")" = "755 root"
}

# --- step 7: node identity (issue #33 P3.1, optional kit) -------------------------

# The node-plane identity (docs/node-network.md §2.6): a provisioned node
# carries its own Ed25519 seed, its anchor-signed role certificate and the
# pinned anchor public key. The kit is produced OFFLINE with capsuletool
# (anchor keygen → rolecert keygen/request/sign — the §2.6 ceremony) and
# dropped into this tree as nodeid/{node.seed,node_cert.cbor,anchor.pub}.
# Idempotent like every step: identical files are a no-op, a differing kit
# replaces it (keeping the .dtn-bak). An ABSENT kit is an explicit,
# loud SKIP — identity is a provisioning FACT, never improvised on the
# node, and never a side effect of an upgrade (rotation is the ceremony
# of §2.6 with seq+1, not this step).
install_nodeid() {
    log "step 7/11: node identity (role cert + anchor pin, issue #33 P3.1)"
    local kit="$SCRIPT_DIR/nodeid"
    local dest="$INSTALL_DIR/nodeid"
    if [ ! -d "$kit" ]; then
        log "SKIP: no node-identity kit in the provisioning tree ($kit)"
        log "      to provision identity, run the capsuletool ceremony of"
        log "      docs/node-network.md §2.6 offline and place nodeid/{node.seed,"
        log "      node_cert.cbor,anchor.pub} next to this script; the node will"
        log "      boot WITHOUT a role cert meanwhile (mail works, management does not)"
        verify "node identity skipped by operator choice (kit absent)" true
        return 0
    fi
    # A PARTIAL kit is an operator mistake — fail closed, never half-identity.
    for f in node.seed node_cert.cbor anchor.pub; do
        verify "kit file $kit/$f present" test -f "$kit/$f"
    done
    install -d -m 0750 -o root -g root "$dest"
    verify "identity dir 0750 root:root" \
        test "$(stat -c '%a %U %G' "$dest")" = "750 root root"
    install_file "$kit/node.seed" "$dest/node.seed" 0600
    install_file "$kit/node_cert.cbor" "$dest/node_cert.cbor" 0644
    install_file "$kit/anchor.pub" "$dest/anchor.pub" 0644
    verify "node.seed installed 0600 root" \
        test "$(stat -c '%a %U' "$dest/node.seed")" = "600 root"
    verify "node_cert.cbor installed 0644 root" \
        test "$(stat -c '%a %U' "$dest/node_cert.cbor")" = "644 root"
    verify "anchor.pub installed 0644 root" \
        test "$(stat -c '%a %U' "$dest/anchor.pub")" = "644 root"
    # Honest bound, recorded where the operator reads it: the FILES are
    # root-owned; granting the daemon (user dtn) read access to its own
    # identity is part of the P3.2+ daemon wiring, deliberately not widened
    # silently here.
    log "identity files are root-owned; the daemon reads them from P3.2+ (documented, not silently widened)"
}

# --- step 8: enable units (nothing is started) -----------------------------------

enable_units() {
    log "step 8/11: enable units (no service is started; reboot activates)"
    systemctl daemon-reload
    # networking: brings up wlan0 (10.42.0.1) via ifupdown at boot.
    # hostapd + dnsmasq: the classic AP stack. The dtn-* units: firewall,
    # bandwidth shaping, portal daemon, power trim, the two shield TIMERS and
    # the Track-3 network-watchdog/telemetry TIMERS (the services they
    # trigger are enabled through the timers — a timer starts its unit
    # regardless of the unit's own enablement).
    # Boot order is encoded in the unit files. Nothing is started: the
    # reboot is the activation step.
    systemctl enable networking hostapd dnsmasq dtn-firewall dtn-traffic-shaping \
        dtn-dns-shield.timer dtn-station-shield.timer \
        dtn-network-watchdog.timer dtn-telemetry.timer dtn-node dtn-power
    verify "networking enabled" systemctl is-enabled networking
    verify "hostapd enabled" systemctl is-enabled hostapd
    verify "dnsmasq enabled" systemctl is-enabled dnsmasq
    verify "dtn-firewall enabled" systemctl is-enabled dtn-firewall
    verify "dtn-traffic-shaping enabled" systemctl is-enabled dtn-traffic-shaping
    verify "dtn-dns-shield.timer enabled" systemctl is-enabled dtn-dns-shield.timer
    verify "dtn-station-shield.timer enabled" systemctl is-enabled dtn-station-shield.timer
    verify "dtn-network-watchdog.timer enabled" systemctl is-enabled dtn-network-watchdog.timer
    verify "dtn-telemetry.timer enabled" systemctl is-enabled dtn-telemetry.timer
    verify "dtn-node enabled" systemctl is-enabled dtn-node
    verify "dtn-power enabled" systemctl is-enabled dtn-power
}

# --- step 8: field hardening (issue #16 Track 3) ---------------------------------

# Runs the three idempotent hardening steps in dependency order. None of them
# starts a service; unattended-upgrades' timers and the journald drop-in take
# effect at the reboot that activates everything else. The read-only root is
# deliberately NOT part of provisioning: it is an explicit operator step
# (see the header note and final_report's checklist).
field_hardening() {
    log "step 9/11: field hardening (ssh surface, unprivileged daemon, security upgrades)"
    # Each script is fail-fast and idempotent; these verifies pin the
    # on-disk end state this step promises.
    /usr/local/sbin/dtn-harden-services.sh
    verify "journald volatile drop-in installed" \
        grep -q '^Storage=volatile$' /etc/systemd/journald.conf.d/dtn-volatile.conf
    /usr/local/sbin/dtn-harden-ssh.sh
    if [ -x /usr/sbin/sshd ]; then
        verify "sshd hardening drop-in installed (keys-only, no root login)" \
            grep -q '^PermitRootLogin no$' /etc/ssh/sshd_config.d/00-dtn-hardening.conf
    else
        log "sshd not installed: no SSH surface exists, drop-in step skipped by design"
    fi
    /usr/local/sbin/dtn-harden-upgrades.sh
    verify "security-only upgrade override installed" \
        grep -q 'Debian-Security' /etc/apt/apt.conf.d/52dtn-security-only.conf
}

# --- step 9: firewall persistence --------------------------------------------------

persist_firewall() {
    log "step 10/11: firewall persistence"
    if command -v netfilter-persistent >/dev/null 2>&1; then
        verify "rules saved to /etc/iptables/rules.v4" test -f /etc/iptables/rules.v4
    else
        log "netfilter-persistent absent: dtn-firewall.service re-applies rules at boot"
        verify "dtn-firewall.sh fallback in place" test -x /usr/local/sbin/dtn-firewall.sh
    fi
}

# --- step 10: operator handoff ------------------------------------------------------

final_report() {
    log "step 11/11: done — every step verified"
    cat <<EOF

=====================================================================
 Provisioning complete. NO portal service was started on purpose.
 The ACTIVATION STEP IS A REBOOT: it brings up the AP stack and the
 portal daemon in the order encoded in the unit files.

 Operator checklist after reboot:
   1. Join the Wi-Fi "offgrid-messages" from a phone; the captive
      portal should pop up on its own and land on
      http://offgrid.local:8080
   2. Verify associated stations from the Pi:
        hostapd_cli -i wlan0 all_sta
   3. Verify the portal daemon answers (canonical host):
        curl -H 'Host: offgrid.local:8080' http://10.42.0.1:8080/
   4. Verify two clients cannot reach each other (isolation):
        ping from client A to client B must fail.
   5. Verify the Track-1 shields are armed (issue #16):
        systemctl list-timers 'dtn-*'
        /usr/local/sbin/dtn-firewall.sh --print | less   # inspect the ruleset
        /usr/local/sbin/dtn-dns-shield.sh --dry-run
        /usr/local/sbin/dtn-station-shield.sh --dry-run
        /usr/local/sbin/dtn-traffic-shaping.sh --dry-run
   6. Verify the Track-3 hardening (issue #16):
        /usr/local/sbin/dtn-harden-services.sh --dry-run
        /usr/local/sbin/dtn-harden-ssh.sh --dry-run
        /usr/local/sbin/dtn-harden-upgrades.sh --dry-run
        /usr/local/sbin/dtn-network-watchdog.sh --dry-run
        /usr/local/sbin/dtn-telemetry.sh --dry-run
   7. OPTIONAL tamper resistance (DEFAULT OFF — read the script header
      first: every later config change needs a remount cycle):
        sudo /usr/local/sbin/dtn-enable-readonly-root.sh --dry-run
      and see raspberry/hardening/enable-readonly-root.sh.
   8. Verify a full reboot restores everything by itself.

 Deployment parameters used in this run:
   Board : ${BOARD_MODEL} (userland ${BOARD_ARCH})
   COUNTRY=${COUNTRY}   (override: COUNTRY=XX ./provision.sh)
   ALLOW_SSH=${ALLOW_SSH}   (override: ALLOW_SSH=1 ./provision.sh)

 Reminders:
   * The SSID, channel and gateway IP are network-wide constants; the
     regulatory country code must match the physical deployment site.
   * Energy sizing (~1 W continuous draw, solar + LiFePO4) is covered
     in docs/hardware.md (Sprint 4).
=====================================================================
EOF
}

# --- dispatch ----------------------------------------------------------------------
# STEPS (issue #22): optional space-separated subset selector for re-runs.
# install.sh --upgrade re-runs exactly the steps that can carry CHANGED files
# (preflight static_ip install_configs install_binary enable_units
# field_hardening persist_firewall) — every one idempotent and network-free,
# so an offline USB upgrade works; the NetworkManager and apt steps are
# one-time setup and a reflash keeps the full default. Every step stays
# individually idempotent (install_file compares before replacing and keeps a
# .dtn-bak of the previous file).
# install_nodeid rides the FRESH-INSTALL default list only: the upgrade
# subset (install.sh --upgrade) never touches node identity — rotation is
# the explicit §2.6 ceremony, mirroring the release-key idempotence rule of
# offline-maintenance §2.2.3.
STEPS="${STEPS:-preflight disable_networkmanager install_packages static_ip install_configs install_binary install_nodeid enable_units field_hardening persist_firewall final_report}"
for step_name in $STEPS; do
    case "$step_name" in
        preflight | disable_networkmanager | install_packages | static_ip | install_configs | install_binary | install_nodeid | enable_units | field_hardening | persist_firewall | final_report)
            "$step_name"
            ;;
        *) die "unknown step in STEPS: $step_name" ;;
    esac
done
