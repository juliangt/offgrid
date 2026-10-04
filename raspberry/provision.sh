#!/usr/bin/env bash
# provision.sh — idempotent provisioning of a Raspberry Pi Zero 2 W as an
# off-grid DTN dead-drop node (Module A, Sprint 3).
# Install path: run ON THE PI as root (or via sudo). Also committed here for
# review. Config files are read from this script's directory tree:
#
#   hostapd/hostapd.conf        -> /etc/hostapd/hostapd.conf
#   dnsmasq/dnsmasq.conf        -> /etc/dnsmasq.conf
#   firewall/iptables.sh        -> /usr/local/sbin/dtn-firewall.sh
#   firewall/dtn-firewall.service -> /etc/systemd/system/dtn-firewall.service
#   power/config.txt.snippet    -> appended to /boot/firmware/config.txt (Bookworm)
#                                  or /boot/config.txt (legacy), once only
#   power/dtn-power.service     -> /etc/systemd/system/dtn-power.service
#   systemd/dtn-node.service    -> /etc/systemd/system/dtn-node.service
#   ../node/dtn-node-linux-arm64|arm -> /opt/dtn-node/dtn-node
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
# See DEVELOPMENT_PLAN.md §1.6 (NetworkManager vs classic stack — BINDING
# DECISION), §5 Sprint 3 and docs/protocol.md §12 (canonical origin).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

COUNTRY="${COUNTRY:-AR}"
export ALLOW_SSH="${ALLOW_SSH:-0}"
NODE_USER="dtn"
NODE_GROUP="dtn"
DATA_DIR="/var/lib/dtn-node"
INSTALL_DIR="/opt/dtn-node"

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
    log "step 1/9: preflight"
    verify "running as root" test "$(id -u)" -eq 0
    verify "Raspberry Pi hardware" grep -q "Raspberry Pi" /proc/device-tree/model
    verify "OS release file present" test -f /etc/os-release

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
    log "step 2/9: network manager selection"
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
    log "step 3/9: packages"
    apt-get update -qq >/dev/null
    # hostapd (AP), dnsmasq (DHCP+DNS), iptables (firewall), iw (used by the
    # post-up power_save line in interfaces.d/wlan0).
    DEBIAN_FRONTEND=noninteractive apt-get install -y hostapd dnsmasq iptables iw >/dev/null
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
    log "step 4/9: static IP 10.42.0.1/24 on wlan0"
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
    log "step 5/9: config files"
    local tmp
    tmp="$(mktemp)"

    # hostapd with the deployment country spliced in (defaults to AR).
    sed "s/^country_code=.*/country_code=${COUNTRY}/" "$SCRIPT_DIR/hostapd/hostapd.conf" > "$tmp"
    install_file "$tmp" /etc/hostapd/hostapd.conf 0644
    rm -f "$tmp"
    verify "hostapd.conf installed" grep -q "^ssid=Red-Comunitaria$" /etc/hostapd/hostapd.conf
    verify "hostapd country_code=${COUNTRY}" grep -q "^country_code=${COUNTRY}$" /etc/hostapd/hostapd.conf

    install_file "$SCRIPT_DIR/dnsmasq/dnsmasq.conf" /etc/dnsmasq.conf 0644
    verify "dnsmasq.conf installed" grep -q "^address=/#/10.42.0.1$" /etc/dnsmasq.conf

    install_file "$SCRIPT_DIR/firewall/iptables.sh" /usr/local/sbin/dtn-firewall.sh 0755
    verify "dtn-firewall.sh installed" test -x /usr/local/sbin/dtn-firewall.sh

    # Fire the firewall once now: it is session-safe (it only adds accepts and
    # a REDIRECT — nothing is dropped, the INPUT policy is left untouched), it
    # validates the ruleset on real hardware and, when netfilter-persistent is
    # present, it saves /etc/iptables/rules.v4 in the same stroke. The portal
    # services themselves stay stopped.
    /usr/local/sbin/dtn-firewall.sh
    verify "REDIRECT hook active" iptables -t nat -C PREROUTING -i wlan0 -j DTN_PORTAL
    verify "REDIRECT 80->8080 active" iptables -t nat -C DTN_PORTAL -p tcp --dport 80 -j REDIRECT --to-ports 8080
    verify "FORWARD policy DROP" test "$(iptables -S FORWARD | head -n 1)" = "-P FORWARD DROP"

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

    install_file "$SCRIPT_DIR/systemd/dtn-node.service" /etc/systemd/system/dtn-node.service 0644
    install_file "$SCRIPT_DIR/firewall/dtn-firewall.service" /etc/systemd/system/dtn-firewall.service 0644
    install_file "$SCRIPT_DIR/power/dtn-power.service" /etc/systemd/system/dtn-power.service 0644
    verify "dtn-node.service installed" test -f /etc/systemd/system/dtn-node.service
    verify "dtn-firewall.service installed" test -f /etc/systemd/system/dtn-firewall.service
    verify "dtn-power.service installed" test -f /etc/systemd/system/dtn-power.service

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
    log "step 6/9: service user, data dir and binary"
    if id "$NODE_USER" >/dev/null 2>&1; then
        echo "[SKIP] user $NODE_USER already exists"
    else
        useradd --system --home-dir "$DATA_DIR" --no-create-home --shell /usr/sbin/nologin "$NODE_USER"
    fi
    verify "user $NODE_USER exists" id "$NODE_USER"

    install -d -m 0750 -o "$NODE_USER" -g "$NODE_GROUP" "$DATA_DIR"
    verify "data dir 0750 $NODE_USER:$NODE_GROUP" \
        test "$(stat -c '%a %U %G' "$DATA_DIR")" = "750 $NODE_USER $NODE_GROUP"

    # Pick the cross-compiled binary matching this Pi's architecture.
    local bin_src
    case "$(uname -m)" in
        aarch64) bin_src="$SCRIPT_DIR/../node/dtn-node-linux-arm64" ;;
        armv7l | armv6l) bin_src="$SCRIPT_DIR/../node/dtn-node-linux-arm" ;;
        *) die "unsupported architecture $(uname -m): build on the Pi or copy binaries from node/build.sh output" ;;
    esac
    verify "binary exists at $bin_src" test -f "$bin_src"
    install -m 0755 -o root -g root "$bin_src" "$INSTALL_DIR/dtn-node"
    verify "binary installed 0755 root" test "$(stat -c '%a %U' "$INSTALL_DIR/dtn-node")" = "755 root"
}

# --- step 7: enable units (nothing is started) -----------------------------------

enable_units() {
    log "step 7/9: enable units (no service is started; reboot activates)"
    systemctl daemon-reload
    # networking: brings up wlan0 (10.42.0.1) via ifupdown at boot.
    # hostapd + dnsmasq: the classic AP stack. The three dtn-* units: firewall,
    # portal daemon, power trim. Boot order is encoded in the unit files.
    systemctl enable networking hostapd dnsmasq dtn-firewall dtn-node dtn-power
    verify "networking enabled" systemctl is-enabled networking
    verify "hostapd enabled" systemctl is-enabled hostapd
    verify "dnsmasq enabled" systemctl is-enabled dnsmasq
    verify "dtn-firewall enabled" systemctl is-enabled dtn-firewall
    verify "dtn-node enabled" systemctl is-enabled dtn-node
    verify "dtn-power enabled" systemctl is-enabled dtn-power
}

# --- step 8: firewall persistence --------------------------------------------------

persist_firewall() {
    log "step 8/9: firewall persistence"
    if command -v netfilter-persistent >/dev/null 2>&1; then
        verify "rules saved to /etc/iptables/rules.v4" test -f /etc/iptables/rules.v4
    else
        log "netfilter-persistent absent: dtn-firewall.service re-applies rules at boot"
        verify "dtn-firewall.sh fallback in place" test -x /usr/local/sbin/dtn-firewall.sh
    fi
}

# --- step 9: operator handoff ------------------------------------------------------

final_report() {
    log "step 9/9: done — every step verified"
    cat <<EOF

=====================================================================
 Provisioning complete. NO portal service was started on purpose.
 The ACTIVATION STEP IS A REBOOT: it brings up the AP stack and the
 portal daemon in the order encoded in the unit files.

 Operator checklist after reboot:
   1. Join the Wi-Fi "Red-Comunitaria" from a phone; the captive
      portal should pop up on its own and land on
      http://portal.red.local:8080
   2. Verify associated stations from the Pi:
        hostapd_cli -i wlan0 all_sta
   3. Verify the portal daemon answers (canonical host):
        curl -H 'Host: portal.red.local:8080' http://10.42.0.1:8080/
   4. Verify two clients cannot reach each other (isolation):
        ping from client A to client B must fail.
   5. Verify a full reboot restores everything by itself.

 Deployment parameters used in this run:
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

preflight
disable_networkmanager
install_packages
static_ip
install_configs
install_binary
enable_units
persist_firewall
final_report
