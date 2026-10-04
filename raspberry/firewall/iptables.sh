#!/usr/bin/env bash
# dtn-firewall.sh — firewall rules for the off-grid DTN dead-drop node (Module A)
# Install path: /usr/local/sbin/dtn-firewall.sh
# Invoked at boot by dtn-firewall.service (companion systemd oneshot) and safe
# to re-run by hand at any time: every rule is verified before it is added and
# only the DTN-owned chains are ever flushed.
#
# What it does:
#   1. Redirects inbound TCP/80 on the AP interface to the portal daemon on
#      TCP/8080 (PREROUTING REDIRECT in the nat table). Combined with
#      dnsmasq's wildcard DNS (address=/#/10.42.0.1) this is what makes any
#      URL a captive device tries to open land on the portal.
#   2. Opens exactly the services clients need on the AP interface:
#      DHCP (udp/67) and DNS (udp+tcp/53) from dnsmasq, and the portal on
#      tcp/8080. SSH from the AP subnet is opt-in (ALLOW_SSH=1).
#   3. Enforces layer-3 client isolation: the FORWARD chain has policy DROP
#      and NO accept rules — no internet forwarding (there is no uplink) and
#      no client-to-client forwarding. This is the second isolation layer,
#      reinforcing hostapd's ap_isolate=1 at layer 2.
#
# Captive-probe note (no extra firewall rules needed on purpose): the OS
# probes (/generate_204 for Android, /hotspot-detect.html for iOS) arrive on
# port 80 with spoofed Hosts via the wildcard DNS, hit the REDIRECT below and
# are answered by the dtn-node daemon itself with a 302 to the canonical
# origin — docs/protocol.md §10.2. Filtering them separately would only
# break captive-portal detection.

set -euo pipefail

# Overridable for testing/deployment variance; defaults match the rest of the
# repository (provision.sh, dnsmasq.conf, dtn-node.service).
WLAN_IF="${WLAN_IF:-wlan0}"
PORTAL_PORT="${PORTAL_PORT:-8080}"
ALLOW_SSH="${ALLOW_SSH:-0}"

NAT_CHAIN="DTN_PORTAL"
IN_CHAIN="DTN_INPUT"
IPT="${IPT:-iptables}"

log() { echo "dtn-firewall: $*"; }

# --- preflight ---------------------------------------------------------------

if [ "$(id -u)" -ne 0 ]; then
    log "ERROR: must run as root (iptables policy changes require CAP_NET_ADMIN)"
    exit 1
fi
if ! command -v "$IPT" >/dev/null 2>&1; then
    log "ERROR: $IPT not found; install the iptables package"
    exit 1
fi
if ! "$IPT" -L >/dev/null 2>&1; then
    log "ERROR: cannot talk to the kernel firewall (module nf_tables loaded?)"
    exit 1
fi

# ensure_chain TABLE CHAIN — create CHAIN if missing, then flush it. Only the
# DTN-owned chains are flushed, so re-running never wipes unrelated rules.
ensure_chain() {
    local table="$1" chain="$2"
    if ! "$IPT" -t "$table" -nL "$chain" >/dev/null 2>&1; then
        "$IPT" -t "$table" -N "$chain"
    fi
    "$IPT" -t "$table" -F "$chain"
}

# ensure_rule TABLE CHAIN [rule...] — add the rule only when absent, making
# repeated runs a no-op instead of piling up duplicates.
ensure_rule() {
    local table="$1" chain="$2"
    shift 2
    if ! "$IPT" -t "$table" -C "$chain" "$@" 2>/dev/null; then
        "$IPT" -t "$table" -A "$chain" "$@"
    fi
}

# --- 1. captive-portal redirect (nat) ----------------------------------------

ensure_chain nat "$NAT_CHAIN"
# Any TCP connection to port 80 arriving on the AP interface is redirected to
# the local portal daemon. REDIRECT (not DNAT) keeps the destination address
# intact for the socket, which is what we want for a local service.
ensure_rule nat PREROUTING -i "$WLAN_IF" -j "$NAT_CHAIN"
"$IPT" -t nat -A "$NAT_CHAIN" -p tcp --dport 80 -j REDIRECT --to-ports "$PORTAL_PORT"

# --- 2. filter INPUT: services exposed to AP clients -------------------------

# General safety rules on INPUT itself (never matched twice thanks to
# ensure_rule; they keep being correct even if the policy is tightened later):
# loopback is always trusted, and replies to connections we initiated are
# accepted. This node has no uplink, so "related" traffic is effectively
# local-only.
ensure_rule filter INPUT -i lo -j ACCEPT
ensure_rule filter INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

ensure_chain filter "$IN_CHAIN"
# DHCP server port: dnsmasq answers client DISCOVER on udp/67 (udp/68 is the
# client's source port; opening 67 is what makes DHCP work at all).
"$IPT" -A "$IN_CHAIN" -p udp --dport 67 -j ACCEPT
# DNS from dnsmasq, both transports: UDP for normal lookups, TCP for large or
# truncated responses.
"$IPT" -A "$IN_CHAIN" -p udp --dport 53 -j ACCEPT
"$IPT" -A "$IN_CHAIN" -p tcp --dport 53 -j ACCEPT
# The portal daemon itself (canonical origin http://portal.red.local:8080).
"$IPT" -A "$IN_CHAIN" -p tcp --dport "$PORTAL_PORT" -j ACCEPT
# Opt-in SSH for the operator, restricted to the AP subnet interface. Off by
# default: an unattended solar node needs no listener.
if [ "$ALLOW_SSH" = "1" ]; then
    "$IPT" -A "$IN_CHAIN" -p tcp --dport 22 -j ACCEPT
fi
# Unmatched AP traffic falls through to the rest of INPUT unchanged.
"$IPT" -A "$IN_CHAIN" -j RETURN
ensure_rule filter INPUT -i "$WLAN_IF" -j "$IN_CHAIN"

# Documented stance on the INPUT policy: we deliberately leave it at the
# distribution default (ACCEPT) instead of flipping it to DROP. The node is a
# standalone island with no uplink; the only externally reachable services are
# the ones this script just accepted, and a hard INPUT DROP would also cut off
# the operator's own maintenance access (serial console sharing, local curl
# checks, sshd) the moment a new legitimate service is added without a rule.
# Attack surface here equals "the services we run", which the accepts make
# explicit.

# --- 3. filter FORWARD: total client isolation at layer 3 --------------------

# No accept rules at all: clients can never reach each other at layer 3
# (reinforcing ap_isolate=1 at layer 2) and no traffic is ever forwarded
# anywhere — by design there is no internet uplink to forward to.
"$IPT" -P FORWARD DROP

# --- 4. persistence ----------------------------------------------------------

# Prefer netfilter-persistent (Debian standard): writing /etc/iptables/rules.v4
# makes the installed iptables-persistent plugin replay these rules at boot.
# When the package is absent, the companion dtn-firewall.service oneshot
# re-applies them at every boot instead.
if [ -d /etc/iptables ] && command -v iptables-save >/dev/null 2>&1; then
    iptables-save > /etc/iptables/rules.v4
    log "rules saved to /etc/iptables/rules.v4 (netfilter-persistent replays them at boot)"
else
    log "netfilter-persistent not installed; dtn-firewall.service re-applies rules at every boot"
fi

log "firewall ready: AP=$WLAN_IF portal port=$PORTAL_PORT ssh=$ALLOW_SSH forward=DROP"
