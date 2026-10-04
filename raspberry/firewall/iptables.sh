#!/usr/bin/env bash
# dtn-firewall.sh — firewall rules for the off-grid DTN dead-drop node (Module A)
# Install path: /usr/local/sbin/dtn-firewall.sh
# Invoked at boot by dtn-firewall.service (companion systemd oneshot) and safe
# to re-run by hand at any time: every rule is verified before it is added and
# only the DTN-owned chains are ever flushed.
#
# Usage:
#   dtn-firewall.sh             apply the ruleset to the running kernel (root;
#                               default, unchanged from earlier releases)
#   dtn-firewall.sh --print     print the FULL ruleset in iptables-restore
#                               format to stdout WITHOUT touching the kernel
#                               (no root) — this is how
#                               tests/hardening_structure.sh asserts the
#                               security properties on the generated ruleset
#                               on a rootless dev machine. The printout is an
#                               inspection model: do NOT pipe it into
#                               iptables-restore (the apply path is
#                               deliberately incremental so foreign rules and
#                               the INPUT policy are never clobbered).
#
# GUIDING PRINCIPLE (issue #16 Track 1 — anti-circumvention, "the AP is not
# free Internet"): assume every client is an attacker. The node is an ISLAND
# with no uplink; a client's only legitimate activity is DHCP, DNS lookups
# answered by this node, and HTTP to the portal on tcp/8080 (the canonical
# origin, docs/protocol.md §10.2). Everything below exists to keep it that
# way. Defense -> rule mapping:
#
#   Threat                                   Rule
#   ---------------------------------------- --------------------------------
#   client-to-client L2/L3 attacks           hostapd ap_isolate=1 (L2) +
#                                            FORWARD policy DROP, zero ACCEPT
#                                            rules (L3)
#   free Internet via the Pi (any uplink     FORWARD policy DROP + blanket
#   iface: eth0/wlan1/usb0)                  -s $CLIENT_SUBNET -j DROP: no
#                                            packet from a client is ever
#                                            forwarded anywhere, period
#   classic proxy / remote-access egress     explicit FORWARD drops: tcp 22,
#   (SSH/telnet/SOCKS/squid/443-as-        23, 1080, 3128, 443, 8080-toward-
#   proxy)                                   other-hosts
#   encrypted-DNS bypass (DoT)               explicit FORWARD drops tcp+udp 853
#                                            (DoH rides tcp/443 to arbitrary
#                                            hosts — killed by the same no-
#                                            forward default; no port of its
#                                            own to block)
#   VPN handshakes                           explicit FORWARD drops: IKE
#                                            udp 500/4500, OpenVPN tcp+udp
#                                            1194, WireGuard udp 51820, L2TP
#                                            udp 1701, PPTP tcp 1723 + GRE
#   raw TCP to the Internet                  the FORWARD DROP policy itself,
#                                            plus the blanket subnet drop
#                                            (redundant on purpose: policy
#                                            and explicit rule both state
#                                            the invariant)
#   DNS-tunnel egress (client-run            explicit FORWARD drops tcp+udp 53:
#   resolver to the outside)                 clients must use THIS node's
#                                            resolver, which only answers
#                                            "portal IP" (dnsmasq.conf)
#   ICMP tunnels (icmpsh, ping -p)           fragmented ICMP dropped outright;
#                                            per-source hashlimit on ICMP so
#                                            covert channels starve
#   DNS-query flooding / tunneling IN        per-source hashlimit on udp+tcp 53
#   to the node                              BEFORE the accept (see rates
#                                            below; note there is NO ctstate
#                                            NEW qualifier on purpose: a UDP
#                                            resolver socket that gets replies
#                                            becomes ESTABLISHED and would
#                                            otherwise bypass any NEW-only
#                                            limit)
#   SYN flood / connection hoarding on       per-source hashlimit on NEW
#   the portal                               conns to 8080 + connlimit per
#                                            source IP
#   sustained abusers                        empty-at-boot chains fed at
#                                            runtime: DTN_DNSBL (dtn-dns-
#                                            shield.sh sheds tunnelers) and
#                                            DTN_ACC (per-source byte
#                                            counters dtn-station-shield.sh
#                                            reads before deauthenticating
#                                            quota hogs)
#
# Captive-probe note (no extra firewall rules needed on purpose): the OS
# probes (/generate_204 for Android, /hotspot-detect.html for iOS) arrive on
# port 80 with spoofed Hosts via the wildcard DNS, hit the REDIRECT below and
# are answered by the dtn-node daemon itself with a 302 to the canonical
# origin — docs/protocol.md §10.2. Filtering them separately would only
# break captive-portal detection.
#
# Legitimate-traffic budget (why the limits are generous): a mule sync is a
# handful of requests — one POST /api/v1/sync pulls up to 200 envelopes
# (~140 KiB) and pushes up to 100 (~70 KiB), §8.1; a full first visit adds
# the SPA (~100 KiB) over a dozen TCP connections at most. DNS: a browser
# issues a few lookups per visit, all answered "portal IP". The limits below
# sit at 30-100x that budget, so no legitimate client is ever throttled; only
# automation trips them.

set -euo pipefail

# Overridable for testing/deployment variance; defaults match the rest of the
# repository (provision.sh, dnsmasq.conf, dtn-node.service).
WLAN_IF="${WLAN_IF:-wlan0}"
PORTAL_PORT="${PORTAL_PORT:-8080}"
ALLOW_SSH="${ALLOW_SSH:-0}"
CLIENT_SUBNET="${CLIENT_SUBNET:-10.42.0.0/24}"
NODE_IP="${NODE_IP:-10.42.0.1}"

# --- threshold tuning (all per source IP; see the budget note above) ---------
# DNS: allow 25 queries/s sustained (burst 50). A real device does <1 q/s;
# 25/s is already ~1500 lookups a minute with zero portal value — shed the
# excess at the firewall and let dtn-dns-shield.sh catch the sustained
# sub-ceiling abuse (its shed threshold, DNS_SHED_QPS=20, must stay BELOW
# this ceiling or the excess would never show up in dnsmasq's query log).
DNS_HL_RATE_QPS="${DNS_HL_RATE_QPS:-25}"
DNS_HL_BURST="${DNS_HL_BURST:-50}"
# Portal: 30 NEW connections/minute sustained (burst 60) and at most 32
# concurrent connections per client. A full visit opens ~a dozen; the sync
# itself is 1-2. 32 concurrent is ~3x the most parallel browser ever needs.
PORTAL_SYN_RATE_PER_MIN="${PORTAL_SYN_RATE_PER_MIN:-30}"
PORTAL_SYN_BURST="${PORTAL_SYN_BURST:-60}"
PORTAL_CONN_LIMIT="${PORTAL_CONN_LIMIT:-32}"
# ICMP: 5 echo requests/s sustained (burst 10) per source — a human "ping
# the node to see if it's up" is ~1/s; more is a flood or a tunnel.
ICMP_HL_RATE_QPS="${ICMP_HL_RATE_QPS:-5}"
ICMP_HL_BURST="${ICMP_HL_BURST:-10}"

NAT_CHAIN="DTN_PORTAL"
IN_CHAIN="DTN_INPUT"
DNSBL_CHAIN="DTN_DNSBL"
ACC_CHAIN="DTN_ACC"
IPT="${IPT:-iptables}"

PRINT_ONLY=0
for arg in "$@"; do
    case "$arg" in
        --print) PRINT_ONLY=1 ;;
        -h | --help)
            sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//; /^$/d; /Usage:/q' | head -n 40
            exit 0
            ;;
        *)
            echo "dtn-firewall: ERROR: unknown option '$arg' (usage: dtn-firewall.sh [--print])" >&2
            exit 1
            ;;
    esac
done

log() { echo "dtn-firewall: $*"; }

# --- preflight (apply mode only — --print must run rootless and kernel-free) --

if [ "$PRINT_ONLY" != "1" ]; then
    if [ "$(id -u)" -ne 0 ]; then
        log "ERROR: must run as root (iptables policy changes require CAP_NET_ADMIN); use --print for a rootless ruleset dump"
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
fi

# ensure_chain TABLE CHAIN — create CHAIN if missing, then flush it. Only the
# DTN-owned chains are flushed, so re-running never wipes unrelated rules.
# (apply mode only)
ensure_chain() {
    local table="$1" chain="$2"
    if ! "$IPT" -t "$table" -nL "$chain" >/dev/null 2>&1; then
        "$IPT" -t "$table" -N "$chain"
    fi
    "$IPT" -t "$table" -F "$chain"
}

# ensure_policy CHAIN POLICY — set a built-in chain policy only when it is not
# already the wanted one (idempotent re-runs). (apply mode only)
ensure_policy() {
    local chain="$1" policy="$2" cur
    cur="$("$IPT" -S "$chain" 2>/dev/null | head -n 1 || true)"
    if [ "$cur" != "-P $chain $policy" ]; then
        "$IPT" -P "$chain" "$policy"
    fi
}

# ensure_rule TABLE CHAIN [rule...] — add the rule only when absent, making
# repeated runs a no-op instead of piling up duplicates. (apply mode only)
ensure_rule() {
    local table="$1" chain="$2"
    shift 2
    if ! "$IPT" -t "$table" -C "$chain" "$@" 2>/dev/null; then
        "$IPT" -t "$table" -A "$chain" "$@"
    fi
}

# rule TABLE CHAIN [rule...] — the SINGLE SOURCE OF TRUTH for every DTN rule.
# In apply mode it installs the rule idempotently; in --print mode it emits
# the same rule as an iptables-restore "-A" line. The two paths can never
# drift apart because there is only one place where rules are written down.
rule() {
    local table="$1" chain="$2"
    shift 2
    if [ "$PRINT_ONLY" = "1" ]; then
        printf -- '-A %s' "$chain"
        local token
        for token in "$@"; do
            printf ' %s' "$token"
        done
        printf '\n'
    else
        ensure_rule "$table" "$chain" "$@"
    fi
}

# table_prologue / table_epilogue — emit the restore-format table headers in
# --print mode; create/flush the DTN-owned chains and set policies in apply
# mode. User chains are declared with "-" (no built-in policy).
table_prologue() {
    local table="$1"
    shift
    if [ "$PRINT_ONLY" = "1" ]; then
        echo "*$table"
        local line
        for line in "$@"; do
            echo ":$line [0:0]"
        done
    else
        local chain_def
        for chain_def in "$@"; do
            case "$chain_def" in
                FORWARD*)
                    # The ONLY policy this script ever enforces is FORWARD
                    # DROP (the island invariant). Every other policy listed
                    # here is printed in --print mode as the stock default
                    # but deliberately left untouched on the running system,
                    # so an operator's own INPUT/OUTPUT hardening survives
                    # re-runs (see the stance comment near the INPUT rules).
                    ensure_policy "${chain_def%% *}" "${chain_def##* }"
                    ;;
                *ACCEPT | *DROP)
                    # Stock-default policy of a built-in chain: model it in
                    # --print, never enforce it on the running system.
                    ;;
                *)
                    ensure_chain "$table" "$chain_def"
                    ;;
            esac
        done
    fi
}

table_epilogue() {
    if [ "$PRINT_ONLY" = "1" ]; then
        echo "COMMIT"
    fi
}

# --- the ruleset --------------------------------------------------------------
# Every rule below appears exactly once; apply mode and --print both walk the
# same calls in the same order (filter table first-fit: order is semantic).

build_ruleset() {
    if [ "$PRINT_ONLY" = "1" ]; then
        echo "# dtn-firewall.sh --print: inspection model of the DTN ruleset."
        echo "# Do NOT apply with iptables-restore: the real apply path"
        echo "# (/usr/local/sbin/dtn-firewall.sh, run by dtn-firewall.service)"
        echo "# is incremental and never flushes rules it does not own."
        echo "# AP=$WLAN_IF PORTAL=$PORTAL_PORT SUBNET=$CLIENT_SUBNET NODE=$NODE_IP SSH=$ALLOW_SSH"
    fi

    # --- 1. captive-portal redirect (nat) ------------------------------------
    # Any TCP connection to port 80 arriving on the AP interface is redirected
    # to the local portal daemon. REDIRECT (not DNAT) keeps the destination
    # address intact for the socket, which is what we want for a local
    # service. This one rule covers the §10.2 captive probes too: they are
    # plain HTTP to the node, so nothing beyond 8080 is ever needed.
    table_prologue nat \
        "PREROUTING ACCEPT" "INPUT ACCEPT" "OUTPUT ACCEPT" "POSTROUTING ACCEPT" \
        "$NAT_CHAIN"
    rule nat PREROUTING -i "$WLAN_IF" -m comment --comment dtn:captive-portal-hook -j "$NAT_CHAIN"
    rule nat "$NAT_CHAIN" -p tcp -m tcp --dport 80 -m comment --comment dtn:probes-and-any-url-land-on-portal -j REDIRECT --to-ports "$PORTAL_PORT"
    table_epilogue

    # --- 2. filter table -------------------------------------------------------
    table_prologue filter \
        "INPUT ACCEPT" "FORWARD DROP" "OUTPUT ACCEPT" \
        "$IN_CHAIN" "$DNSBL_CHAIN" "$ACC_CHAIN"

    # INPUT skeleton. Order matters: the AP-client jump comes BEFORE the
    # ESTABLISHED,RELATED accept so that per-service rate limits in
    # $IN_CHAIN see every packet (a UDP DNS socket that receives replies is
    # conntrack-ESTABLISHED and would otherwise slip past any NEW-only
    # limit). Loopback is trusted unconditionally.
    # [print mode notes ":INPUT ACCEPT" — that is the stock default; the
    # apply path below never touches the INPUT policy.]
    rule filter INPUT -i lo -m comment --comment dtn:loopback-trusted -j ACCEPT
    rule filter INPUT -i "$WLAN_IF" -m comment --comment dtn:client-subnet-enters-here -j "$IN_CHAIN"
    rule filter INPUT -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment dtn:replies-to-own-connections -j ACCEPT

    # Documented stance on the INPUT policy: we deliberately leave it at the
    # distribution default (ACCEPT) instead of flipping it to DROP. The node
    # is a standalone island with no uplink; the only externally reachable
    # services are the ones this script accepts (now rate-limited above), and
    # a hard INPUT DROP would also cut off the operator's own maintenance
    # access (serial console sharing, local curl checks, sshd) the moment a
    # new legitimate service is added without a rule. Attack surface here
    # equals "the services we run", which the accepts make explicit. Clients
    # cannot exploit the policy for egress: their traffic enters through the
    # $IN_CHAIN above and every egress desire dies in FORWARD.

    # $ACC_CHAIN first: per-source byte counters (inserted at runtime by
    # dtn-station-shield.sh) must see everything, including packets that are
    # dropped further down. Aggregate counter = this jump rule's counters.
    rule filter "$IN_CHAIN" -m comment --comment dtn:accounting-counts-everything-first -j "$ACC_CHAIN"
    # $DNSBL_CHAIN: empty at boot; dtn-dns-shield.sh inserts one -s SRC -j
    # DROP per shed source with a cooldown. Kept volatile ON PURPOSE
    # (privacy, issue #16 / docs/protocol.md §13): this run of the script
    # flushes it, so no client IP ever survives a reboot or reaches disk via
    # netfilter-persistent's rules.v4.
    rule filter "$IN_CHAIN" -m comment --comment dtn:runtime-dns-blacklist-dtn-dns-shield -j "$DNSBL_CHAIN"

    # DHCP: dnsmasq answers DISCOVER on udp/67 (udp/68 is the client's
    # source port; opening 67 is what makes DHCP work at all).
    rule filter "$IN_CHAIN" -p udp -m udp --dport 67 -m comment --comment dtn:dhcp-server -j ACCEPT

    # DNS with per-source flood/tunnel shedding: the hashlimit DROP matches
    # only sources ABOVE the rate; everyone else falls through to the plain
    # accepts. Deliberately NO ctstate qualifier (see INPUT skeleton note).
    rule filter "$IN_CHAIN" -p udp -m udp --dport 53 -m hashlimit --hashlimit-above "${DNS_HL_RATE_QPS}/second" --hashlimit-burst "$DNS_HL_BURST" --hashlimit-mode srcip --hashlimit-name dtn_dns_udp -m comment --comment dtn:anti-dnstunnel-per-src-shed -j DROP
    rule filter "$IN_CHAIN" -p tcp -m tcp --dport 53 -m hashlimit --hashlimit-above "${DNS_HL_RATE_QPS}/second" --hashlimit-burst "$DNS_HL_BURST" --hashlimit-mode srcip --hashlimit-name dtn_dns_tcp -m comment --comment dtn:anti-dnstunnel-per-src-shed -j DROP
    rule filter "$IN_CHAIN" -p udp -m udp --dport 53 -m comment --comment dtn:dns-under-rate -j ACCEPT
    rule filter "$IN_CHAIN" -p tcp -m tcp --dport 53 -m comment --comment dtn:dns-under-rate -j ACCEPT

    # The portal (canonical origin http://offgrid.local:8080), guarded against
    # SYN floods and connection hoarding per source IP. The SYN hashlimit
    # counts only NEW connections, so established legitimate transfers are
    # never disturbed; the connlimit is what actually stops socket hoarders.
    rule filter "$IN_CHAIN" -p tcp -m tcp --dport "$PORTAL_PORT" -m conntrack --ctstate NEW -m hashlimit --hashlimit-above "${PORTAL_SYN_RATE_PER_MIN}/minute" --hashlimit-burst "$PORTAL_SYN_BURST" --hashlimit-mode srcip --hashlimit-name dtn_portal_syn -m comment --comment dtn:portal-synflood-guard -j DROP
    rule filter "$IN_CHAIN" -p tcp -m tcp --dport "$PORTAL_PORT" -m connlimit --connlimit-above "$PORTAL_CONN_LIMIT" --connlimit-mask 32 --connlimit-saddr -m comment --comment dtn:portal-conns-per-client-cap -j DROP
    rule filter "$IN_CHAIN" -p tcp -m tcp --dport "$PORTAL_PORT" -m comment --comment dtn:portal-canonical-origin -j ACCEPT

    # ICMP: fragmented echo payloads are a classic tunnel/evasion carrier and
    # never legitimate from a client, so they die unconditionally; everything
    # else is per-source rate limited (see ICMP_HL_* above). Requests above
    # the rate are dropped BEFORE the accept, not just unaccepted — the INPUT
    # policy stays ACCEPT (documented below), so an unaccepted-but-not-dropped
    # packet would sail through.
    rule filter "$IN_CHAIN" -p icmp -m comment --comment dtn:fragmented-icmp-tunnel-evasion -f -j DROP
    rule filter "$IN_CHAIN" -p icmp -m icmp --icmp-type 8 -m hashlimit --hashlimit-above "${ICMP_HL_RATE_QPS}/second" --hashlimit-burst "$ICMP_HL_BURST" --hashlimit-mode srcip --hashlimit-name dtn_icmp -m comment --comment dtn:icmp-flood-tunnel-shed -j DROP
    rule filter "$IN_CHAIN" -p icmp -m comment --comment dtn:icmp-under-rate -j ACCEPT

    # Opt-in SSH for the operator, restricted to the AP subnet interface. Off
    # by default: an unattended solar node needs no listener.
    if [ "$ALLOW_SSH" = "1" ]; then
        rule filter "$IN_CHAIN" -p tcp -m tcp --dport 22 -m comment --comment dtn:opt-in-operator-ssh -j ACCEPT
    fi
    # Unmatched AP traffic falls through to the rest of INPUT unchanged.
    rule filter "$IN_CHAIN" -j RETURN

    # Accounting chain: per-source counter rules get inserted ABOVE this
    # terminal RETURN by dtn-station-shield.sh; the RETURN keeps the chain
    # transparent for everything else.
    rule filter "$ACC_CHAIN" -m comment --comment dtn:station-shield-inserts-counters-above -j RETURN

    # --- 3. FORWARD: total client isolation at layer 3 (issue #16 Track 1) --
    # The node is an island: there is nothing a client packet could ever be
    # legitimately forwarded TO — not another client (ap_isolate=1 at L2),
    # not an uplink (none exists), not anything else. The rules below are
    # REDUNDANT WITH THE POLICY on purpose (defense in depth): each named
    # drop states one concrete escape route and carries its own counter, so
    # an operator running "iptables -vL FORWARD" sees WHICH tunnel a client
    # attempted. Nothing in FORWARD ever ACCEPTs.
    #
    # Named escape-route kills (first, so their per-rule counters stay hot):
    rule filter FORWARD -s "$CLIENT_SUBNET" -p tcp -m tcp --dport 22 -m comment --comment track1:ssh-egress-kill -j DROP
    rule filter FORWARD -s "$CLIENT_SUBNET" -p tcp -m tcp --dport 23 -m comment --comment track1:telnet-egress-kill -j DROP
    rule filter FORWARD -s "$CLIENT_SUBNET" -p tcp -m tcp --dport 1080 -m comment --comment track1:socks-proxy-egress-kill -j DROP
    rule filter FORWARD -s "$CLIENT_SUBNET" -p tcp -m tcp --dport 3128 -m comment --comment track1:squid-proxy-egress-kill -j DROP
    rule filter FORWARD -s "$CLIENT_SUBNET" -p tcp -m tcp --dport 443 -m comment --comment track1:https-doh-egress-kill -j DROP
    rule filter FORWARD -s "$CLIENT_SUBNET" -p tcp -m tcp --dport 8080 -m comment --comment track1:proxy-port-reuse-egress-kill -j DROP
    rule filter FORWARD -s "$CLIENT_SUBNET" -p tcp -m tcp --dport 853 -m comment --comment track1:dns-over-tls-kill -j DROP
    rule filter FORWARD -s "$CLIENT_SUBNET" -p udp -m udp --dport 853 -m comment --comment track1:dns-over-tls-kill -j DROP
    # DoH rides tcp/443 to arbitrary hosts (killed above with HTTPS egress);
    # there is no distinct DoH port to block — the no-forward default is the
    # DoH defense, stated here so the stance is on record.
    rule filter FORWARD -s "$CLIENT_SUBNET" -p tcp -m tcp --dport 53 -m comment --comment track1:tcp-dns-egress-kill-use-own-resolver -j DROP
    rule filter FORWARD -s "$CLIENT_SUBNET" -p udp -m udp --dport 53 -m comment --comment track1:udp-dns-egress-kill-use-own-resolver -j DROP
    rule filter FORWARD -s "$CLIENT_SUBNET" -p udp -m udp --dport 500 -m comment --comment track1:ike-isakmp-kill -j DROP
    rule filter FORWARD -s "$CLIENT_SUBNET" -p udp -m udp --dport 4500 -m comment --comment track1:ipsec-natt-kill -j DROP
    rule filter FORWARD -s "$CLIENT_SUBNET" -p tcp -m tcp --dport 1194 -m comment --comment track1:openvpn-tcp-kill -j DROP
    rule filter FORWARD -s "$CLIENT_SUBNET" -p udp -m udp --dport 1194 -m comment --comment track1:openvpn-udp-kill -j DROP
    rule filter FORWARD -s "$CLIENT_SUBNET" -p udp -m udp --dport 51820 -m comment --comment track1:wireguard-kill -j DROP
    rule filter FORWARD -s "$CLIENT_SUBNET" -p udp -m udp --dport 1701 -m comment --comment track1:l2tp-kill -j DROP
    rule filter FORWARD -s "$CLIENT_SUBNET" -p tcp -m tcp --dport 1723 -m comment --comment track1:pptp-control-kill -j DROP
    rule filter FORWARD -s "$CLIENT_SUBNET" -p gre -m comment --comment track1:pptp-gre-data-kill -j DROP
    rule filter FORWARD -s "$CLIENT_SUBNET" -p icmp -m comment --comment track1:fragmented-icmp-kill -f -j DROP
    rule filter FORWARD -s "$CLIENT_SUBNET" -p icmp -m hashlimit --hashlimit-above "${ICMP_HL_RATE_QPS}/second" --hashlimit-burst "$ICMP_HL_BURST" --hashlimit-mode srcip --hashlimit-name dtn_icmp_fwd -m comment --comment track1:icmp-tunnel-kill -j DROP
    # Blanket rule: raw TCP (and everything else) from the client subnet is
    # forwarded nowhere, ever. Even if a future edit adds an ACCEPT above or
    # flips the policy, this line still states — and enforces — the island
    # invariant.
    rule filter FORWARD -s "$CLIENT_SUBNET" -m comment --comment track1:blanket-no-client-forwarding-ever -j DROP
    rule filter FORWARD -d "$CLIENT_SUBNET" -m comment --comment track1:nothing-forwarded-to-clients-either -j DROP
    # The policy itself, restated: no accept rules at all in FORWARD — clients
    # can never reach each other at layer 3 (reinforcing ap_isolate=1 at
    # layer 2) and no traffic is ever forwarded anywhere.
    table_epilogue
}

if [ "$PRINT_ONLY" = "1" ]; then
    build_ruleset
    exit 0
fi

build_ruleset

# --- persistence ----------------------------------------------------------------

# Prefer netfilter-persistent (Debian standard): writing /etc/iptables/rules.v4
# makes the installed iptables-persistent plugin replay these rules at boot.
# When the package is absent, the companion dtn-firewall.service oneshot
# re-applies them at every boot instead. Runtime-populated state (DTN_DNSBL
# blacklist entries, DTN_ACC per-source counters) is flushed by the re-run
# above BEFORE the save, so rules.v4 never carries client-identifying data.
if [ -d /etc/iptables ] && command -v iptables-save >/dev/null 2>&1; then
    iptables-save > /etc/iptables/rules.v4
    log "rules saved to /etc/iptables/rules.v4 (netfilter-persistent replays them at boot)"
else
    log "netfilter-persistent not installed; dtn-firewall.service re-applies rules at every boot"
fi

log "firewall ready: AP=$WLAN_IF portal port=$PORTAL_PORT ssh=$ALLOW_SSH forward=DROP dns<=${DNS_HL_RATE_QPS}/s per src portal<=${PORTAL_CONN_LIMIT} conns per src icmp<=${ICMP_HL_RATE_QPS}/s per src"
