#!/usr/bin/env bash
# tests/hardening_structure.sh — structural security test for the Raspberry Pi
# anti-circumvention hardening (Module A, issue #16 Track 1: "the AP is not
# free Internet").
#
# The deployment target is Raspberry Pi OS Bookworm, but this test runs on any
# POSIX-ish host (macOS dev machines included) WITHOUT root and WITHOUT
# iptables/tc/hostapd: it asserts the security properties ON THE GENERATED
# ARTIFACTS rather than on a live kernel —
#
#   1. bash -n syntax-checks every shell script the hardening work added or
#      touches;
#   2. raspberry/firewall/iptables.sh --print emits the full ruleset in
#      iptables-restore format WITHOUT root (rule-generation/application
#      separation); the test then asserts: FORWARD policy DROP; every FORWARD
#      rule scoped to the client subnet and every one of them a DROP; the
#      explicit escape-route kills (SSH/telnet/SOCKS/squid/443/8080 egress,
#      DoT 853, DNS egress 53, IKE 500/4500, OpenVPN 1194, WireGuard 51820,
#      L2TP 1701, PPTP 1723 + GRE); the per-source DNS hashlimit; the portal
#      connlimit + NEW-connection hashlimit on 8080; the ICMP rate limit and
#      fragmented-ICMP drops; the captive-portal REDIRECT; the runtime shield
#      chains; and that nothing ever ACCEPTs, MASQUERADEs or SNATs client
#      traffic anywhere;
#   3. raspberry/firewall/traffic-shaping.sh --dry-run prints the exact tc
#      stream: cake dual-dsthost on the wlan0 egress, the IFB ingress mirror
#      with cake dual-srchost for the client->node direction;
#   4. raspberry/firewall/dns-shield.sh --dry-run: a synthetic dnsmasq log
#      (via env overrides) with a 100 q/s flooder and a quiet client — the
#      flooder is shed, the quiet client is not, queried DOMAIN NAMES never
#      appear in the output (blind-node privacy, docs/protocol.md §13), the
#      fixture is not mutated, and state lives under tmpfs;
#   5. raspberry/firewall/station-shield.sh --dry-run with a fake hostapd_cli,
#      lease file and conntrack fixture: the quota hog and the connection
#      hoarder are shed via hostapd_cli deauthenticate, the honest mule is
#      not, hostapd_cli absence degrades gracefully, state lives under tmpfs;
#   6. the systemd units/timers exist, point at the installed script paths and
#      carry a firing cadence; provision.sh installs and enables them;
#   7. docs/BUILD.md lists this test in "Run all tests";
#   8. issue #16 Track 3 (hostile clients + node hardening) on the generated
#      artifacts as well: the INPUT-side tcp/22 kill for the client subnet;
#      the daemon unit's hardening set (unprivileged user, ProtectSystem=
#      strict + ReadWritePaths, Restart=always, watchdog, W^X); the sshd
#      drop-in (keys only, no root login) and its validate-before-install
#      script; the read-only-root twins (dry-run/--status, the durable
#      data-dir bind-mount in the generated initramfs script, rollback);
#      the network watchdog (per-component restart plan, restart-storm
#      guard, tmpfs state); and the counters-only telemetry (one aggregated
#      integer line, no MAC/IP ever leaves its parsers, all_sta never
#      called — §13 blind-node privacy).
#
# NOT covered here (by design): live-kernel rule application, real tc qdiscs
# and real hostapd deauthentication — those need a rooted Pi and belong to the
# on-hardware checklist (docs/BUILD.md §5 "Verify after reboot"); the portal
# daemon's own behavior is covered by tests/sync_e2e.sh and the Go tests.
#
# Usage:  bash tests/hardening_structure.sh
# Needs:  bash only (grep/sed/awk/sha256sum-or-shasum/mktemp). No root, no
#         network, no hardware.
# Exit:   0 = every assertion passed; 1 = at least one failed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PASS_COUNT=0
FAIL_COUNT=0

WORK="$(mktemp -d "${TMPDIR:-/tmp}/dtn-hardening.XXXXXX")"
cleanup() {
    local status=$?
    rm -rf "$WORK"
    exit "$status"
}
trap cleanup EXIT

log() { printf '%s\n' "hardening: $*"; }

# check DESC EXPECTED ACTUAL — record one assertion (PASS or FAIL), exactly
# the sync_e2e.sh style.
check() {
    if [ "$2" = "$3" ]; then
        printf 'PASS: %s\n' "$1"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        printf 'FAIL: %s\n      expected [%s]\n      actual   [%s]\n' "$1" "$2" "$3"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

# sha256_file PATH — portable sha256 (macOS shasum / GNU sha256sum).
sha256_file() {
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        sha256sum "$1" | awk '{print $1}'
    fi
}

# count_regex PATTERN FILE — number of lines matching an extended regex
# (0 when grep finds nothing; never fails the run).
count_regex() {
    { grep -Ec -- "$1" "$2" || true; }
}

# has_line FIXED STRING FILE — 1 when FILE contains the exact line (fixed-
# string match; used for lines with braces/$ that ERE would mangle).
has_line() {
    if grep -Fqx -- "$1" "$2" 2>/dev/null; then printf 1; else printf 0; fi
}

# refused_nonroot LOGFILE RC — "refused" when a script exited non-zero naming
# root as the reason (the dry-run/print paths are the rootless surface).
refused_nonroot() {
    if [ "$2" -ne 0 ] && grep -q root "$1" 2>/dev/null; then printf refused; else printf broken; fi
}

# ---------------------------------------------------------------------------
# 1. Syntax gate: bash -n on every shell script in the hardening surface.
# ---------------------------------------------------------------------------
log "section 1: bash -n syntax checks"
for script in \
    "$ROOT/raspberry/provision.sh" \
    "$ROOT/raspberry/install.sh" \
    "$ROOT/raspberry/firewall/iptables.sh" \
    "$ROOT/raspberry/firewall/dns-shield.sh" \
    "$ROOT/raspberry/firewall/station-shield.sh" \
    "$ROOT/raspberry/firewall/traffic-shaping.sh" \
    "$ROOT/raspberry/hardening/harden-ssh.sh" \
    "$ROOT/raspberry/hardening/harden-services.sh" \
    "$ROOT/raspberry/hardening/harden-upgrades.sh" \
    "$ROOT/raspberry/hardening/enable-readonly-root.sh" \
    "$ROOT/raspberry/hardening/disable-readonly-root.sh" \
    "$ROOT/raspberry/hardening/dtn-network-watchdog.sh" \
    "$ROOT/raspberry/hardening/dtn-telemetry.sh" \
    "$SCRIPT_DIR/hardening_structure.sh"; do
    if bash -n "$script" 2> "$WORK/synerr"; then
        check "bash -n $(basename "$script") parses clean" "ok" "ok"
    else
        check "bash -n $(basename "$script") parses clean" "ok" "syntax error: $(cat "$WORK/synerr")"
    fi
done

# ---------------------------------------------------------------------------
# 2. hostapd.conf: layer-2 isolation + the control socket the shields need.
# ---------------------------------------------------------------------------
log "section 2: hostapd.conf client isolation"
HOSTAPD_CONF="$ROOT/raspberry/hostapd/hostapd.conf"
check "hostapd.conf: ap_isolate=1 present (L2 clients never talk to each other)" \
    "1" "$(count_regex '^ap_isolate=1$' "$HOSTAPD_CONF")"
check "hostapd.conf: ctrl_interface present (dtn-station-shield hostapd_cli dependency)" \
    "1" "$(count_regex '^ctrl_interface=/var/run/hostapd$' "$HOSTAPD_CONF")"
check "hostapd.conf: no bridge= line (bridging would leak L2 frames off the island)" \
    "0" "$(count_regex '^bridge=' "$HOSTAPD_CONF")"
# Audit pins (docs/security-audit.md §4): the open-AP stance is explicit and
# stays free of link-layer secrets and WPS push-button surface.
check "hostapd.conf: explicitly open (wpa=0 + auth_algs=1, exactly once each)" \
    "2" "$(count_regex '^wpa=0$|^auth_algs=1$' "$HOSTAPD_CONF")"
check "hostapd.conf: no WPS anywhere (wps_state/wps_pbc/eap_server would add a virtual push-button to an open AP)" \
    "0" "$(count_regex '^wps_state=|^wps_pbc=|^eap_server=' "$HOSTAPD_CONF")"
check "hostapd.conf: no wpa_passphrase (open by design — a committed PSK would be a shared secret pretending to be one)" \
    "0" "$(count_regex '^wpa_passphrase' "$HOSTAPD_CONF")"
check "hostapd.conf: SSID broadcast on (a hidden SSID breaks captive detection, adds zero security)" \
    "1" "$(count_regex '^ignore_broadcast_ssid=0$' "$HOSTAPD_CONF")"
check "hostapd.conf: association ceiling max_num_sta=20 (L2 backstop for every per-source shield)" \
    "1" "$(count_regex '^max_num_sta=20$' "$HOSTAPD_CONF")"

# ---------------------------------------------------------------------------
# 3. dnsmasq.conf: authoritative wildcard for the portal only + tmpfs query
#    log for the DNS shield.
# ---------------------------------------------------------------------------
log "section 3: dnsmasq.conf authoritative portal DNS"
DNSMASQ_CONF="$ROOT/raspberry/dnsmasq/dnsmasq.conf"
check "dnsmasq.conf: wildcard answer address=/#/10.42.0.1 (every name resolves to the portal)" \
    "1" "$(count_regex '^address=/#/10\.42\.0\.1$' "$DNSMASQ_CONF")"
check "dnsmasq.conf: canonical host record address=/offgrid.local/10.42.0.1 (protocol §12)" \
    "1" "$(count_regex '^address=/offgrid\.local/10\.42\.0\.1$' "$DNSMASQ_CONF")"
check "dnsmasq.conf: probe domains still wildcard-answered (no per-domain carve-outs)" \
    "0" "$(count_regex '^address=/connectivitycheck|^address=/captive\.apple|^address=/edge\.microsoft' "$DNSMASQ_CONF")"
check "dnsmasq.conf: no-resolv (no upstream resolver to tunnel through)" \
    "1" "$(count_regex '^no-resolv$' "$DNSMASQ_CONF")"
check "dnsmasq.conf: zero server= upstream lines (island resolver)" \
    "0" "$(count_regex '^server=' "$DNSMASQ_CONF")"
check "dnsmasq.conf: log-queries enabled (dtn-dns-shield feed)" \
    "1" "$(count_regex '^log-queries$' "$DNSMASQ_CONF")"
check "dnsmasq.conf: query log goes to tmpfs /dev/shm (names never hit disk, §13)" \
    "1" "$(count_regex '^log-facility=/dev/shm/' "$DNSMASQ_CONF")"
check "dnsmasq.conf: explicit dhcp-leasefile (station-shield MAC<->IP source)" \
    "1" "$(count_regex '^dhcp-leasefile=/var/lib/misc/dnsmasq\.leases$' "$DNSMASQ_CONF")"

# ---------------------------------------------------------------------------
# 3b. provision.sh static_ip: IPv6 disabled on the client-facing interfaces
#     (audit PI-01, docs/security-audit.md §4 — the Track-1 shields are
#     iptables/IPv4-only; a live link-local address on wlan0 would be a side
#     door around every per-source hashlimit, the connlimit and DTN_DNSBL).
# ---------------------------------------------------------------------------
log "section 3b: provision.sh IPv6 island sysctl (PI-01)"
PROVISION="$ROOT/raspberry/provision.sh"
check "provision.sh: installs the island sysctl file at /etc/sysctl.d/99-dtn-island.conf" \
    "1" "$(count_regex 'install_file "\$tmp" /etc/sysctl\.d/99-dtn-island\.conf 0644' "$PROVISION")"
check "provision.sh: IPv6 disabled on wlan0 (the AP interface itself)" \
    "1" "$(count_regex '^net\.ipv6\.conf\.wlan0\.disable_ipv6 = 1$' "$PROVISION")"
check "provision.sh: IPv6 disabled on eth0 (the wired side)" \
    "1" "$(count_regex '^net\.ipv6\.conf\.eth0\.disable_ipv6 = 1$' "$PROVISION")"
check "provision.sh: IPv6 disabled by default for interfaces created later" \
    "1" "$(count_regex '^net\.ipv6\.conf\.default\.disable_ipv6 = 1$' "$PROVISION")"
check "provision.sh: loopback keeps its IPv6 (no conf.all hammer — the daemon's dual-stack bind stays valid)" \
    "0" "$(count_regex 'conf\.all\.disable_ipv6' "$PROVISION")"
check "provision.sh: applies the sysctl file immediately (closes the pre-reboot window)" \
    "1" "$(count_regex 'sysctl -q -p /etc/sysctl\.d/99-dtn-island\.conf' "$PROVISION")"

# ---------------------------------------------------------------------------
# 4. iptables.sh --print: the generated ruleset IS the security surface.
# ---------------------------------------------------------------------------
log "section 4: iptables.sh --print generated ruleset"
RULES="$WORK/rules.txt"
if "$ROOT/raspberry/firewall/iptables.sh" --print > "$RULES" 2> "$WORK/rules.err"; then
    check "iptables.sh --print runs rootless and emits a ruleset" "ok" "ok"
else
    check "iptables.sh --print runs rootless and emits a ruleset" "ok" "failed: $(cat "$WORK/rules.err")"
fi
"$ROOT/raspberry/firewall/iptables.sh" --print > "$WORK/rules2.txt" 2>/dev/null
if cmp -s "$RULES" "$WORK/rules2.txt"; then
    check "iptables.sh --print is deterministic (two runs byte-identical)" "ok" "ok"
else
    check "iptables.sh --print is deterministic (two runs byte-identical)" "ok" "output differs between runs"
fi

check "ruleset: *nat table present" "1" "$(count_regex '^\*nat$' "$RULES")"
check "ruleset: *filter table present" "1" "$(count_regex '^\*filter$' "$RULES")"
check "ruleset: exactly two COMMIT terminators" "2" "$(count_regex '^COMMIT$' "$RULES")"

check "ruleset: FORWARD policy is DROP (no forwarding by default, ever)" \
    "1" "$(count_regex '^:FORWARD DROP ' "$RULES")"
check "ruleset: zero ACCEPT rules in FORWARD (client isolation at L3)" \
    "0" "$(count_regex '^-A FORWARD .* -j ACCEPT' "$RULES")"
FORWARD_TOTAL="$(count_regex '^-A FORWARD ' "$RULES")"
FORWARD_SCOPED=$(( $(count_regex '^-A FORWARD -s 10\.42\.0\.0/24 ' "$RULES") + $(count_regex '^-A FORWARD -d 10\.42\.0\.0/24 ' "$RULES") ))
check "ruleset: every FORWARD rule is scoped to the client subnet (10.42.0.0/24)" \
    "$FORWARD_TOTAL" "$FORWARD_SCOPED"
check "ruleset: blanket client-subnet forward drop present (raw TCP to the Internet dies here)" \
    "1" "$(count_regex '^-A FORWARD -s 10\.42\.0\.0/24 .*track1:blanket-no-client-forwarding-ever.* -j DROP' "$RULES")"
check "ruleset: no NAT egress of any kind (zero MASQUERADE/SNAT)" \
    "0" "$(count_regex 'MASQUERADE|-j SNAT' "$RULES")"

# Explicit escape-route kills in FORWARD (defense in depth vs the DROP
# policy; issue #16 Track 1 section 2 checklist).
check "FORWARD kill: SSH egress tcp/22"            "1" "$(count_regex '^-A FORWARD -s 10\.42\.0\.0/24 -p tcp .* --dport 22 .* -j DROP' "$RULES")"
check "FORWARD kill: telnet egress tcp/23"         "1" "$(count_regex '^-A FORWARD -s 10\.42\.0\.0/24 -p tcp .* --dport 23 .* -j DROP' "$RULES")"
check "FORWARD kill: SOCKS proxy egress tcp/1080"  "1" "$(count_regex '^-A FORWARD -s 10\.42\.0\.0/24 -p tcp .* --dport 1080 .* -j DROP' "$RULES")"
check "FORWARD kill: squid proxy egress tcp/3128"  "1" "$(count_regex '^-A FORWARD -s 10\.42\.0\.0/24 -p tcp .* --dport 3128 .* -j DROP' "$RULES")"
check "FORWARD kill: HTTPS/DoH egress tcp/443"     "1" "$(count_regex '^-A FORWARD -s 10\.42\.0\.0/24 -p tcp .* --dport 443 .* -j DROP' "$RULES")"
check "FORWARD kill: proxy-port reuse tcp/8080 toward other hosts" \
    "1" "$(count_regex '^-A FORWARD -s 10\.42\.0\.0/24 -p tcp .* --dport 8080 .* -j DROP' "$RULES")"
check "FORWARD kill: DNS-over-TLS tcp/853"         "1" "$(count_regex '^-A FORWARD -s 10\.42\.0\.0/24 -p tcp .* --dport 853 .* -j DROP' "$RULES")"
check "FORWARD kill: DNS-over-TLS udp/853"         "1" "$(count_regex '^-A FORWARD -s 10\.42\.0\.0/24 -p udp .* --dport 853 .* -j DROP' "$RULES")"
check "FORWARD kill: DNS egress tcp/53 (own resolver only)" \
    "1" "$(count_regex '^-A FORWARD -s 10\.42\.0\.0/24 -p tcp .* --dport 53 .* -j DROP' "$RULES")"
check "FORWARD kill: DNS egress udp/53 (own resolver only)" \
    "1" "$(count_regex '^-A FORWARD -s 10\.42\.0\.0/24 -p udp .* --dport 53 .* -j DROP' "$RULES")"
check "FORWARD kill: IKE handshake udp/500"        "1" "$(count_regex '^-A FORWARD -s 10\.42\.0\.0/24 -p udp .* --dport 500 .* -j DROP' "$RULES")"
check "FORWARD kill: IPsec NAT-T udp/4500"         "1" "$(count_regex '^-A FORWARD -s 10\.42\.0\.0/24 -p udp .* --dport 4500 .* -j DROP' "$RULES")"
check "FORWARD kill: OpenVPN tcp/1194 + udp/1194"  "2" "$(count_regex '^-A FORWARD -s 10\.42\.0\.0/24 .* --dport 1194 .* -j DROP' "$RULES")"
check "FORWARD kill: WireGuard udp/51820"          "1" "$(count_regex '^-A FORWARD -s 10\.42\.0\.0/24 -p udp .* --dport 51820 .* -j DROP' "$RULES")"
check "FORWARD kill: L2TP udp/1701"                "1" "$(count_regex '^-A FORWARD -s 10\.42\.0\.0/24 -p udp .* --dport 1701 .* -j DROP' "$RULES")"
check "FORWARD kill: PPTP control tcp/1723"        "1" "$(count_regex '^-A FORWARD -s 10\.42\.0\.0/24 -p tcp .* --dport 1723 .* -j DROP' "$RULES")"
check "FORWARD kill: PPTP data-channel GRE"        "1" "$(count_regex '^-A FORWARD -s 10\.42\.0\.0/24 -p gre .* -j DROP' "$RULES")"

# INPUT-side rate guards (the services stay open, the floods do not).
check "INPUT: per-source DNS hashlimit shed on udp/53" \
    "1" "$(count_regex '^-A DTN_INPUT -p udp .* --dport 53 .*hashlimit.* -j DROP' "$RULES")"
check "INPUT: per-source DNS hashlimit shed on tcp/53" \
    "1" "$(count_regex '^-A DTN_INPUT -p tcp .* --dport 53 .*hashlimit.* -j DROP' "$RULES")"
check "INPUT: DNS still answered under the rate (udp+tcp accepts)" \
    "2" "$(count_regex '^-A DTN_INPUT -p (udp|tcp) .* --dport 53 .* -j ACCEPT' "$RULES")"
check "INPUT: portal SYN-flood hashlimit on NEW connections to 8080" \
    "1" "$(count_regex '^-A DTN_INPUT -p tcp .* --dport 8080 .*ctstate NEW .*hashlimit .* -j DROP' "$RULES")"
check "INPUT: portal connlimit per source IP on 8080" \
    "1" "$(count_regex '^-A DTN_INPUT .* --dport 8080 .*connlimit.* -j DROP' "$RULES")"
check "INPUT: portal itself still reachable on 8080 (canonical origin)" \
    "1" "$(count_regex '^-A DTN_INPUT .* --dport 8080 .* -j ACCEPT' "$RULES")"
check "INPUT: DHCP served (udp/67 accept)" \
    "1" "$(count_regex '^-A DTN_INPUT -p udp .* --dport 67 .* -j ACCEPT' "$RULES")"
check "INPUT: fragmented ICMP dropped outright (tunnel/evasion carrier)" \
    "1" "$(count_regex '^-A DTN_INPUT -p icmp .* -f -j DROP' "$RULES")"
check "INPUT: per-source ICMP hashlimit (icmpsh/ping-tunnel starvation)" \
    "1" "$(count_regex '^-A DTN_INPUT -p icmp .*hashlimit.* -j DROP' "$RULES")"
check "FORWARD: fragmented ICMP dropped for the client subnet too" \
    "1" "$(count_regex '^-A FORWARD -s 10\.42\.0\.0/24 -p icmp .* -f -j DROP' "$RULES")"
check "FORWARD: per-source ICMP hashlimit for the client subnet" \
    "1" "$(count_regex '^-A FORWARD -s 10\.42\.0\.0/24 -p icmp .*hashlimit.* -j DROP' "$RULES")"

# Captive-portal plumbing and the runtime shield chains.
check "nat: port-80 REDIRECT to the portal (probes included, protocol §10.2)" \
    "1" "$(count_regex '^-A DTN_PORTAL -p tcp .* --dport 80 .*REDIRECT --to-ports 8080' "$RULES")"
check "nat: REDIRECT hooked on the AP interface only" \
    "1" "$(count_regex '^-A PREROUTING -i wlan0 .* -j DTN_PORTAL' "$RULES")"
check "filter: runtime DNS-blacklist chain declared (dtn-dns-shield feed)" \
    "1" "$(count_regex '^:DTN_DNSBL ' "$RULES")"
check "filter: per-source accounting chain declared (dtn-station-shield feed)" \
    "1" "$(count_regex '^:DTN_ACC ' "$RULES")"
check "filter: client traffic enters the DTN_INPUT chain on the AP interface" \
    "1" "$(count_regex '^-A INPUT -i wlan0 .* -j DTN_INPUT' "$RULES")"

# Variables must actually flow into the generated ruleset (override and see).
# Grep the SAVED file, never a `--print | grep` pipe: under pipefail, grep -q
# exiting at the first match can SIGPIPE the producer and flip the result.
if grep -q -- '--hashlimit-above 25/second' "$RULES"; then
    DNS_HL_DEFAULT=wired
else
    DNS_HL_DEFAULT=missing
fi
check "ruleset: DNS hashlimit ceiling rendered from the documented default (25/s)" \
    "wired" "$DNS_HL_DEFAULT"
CLIENT_SUBNET=192.168.7.0/24 "$ROOT/raspberry/firewall/iptables.sh" --print > "$WORK/rules3.txt" 2>/dev/null
if grep -q -- '-A FORWARD -s 192\.168\.7\.0/24' "$WORK/rules3.txt"; then
    check "ruleset: CLIENT_SUBNET override flows through rule generation" "wired" "wired"
else
    check "ruleset: CLIENT_SUBNET override flows through rule generation" "wired" "missing"
fi

# Apply path must refuse to run without root (clear error, never a partial run).
"$ROOT/raspberry/firewall/iptables.sh" > "$WORK/apply.out" 2>&1 && APPLY_RC=0 || APPLY_RC=$?
check "iptables.sh apply path refuses non-root (and --print stays the rootless path)" \
    "refused" "$(refused_nonroot "$WORK/apply.out" "$APPLY_RC")"

# ---------------------------------------------------------------------------
# 5. traffic-shaping.sh --dry-run: the tc command stream.
# ---------------------------------------------------------------------------
log "section 5: traffic-shaping.sh --dry-run tc commands"
SHAPE_OUT="$WORK/shaping.txt"
"$ROOT/raspberry/firewall/traffic-shaping.sh" --dry-run > "$SHAPE_OUT" 2>&1 && SHAPE_RC=0 || SHAPE_RC=$?
check "traffic-shaping --dry-run runs rootless and exits 0" "0" "$SHAPE_RC"
check "shaping: egress cake qdisc replaces the wlan0 root qdisc" \
    "1" "$(count_regex 'qdisc replace dev wlan0 root cake bandwidth [0-9]+mbit dual-dsthost' "$SHAPE_OUT")"
check "shaping: ingress qdisc attached on the AP interface (ffff: ingress)" \
    "1" "$(count_regex 'qdisc replace dev wlan0 handle ffff: ingress' "$SHAPE_OUT")"
check "shaping: ingress mirrored into the ifb device (matchall mirred redirect)" \
    "1" "$(count_regex 'filter add dev wlan0 parent ffff: matchall action mirred egress redirect dev ifb0' "$SHAPE_OUT")"
check "shaping: per-source cake on the mirrored ingress (client->node fairness)" \
    "1" "$(count_regex 'qdisc replace dev ifb0 root cake bandwidth [0-9]+mbit dual-srchost' "$SHAPE_OUT")"
check "shaping: both host-fairness modes present (dual-srchost + dual-dsthost)" \
    "2" "$(count_regex 'dual-(srchost|dsthost)' "$SHAPE_OUT")"
check "shaping: bandwidth ceiling is a documented tunable (default rendered)" \
    "2" "$(count_regex 'bandwidth 25mbit' "$SHAPE_OUT")"
"$ROOT/raspberry/firewall/traffic-shaping.sh" > "$WORK/shape_apply.out" 2>&1 && SHAPE_APPLY_RC=0 || SHAPE_APPLY_RC=$?
check "traffic-shaping apply path refuses non-root" \
    "refused" "$(refused_nonroot "$WORK/shape_apply.out" "$SHAPE_APPLY_RC")"

# ---------------------------------------------------------------------------
# 6. dns-shield.sh --dry-run: shed the flooder, keep the quiet client, never
#    surface queried names (blind-node privacy).
# ---------------------------------------------------------------------------
log "section 6: dns-shield.sh --dry-run (synthetic dnsmasq window)"
DNS_LOG_FIXTURE="$WORK/dns-queries.log"
DNS_STATE_FIXTURE="$WORK/dns-state"
i=0
while [ "$i" -lt 6000 ]; do
    printf 'Oct  4 13:22:01 dnsmasq[923]: %d 10.42.0.66/41002 query[A] tunnel-marker-%d.evil.example from 10.42.0.66\n' "$i" "$i" >> "$DNS_LOG_FIXTURE"
    i=$((i + 1))
done
i=0
while [ "$i" -lt 8 ]; do
    printf 'Oct  4 13:22:01 dnsmasq[923]: %d 10.42.0.67/41003 query[A] quiet-mule.example from 10.42.0.67\n' "$i" >> "$DNS_LOG_FIXTURE"
    i=$((i + 1))
done
DNS_FIXTURE_SHA="$(sha256_file "$DNS_LOG_FIXTURE")"
DNS_OUT="$WORK/dnsshield.txt"
DNS_LOG="$DNS_LOG_FIXTURE" STATE_FILE="$DNS_STATE_FIXTURE" \
    "$ROOT/raspberry/firewall/dns-shield.sh" --dry-run > "$DNS_OUT" 2>&1 && DNS_RC=0 || DNS_RC=$?
check "dns-shield --dry-run runs rootless and exits 0" "0" "$DNS_RC"
check "dns-shield: 100 q/s source (>= 4x threshold) shed on the first window" \
    "1" "$(count_regex '\[dry-run\] would shed 10\.42\.0\.66' "$DNS_OUT")"
check "dns-shield: quiet client (0.13 q/s) is never shed" \
    "0" "$(count_regex 'would shed 10\.42\.0\.67' "$DNS_OUT")"
check "dns-shield: queried domain names NEVER appear in output (§13 blind-node privacy)" \
    "0" "$(count_regex 'evil\.example|quiet-mule\.example|tunnel-marker' "$DNS_OUT")"
check "dns-shield: dry-run is observational (fixture log byte-untouched)" \
    "$DNS_FIXTURE_SHA" "$(sha256_file "$DNS_LOG_FIXTURE")"
check "dns-shield: threshold variables documented with defaults (SHED_QPS/FAST_FACTOR/WINDOWS)" \
    "3" "$(count_regex '^DNS_SHED_QPS=|^DNS_SHED_FAST_FACTOR=|^DNS_SHED_WINDOWS=' "$ROOT/raspberry/firewall/dns-shield.sh")"
check "dns-shield: cooldown variable present (blacklist lifetime bounded)" \
    "1" "$(count_regex '^DNS_COOLDOWN_SECONDS=' "$ROOT/raspberry/firewall/dns-shield.sh")"
check "dns-shield: state + log defaults live under tmpfs /dev/shm (no persistence)" \
    "2" "$(($(has_line 'DNS_LOG="${DNS_LOG:-/dev/shm/dtn-dns-queries.log}"' "$ROOT/raspberry/firewall/dns-shield.sh") + $(has_line 'STATE_FILE="${STATE_FILE:-/dev/shm/dtn-dns-shield.state}"' "$ROOT/raspberry/firewall/dns-shield.sh")))"
check "dns-shield: window log is truncated after each run (bounded by construction)" \
    "1" "$(count_regex ': > "\$DNS_LOG"' "$ROOT/raspberry/firewall/dns-shield.sh")"
if grep -qF 'query\[[A-Za-z]+\]' "$ROOT/raspberry/firewall/dns-shield.sh" && \
   grep -qF '$NF ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ ' "$ROOT/raspberry/firewall/dns-shield.sh"; then
    PARSER_KEYED=1
else
    PARSER_KEYED=0
fi
check "dns-shield: awk parser keyed on query[TYPE] lines, validates \$NF as an IP (names never parsed)" \
    "1" "$PARSER_KEYED"
check "dns-shield: never writes outside tmpfs state (no redirects into /var, /etc, /home)" \
    "0" "$(count_regex '>>? ?/(var|etc|home)/' "$ROOT/raspberry/firewall/dns-shield.sh")"
DNS_LOG="$DNS_LOG_FIXTURE" STATE_FILE="$DNS_STATE_FIXTURE" \
    "$ROOT/raspberry/firewall/dns-shield.sh" > "$WORK/dns_apply.out" 2>&1 && DNS_APPLY_RC=0 || DNS_APPLY_RC=$?
check "dns-shield apply path refuses non-root" \
    "refused" "$(refused_nonroot "$WORK/dns_apply.out" "$DNS_APPLY_RC")"

# ---------------------------------------------------------------------------
# 7. station-shield.sh --dry-run: quota + connection heuristics, hostapd_cli
#    shedding, graceful degradation.
# ---------------------------------------------------------------------------
log "section 7: station-shield.sh --dry-run (synthetic hostapd/lease/conntrack state)"
cat > "$WORK/hostapd_cli" <<'FIXTURE_CLI'
#!/usr/bin/env bash
# test fixture: stands in for hostapd_cli all_sta
cat <<'FIXTURE_STA'
Selected interface 'wlan0'
addr=aa:bb:cc:00:00:01
flags=[AUTHORIZED][ASSOCIATED]
rx_bytes=134217728
tx_bytes=1048576

addr=aa:bb:cc:00:00:02
flags=[AUTHORIZED][ASSOCIATED]
rx_bytes=50000
tx_bytes=30000

addr=aa:bb:cc:00:00:03
flags=[AUTHORIZED][ASSOCIATED]
rx_bytes=4096
tx_bytes=2048
FIXTURE_STA
FIXTURE_CLI
chmod 0755 "$WORK/hostapd_cli"
cat > "$WORK/leases" <<'FIXTURE_LEASES'
1759500000 aa:bb:cc:00:00:01 10.42.0.66 quota-hog 01:aa:bb:cc:00:00:01
1759500000 aa:bb:cc:00:00:02 10.42.0.67 honest-mule 01:aa:bb:cc:00:00:02
1759500000 aa:bb:cc:00:00:03 10.42.0.68 conn-hoarder 01:aa:bb:cc:00:00:03
FIXTURE_LEASES
: > "$WORK/conntrack"
i=0
while [ "$i" -lt 100 ]; do
    printf 'ipv4 2 tcp 6 431998 ESTABLISHED src=10.42.0.68 dst=10.42.0.1 sport=%d dport=8080 src=10.42.0.1 dst=10.42.0.68 sport=8080 dport=%d [ASSURED] mark=0 use=1\n' "$((50000 + i))" "$((40000 + i))" >> "$WORK/conntrack"
    i=$((i + 1))
done
printf 'ipv4 2 tcp 6 431998 ESTABLISHED src=10.42.0.67 dst=10.42.0.1 sport=51000 dport=8080 src=10.42.0.1 dst=10.42.0.67 sport=8080 dport=51000 [ASSURED] mark=0 use=1\n' >> "$WORK/conntrack"
STA_OUT="$WORK/sta.txt"
HOSTAPD_CLI="$WORK/hostapd_cli" LEASE_FILE="$WORK/leases" NF_CONNTRACK="$WORK/conntrack" \
    STATE_FILE="$WORK/sta-state" \
    "$ROOT/raspberry/firewall/station-shield.sh" --dry-run > "$STA_OUT" 2>&1 && STA_RC=0 || STA_RC=$?
check "station-shield --dry-run runs rootless and exits 0" "0" "$STA_RC"
check "station-shield: quota hog (128 MiB moved on an ISLAND node) is shed" \
    "1" "$(count_regex 'would deauthenticate aa:bb:cc:00:00:01' "$STA_OUT")"
check "station-shield: connection hoarder (100 conns > cap) is shed" \
    "1" "$(count_regex 'would deauthenticate aa:bb:cc:00:00:03' "$STA_OUT")"
check "station-shield: honest mule (~80 KiB, 1 conn) is never shed" \
    "0" "$(count_regex 'would deauthenticate aa:bb:cc:00:00:02' "$STA_OUT")"
check "station-shield: shedding goes through hostapd_cli deauthenticate" \
    "1" "$(count_regex '\$HOSTAPD_CLI" -i "\$HOSTAPD_IF" deauthenticate' "$ROOT/raspberry/firewall/station-shield.sh")"
HOSTAPD_CLI=/nonexistent-hostapd-cli LEASE_FILE="$WORK/leases" NF_CONNTRACK="$WORK/conntrack" \
    STATE_FILE="$WORK/sta-state2" \
    "$ROOT/raspberry/firewall/station-shield.sh" --dry-run > "$WORK/sta2.txt" 2>&1 && STA2_RC=0 || STA2_RC=$?
check "station-shield: hostapd_cli absence degrades gracefully (exit 0 + log, never breaks the AP)" \
    "graceful" "$([ "$STA2_RC" -eq 0 ] && grep -q 'hostapd_cli not available' "$WORK/sta2.txt" && echo graceful || echo broken)"
check "station-shield: threshold variables documented with defaults (QUOTA/MAX_CONNS/COOLDOWN)" \
    "3" "$(count_regex '^STATION_QUOTA_BYTES=|^STATION_MAX_CONNS=|^STATION_COOLDOWN_SECONDS=' "$ROOT/raspberry/firewall/station-shield.sh")"
check "station-shield: state default lives under tmpfs /dev/shm (MACs never persisted)" \
    "1" "$(has_line 'STATE_FILE="${STATE_FILE:-/dev/shm/dtn-station-shield.state}"' "$ROOT/raspberry/firewall/station-shield.sh")"
check "station-shield: never writes outside tmpfs state (no redirects into /var, /etc, /home)" \
    "0" "$(count_regex '>>? ?/(var|etc|home)/' "$ROOT/raspberry/firewall/station-shield.sh")"
check "station-shield: state file holds only cooldown stamps + MACs (no counters persisted)" \
    "1" "$(count_regex 'cooldown \$\{mac\} \$\{expiry\}' "$ROOT/raspberry/firewall/station-shield.sh")"
HOSTAPD_CLI="$WORK/hostapd_cli" LEASE_FILE="$WORK/leases" \
    "$ROOT/raspberry/firewall/station-shield.sh" > "$WORK/sta_apply.out" 2>&1 && STA_APPLY_RC=0 || STA_APPLY_RC=$?
check "station-shield apply path refuses non-root" \
    "refused" "$(refused_nonroot "$WORK/sta_apply.out" "$STA_APPLY_RC")"

# ---------------------------------------------------------------------------
# 8. systemd wiring: units, timers, and the provision.sh hook.
# ---------------------------------------------------------------------------
log "section 8: systemd units, timers and provision.sh wiring"
FW_DIR="$ROOT/raspberry/firewall"
for unit in dtn-traffic-shaping.service dtn-dns-shield.service dtn-dns-shield.timer \
    dtn-station-shield.service dtn-station-shield.timer; do
    if [ -f "$FW_DIR/$unit" ]; then
        check "systemd: $unit exists" "ok" "ok"
    else
        check "systemd: $unit exists" "ok" "missing"
    fi
done
check "systemd: shaping unit execs the installed script" \
    "1" "$(count_regex '^ExecStart=/usr/local/sbin/dtn-traffic-shaping\.sh$' "$FW_DIR/dtn-traffic-shaping.service")"
check "systemd: dns shield unit execs the installed script" \
    "1" "$(count_regex '^ExecStart=/usr/local/sbin/dtn-dns-shield\.sh$' "$FW_DIR/dtn-dns-shield.service")"
check "systemd: station shield unit execs the installed script" \
    "1" "$(count_regex '^ExecStart=/usr/local/sbin/dtn-station-shield\.sh$' "$FW_DIR/dtn-station-shield.service")"
check "systemd: dns shield timer carries a firing cadence" \
    "1" "$(count_regex '^OnUnitActiveSec=' "$FW_DIR/dtn-dns-shield.timer")"
check "systemd: station shield timer carries a firing cadence" \
    "1" "$(count_regex '^OnUnitActiveSec=' "$FW_DIR/dtn-station-shield.timer")"
check "systemd: shield units keep their writable surface on tmpfs only" \
    "2" "$(($(count_regex '^ReadWritePaths=/dev/shm$' "$FW_DIR/dtn-dns-shield.service") + $(count_regex '^ReadWritePaths=/dev/shm$' "$FW_DIR/dtn-station-shield.service")))"
check "provision.sh: installs all three hardening executables to /usr/local/sbin" \
    "3" "$(count_regex 'dns-shield\.sh" /usr/local/sbin/dtn-dns-shield\.sh|station-shield\.sh" /usr/local/sbin/dtn-station-shield\.sh|traffic-shaping\.sh" /usr/local/sbin/dtn-traffic-shaping\.sh' "$ROOT/raspberry/provision.sh")"
check "provision.sh: installs the shield units and timers" \
    "5" "$(count_regex '^    install_file "\$SCRIPT_DIR/firewall/dtn-(traffic-shaping|dns-shield|station-shield).* /etc/systemd/system/' "$ROOT/raspberry/provision.sh")"
check "provision.sh: enables the shield timers (reboot activates them)" \
    "1" "$(count_regex 'dtn-dns-shield\.timer dtn-station-shield\.timer' "$ROOT/raspberry/provision.sh")"

# ---------------------------------------------------------------------------
# 9. Track 3: hostile clients + node hardening (issue #16) — the sshd drop-in,
#    the daemon unit's hardening set, the client->tcp/22 INPUT kill, the
#    read-only-root twins, the network watchdog and the counters-only
#    telemetry. Same philosophy as sections 4-7: assert the GENERATED
#    artifacts and the rootless surface (dry-run/--status/--print), never a
#    live kernel or a real sshd.
# ---------------------------------------------------------------------------
log "section 9: Track 3 hardening (ssh surface, daemon unit, readonly root, watchdog, telemetry)"
HARD_DIR="$ROOT/raspberry/hardening"
NODE_UNIT="$ROOT/raspberry/systemd/dtn-node.service"

# --- 9a. minimal SSH attack surface ----------------------------------------
SSHD_DROPIN="$HARD_DIR/sshd-hardening.conf"
check "sshd drop-in: PermitRootLogin no (no root over the network, ever)" \
    "1" "$(count_regex '^PermitRootLogin no$' "$SSHD_DROPIN")"
check "sshd drop-in: PasswordAuthentication no (keys only — hostile-network rule)" \
    "1" "$(count_regex '^PasswordAuthentication no$' "$SSHD_DROPIN")"
check "sshd drop-in: PubkeyAuthentication yes" \
    "1" "$(count_regex '^PubkeyAuthentication yes$' "$SSHD_DROPIN")"
check "sshd drop-in: agent + TCP forwarding both disabled (the node is an island)" \
    "2" "$(count_regex '^Allow(Agent|Tcp)Forwarding no$' "$SSHD_DROPIN")"
check "harden-ssh: validates with sshd -t BEFORE installing (a broken config must never strand the operator)" \
    "1" "$(count_regex 'SSHD_BIN" -t -f' "$HARD_DIR/harden-ssh.sh")"
check "harden-ssh: installs the drop-in into /etc/ssh/sshd_config.d (Bookworm include dir)" \
    "1" "$(count_regex 'DROP_IN_DIR=.*/etc/ssh/sshd_config\.d' "$HARD_DIR/harden-ssh.sh")"
check "harden-ssh: documents the lockout/rollback path (physical console + backup restore)" \
    "1" "$(count_regex 'ROLLBACK / LOCKOUT NOTE' "$HARD_DIR/harden-ssh.sh")"
SSH_DRY_OUT="$WORK/harden-ssh-dry.txt"
"$HARD_DIR/harden-ssh.sh" --dry-run > "$SSH_DRY_OUT" 2>&1 && SSH_DRY_RC=0 || SSH_DRY_RC=$?
check "harden-ssh --dry-run runs rootless and exits 0 (sshd absent = nothing to harden)" \
    "0" "$SSH_DRY_RC"

# --- 9b. the firewall: clients must never reach sshd ------------------------
# (Traced hole this closes: DTN_INPUT ends in RETURN and the INPUT policy
# stays ACCEPT, so WITHOUT an explicit drop a running sshd answers any AP
# client even with ALLOW_SSH=0.)
"$ROOT/raspberry/firewall/iptables.sh" --print > "$WORK/rules-t3.txt" 2>/dev/null
ALLOW_SSH=1 "$ROOT/raspberry/firewall/iptables.sh" --print > "$WORK/rules-t3-ssh.txt" 2>/dev/null
check "ruleset: client tcp/22 reaches DTN_INPUT and is DROPPED by default (sshd unreachable from the AP)" \
    "1" "$(count_regex '^-A DTN_INPUT -p tcp -m tcp --dport 22 .*track3:ssh-never-reachable-from-clients.* -j DROP' "$WORK/rules-t3.txt")"
check "ruleset: default run has NO ssh accept in DTN_INPUT" \
    "0" "$(count_regex '^-A DTN_INPUT .* --dport 22 .* -j ACCEPT' "$WORK/rules-t3.txt")"
check "ruleset: ALLOW_SSH=1 swaps the drop for the explicit opt-in accept" \
    "1" "$(count_regex '^-A DTN_INPUT -p tcp -m tcp --dport 22 .*dtn:opt-in-operator-ssh -j ACCEPT' "$WORK/rules-t3-ssh.txt")"
check "ruleset: ALLOW_SSH=1 removes the default drop (one stance per deployment)" \
    "0" "$(count_regex '^-A DTN_INPUT .* --dport 22 .*track3:ssh-never-reachable-from-clients.* -j DROP' "$WORK/rules-t3-ssh.txt")"

# --- 9c. dtn-node.service hardening set + boot resilience -------------------
check "dtn-node.service: unprivileged User=dtn" \
    "1" "$(count_regex '^User=dtn$' "$NODE_UNIT")"
check "dtn-node.service: NoNewPrivileges" \
    "1" "$(count_regex '^NoNewPrivileges=' "$NODE_UNIT")"
check "dtn-node.service: ProtectSystem=strict" \
    "1" "$(count_regex '^ProtectSystem=strict$' "$NODE_UNIT")"
check "dtn-node.service: ReadWritePaths is exactly the state dir" \
    "1" "$(count_regex '^ReadWritePaths=/var/lib/dtn-node$' "$NODE_UNIT")"
check "dtn-node.service: Restart=always + RestartSec (power-cut convergence)" \
    "2" "$(count_regex '^Restart=always$|^RestartSec=' "$NODE_UNIT")"
check "dtn-node.service: WatchdogSec present (daemon pings WATCHDOG=1 via internal/sdnotify)" \
    "1" "$(count_regex '^WatchdogSec=' "$NODE_UNIT")"
check "dtn-node.service: RestrictSUIDSGID" \
    "1" "$(count_regex '^RestrictSUIDSGID=yes$' "$NODE_UNIT")"
check "dtn-node.service: MemoryDenyWriteExecute (cgo-free Go: no W+X mappings — claim documented in the unit)" \
    "1" "$(count_regex '^MemoryDenyWriteExecute=yes$' "$NODE_UNIT")"
check "dtn-node.service: WantedBy=multi-user.target (boot resilience: enabled by provision.sh)" \
    "1" "$(count_regex '^WantedBy=multi-user.target$' "$NODE_UNIT")"

# --- 9d. harden-services: unprivileged daemon + volatile journal -------------
check "harden-services: journald Storage=volatile (log wear never reaches the SD)" \
    "1" "$(count_regex '^Storage=volatile$' "$HARD_DIR/harden-services.sh")"
check "harden-services: journal size cap present (RAM bound, exact drop-in directive)" \
    "1" "$(count_regex '^SystemMaxUse=16M$' "$HARD_DIR/harden-services.sh")"
check "harden-services: documents the ext4 commit= choice (dirty-shutdown rationale on record)" \
    "1" "$(count_regex 'commit=' "$HARD_DIR/harden-services.sh")"
check "harden-services: pins the read-only-root interplay (data dir MUST stay durable)" \
    "1" "$(count_regex 'enable-readonly-root' "$HARD_DIR/harden-services.sh")"
SERVICES_DRY_OUT="$WORK/harden-services-dry.txt"
"$HARD_DIR/harden-services.sh" --dry-run > "$SERVICES_DRY_OUT" 2>&1 && SERVICES_DRY_RC=0 || SERVICES_DRY_RC=$?
check "harden-services --dry-run runs rootless and exits 0" "0" "$SERVICES_DRY_RC"
"$HARD_DIR/harden-services.sh" > "$WORK/harden-services-apply.out" 2>&1 && SERVICES_APPLY_RC=0 || SERVICES_APPLY_RC=$?
check "harden-services apply path refuses non-root" \
    "refused" "$(refused_nonroot "$WORK/harden-services-apply.out" "$SERVICES_APPLY_RC")"

# --- 9e. harden-upgrades: SECURITY-ONLY unattended upgrades ------------------
check "harden-upgrades: wipes the distro origin list first (#clear = deterministic security-only)" \
    "1" "$(count_regex '^#clear Unattended-Upgrade::Origins-Pattern;' "$HARD_DIR/harden-upgrades.sh")"
check "harden-upgrades: Debian security pool enabled (the exact override pattern line)" \
    "1" "$(count_regex 'label=Debian-Security";$' "$HARD_DIR/harden-upgrades.sh")"
check "harden-upgrades: Raspberry Pi archive enabled (the radios live there)" \
    "1" "$(count_regex 'site=archive\.raspberrypi\.com";$' "$HARD_DIR/harden-upgrades.sh")"
check "harden-upgrades: NO automatic reboots (the operator owns the reboot)" \
    "1" "$(count_regex '^Unattended-Upgrade::Automatic-Reboot "false";$' "$HARD_DIR/harden-upgrades.sh")"
check "harden-upgrades: states the security-only trade-off (feature updates stay manual via install.sh)" \
    "1" "$(count_regex 'THE TRADE-OFF' "$HARD_DIR/harden-upgrades.sh")"
UPGRADES_DRY_OUT="$WORK/harden-upgrades-dry.txt"
"$HARD_DIR/harden-upgrades.sh" --dry-run > "$UPGRADES_DRY_OUT" 2>&1 && UPGRADES_DRY_RC=0 || UPGRADES_DRY_RC=$?
check "harden-upgrades --dry-run runs rootless and exits 0" "0" "$UPGRADES_DRY_RC"
"$HARD_DIR/harden-upgrades.sh" > "$WORK/harden-upgrades-apply.out" 2>&1 && UPGRADES_APPLY_RC=0 || UPGRADES_APPLY_RC=$?
check "harden-upgrades apply path refuses non-root" \
    "refused" "$(refused_nonroot "$WORK/harden-upgrades-apply.out" "$UPGRADES_APPLY_RC")"

# --- 9f. read-only root: tamper resistance with ONE durable path -------------
ENABLE_RO="$HARD_DIR/enable-readonly-root.sh"
DISABLE_RO="$HARD_DIR/disable-readonly-root.sh"
ENABLE_DRY_OUT="$WORK/enable-ro-dry.txt"
"$ENABLE_RO" --dry-run > "$ENABLE_DRY_OUT" 2>&1 && ENABLE_DRY_RC=0 || ENABLE_DRY_RC=$?
check "enable-readonly-root --dry-run runs rootless and exits 0" "0" "$ENABLE_DRY_RC"
check "enable-readonly-root: generated initramfs script bind-mounts the DATA DIR from the real root (the DB survives power cuts)" \
    "1" "$(count_regex 'mount --bind /overlay/lower/var/lib/dtn-node' "$ENABLE_DRY_OUT")"
check "enable-readonly-root: generated initramfs script uses a tmpfs upper (writes die at reboot = tamper resistance)" \
    "1" "$(count_regex 'mount -t tmpfs.*tmpfs /overlay' "$ENABLE_DRY_OUT")"
check "enable-readonly-root: wires config.txt with a dedicated initramfs image" \
    "1" "$(count_regex 'initramfs initramfs-dtn followkernel' "$ENABLE_DRY_OUT")"
check "enable-readonly-root: installs a kernel-upgrade regen hook (a stale initramfs must never brick the node)" \
    "1" "$(count_regex 'post-update.d/dtn-overlayroot-regen' "$ENABLE_DRY_OUT")"
check "enable-readonly-root: documents what stays writable + the remount trade-off (field-ops contract)" \
    "1" "$(count_regex 'WHAT STAYS WRITABLE' "$ENABLE_RO")"
"$DISABLE_RO" --dry-run > "$WORK/disable-ro-dry.txt" 2>&1 && DISABLE_DRY_RC=0 || DISABLE_DRY_RC=$?
check "disable-readonly-root --dry-run runs rootless and exits 0 (rollback twin exists)" \
    "0" "$DISABLE_DRY_RC"
check "disable-readonly-root: removes the config.txt initramfs line (full rollback)" \
    "1" "$(count_regex 'initramfs-dtn' "$WORK/disable-ro-dry.txt")"
"$ENABLE_RO" --status > "$WORK/enable-ro-status.txt" 2>&1 && ENABLE_STATUS_RC=0 || ENABLE_STATUS_RC=$?
"$DISABLE_RO" --status > "$WORK/disable-ro-status.txt" 2>&1 && DISABLE_STATUS_RC=0 || DISABLE_STATUS_RC=$?
check "readonly twins --status run rootless and exit 0 (informational, never fails)" \
    "0" "$((ENABLE_STATUS_RC + DISABLE_STATUS_RC))"
"$ENABLE_RO" > "$WORK/enable-ro-apply.out" 2>&1 && ENABLE_APPLY_RC=0 || ENABLE_APPLY_RC=$?
"$DISABLE_RO" > "$WORK/disable-ro-apply.out" 2>&1 && DISABLE_APPLY_RC=0 || DISABLE_APPLY_RC=$?
check "readonly-root apply paths refuse non-root (boot-path changes need root)" \
    "refused,refused" "$(refused_nonroot "$WORK/enable-ro-apply.out" "$ENABLE_APPLY_RC"),$(refused_nonroot "$WORK/disable-ro-apply.out" "$DISABLE_APPLY_RC")"

# --- 9g. network watchdog: self-healing with a restart-storm guard ----------
WATCHDOG="$HARD_DIR/dtn-network-watchdog.sh"
check "network-watchdog: restart-storm guard variables documented with defaults" \
    "2" "$(count_regex '^MAX_RESTARTS_PER_HOUR=|^STORM_WINDOW_SECONDS=' "$WATCHDOG")"
check "network-watchdog: budget state lives in tmpfs /dev/shm (a reboot resets it — a reboot IS the big reset)" \
    "1" "$(has_line 'STATE_FILE="${STATE_FILE:-/dev/shm/dtn-network-watchdog.state}"' "$WATCHDOG")"
check "network-watchdog: budget exhaustion leaves a journald marker (logger), never an infinite restart loop" \
    "1" "$(count_regex 'LOGGER" -t dtn-network-watchdog' "$WATCHDOG")"
WD_DRY_OUT="$WORK/watchdog-dry.txt"
"$WATCHDOG" --dry-run > "$WD_DRY_OUT" 2>&1 && WD_DRY_RC=0 || WD_DRY_RC=$?
check "network-watchdog --dry-run runs rootless and exits 0" "0" "$WD_DRY_RC"
# Fixture run: every probe fails -> the watchdog must name ALL THREE failed
# components individually (restart ONLY what failed, never the whole box).
WD_FIX="$WORK/watchdog-fail"
printf '#!/bin/sh\nexit 1\n' > "$WD_FIX"
chmod +x "$WD_FIX"
HOSTAPD_CLI="$WD_FIX" DIG="$WD_FIX" CURL="$WD_FIX" SYSTEMCTL="$WD_FIX" \
    "$WATCHDOG" --dry-run > "$WORK/watchdog-fix.txt" 2>&1 && WD_FIX_RC=0 || WD_FIX_RC=$?
check "network-watchdog --dry-run exits 0 against failing fixtures" "0" "$WD_FIX_RC"
check "network-watchdog: failing probes yield a per-component restart plan (hostapd + dnsmasq + dtn-node)" \
    "3" "$(count_regex 'would restart (hostapd|dnsmasq|dtn-node)\.service' "$WORK/watchdog-fix.txt")"
# Storm guard active path: budget 0 -> "budget exhausted", never a restart.
MAX_RESTARTS_PER_HOUR=0 HOSTAPD_CLI="$WD_FIX" DIG="$WD_FIX" CURL="$WD_FIX" \
    "$WATCHDOG" --dry-run > "$WORK/watchdog-budget.txt" 2>&1 && WD_BUDGET_RC=0 || WD_BUDGET_RC=$?
check "network-watchdog --dry-run exits 0 with an exhausted budget" "0" "$WD_BUDGET_RC"
check "network-watchdog: exhausted budget blocks ALL THREE restarts (storm guard actually gates)" \
    "3" "$(count_regex 'budget exhausted' "$WORK/watchdog-budget.txt")"
check "network-watchdog: exhausted budget issues ZERO restarts" \
    "0" "$(count_regex 'would restart' "$WORK/watchdog-budget.txt")"

# --- 9h. telemetry: counters ONLY (blind-node privacy, §13) ------------------
TELEMETRY="$HARD_DIR/dtn-telemetry.sh"
# The honest all_sta assertion: the CONTRACT says per-station output is user
# data, so the header documents it — but no EXECUTABLE line may ever invoke
# it. Strip comments, then count.
check "telemetry: NEVER invokes all_sta on any executable line (per-station output is user data; only the num_stations counter is read)" \
    "0" "$({ grep -Ev '^[[:space:]]*#' "$TELEMETRY" || true; } | { grep -c 'all_sta' || true; })"
check "telemetry: reads hostapd through exactly one status call (the num_stations counter)" \
    "1" "$(count_regex 'HOSTAPD_CLI" -i "\$HOSTAPD_IF" status' "$TELEMETRY")"
check "telemetry: summary defaults to tmpfs /dev/shm (nothing about users hits the SD)" \
    "1" "$(has_line 'OUT_FILE="${OUT_FILE:-/dev/shm/dtn-telemetry.summary}"' "$TELEMETRY")"
check "telemetry: 429/507 fields are honest na (format contract + value; the daemon logs no per-request lines, iptables counts instead)" \
    "2" "$(count_regex 'daemon_429=na daemon_507=na' "$TELEMETRY")"
# Fixture run: raw feeds carry client IPs/MACs (like the live node does); the
# emitted summary line must carry integers only. The fake hostapd_cli writes
# a breadcrumb if it is EVER called with all_sta. Heredocs are UNQUOTED on
# purpose: $TEL_FIX bakes the absolute breadcrumb path in at write time, and
# every \$ the fixture needs at RUNTIME stays escaped.
TEL_FIX="$WORK/telemetry-fix"
mkdir -p "$TEL_FIX"
cat > "$TEL_FIX/hostapd_cli" <<FIXTURE_CLI
#!/bin/sh
for a in "\$@"; do [ "\$a" = "all_sta" ] && { echo called >> $TEL_FIX/breadcrumb; exit 9; }; done
echo "state=ENABLED"
echo "num_stations=3"
FIXTURE_CLI
cat > "$TEL_FIX/ipt" <<FIXTURE_IPT
#!/bin/sh
case "\$*" in
  *"-S DTN_DNSBL"*)
    echo "-A DTN_DNSBL -s 10.42.0.66/32 -j DROP"
    echo "-A DTN_DNSBL -s 10.42.0.99/32 -j DROP" ;;
  *"-L DTN_DNSBL"*)
    echo "   42  2100 DROP   all  --  wlan0  *  10.42.0.66  0.0.0.0/0"
    echo "   10   500 DROP   all  --  wlan0  *  10.42.0.99  0.0.0.0/0" ;;
  *"-L DTN_INPUT"*)
    echo "   7   336 DROP  all  --  wlan0  *  10.42.0.55  0.0.0.0/0 /* dtn:portal-synflood-guard */"
    echo "  99 12000 DTN_ACC  all  --  wlan0  *  0.0.0.0/0  0.0.0.0/0 /* dtn:accounting-counts-everything-first */" ;;
esac
FIXTURE_IPT
chmod +x "$TEL_FIX/hostapd_cli" "$TEL_FIX/ipt"
printf 'cooldown aa:bb:cc:00:00:01 9999999999\n' > "$TEL_FIX/station.state"
printf 'streak 10.42.0.66 2\nblacklist 10.42.0.66 9999999999\n' > "$TEL_FIX/dns.state"
HOSTAPD_CLI="$TEL_FIX/hostapd_cli" IPT="$TEL_FIX/ipt" \
    DNS_STATE="$TEL_FIX/dns.state" STATION_STATE="$TEL_FIX/station.state" \
    "$TELEMETRY" --dry-run > "$WORK/telemetry-out.txt" 2>&1 && TEL_RC=0 || TEL_RC=$?
check "telemetry --dry-run runs rootless and exits 0" "0" "$TEL_RC"
check "telemetry: station counter parsed from the status probe (integer, not na)" \
    "1" "$(count_regex 'stations=3' "$WORK/telemetry-out.txt")"
check "telemetry: active DNS-shed counter from the -S feed (2 DROP rules, IPs discarded)" \
    "1" "$(count_regex 'dns_shed_active=2' "$WORK/telemetry-out.txt")"
check "telemetry: shed-packet counter summed from the -v -x feed (42 + 10 = 52)" \
    "1" "$(count_regex 'dns_shed_packets=52' "$WORK/telemetry-out.txt")"
check "telemetry: station-shield cooldown count from the tmpfs state (MAC reduced to a number)" \
    "1" "$(count_regex 'station_cooldowns=1' "$WORK/telemetry-out.txt")"
check "telemetry: DTN_ACC aggregate from the jump-rule counter (99 pkts / 12000 bytes)" \
    "1" "$(count_regex 'acc_packets=99 acc_bytes=12000' "$WORK/telemetry-out.txt")"
check "telemetry: NO IP address ever reaches the output (raw fixture feeds DO contain them — the parsers discard them)" \
    "0" "$(count_regex '\b[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\b' "$WORK/telemetry-out.txt")"
check "telemetry: NO MAC address ever reaches the output (state file held one; only its count is read)" \
    "0" "$(count_regex '\b[0-9a-f]{2}(:[0-9a-f]{2}){5}\b' "$WORK/telemetry-out.txt")"
if [ -f "$TEL_FIX/breadcrumb" ]; then TEL_ALLSTA=1; else TEL_ALLSTA=0; fi
check "telemetry: all_sta was NEVER called against the (fixture) hostapd" \
    "0" "$TEL_ALLSTA"
"$TELEMETRY" > "$WORK/telemetry-apply.out" 2>&1 && TEL_APPLY_RC=0 || TEL_APPLY_RC=$?
check "telemetry apply path refuses non-root" \
    "refused" "$(refused_nonroot "$WORK/telemetry-apply.out" "$TEL_APPLY_RC")"

# --- 9i. Track-3 systemd units/timers + provision.sh wiring ------------------
check "systemd: network-watchdog service + timer exist" \
    "ok" "$([ -f "$HARD_DIR/dtn-network-watchdog.service" ] && [ -f "$HARD_DIR/dtn-network-watchdog.timer" ] && echo ok || echo missing)"
check "systemd: telemetry service + timer exist" \
    "ok" "$([ -f "$HARD_DIR/dtn-telemetry.service" ] && [ -f "$HARD_DIR/dtn-telemetry.timer" ] && echo ok || echo missing)"
check "systemd: watchdog unit execs the installed script" \
    "1" "$(count_regex '^ExecStart=/usr/local/sbin/dtn-network-watchdog\.sh$' "$HARD_DIR/dtn-network-watchdog.service")"
check "systemd: telemetry unit execs the installed script" \
    "1" "$(count_regex '^ExecStart=/usr/local/sbin/dtn-telemetry\.sh$' "$HARD_DIR/dtn-telemetry.service")"
check "systemd: watchdog + telemetry timers carry a firing cadence" \
    "2" "$(($(count_regex '^OnUnitActiveSec=' "$HARD_DIR/dtn-network-watchdog.timer") + $(count_regex '^OnUnitActiveSec=' "$HARD_DIR/dtn-telemetry.timer")))"
check "systemd: both timer units wanted by timers.target" \
    "2" "$(($(count_regex '^WantedBy=timers.target$' "$HARD_DIR/dtn-network-watchdog.timer") + $(count_regex '^WantedBy=timers.target$' "$HARD_DIR/dtn-telemetry.timer")))"
check "systemd: watchdog + telemetry services keep their writable surface on tmpfs only" \
    "2" "$(($(count_regex '^ReadWritePaths=/dev/shm$' "$HARD_DIR/dtn-network-watchdog.service") + $(count_regex '^ReadWritePaths=/dev/shm$' "$HARD_DIR/dtn-telemetry.service")))"
check "provision.sh: installs the three hardening executables" \
    "3" "$(count_regex 'hardening/harden-ssh\.sh" /usr/local/sbin/dtn-harden-ssh\.sh|hardening/harden-services\.sh" /usr/local/sbin/dtn-harden-services\.sh|hardening/harden-upgrades\.sh" /usr/local/sbin/dtn-harden-upgrades\.sh' "$ROOT/raspberry/provision.sh")"
check "provision.sh: stages the readonly-root twins (default OFF, operator opt-in)" \
    "2" "$(count_regex 'hardening/enable-readonly-root\.sh" /usr/local/sbin/dtn-enable-readonly-root\.sh|hardening/disable-readonly-root\.sh" /usr/local/sbin/dtn-disable-readonly-root\.sh' "$ROOT/raspberry/provision.sh")"
check "provision.sh: installs the watchdog + telemetry scripts, units and timers" \
    "6" "$(count_regex 'hardening/dtn-(network-watchdog|telemetry)\.(sh|service|timer)" /(usr/local/sbin|etc)/' "$ROOT/raspberry/provision.sh")"
check "provision.sh: enables the watchdog + telemetry timers (reboot activates them)" \
    "1" "$(count_regex 'dtn-network-watchdog\.timer dtn-telemetry\.timer' "$ROOT/raspberry/provision.sh")"
check "provision.sh: runs the three hardening steps in field_hardening" \
    "3" "$(count_regex '^    /usr/local/sbin/dtn-harden-(ssh|services|upgrades)\.sh$' "$ROOT/raspberry/provision.sh")"
check "provision.sh: installs the watchdog's probe tools (dnsutils + curl)" \
    "1" "$(count_regex 'apt-get install -y dnsutils curl' "$ROOT/raspberry/provision.sh")"


# ---------------------------------------------------------------------------
# 10. docs/BUILD.md documents this test.
# ---------------------------------------------------------------------------
log "section 10: docs/BUILD.md test list"
BUILD_MD="$ROOT/docs/BUILD.md"
check "BUILD.md: run-all-tests list includes tests/hardening_structure.sh" \
    "1" "$(count_regex 'bash tests/hardening_structure\.sh' "$BUILD_MD")"

# ---------------------------------------------------------------------------
# Summary.
# ---------------------------------------------------------------------------
log "summary: $PASS_COUNT passed, $FAIL_COUNT failed"
if [ "$FAIL_COUNT" -gt 0 ]; then
    log "RESULT: FAIL"
    exit 1
fi
log "RESULT: PASS"
