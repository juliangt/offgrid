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
#   7. docs/BUILD.md lists this test in "Run all tests".
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
# 9. docs/BUILD.md documents the new test.
# ---------------------------------------------------------------------------
log "section 9: docs/BUILD.md test list"
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
