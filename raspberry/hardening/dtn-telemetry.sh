#!/usr/bin/env bash
# dtn-telemetry.sh — privacy-preserving health counters for the off-grid DTN
# dead-drop node (Module A, issue #16 Track 3).
# Repo path : raspberry/hardening/dtn-telemetry.sh
# Install   : /usr/local/sbin/dtn-telemetry.sh
# Run every five minutes by dtn-telemetry.timer (systemd oneshot); safe to
# re-run by hand.
#
# Usage:
#   dtn-telemetry.sh            apply (root): collect COUNTERS ONLY and write
#                               ONE aggregated summary line to stdout (the
#                               journal keeps it) and to $OUT_FILE (tmpfs,
#                               latest snapshot for the operator runbook)
#   dtn-telemetry.sh --dry-run  run the same collection and print the line —
#                               no writes, no root required (what
#                               tests/hardening_structure.sh exercises, via
#                               the env overrides below)
#
# PRIVACY CONTRACT (binding; issue #16 + docs/protocol.md §13 — the node is
# a BLIND channel): this script is counters-only BY CONSTRUCTION.
#   * It NEVER calls "hostapd_cli all_sta" (per-station output) — only
#     "status", whose num_stations= counter is one integer.
#   * iptables listings that carry per-source rows (DTN_DNSBL, DTN_INPUT)
#     are read ONLY through awk programs that emit sums; source IPs and MACs
#     never survive the pipeline, never reach stdout, never reach any file.
#   * The shield state files (/dev/shm/dtn-*.state, tmpfs) are READ and
#     reduced to line COUNTS — the MACs and IPs inside them are never
#     printed or copied.
#   * The output line contains labels and integers (or "na"), nothing else;
#     it lands in the VOLATILE journal (harden-services.sh sets
#     Storage=volatile) and one tmpfs line. No user-identifying data exists
#     anywhere in this pipeline, so there is nothing to leak at reboot, on
#     the SD card, or to a hostile client that somehow reads the summary.
#
# ABOUT 429/507 COUNTS (checked, not guessed): the daemon is deliberately
# silent per-request — node/main.go logs lifecycle lines only and the api
# package (handlers/middleware/ratelimit, which emit the 429 rate_limited /
# node_full and 507 storage errors) logs NOTHING. That is the §13 design:
# request lines would carry IPs or envelope metadata. THEREFORE there are no
# journald lines to parse and none will be parsed here; the fields are
# reported as "na" and the firewall-side stand-in for "abuse was shed at the
# door" is portal_dropped (the SYN-hashlimit DROP counter on 8080). If a
# future daemon ever logs per-request outcomes, that logging MUST stay
# IP-free before any parser is pointed at it — until then, iptables counts.
#
# OUTPUT (one line, runbook + chaos-matrix format):
#   dtn-telemetry date=<UTC> stations=<n> dns_shed_active=<n>
#   dns_shed_packets=<n> dns_streaks=<n> dns_blacklist=<n>
#   station_cooldowns=<n> portal_dropped=<n> acc_packets=<n> acc_bytes=<n>
#   daemon_429=na daemon_507=na
# Every value is an integer or the literal "na" (unverifiable this run:
# tool missing, unit down, fixture absent). Nothing else, ever.

set -euo pipefail

# Environment overrides so tests can point these at fixtures; the defaults
# are the provisioned paths (mirrors the two shields and the watchdog).
HOSTAPD_CLI="${HOSTAPD_CLI:-hostapd_cli}"
HOSTAPD_IF="${HOSTAPD_IF:-wlan0}"
IPT="${IPT:-iptables}"
DNSBL_CHAIN="${DNSBL_CHAIN:-DTN_DNSBL}"
INPUT_CHAIN="${INPUT_CHAIN:-DTN_INPUT}"
ACC_CHAIN="${ACC_CHAIN:-DTN_ACC}"
DNS_STATE="${DNS_STATE:-/dev/shm/dtn-dns-shield.state}"
STATION_STATE="${STATION_STATE:-/dev/shm/dtn-station-shield.state}"
OUT_FILE="${OUT_FILE:-/dev/shm/dtn-telemetry.summary}"

DRY_RUN=0
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        -h | --help)
            sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//; /^$/d; /Usage:/q' | head -n 20
            exit 0
            ;;
        *)
            echo "dtn-telemetry: ERROR: unknown option '$arg' (usage: dtn-telemetry.sh [--dry-run])" >&2
            exit 1
            ;;
    esac
done

log() { echo "dtn-telemetry: $*"; }

# num_of DESC VALUE — normalize a collector result to an integer or "na".
# A failed collector is an "na", never a zero (zero is a MEASUREMENT; na is
# the honest "could not look").
num_of() {
    local value="$1"
    if [ -n "$value" ] && [ "$value" -eq "$value" ] 2>/dev/null; then
        printf '%s' "$value"
    else
        printf 'na'
    fi
}

# --- collectors (every one optional; each reduces its raw feed to ONE number)
#
# The iptables -L / -S feeds DO contain client IPs (the shields' runtime
# state). Each awk below is the ONLY thing that touches them, and each emits
# a single integer — the same parser-discipline the dns-shield uses for DNS
# names (blind-node privacy, docs/protocol.md §13).

# Associated stations: ONE integer from "hostapd_cli status" (NEVER all_sta,
# whose per-station output is user data — see the privacy contract above).
collect_stations() {
    command -v "$HOSTAPD_CLI" >/dev/null 2>&1 || return 1
    local status
    status="$("$HOSTAPD_CLI" -i "$HOSTAPD_IF" status 2>/dev/null || true)"
    printf '%s\n' "$status" | awk -F= '$1 == "num_stations" { print $2; found = 1; exit } END { if (!found) exit 1 }'
}

# Active DNS-shed sheds: number of DROP rules currently in the DTN_DNSBL
# chain (each one is one shed source; the rules themselves are discarded).
# grep -c always PRINTS the count (even 0) and merely exits 1 on zero — the
# || true normalizes the status, the printed number is the value.
collect_dns_shed_active() {
    command -v "$IPT" >/dev/null 2>&1 || return 1
    local rules count
    rules="$("$IPT" -S "$DNSBL_CHAIN" 2>/dev/null || true)"
    count="$(printf '%s\n' "$rules" | grep -Fc -- '-j DROP' || true)"
    printf '%s' "$count"
}

# Packets shed by those rules so far: the summed pkts counter of every DROP
# rule in the chain listing (source IPs sit in the same rows — discarded by
# the awk). A failed listing (chain missing, iptables broken) is an "na",
# not a fake zero.
collect_dns_shed_packets() {
    command -v "$IPT" >/dev/null 2>&1 || return 1
    "$IPT" -L "$DNSBL_CHAIN" -v -n -x 2>/dev/null \
        | awk '$3 == "DROP" { s += $1 } END { print s + 0 }' \
        || return 1
}

# DNS-shield tmpfs state, reduced to counts: in-window offenders being
# tracked (streak) and active blacklist entries.
collect_dns_streaks() {
    [ -r "$DNS_STATE" ] || return 1
    awk '$1 == "streak" { n++ } END { print n + 0 }' "$DNS_STATE"
}

collect_dns_blacklist() {
    [ -r "$DNS_STATE" ] || return 1
    awk '$1 == "blacklist" { n++ } END { print n + 0 }' "$DNS_STATE"
}

# Station-shield tmpfs state, reduced to a count of live cooldowns (the MACs
# on those lines are never read into any variable of this script).
collect_station_cooldowns() {
    [ -r "$STATION_STATE" ] || return 1
    awk '$1 == "cooldown" { n++ } END { print n + 0 }' "$STATION_STATE"
}

# Portal SYN-flood shed: the pkts counter of the hashlimit DROP rule on 8080
# (matched by its comment token, the stable identifier iptables.sh gives it).
collect_portal_dropped() {
    command -v "$IPT" >/dev/null 2>&1 || return 1
    "$IPT" -L "$INPUT_CHAIN" -v -n -x 2>/dev/null \
        | awk '/dtn:portal-synflood-guard/ { s += $1 } END { print s + 0 }' \
        || return 1
}

# DTN_ACC aggregate: pkts/bytes on the jump rule itself (iptables.sh documents
# that jump-rule counter as the accounting total). Per-source counter rules
# BELOW the jump are never parsed.
collect_acc() {
    command -v "$IPT" >/dev/null 2>&1 || return 1
    "$IPT" -L "$INPUT_CHAIN" -v -n -x 2>/dev/null \
        | awk '$3 == "DTN_ACC" { print $1, $2; found = 1; exit } END { if (!found) exit 1 }' \
        || return 1
}

# --- assemble the one line ------------------------------------------------------

stations="$(num_of "$(collect_stations || true)")"
dns_shed_active="$(num_of "$(collect_dns_shed_active || true)")"
dns_shed_packets="$(num_of "$(collect_dns_shed_packets || true)")"
dns_streaks="$(num_of "$(collect_dns_streaks || true)")"
dns_blacklist="$(num_of "$(collect_dns_blacklist || true)")"
station_cooldowns="$(num_of "$(collect_station_cooldowns || true)")"
portal_dropped="$(num_of "$(collect_portal_dropped || true)")"
acc_pairs="$(collect_acc || true)"
if [ -n "$acc_pairs" ]; then
    acc_packets="$(num_of "$(printf '%s' "$acc_pairs" | awk '{ print $1 }')")"
    acc_bytes="$(num_of "$(printf '%s' "$acc_pairs" | awk '{ print $2 }')")"
else
    acc_packets="na"
    acc_bytes="na"
fi

# daemon_429 / daemon_507 are "na" by design — see the ABOUT block above.
SUMMARY_LINE="dtn-telemetry date=$(date -u +%Y-%m-%dT%H:%M:%SZ) stations=${stations} dns_shed_active=${dns_shed_active} dns_shed_packets=${dns_shed_packets} dns_streaks=${dns_streaks} dns_blacklist=${dns_blacklist} station_cooldowns=${station_cooldowns} portal_dropped=${portal_dropped} acc_packets=${acc_packets} acc_bytes=${acc_bytes} daemon_429=na daemon_507=na"

if [ "$DRY_RUN" = "1" ]; then
    log "[dry-run] would write one line to $OUT_FILE (and stdout):"
    echo "$SUMMARY_LINE"
    exit 0
fi

# --- apply: publish (tmpfs snapshot, atomic) + stdout (the journal keeps it) -

if [ "$(id -u)" -ne 0 ]; then
    echo "dtn-telemetry: ERROR: must run as root (iptables counters + hostapd control socket); try --dry-run" >&2
    exit 1
fi

printf '%s\n' "$SUMMARY_LINE" > "${OUT_FILE}.tmp"
mv "${OUT_FILE}.tmp" "$OUT_FILE"
echo "$SUMMARY_LINE"
