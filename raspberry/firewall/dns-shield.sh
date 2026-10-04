#!/usr/bin/env bash
# dtn-dns-shield.sh — anti-DNS-tunneling shield for the off-grid DTN node
# (Module A, issue #16 Track 1).
# Install path: /usr/local/sbin/dtn-dns-shield.sh
# Run once a minute by dtn-dns-shield.timer (systemd oneshot). Safe to re-run
# by hand; safe to run concurrently with itself (all state updates are
# rewrite-on-rename, all iptables mutations are check-then-add).
#
# Usage:
#   dtn-dns-shield.sh             apply (root): read the query window, shed
#                                 abusive resolvers into the DTN_DNSBL chain
#   dtn-dns-shield.sh --dry-run   print exactly what apply WOULD do — no
#                                 root, no kernel calls, no state/log writes
#                                 (this is what tests/hardening_structure.sh
#                                 exercises, via the env overrides below)
#
# WHY (issue #16 Track 1 — anti-circumvention): dnsmasq answers every name
# with the portal IP (dnsmasq.conf address=/#/, docs/protocol.md §12), so the
# ONLY thing a client can do with this resolver is confirm "everything is the
# portal". Any volume of queries beyond a handful per visit has zero portal
# value — it is a covert channel (IP-over-DNS needs the upstream the node
# does not have; against an island node the remaining abuse is query
# flooding, which costs the AP's airtime and dnsmasq's single-threaded CPU).
#
# HOW — two complementary layers (rates must be ordered like this):
#   1. the firewall's per-source hashlimit (iptables.sh) drops bursts ABOVE
#      DNS_HL_RATE_QPS=25/s instantly, at packet speed;
#   2. THIS script catches the sustained-but-sub-ceiling abuser (e.g. 20 q/s
#      forever): it reads dnsmasq's query log for one WINDOW, keeps only
#      per-source-IP RATE counters, and sheds a source that stays above
#      DNS_SHED_QPS for DNS_SHED_WINDOWS consecutive windows — or blows
#      straight past DNS_SHED_FAST_FACTOR x the threshold, which is flood
#      territory and shed immediately. Shed = one DROP rule in the DTN_DNSBL
#      chain for DNS_COOLDOWN_SECONDS.
#
# PRIVACY CONTRACT (binding; issue #16 + docs/protocol.md §13 — the node is
# a blind channel): DNS names a client's device looks up ARE user data. This
# script therefore:
#   * reads dnsmasq's log from TMPFS (dnsmasq.conf log-facility=/dev/shm/...):
#     nothing ever touches the SD card, the journal or any disk file;
#   * extracts ONLY the source IP per query line and counts — queried names
#     are discarded inside the awk program, before any variable in this
#     script ever sees them, and no name is ever printed or stored;
#   * keeps its state (IPs, counters, blacklist expiry timestamps) in TMPFS
#     (/dev/shm) — it dies at reboot, never persisted;
#   * truncates the log after each window, so even the tmpfs copy stays
#     bounded to one window;
#   * the DTN_DNSBL chain it feeds is flushed by every dtn-firewall.sh run,
#     so no client IP survives a reboot (or lands in rules.v4).

set -euo pipefail

# Environment overrides exist so tests can point these at fixtures (see
# tests/hardening_structure.sh); the defaults are the provisioned paths.
# Both MUST live under a tmpfs (privacy contract above): /dev/shm on Linux.
DNS_LOG="${DNS_LOG:-/dev/shm/dtn-dns-queries.log}"
STATE_FILE="${STATE_FILE:-/dev/shm/dtn-dns-shield.state}"
IPT="${IPT:-iptables}"
DNSBL_CHAIN="${DNSBL_CHAIN:-DTN_DNSBL}"

# One window == one invocation == the timer period (dtn-dns-shield.timer:
# OnUnitActiveSec=60). Rates are counts normalized to queries/second.
DNS_WINDOW_SECONDS="${DNS_WINDOW_SECONDS:-60}"
# Sustained shed threshold, queries/second per source. MUST stay strictly
# below the firewall hashlimit ceiling (DNS_HL_RATE_QPS=25) — see WHY above:
# above the ceiling the firewall drops the packets, so dnsmasq's log (the
# only thing this script reads) would never show the excess.
DNS_SHED_QPS="${DNS_SHED_QPS:-20}"
# A rate this many times the threshold is flood, not mere abuse: shed on the
# FIRST window without waiting for confirmation (4 x 20 = 80 q/s).
DNS_SHED_FAST_FACTOR="${DNS_SHED_FAST_FACTOR:-4}"
# Moderate abusers get DNS_SHED_WINDOWS consecutive windows above the
# threshold before shedding — one bad minute (a phone with a stuck resolver
# loop) is tolerated, three in a row is a policy.
DNS_SHED_WINDOWS="${DNS_SHED_WINDOWS:-3}"
# How long a shed source stays in DTN_DNSBL. Re-offending restarts nothing:
# the source simply re-qualifies and is re-added.
DNS_COOLDOWN_SECONDS="${DNS_COOLDOWN_SECONDS:-600}"

DRY_RUN=0
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        -h | --help)
            sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//; /^$/d; /Usage:/q' | head -n 20
            exit 0
            ;;
        *)
            echo "dtn-dns-shield: ERROR: unknown option '$arg' (usage: dtn-dns-shield.sh [--dry-run])" >&2
            exit 1
            ;;
    esac
done

log() { echo "dtn-dns-shield: $*"; }
die() { echo "dtn-dns-shield: ERROR: $*" >&2; exit 1; }

# --- apply-mode preflight (never reached by --dry-run) -----------------------

if [ "$DRY_RUN" != "1" ]; then
    [ "$(id -u)" -eq 0 ] || die "must run as root (iptables DTN_DNSBL updates require CAP_NET_ADMIN); try --dry-run"
    command -v "$IPT" >/dev/null 2>&1 || die "$IPT not found; install the iptables package"
    "$IPT" -nL "$DNSBL_CHAIN" >/dev/null 2>&1 \
        || die "chain $DNSBL_CHAIN missing — run dtn-firewall.sh first (it creates the DTN chains)"
fi

# --- 1. read the window: count QUERIES PER SOURCE IP, names never leave awk --
#
# dnsmasq log-queries lines look like:
#   Oct  4 13:22:01 dnsmasq[923]: 1234 10.42.0.57/41002 query[A] example.com from 10.42.0.57
# The source IP is the LAST field of every "query[...]" line; the queried
# name sits in the middle and is deliberately NOT captured — the awk program
# below is the ONLY parser that touches raw log lines, and all it emits is
# "IP COUNT" pairs. (Matching $NF against dotted-quad syntax guards against
# trailing-whitespace or format-drift lines; those are simply not counted.)

COUNTS=""
if [ -r "$DNS_LOG" ]; then
    COUNTS="$(awk '
        /query\[[A-Za-z]+\]/ && $NF ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ { c[$NF]++ }
        END { for (ip in c) print ip, c[ip] }
    ' "$DNS_LOG")"
fi

# prev_state FIELD IP — one lookup in the (possibly absent) state file.
prev_state() {
    local field="$1" ip="$2"
    [ -r "$STATE_FILE" ] || { printf '0'; return; }
    awk -v f="$field" -v ip="$ip" \
        '$1 == f && $2 == ip { print $3; found = 1; exit } END { if (!found) print 0 }' \
        "$STATE_FILE"
}

# --- 2. decide: who gets shed this window ------------------------------------
#
# Emits "SHED <ip> <reason>" lines; collects the new per-IP streaks for the
# state rewrite. Streak semantics: consecutive windows with rate >=
# DNS_SHED_QPS; a quiet window resets the streak to 0.

NOW="$(date +%s)"
DECISIONS=""
NEW_STREAKS=""

if [ -z "$COUNTS" ]; then
    log "no queries in the current window (dnsmasq quiet, not provisioned yet, or non-Linux host): nothing to do"
fi

while read -r ip count; do
    [ -n "$ip" ] || continue
    # Ceiling-normalized rate: counts in the window -> queries/second
    # (integer, rounded up).
    rate=$(( (count + DNS_WINDOW_SECONDS - 1) / DNS_WINDOW_SECONDS ))
    fast_threshold=$(( DNS_SHED_QPS * DNS_SHED_FAST_FACTOR ))
    prev="$(prev_state streak "$ip")"
    if [ "$rate" -ge "$fast_threshold" ]; then
        DECISIONS="${DECISIONS}SHED ${ip} flood ${rate} q/s (>= ${fast_threshold}, instant shed)"$'\n'
        NEW_STREAKS="${NEW_STREAKS}streak ${ip} 0"$'\n'
    elif [ "$rate" -ge "$DNS_SHED_QPS" ]; then
        streak=$(( prev + 1 ))
        if [ "$streak" -ge "$DNS_SHED_WINDOWS" ]; then
            DECISIONS="${DECISIONS}SHED ${ip} sustained ${rate} q/s over ${streak} windows (>= ${DNS_SHED_WINDOWS})"$'\n'
            NEW_STREAKS="${NEW_STREAKS}streak ${ip} 0"$'\n'
        else
            NEW_STREAKS="${NEW_STREAKS}streak ${ip} ${streak}"$'\n'
        fi
    else
        NEW_STREAKS="${NEW_STREAKS}streak ${ip} 0"$'\n'
    fi
done <<COUNTS_EOF
$COUNTS
COUNTS_EOF

# Expired blacklist entries: lift them (the firewall DROP rules for active
# ones are kept untouched — they were added by an earlier run and their
# expiry is tracked HERE, in tmpfs, not in the kernel).
LIFTED=""
KEEPS=""
if [ -r "$STATE_FILE" ]; then
    while read -r kind ip expiry; do
        [ "$kind" = "blacklist" ] || continue
        if [ "$expiry" -le "$NOW" ]; then
            LIFTED="${LIFTED}${ip}"$'\n'
        else
            KEEPS="${KEEPS}blacklist ${ip} ${expiry}"$'\n'
        fi
    done < "$STATE_FILE"
fi

# --- 3. act -------------------------------------------------------------------

blacklist_add() {
    local ip="$1"
    if ! "$IPT" -C "$DNSBL_CHAIN" -s "$ip" -j DROP 2>/dev/null; then
        "$IPT" -I "$DNSBL_CHAIN" 1 -s "$ip" -j DROP
    fi
}

while read -r tag ip reason; do
    [ -n "${ip:-}" ] || continue
    expiry=$(( NOW + DNS_COOLDOWN_SECONDS ))
    if [ "$DRY_RUN" = "1" ]; then
        log "[dry-run] would shed $ip — $reason; would add $DNSBL_CHAIN DROP for ${DNS_COOLDOWN_SECONDS}s"
    else
        blacklist_add "$ip"
        log "shed $ip — $reason; $DNSBL_CHAIN DROP added for ${DNS_COOLDOWN_SECONDS}s"
    fi
    KEEPS="${KEEPS}blacklist ${ip} ${expiry}"$'\n'
done <<DECISIONS_EOF
$DECISIONS
DECISIONS_EOF

for ip in $LIFTED; do
    if [ "$DRY_RUN" = "1" ]; then
        log "[dry-run] would lift $ip — cooldown expired"
    else
        if "$IPT" -C "$DNSBL_CHAIN" -s "$ip" -j DROP 2>/dev/null; then
            "$IPT" -D "$DNSBL_CHAIN" -s "$ip" -j DROP
        fi
        log "lifted $ip — cooldown expired, $DNSBL_CHAIN DROP removed"
    fi
done


# State rewrite (apply mode only — dry-run is strictly observational and
# never touches state or the log). Content: IPs, streak counters, expiry
# timestamps. No names, no counters older than the last window; tmpfs only.
if [ "$DRY_RUN" != "1" ]; then
    { printf '%s' "$NEW_STREAKS"; printf '%s' "$KEEPS"; } > "${STATE_FILE}.tmp"
    mv "${STATE_FILE}.tmp" "$STATE_FILE"
    # Bounded log: this window has been fully consumed; next run starts
    # clean. (dnsmasq keeps the file open O_APPEND, so truncation in place
    # is safe; if the inode was recycled by a reboot the next window simply
    # starts from an empty file.)
    : > "$DNS_LOG"
fi

exit 0
