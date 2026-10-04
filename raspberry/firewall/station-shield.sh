#!/usr/bin/env bash
# dtn-station-shield.sh — Wi-Fi station abuse shield for the off-grid DTN node
# (Module A, issue #16 Track 1).
# Install path: /usr/local/sbin/dtn-station-shield.sh
# Run every couple of minutes by dtn-station-shield.timer (systemd oneshot).
# Safe to re-run by hand; every mutation is check-then-act.
#
# Usage:
#   dtn-station-shield.sh            apply (root): detect and SHED abusive
#                                    stations (hostapd_cli deauthenticate,
#                                    individual stations only)
#   dtn-station-shield.sh --dry-run  print exactly what apply WOULD do — no
#                                    root, no kernel/hostapd calls, no state
#                                    writes (this is what
#                                    tests/hardening_structure.sh exercises,
#                                    via the env overrides below)
#
# WHY (issue #16 Track 1 + the node's raison d'etre): this node is an ISLAND.
# The only data it can ever hand out is its own envelope pool — at the §8.1
# cap that is 5000 envelopes x ~0.7 KiB ≈ 3.5 MiB total content, and a
# legitimate mule sync moves at most 200 pulled + 100 pushed envelopes
# (~210 KiB round trip, §8.1), plus the ~100 KiB SPA on a first visit.
# THEREFORE any station moving tens of megabytes, or holding dozens of
# concurrent connections, is BY DEFINITION abusing the portal — there is
# nothing legitimate to download at volume here. Detection feeds on the two
# accounting surfaces the node already has:
#   * hostapd's per-station byte counters ("hostapd_cli -i wlan0 all_sta",
#     rx_bytes/tx_bytes, reset on reassociation — the natural quota epoch);
#   * the per-source iptables byte counters in the DTN_ACC chain that
#     dtn-firewall.sh creates (iptables.sh) and this script populates per
#     DHCP lease, as the fallback when hostapd counters are unavailable;
#   * /proc/net/nf_conntrack, for concurrent-connection counts per source.
# A station over quota, or a source over the connection cap, is
# DEAUTHENTICATED (802.11 reason 2, PREV_AUTH_NOT_VALID): the STATION is
# shed, never the AP — hostapd keeps running, everyone else is untouched,
# and the offender is free to reassociate (its counters restart; repeated
# abuse simply re-triggers the shed).
#
# GRACEFUL DEGRADATION (required by issue #16): if hostapd_cli is absent or
# cannot reach hostapd, the script logs it, skips station shedding and exits
# 0 — the node must never be destabilized by its own shield.
#
# PRIVACY CONTRACT (binding; issue #16 + docs/protocol.md §13): counters and
# cooldowns live in TMPFS (/dev/shm) and hold only what enforcement needs —
# MACs, byte totals, expiry timestamps. Nothing is ever written to the SD
# card or the journal; everything dies at reboot. The lease file and
# conntrack table are READ (never copied out of tmpfs).

set -euo pipefail

# Environment overrides exist so tests can point these at fixtures; the
# defaults are the provisioned paths.
HOSTAPD_CLI="${HOSTAPD_CLI:-hostapd_cli}"
HOSTAPD_IF="${HOSTAPD_IF:-wlan0}"
LEASE_FILE="${LEASE_FILE:-/var/lib/misc/dnsmasq.leases}"
NF_CONNTRACK="${NF_CONNTRACK:-/proc/net/nf_conntrack}"
STATE_FILE="${STATE_FILE:-/dev/shm/dtn-station-shield.state}"
IPT="${IPT:-iptables}"
ACC_CHAIN="${ACC_CHAIN:-DTN_ACC}"

# Quota per association epoch, bytes, summed rx+tx. 64 MiB is ~18 full-node
# downloads and ~300 mule syncs — no legitimate client comes near it; see
# WHY above for the legitimate budget. (hostapd resets the counters when the
# station reassociates, so this is per-stay, not lifetime.)
STATION_QUOTA_BYTES="${STATION_QUOTA_BYTES:-67108864}"
# Concurrent connections per source IP across all ports (conntrack). A
# browser + OS chatter holds ~10-30; 64 is 2x the portal's own per-client
# connlimit budget on 8080 alone and only reachable by socket hoarders.
STATION_MAX_CONNS="${STATION_MAX_CONNS:-64}"
# Cooldown after a deauthentication: skip re-shedding the same MAC for this
# long (the station may simply have reassociated while walking away).
STATION_COOLDOWN_SECONDS="${STATION_COOLDOWN_SECONDS:-900}"
# 802.11 deauth reason 2 = PREV_AUTH_NOT_VALID ("you must re-authenticate").
DEAUTH_REASON="${DEAUTH_REASON:-2}"

DRY_RUN=0
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        -h | --help)
            sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//; /^$/d; /Usage:/q' | head -n 20
            exit 0
            ;;
        *)
            echo "dtn-station-shield: ERROR: unknown option '$arg' (usage: dtn-station-shield.sh [--dry-run])" >&2
            exit 1
            ;;
    esac
done

log() { echo "dtn-station-shield: $*"; }
die() { echo "dtn-station-shield: ERROR: $*" >&2; exit 1; }

# --- apply-mode preflight (never reached by --dry-run) -----------------------

if [ "$DRY_RUN" != "1" ]; then
    [ "$(id -u)" -eq 0 ] || die "must run as root (hostapd_cli control socket + iptables DTN_ACC require root); try --dry-run"
    command -v "$IPT" >/dev/null 2>&1 || die "$IPT not found; install the iptables package"
    "$IPT" -nL "$ACC_CHAIN" >/dev/null 2>&1 \
        || die "chain $ACC_CHAIN missing — run dtn-firewall.sh first (it creates the DTN chains)"
fi

# --- 1. inputs (every one of them optional; the shield degrades, never dies) -

# MAC <-> IP map from dnsmasq's lease file (dhcp-leasefile in dnsmasq.conf):
# "<expiry> <mac> <ip> <host> <clientid>" -> "MAC IP" pairs.
LEASES=""
if [ -r "$LEASE_FILE" ]; then
    LEASES="$(awk 'NF >= 3 { print $2, $3 }' "$LEASE_FILE")"
else
    log "lease file not readable at $LEASE_FILE: IP-correlated checks skipped this cycle"
fi

# Per-station byte counters from hostapd. hostapd_cli may be absent (not
# installed / not provisioned yet) or hostapd's control socket may be gone;
# both cases degrade to detection-only with a log line, per the contract.
STA_DATA=""
if command -v "$HOSTAPD_CLI" >/dev/null 2>&1; then
    if ! STA_DATA="$("$HOSTAPD_CLI" -i "$HOSTAPD_IF" all_sta 2>/dev/null)"; then
        STA_DATA=""
        log "hostapd_cli could not query $HOSTAPD_IF (hostapd down or control socket absent): station counters unavailable this cycle"
    fi
else
    log "hostapd_cli not available: station shedding disabled this cycle (graceful skip)"
fi
# Parse all_sta into "MAC RX TX" triples. The raw all_sta output stays inside
# this awk; only the triples below are kept, and only in memory/state-tmpfs.
STATIONS="$(printf '%s\n' "$STA_DATA" | awk '
    /^addr=/     { if (mac != "") print mac, rxb, txb; mac = substr($0, 6); rxb = 0; txb = 0 }
    /^rx_bytes=/ { rxb = substr($0, index($0, "=") + 1) + 0 }
    /^tx_bytes=/ { txb = substr($0, index($0, "=") + 1) + 0 }
    END          { if (mac != "") print mac, rxb, txb }
')"

# Per-source connection counts from conntrack ("src=IP" appears once per
# connection a source originated; the reply tuple carries the node's IP).
CONNS_IP=""
if [ -r "$NF_CONNTRACK" ]; then
    CONNS_IP="$NF_CONNTRACK"
else
    log "conntrack table not readable at $NF_CONNTRACK: connection-count check skipped this cycle"
    CONNS_IP=""
fi

# Per-source byte counters from the DTN_ACC accounting chain (apply mode
# only: listing the kernel ruleset needs root; dry-run prints the plan using
# the other two feeds). Output "IP BYTES" pairs.
acc_bytes_for() {
    "$IPT" -L "$ACC_CHAIN" -v -n -x 2>/dev/null | awk '
        $3 == "RETURN" && $(NF - 1) ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {
            src = $(NF - 1); sub(/\/32$/, "", src); print src, $2
        }' || true
}

# --- 2. keep DTN_ACC fed with one counter rule per current lease (apply only)

if [ "$DRY_RUN" != "1" ]; then
    acc_have="$("$IPT" -S "$ACC_CHAIN" 2>/dev/null || true)"
    while read -r mac ip; do
        [ -n "$mac" ] || continue
        if ! printf '%s\n' "$acc_have" | grep -qF -- "-s $ip "; then
            "$IPT" -I "$ACC_CHAIN" 1 -s "$ip" -j RETURN
            log "accounting: added DTN_ACC counter for $ip ($mac)"
        fi
    done <<LEASES_EOF
$LEASES
LEASES_EOF
    # Prune counters for leases that vanished (rules live above the terminal
    # RETURN; "-S" lines look like "-A DTN_ACC -s IP -j RETURN", so the -D
    # gets the line minus the leading "-A " verb).
    if [ -n "$LEASES" ] && [ -n "$acc_have" ]; then
        printf '%s\n' "$acc_have" | grep -- ' -s ' | while read -r ruleline; do
            rip="$(printf '%s' "$ruleline" | sed -n 's/.* -s \([0-9.]*\) .*/\1/p')"
            [ -n "$rip" ] || continue
            if ! printf '%s\n' "$LEASES" | grep -qF " $rip"; then
                # shellcheck disable=SC2086  # word splitting is the parser
                "$IPT" -D $(printf '%s' "$ruleline" | sed 's/^-A //') 2>/dev/null || true
                log "accounting: pruned DTN_ACC counter for $rip (lease gone)"
            fi
        done
    fi
fi

# --- 3. decide + shed ---------------------------------------------------------

NOW="$(date +%s)"
ACTIONS=""     # "DEAUTH <mac> <reason>" lines
NEW_STATE=""   # "cooldown <mac> <expiry>" lines

on_cooldown() {
    local mac="$1"
    [ -r "$STATE_FILE" ] || return 1
    awk -v mac="$mac" -v now="$NOW" \
        '$1 == "cooldown" && $2 == mac { if ($3 > now) exit 0; else exit 1 }' \
        "$STATE_FILE"
}

# mac_for IP — reverse lookup in the lease map.
mac_for() {
    local ip="$1"
    printf '%s\n' "$LEASES" | awk -v ip="$ip" '$2 == ip { print $1; exit }'
}

# Feeds already verified: quota over the byte ceiling...
while read -r mac rxb txb; do
    [ -n "$mac" ] || continue
    total=$(( rxb + txb ))
    if [ "$total" -gt "$STATION_QUOTA_BYTES" ] && ! on_cooldown "$mac"; then
        ACTIONS="${ACTIONS}DEAUTH ${mac} moved ${total} bytes this association (quota ${STATION_QUOTA_BYTES})"$'\n'
    fi
done <<STATIONS_EOF
$STATIONS
STATIONS_EOF

# ...or hoarding connections...
if [ -n "$CONNS_IP" ]; then
    while read -r mac ip; do
        [ -n "$mac" ] || continue
        if on_cooldown "$mac"; then continue; fi
        count="$(grep -oF "src=$ip " "$CONNS_IP" 2>/dev/null | wc -l | tr -d ' ')" || count=0
        if [ "${count:-0}" -gt "$STATION_MAX_CONNS" ]; then
            ACTIONS="${ACTIONS}DEAUTH ${mac} holds ${count} concurrent connections (cap ${STATION_MAX_CONNS})"$'\n'
        fi
    done <<LEASES_EOF
$LEASES
LEASES_EOF
fi

# ...or burning bytes in the firewall accounting chain when hostapd gave us
# nothing for that station (apply mode only; the counters were ensured above).
if [ "$DRY_RUN" != "1" ]; then
    while read -r ip bytes; do
        [ -n "$ip" ] || continue
        [ "$bytes" -gt "$STATION_QUOTA_BYTES" ] || continue
        mac="$(mac_for "$ip")"
        [ -n "$mac" ] || continue
        if ! on_cooldown "$mac" && ! printf '%s' "$ACTIONS" | grep -qF "DEAUTH $mac "; then
            ACTIONS="${ACTIONS}DEAUTH ${mac} counted ${bytes} bytes in DTN_ACC (quota ${STATION_QUOTA_BYTES})"$'\n'
        fi
    done <<ACC_EOF
$(acc_bytes_for)
ACC_EOF
fi

deauth_station() {
    local mac="$1"
    if command -v "$HOSTAPD_CLI" >/dev/null 2>&1; then
        "$HOSTAPD_CLI" -i "$HOSTAPD_IF" deauthenticate "$mac" "$DEAUTH_REASON" || \
            log "deauthenticate $mac failed (hostapd unreachable?); will retry after cooldown"
    else
        log "cannot shed $mac: hostapd_cli unavailable (graceful skip)"
    fi
}

while read -r tag mac reason; do
    [ -n "${mac:-}" ] || continue
    expiry=$(( NOW + STATION_COOLDOWN_SECONDS ))
    if [ "$DRY_RUN" = "1" ]; then
        log "[dry-run] would deauthenticate $mac — $reason (reason $DEAUTH_REASON), cooldown ${STATION_COOLDOWN_SECONDS}s"
    else
        deauth_station "$mac"
        log "shed station $mac — $reason (reason $DEAUTH_REASON); AP itself untouched"
    fi
    NEW_STATE="${NEW_STATE}cooldown ${mac} ${expiry}"$'\n'
done <<ACTIONS_EOF
$ACTIONS
ACTIONS_EOF

# --- 4. state rewrite (apply only; tmpfs, MACs + expiry stamps, nothing else) -

if [ "$DRY_RUN" != "1" ]; then
    printf '%s' "$NEW_STATE" > "${STATE_FILE}.tmp"
    mv "${STATE_FILE}.tmp" "$STATE_FILE"
fi

exit 0
