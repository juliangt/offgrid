#!/usr/bin/env bash
# dtn-network-watchdog.sh — self-healing AP stack supervisor for the off-grid
# DTN dead-drop node (Module A, issue #16 Track 3).
# Repo path : raspberry/hardening/dtn-network-watchdog.sh
# Install   : /usr/local/sbin/dtn-network-watchdog.sh
# Run every two minutes by dtn-network-watchdog.timer (systemd oneshot).
# Safe to re-run by hand; state lives in TMPFS only.
#
# Usage:
#   dtn-network-watchdog.sh            apply (root): probe the stack, restart
#                                      only what failed (budget-capped)
#   dtn-network-watchdog.sh --dry-run  run the probes and print exactly what
#                                      apply WOULD do — rootless, no restarts,
#                                      no state writes (what
#                                      tests/hardening_structure.sh exercises)
#
# WHY (issue #16 Track 3: "zero manual SSH"): a field unit survives power
# cuts by rebooting, and every unit is enabled at boot — but a component can
# still die AFTER a clean boot (brcmfmac wedge, dnsmasq OOM under a DHCP
# flood, a daemon crash that even Restart=always turns into a crash loop).
# Nobody is on call; the node must notice and act. The watchdog is strictly
# the LAST line of defense: dtn-node.service has its own systemd watchdog
# (WatchdogSec), so this script only re-checks the daemon as belt-and-braces.
#
# PROBES (each answers one question, all local, none network-facing):
#   * hostapd association-capable  : "hostapd_cli -i wlan0 status" reports
#                                    state=ENABLED (the radio accepts
#                                    associations — the AP's whole job);
#   * dnsmasq answering            : a probe A query for a junk name against
#                                    10.42.0.1 must come back with the
#                                    wildcard answer (the captive portal's
#                                    foundation). Queried against the node's
#                                    OWN AP address on purpose — NOT lo:
#                                    dnsmasq.conf deliberately uses
#                                    bind-interfaces + interface=wlan0, so
#                                    loopback is a dead end BY DESIGN.
#   * daemon answering             : the §10.2 captive probe path
#                                    /generate_204 on 127.0.0.1:$PORTAL_PORT
#                                    with the canonical Host must give 302.
#
# RESTART-STORM GUARD (bounded, required by issue #16): restarting a wedged
# hostapd twice is healing; restarting it every two minutes for an hour is a
# reboot loop that hammers the SD card and the radio. Per component, at most
# MAX_RESTARTS_PER_HOUR within STORM_WINDOW_SECONDS: past the budget the
# watchdog STOPS and drops a journald marker (logger) saying the component
# needs eyes — an honest "I give up" beats an infinite crash loop. Counters
# live in TMPFS (/dev/shm) and die at reboot: a fresh boot always gets a
# fresh budget, which is correct — a reboot already IS the big reset.
#
# PRIVACY: probes and counters only — no MACs, no IPs of clients, nothing
# persisted outside the tmpfs state file (docs/protocol.md §13).

set -euo pipefail

# Environment overrides (tests point these at fixtures); defaults are the
# provisioned paths/constants.
HOSTAPD_CLI="${HOSTAPD_CLI:-hostapd_cli}"
HOSTAPD_IF="${HOSTAPD_IF:-wlan0}"
DIG="${DIG:-dig}"
CURL="${CURL:-curl}"
SYSTEMCTL="${SYSTEMCTL:-systemctl}"
LOGGER="${LOGGER:-logger}"
NODE_IP="${NODE_IP:-10.42.0.1}"
PORTAL_PORT="${PORTAL_PORT:-8080}"
PORTAL_HOST="${PORTAL_HOST:-offgrid.local:8080}"
PROBE_NAME="${PROBE_NAME:-watchdog-probe.offgrid.invalid}"
STATE_FILE="${STATE_FILE:-/dev/shm/dtn-network-watchdog.state}"
# Restart budget per component (see the storm-guard note above).
MAX_RESTARTS_PER_HOUR="${MAX_RESTARTS_PER_HOUR:-3}"
STORM_WINDOW_SECONDS="${STORM_WINDOW_SECONDS:-3600}"

DRY_RUN=0
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        -h | --help)
            sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//; /^$/d; /Usage:/q' | head -n 20
            exit 0
            ;;
        *)
            echo "dtn-network-watchdog: ERROR: unknown option '$arg' (usage: dtn-network-watchdog.sh [--dry-run])" >&2
            exit 1
            ;;
    esac
done

log() { echo "dtn-network-watchdog: $*"; }

# --- 1. probes (every tool optional; a missing tool = unverifiable = skip) ----
#
# Each *_healthy returns 0 healthy / 1 unhealthy / 125 unverifiable. Outputs
# are captured into variables before matching on purpose: a `cmd | grep -q`
# under pipefail can let grep's early exit SIGPIPE the producer and flip the
# result (the same trap tests/hardening_structure.sh documents for --print).

# tool DESC PATH — 125 (unverifiable, never a restart) when PATH is absent.
tool() {
    local desc="$1" bin="$2"
    if ! command -v "$bin" >/dev/null 2>&1; then
        log "$desc: tool '$bin' not available — unverifiable this cycle (graceful skip)"
        return 125
    fi
    return 0
}

hostapd_healthy() {
    tool "hostapd" "$HOSTAPD_CLI" || return
    # state=ENABLED is hostapd's "the interface is up and accepting
    # associations" — the AP's whole job.
    local status
    status="$("$HOSTAPD_CLI" -i "$HOSTAPD_IF" status 2>/dev/null || true)"
    printf '%s\n' "$status" | grep -q '^state=ENABLED$'
}

dnsmasq_healthy() {
    tool "dnsmasq" "$DIG" || return
    # The wildcard must answer a junk probe name with the portal IP. The
    # query goes to the node's OWN AP address, NOT lo: dnsmasq.conf
    # deliberately binds wlan0 only (bind-interfaces + interface=wlan0), so
    # loopback is a dead end BY DESIGN. The junk name is a fixed constant —
    # never user data.
    local answer
    answer="$("$DIG" +time=2 +tries=1 +noall +answer @"$NODE_IP" "$PROBE_NAME" A 2>/dev/null || true)"
    printf '%s\n' "$answer" | grep -qF "$NODE_IP"
}

daemon_healthy() {
    tool "dtn-node" "$CURL" || return
    # 302 = the §10.2 captive-probe path answering on the canonical origin.
    local code
    code="$("$CURL" -s -o /dev/null -w '%{http_code}' -H "Host: $PORTAL_HOST" \
        "http://127.0.0.1:$PORTAL_PORT/generate_204" 2>/dev/null || true)"
    [ "$code" = "302" ]
}

# --- 2. restart budget (tmpfs state: "restart <unit> <epoch>" lines) ----------

budget_used() {
    local unit="$1"
    [ -r "$STATE_FILE" ] || { printf '0'; return; }
    awk -v unit="$unit" -v now="$NOW" -v window="$STORM_WINDOW_SECONDS" \
        '$1 == "restart" && $2 == unit && (now - $3) < window { n++ } END { print n + 0 }' \
        "$STATE_FILE"
}

# --- 3. decide + act (restart ONLY the failed component, budget-capped) -------

NOW="$(date +%s)"

check_and_heal() {
    local desc="$1" unit="$2"
    shift 2
    local healthy budget
    if "$@"; then
        healthy=0
    else
        healthy=$?
    fi
    if [ "$healthy" = "0" ]; then
        log "$desc: OK"
        return 0
    elif [ "$healthy" = "125" ]; then
        return 0 # unverifiable: never restart on a missing probe tool
    fi

    budget="$(budget_used "$unit")"
    if [ "$budget" -ge "$MAX_RESTARTS_PER_HOUR" ]; then
        log "$desc: UNHEALTHY and restart budget exhausted ($budget/$MAX_RESTARTS_PER_HOUR in ${STORM_WINDOW_SECONDS}s) — NOT restarting"
        if [ "$DRY_RUN" != "1" ]; then
            # The honest marker an operator (or the chaos matrix) looks for.
            "$LOGGER" -t dtn-network-watchdog \
                "component $unit unhealthy; restart budget exhausted ($budget/$MAX_RESTARTS_PER_HOUR per ${STORM_WINDOW_SECONDS}s) — needs manual attention"
        fi
        return 0
    fi

    if [ "$DRY_RUN" = "1" ]; then
        log "[dry-run] $desc: UNHEALTHY — would restart $unit (budget $budget/$MAX_RESTARTS_PER_HOUR in ${STORM_WINDOW_SECONDS}s)"
        return 0
    fi

    log "$desc: UNHEALTHY — restarting $unit (budget $budget/$MAX_RESTARTS_PER_HOUR in ${STORM_WINDOW_SECONDS}s)"
    if "$SYSTEMCTL" restart "$unit" >/dev/null 2>&1; then
        log "$desc: restart of $unit issued"
    else
        log "$desc: restart of $unit FAILED (systemd refused?) — counts against the budget anyway"
    fi
    echo "restart $unit $NOW" >> "$STATE_FILE"
    return 0
}

check_and_heal "hostapd (association-capable)" hostapd.service hostapd_healthy
check_and_heal "dnsmasq (answering wildcard DNS)" dnsmasq.service dnsmasq_healthy
check_and_heal "dtn-node (captive probe 302)" dtn-node.service daemon_healthy

# --- 4. state rewrite (apply only): prune entries older than the window so the
# tmpfs file stays bounded to one hour of history, counters only.

if [ "$DRY_RUN" != "1" ]; then
    if [ -f "$STATE_FILE" ]; then
        awk -v now="$NOW" -v window="$STORM_WINDOW_SECONDS" \
            '$1 == "restart" && (now - $3) < window { print }' \
            "$STATE_FILE" > "${STATE_FILE}.tmp" || true
        mv "${STATE_FILE}.tmp" "$STATE_FILE"
    fi
fi

exit 0
