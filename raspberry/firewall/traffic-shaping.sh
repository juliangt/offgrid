#!/usr/bin/env bash
# dtn-traffic-shaping.sh — per-client bandwidth fairness for the off-grid DTN
# node's AP interface (Module A, issue #16 Track 1).
# Install path: /usr/local/sbin/dtn-traffic-shaping.sh
# Invoked at boot by dtn-traffic-shaping.service (after networking has brought
# wlan0 up, before hostapd starts answering clients) and idempotent: every
# qdisc/filter operation is a "replace", so re-running cleanly swaps the
# previous shaping for the current one instead of stacking.
#
# Usage:
#   dtn-traffic-shaping.sh            apply (root)
#   dtn-traffic-shaping.sh --dry-run  print the exact tc/ip commands without
#                                     executing anything (no root needed —
#                                     this is what tests/hardening_structure.sh
#                                     exercises)
#
# WHY (issue #16 Track 1): the AP radio is the node's only shared resource a
# client can saturate. CAKE (Common Applications Kept Enhanced) with per-host
# flow isolation makes every STATION an equal shareholder of the airtime, so
# one abusive device hammering the portal cannot starve the legitimate mule
# sync of everybody else. Two directions, two qdiscs:
#
#   * egress (node -> clients), dev wlan0 root: cake dual-dsthost — fairness
#     across DESTINATION stations, which is the client-facing direction of
#     the radio (portal answers, SPA downloads);
#   * ingress (clients -> node), via the IFB pattern: the kernel cannot queue
#     what has already arrived, so an ingress qdisc mirrors arriving frames
#     into the ifb0 virtual device where cake dual-srchost — fairness across
#     SOURCE stations — rate-limits the abuser's uplink into the node.
#
# CAKE's host-isolation modes are mutually exclusive per qdisc, so each
# direction carries the host dimension that matters for it (dual-srchost on
# ingress = per-sender fairness for client->node floods, dual-dsthost on
# egress = per-receiver fairness for node->client answers); the test asserts
# BOTH tokens are present in the generated command stream.
#
# Values are ceilings, not targets: a Zero 2 W's 802.11n radio rarely exceeds
# ~25-40 Mbit/s real throughput, so 25 Mbit is "as fast as the box can go",
# only smoothed. A full mule sync (~210 KiB, docs/protocol.md §8.1) drains in
# well under a second at that rate — legitimate traffic is never throttled in
# practice; abuse merely loses its ability to crowd out others.

set -euo pipefail

WLAN_IF="${WLAN_IF:-wlan0}"
IFB_IF="${IFB_IF:-ifb0}"
# Tunable ceilings; rationale in the header. Override for exotic radios.
CAKE_EGRESS_BANDWIDTH="${CAKE_EGRESS_BANDWIDTH:-25mbit}"
CAKE_INGRESS_BANDWIDTH="${CAKE_INGRESS_BANDWIDTH:-25mbit}"

DRY_RUN=0
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        -h | --help)
            sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//; /^$/d; /Usage:/q' | head -n 20
            exit 0
            ;;
        *)
            echo "dtn-traffic-shaping: ERROR: unknown option '$arg' (usage: dtn-traffic-shaping.sh [--dry-run])" >&2
            exit 1
            ;;
    esac
done

log() { echo "dtn-traffic-shaping: $*"; }
die() { echo "dtn-traffic-shaping: ERROR: $*" >&2; exit 1; }

# run DESC -- CMD... — execute or, in dry-run mode, print verbatim.
run() {
    local desc="$1"
    shift
    if [ "$DRY_RUN" = "1" ]; then
        printf 'dtn-traffic-shaping: [dry-run] %s\n  ' "$desc"
        printf '%s ' "$@"
        printf '\n'
    else
        "$@"
    fi
}

if [ "$DRY_RUN" != "1" ]; then
    [ "$(id -u)" -eq 0 ] || die "must run as root (tc qdisc changes require CAP_NET_ADMIN); try --dry-run"
    command -v tc >/dev/null 2>&1 || die "tc not found; install the iproute2 package"
    command -v modprobe >/dev/null 2>&1 || die "modprobe not found; kernel module tools missing"

    # Boot-time resilience: right after networking.service the interface may
    # still be settling; wait, bounded, then fail with a clear message (the
    # unit can be restarted; hostapd ordering keeps clients out meanwhile).
    i=0
    until ip link show "$WLAN_IF" >/dev/null 2>&1; do
        i=$((i + 1))
        if [ "$i" -ge 30 ]; then
            die "interface $WLAN_IF does not exist after 30s; is this the AP board?"
        fi
        sleep 1
    done
fi

# 1. The ifb module backs the ingress mirror device. On Raspberry Pi OS it is
#    a standard module (CONFIG_IFB=m); a kernel without it cannot do ingress
#    shaping and the script must say so instead of silently half-working.
run "ensure ifb module" modprobe ifb
if [ "$DRY_RUN" = "1" ] || ! ip link show "$IFB_IF" >/dev/null 2>&1; then
    run "create ingress mirror device $IFB_IF" ip link add "$IFB_IF" type ifb
fi
run "bring up $IFB_IF" ip link set "$IFB_IF" up

# 2. Ingress: mirror everything arriving on the AP interface into ifb0, where
#    cake dual-srchost enforces per-source-station fairness for the
#    client->node direction (portal pushes, mule uploads, floods).
run "attach ingress qdisc on $WLAN_IF" tc qdisc replace dev "$WLAN_IF" handle ffff: ingress
# Only our matchall mirror lives on ffff:; deleting first makes re-runs
# deterministic (a stale filter for a renamed IFB would blackhole ingress).
if [ "$DRY_RUN" != "1" ]; then
    tc filter del dev "$WLAN_IF" parent ffff: 2>/dev/null || true
fi
run "mirror ingress into $IFB_IF" tc filter add dev "$WLAN_IF" parent ffff: matchall action mirred egress redirect dev "$IFB_IF"
run "per-source cake on the mirrored ingress" tc qdisc replace dev "$IFB_IF" root cake bandwidth "$CAKE_INGRESS_BANDWIDTH" dual-srchost

# 3. Egress: cake dual-dsthost on the AP interface itself — per-destination-
#    station fairness for the node->client direction.
run "per-destination cake on $WLAN_IF egress" tc qdisc replace dev "$WLAN_IF" root cake bandwidth "$CAKE_EGRESS_BANDWIDTH" dual-dsthost

# 4. Verify (apply mode): both qdiscs must actually report cake.
if [ "$DRY_RUN" != "1" ]; then
    tc qdisc show dev "$WLAN_IF" | grep -q cake || die "egress cake qdisc not active on $WLAN_IF after apply"
    tc qdisc show dev "$IFB_IF" | grep -q cake || die "ingress cake qdisc not active on $IFB_IF after apply"
    log "shaping active: $WLAN_IF egress cake $CAKE_EGRESS_BANDWIDTH dual-dsthost, $IFB_IF ingress cake $CAKE_INGRESS_BANDWIDTH dual-srchost"
fi

exit 0
