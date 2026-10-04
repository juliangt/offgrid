#!/usr/bin/env bash
# tests/chaos/chaos_restart_under_load.sh — SIGTERM-restart the daemon R times
# while N concurrent sync workers hammer it (issue #16 Phase 4, Track 4; the
# "restart under load" row of FAILURE_MATRIX.md).
#
# Injection: N background workers loop the three §10.4 traffic shapes (valid
# push batches, malformed-junk posts, pull-only syncs) with hard curl
# timeouts, while the main loop SIGTERMs the daemon, waits for the drain and
# restarts it on the same database, R times.
#
# Expected behavior (degrade + auto-recover):
#   - every request DURING a live window is answered from the clean set:
#     200, or the shed family 400/413/429/507 (rate budgets, validation).
#     NO 5xx chaos, no panic storm — a restart is never observable as an
#     internal-error burst;
#   - connection drops/refusals happen ONLY in the restart windows (the
#     listener is gone); they are EXPECTED and bounded — every worker
#     request carries --max-time/--connect-timeout, so nothing hangs forever
#     (the assertion is timeouts == 0);
#   - after the last restart the daemon is ready again, serves the seeded
#     envelopes byte-identical, and no quarantine happened.
#
# Data expectation: only never-ACKed in-flight requests of the restart
# windows are accepted loss (their clients saw the drop and retry); the
# seeded (ACKed) set MUST survive every restart.
#
# Usage:  bash tests/chaos/chaos_restart_under_load.sh
# Env:    CHAOS_RESTART_PORT (default 18098), CHAOS_RESTARTS (default 4),
#         CHAOS_WORKERS (default 6)
# Needs:  go (daemon build), curl. No root.
# Exit:   0 = every assertion passed; 1 = at least one failed.

set -euo pipefail

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

PORT="${CHAOS_RESTART_PORT:-18098}"
RESTARTS="${CHAOS_RESTARTS:-4}"
WORKERS="${CHAOS_WORKERS:-6}"

chaos_init chaos-restart

build_daemon || fatal "daemon build failed"
DB="$CHAOS_WORK/node.db"
LOG="$CHAOS_WORK/node.log"

# ---------------------------------------------------------------------------
# 0. Baseline: seed five live envelopes and record their payload shas.
# ---------------------------------------------------------------------------
start_daemon "$PORT" "$DB" "$LOG"
wait_ready "$PORT" || { cat "$LOG" >&2; fatal "daemon never became ready"; }

NOW="$(date +%s)"
# Seeded envelopes carry created_at = NOW+100 (legal: within the §10.5 300 s
# clock skew) so they always sort FIRST in the created_at-DESC pull page —
# worker envelopes (created at real time) can never push the survival set off
# the 50-envelope page the final byte-identity check reads.
SEED_AT="$((NOW + 100))"
seed_envs=""
seed_known="["
for i in 1 2 3 4 5; do
    seed_envs="$seed_envs$(envelope_json "$(hex_id "$i")" "$SEED_AT" 3600 "$(payload_b64 "$i")"),"
    seed_known="$seed_known\"$(hex_id "$i")\","
done
seed_envs="${seed_envs%,}"
seed_known="${seed_known%,}]"
make_sync_body "$CHAOS_WORK/seed.json" "$seed_known" "[$seed_envs]"
code="$(http POST "http://127.0.0.1:$PORT/api/v1/sync" "$CHAOS_WORK/seed.json")"
[ "$code" = "200" ] || fatal "seeding push failed with HTTP $code"
make_sync_body "$CHAOS_WORK/pull_seed.json" "[]" "[]"
code="$(http POST "http://127.0.0.1:$PORT/api/v1/sync" "$CHAOS_WORK/pull_seed.json")"
[ "$code" = "200" ] || fatal "seeding pull failed with HTTP $code"
SEEDED_SHAS="$(payload_shas_of "$CHAOS_WORK/last_body")"
check "seed: exactly 5 envelopes ACKed" "5" "$(printf '%s\n' "$SEEDED_SHAS" | grep -c . || true)"

# ---------------------------------------------------------------------------
# 1. Workers: each loops one of the three traffic shapes until the stop flag,
#    classifying every outcome into ok / shed / drop / hang / err via hard
#    curl timeouts. Drops (curl 7/52/56 with no HTTP answer) are legal ONLY
#    because the restart windows kill the listener; anything with an HTTP
#    status outside {200, 4xx, 507} is an err.
# ---------------------------------------------------------------------------
log "starting $WORKERS load workers (valid pushes + junk posts + pull-only syncs)"
STOP="$CHAOS_WORK/stop"
WORKER_PIDS=""
worker() {
    local w=$1 try=0 kind code ec
    local body_file="$CHAOS_WORK/worker_$w.json"
    while [ ! -e "$STOP" ] && [ "$try" -lt 400 ]; do
        try=$((try + 1))
        kind=$(( (w + try) % 3 ))
        rm -f "$body_file"
        case $kind in
            0) # valid push batch: 3 fresh live envelopes
                local p now ids envs j
                now="$(date +%s)"; ids="["; envs="["
                for j in 1 2 3; do
                    p="$(payload_b64 "$w-$try-$j")"
                    ids="$ids\"$(hex_id $((w * 100000 + try * 10 + j)))\","
                    envs="$envs$(envelope_json "$(hex_id $((w * 100000 + try * 10 + j)))" "$now" 3600 "$p"),"
                done
                printf '{"known_ids":%s,"push_envelopes":%s,"limit":5}' "${ids%,}]" "${envs%,}]" > "$body_file"
                ;;
            1) # junk post: truncated JSON (the §10.4 parser must answer 400)
                printf '{"known_ids":[{"nope"' > "$body_file"
                ;;
            2) # pull-only sync (costs no budget mint)
                printf '{"known_ids":[],"push_envelopes":[],"limit":50}' > "$body_file"
                ;;
        esac
        ec=0
        code="$(curl -s --max-time 8 --connect-timeout 2 -o /dev/null -w '%{http_code}' \
            -H 'Host: offgrid.local:8080' -H 'Content-Type: application/json' \
            --data-binary @"$body_file" \
            -X POST "http://127.0.0.1:$PORT/api/v1/sync" 2>/dev/null)" || ec=$?
        if [ "$ec" -eq 0 ]; then
            case $code in
                200) echo ok ;;
                400|413|429|507) echo shed ;;
                *) echo "err:$code" ;;
            esac
        else
            case $ec in
                7|52|56) echo drop ;;   # connection refused/empty/reset: restart-window noise
                28) echo hang ;;        # timeout: a request that would hang forever
                *) echo "err:curl-$ec" ;;
            esac
        fi >> "$CHAOS_WORK/worker_$w.out"
        sleep 0.0$((w * 2 + 2)) # 0.04..0.16 s, per-worker jitter
    done
}
for w in $(seq 1 "$WORKERS"); do
    worker "$w" &
    WORKER_PIDS="$WORKER_PIDS $!"
done
sleep 1.5 # let the load build before the first restart

# reap_workers — wait for the WORKER subshells only, never a bare `wait`: a
# no-arg wait blocks on ALL children, the still-running daemon included, and
# would hang the script forever right after the final restart.
reap_workers() {
    local p
    for p in $WORKER_PIDS; do
        wait "$p" 2>/dev/null || true
    done
}

# ---------------------------------------------------------------------------
# 2. R SIGTERM restart cycles under the live load; every window must end in
#    a READY daemon within a bounded time (the wait_ready poll bound).
# ---------------------------------------------------------------------------
r=1
while [ "$r" -le "$RESTARTS" ]; do
    log "restart cycle $r/$RESTARTS: SIGTERM under load"
    stop_daemon
    start_daemon "$PORT" "$DB" "$LOG"
    if wait_ready "$PORT" 75; then READY=0; else READY=1; fi
    check "restart $r: daemon ready again within the bounded window" "0" "$READY"
    if [ "$READY" -ne 0 ]; then
        touch "$STOP"
        reap_workers
        cat "$LOG" >&2 || true
        exit 1
    fi
    r=$((r + 1))
    sleep 0.8
done

# ---------------------------------------------------------------------------
# 3. Tally and final assertions.
# ---------------------------------------------------------------------------
touch "$STOP"
reap_workers

TALLY="$(cat "$CHAOS_WORK"/worker_*.out 2>/dev/null | sort | uniq -c | sed -E 's/^ +([0-9]+) /\1 /' || true)"
sum_for() { printf '%s\n' "$TALLY" | awk -v k="$1" '$2 == k {s+=$1} END {print s+0}'; }
OK_N="$(sum_for ok)"
SHED_N="$(sum_for shed)"
DROP_N="$(sum_for drop)"
HANG_N="$(sum_for hang)"
ERR_N="$(printf '%s\n' "$TALLY" | awk '$2 ~ /^err/ {s+=$1} END {print s+0}')"
ERR_DETAIL="$(printf '%s\n' "$TALLY" | awk '$2 ~ /^err/ {printf "%s=%s ", $2, $1}')"

log "tally: ok=$OK_N shed=$SHED_N drop=$DROP_N (restart-window noise) hang=$HANG_N err=$ERR_N $ERR_DETAIL"
check "no request errors: never a 5xx/panic storm, only the clean answer set" "0" "$ERR_N"
check "no hung requests: every worker call completed inside its curl timeout" "0" "$HANG_N"
check "the daemon still served during the episode (ok >= 1)" "yes" \
    "$([ "${OK_N:-0}" -ge 1 ] && echo yes || echo no)"

# The workers have just exhausted the per-IP POST budget (60-burst, refilled
# 1 request per 2 s — the shed tally above is exactly that guard working).
# A budget-refused request spends nothing, so the final verification simply
# polls until a token refills (bounded: 120 s).
FINAL_PULL_CODE="000"
for i in $(seq 1 40); do
    make_sync_body "$CHAOS_WORK/final_pull.json" "[]" "[]"
    FINAL_PULL_CODE="$(http POST "http://127.0.0.1:$PORT/api/v1/sync" "$CHAOS_WORK/final_pull.json")" || FINAL_PULL_CODE=000
    if [ "$FINAL_PULL_CODE" = "200" ]; then break; fi
    sleep 3
done
code="$FINAL_PULL_CODE"
check "final daemon: pull -> 200 (after the per-IP request budget refills)" "200" "$code"
FINAL_SHAS="$(payload_shas_of "$CHAOS_WORK/last_body")"
check "final daemon: every seeded envelope still served byte-identical (0 missing)" \
    "0" \
    "$(printf '%s\n' "$SEEDED_SHAS" | while IFS= read -r s; do printf '%s\n' "$FINAL_SHAS" | grep -qx "$s" || echo missing; done | grep -c . || true)"
check "final daemon: store survived all restarts unquarantined" \
    "0" "$(quarantine_count "$DB")"

stop_daemon
chaos_summary
