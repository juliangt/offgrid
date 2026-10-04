#!/usr/bin/env bash
# tests/chaos/chaos_kill_mid_sync.sh — SIGKILL the daemon mid-sync (issue #16
# Phase 4, Track 4; the "daemon killed mid-sync" rows of FAILURE_MATRIX.md).
#
# Injection: seed a store, then keep large valid §10.4 sync POSTs flowing in
# the background and SIGKILL the daemon at a random moment mid-flight — the
# hard power-cut analog for the process (no drain, no checkpoint, sockets
# RST, whatever transaction was in flight dies with the process).
#
# Expected behavior (degrade + auto-recover):
#   - the restarted daemon becomes ready again on the same database;
#   - the store is NOT corrupted: zero .corrupt-* quarantine artifacts
#     (SQLite WAL atomicity means a killed process leaves a consistent
#     database, never a half-broken one);
#   - every envelope that was already ACKed to a client (the seeded ones)
#     is still served BYTE-IDENTICAL (payload sha256 set match);
#   - a fresh sync (push + pull) works right after the restart.
#
# Data expectation: the in-flight, never-ACKed batch of the killed request is
# explicitly accepted loss (the client saw no 200 and must retry); it may or
# may not have landed depending on the kill timing — both outcomes are legal
# and only the seeded set is asserted.
#
# Usage:  bash tests/chaos/chaos_kill_mid_sync.sh
# Env:    CHAOS_KILL_PORT (default 18095; chaos suite owns 18095-18099)
# Needs:  go (daemon build), curl. No root.
# Exit:   0 = every assertion passed; 1 = at least one failed.

set -euo pipefail

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

PORT="${CHAOS_KILL_PORT:-18095}"

chaos_init chaos-kill

build_daemon || fatal "daemon build failed"
DB="$CHAOS_WORK/node.db"
LOG="$CHAOS_WORK/node.log"

# ---------------------------------------------------------------------------
# 0. Baseline: start the daemon, seed three live envelopes through the real
#    push path, record their payload sha256 set (the ACKed data).
# ---------------------------------------------------------------------------
start_daemon "$PORT" "$DB" "$LOG"
wait_ready "$PORT" || { cat "$LOG" >&2; fatal "daemon never became ready"; }

NOW="$(date +%s)"
# Seeded envelopes carry created_at = NOW+100 (legal: within the §10.5 300 s
# clock skew) so they always sort FIRST in the created_at-DESC pull page — a
# flood that lands thousands of envelopes can never push the survival set off
# the 50-envelope page the byte-identity check reads.
SEED_AT="$((NOW + 100))"
E1="$(envelope_json "$(hex_id 1)" "$SEED_AT" 3600 "$(payload_b64 1)")"
E2="$(envelope_json "$(hex_id 2)" "$SEED_AT" 3600 "$(payload_b64 2)")"
E3="$(envelope_json "$(hex_id 3)" "$SEED_AT" 3600 "$(payload_b64 3)")"
make_sync_body "$CHAOS_WORK/seed.json" "[\"$(hex_id 1)\",\"$(hex_id 2)\",\"$(hex_id 3)\"]" "[$E1,$E2,$E3]"
code="$(http POST "http://127.0.0.1:$PORT/api/v1/sync" "$CHAOS_WORK/seed.json")"
[ "$code" = "200" ] || fatal "seeding push failed with HTTP $code"

make_sync_body "$CHAOS_WORK/pull_seed.json" "[]" "[]"
code="$(http POST "http://127.0.0.1:$PORT/api/v1/sync" "$CHAOS_WORK/pull_seed.json")"
[ "$code" = "200" ] || fatal "seeding pull failed with HTTP $code"
SEEDED_SHAS="$(payload_shas_of "$CHAOS_WORK/last_body")"
check "seed: exactly 3 envelopes ACKed and served" "3" \
    "$(printf '%s\n' "$SEEDED_SHAS" | grep -c . || true)"

# ---------------------------------------------------------------------------
# 1. Injection: keep LARGE valid sync POSTs flowing in the background and
#    SIGKILL the daemon at a random moment in (0.03, 0.30) s. 40 sequential
#    100-envelope batches (~50 KiB bodies each, fresh ids so dedup never
#    collapses them) guarantee a request is in flight when the kill lands.
# ---------------------------------------------------------------------------
log "firing 40 background 100-envelope sync POSTs, then SIGKILL mid-flight"
(
    NOW2="$(date +%s)"
    BIG="$(payload_b64 flood)"
    slot_base=1000
    for batch in $(seq 1 40); do
        envs=""
        for slot in $(seq 0 99); do
            envs="$envs$(envelope_json "$(hex_id $((slot_base + slot)))" "$NOW2" 3600 "$BIG"),"
        done
        printf '{"known_ids":[],"push_envelopes":[%s],"limit":1}' "${envs%,}" \
            > "$CHAOS_WORK/flood_body.json"
        curl -s --max-time 10 --connect-timeout 2 -o /dev/null \
            -H 'Host: offgrid.local:8080' -H 'Content-Type: application/json' \
            --data-binary @"$CHAOS_WORK/flood_body.json" \
            -X POST "http://127.0.0.1:$PORT/api/v1/sync" 2>/dev/null || true
        slot_base=$((slot_base + 1000))
    done
) &
FLOOD_PID=$!

DELAY=$((RANDOM % 270 + 30))
sleep "$(printf '0.%03d' "$DELAY")"
log "SIGKILL the daemon (pid $DAEMON_PID) after ${DELAY} ms of flood traffic"
kill_daemon
wait "$FLOOD_PID" 2>/dev/null || true

# ---------------------------------------------------------------------------
# 2. Restart on the same database and assert the recovery contract.
# ---------------------------------------------------------------------------
log "restarting the daemon on the same database"
start_daemon "$PORT" "$DB" "$LOG"
if wait_ready "$PORT"; then READY=0; else READY=1; fi
check "daemon ready again after SIGKILL mid-sync" "0" "$READY"
if [ "$READY" -ne 0 ]; then
    cat "$LOG" >&2 || true
    exit 1
fi

check "store not corrupted: zero .corrupt-* quarantine artifacts (WAL atomicity)" \
    "0" "$(quarantine_count "$DB")"

# The seeded (ACKed) envelopes must survive byte-identical: the sorted sha
# sets are compared and the assertion is the number of seeded shas MISSING
# from the post-restart pull (0 = nothing lost).
make_sync_body "$CHAOS_WORK/pull_after.json" "[]" "[]"
code="$(http POST "http://127.0.0.1:$PORT/api/v1/sync" "$CHAOS_WORK/pull_after.json")"
check "pull after restart -> 200" "200" "$code"
AFTER_SHAS="$(payload_shas_of "$CHAOS_WORK/last_body")"
check "every seeded (ACKed) envelope survives byte-identical (0 payload shas missing)" \
    "0" \
    "$(comm -23 <(printf '%s\n' "$SEEDED_SHAS" | sort) <(printf '%s\n' "$AFTER_SHAS" | sort) | grep -c . || true)"

# A fresh sync works right after the restart: push one new envelope, then
# find its payload back byte-identical in a pull.
FRESH_PAYLOAD="$(payload_b64 fresh)"
FRESH_SHA="$(sha256_hex "$FRESH_PAYLOAD")"
FRESH_ID="$(hex_id 999999)"
FRESH="$(envelope_json "$FRESH_ID" "$((NOW + 120))" 3600 "$FRESH_PAYLOAD")"
make_sync_body "$CHAOS_WORK/fresh_push.json" "[\"$FRESH_ID\"]" "[$FRESH]"
code="$(http POST "http://127.0.0.1:$PORT/api/v1/sync" "$CHAOS_WORK/fresh_push.json")"
check "fresh sync (push) accepted after restart -> 200" "200" "$code"
make_sync_body "$CHAOS_WORK/fresh_pull.json" "[]" "[]"
code="$(http POST "http://127.0.0.1:$PORT/api/v1/sync" "$CHAOS_WORK/fresh_pull.json")"
check "fresh sync (pull) answered after restart -> 200" "200" "$code"
FRESH_PULL_SHAS="$(payload_shas_of "$CHAOS_WORK/last_body")"
check "the freshly pushed envelope is served byte-identical" "1" \
    "$(printf '%s\n' "$FRESH_PULL_SHAS" | grep -cx "$FRESH_SHA" >/dev/null 2>&1 && echo 1 || echo 0)"

chaos_summary
