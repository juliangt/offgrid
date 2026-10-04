#!/usr/bin/env bash
# tests/chaos/chaos_janitor_flood.sh — flood the store to its §8.1 cap with a
# mix of expired-TTL and live envelopes, then restart the daemon so the
# startup sweep of §10.6 runs (issue #16 Phase 4, Track 4; the "flooded store
# + startup janitor" row of FAILURE_MATRIX.md).
#
# Injection: 5000 rows (the storage.maxEnvelopes cap) are crafted DIRECTLY
# into a schema-2 database with the sqlite3 CLI — 4500 long-expired + 500
# live — because the per-IP envelope budget (issue #16 Phase 2) exists
# precisely to make an HTTP-only flood impossible; the whole point here is
# the store AT its cap. The daemon then starts against the full store WHILE a
# background writer hammers pushes at it.
#
# Expected behavior (degrade + auto-recover):
#   - the startup sweep completes within a bounded time DESPITE the concurrent
#     write pressure (the issue's specific worry: TTL eviction is not starved
#     by writes — the sweep log line and the purged rows prove it);
#   - expired envelopes are purged, live envelopes are kept BYTE-IDENTICAL
#     (id set + payload sha match);
#   - capacity is reclaimed: fresh pushes are accepted again, and the push
#     batch that lands is served back;
#   - at the cap BEFORE the sweep, pushes are refused with 429 node_full (the
#     "reject newest, keep oldest" guard) — timing-dependent here because the
#     sweep may beat the first writer request to it, so it is REPORTED, not
#     asserted (the property itself is pinned by the Go flood tests).
#
# Data expectation: expired envelopes are explicitly accepted loss (their TTL
# ran out; the janitor's whole job); live (unexpired, ACKed) envelopes are
# NEVER touched by the janitor — the byte-identity check is the regression
# fence for "the janitor must not eat live mail".
#
# Usage:  bash tests/chaos/chaos_janitor_flood.sh
# Env:    CHAOS_JANITOR_PORT (default 18099), CHAOS_FLOOD_ROWS (default 5000)
# Needs:  go (daemon build), curl, sqlite3 CLI. No root.
# Exit:   0 = every assertion passed; 1 = at least one failed.

set -euo pipefail

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

PORT="${CHAOS_JANITOR_PORT:-18099}"
TOTAL="${CHAOS_FLOOD_ROWS:-5000}"
# LIVE is capped at 500 deliberately: the §8.1 API caps known_ids at 500 per
# request, so the byte-identity phase enumerates the live set by cumulative
# exclusion (limit 200/pull, known_ids = everything seen so far) — enumerable
# without hitting that cap only up to 600 rows. The cap pressure of the row
# comes from the EXPIRED mass (4500 at the default), which is what the sweep
# has to chew through anyway.
LIVE=$((TOTAL / 10))

chaos_init chaos-janitor

command -v sqlite3 >/dev/null 2>&1 || { skip "sqlite3 CLI not available"; chaos_summary; }

build_daemon || fatal "daemon build failed"
DB="$CHAOS_WORK/flood.db"
LOG="$CHAOS_WORK/node.log"

# ---------------------------------------------------------------------------
# 1. Craft the flooded store offline: the exact §9/§15.3 schema-2 shape
#    (envelopes.v present, user_version = 2 — the marker is authoritative),
#    TOTAL rows: LIVE long-lived + the rest long-expired. Payloads all share
#    one valid §8.2 fixture so byte-identity is one sha comparison.
# ---------------------------------------------------------------------------
NOW="$(date +%s)"
PAYLOAD="$(payload_b64 janitor)"
LIVE_SHA="$(sha256_hex "$PAYLOAD")"
log "crafting the flooded store: $TOTAL rows ($LIVE live, $((TOTAL - LIVE)) expired)"
{
    printf 'PRAGMA journal_mode = WAL;\n'
    cat <<'SCHEMA'
CREATE TABLE envelopes (
  id         TEXT PRIMARY KEY,
  dest_hint  TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  ttl        INTEGER NOT NULL,
  payload    TEXT NOT NULL,
  v          INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX idx_envelopes_dest_hint ON envelopes(dest_hint);
CREATE INDEX idx_envelopes_expiry    ON envelopes(created_at, ttl);
CREATE TABLE directory (
  pubkey    TEXT PRIMARY KEY,
  x25519    TEXT NOT NULL,
  alias     TEXT NOT NULL,
  last_seen INTEGER NOT NULL
);
SCHEMA
    printf 'BEGIN;\n'
    i=1
    while [ "$i" -le "$TOTAL" ]; do
        if [ "$i" -le "$LIVE" ]; then
            # live: born now, max TTL (§8.1: 30 days) — the janitor must NOT touch these
            printf "INSERT INTO envelopes (id, dest_hint, created_at, ttl, payload, v) VALUES ('%s', '9f3ab02c1d77e4c1', %s, 2592000, '%s', 1);\n" \
                "$(hex_id "$i")" "$NOW" "$PAYLOAD"
        else
            # expired: born 60 days ago, 1 h TTL — the janitor's job
            printf "INSERT INTO envelopes (id, dest_hint, created_at, ttl, payload, v) VALUES ('%s', '9f3ab02c1d77e4c1', %s, 3600, '%s', 1);\n" \
                "$(hex_id "$i")" "$((NOW - 5184000))" "$PAYLOAD"
        fi
        i=$((i + 1))
    done
    printf 'COMMIT;\nPRAGMA user_version = 2;\n'
} > "$CHAOS_WORK/flood.sql"

sqlite3 "$DB" < "$CHAOS_WORK/flood.sql" >/dev/null
check "fixture: store holds exactly $TOTAL rows at the cap" "$TOTAL" \
    "$(sqlite3 "$DB" 'SELECT COUNT(*) FROM envelopes;')"
check "fixture: schema-2 marker (user_version = 2, the daemon must trust it)" "2" \
    "$(sqlite3 "$DB" 'PRAGMA user_version;')"
seq 1 "$LIVE" | while IFS= read -r n; do hex_id "$n"; done > "$CHAOS_WORK/live_ids.expected"

# ---------------------------------------------------------------------------
# 2. The background writer: starts BEFORE the daemon (retrying through the
#    connection-refused window) and hammers small expired-TTL push batches
#    while the startup sweep runs. Tiny batches (6 requests x 5 envelopes)
#    stay far under the per-IP budgets so every downstream verification
#    request is budget-clean. Expired pushes are accepted on the wire and
#    never served — real write pressure with zero live-set pollution.
# ---------------------------------------------------------------------------
STOP="$CHAOS_WORK/stop"
WRITER_LOG="$CHAOS_WORK/writer.log"
writer() {
    local n=0 code ec id batch
    local base=900000
    while [ "$n" -lt 30 ]; do
        if [ -e "$STOP" ]; then break; fi
        batch=""
        for j in 1 2 3 4 5; do
            n=$((n + 1))
            id="$(hex_id $((base + n)))"
            batch="$batch$(envelope_json "$id" "$((NOW - 5184000))" 3600 "$PAYLOAD"),"
        done
        printf '{"known_ids":[],"push_envelopes":[%s],"limit":1}' "${batch%,}" > "$CHAOS_WORK/writer_body.json"
        ec=0
        code="$(curl -s --max-time 8 --connect-timeout 1 -o /dev/null -w '%{http_code}' \
            -H 'Host: offgrid.local:8080' -H 'Content-Type: application/json' \
            --data-binary @"$CHAOS_WORK/writer_body.json" \
            -X POST "http://127.0.0.1:$PORT/api/v1/sync" 2>/dev/null)" || ec=$?
        if [ "$ec" -eq 0 ]; then
            printf '%s\n' "$code"
        else
            printf 'refused\n'   # the connection-refused window before the daemon binds
        fi
        sleep 0.1
    done
}
writer >> "$WRITER_LOG" &
WRITER_PID=$!

# ---------------------------------------------------------------------------
# 3. Start the daemon against the flooded store and time the startup sweep
#    under the live write pressure (bounded: 30 s).
# ---------------------------------------------------------------------------
T0="$(date +%s)"
start_daemon "$PORT" "$DB" "$LOG"
wait_ready "$PORT" 75 || { touch "$STOP"; wait "$WRITER_PID" 2>/dev/null || true; cat "$LOG" >&2; fatal "daemon never became ready over the flooded store"; }

SWEEP_BOUND=30
SWEEP_OK=0
elapsed=0
while [ "$elapsed" -le "$SWEEP_BOUND" ]; do
    if grep -Eq '\[cleanup\] deleted [0-9]+ expired envelopes' "$LOG" 2>/dev/null; then
        SWEEP_OK=1
        break
    fi
    sleep 0.2
    elapsed=$(( $(date +%s) - T0 ))
done
check "startup sweep completed within the bounded time despite write pressure (<= ${SWEEP_BOUND} s)" \
    "1" "$SWEEP_OK"
DELETED="$(sed -n 's/.*\[cleanup\] deleted \([0-9]*\) expired envelopes.*/\1/p' "$LOG" | head -1)"
check "startup sweep purged the seeded expired backlog (deleted >= $((TOTAL - LIVE)))" \
    "yes" "$([ "${DELETED:-0}" -ge "$((TOTAL - LIVE))" ] && echo yes || echo "no (deleted=${DELETED:-0})")"
log "startup sweep deleted $DELETED expired envelopes"

touch "$STOP"
wait "$WRITER_PID" 2>/dev/null || true
log "writer outcomes (cap refusals are timing-dependent: 429 node_full until the sweep wins the race, 200 after): $(sort "$WRITER_LOG" | uniq -c | tr '\n' ' ')"

# ---------------------------------------------------------------------------
# 4. Byte-identity of the live set: enumerate the store by cumulative
#    exclusion (limit 200/pull, known_ids = every id seen so far — the
#    flood_test.go storedCount pattern, kept under the §8.1 500-known_ids
#    cap by LIVE <= 500). The writer's landed rows are expired and therefore
#    NEVER served, so the served set must be exactly the seeded live set.
# ---------------------------------------------------------------------------
PAGES=0
PULL_FAILS=0
: > "$CHAOS_WORK/live_ids.actual"
: > "$CHAOS_WORK/live_shas.actual"
while [ "$PAGES" -lt 10 ]; do
    KNOWN="[$(sed 's/.*/"&"/' "$CHAOS_WORK/live_ids.actual" | sort | paste -sd, -)]"
    printf '{"known_ids":%s,"push_envelopes":[],"limit":200}' "$KNOWN" > "$CHAOS_WORK/page.json"
    code="$(http POST "http://127.0.0.1:$PORT/api/v1/sync" "$CHAOS_WORK/page.json")" || code=000
    if [ "$code" != "200" ]; then PULL_FAILS=$((PULL_FAILS + 1)); break; fi
    N="$(count_envelopes_of "$CHAOS_WORK/last_body")"
    if [ "$N" -eq 0 ]; then break; fi
    PAGES=$((PAGES + 1))
    ids_of "$CHAOS_WORK/last_body" >> "$CHAOS_WORK/live_ids.actual"
    payload_shas_of "$CHAOS_WORK/last_body" >> "$CHAOS_WORK/live_shas.actual"
done
check "paging through the flooded-and-swept store: every pull -> 200" "0" "$PULL_FAILS"
sort -u "$CHAOS_WORK/live_ids.actual" -o "$CHAOS_WORK/live_ids.actual"
ID_DIFF="$(diff "$CHAOS_WORK/live_ids.expected" "$CHAOS_WORK/live_ids.actual" | grep -c '^[<>]' || true)"
check "live envelopes kept byte-identical: the served id set is exactly the seeded live set" \
    "0" "$ID_DIFF"
if [ "$ID_DIFF" != "0" ]; then
    log "id-set diff (first 5): $(diff "$CHAOS_WORK/live_ids.expected" "$CHAOS_WORK/live_ids.actual" | grep '^[<>]' | head -5 | tr '\n' ' ')"
fi
check "live envelopes kept byte-identical: every served payload sha matches the fixture" \
    "0" "$(grep -vc "^$LIVE_SHA$" "$CHAOS_WORK/live_shas.actual" 2>/dev/null || true)"

# ---------------------------------------------------------------------------
# 5. Capacity reclaimed: a fresh live push is accepted (200) and served back.
# ---------------------------------------------------------------------------
FRESH_ID="$(hex_id 999999)"
FRESH="$(envelope_json "$FRESH_ID" "$(date +%s)" 3600 "$(payload_b64 fresh)")"
make_sync_body "$CHAOS_WORK/fresh.json" "[\"$FRESH_ID\"]" "[$FRESH]"
code="$(http POST "http://127.0.0.1:$PORT/api/v1/sync" "$CHAOS_WORK/fresh.json")"
check "capacity reclaimed: fresh push accepted after the sweep -> 200" "200" "$code"
make_sync_body "$CHAOS_WORK/verify.json" "[]" "[]"
code="$(http POST "http://127.0.0.1:$PORT/api/v1/sync" "$CHAOS_WORK/verify.json")"
check "post-sweep pull -> 200" "200" "$code"
check "the fresh envelope is served" \
    "1" "$(ids_of "$CHAOS_WORK/last_body" | grep -cx "$FRESH_ID" >/dev/null 2>&1 && echo 1 || echo 0)"

stop_daemon
chaos_summary
