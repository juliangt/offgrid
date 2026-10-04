#!/usr/bin/env bash
# tests/chaos/chaos_corrupt_db.sh — corrupt the SQLite database on purpose,
# three ways, and pin the phase-2 storage.Open recovery contract end to end
# (issue #16 Phase 4, Track 4; the SQLite rows of FAILURE_MATRIX.md).
#
# Injection (one daemon run per kind, each on its own database):
#   truncate — the db file is cut to 30% of its size (power loss / flash wear
#              mid-write) → SQLite corruption (SQLITE_CORRUPT);
#   garbage  — the db header is overwritten with junk bytes
#              → SQLite corruption (SQLITE_NOTADB);
#   wal      — committed-but-uncheckpointed envelopes (daemon SIGKILLed so
#              the -wal sidecar survives) are damaged by truncating the -wal
#              sidecar to 30% mid-frame → the healthy MAIN db must recover
#              cleanly (SQLite replays the valid WAL prefix), never quarantine.
#
# Expected behavior (the storage.Open contract of node/internal/storage):
#   corruption kinds  → the daemon QUARANTINES the file as <db>.corrupt-<ts>
#                       (sidecars included, operator-recoverable evidence),
#                       starts on a fresh rebuilt database and serves;
#                       NEVER a half-broken serve, and the only alternative
#                       legal outcome is a loud non-zero exit WITHOUT side
#                       effects (refusal branch of the contract);
#   wal kind          → the healthy main database is NEVER quarantined; the
#                       checkpointed (ACKed) envelopes survive byte-identical;
#                       the uncheckpointed WAL tail is explicitly accepted
#                       loss (may or may not have survived the truncation —
#                       only the checkpointed set is asserted).
#
# Recovery path: after each corruption kind, the (re)started daemon accepts
# pushes again (a fresh sync round-trips end to end).
#
# Usage:  bash tests/chaos/chaos_corrupt_db.sh
# Env:    CHAOS_CORRUPT_PORT (default 18096; chaos suite owns 18095-18099)
# Needs:  go (daemon build), curl, sqlite3 CLI, truncate, dd. No root.
# Exit:   0 = every assertion passed; 1 = at least one failed.

set -euo pipefail

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

PORT="${CHAOS_CORRUPT_PORT:-18096}"

chaos_init chaos-corrupt

command -v sqlite3 >/dev/null 2>&1 || { skip "sqlite3 CLI not available"; chaos_summary; }
command -v truncate >/dev/null 2>&1 || { skip "truncate not available"; chaos_summary; }

build_daemon || fatal "daemon build failed"

# seed_store DIR — run one daemon against a FRESH database in DIR, push two
# live envelopes through the real path, stop it gracefully (WAL checkpointed
# into the main file, sidecars gone). Sets SEEDED_SHAS to "sha1 sha2", the
# payload fingerprints of the two ACKed envelopes.
# NOTE: this (and every other function that starts a daemon) MUST be called
# in the parent shell, never inside $( ... ) — a command substitution runs
# in a subshell, and a daemon started there is orphaned with its PID lost to
# the caller (the stop/kill bookkeeping would silently miss it).
SEEDED_SHAS=""
seed_store() {
    local dir=$1 db="$1/node.db" log="$1/seed.log"
    local now p1 p2
    mkdir -p "$dir"
    now="$(date +%s)"
    p1="$(payload_b64 "$dir-1")"
    p2="$(payload_b64 "$dir-2")"
    start_daemon "$PORT" "$db" "$log"
    wait_ready "$PORT" || { cat "$log" >&2; fatal "seed daemon never became ready"; }
    local e1 e2
    e1="$(envelope_json "$(hex_id 1)" "$now" 3600 "$p1")"
    e2="$(envelope_json "$(hex_id 2)" "$now" 3600 "$p2")"
    make_sync_body "$dir/seed.json" "[\"$(hex_id 1)\",\"$(hex_id 2)\"]" "[$e1,$e2]"
    local code
    code="$(http POST "http://127.0.0.1:$PORT/api/v1/sync" "$dir/seed.json")"
    [ "$code" = "200" ] || fatal "seed push failed with HTTP $code"
    stop_daemon
    SEEDED_SHAS="$(printf '%s %s' "$(sha256_hex "$p1")" "$(sha256_hex "$p2")")"
}

# start_and_classify DB LOG — start the daemon over a damaged database and
# classify the outcome into OUTCOME: "ready" (recovered + serving) or
# "exited-nonzero". Anything else (a wedged daemon: neither ready nor
# exited) is fatal. Runs in the parent shell (see the seed_store note).
OUTCOME=""
start_and_classify() {
    local db=$1 log=$2
    OUTCOME=""
    start_daemon "$PORT" "$db" "$log"
    if wait_ready "$PORT" 50; then
        OUTCOME="ready"
        return 0
    fi
    if kill -0 "$DAEMON_PID" 2>/dev/null; then
        cat "$log" >&2
        fatal "daemon over a damaged database is neither ready nor exited (hang)"
    fi
    wait "$DAEMON_PID" 2>/dev/null || true
    DAEMON_PID=""
    OUTCOME="exited-nonzero"
}

# ---------------------------------------------------------------------------
# Kind 1: truncated db file (SQLITE_CORRUPT — the classic power-loss scar).
# ---------------------------------------------------------------------------
log "kind 1/3: truncate the database file to 30%"
KDIR="$CHAOS_WORK/truncate"; mkdir -p "$KDIR"
DB="$KDIR/node.db"
seed_store "$KDIR"
SIZE="$(stat_size "$DB")"
truncate -s $((SIZE * 3 / 10)) "$DB"
start_and_classify "$DB" "$KDIR/recover.log"

# Contract: corruption is quarantined-and-rebuilt ("ready"); the refusal
# branch ("exited-nonzero" without side effects) is legal per the contract
# but NOT what the phase-2 tests pin for SQLITE_CORRUPT — flag it as a
# failure so a silent contract change cannot slip through.
check "truncated db: daemon recovers (quarantine + rebuild), never a half-broken serve" \
    "ready" "$OUTCOME"
check "truncated db: .corrupt-* quarantine evidence kept on disk" \
    "yes" "$([ "$(quarantine_count "$DB")" -ge 1 ] && echo yes || echo no)"
check "truncated db: quarantine log names the accepted loss and the evidence files" \
    "yes" "$(grep -q 'quarantined' "$KDIR/recover.log" && grep -q 'LOST' "$KDIR/recover.log" && echo yes || echo no)"
if [ "$OUTCOME" = "ready" ]; then
    make_sync_body "$KDIR/pull.json" "[]" "[]"
    code="$(http POST "http://127.0.0.1:$PORT/api/v1/sync" "$KDIR/pull.json")"
    check "truncated db: rebuilt store serves (empty is the accepted loss) -> 200" "200" "$code"
    # Recovery path: the rebuilt database accepts pushes again.
    e1="$(envelope_json "$(hex_id 77)" "$(date +%s)" 3600 "$(payload_b64 post-truncate)")"
    make_sync_body "$KDIR/push.json" "[\"$(hex_id 77)\"]" "[$e1]"
    code="$(http POST "http://127.0.0.1:$PORT/api/v1/sync" "$KDIR/push.json")"
    check "truncated db: rebuilt store accepts pushes again -> 200" "200" "$code"
fi
stop_daemon

# ---------------------------------------------------------------------------
# Kind 2: garbage header (SQLITE_NOTADB — bit rot / partial overwrite).
# ---------------------------------------------------------------------------
log "kind 2/3: overwrite the database header with garbage"
KDIR="$CHAOS_WORK/garbage"; mkdir -p "$KDIR"
DB="$KDIR/node.db"
seed_store "$KDIR"
printf 'DTN-CHAOS: this is not a database, it is 32 bytes of junk' | \
    dd of="$DB" bs=32 count=1 conv=notrunc 2>/dev/null
start_and_classify "$DB" "$KDIR/recover.log"
check "garbage header: daemon recovers (quarantine + rebuild), never a half-broken serve" \
    "ready" "$OUTCOME"
check "garbage header: .corrupt-* quarantine evidence kept on disk" \
    "yes" "$([ "$(quarantine_count "$DB")" -ge 1 ] && echo yes || echo no)"
check "garbage header: quarantine log names the accepted loss and the evidence files" \
    "yes" "$(grep -q 'quarantined' "$KDIR/recover.log" && grep -q 'LOST' "$KDIR/recover.log" && echo yes || echo no)"
if [ "$OUTCOME" = "ready" ]; then
    e1="$(envelope_json "$(hex_id 78)" "$(date +%s)" 3600 "$(payload_b64 post-garbage)")"
    make_sync_body "$KDIR/push.json" "[\"$(hex_id 78)\"]" "[$e1]"
    code="$(http POST "http://127.0.0.1:$PORT/api/v1/sync" "$KDIR/push.json")"
    check "garbage header: rebuilt store accepts pushes again -> 200" "200" "$code"
fi
stop_daemon

# ---------------------------------------------------------------------------
# Kind 3: truncated -wal sidecar with committed-but-uncheckpointed frames
# (SIGKILL mid-write, then the WAL is damaged). The MAIN database is healthy
# — the recovery MUST be clean: no quarantine, checkpointed data intact.
# ---------------------------------------------------------------------------
log "kind 3/3: SIGKILL mid-write, then truncate the -wal sidecar to 30%"
KDIR="$CHAOS_WORK/wal"; mkdir -p "$KDIR"
DB="$KDIR/node.db"
seed_store "$KDIR"
# Re-open and push two more envelopes, then SIGKILL: those two exist only in
# the -wal sidecar (no graceful checkpoint).
start_daemon "$PORT" "$DB" "$KDIR/walwrite.log"
wait_ready "$PORT" || { cat "$KDIR/walwrite.log" >&2; fatal "wal-write daemon never became ready"; }
WAL_ONLY_P1="$(payload_b64 walonly-1)"
e1="$(envelope_json "$(hex_id 3)" "$(date +%s)" 3600 "$WAL_ONLY_P1")"
e2="$(envelope_json "$(hex_id 4)" "$(date +%s)" 3600 "$(payload_b64 walonly-2)")"
make_sync_body "$KDIR/walpush.json" "[\"$(hex_id 3)\",\"$(hex_id 4)\"]" "[$e1,$e2]"
code="$(http POST "http://127.0.0.1:$PORT/api/v1/sync" "$KDIR/walpush.json")"
[ "$code" = "200" ] || fatal "wal-only push failed with HTTP $code"
kill_daemon
[ -s "$DB-wal" ] || fatal "expected a non-empty -wal sidecar after SIGKILL (test setup broken)"
truncate -s $(( $(stat_size "$DB-wal") * 3 / 10 )) "$DB-wal"

start_and_classify "$DB" "$KDIR/recover.log"
check "truncated wal: daemon recovers, never a half-broken serve" "ready" "$OUTCOME"
check "truncated wal: the HEALTHY main database is never quarantined" \
    "0" "$(quarantine_count "$DB")"
check "truncated wal: no quarantine line in the recovery log (clean recovery)" \
    "yes" "$(grep -q 'quarantined' "$KDIR/recover.log" && echo no || echo yes)"
if [ "$OUTCOME" = "ready" ]; then
    make_sync_body "$KDIR/pull.json" "[]" "[]"
    code="$(http POST "http://127.0.0.1:$PORT/api/v1/sync" "$KDIR/pull.json")"
    check "truncated wal: pull -> 200" "200" "$code"
    PULLED_SHAS="$(payload_shas_of "$CHAOS_WORK/last_body")"
    check "truncated wal: checkpointed (ACKed) envelopes survive byte-identical (0 missing)" \
        "0" \
        "$(printf '%s' "$SEEDED_SHAS" | tr ' ' '\n' | while IFS= read -r s; do printf '%s\n' "$PULLED_SHAS" | grep -qx "$s" || echo "$s"; done | grep -c . || true)"
    # The uncheckpointed tail is accepted loss — report what survived, assert nothing.
    log "note: of the 2 uncheckpointed (accepted-loss) envelopes, $(( $(printf '%s\n' "$PULLED_SHAS" | grep -c . || true) - 2 )) survived the WAL truncation"
    # Recovery path: pushes work again.
    e1="$(envelope_json "$(hex_id 79)" "$(date +%s)" 3600 "$(payload_b64 post-wal)")"
    make_sync_body "$KDIR/push.json" "[\"$(hex_id 79)\"]" "[$e1]"
    code="$(http POST "http://127.0.0.1:$PORT/api/v1/sync" "$KDIR/push.json")"
    check "truncated wal: store accepts pushes again -> 200" "200" "$code"
fi
stop_daemon

chaos_summary
