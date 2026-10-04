#!/usr/bin/env bash
# tests/chaos/lib.sh — shared helpers of the chaos suite (issue #16 Phase 4,
# Track 4: chaos engineering). Sourced by every tests/chaos/chaos_*.sh script,
# never executed directly.
#
# It deliberately mirrors the conventions of tests/sync_e2e.sh so a chaos run
# reads like any other suite in this repository:
#   - PASS/FAIL counters via check DESC EXPECTED ACTUAL (summary + exit code
#     at the end: 0 = every assertion passed, 1 = at least one failed);
#   - the daemon is built ONCE per script into a temp workdir with a plain
#     `go build` in node/ (the dev-binary path of sync_e2e.sh, not the
#     cross builds of node/build.sh);
#   - readiness is GET /generate_204 answering 302 (§10.2 probe);
#   - every resource is released by the EXIT trap even on failure: daemons
#     killed, extra hooks (volume detach...) run, the workdir removed.
#
# Chaos-specific additions:
#   - SKIP protocol: `skip REASON...` prints a `SKIP: ...` line and bumps the
#     skip counter without failing the run — the platform-unavailable escape
#     hatch (e.g. no loopback image tooling on this host). A script that can
#     only skip prints the SKIP line(s), still ends with the summary and
#     exits 0.
#   - platform detection: CHAOS_OS is "Darwin" or "Linux" (uname -s); chaos
#     scripts must work on BOTH (macOS dev machine AND Linux CI/Pi) and use
#     the SKIP path when the tooling of an injection is unavailable.
#   - chaos_on_cleanup CMD registers an extra cleanup hook (run LIFO inside
#     the EXIT trap before the workdir is removed).
#
# Ports: the chaos suite owns 127.0.0.1:18095-18099 — disjoint from the
# 18091-18094 defaults of tests/sync_e2e.sh so the suites never collide.
# Every script's port is env-overridable (CHAOS_<NAME>_PORT).

# lib.sh is sourced with the caller's shell options; chaos scripts run under
# `set -euo pipefail` themselves.

CHAOS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$CHAOS_DIR/../.." && pwd)"
CHAOS_OS="$(uname -s)"

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

CHAOS_PREFIX="chaos"
CHAOS_WORK=""
DAEMON_PID=""
CHAOS_CLEANUPS=""

# ---------------------------------------------------------------------------
# lifecycle
# ---------------------------------------------------------------------------

# chaos_init PREFIX — start a chaos script: per-script log prefix and a temp
# workdir guarded by the EXIT trap. Must be the first call of every script.
chaos_init() {
    CHAOS_PREFIX="$1"
    CHAOS_WORK="$(mktemp -d "${TMPDIR:-/tmp}/dtn-chaos-$1.XXXXXX")"
    CHAOS_CLEANUPS=""
    DAEMON_PID=""
    trap chaos_cleanup EXIT
}

# chaos_on_cleanup CMD — register one extra cleanup command (LIFO). Used for
# everything the generic trap cannot know: volume detach, loopDevice release.
chaos_on_cleanup() {
    CHAOS_CLEANUPS="$1
$CHAOS_CLEANUPS"
}

chaos_cleanup() {
    local status=$?
    if [ -n "$DAEMON_PID" ]; then
        kill -9 "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
        DAEMON_PID=""
    fi
    if [ -n "$CHAOS_CLEANUPS" ]; then
        printf '%s\n' "$CHAOS_CLEANUPS" | while IFS= read -r cmd; do
            [ -n "$cmd" ] && eval "$cmd" >/dev/null 2>&1 || true
        done
    fi
    rm -rf "$CHAOS_WORK"
    exit "$status"
}

log() { printf '%s\n' "$CHAOS_PREFIX: $*"; }

# check DESC EXPECTED ACTUAL — record one assertion (PASS or FAIL), exactly
# the sync_e2e.sh helper.
check() {
    if [ "$2" = "$3" ]; then
        printf 'PASS: %s\n' "$1"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        printf 'FAIL: %s\n      expected [%s]\n      actual   [%s]\n' "$1" "$2" "$3"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

# skip REASON... — record a platform-unavailable injection. Never fails the
# run; run_all.sh aggregates the SKIP lines into its summary.
skip() {
    printf 'SKIP: %s\n' "$*"
    SKIP_COUNT=$((SKIP_COUNT + 1))
}

# chaos_summary — the suite tail (sync_e2e.sh style). Exit 0 all-pass, 1 on
# any failure; SKIPs are reported but never fail.
chaos_summary() {
    log "summary: $PASS_COUNT passed, $FAIL_COUNT failed, $SKIP_COUNT skipped"
    if [ "$FAIL_COUNT" -gt 0 ]; then
        log "RESULT: FAIL"
        exit 1
    fi
    log "RESULT: PASS"
    exit 0
}

# fatal MSG — a setup failure that makes every downstream assertion
# meaningless (daemon never became ready, build failed). Prints the message
# and exits 1 immediately.
fatal() {
    printf '%s: FAIL: %s\n' "$CHAOS_PREFIX" "$*" >&2
    exit 1
}

# ---------------------------------------------------------------------------
# daemon helpers
# ---------------------------------------------------------------------------

# build_daemon — build the dev binary once into $CHAOS_WORK (plain go build in
# node/, the sync_e2e.sh approach; NOT the cross builds of node/build.sh).
build_daemon() {
    log "building the dev binary (go build in node/)"
    (cd "$ROOT/node" && go build -o "$CHAOS_WORK/dtn-node" .) || return 1
}

# start_daemon PORT DB LOGFILE — launch the daemon in the background; its PID
# lands in DAEMON_PID (the EXIT trap kill -9s any leftover).
start_daemon() {
    "$CHAOS_WORK/dtn-node" -addr "127.0.0.1:$1" -db "$2" >"$3" 2>&1 &
    DAEMON_PID=$!
}

# stop_daemon — SIGTERM the daemon and reap it (graceful drain: closes the
# SQLite handle, checkpointing and removing any -wal/-shm sidecars).
stop_daemon() {
    [ -n "$DAEMON_PID" ] || return 0
    kill "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
    DAEMON_PID=""
}

# kill_daemon — SIGKILL the daemon and reap it (the hard power-cut analog:
# no drain, no checkpoint, sidecars left exactly as the process left them).
kill_daemon() {
    [ -n "$DAEMON_PID" ] || return 0
    kill -9 "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
    DAEMON_PID=""
}

# wait_ready PORT [TRIES] — poll GET /generate_204 until 302 (§10.2), the
# sync_e2e.sh readiness probe; TRIES defaults to 100 x 0.2 s like the e2e.
# Every probe is time-bounded so a wedged daemon fails the poll instead of
# hanging the suite. The answer must come from OUR daemon: when DAEMON_PID is
# set, a 302 only counts while that process is still alive (a stale daemon
# from a previous run leaking the port must never pass as "ready"), and a
# daemon that exits (e.g. the storage.Open refusal branch) fails the poll
# immediately instead of burning the whole budget.
wait_ready() {
    local port=$1 tries=${2:-100}
    local url="http://127.0.0.1:$port/generate_204"
    local i code=000
    for i in $(seq 1 "$tries"); do
        if [ -n "$DAEMON_PID" ] && ! kill -0 "$DAEMON_PID" 2>/dev/null; then
            printf '%s: daemon (pid %s) exited before becoming ready on port %s\n' "$CHAOS_PREFIX" "$DAEMON_PID" "$port" >&2
            return 1
        fi
        code="$(curl -s --max-time 3 --connect-timeout 2 -o /dev/null -w '%{http_code}' "$url" 2>/dev/null)" || code=000
        if [ "$code" = "302" ]; then
            if [ -n "$DAEMON_PID" ] && ! kill -0 "$DAEMON_PID" 2>/dev/null; then
                continue # died between probe and check: keep polling
            fi
            return 0
        fi
        sleep 0.2
    done
    printf '%s: node on port %s did not become ready (last probe code %s)\n' "$CHAOS_PREFIX" "$port" "$code" >&2
    return 1
}

# ---------------------------------------------------------------------------
# HTTP + fixture helpers
# ---------------------------------------------------------------------------

# http METHOD URL [BODY_FILE] — JSON request against the canonical origin
# (Host header override, sync_e2e.sh style). Echoes the HTTP status code;
# the response body lands in $CHAOS_WORK/last_body. Time-bounded so a
# degraded daemon surfaces as a code instead of a hang.
http() {
    local method=$1 url=$2 body=${3:-}
    local args=(-sS --max-time 15 --connect-timeout 3 -o "$CHAOS_WORK/last_body" -w '%{http_code}' -H 'Host: offgrid.local:8080')
    if [ -n "$body" ]; then
        args+=(-H 'Content-Type: application/json' --data-binary @"$body")
    fi
    curl "${args[@]}" -X "$method" "$url"
}

# make_sync_body FILE KNOWN_IDS_JSON ENVELOPES_JSON — build a §10.4 body.
make_sync_body() {
    printf '{"known_ids":%s,"push_envelopes":%s,"limit":50}' "$2" "$3" > "$1"
}

# hex_id N — a deterministic 64-lowercase-hex envelope id (§3.1 shape), on
# its own line. Command substitutions strip the trailing newline, so inline
# uses $(hex_id n) are unaffected; line-oriented uses (id files) need it.
hex_id() { printf '%064x\n' "$1"; }

# payload_b64 [SEED] — a valid §8.2 payload fixture: padded standard Base64
# of exactly 248 decoded bytes (the §8.2 floor), deterministic per seed so
# different envelopes never share payload bytes by accident. The tr strips
# the line wraps GNU base64 inserts (BSD base64 does not wrap) — the payload
# must be one single-line JSON string member on every platform.
payload_b64() {
    local seed=${1:-0}
    { printf '%s' "$seed" | head -c 248; head -c 248 /dev/urandom; } | head -c 248 | base64 | tr -d '\n'
}

# envelope_json ID CREATED_AT TTL PAYLOAD_B64 — a valid v1 §3.1 envelope.
envelope_json() {
    printf '{"v":1,"id":"%s","dest_hint":"9f3ab02c1d77e4c1","created_at":%s,"ttl":%s,"payload":"%s"}' \
        "$1" "$2" "$3" "$4"
}

# sha256_hex STRING / sha256_file PATH — portable sha256 (macOS shasum,
# GNU sha256sum), same helpers as sync_e2e.sh.
sha256_hex() {
    if command -v shasum >/dev/null 2>&1; then
        printf '%s' "$1" | shasum -a 256 | awk '{print $1}'
    else
        printf '%s' "$1" | sha256sum | awk '{print $1}'
    fi
}

sha256_file() {
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        sha256sum "$1" | awk '{print $1}'
    fi
}

# stat_size PATH — file size in bytes, BSD vs GNU stat.
stat_size() {
    if [ "$CHAOS_OS" = "Darwin" ]; then
        stat -f%z "$1"
    else
        stat -c%s "$1"
    fi
}

# quarantine_count DB — how many .corrupt-* quarantine artifacts exist for
# DB right now (the phase-2 storage.Open evidence files, sidecars included).
quarantine_count() {
    local n=0 f
    for f in "$1".corrupt-*; do
        [ -e "$f" ] && n=$((n + 1))
    done
    printf '%s' "$n"
}

# payload_shas_of BODY_FILE — sorted sha256 of every envelope payload in a
# sync response body (base64 payloads cannot contain quotes, so the greedy
# grep is exact; sorted so set comparison is order-free).
payload_shas_of() {
    { grep -o '"payload":"[^"]*"' "$1" 2>/dev/null || true; } \
        | sed -E 's/^"payload":"(.*)"$/\1/' \
        | while IFS= read -r p; do sha256_hex "$p"; done \
        | sort
}

# ids_of BODY_FILE — sorted envelope ids of a sync response body.
ids_of() {
    { grep -o '"id":"[0-9a-f]*"' "$1" 2>/dev/null || true; } | sed -E 's/"id":"(.*)"/\1/' | sort
}

# count_envelopes_of BODY_FILE — number of envelope objects in a sync
# response body (the sync_e2e.sh json_count_envelopes, file-parameterized).
count_envelopes_of() {
    { grep -o '"id":"' "$1" 2>/dev/null || true; } | wc -l | tr -d ' '
}
