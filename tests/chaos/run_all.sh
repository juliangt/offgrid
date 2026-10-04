#!/usr/bin/env bash
# tests/chaos/run_all.sh — run the whole chaos suite in order and aggregate
# the per-script results (issue #16 Phase 4, Track 4).
#
# One script per injection (see FAILURE_MATRIX.md for the failure-mode row
# each one verifies):
#
#   chaos_kill_mid_sync.sh      SIGKILL mid-sync: recover, no quarantine, ACKed data intact
#   chaos_corrupt_db.sh         truncate / garbage header / truncated WAL: quarantine-or-recover contract
#   chaos_full_disk.sh          ENOSPC during write: clean 507-family shed, recover on free (SKIPs without volume tooling)
#   chaos_restart_under_load.sh SIGTERM restarts under concurrent load: clean answer set only, bounded windows
#   chaos_janitor_flood.sh      flooded store + startup janitor: sweep bounded, live mail byte-identical, capacity reclaimed
#   chaos_fuzz_parsers.sh       Go native fuzzing of the envelope/sync parsers (FUZZTIME env, default 20s per target)
#
# Protocol: each child script prints PASS:/FAIL: assertions and may print
# SKIP: lines (platform-unavailable injection). The run FAILS only on child
# exit code 1 — a SKIP never fails the run. Exit 0 when every script passed.
#
# Usage:  bash tests/chaos/run_all.sh
# Env:    everything the children accept (ports, CHAOS_RESTARTS, FUZZTIME...)
# Needs:  go, curl; per-script extras listed in each script header.
# Exit:   0 = all scripts passed; 1 = at least one script failed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SCRIPTS="
chaos_kill_mid_sync.sh
chaos_corrupt_db.sh
chaos_full_disk.sh
chaos_restart_under_load.sh
chaos_janitor_flood.sh
chaos_fuzz_parsers.sh
"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/dtn-chaos-runall.XXXXXX")"
cleanup() {
    local status=$?
    rm -rf "$WORK"
    exit "$status"
}
trap cleanup EXIT

FAILED=0
RESULTS=""
TOTAL_PASS=0
TOTAL_SKIP=0

for s in $SCRIPTS; do
    printf '\n=== %s ===\n' "$s"
    LOG="$WORK/$s.log"
    set +e
    bash "$SCRIPT_DIR/$s" 2>&1 | tee "$LOG"
    ec="${PIPESTATUS[0]}"
    set -e
    p="$(grep -c '^PASS:' "$LOG" 2>/dev/null || true)"
    f="$(grep -c '^FAIL:' "$LOG" 2>/dev/null || true)"
    k="$(grep -c '^SKIP:' "$LOG" 2>/dev/null || true)"
    TOTAL_PASS=$((TOTAL_PASS + p))
    TOTAL_SKIP=$((TOTAL_SKIP + k))
    if [ "$ec" -eq 0 ]; then
        status="PASS"
        if [ "$k" -gt 0 ]; then status="PASS ($k skip(s))"; fi
        if [ "$f" -gt 0 ]; then
            # A script must never print FAIL and exit 0; if it does, that is
            # a broken script, not a pass.
            status="FAIL (exit 0 with $f FAIL lines — broken script)"
            FAILED=1
        fi
    else
        status="FAIL (exit $ec)"
        FAILED=1
    fi
    RESULTS="$RESULTS
  $s: $status [$p pass, $f fail, $k skip]"
done

printf '\n=== chaos suite summary ===\n%s\n' "$RESULTS"
printf 'total: %s assertion(s) passed, %s skip(s)\n' "$TOTAL_PASS" "$TOTAL_SKIP"
if [ "$FAILED" -ne 0 ]; then
    printf 'chaos: RESULT: FAIL\n'
    exit 1
fi
printf 'chaos: RESULT: PASS\n'
