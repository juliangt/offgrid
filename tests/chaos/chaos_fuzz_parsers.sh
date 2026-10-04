#!/usr/bin/env bash
# tests/chaos/chaos_fuzz_parsers.sh — malformed-envelope flood as Go native
# fuzzing (issue #16 Phase 4, Track 4; the "malformed envelope flood / parser
# fuzzing" row of FAILURE_MATRIX.md).
#
# Injection: the fuzz targets live IN the Go packages (committed, so plain
# `go test` always exercises their seed corpora):
#
#   node/internal/envelope.FuzzParseEnvelope — arbitrary bytes through the
#       §10.5/§15.3 parse+validate path (json.Unmarshal + Envelope.Validate);
#   node/internal/api.FuzzSyncHandler — arbitrary bytes as a POST /api/v1/sync
#       body through the FULL handler stack (decode, §8.1 shape checks,
#       validation, storage).
#
# Expected behavior: untrusted bytes can only produce a validation ERROR or a
# clean answer — never a panic, and from the sync endpoint never a 5xx (the
# only legal statuses are 200/400/413). A fuzz failure is a REAL daemon bug:
# the script fails loudly (and the crashing input lands in the package's
# testdata/fuzz/ corpus — a stop-and-report finding, per the phase rules).
#
# CI-able by design: go test (seed corpora) runs first and must be green;
# each target is then fuzzed for FUZZTIME (default 20s, env-overridable) so
# a full chaos run stays in the minute range. Set FUZZTIME=0 to skip the
# fuzzing phase entirely (seed corpora only) — reported as skips.
#
# Usage:  bash tests/chaos/chaos_fuzz_parsers.sh
# Env:    FUZZTIME (default 20s; a Go duration: 10s, 1m, 0 to disable)
# Needs:  go only. No daemon, no ports, no root.
# Exit:   0 = seeds green and fuzzing found nothing; 1 = a target failed.

set -euo pipefail

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

FUZZTIME="${FUZZTIME:-20s}"

chaos_init chaos-fuzz

# ---------------------------------------------------------------------------
# 0. Seed corpora first: plain go test over every package (the fuzz targets
#    run their f.Add seeds as ordinary tests — this is the fast gate that
#    also guards `make test`).
# ---------------------------------------------------------------------------
log "go test ./... (seed corpora) in node/"
if (cd "$ROOT/node" && go test ./... -count=1); then
    check "go test seed corpora green (envelope + api fuzz seeds)" "ok" "ok"
else
    check "go test seed corpora green (envelope + api fuzz seeds)" "ok" "fail"
    chaos_summary
fi

# ---------------------------------------------------------------------------
# 1. Real fuzzing, one target per -fuzz invocation (Go requires exactly one
#    matching target). A nonzero exit means the fuzzer FOUND something —
#    the crashing input is written under node/internal/<pkg>/testdata/fuzz/.
# ---------------------------------------------------------------------------
fuzz_one() {
    local pkg=$1 target=$2
    if [ "$FUZZTIME" = "0" ]; then
        skip "fuzzing disabled (FUZZTIME=0): $target"
        return 0
    fi
    log "fuzzing $target for $FUZZTIME"
    if (cd "$ROOT/node" && go test "./internal/$pkg" -run '^$' -fuzz "^${target}$" -fuzztime "$FUZZTIME"); then
        check "fuzz $target: no crash within $FUZZTIME" "clean" "clean"
    else
        check "fuzz $target: no crash within $FUZZTIME" "clean" "CRASH FOUND (see node/internal/$pkg/testdata/fuzz/ — stop and report the bug)"
    fi
}

fuzz_one envelope FuzzParseEnvelope
fuzz_one api FuzzSyncHandler

chaos_summary
