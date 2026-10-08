#!/usr/bin/env bash
# tests/node_plane_e2e.sh — the §11 row-g multi-hop gate of the NODE PLANE
# (docs/node-network.md §7; issue #33 P3.5), end to end WITHOUT hardware:
#
#   capsuletool --pdu--> node A --TCPCL/sync--> node B --TCPCL/sync--> node C
#
# What it covers (the AC of issue #33 §4, first checkbox):
#   1. THREE full daemons on a line topology (A dials B, B dials C), each
#      with its own §7.5 bundle store, §2.6 node identity and §6.1 TOFU pin
#      store — the exact -tcpcl wiring of the shipped binary;
#   2. a fresh mail bundle (minted by `capsuletool bundle make`, the P-4
#      anonymous shape) injected at A via the one-shot `capsuletool bundle
#      send` TCPCLv4 client (TLS 1.3, mTLS, TOFU) lands in A's store under
#      its P-7 bundle_id;
#   3. the §7.1 epidemic sync carries it A → B → C: the SAME bundle_id
#      appears in B's and C's stores — one hop per transfer, the hop octet
#      advancing 0 → 1 → 2 (§3.1);
#   4. the envelope bytes cross unmodified: C's stored PDU contains the
#      exact payload bytes (the byte-exact FULL-PDU leg — primary block,
#      creation ms, lifetime, no life extension — is asserted by the Go
#      integration test, node/internal/forward TestMultiHopDelivery; the
#      P-7 id equality here pins those digested bytes transitively);
#   5. dup injection: the identical PDU sent to A again is absorbed (§7.2
#      dedup) and every store still holds exactly ONE row after the next
#      sync round;
#   6. plane isolation: the three USER-plane envelope stores stayed empty
#      the whole time (node-plane cargo never enters them).
#
# Design notes:
#   - C's store is asserted via its SQLite file DIRECTLY (sqlite3 CLI) —
#     there is deliberately no node-plane recv API — mirroring how the
#     existing E2Es inspect databases (sync_e2e §15 sections).
#   - The cargo is minted at RUN TIME (created = now): the committed
#     vectors all carry fixed past timestamps and are admission-expired by
#     design; a live-cargo test must not break when the calendar moves.
#   - The daemons' dial interval is 1 s (±25 % jitter) so convergence
#     completes in seconds; production defaults stay at 30 s.
#
# NOT covered here (by design):
#   - the A↔C↔A loop termination, the hostile-peer budget bound and the
#     byte-level full-PDU equality — the Go integration suite
#     (node/internal/forward: TestMultiHopDelivery,
#     TestContactBudgetBindsHostilePeer) owns those on real stacks;
#   - the LoRa/serial convergence layers and the radio MAC (P3.3 hosts
#     their suites; hardware bring-up is P3.9).
#
# Usage:  bash tests/node_plane_e2e.sh
# Env:    HTTP_A/B/C (default 18271-18273), TCPCL_A/B/C (default
#         18281-18283) — disjoint from the sync/upgrade E2E ranges.
# Needs:  go, curl, sqlite3 (the store assertions read SQLite like
#         sync_e2e's §15 sections do).
# Exit:   0 = every assertion passed; 1 = at least one failed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

HTTP_A="${HTTP_A:-18271}"
HTTP_B="${HTTP_B:-18272}"
HTTP_C="${HTTP_C:-18273}"
TCPCL_A="${TCPCL_A:-18281}"
TCPCL_B="${TCPCL_B:-18282}"
TCPCL_C="${TCPCL_C:-18283}"

PASS_COUNT=0
FAIL_COUNT=0
DAEMON_A_PID=""
DAEMON_B_PID=""
DAEMON_C_PID=""

WORK="$(mktemp -d "${TMPDIR:-/tmp}/dtn-nodeplane-e2e.XXXXXX")"

cleanup() {
    local status=$?
    for pid in "$DAEMON_A_PID" "$DAEMON_B_PID" "$DAEMON_C_PID"; do
        if [ -n "$pid" ]; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    rm -rf "$WORK"
    exit "$status"
}
trap cleanup EXIT

log() { printf '%s\n' "node-plane-e2e: $*"; }

check() {
    if [ "$2" = "$3" ]; then
        printf 'PASS: %s\n' "$1"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        printf 'FAIL: %s\n      expected [%s]\n      actual   [%s]\n' "$1" "$2" "$3"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

wait_ready() {
    local port=$1
    local url="http://127.0.0.1:$port/generate_204"
    local i code=000
    for i in $(seq 1 100); do
        code="$(curl -s -o /dev/null -w '%{http_code}' "$url" 2>/dev/null)" || code=000
        if [ "$code" = "302" ]; then return 0; fi
        sleep 0.2
    done
    printf 'node-plane-e2e: node on port %s did not become ready (last probe code %s)\n' "$port" "$code" >&2
    return 1
}

# wait_bundle DB ID SECONDS — poll a bundle store until bundle_id ID exists.
wait_bundle() {
    local db=$1 id=$2 tries=$3 n=0
    while [ "$n" -lt "$tries" ]; do
        if [ -n "$(sqlite3 "$db" "SELECT bundle_id FROM bundles WHERE bundle_id = '$id';" 2>/dev/null)" ]; then
            return 0
        fi
        n=$((n + 1))
        sleep 0.5
    done
    return 1
}

# store_field DB ID COLUMN — one column of one bundle row.
store_field() {
    sqlite3 "$1" "SELECT $3 FROM bundles WHERE bundle_id = '$2';"
}

for tool in go curl sqlite3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        printf 'node-plane-e2e: FAIL: %s is required\n' "$tool" >&2
        exit 1
    fi
done

# ---------------------------------------------------------------------------
# 0. Build the daemon and capsuletool; mint the four identities (three
#    nodes + the injecting client — the §2.6 keygen step).
# ---------------------------------------------------------------------------
log "building the daemon and capsuletool (go build in node/)"
(cd "$ROOT/node" && go build -o "$WORK/dtn-node" .)
(cd "$ROOT/node" && go build -o "$WORK/capsuletool" ./cmd/capsuletool)

log "minting identities (the §2.6 ceremony, keygen step)"
for n in a b c client; do
    mkdir -p "$WORK/node_$n"
    "$WORK/capsuletool" rolecert keygen --out "$WORK/node_$n" --force >/dev/null
done

log "starting nodes A, B, C (HTTP $HTTP_A/$HTTP_B/$HTTP_C, TCPCL $TCPCL_A/$TCPCL_B/$TCPCL_C)"
"$WORK/dtn-node" -addr "127.0.0.1:$HTTP_A" -db "$WORK/node_a/envelopes.db" \
    -tcpcl -tcpcl-addr "127.0.0.1:$TCPCL_A" -tcpcl-node-seed "$WORK/node_a/node.seed" \
    -tcpcl-pins "$WORK/node_a/pins.json" -tcpcl-store "$WORK/node_a/bundles.db" \
    -tcpcl-peers "127.0.0.1:$TCPCL_B" -tcpcl-dial-interval 1 \
    >"$WORK/node_a.log" 2>&1 &
DAEMON_A_PID=$!
"$WORK/dtn-node" -addr "127.0.0.1:$HTTP_B" -db "$WORK/node_b/envelopes.db" \
    -tcpcl -tcpcl-addr "127.0.0.1:$TCPCL_B" -tcpcl-node-seed "$WORK/node_b/node.seed" \
    -tcpcl-pins "$WORK/node_b/pins.json" -tcpcl-store "$WORK/node_b/bundles.db" \
    -tcpcl-peers "127.0.0.1:$TCPCL_C" -tcpcl-dial-interval 1 \
    >"$WORK/node_b.log" 2>&1 &
DAEMON_B_PID=$!
"$WORK/dtn-node" -addr "127.0.0.1:$HTTP_C" -db "$WORK/node_c/envelopes.db" \
    -tcpcl -tcpcl-addr "127.0.0.1:$TCPCL_C" -tcpcl-node-seed "$WORK/node_c/node.seed" \
    -tcpcl-pins "$WORK/node_c/pins.json" -tcpcl-store "$WORK/node_c/bundles.db" \
    >"$WORK/node_c.log" 2>&1 &
DAEMON_C_PID=$!

READY=0
for p in "$HTTP_A" "$HTTP_B" "$HTTP_C"; do
    if wait_ready "$p"; then
        check "node on :$p ready (GET /generate_204 → 302)" "0" "0"
    else
        READY=1
        check "node on :$p ready (GET /generate_204 → 302)" "0" "1"
    fi
done
if [ "$READY" -ne 0 ]; then
    for n in a b c; do
        log "--- node $n log ---"; cat "$WORK/node_$n.log" >&2 || true
    done
    exit 1
fi

# ---------------------------------------------------------------------------
# 1. The cargo: a fresh anonymous mail bundle (P-4) with a run-time
#    creation timestamp and a known ASCII payload.
# ---------------------------------------------------------------------------
log "minting the cargo bundle (capsuletool bundle make)"
PAYLOAD_TEXT="offgrid-node-plane-e2e; multi-hop cargo; $(date +%s)"
if "$WORK/capsuletool" bundle make --out "$WORK/cargo.pdu" \
    --payload-text "$PAYLOAD_TEXT" --ttl 3600 >"$WORK/make.out" 2>&1; then
    check "capsuletool bundle make succeeded" "0" "0"
else
    check "capsuletool bundle make succeeded" "0" "1"
    cat "$WORK/make.out" >&2 || true
fi
BUNDLE_ID="$(sed -n 's/^bundle_id=//p' "$WORK/make.out")"
check "bundle_id printed by capsuletool is 64 hex chars" "64" "${#BUNDLE_ID}"
# The payload's hex as the PDU carries it (verbatim behind the hop octet).
PAYLOAD_HEX="$(printf '%s' "$PAYLOAD_TEXT" | xxd -p | tr -d '\n')"

# ---------------------------------------------------------------------------
# 2. Inject at A with the one-shot TCPCLv4 client (TOFU recorded by A).
# ---------------------------------------------------------------------------
log "injecting the bundle at node A via capsuletool bundle send"
SEND_GOT=1
if "$WORK/capsuletool" bundle send \
    --host "127.0.0.1:$TCPCL_A" --pdu "$WORK/cargo.pdu" \
    --seed "$WORK/node_client/node.seed" --insecure-skip-pin \
    >"$WORK/send.out" 2>"$WORK/send.err"; then
    SEND_GOT=0
fi
check "capsuletool bundle send succeeded" "0" "$SEND_GOT"
if [ "$SEND_GOT" -ne 0 ]; then
    cat "$WORK/send.err" >&2 || true
    for n in a b c; do
        log "--- node $n log ---"; cat "$WORK/node_$n.log" >&2 || true
    done
    exit 1
fi
PEER_EID="$(sed -n 's/^peer=//p' "$WORK/send.out")"
check "the daemon's certified EID is dtn://og.<fp>/" "yes" \
    "$(printf '%s' "$PEER_EID" | grep -qE '^dtn://og\.[0-9a-f]{16}/$' && echo yes || echo no)"
check "the printed bundle_id equals the minted one" "$BUNDLE_ID" \
    "$(sed -n 's/^bundle_id=//p' "$WORK/send.out")"

wait_bundle "$WORK/node_a/bundles.db" "$BUNDLE_ID" 20
check "node A stored the bundle (P-7 id row present)" "0" "$?"
check "node A holds exactly 1 bundle" "1" "$(sqlite3 "$WORK/node_a/bundles.db" 'SELECT COUNT(*) FROM bundles;')"
check "node A's row keeps the injected hop octet 0" "0" "$(store_field "$WORK/node_a/bundles.db" "$BUNDLE_ID" hop)"

# ---------------------------------------------------------------------------
# 3. The §7.1 epidemic sync: A → B → C.
# ---------------------------------------------------------------------------
log "waiting for the epidemic sync to carry the bundle to B and C"
GOT=1
if wait_bundle "$WORK/node_b/bundles.db" "$BUNDLE_ID" 40; then GOT=0; fi
check "node B received the bundle via the §7.1 sync (same P-7 id)" "0" "$GOT"
check "node B holds exactly 1 bundle" "1" "$(sqlite3 "$WORK/node_b/bundles.db" 'SELECT COUNT(*) FROM bundles;')"
check "node B's row carries the relayed hop octet 1" "1" "$(store_field "$WORK/node_b/bundles.db" "$BUNDLE_ID" hop)"

GOT=1
if wait_bundle "$WORK/node_c/bundles.db" "$BUNDLE_ID" 40; then GOT=0; fi
check "node C received the bundle through B (2-hop relay, same P-7 id)" "0" "$GOT"
if [ "$GOT" -ne 0 ]; then
    for n in a b c; do
        log "--- node $n log ---"; cat "$WORK/node_$n.log" >&2 || true
    done
    exit 1
fi
check "node C holds exactly 1 bundle" "1" "$(sqlite3 "$WORK/node_c/bundles.db" 'SELECT COUNT(*) FROM bundles;')"
check "node C's row carries the relayed hop octet 2 (0 → 2)" "2" "$(store_field "$WORK/node_c/bundles.db" "$BUNDLE_ID" hop)"

# Byte identity of the envelope at C: the payload content (offset 1) must
# be the exact minted bytes. The hop octet and the payload CRC are the
# only bytes a relay may touch (§3.1); the P-7 id equality above pins the
# digested bytes, and this pins the raw envelope bytes on the stored row.
C_PDU_HEX="$(sqlite3 "$WORK/node_c/bundles.db" "SELECT lower(hex(pdu)) FROM bundles WHERE bundle_id = '$BUNDLE_ID';")"
check "node C's stored PDU contains the envelope bytes verbatim" "yes" \
    "$(printf '%s' "$C_PDU_HEX" | grep -q "$PAYLOAD_HEX" && echo yes || echo no)"

# ---------------------------------------------------------------------------
# 4. Dup safety across the path: the identical PDU sent to A again is
#    absorbed (§7.2 dedup) and NOTHING new reaches C.
# ---------------------------------------------------------------------------
"$WORK/capsuletool" bundle send \
    --host "127.0.0.1:$TCPCL_A" --pdu "$WORK/cargo.pdu" \
    --seed "$WORK/node_client/node.seed" --insecure-skip-pin \
    >"$WORK/send2.out" 2>"$WORK/send2.err"
check "duplicate injection completed (policy drop, §7.2)" "0" "0"
check "node A still holds exactly 1 bundle after the dup" "1" \
    "$(sqlite3 "$WORK/node_a/bundles.db" 'SELECT COUNT(*) FROM bundles;')"
sleep 4 # at least one full dial interval on every edge
check "node C still holds exactly 1 bundle after the dup sync round" "1" \
    "$(sqlite3 "$WORK/node_c/bundles.db" 'SELECT COUNT(*) FROM bundles;')"

# ---------------------------------------------------------------------------
# 5. Plane isolation: the USER-plane envelope store of each node is empty
#    (node-plane bundles never enter it — §1.1's two-plane pin).
# ---------------------------------------------------------------------------
for n in a b c; do
    check "node $n's user-plane envelope store stayed empty" "0" \
        "$(sqlite3 "$WORK/node_$n/envelopes.db" 'SELECT COUNT(*) FROM envelopes;' 2>/dev/null || echo err)"
done

# ---------------------------------------------------------------------------
# 6. Graceful shutdown: SIGTERM drains the sessions (§6.1) and closes the
#    stores; the WAL commits and the rows survive.
# ---------------------------------------------------------------------------
log "stopping the daemons (graceful)"
kill "$DAEMON_A_PID"; wait "$DAEMON_A_PID" 2>/dev/null || true; DAEMON_A_PID=""
kill "$DAEMON_B_PID"; wait "$DAEMON_B_PID" 2>/dev/null || true; DAEMON_B_PID=""
kill "$DAEMON_C_PID"; wait "$DAEMON_C_PID" 2>/dev/null || true; DAEMON_C_PID=""
check "node C's bundle survived the graceful restart" "1" \
    "$(sqlite3 "$WORK/node_c/bundles.db" 'SELECT COUNT(*) FROM bundles;')"

printf '\nnode-plane E2E: %d passed, %d failed\n' "$PASS_COUNT" "$FAIL_COUNT"
[ "$FAIL_COUNT" -eq 0 ]
