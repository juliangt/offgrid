#!/usr/bin/env bash
# tests/sync_e2e.sh — full E2E integration test WITHOUT hardware (plan 4.3).
#
# Simulates the complete mule journey of docs/protocolo.md §2 against two
# real daemon instances, using curl only:
#
#   Alice --push--> node A --pull--> MULE --push--> node B --pull--> Bob
#
# What it covers:
#   1. two daemons on distinct loopback ports (env-tunable) with separate
#      temp databases; readiness = GET /generate_204 answering 302;
#   2. directory registration of Alice and Bob on BOTH nodes + GET listing;
#   3. Alice pushes the §3.2 spec envelope to node A; the mule pulls it and
#      records the sha256 of its payload;
#   4. the mule carries it to node B; Bob pulls the IDENTICAL payload bytes
#      (E2E byte integrity through a mule, §10.4 sync protocol for real);
#   5. INSERT OR IGNORE dedup: re-pushing never duplicates (§10.4 step 2);
#   6. expired TTL: an expired envelope is accepted on push but NEVER served
#      (TTL-filtered from the pull select, §10.4 step 3);
#   7. known_ids exclusion on node B; >1 MiB body -> 413; malformed envelope
#      id -> 400;
#   8. canonical-host 301 for raw-IP requests vs the captive-probe 302
#      exemption (§10.2).
#
# Determinism: the §3.2 example envelope is parsed VERBATIM out of
# docs/protocolo.md at runtime (so the test vector cannot drift from the
# spec; the expected id is asserted, so parser drift fails loudly). Its
# created_at (1759500000) is fixed in the past, therefore:
#   - the positive path re-dates ONLY created_at to "now" (id, dest_hint and
#     payload stay byte-verbatim); the server MUST NOT recompute or reject
#     the id (§6.2), which this simultaneously exercises;
#   - the verbatim envelope itself is the expired-TTL fixture (accepted on
#     push, TTL-filtered from pull). This requires a wall clock after
#     2025-10-10 (created_at + ttl); the script aborts with a clear message
#     if the spec example is ever re-dated and stops being expired.
#
# NOT covered here (by design):
#   - real radio/AP/captive-portal hardware and the physical two-node walk
#     (plan 4.1/4.2 — manual hardware checklist);
#   - browser/IndexedDB/mule-UI behavior (manual; the crypto engine is
#     covered headless by tests/crypto_roundtrip.mjs);
#   - the 15-minute cleaner wall-clock behavior (covered by the TTL
#     boundary + DeleteExpired unit tests in node/internal/storage).
#
# Usage:  bash tests/sync_e2e.sh
# Env:    PORT_A (default 18091), PORT_B (default 18092)
# Exit:   0 = every assertion passed; 1 = at least one failed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SPEC="$ROOT/docs/protocolo.md"

PORT_A="${PORT_A:-18091}"
PORT_B="${PORT_B:-18092}"

PASS_COUNT=0
FAIL_COUNT=0
DAEMON_A_PID=""
DAEMON_B_PID=""

WORK="$(mktemp -d "${TMPDIR:-/tmp}/dtn-e2e.XXXXXX")"

cleanup() {
    local status=$?
    if [ -n "$DAEMON_A_PID" ]; then
        kill "$DAEMON_A_PID" 2>/dev/null || true
        wait "$DAEMON_A_PID" 2>/dev/null || true
    fi
    if [ -n "$DAEMON_B_PID" ]; then
        kill "$DAEMON_B_PID" 2>/dev/null || true
        wait "$DAEMON_B_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK"
    exit "$status"
}
trap cleanup EXIT

log() { printf '%s\n' "e2e: $*"; }

# check DESC EXPECTED ACTUAL — record one assertion (PASS or FAIL).
check() {
    if [ "$2" = "$3" ]; then
        printf 'PASS: %s\n' "$1"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        printf 'FAIL: %s\n      expected [%s]\n      actual   [%s]\n' "$1" "$2" "$3"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

# wait_ready PORT — poll GET /generate_204 until it answers 302 (§10.2).
# The probe is sent with the default Host (127.0.0.1:PORT): the endpoint must
# answer 302 regardless of Host, so this validates the exemption end to end.
wait_ready() {
    local port=$1
    local url="http://127.0.0.1:$port/generate_204"
    local i code=000
    for i in $(seq 1 100); do
        code="$(curl -s -o /dev/null -w '%{http_code}' "$url" 2>/dev/null)" || code=000
        if [ "$code" = "302" ]; then return 0; fi
        sleep 0.2
    done
    printf 'e2e: node on port %s did not become ready (last probe code %s)\n' "$port" "$code" >&2
    return 1
}

# http METHOD URL [BODY_FILE] — perform a JSON request against the canonical
# origin (Host header override: every non-probe endpoint sits behind the
# canonical-host middleware) and echo the HTTP status code. The response body
# lands in $WORK/last_body.
http() {
    local method=$1 url=$2 body=${3:-}
    local args=(-sS -o "$WORK/last_body" -w '%{http_code}' -H 'Host: portal.red.local:8080')
    if [ -n "$body" ]; then
        args+=(-H 'Content-Type: application/json' --data-binary @"$body")
    fi
    curl "${args[@]}" -X "$method" "$url"
}

# make_sync_body FILE KNOWN_IDS_JSON ENVELOPES_JSON — build a §10.4 body.
make_sync_body() {
    printf '{"known_ids":%s,"push_envelopes":%s,"limit":50}' "$2" "$3" > "$1"
}

# json_count_envelopes — number of envelope objects in the last response.
json_count_envelopes() {
    { grep -o '"id":"' "$WORK/last_body" || true; } | wc -l | tr -d ' '
}

# json_id / json_payload — pull a field out of the last single-envelope body
# (Go writes compact JSON; base64 payloads cannot contain quotes).
json_id()      { sed -E 's/.*"id":"([0-9a-f]{64})".*/\1/' "$WORK/last_body"; }
json_payload() { sed -E 's/.*"payload":"([^"]*)".*/\1/'       "$WORK/last_body"; }

# sha256_hex STRING — portable sha256 of a string (macOS shasum, GNU sha256sum).
sha256_hex() {
    if command -v shasum >/dev/null 2>&1; then
        printf '%s' "$1" | shasum -a 256 | awk '{print $1}'
    else
        printf '%s' "$1" | sha256sum | awk '{print $1}'
    fi
}

# ---------------------------------------------------------------------------
# 0. Build the dev binary and start two daemons with separate temp DBs.
# ---------------------------------------------------------------------------
log "building the dev binary (go build in node/)"
(cd "$ROOT/node" && go build -o "$WORK/dtn-node" .)

log "starting node A on 127.0.0.1:$PORT_A and node B on 127.0.0.1:$PORT_B"
"$WORK/dtn-node" -addr "127.0.0.1:$PORT_A" -db "$WORK/node_a.db" >"$WORK/node_a.log" 2>&1 &
DAEMON_A_PID=$!
"$WORK/dtn-node" -addr "127.0.0.1:$PORT_B" -db "$WORK/node_b.db" >"$WORK/node_b.log" 2>&1 &
DAEMON_B_PID=$!

if wait_ready "$PORT_A"; then NODE_A_READY=0; else NODE_A_READY=1; fi
check "node A ready: GET /generate_204 answers 302 (default Host)" "0" "$NODE_A_READY"
if wait_ready "$PORT_B"; then NODE_B_READY=0; else NODE_B_READY=1; fi
check "node B ready: GET /generate_204 answers 302 (default Host)" "0" "$NODE_B_READY"
if [ "$NODE_A_READY" -ne 0 ] || [ "$NODE_B_READY" -ne 0 ]; then
    log "--- node A log ---"; cat "$WORK/node_a.log" >&2 || true
    log "--- node B log ---"; cat "$WORK/node_b.log" >&2 || true
    exit 1
fi

# ---------------------------------------------------------------------------
# 1. Parse the §3.2 example envelope verbatim out of docs/protocolo.md.
# ---------------------------------------------------------------------------
log "parsing the §3.2 example envelope verbatim from docs/protocolo.md"
ENVELOPE_DOC_JSON="$(awk '
    /^### 3\.2 Example/        {seen = 1; next}
    seen && fence_seen != 1 && /^```json/ {fence_seen = 1; next}
    fence_seen == 1 && /^```/  {exit}
    fence_seen == 1            {print}
' "$SPEC" | tr -d "\n")"

ENV_ID="$(printf '%s' "$ENVELOPE_DOC_JSON" | sed -E 's/.*"id": *"([0-9a-f]{64})".*/\1/')"
ENV_HINT="$(printf '%s' "$ENVELOPE_DOC_JSON" | sed -E 's/.*"dest_hint": *"([0-9a-f]{16})".*/\1/')"
ENV_CREATED_AT="$(printf '%s' "$ENVELOPE_DOC_JSON" | sed -E 's/.*"created_at": *([0-9]+).*/\1/')"
ENV_TTL="$(printf '%s' "$ENVELOPE_DOC_JSON" | sed -E 's/.*"ttl": *([0-9]+).*/\1/')"
ENV_PAYLOAD="$(printf '%s' "$ENVELOPE_DOC_JSON" | sed -E 's/.*"payload": *"([^"]+)".*/\1/')"

# Hard gate: if the parser drifted from the spec document, stop immediately —
# every downstream assertion would be meaningless.
if ! printf '%s' "$ENV_ID" | grep -qE '^[0-9a-f]{64}$' || \
   ! printf '%s' "$ENV_HINT" | grep -qE '^[0-9a-f]{16}$' || \
   ! printf '%s' "$ENV_PAYLOAD" | grep -qE '^[A-Za-z0-9+/]+={0,2}$'; then
    printf 'e2e: FAIL: could not parse the §3.2 example envelope from %s — aborting\n' "$SPEC" >&2
    exit 1
fi

# Fixtures:
#   ENV_VERBATIM — the spec example exactly as written (expired at run time).
#   ENV_FRESH    — same id/dest_hint/ttl/payload, created_at re-dated to now.
#   ENV_OLD      — guaranteed-expired fixture (created_at = now - ttl - 1h).
#   ENV_BADID    — fresh fixture with a malformed id (64 'g' chars).
NOW="$(date +%s)"
ENV_VERBATIM="{\"v\":1,\"id\":\"$ENV_ID\",\"dest_hint\":\"$ENV_HINT\",\"created_at\":$ENV_CREATED_AT,\"ttl\":$ENV_TTL,\"payload\":\"$ENV_PAYLOAD\"}"
ENV_FRESH="{\"v\":1,\"id\":\"$ENV_ID\",\"dest_hint\":\"$ENV_HINT\",\"created_at\":$NOW,\"ttl\":$ENV_TTL,\"payload\":\"$ENV_PAYLOAD\"}"
ENV_OLD_ID="$(printf 'e%.0s' $(seq 1 64))"
ENV_OLD_CREATED_AT="$((NOW - ENV_TTL - 3600))"
ENV_OLD="{\"v\":1,\"id\":\"$ENV_OLD_ID\",\"dest_hint\":\"$ENV_HINT\",\"created_at\":$ENV_OLD_CREATED_AT,\"ttl\":$ENV_TTL,\"payload\":\"$ENV_PAYLOAD\"}"
ENV_BADID_ID="$(printf 'g%.0s' $(seq 1 64))"
ENV_BADID="{\"v\":1,\"id\":\"$ENV_BADID_ID\",\"dest_hint\":\"$ENV_HINT\",\"created_at\":$NOW,\"ttl\":$ENV_TTL,\"payload\":\"$ENV_PAYLOAD\"}"

if [ "$ENV_CREATED_AT" -gt "$NOW" ] || [ "$((ENV_CREATED_AT + ENV_TTL))" -ge "$NOW" ]; then
    printf 'e2e: FAIL: the §3.2 example (created_at=%s ttl=%s) is no longer expired at run time; docs/protocolo.md was re-dated — update this script\n' "$ENV_CREATED_AT" "$ENV_TTL" >&2
    exit 1
fi

check "spec §3.2 envelope id parsed verbatim (test vector §6.2)" \
    "d375c17f54525e1816e5f2c01da100e17176c38fd016ea07acb5d3077eb6444f" "$ENV_ID"
check "spec §3.2 verbatim envelope is expired at run time (created_at + ttl < now)" \
    "expired" "$([ "$((ENV_CREATED_AT + ENV_TTL))" -lt "$NOW" ] && echo expired || echo servable)"

# ---------------------------------------------------------------------------
# 2. Directory registration on both nodes (§10.3).
#
# Key material (opaque 32-byte values to the node; directory entries only):
#   alice Ed25519 pubkey : the §4.1/§5.1 example k (Base64, 32 bytes)
#   alice X25519 pubkey  : RFC 7748 §6.1 "Alice" key (spec §6.1 vector), Base64
#   bob   Ed25519 pubkey : the §6.1 full SHA-256 digest value, Base64
#   bob   X25519 pubkey  : RFC 7748 §6.1 "Bob" key, Base64
# ---------------------------------------------------------------------------
ALICE_DIR='{"alias":"alice","pubkey":"11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=","x25519":"hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo="}'
BOB_DIR='{"alias":"bob","pubkey":"MAyclgO5Kks57TlYv5JAEUgE20/TcwEsDKR0MtY0Ja4=","x25519":"PUAXw+hDiVqStwqnTRt+vJyYLM8uxJaMwM1V8Sr0Zgw="}'

printf '%s' "$ALICE_DIR" > "$WORK/reg_alice.json"
printf '%s' "$BOB_DIR"   > "$WORK/reg_bob.json"

for PORT in "$PORT_A" "$PORT_B"; do
    code="$(http POST "http://127.0.0.1:$PORT/api/v1/directory" "$WORK/reg_alice.json")"
    check "register alice on node (port $PORT) -> 200" "200" "$code"
    code="$(http POST "http://127.0.0.1:$PORT/api/v1/directory" "$WORK/reg_bob.json")"
    check "register bob on node (port $PORT) -> 200" "200" "$code"
done

code="$(http GET "http://127.0.0.1:$PORT_A/api/v1/directory")"
check "GET directory on node A -> 200" "200" "$code"
DIR_COUNT="$({ grep -o '"alias"' "$WORK/last_body" || true; } | wc -l | tr -d ' ')"
check "directory on node A lists both users" "2" "$DIR_COUNT"

# ---------------------------------------------------------------------------
# 3. Alice pushes the spec envelope to node A (§10.4 push path).
# ---------------------------------------------------------------------------
make_sync_body "$WORK/sync_push_a.json" "[\"$ENV_ID\"]" "[$ENV_FRESH]"
code="$(http POST "http://127.0.0.1:$PORT_A/api/v1/sync" "$WORK/sync_push_a.json")"
check "alice pushes the spec envelope to node A -> 200" "200" "$code"
check "push response pulls nothing back (own push listed in known_ids)" "0" "$(json_count_envelopes)"

# ---------------------------------------------------------------------------
# 4. Mule syncs with node A and picks up the envelope.
# ---------------------------------------------------------------------------
make_sync_body "$WORK/sync_mule_a.json" "[]" "[]"
code="$(http POST "http://127.0.0.1:$PORT_A/api/v1/sync" "$WORK/sync_mule_a.json")"
check "mule syncs with node A -> 200" "200" "$code"
check "mule pulls exactly 1 envelope from node A" "1" "$(json_count_envelopes)"
check "pulled envelope keeps the spec id" "$ENV_ID" "$(json_id)"
PAYLOAD_SHA_A="$(sha256_hex "$(json_payload)")"
log "mule recorded payload sha256: $PAYLOAD_SHA_A"

# ---------------------------------------------------------------------------
# 5. Mule walks to node B: push what it carries, then Bob pulls.
# ---------------------------------------------------------------------------
make_sync_body "$WORK/sync_mule_b.json" "[\"$ENV_ID\"]" "[$ENV_FRESH]"
code="$(http POST "http://127.0.0.1:$PORT_B/api/v1/sync" "$WORK/sync_mule_b.json")"
check "mule drops the envelope at node B -> 200" "200" "$code"

make_sync_body "$WORK/sync_bob_b.json" "[]" "[]"
code="$(http POST "http://127.0.0.1:$PORT_B/api/v1/sync" "$WORK/sync_bob_b.json")"
check "bob pulls from node B -> 200" "200" "$code"
check "bob pulls exactly 1 envelope from node B" "1" "$(json_count_envelopes)"
check "bob received the envelope with the spec id" "$ENV_ID" "$(json_id)"
PAYLOAD_SHA_B="$(sha256_hex "$(json_payload)")"
check "E2E byte integrity: payload sha256 identical through the mule" "$PAYLOAD_SHA_A" "$PAYLOAD_SHA_B"

# ---------------------------------------------------------------------------
# 6. Negative assertions.
# ---------------------------------------------------------------------------
# (a) INSERT OR IGNORE dedup: re-pushing the same envelope must not duplicate.
make_sync_body "$WORK/sync_dedup.json" "[\"$ENV_ID\"]" "[$ENV_FRESH]"
code="$(http POST "http://127.0.0.1:$PORT_B/api/v1/sync" "$WORK/sync_dedup.json")"
check "re-pushing the same envelope to node B -> 200 (dedup is silent)" "200" "$code"
make_sync_body "$WORK/sync_after_dedup.json" "[]" "[]"
code="$(http POST "http://127.0.0.1:$PORT_B/api/v1/sync" "$WORK/sync_after_dedup.json")"
check "pull after duplicate push returns exactly 1 (no duplicate)" "1" "$(json_count_envelopes)"

# (b) Expired TTL: the VERBATIM §3.2 envelope is accepted on push but never
# served (§10.4 pulls only created_at + ttl >= now).
make_sync_body "$WORK/sync_expired.json" "[]" "[$ENV_VERBATIM]"
code="$(http POST "http://127.0.0.1:$PORT_B/api/v1/sync" "$WORK/sync_expired.json")"
check "expired envelope (verbatim §3.2) accepted on push -> 200" "200" "$code"
make_sync_body "$WORK/sync_after_expired.json" "[]" "[]"
code="$(http POST "http://127.0.0.1:$PORT_B/api/v1/sync" "$WORK/sync_after_expired.json")"
check "expired envelope is TTL-filtered: pull still returns exactly 1" "1" "$(json_count_envelopes)"

# (c) known_ids exclusion on node B (§10.4 step 3: id NOT IN known_ids).
make_sync_body "$WORK/sync_known.json" "[\"$ENV_ID\"]" "[]"
code="$(http POST "http://127.0.0.1:$PORT_B/api/v1/sync" "$WORK/sync_known.json")"
check "pull with the envelope id in known_ids excludes it (0 envelopes)" "0" "$(json_count_envelopes)"

# (d) Body over 1 MiB -> 413 (§10.1 limitBody middleware).
PAD="$(head -c 1100000 /dev/zero | tr '\0' 'a')"
printf '{"known_ids":[],"push_envelopes":[],"limit":50,"pad":"%s"}' "$PAD" > "$WORK/oversize.json"
code="$(http POST "http://127.0.0.1:$PORT_A/api/v1/sync" "$WORK/oversize.json")"
check "sync body > 1 MiB rejected with 413" "413" "$code"

# (e) Malformed envelope (id outside ^[0-9a-f]{64}$) -> 400 (§10.5).
make_sync_body "$WORK/sync_badid.json" "[]" "[$ENV_BADID]"
code="$(http POST "http://127.0.0.1:$PORT_B/api/v1/sync" "$WORK/sync_badid.json")"
check "envelope with malformed id (bad hex) rejected with 400" "400" "$code"

# ---------------------------------------------------------------------------
# 7. Canonical-host middleware: 301 for raw IP, 302 probe exemption (§10.2).
#    Both requests deliberately use the default curl Host (127.0.0.1:PORT).
# ---------------------------------------------------------------------------
code="$(curl -sS -o /dev/null -D "$WORK/hdr_root" -w '%{http_code}' "http://127.0.0.1:$PORT_A/")"
check "raw-IP GET / redirects with 301 to the canonical origin" "301" "$code"
if tr -d '\r' < "$WORK/hdr_root" | grep -qi '^Location: http://portal\.red\.local:8080/$'; then LOC=canonical; else LOC=missing; fi
check "301 Location is exactly http://portal.red.local:8080/" "canonical" "$LOC"

code="$(curl -sS -o /dev/null -D "$WORK/hdr_probe" -w '%{http_code}' "http://127.0.0.1:$PORT_A/generate_204")"
check "captive probe with default Host answers 302 (never 204, never 301)" "302" "$code"
if tr -d '\r' < "$WORK/hdr_probe" | grep -qi '^Location: http://portal\.red\.local:8080/$'; then LOC=canonical; else LOC=missing; fi
check "302 Location is exactly http://portal.red.local:8080/" "canonical" "$LOC"

# ---------------------------------------------------------------------------
# Summary.
# ---------------------------------------------------------------------------
log "summary: $PASS_COUNT passed, $FAIL_COUNT failed"
if [ "$FAIL_COUNT" -gt 0 ]; then
    log "RESULT: FAIL"
    exit 1
fi
log "RESULT: PASS"
