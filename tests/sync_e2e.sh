#!/usr/bin/env bash
# tests/sync_e2e.sh — full E2E integration test WITHOUT hardware (plan 4.3).
#
# Simulates the complete mule journey of docs/protocol.md §2 against two
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
#      exemption (§10.2);
#   9. §15 versioned admission (§15.7 c, d, e): the fixture's blind v1→v2
#      conversion (same id, meta.orig_v = 1, everything else byte-identical)
#      is admitted, served exactly once with its stored v2 and WITHOUT any
#      meta member, created_at/ttl un-refreshed; the v1 original (same id) is
#      absorbed — dedup is version-agnostic — in BOTH orders (v2 first on a
#      fresh node C, v1 first on node A) and the FIRST stored version always
#      wins; a v1 envelope carrying meta and a v: 3 envelope are refused 400
#      with the batch failing closed (§15.3);
#   10. GET /api/v1/capabilities (§15.5): the six-member advertisement — api,
#       envelope_versions [1,2] ascending, min/max 1/2, schema_version 2,
#       non-empty build — and POST → 405 with Allow: GET;
#   11. §15.7 a schema migration E2E: a hand-crafted schema-1 database (the
#       §9 CREATE TABLE verbatim, user_version left at 0, one row inserted
#       the old way, made with the sqlite3 CLI before its daemon ever
#       starts) migrates on daemon start — the pre-existing row stays intact
#       and servable (v = 1, byte-identical payload), user_version becomes 2,
#       envelopes.v appears, and a fresh v2 envelope is admitted;
#   12. §15.7 b downgrade refusal E2E: user_version = 99 makes the daemon
#       exit non-zero before ever becoming ready, naming both versions on
#       stderr, and leaving the database bytes (plus any -wal/-shm sidecars)
#       untouched (sha256 fingerprint before/after).
#
# Determinism: the §3.2 example envelope is parsed VERBATIM out of
# docs/protocol.md at runtime (so the test vector cannot drift from the
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
#   - the §15.7 f negotiation guard and the SPA-side conversion/store
#     migration chain (headless: tests/version_migration.mjs);
#   - the 15-minute cleaner wall-clock behavior (covered by the TTL
#     boundary + DeleteExpired unit tests in node/internal/storage).
#
# Usage:  bash tests/sync_e2e.sh
# Env:    PORT_A (default 18091), PORT_B (default 18092), PORT_C (default
#         18093), PORT_E (default 18094)
# Needs:  go (daemon build), curl, and for sections 11-12 (§15.7 a/b) the
#         sqlite3 CLI plus shasum (macOS) / sha256sum (GNU) for the database
#         fixtures and the §15.7 b byte fingerprint.
# Exit:   0 = every assertion passed; 1 = at least one failed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SPEC="$ROOT/docs/protocol.md"

PORT_A="${PORT_A:-18091}"
PORT_B="${PORT_B:-18092}"
PORT_C="${PORT_C:-18093}"
PORT_E="${PORT_E:-18094}"

PASS_COUNT=0
FAIL_COUNT=0
DAEMON_A_PID=""
DAEMON_B_PID=""
DAEMON_C_PID=""
DAEMON_E_PID=""

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
    if [ -n "$DAEMON_C_PID" ]; then
        kill "$DAEMON_C_PID" 2>/dev/null || true
        wait "$DAEMON_C_PID" 2>/dev/null || true
    fi
    if [ -n "$DAEMON_E_PID" ]; then
        kill "$DAEMON_E_PID" 2>/dev/null || true
        wait "$DAEMON_E_PID" 2>/dev/null || true
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
    local args=(-sS -o "$WORK/last_body" -w '%{http_code}' -H 'Host: offgrid.local:8080')
    if [ -n "$body" ]; then
        args+=(-H 'Content-Type: application/json' --data-binary @"$body")
    fi
    curl "${args[@]}" -X "$method" "$url"
}

# stop_daemon PID — SIGTERM one of our daemons and reap it (graceful drain
# closes the SQLite handle, checkpointing and removing any -wal/-shm files).
stop_daemon() {
    kill "$1" 2>/dev/null || true
    wait "$1" 2>/dev/null || true
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

# json_v / json_created_at / json_ttl — further single-envelope fields of the
# last response body (each name occurs once in a one-envelope body, so the
# greedy sed is safe; used by the §15 sections below).
json_v()          { sed -E 's/.*"v":([0-9]+).*/\1/'           "$WORK/last_body"; }
json_created_at() { sed -E 's/.*"created_at":([0-9]+).*/\1/'  "$WORK/last_body"; }
json_ttl()        { sed -E 's/.*"ttl":([0-9]+).*/\1/'         "$WORK/last_body"; }

# caps_str MEMBER / caps_num MEMBER — a string resp. integer member of the
# last response body (the §15.5 capabilities document; Go writes compact JSON,
# so the member name is a unique anchor for the greedy sed).
caps_str() { sed -E "s/.*\"$1\":\"([^\"]*)\".*/\1/" "$WORK/last_body"; }
caps_num() { sed -E "s/.*\"$1\":([0-9]+).*/\1/"     "$WORK/last_body"; }

# sha256_hex STRING — portable sha256 of a string (macOS shasum, GNU sha256sum).
sha256_hex() {
    if command -v shasum >/dev/null 2>&1; then
        printf '%s' "$1" | shasum -a 256 | awk '{print $1}'
    else
        printf '%s' "$1" | sha256sum | awk '{print $1}'
    fi
}

# sha256_file PATH — portable sha256 of a file's bytes.
sha256_file() {
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        sha256sum "$1" | awk '{print $1}'
    fi
}

# db_fingerprint DB — sha256 of the database file plus any -wal/-shm sidecar
# present right now (space-separated), so the §15.7 b downgrade-refusal check
# compares the exact on-disk state the refused start was handed.
db_fingerprint() {
    local db=$1 out p
    out="$(sha256_file "$db")"
    for p in "$db-wal" "$db-shm"; do
        if [ -e "$p" ]; then
            out="$out $(sha256_file "$p")"
        fi
    done
    printf '%s' "$out"
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
# 1. Parse the §3.2 example envelope verbatim out of docs/protocol.md.
# ---------------------------------------------------------------------------
log "parsing the §3.2 example envelope verbatim from docs/protocol.md"
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
    printf 'e2e: FAIL: the §3.2 example (created_at=%s ttl=%s) is no longer expired at run time; docs/protocol.md was re-dated — update this script\n' "$ENV_CREATED_AT" "$ENV_TTL" >&2
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
if tr -d '\r' < "$WORK/hdr_root" | grep -qi '^Location: http://offgrid\.local:8080/$'; then LOC=canonical; else LOC=missing; fi
check "301 Location is exactly http://offgrid.local:8080/" "canonical" "$LOC"

code="$(curl -sS -o /dev/null -D "$WORK/hdr_probe" -w '%{http_code}' "http://127.0.0.1:$PORT_A/generate_204")"
check "captive probe with default Host answers 302 (never 204, never 301)" "302" "$code"
if tr -d '\r' < "$WORK/hdr_probe" | grep -qi '^Location: http://offgrid\.local:8080/$'; then LOC=canonical; else LOC=missing; fi
check "302 Location is exactly http://offgrid.local:8080/" "canonical" "$LOC"

# ---------------------------------------------------------------------------
# 8. §15 versioned admission, conversion fidelity and version-agnostic dedup
#    (§15.7 c, d, e). Fresh node C replays the mule story with the fixture's
#    blind v1→v2 conversion (§15.1: exactly v = 2 + meta.orig_v = 1, every
#    other member byte-identical, id unchanged). Node A — which stored the
#    v1 fixture FIRST, in section 3 — replays the reversed order.
# ---------------------------------------------------------------------------
ENV_V2="{\"v\":2,\"id\":\"$ENV_ID\",\"dest_hint\":\"$ENV_HINT\",\"created_at\":$NOW,\"ttl\":$ENV_TTL,\"payload\":\"$ENV_PAYLOAD\",\"meta\":{\"orig_v\":1}}"
ENV_V1_META="{\"v\":1,\"id\":\"$ENV_ID\",\"dest_hint\":\"$ENV_HINT\",\"created_at\":$NOW,\"ttl\":$ENV_TTL,\"payload\":\"$ENV_PAYLOAD\",\"meta\":{\"orig_v\":1}}"
ENV_V3="{\"v\":3,\"id\":\"$ENV_ID\",\"dest_hint\":\"$ENV_HINT\",\"created_at\":$NOW,\"ttl\":$ENV_TTL,\"payload\":\"$ENV_PAYLOAD\"}"
ENV2_ID="$(printf 'f%.0s' $(seq 1 64))"
ENV2_FRESH="{\"v\":1,\"id\":\"$ENV2_ID\",\"dest_hint\":\"$ENV_HINT\",\"created_at\":$NOW,\"ttl\":$ENV_TTL,\"payload\":\"$ENV_PAYLOAD\"}"
ENV2_V2="{\"v\":2,\"id\":\"$ENV2_ID\",\"dest_hint\":\"$ENV_HINT\",\"created_at\":$NOW,\"ttl\":$ENV_TTL,\"payload\":\"$ENV_PAYLOAD\",\"meta\":{\"orig_v\":1}}"

log "starting node C on 127.0.0.1:$PORT_C with a fresh database (§15 coverage)"
"$WORK/dtn-node" -addr "127.0.0.1:$PORT_C" -db "$WORK/node_c.db" >"$WORK/node_c.log" 2>&1 &
DAEMON_C_PID=$!
if wait_ready "$PORT_C"; then NODE_C_READY=0; else NODE_C_READY=1; fi
check "node C ready: GET /generate_204 answers 302 (default Host)" "0" "$NODE_C_READY"
if [ "$NODE_C_READY" -ne 0 ]; then
    log "--- node C log ---"; cat "$WORK/node_c.log" >&2 || true
    exit 1
fi

# (a) §15.7 c admission: the converted envelope is admitted and stored.
make_sync_body "$WORK/sync_v2_c.json" "[\"$ENV_ID\"]" "[$ENV_V2]"
code="$(http POST "http://127.0.0.1:$PORT_C/api/v1/sync" "$WORK/sync_v2_c.json")"
check "push the fixture's v2 conversion (same id, meta.orig_v=1) to node C -> 200 (§15.7 c)" "200" "$code"

# (b) §15.7 d + e serving fidelity: exactly once, stored v2, never meta,
#     created_at/ttl untouched (conversion MUST NOT refresh lifetime).
make_sync_body "$WORK/sync_pull_c.json" "[]" "[]"
code="$(http POST "http://127.0.0.1:$PORT_C/api/v1/sync" "$WORK/sync_pull_c.json")"
check "pull from node C -> 200" "200" "$code"
check "node C serves the converted envelope exactly once" "1" "$(json_count_envelopes)"
check "served envelope keeps the fixture id (conversion cannot change id, §15.7 d)" "$ENV_ID" "$(json_id)"
check "served envelope carries its stored v2 (§15.3)" "2" "$(json_v)"
if grep -q '"meta"' "$WORK/last_body"; then META=present; else META=absent; fi
check "served envelope carries NO meta member (§15.3: admission-time only, never persisted)" "absent" "$META"
check "served created_at unchanged by conversion (no life extension, §15.7 e)" "$NOW" "$(json_created_at)"
check "served ttl unchanged by conversion (no life extension, §15.7 e)" "$ENV_TTL" "$(json_ttl)"

# (c) §15.7 c dedup, forward order: re-pushing the v1 original (same id) is
#     absorbed by the stored v2 row — dedup is version-agnostic.
make_sync_body "$WORK/sync_v1_after_v2.json" "[\"$ENV_ID\"]" "[$ENV_FRESH]"
code="$(http POST "http://127.0.0.1:$PORT_C/api/v1/sync" "$WORK/sync_v1_after_v2.json")"
check "push the v1 original (same id) to node C -> 200 (dedup is silent)" "200" "$code"
make_sync_body "$WORK/sync_pull_c2.json" "[]" "[]"
code="$(http POST "http://127.0.0.1:$PORT_C/api/v1/sync" "$WORK/sync_pull_c2.json")"
check "pull from node C after the v1 re-push -> 200" "200" "$code"
check "node C still holds exactly 1 envelope after the v1 re-push" "1" "$(json_count_envelopes)"
check "node C keeps serving the FIRST stored version (v2)" "2" "$(json_v)"

# (d) §15.7 c reverse order on node A (its copy was stored as v1 in section
#     3): the v2 conversion must be absorbed and the served row keep v1.
make_sync_body "$WORK/sync_v1_a.json" "[\"$ENV_ID\"]" "[$ENV_FRESH]"
code="$(http POST "http://127.0.0.1:$PORT_A/api/v1/sync" "$WORK/sync_v1_a.json")"
check "push the v1 fixture to node A (stored there first in section 3) -> 200" "200" "$code"
make_sync_body "$WORK/sync_pull_a.json" "[]" "[]"
code="$(http POST "http://127.0.0.1:$PORT_A/api/v1/sync" "$WORK/sync_pull_a.json")"
check "pull from node A -> 200" "200" "$code"
check "node A serves exactly 1 envelope" "1" "$(json_count_envelopes)"
check "node A serves its first stored version (v1)" "1" "$(json_v)"
make_sync_body "$WORK/sync_v2_a.json" "[\"$ENV_ID\"]" "[$ENV_V2]"
code="$(http POST "http://127.0.0.1:$PORT_A/api/v1/sync" "$WORK/sync_v2_a.json")"
check "push the v2 conversion to node A -> 200 (absorbed: dedup is version-agnostic, §15.7 c)" "200" "$code"
make_sync_body "$WORK/sync_pull_a2.json" "[]" "[]"
code="$(http POST "http://127.0.0.1:$PORT_A/api/v1/sync" "$WORK/sync_pull_a2.json")"
check "pull from node A after the v2 push -> 200" "200" "$code"
check "node A still holds exactly 1 envelope after the v2 push" "1" "$(json_count_envelopes)"
check "node A keeps serving v1 (the first stored version wins)" "1" "$(json_v)"

# (e) §15.3 structural refusals — and the batch fails closed (§10.4): the
#     invalid v1+meta envelope must reject the WHOLE batch, so the valid
#     companion envelope (id ENV2_ID) must never land.
make_sync_body "$WORK/sync_v1meta.json" "[]" "[$ENV_V1_META, $ENV2_FRESH]"
code="$(http POST "http://127.0.0.1:$PORT_C/api/v1/sync" "$WORK/sync_v1meta.json")"
check "v1 envelope carrying meta rejected with 400 (§15.3: meta MUST be absent on v1)" "400" "$code"
make_sync_body "$WORK/sync_pull_c3.json" "[]" "[]"
code="$(http POST "http://127.0.0.1:$PORT_C/api/v1/sync" "$WORK/sync_pull_c3.json")"
check "after the failed batch the pull -> 200" "200" "$code"
check "failed batch fails closed: node C still holds exactly 1 envelope" "1" "$(json_count_envelopes)"
check "failed batch fails closed: the valid companion id never landed" "$ENV_ID" "$(json_id)"
make_sync_body "$WORK/sync_v3.json" "[]" "[$ENV_V3]"
code="$(http POST "http://127.0.0.1:$PORT_C/api/v1/sync" "$WORK/sync_v3.json")"
check "v: 3 envelope (outside the supported set {1,2}) rejected with 400 (§15.3)" "400" "$code"

stop_daemon "$DAEMON_C_PID"
DAEMON_C_PID=""

# ---------------------------------------------------------------------------
# 9. §15.5 version advertisement: GET /api/v1/capabilities on node A.
# ---------------------------------------------------------------------------
code="$(http GET "http://127.0.0.1:$PORT_A/api/v1/capabilities")"
check "GET /api/v1/capabilities -> 200 (§15.5)" "200" "$code"
check "capabilities api is \"v1\"" "v1" "$(caps_str api)"
ENVELOPE_VERSIONS="$(grep -oE '"envelope_versions":\[[0-9,]*\]' "$WORK/last_body" | sed -E 's/^"envelope_versions"://')"
check "capabilities envelope_versions is [1,2] (ascending supported set, §15.3)" "[1,2]" "$ENVELOPE_VERSIONS"
check "capabilities min_envelope_version is 1 (first element)" "1" "$(caps_num min_envelope_version)"
check "capabilities max_envelope_version is 2 (negotiation ceiling)" "2" "$(caps_num max_envelope_version)"
check "capabilities schema_version is 2 (§15.3)" "2" "$(caps_num schema_version)"
if grep -q '"build":"' "$WORK/last_body"; then BUILD_ID="$(caps_str build)"; else BUILD_ID=""; fi
check "capabilities build is non-empty (§15.5)" "non-empty" "$([ -n "$BUILD_ID" ] && echo non-empty || echo empty)"
code="$(curl -sS -o /dev/null -D "$WORK/hdr_caps" -w '%{http_code}' -H 'Host: offgrid.local:8080' -X POST "http://127.0.0.1:$PORT_A/api/v1/capabilities")"
check "POST /api/v1/capabilities rejected with 405 (§10.1 wrong method)" "405" "$code"
if tr -d '\r' < "$WORK/hdr_caps" | grep -qi '^Allow: GET'; then ALLOW=get; else ALLOW=missing; fi
check "capabilities 405 advertises Allow: GET (§10.1)" "get" "$ALLOW"

# ---------------------------------------------------------------------------
# 10. §15.7 a — schema migration E2E: a schema-1 database written "by an old
#     node" (the §9 CREATE TABLE verbatim, user_version left at 0, one row
#     inserted the old way — no v column exists) is migrated by the current
#     daemon on open. Crafted with the sqlite3 CLI BEFORE this daemon ever
#     starts; the row is the re-dated fixture so the startup sweep (§10.6)
#     cannot reap it.
# ---------------------------------------------------------------------------
LEGACY_DB="$WORK/node_legacy.db"
# (stdout of the creation goes to /dev/null: `PRAGMA journal_mode = WAL`
# echoes "wal", which would otherwise pollute the run log.)
sqlite3 "$LEGACY_DB" >/dev/null <<SQL
PRAGMA journal_mode = WAL;
CREATE TABLE envelopes (
  id        TEXT PRIMARY KEY,      -- envelope id, 64 lowercase hex chars (client-computed)
  dest_hint TEXT NOT NULL,         -- 16 lowercase hex chars
  created_at INTEGER NOT NULL,     -- unix seconds
  ttl       INTEGER NOT NULL,      -- seconds
  payload   TEXT NOT NULL          -- Base64( eph_pub || nonce || box )
);
CREATE INDEX idx_envelopes_dest_hint ON envelopes(dest_hint);
CREATE INDEX idx_envelopes_expiry    ON envelopes(created_at, ttl);

CREATE TABLE directory (
  pubkey    TEXT PRIMARY KEY,      -- ed25519 public key, Base64 (identity)
  x25519    TEXT NOT NULL,         -- X25519 public key, Base64 (encryption)
  alias     TEXT NOT NULL,
  last_seen INTEGER NOT NULL       -- unix seconds, set by the node on upsert
);

INSERT INTO envelopes (id, dest_hint, created_at, ttl, payload)
  VALUES ('$ENV_ID', '$ENV_HINT', $NOW, $ENV_TTL, '$ENV_PAYLOAD');

PRAGMA user_version = 0;
SQL
if [ "$(sqlite3 "$LEGACY_DB" 'PRAGMA user_version;')" = "0" ] && \
   ! sqlite3 "$LEGACY_DB" 'PRAGMA table_info(envelopes);' | grep -q '|v|'; then
    LEG_SANITY=ok
else
    LEG_SANITY=broken
fi
check "legacy fixture is schema 1: user_version 0, no envelopes.v column" "ok" "$LEG_SANITY"

log "starting the migrating daemon on 127.0.0.1:$PORT_E against the schema-1 database"
"$WORK/dtn-node" -addr "127.0.0.1:$PORT_E" -db "$LEGACY_DB" >"$WORK/node_legacy.log" 2>&1 &
DAEMON_E_PID=$!
if wait_ready "$PORT_E"; then NODE_E_READY=0; else NODE_E_READY=1; fi
check "daemon against the schema-1 database becomes ready (§15.7 a: migration ran, not refused)" "0" "$NODE_E_READY"
if [ "$NODE_E_READY" -ne 0 ]; then
    log "--- migrated node log ---"; cat "$WORK/node_legacy.log" >&2 || true
    exit 1
fi

make_sync_body "$WORK/sync_legacy_pull.json" "[]" "[]"
code="$(http POST "http://127.0.0.1:$PORT_E/api/v1/sync" "$WORK/sync_legacy_pull.json")"
check "pull from the migrated daemon -> 200" "200" "$code"
check "migrated daemon serves exactly the pre-existing envelope" "1" "$(json_count_envelopes)"
check "pre-existing envelope keeps its id through the migration" "$ENV_ID" "$(json_id)"
check "pre-existing envelope is served as v1 (DEFAULT 1 backfill, §15.3)" "1" "$(json_v)"
check "pre-existing payload is byte-identical through the migration (§15.3)" \
    "$(sha256_hex "$ENV_PAYLOAD")" "$(sha256_hex "$(json_payload)")"
check "user_version migrated from 0 to 2 (§15.3)" "2" "$(sqlite3 "$LEGACY_DB" 'PRAGMA user_version;')"
if sqlite3 "$LEGACY_DB" 'PRAGMA table_info(envelopes);' | grep -q '|v|'; then VCOL=present; else VCOL=missing; fi
check "envelopes table gained the v column (schema 2)" "present" "$VCOL"

make_sync_body "$WORK/sync_legacy_v2.json" "[\"$ENV_ID\"]" "[$ENV2_V2]"
code="$(http POST "http://127.0.0.1:$PORT_E/api/v1/sync" "$WORK/sync_legacy_v2.json")"
check "migrated node admits a fresh v2 envelope -> 200" "200" "$code"
make_sync_body "$WORK/sync_legacy_pull2.json" "[\"$ENV_ID\"]" "[]"
code="$(http POST "http://127.0.0.1:$PORT_E/api/v1/sync" "$WORK/sync_legacy_pull2.json")"
check "pull from the migrated node excluding the legacy id -> 200" "200" "$code"
check "migrated node serves exactly the new envelope" "1" "$(json_count_envelopes)"
check "new envelope served with its id" "$ENV2_ID" "$(json_id)"
check "new envelope served with its stored v2 (migrated node accepts the new set, §15.3)" "2" "$(json_v)"

stop_daemon "$DAEMON_E_PID"
DAEMON_E_PID=""

# ---------------------------------------------------------------------------
# 11. §15.7 b — downgrade refusal E2E: user_version = 99 (a database "from a
#     newer binary") must make the daemon exit non-zero before ever becoming
#     ready, name both versions on stderr, and leave the database bytes
#     untouched. Runs on the migrated database after stopping its daemon.
# ---------------------------------------------------------------------------
sqlite3 "$LEGACY_DB" 'PRAGMA user_version = 99;'
# The sqlite3 CLI leaves empty, fully-checkpointed -wal/-shm sidecars behind
# on exit, while a daemon open+close removes them again. Normalize to the
# quiescent on-disk state BEFORE fingerprinting so both sides of the
# comparison describe the same shape. Only an EMPTY -wal is ever removed
# (nothing left to checkpoint); a non-empty one is kept and will — rightly —
# fail the byte comparison below.
if [ -f "$LEGACY_DB-wal" ] && [ ! -s "$LEGACY_DB-wal" ]; then
    rm -f "$LEGACY_DB-wal" "$LEGACY_DB-shm"
fi
FINGERPRINT_BEFORE="$(db_fingerprint "$LEGACY_DB")"

log "attempting to start a daemon against the user_version-99 database (must refuse)"
"$WORK/dtn-node" -addr "127.0.0.1:$PORT_E" -db "$LEGACY_DB" >"$WORK/node_refused.log" 2>&1 &
REFUSED_PID=$!
REF_READY=1
for i in $(seq 1 25); do
    if ! kill -0 "$REFUSED_PID" 2>/dev/null; then break; fi
    probe="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT_E/generate_204" 2>/dev/null)" || probe=000
    if [ "$probe" = "302" ]; then REF_READY=0; break; fi
    sleep 0.2
done
REF_STATUS=0
if [ "$REF_READY" -eq 0 ]; then
    # Regression: the daemon started serving a database from the future.
    # Stop it (a wait would never return) — the readiness check below, and
    # the byte fingerprint of the now-migrated file, record the failure.
    stop_daemon "$REFUSED_PID"
    REF_STATUS="killed-while-running"
else
    wait "$REFUSED_PID" 2>/dev/null || REF_STATUS=$?
fi
check "start against user_version 99 exits non-zero (§15.7 b downgrade refusal)" \
    "non-zero" "$([ "$REF_STATUS" != 0 ] && echo non-zero || echo zero)"
check "downgrade-refused daemon never became ready" "1" "$REF_READY"
if grep -q '99' "$WORK/node_refused.log" && grep -q '2' "$WORK/node_refused.log"; then
    NAMED=both
else
    NAMED=missing
fi
check "refusal message names both schema versions (99 and 2)" "both" "$NAMED"
check "refused start left the database byte-untouched, sidecars included (§15.3)" \
    "$FINGERPRINT_BEFORE" "$(db_fingerprint "$LEGACY_DB")"

# ---------------------------------------------------------------------------
# Summary.
# ---------------------------------------------------------------------------
log "summary: $PASS_COUNT passed, $FAIL_COUNT failed"
if [ "$FAIL_COUNT" -gt 0 ]; then
    log "RESULT: FAIL"
    exit 1
fi
log "RESULT: PASS"
