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
#   10. GET /api/v1/capabilities (§15.5): the eight-member advertisement — api,
#       envelope_versions [1,2] ascending, min/max 1/2, schema_version 3,
#       non-empty build, plus the additive §6.1 hint-epoch members — and
#       POST → 405 with Allow: GET;
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
#   13. §10.7 diagnostics surface (issue #31) on node A, whose aggregate
#       state is fully known at that point: GET /api/v1/health answers 200
#       application/json with exactly the documented members and TRUTHFUL
#       aggregates (1 stored envelope, capacity 5000, 2 directory entries,
#       3 accepted / 1 rejected push [the §6d 413 → too_large], 2 dedup hits,
#       the startup TTL sweep) in well under the 50 ms budget; POST → 405
#       with Allow: GET; GET /status serves the operator page (no JavaScript,
#       same build) and is linked from nowhere in the portal (index.html and
#       every script it loads); the canonical-host 301 covers both paths;
#       the captive probes are unaffected; and neither body carries any
#       envelope id, hint, payload, alias or key (privacy, §13).
#       (The per-IP 429 shed of the diagnostics budget is unit-covered:
#       driving 61 requests through curl here would be slow and flaky.)
#
#   13. §4.4 long-message chunking (issue #24): a 1 KiB UTF-8 message built
#       with the SHIPPED SPA engine (loaded headlessly via
#       tests/helpers/spa_loader.mjs) travels as ordinary chunk envelopes
#       Alice -> node A -> mule (carrying the exact served bytes) -> node B
#       -> Bob; Bob's side decrypts and reassembles the SERVED envelopes —
#       fed reversed and with one duplicate — into ONE message whose
#       sha256 equals the original text; every served envelope is a valid
#       §3.1 v1 envelope within the §8.2 payload bounds [248, 400] (the
#       daemons accepted nothing a node would reject); a one-chunk-short
#       partial never renders as a complete message.
#   14. §4.5 delivery acknowledgments (issue #25): the ack travels the full
#       multi-node path with the SHIPPED SPA engine on both ends — Alice
#       pushes a flat and a chunked message through a fresh node pair,
#       Bob's engine decrypts/reassembles, resolves Alice's X25519 key
#       from the node directory and emits exactly ONE signed ack envelope
#       addressed back to her dest_hint (flat: the envelope id; chunked:
#       the LAST chunk's envelope id, emitted once at reassembly
#       completion); a mule carries the acks back; Alice's engine verifies
#       them against her sent record (bound to the recipient's Ed25519
#       key) and flips the state to delivered. Every ack is an ordinary
#       §3.1 v1 envelope within the §8.2 bounds; acks are never acked
#       (termination); and a mule tampering with the ack payload fails
#       verification at Alice (state stays queued).
#   15. §6.1 rotating dest_hint (issue #26): the full mail path with
#       ROTATING hints, both endpoints on the SHIPPED SPA engine
#       (tests/helpers/hint_e2e.mjs; INJECTED CLOCKS — the harness passes
#       NOW and the observed epoch explicitly, so no leg depends on the
#       wall clock except the honestly-flagged during-window legacy leg):
#       the sender derives the hint from the SERVER-SET epoch of the
#       recipient's directory entry (a spoofed client epoch member is
#       ignored by the node); hint(E) mail is delivered and decrypted,
#       survives a simulated epoch boundary (observed E+1) with no message
#       loss (§15.7 g), hint(E-1) mail arrives during the window; a
#       pre-1.6 STATIC-hint envelope is delivered inside the §6.1
#       transition window (§15.7 h) and the SAME envelope is foreign
#       cargo for a simulated post-deadline build (clock =
#       HINT_TRANSITION_DEADLINE + 1 day; §15.7 i); directory GET carries
#       the additive epoch member and capabilities the additive §6.1
#       members.
#   16. §4.6 prekey bundles — forward secrecy (issue #27): the full mail
#       path with a PREKEY-published Bob, both endpoints on the SHIPPED SPA
#       engine (tests/helpers/prekey_e2e.mjs): Bob registers WITH a bundle
#       (blind node admission, verbatim GET round-trip ≤ 2 KiB); Alice's
#       engine targets a random ONE-TIME prekey while dest_hint stays
#       hint_E(Bob's IDENTITY key); delivery + decrypt through the prekey
#       trial path and the OPK secret is wiped on use; the CAPTURED
#       envelope bytes then FAIL to decrypt both for an attacker holding
#       ONLY Bob's extracted long-term key and for Bob's post-wipe state
#       (the acceptance criterion, end to end); an old-client envelope
#       addressed to Bob's identity key still opens (permanent identity
#       trial path, no forward secrecy — documented); a bundle-less
#       recipient (Alice) receives identity-fallback mail; and a stale-SPK
#       replenish rotates the published bundle through the ordinary
#       directory upsert.
#   17. §4.7 identity QR — in-person contact exchange (issue #28): the
#       acceptance journey on the SHIPPED SPA engine
#       (tests/helpers/qr_e2e.mjs) with the DIRECTORY NEVER USED — both
#       nodes' directory endpoints stay EMPTY the whole time: Alice and
#       Bob import each other's OFFGRID1 payloads into their CONTACTS
#       (the §4.7 engine parser/verifier), a TAMPERED payload is rejected
#       with a visible reason (bad_crc) and stores nothing, Alice sends to
#       her contact with the §6.1 offline-cold STATIC hint and the §4.6
#       identity fallback, Bob receives and REPLIES the same way, and both
#       inboxes show both messages.
#   18. §12.1 PWA-lite installability (issue #29): /manifest.json serves
#       with the application/manifest+json content type and the exact
#       §12.1 members (relative start_url/scope "/", standalone, 192+512
#       "any maskable" icons, NO service-worker member), the three PNG
#       icons serve as image/png with the exact advertised pixel dimensions
#       (PNG magic + IHDR parsed), the portal HTML carries the manifest
#       link, theme-color, the iOS meta tags and the honest no-offline
#       note, NO external URL appears in any of them (zero external
#       assets), unknown icons 404, POST 405, and the canonical-host 301
#       covers the new paths.
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
#         18093), PORT_E (default 18094), PORT_D (default 18095)
# Needs:  go (daemon build), curl, node (the §4.4 chunking and §4.5 ack E2Es
#         drive the shipped SPA engine via tests/helpers/*.mjs), and for
#         sections 11-12 (§15.7 a/b) the sqlite3 CLI plus shasum (macOS) /
#         sha256sum (GNU) for the database fixtures and the §15.7 b byte
#         fingerprint.
# Exit:   0 = every assertion passed; 1 = at least one failed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SPEC="$ROOT/docs/protocol.md"

PORT_A="${PORT_A:-18091}"
PORT_B="${PORT_B:-18092}"
PORT_C="${PORT_C:-18093}"
PORT_E="${PORT_E:-18094}"
PORT_D="${PORT_D:-18095}"

PASS_COUNT=0
FAIL_COUNT=0
DAEMON_A_PID=""
DAEMON_B_PID=""
DAEMON_C_PID=""
DAEMON_E_PID=""
DAEMON_D_PID=""

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
    if [ -n "$DAEMON_D_PID" ]; then
        kill "$DAEMON_D_PID" 2>/dev/null || true
        wait "$DAEMON_D_PID" 2>/dev/null || true
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
BOB_DIR='{"alias":"bob","pubkey":"MAyclgO5Kks57TlYv5JAEUgE20/TcwEsDKR0MtY0Ja4=","x25519":"3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08="}'

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
check "capabilities schema_version is 4 (§15.3, §4.6)" "4" "$(caps_num schema_version)"
check "capabilities hint_epoch_seconds is 86400 (§6.1 additive)" "86400" "$(caps_num hint_epoch_seconds)"
HINT_CUR="$(caps_num hint_epoch_current)"
check "capabilities hint_epoch_current is a non-negative integer (§6.1 additive)" \
    "ok" "$([ "$HINT_CUR" -ge 0 ] 2>/dev/null && echo ok || echo bad)"
check "capabilities hint_epoch_current matches floor(node now / 86400) (§6.1)" \
    "$(( $(date +%s) / 86400 ))" "$HINT_CUR"
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

-- A pre-1.6 directory row: its epoch column does not exist yet; the 2→3
-- migration must backfill it to 0 (deliberately stale, §6.1).
INSERT INTO directory (pubkey, x25519, alias, last_seen)
  VALUES ('bGVnYWN5X3VzZXJfa2V5X2FhYWFhYWFhYWFhYWFhYWE=', 'bGVnYWN5X3VzZXJfa2V5X2FhYWFhYWFhYWFhYWFhYWE=', 'legacy_user', 1700000000);

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
check "user_version migrated from 0 to 4 (§15.3 chain 1→2→3→4)" "4" "$(sqlite3 "$LEGACY_DB" 'PRAGMA user_version;')"
if sqlite3 "$LEGACY_DB" 'PRAGMA table_info(envelopes);' | grep -q '|v|'; then VCOL=present; else VCOL=missing; fi
check "envelopes table gained the v column (chain step 1→2)" "present" "$VCOL"
if sqlite3 "$LEGACY_DB" 'PRAGMA table_info(directory);' | grep -q '|epoch|'; then ECOL=present; else ECOL=missing; fi
check "directory table gained the epoch column (chain step 2→3, §6.1)" "present" "$ECOL"
if sqlite3 "$LEGACY_DB" 'PRAGMA table_info(directory);' | grep -q '|prekeys|'; then PCOL=present; else PCOL=missing; fi
check "directory table gained the nullable prekeys column (chain step 3→4, §4.6)" "present" "$PCOL"
LEG_PREKEYS="$(sqlite3 "$LEGACY_DB" 'SELECT prekeys FROM directory LIMIT 1;')"
check "pre-existing directory row backfilled to prekeys NULL (bundle-less, §4.6)" "" "$LEG_PREKEYS"
LEG_EPOCH="$(sqlite3 "$LEGACY_DB" 'SELECT epoch FROM directory LIMIT 1;')"
check "pre-existing directory row backfilled to epoch 0 (deliberately stale, §6.1)" "0" "$LEG_EPOCH"

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
if grep -q '99' "$WORK/node_refused.log" && grep -q '4' "$WORK/node_refused.log"; then
    NAMED=both
else
    NAMED=missing
fi
check "refusal message names both schema versions (99 and 4)" "both" "$NAMED"
check "refused start left the database byte-untouched, sidecars included (§15.3)" \
    "$FINGERPRINT_BEFORE" "$(db_fingerprint "$LEGACY_DB")"

# ---------------------------------------------------------------------------
# 12. §10.7 diagnostics surface (issue #31): health snapshot + operator
#     status view, asserted against node A — still running, with a fully
#     known aggregate history:
#       envelopes            1    (the §3 fixture; both §8d re-pushes absorbed)
#       directory_entries    2    (alice, bob — §2)
#       pushes_accepted      3    (§3 push + the two §8d re-pushes)
#       pushes_rejected      1    (the §6d oversize 413 → class too_large)
#       dedup_hits           2    (both §8d re-pushes were absorbed)
#       ttl_sweeps           1    (the startup sweep; 0 envelopes swept)
#     The first health GET is also the FIRST one node A ever serves, so the
#     1-second snapshot cache refreshes now and sees every prior counter.
# ---------------------------------------------------------------------------
code="$(http GET "http://127.0.0.1:$PORT_A/api/v1/health")"
check "GET /api/v1/health -> 200 (§10.7)" "200" "$code"
cp "$WORK/last_body" "$WORK/health_body"
curl -sS -o /dev/null -D "$WORK/hdr_health" -H 'Host: offgrid.local:8080' "http://127.0.0.1:$PORT_A/api/v1/health"
if tr -d '\r' < "$WORK/hdr_health" | grep -qi '^Content-Type: application/json; charset=utf-8'; then CT=ok; else CT=bad; fi
check "health Content-Type is application/json; charset=utf-8" "ok" "$CT"
check "health status is \"ok\" (liveness, no invented judgment)" "ok" "$(caps_str status)"
check "health api is \"v1\" (same source as capabilities)" "v1" "$(caps_str api)"
check "health schema_version is 4 (same source as capabilities)" "4" "$(caps_num schema_version)"
ENVELOPE_VERSIONS_HEALTH="$(grep -oE '"envelope_versions":\[[0-9,]*\]' "$WORK/last_body" | sed -E 's/^"envelope_versions"://')"
check "health envelope_versions is [1,2] (same source as capabilities)" "[1,2]" "$ENVELOPE_VERSIONS_HEALTH"
if grep -q '"build":"' "$WORK/last_body"; then BUILD_HEALTH="$(caps_str build)"; else BUILD_HEALTH=""; fi
check "health build is non-empty (same source as capabilities)" "non-empty" "$([ -n "$BUILD_HEALTH" ] && echo non-empty || echo empty)"
UPTIME="$(caps_num uptime_seconds)"
check "health uptime_seconds is a non-negative integer" "ok" "$([ "$UPTIME" -ge 0 ] 2>/dev/null && echo ok || echo bad)"
check "health envelope_capacity is 5000 (§8.1)" "5000" "$(caps_num envelope_capacity)"
check "health envelopes matches the known store count (1)" "1" "$(caps_num envelopes)"
check "health directory_entries matches the known directory (2)" "2" "$(caps_num directory_entries)"
DB_SIZE="$(caps_num db_size_bytes)"
check "health db_size_bytes is positive (schema on disk)" "ok" "$([ "$DB_SIZE" -gt 0 ] 2>/dev/null && echo ok || echo bad)"
LAST_CLEANUP="$(caps_num last_cleanup_unix)"
check "health last_cleanup_unix is set (startup sweep recorded)" "ok" "$([ "$LAST_CLEANUP" -gt 0 ] 2>/dev/null && echo ok || echo bad)"
check "health last_cleanup_envelopes_deleted is 0 (nothing expired yet)" "0" "$(caps_num last_cleanup_envelopes_deleted)"
check "health counters.pushes_accepted matches the known count (3)" "3" "$(caps_num pushes_accepted)"
check "health counters.pushes_rejected matches the known count (1)" "1" "$(caps_num pushes_rejected)"
check "health rejected_by_class.too_large is 1 (the §6d 413)" "1" "$(caps_num too_large)"
check "health rejected_by_class.invalid is 0" "0" "$(caps_num invalid)"
check "health rejected_by_class.node_full is 0" "0" "$(caps_num node_full)"
check "health counters.dedup_hits matches the known count (2)" "2" "$(caps_num dedup_hits)"
check "health counters.ttl_sweeps is 1 (the startup sweep)" "1" "$(caps_num ttl_sweeps)"
check "health counters.ttl_swept_envelopes is 0" "0" "$(caps_num ttl_swept_envelopes)"

# Latency: the cached snapshot must answer far under the 50 ms budget. The
# 0.2 s bound leaves CI headroom while still catching any regression that
# makes the endpoint touch SQLite (or worse) per request.
HEALTH_MS="$(curl -sS -o /dev/null -w '%{time_total}' -H 'Host: offgrid.local:8080' "http://127.0.0.1:$PORT_A/api/v1/health")"
check "health answers in well under the 50 ms budget (< 0.2 s here)" "ok" "$(awk -v t="$HEALTH_MS" 'BEGIN {print (t < 0.2) ? "ok" : "slow (" t "s)"}')"

# Wrong methods → 405 with Allow: GET, both diagnostics paths.
code="$(curl -sS -o /dev/null -D "$WORK/hdr_h405" -w '%{http_code}' -H 'Host: offgrid.local:8080' -X POST "http://127.0.0.1:$PORT_A/api/v1/health")"
check "POST /api/v1/health rejected with 405 (§10.1 wrong method)" "405" "$code"
if tr -d '\r' < "$WORK/hdr_h405" | grep -qi '^Allow: GET'; then ALLOW=get; else ALLOW=missing; fi
check "health 405 advertises Allow: GET" "get" "$ALLOW"
code="$(curl -sS -o /dev/null -D "$WORK/hdr_s405" -w '%{http_code}' -H 'Host: offgrid.local:8080' -X POST "http://127.0.0.1:$PORT_A/status")"
check "POST /status rejected with 405" "405" "$code"

# The operator status view: HTML, no JavaScript, rendered from the same
# snapshot (the build identifier is "dev" — the E2E builds without ldflags).
code="$(http GET "http://127.0.0.1:$PORT_A/status")"
check "GET /status -> 200 (§10.7 operator view)" "200" "$code"
curl -sS -o /dev/null -D "$WORK/hdr_status" -H 'Host: offgrid.local:8080' "http://127.0.0.1:$PORT_A/status"
if tr -d '\r' < "$WORK/hdr_status" | grep -qi '^Content-Type: text/html; charset=utf-8'; then CT=ok; else CT=bad; fi
check "status Content-Type is text/html; charset=utf-8" "ok" "$CT"
cp "$WORK/last_body" "$WORK/status_body"
if grep -q 'Node status' "$WORK/status_body"; then H1=present; else H1=missing; fi
check "status page carries its heading" "present" "$H1"
if grep -qF '<code>dev</code>' "$WORK/status_body"; then B=shown; else B=missing; fi
check "status page shows the build identifier (same snapshot as /api/v1/health)" "shown" "$B"
if grep -qi '<script' "$WORK/status_body"; then JS=present; else JS=absent; fi
check "status page requires no JavaScript" "absent" "$JS"
if grep -qF '5000' "$WORK/status_body"; then CAP=shown; else CAP=missing; fi
check "status page shows the envelope capacity" "shown" "$CAP"

# The operator page must not be reachable from the portal: no link (or any
# reference) to /status in index.html nor in any script the portal loads.
code="$(http GET "http://127.0.0.1:$PORT_A/")"
check "GET / -> 200 (portal, for the not-linked check)" "200" "$code"
cp "$WORK/last_body" "$WORK/index_body"
if grep -qF '/status' "$WORK/index_body"; then LINK=yes; else LINK=no; fi
check "portal index.html does not reference /status" "no" "$LINK"
JS_REFS="$(grep -oE 'src="/js/[^"]+"' "$WORK/index_body" | sed -E 's/src="([^"]+)"/\1/' || true)"
NOT_LINKED=yes
for js in $JS_REFS; do
    curl -sS -H 'Host: offgrid.local:8080' "http://127.0.0.1:$PORT_A$js" > "$WORK/portal_js"
    if grep -qF '/status' "$WORK/portal_js"; then NOT_LINKED=no; fi
done
check "no portal script references /status" "yes" "$([ "$NOT_LINKED" = yes ] && echo yes || echo no)"

# Canonical-host middleware covers the diagnostics paths (§10.2); probes are
# unaffected by any of this (§10.2).
code="$(curl -sS -o /dev/null -D "$WORK/hdr_h301" -w '%{http_code}' "http://127.0.0.1:$PORT_A/api/v1/health")"
check "raw-IP GET /api/v1/health redirects with 301" "301" "$code"
if tr -d '\r' < "$WORK/hdr_h301" | grep -qi '^Location: http://offgrid\.local:8080/api/v1/health$'; then LOC=canonical; else LOC=missing; fi
check "health 301 Location preserves the path on the canonical origin" "canonical" "$LOC"
code="$(curl -sS -o /dev/null -D "$WORK/hdr_s301" -w '%{http_code}' "http://127.0.0.1:$PORT_A/status")"
check "raw-IP GET /status redirects with 301" "301" "$code"
if tr -d '\r' < "$WORK/hdr_s301" | grep -qi '^Location: http://offgrid\.local:8080/status$'; then LOC=canonical; else LOC=missing; fi
check "status 301 Location preserves the path on the canonical origin" "canonical" "$LOC"
code="$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT_A/generate_204")"
check "captive probe still answers 302 with the default Host (§10.2)" "302" "$code"

# Privacy (§13 review of the diagnostics surface): neither body may carry any
# envelope id, dest_hint, payload fragment, alias or public key. The bodies
# are the saved health and status snapshots ($WORK/health_body and
# $WORK/status_body), NOT the live last_body (by now the portal index, whose
# alias placeholder says "alice_77" — allowed there, it is UI copy).
PRIVACY=clean
for secret in "$ENV_ID" "$ENV_HINT" "$ENV_PAYLOAD" "alice" "bob" \
    "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=" "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo="; do
    if grep -qF "$secret" "$WORK/health_body" 2>/dev/null; then PRIVACY=leak; fi
    if grep -qF "$secret" "$WORK/status_body" 2>/dev/null; then PRIVACY=leak; fi
done
check "no envelope id, hint, payload, alias or key appears in health or status (§13)" "clean" "$PRIVACY"

# ---------------------------------------------------------------------------
# 12b. §12.1 PWA-lite installability (issue #29): the web app manifest and
#      its icons serve same-origin from the embedded assets, with the exact
#      advertised members and pixel dimensions, the portal HTML carries the
#      manifest link + iOS meta tags, NOTHING references an external URL
#      (zero external assets; CSP img-src 'self' intact), the honest
#      no-offline wording ships in the page, and the canonical-host 301 plus
#      the JSON 404/405 conventions cover the new paths (§10.2, §10.1).
# ---------------------------------------------------------------------------
code="$(http GET "http://127.0.0.1:$PORT_A/manifest.json")"
check "GET /manifest.json -> 200 (§12.1)" "200" "$code"
curl -sS -o /dev/null -D "$WORK/hdr_manifest" -H 'Host: offgrid.local:8080' "http://127.0.0.1:$PORT_A/manifest.json"
if tr -d '\r' < "$WORK/hdr_manifest" | grep -qi '^Content-Type: application/manifest+json'; then CT=ok; else CT=bad; fi
check "manifest Content-Type is application/manifest+json" "ok" "$CT"
if tr -d '\r' < "$WORK/hdr_manifest" | grep -qi '^Cache-Control: no-cache'; then CC=ok; else CC=bad; fi
check "manifest Cache-Control is no-cache (revalidated on every load)" "ok" "$CC"
cp "$WORK/last_body" "$WORK/manifest_body"

node -e '
const fs = require("fs");
const m = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
const checks = [
  ["name", m.name === "Offgrid Messages"],
  ["short_name", m.short_name === "Offgrid"],
  ["start_url is RELATIVE \"/\"", m.start_url === "/"],
  ["scope is \"/\"", m.scope === "/"],
  ["display standalone", m.display === "standalone"],
  ["no serviceworker member", !("serviceworker" in m)],
  ["icons carry 192+512 maskable", Array.isArray(m.icons) && m.icons.length === 2 &&
    m.icons.some(i => i.sizes === "192x192" && i.purpose === "any maskable" && i.type === "image/png") &&
    m.icons.some(i => i.sizes === "512x512" && i.purpose === "any maskable" && i.type === "image/png")],
  ["no absolute URL in the manifest", !/https?:\/\//i.test(JSON.stringify(m))],
];
let bad = null;
for (const [label, pass] of checks) { if (!pass) { bad = label; break; } }
if (bad) { console.error("manifest check failed: " + bad); process.exit(1); }
' "$WORK/manifest_body" || MANIFEST_RC=$?
check "manifest members: name/short_name/relative start_url+scope/standalone/192+512 maskable/no SW/no URL" "0" "${MANIFEST_RC:-0}"

# Icons: PNG magic + IHDR dimension parse (independent of any image tooling),
# exact sizes, image/png content type.
ICON_SPECS="icon-192.png:192 icon-512.png:512 icon-180.png:180"
for spec in $ICON_SPECS; do
    ICON_FILE="${spec%%:*}"; ICON_SIZE="${spec##*:}"
    code="$(http GET "http://127.0.0.1:$PORT_A/icons/$ICON_FILE")"
    check "GET /icons/$ICON_FILE -> 200" "200" "$code"
    cp "$WORK/last_body" "$WORK/icon_body"
    curl -sS -o /dev/null -D "$WORK/hdr_icon" -H 'Host: offgrid.local:8080' "http://127.0.0.1:$PORT_A/icons/$ICON_FILE"
    if tr -d '\r' < "$WORK/hdr_icon" | grep -qi '^Content-Type: image/png'; then CT=ok; else CT=bad; fi
    check "icon $ICON_FILE Content-Type is image/png" "ok" "$CT"
    node -e '
const fs = require("fs");
const b = fs.readFileSync(process.argv[1]);
const magic = Buffer.from([0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a]);
if (!b.subarray(0,8).equals(magic)) process.exit(1);
if (b.toString("ascii",12,16) !== "IHDR") process.exit(1);
const w = b.readUInt32BE(16), h = b.readUInt32BE(20);
const want = Number(process.argv[2]);
process.exit(w === want && h === want ? 0 : 1);
' "$WORK/icon_body" "$ICON_SIZE" || ICON_RC=$?
    check "icon $ICON_FILE is a PNG of exactly ${ICON_SIZE}x${ICON_SIZE} (magic + IHDR)" "0" "${ICON_RC:-0}"
done
code="$(http GET "http://127.0.0.1:$PORT_A/icons/icon-64.png")"
check "GET /icons/icon-64.png (unknown icon) -> JSON 404" "404" "$code"
code="$(curl -sS -o /dev/null -w '%{http_code}' -H 'Host: offgrid.local:8080' -X POST -H 'Content-Type: application/json' --data '{}' "http://127.0.0.1:$PORT_A/manifest.json")"
check "POST /manifest.json -> 405 (wrong method, §10.1)" "405" "$code"

# The portal HTML must carry the manifest link, theme-color and the iOS
# metadata, the honesty note, and NO external URL beyond the canonical §12
# origin reference the §13.4 banner already displays.
code="$(http GET "http://127.0.0.1:$PORT_A/")"
cp "$WORK/last_body" "$WORK/index_pwa"
for marker in '<link rel="manifest" href="/manifest.json">' '<meta name="theme-color"' \
    'apple-mobile-web-app-capable' 'apple-mobile-web-app-status-bar-style' \
    '<link rel="apple-touch-icon" href="/icons/icon-180.png">' \
    'it is a shortcut, not an offline app'; do
    if grep -qF "$marker" "$WORK/index_pwa"; then FOUND=yes; else FOUND=no; fi
    check "portal HTML carries: $marker" "yes" "$FOUND"
done
EXTERNALS="$({ grep -oE 'https?://[^"<[:space:]]+' "$WORK/index_pwa" || true; } | { grep -v '^http://offgrid\.local:8080' || true; } | sort -u | tr '\n' ' ')"
check "no external URL in the portal HTML beyond the canonical origin" "" "$EXTERNALS"
check "no external URL in the manifest" "" "$({ grep -oE 'https?://[^"<[:space:]]+' "$WORK/manifest_body" || true; } | tr '\n' ' ')"
# The icons are binary: audit the SERVED bytes for any URL fragment too
# (grep -a treats them as text; zero matches is the pass).
ICON_URLS=clean
for ICON_FILE in icon-192.png icon-512.png icon-180.png; do
    curl -sS -H 'Host: offgrid.local:8080' "http://127.0.0.1:$PORT_A/icons/$ICON_FILE" -o "$WORK/icon_urlcheck" 2>/dev/null
    if LC_ALL=C grep -qa 'http' "$WORK/icon_urlcheck"; then ICON_URLS=dirty; fi
done
check "no URL fragment in any served icon (zero external assets)" "clean" "$ICON_URLS"

# Canonical-host middleware covers the new paths (§10.2).
code="$(curl -sS -o /dev/null -D "$WORK/hdr_m301" -w '%{http_code}' "http://127.0.0.1:$PORT_A/manifest.json")"
check "raw-IP GET /manifest.json redirects with 301" "301" "$code"
if tr -d '\r' < "$WORK/hdr_m301" | grep -qi '^Location: http://offgrid\.local:8080/manifest\.json$'; then LOC=canonical; else LOC=missing; fi
check "manifest 301 Location preserves the path on the canonical origin" "canonical" "$LOC"
code="$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT_A/icons/icon-192.png")"
check "raw-IP GET /icons/icon-192.png redirects with 301" "301" "$code"

# ---------------------------------------------------------------------------
# 13. §4.4 long-message chunking (issue #24): a 1 KiB message survives the
#     full Alice -> node A -> mule -> node B -> Bob path as ordinary
#     envelopes and reassembles into ONE message at Bob's client. Both
#     endpoints run the SHIPPED SPA engine headlessly
#     (tests/helpers/spa_loader.mjs loads exactly the files index.html
#     serves): the fixture builds real chunk envelopes, the mule carries
#     the exact bytes it pulled, and Bob decrypts + reassembles the
#     envelopes the REAL daemon served. Nodes and mules see nothing new
#     (§4.4 lives inside the box; the §8.2 payload bounds still bind per
#     envelope and are asserted on the SERVED bytes).
#     (Runs after section 12 so the §10.7 counter assertions on node A
#     describe the same aggregate history.)
# ---------------------------------------------------------------------------
log "building the §4.4 1 KiB chunk fixture with the shipped SPA engine"
node "$SCRIPT_DIR/helpers/chunk_e2e.mjs" fixture "$WORK/chunk_fixture.json" >"$WORK/chunk_fixture.log" 2>&1 || {
    log "fixture build failed"; cat "$WORK/chunk_fixture.log" >&2; exit 1;
}
CHUNK_PARTS="$(sed -n 's/^parts=//p' "$WORK/chunk_fixture.log")"
CHUNK_BYTES="$(sed -n 's/^text_bytes=//p' "$WORK/chunk_fixture.log")"
CHUNK_SHA="$(sed -n 's/^text_sha256=//p' "$WORK/chunk_fixture.log")"
check "§4.4 fixture text is exactly 1 KiB (1024 UTF-8 bytes)" "1024" "$CHUNK_BYTES"
check "§4.4 fixture splits into 2..16 envelopes (the §4.4 cap)" \
    "ok" "$([ "$CHUNK_PARTS" -ge 2 ] 2>/dev/null && [ "$CHUNK_PARTS" -le 16 ] && echo ok || echo bad)"

node "$SCRIPT_DIR/helpers/chunk_e2e.mjs" bodies "$WORK/chunk_fixture.json" "$WORK" "$ENV_ID" >/dev/null 2>&1 || {
    log "chunk sync bodies failed to build"; exit 1;
}

# Alice pushes ALL chunk envelopes to node A in one sync (§10.4: their ids
# ride in known_ids — plus the §3 fixture envelope's id, still servable on
# node A — so nothing is pulled back).
code="$(http POST "http://127.0.0.1:$PORT_A/api/v1/sync" "$WORK/alice_push.json")"
check "alice pushes the 1 KiB message as $CHUNK_PARTS chunk envelopes to node A -> 200" "200" "$code"
check "chunk push response pulls nothing back (own ids in known_ids)" "0" "$(json_count_envelopes)"

# The mule pulls everything it does not know from node A and carries the
# SERVED bytes to node B (the §3 fixture envelope is already known to it).
make_sync_body "$WORK/sync_mule_chunk_a.json" "[\"$ENV_ID\"]" "[]"
code="$(http POST "http://127.0.0.1:$PORT_A/api/v1/sync" "$WORK/sync_mule_chunk_a.json")"
check "mule syncs with node A for the chunk envelopes -> 200" "200" "$code"
check "mule pulls exactly $CHUNK_PARTS chunk envelopes from node A" "$CHUNK_PARTS" "$(json_count_envelopes)"
cp "$WORK/last_body" "$WORK/mule_chunk_pull.json"
node "$SCRIPT_DIR/helpers/chunk_e2e.mjs" carry "$WORK/mule_chunk_pull.json" "$WORK/mule_chunk_push.json" >"$WORK/chunk_carry.log" 2>&1
check "mule carries exactly the envelopes it pulled" "$CHUNK_PARTS" "$(sed -n 's/^carried=//p' "$WORK/chunk_carry.log")"
code="$(http POST "http://127.0.0.1:$PORT_B/api/v1/sync" "$WORK/mule_chunk_push.json")"
check "mule drops the chunk envelopes at node B -> 200 (nothing a node would reject)" "200" "$code"

# Bob pulls from node B — known_ids exclude the §3 fixture envelope; the
# expired §6b verbatim envelope is TTL-filtered — so exactly the chunks
# arrive, in the node's own (id-tiebreak) order.
make_sync_body "$WORK/sync_bob_chunk.json" "[\"$ENV_ID\"]" "[]"
code="$(http POST "http://127.0.0.1:$PORT_B/api/v1/sync" "$WORK/sync_bob_chunk.json")"
check "bob pulls from node B -> 200" "200" "$code"
check "bob pulls exactly the $CHUNK_PARTS chunk envelopes" "$CHUNK_PARTS" "$(json_count_envelopes)"
cp "$WORK/last_body" "$WORK/bob_chunk_pull.json"

# Bob's client (the shipped SPA engine): decrypt + reassemble the served
# bytes, fed REVERSED and with one DUPLICATE envelope. The verify mode
# always exits 0; the checks below carry its verdicts.
CHUNK_VERIFY="$(node "$SCRIPT_DIR/helpers/chunk_e2e.mjs" verify "$WORK/chunk_fixture.json" "$WORK/bob_chunk_pull.json" 2>"$WORK/chunk_verify.log" || true)"
check "§4.4 reassembly: every served envelope within the §8.2 payload bounds [248,400]" \
    "ok" "$(printf '%s\n' "$CHUNK_VERIFY" | sed -n 's/^bounds=//p')"
check "§4.4 reassembly: every served envelope is a valid ordinary §3.1 envelope" \
    "ok" "$(printf '%s\n' "$CHUNK_VERIFY" | sed -n 's/^shapes=//p')"
check "§4.4 reassembly: reversed arrival order yields ONE complete message" \
    "ok" "$(printf '%s\n' "$CHUNK_VERIFY" | sed -n 's/^reassembled=//p')"
check "§4.4 reassembly: the duplicated chunk was absorbed (first write wins)" \
    "ok" "$(printf '%s\n' "$CHUNK_VERIFY" | sed -n 's/^duplicates=//p')"
check "§4.4 reassembly: one chunk short stays an incomplete partial (never rendered)" \
    "ok" "$(printf '%s\n' "$CHUNK_VERIFY" | sed -n 's/^nocomplete=//p')"
check "§4.4 reassembly: sha256 of the reassembled text equals the original 1 KiB text" \
    "ok" "$(printf '%s\n' "$CHUNK_VERIFY" | sed -n 's/^sha=//p')"
check "§4.4 reassembly: reassembled text sha256 matches the fixture (E2E, real daemons)" \
    "$CHUNK_SHA" "$(printf '%s\n' "$CHUNK_VERIFY" | sed -n 's/^reassembled_sha256=//p')"

# ---------------------------------------------------------------------------
# 14. §4.5 delivery acknowledgments (issue #25): the ack travels the full
#     multi-node path. Both endpoints run the SHIPPED SPA engine headlessly
#     (tests/helpers/ack_e2e.mjs): Alice pushes a flat and a chunked
#     message into a FRESH node pair (so pull counts are exact), Bob's
#     engine decrypts/reassembles the served bytes and emits exactly ONE
#     signed ack envelope addressed back to Alice's dest_hint — resolving
#     her X25519 key from the node directory by the Ed25519 key her signed
#     message carried (best-effort, §4.5) — and a mule carries the acks
#     back the same way it carries any mail. Alice's engine verifies each
#     ack against her sent record (bound to the recipient's Ed25519 key)
#     and flips the state to delivered. The negative leg starts a third
#     fresh node: an adversarial mule flips a payload character en route
#     and the tampered ack must fail verification at Alice (state stays
#     queued).
# ---------------------------------------------------------------------------
ACK_E2E="$SCRIPT_DIR/helpers/ack_e2e.mjs"

log "building the §4.5 ack fixture with the shipped SPA engine"
node "$ACK_E2E" fixture "$WORK/ack_fixture.json" >"$WORK/ack_fixture.log" 2>&1 || {
    log "ack fixture build failed"; cat "$WORK/ack_fixture.log" >&2; exit 1;
}
ACK_FLAT_ID="$(sed -n 's/^flat_id=//p' "$WORK/ack_fixture.log")"
ACK_CHUNK_PARTS="$(sed -n 's/^chunk_parts=//p' "$WORK/ack_fixture.log")"
ACK_CHUNK_REF="$(sed -n 's/^chunk_ref=//p' "$WORK/ack_fixture.log")"
# Bob's ack-signing Ed25519 public key (derived by the fixture from a fixed
# seed; passed to alice_verify so the sent record binds the expected signer).
BOB_SIGN_PUB="$(node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).bob_sign_pub)' "$WORK/ack_fixture.json")"
check "§4.5 fixture: flat message built with a 64-hex envelope id" \
    "ok" "$(printf '%s' "$ACK_FLAT_ID" | grep -qE '^[0-9a-f]{64}$' && echo ok || echo bad)"
check "§4.5 fixture: chunked message splits into 2..16 envelopes (§4.4 cap)" \
    "ok" "$([ "$ACK_CHUNK_PARTS" -ge 2 ] 2>/dev/null && [ "$ACK_CHUNK_PARTS" -le 16 ] && echo ok || echo bad)"
ACK_ALICE_PUB="$(node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).alice_pub)' "$WORK/ack_fixture.json")"
ACK_ALICE_X25519="$(node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).alice_x25519)' "$WORK/ack_fixture.json")"
ACK_ALICE_REG="{\"alias\":\"alice_ack\",\"pubkey\":\"$ACK_ALICE_PUB\",\"x25519\":\"$ACK_ALICE_X25519\"}"
printf '%s' "$ACK_ALICE_REG" > "$WORK/ack_reg_alice.json"
node "$ACK_E2E" bodies "$WORK/ack_fixture.json" "$WORK" >/dev/null 2>&1

log "starting the §4.5 ack node pair: 127.0.0.1:$PORT_D and 127.0.0.1:$PORT_E (fresh databases)"
"$WORK/dtn-node" -addr "127.0.0.1:$PORT_D" -db "$WORK/node_ack_a.db" >"$WORK/node_ack_a.log" 2>&1 &
DAEMON_D_PID=$!
"$WORK/dtn-node" -addr "127.0.0.1:$PORT_E" -db "$WORK/node_ack_b.db" >"$WORK/node_ack_b.log" 2>&1 &
DAEMON_E_PID=$!
ACK_READY=0
if wait_ready "$PORT_D" && wait_ready "$PORT_E"; then ACK_READY=1; fi
check "ack node pair ready (§4.5 round trip)" "1" "$ACK_READY"
if [ "$ACK_READY" -ne 1 ]; then
    log "--- ack node A log ---"; cat "$WORK/node_ack_a.log" >&2 || true
    log "--- ack node B log ---"; cat "$WORK/node_ack_b.log" >&2 || true
    exit 1
fi

# Alice (the fixture identity) registers on BOTH ack nodes: the ack's
# best-effort resolution reads the directory of the node Bob syncs with.
for PORT in "$PORT_D" "$PORT_E"; do
    code="$(http POST "http://127.0.0.1:$PORT/api/v1/directory" "$WORK/ack_reg_alice.json")"
    check "register alice_ack on ack node (port $PORT) -> 200" "200" "$code"
done

# ---- FLAT round: message out, ONE ack back, state flips to delivered. ----
code="$(http POST "http://127.0.0.1:$PORT_D/api/v1/sync" "$WORK/ack_push_flat.json")"
check "alice pushes the flat message to ack node 1 -> 200" "200" "$code"
check "flat push pulls nothing back (own id in known_ids)" "0" "$(json_count_envelopes)"

make_sync_body "$WORK/ack_mule1_a.json" "[]" "[]"
code="$(http POST "http://127.0.0.1:$PORT_D/api/v1/sync" "$WORK/ack_mule1_a.json")"
check "mule syncs with ack node 1 -> 200" "200" "$code"
check "mule pulls exactly 1 envelope (the flat message)" "1" "$(json_count_envelopes)"
cp "$WORK/last_body" "$WORK/ack_mule_pull1.json"
node "$ACK_E2E" carry "$WORK/ack_mule_pull1.json" "$WORK/ack_mule_push1.json" >/dev/null 2>&1
code="$(http POST "http://127.0.0.1:$PORT_E/api/v1/sync" "$WORK/ack_mule_push1.json")"
check "mule drops the flat message at ack node 2 -> 200" "200" "$code"

make_sync_body "$WORK/ack_bob_pull.json" "[]" "[]"
code="$(http POST "http://127.0.0.1:$PORT_E/api/v1/sync" "$WORK/ack_bob_pull.json")"
check "bob pulls from ack node 2 -> 200" "200" "$code"
check "bob pulls exactly the flat message" "1" "$(json_count_envelopes)"
cp "$WORK/last_body" "$WORK/ack_bob_flat_pull.json"
code="$(http GET "http://127.0.0.1:$PORT_E/api/v1/directory")"
check "bob reads the ack node 2 directory -> 200 (§4.5 best-effort resolution)" "200" "$code"
cp "$WORK/last_body" "$WORK/ack_dir_b.json"

BOB_ACK_FLAT="$(node "$ACK_E2E" bob_ack "$WORK/ack_fixture.json" "$WORK/ack_bob_flat_pull.json" "$WORK/ack_dir_b.json" "$WORK/bob_ack_flat.json" flat 2>"$WORK/ack_bob_flat.log" || true)"
check "§4.5 bob_ack (flat): decrypt, task, reference, dest, ttl and bounds all hold" \
    "ok" "$(printf '%s\n' "$BOB_ACK_FLAT" | sed -n 's/^result=//p')"
check "§4.5 bob_ack (flat): the ack references the message's envelope id" \
    "$ACK_FLAT_ID" "$(printf '%s\n' "$BOB_ACK_FLAT" | sed -n 's/^ack_ref=//p')"
check "§4.5 bob_ack (flat): exactly ONE ack envelope per message (overhead bound)" \
    "1" "$(printf '%s\n' "$BOB_ACK_FLAT" | sed -n 's/^count=//p')"
check "§4.5 bob_ack (flat): TERMINATION — the ack itself yields no ack task" \
    "ok" "$(printf '%s\n' "$BOB_ACK_FLAT" | sed -n 's/^term=//p')"
ACK1_ID="$(node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).envelope.id)' "$WORK/bob_ack_flat.json")"
ACK1_ENV="[$(node -e 'process.stdout.write(JSON.stringify(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).envelope))' "$WORK/bob_ack_flat.json")]"

# Bob's engine hands the ack to HIS node like any outgoing mail (§4.5: it
# rides the next sync; the harness pushes it directly).
make_sync_body "$WORK/ack_bob_push1.json" "[\"$ACK1_ID\"]" "$ACK1_ENV"
code="$(http POST "http://127.0.0.1:$PORT_E/api/v1/sync" "$WORK/ack_bob_push1.json")"
check "bob pushes his ack envelope to ack node 2 -> 200 (an ack is an ordinary envelope)" "200" "$code"

# The ack rides back: mule pulls it (only the flat id is known so far),
# carries it to ack node 1; Alice pulls and her engine flips the state.
make_sync_body "$WORK/ack_mule2_b.json" "[\"$ACK_FLAT_ID\"]" "[]"
code="$(http POST "http://127.0.0.1:$PORT_E/api/v1/sync" "$WORK/ack_mule2_b.json")"
check "mule pulls the ack from ack node 2 -> 200" "200" "$code"
check "mule pulls exactly 1 envelope (the ack)" "1" "$(json_count_envelopes)"
cp "$WORK/last_body" "$WORK/ack_mule_pull2.json"
node "$ACK_E2E" carry "$WORK/ack_mule_pull2.json" "$WORK/ack_mule_push2.json" >/dev/null 2>&1
code="$(http POST "http://127.0.0.1:$PORT_D/api/v1/sync" "$WORK/ack_mule_push2.json")"
check "mule drops the ack at ack node 1 -> 200" "200" "$code"

make_sync_body "$WORK/ack_alice_pull.json" "[\"$ACK_FLAT_ID\"]" "[]"
code="$(http POST "http://127.0.0.1:$PORT_D/api/v1/sync" "$WORK/ack_alice_pull.json")"
check "alice pulls from ack node 1 -> 200" "200" "$code"
check "alice pulls exactly 1 envelope (the ack)" "1" "$(json_count_envelopes)"
cp "$WORK/last_body" "$WORK/ack_alice_flat_pull.json"
ALICE_VERIFY_FLAT="$(node "$ACK_E2E" alice_verify "$WORK/ack_fixture.json" "$WORK/ack_alice_flat_pull.json" "$BOB_SIGN_PUB" 2>"$WORK/ack_verify_flat.log" || true)"
check "§4.5 alice_verify (flat): the served ack decrypts and binds to the sent record" \
    "ok" "$(printf '%s\n' "$ALICE_VERIFY_FLAT" | sed -n 's/^matched=//p')"
check "§4.5 alice_verify (flat): the message state flips to delivered" \
    "delivered" "$(printf '%s\n' "$ALICE_VERIFY_FLAT" | sed -n 's/^state=//p')"

# ---- CHUNKED round: ONE ack at reassembly completion, referencing the
#      agreed id (the LAST chunk's envelope id). ----
code="$(http POST "http://127.0.0.1:$PORT_D/api/v1/sync" "$WORK/ack_push_chunked.json")"
check "alice pushes the chunked message ($ACK_CHUNK_PARTS envelopes) to ack node 1 -> 200" "200" "$code"

ACK_CHUNK_IDS_JSON="$(node -e 'const fx=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));process.stdout.write(JSON.stringify(fx.chunked.envelopes.map((e)=>e.id)))' "$WORK/ack_fixture.json")"
# The mule knows the flat message and the first ack; the chunks are new cargo.
MULE_KNOWS="[\"$ACK_FLAT_ID\",\"$ACK1_ID\",${ACK_CHUNK_IDS_JSON:1}"
make_sync_body "$WORK/ack_mule3_a.json" "[\"$ACK_FLAT_ID\",\"$ACK1_ID\"]" "[]"
code="$(http POST "http://127.0.0.1:$PORT_D/api/v1/sync" "$WORK/ack_mule3_a.json")"
check "mule syncs with ack node 1 for the chunk envelopes -> 200" "200" "$code"
check "mule pulls exactly $ACK_CHUNK_PARTS chunk envelopes" "$ACK_CHUNK_PARTS" "$(json_count_envelopes)"
cp "$WORK/last_body" "$WORK/ack_mule_pull3.json"
node "$ACK_E2E" carry "$WORK/ack_mule_pull3.json" "$WORK/ack_mule_push3.json" >/dev/null 2>&1
code="$(http POST "http://127.0.0.1:$PORT_E/api/v1/sync" "$WORK/ack_mule_push3.json")"
check "mule drops the chunk envelopes at ack node 2 -> 200" "200" "$code"

# Bob knows the flat message and the first ack; the chunks are new to him.
make_sync_body "$WORK/ack_bob_pull2.json" "[\"$ACK_FLAT_ID\",\"$ACK1_ID\"]" "[]"
code="$(http POST "http://127.0.0.1:$PORT_E/api/v1/sync" "$WORK/ack_bob_pull2.json")"
check "bob pulls from ack node 2 -> 200" "200" "$code"
check "bob pulls exactly the $ACK_CHUNK_PARTS chunk envelopes" "$ACK_CHUNK_PARTS" "$(json_count_envelopes)"
cp "$WORK/last_body" "$WORK/ack_bob_chunk_pull.json"
BOB_ACK_CHUNKED="$(node "$ACK_E2E" bob_ack "$WORK/ack_fixture.json" "$WORK/ack_bob_chunk_pull.json" "$WORK/ack_dir_b.json" "$WORK/bob_ack_chunked.json" chunked 2>"$WORK/ack_bob_chunk.log" || true)"
check "§4.5 bob_ack (chunked): reassembly completed and every ack check holds" \
    "ok" "$(printf '%s\n' "$BOB_ACK_CHUNKED" | sed -n 's/^result=//p')"
check "§4.5 bob_ack (chunked): the ack references the LAST chunk's envelope id (§4.5 agreed id)" \
    "$ACK_CHUNK_REF" "$(printf '%s\n' "$BOB_ACK_CHUNKED" | sed -n 's/^ack_ref=//p')"
check "§4.5 bob_ack (chunked): exactly ONE ack for the whole message" \
    "1" "$(printf '%s\n' "$BOB_ACK_CHUNKED" | sed -n 's/^count=//p')"
ACK2_ID="$(node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).envelope.id)' "$WORK/bob_ack_chunked.json")"
ACK2_ENV="[$(node -e 'process.stdout.write(JSON.stringify(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).envelope))' "$WORK/bob_ack_chunked.json")]"
make_sync_body "$WORK/ack_bob_push2.json" "[\"$ACK2_ID\"]" "$ACK2_ENV"
code="$(http POST "http://127.0.0.1:$PORT_E/api/v1/sync" "$WORK/ack_bob_push2.json")"
check "bob pushes the chunked message's ack to ack node 2 -> 200" "200" "$code"

# The mule still does not know ack2 (it only carried flat, ack1, chunks).
make_sync_body "$WORK/ack_mule4_b.json" "$MULE_KNOWS" "[]"
code="$(http POST "http://127.0.0.1:$PORT_E/api/v1/sync" "$WORK/ack_mule4_b.json")"
check "mule pulls the chunked message's ack from ack node 2 -> 200" "200" "$code"
check "mule pulls exactly 1 envelope (the second ack)" "1" "$(json_count_envelopes)"
cp "$WORK/last_body" "$WORK/ack_mule_pull4.json"
node "$ACK_E2E" carry "$WORK/ack_mule_pull4.json" "$WORK/ack_mule_push4.json" >/dev/null 2>&1
code="$(http POST "http://127.0.0.1:$PORT_D/api/v1/sync" "$WORK/ack_mule_push4.json")"
check "mule drops the second ack at ack node 1 -> 200" "200" "$code"

make_sync_body "$WORK/ack_alice_pull2.json" "$MULE_KNOWS" "[]"
code="$(http POST "http://127.0.0.1:$PORT_D/api/v1/sync" "$WORK/ack_alice_pull2.json")"
check "alice pulls from ack node 1 -> 200" "200" "$code"
check "alice pulls exactly 1 envelope (the chunked message's ack)" "1" "$(json_count_envelopes)"
cp "$WORK/last_body" "$WORK/ack_alice_chunk_pull.json"
ALICE_VERIFY_CHUNKED="$(node "$ACK_E2E" alice_verify "$WORK/ack_fixture.json" "$WORK/ack_alice_chunk_pull.json" "$BOB_SIGN_PUB" 2>"$WORK/ack_verify_chunk.log" || true)"
check "§4.5 alice_verify (chunked): the served ack binds to the sent record" \
    "ok" "$(printf '%s\n' "$ALICE_VERIFY_CHUNKED" | sed -n 's/^matched=//p')"
check "§4.5 alice_verify (chunked): the message state flips to delivered" \
    "delivered" "$(printf '%s\n' "$ALICE_VERIFY_CHUNKED" | sed -n 's/^state=//p')"

# ---- Negative: an adversarial mule tampers with the ack payload en route.
#      A fresh node carries the tampered bytes blindly (same id: admission
#      and dedup are unchanged) and Alice's engine MUST reject them.
#      Re-pulling with MULE_KNOWS yields ack2 again: the node still serves
#      it (pulls are stateless; nothing about the original is consumed). ----
make_sync_body "$WORK/ack_mule5_b.json" "$MULE_KNOWS" "[]"
code="$(http POST "http://127.0.0.1:$PORT_E/api/v1/sync" "$WORK/ack_mule5_b.json")"
check "adversarial mule re-pulls the chunked ack from ack node 2 -> 200" "200" "$code"
check "adversarial mule pulls exactly 1 envelope (the ack)" "1" "$(json_count_envelopes)"
cp "$WORK/last_body" "$WORK/ack_mule_pull5.json"
node "$ACK_E2E" tamper "$WORK/ack_mule_pull5.json" "$WORK/ack_tampered.json" >/dev/null 2>&1

stop_daemon "$DAEMON_D_PID"
DAEMON_D_PID=""
stop_daemon "$DAEMON_E_PID"
DAEMON_E_PID=""

log "starting the tamper node on 127.0.0.1:$PORT_C with a fresh database (§4.5 negative)"
"$WORK/dtn-node" -addr "127.0.0.1:$PORT_C" -db "$WORK/node_ack_tamper.db" >"$WORK/node_ack_tamper.log" 2>&1 &
DAEMON_C_PID=$!
TAMPER_READY=0
if wait_ready "$PORT_C"; then TAMPER_READY=1; fi
check "tamper node ready" "1" "$TAMPER_READY"
TAMPER_PUSH="[$(cat "$WORK/ack_tampered.json")]"
make_sync_body "$WORK/ack_tamper_push.json" "[]" "$TAMPER_PUSH"
code="$(http POST "http://127.0.0.1:$PORT_C/api/v1/sync" "$WORK/ack_tamper_push.json")"
check "the tampered ack is admitted (an ordinary envelope: id and shape unchanged) -> 200" "200" "$code"
make_sync_body "$WORK/ack_tamper_pull.json" "[]" "[]"
code="$(http POST "http://127.0.0.1:$PORT_C/api/v1/sync" "$WORK/ack_tamper_pull.json")"
check "alice pulls the TAMPERED ack from the tamper node -> 200" "200" "$code"
check "tamper node serves exactly the tampered ack" "1" "$(json_count_envelopes)"
cp "$WORK/last_body" "$WORK/ack_alice_tamper_pull.json"
ALICE_VERIFY_TAMPER="$(node "$ACK_E2E" alice_verify "$WORK/ack_fixture.json" "$WORK/ack_alice_tamper_pull.json" "$BOB_SIGN_PUB" 2>"$WORK/ack_verify_tamper.log" || true)"
check "§4.5 negative: the tampered ack FAILS verification at Alice (Poly1305 MAC)" \
    "fail" "$(printf '%s\n' "$ALICE_VERIFY_TAMPER" | sed -n 's/^decrypted=//p')"
check "§4.5 negative: no delivery signal — the state stays queued" \
    "queued" "$(printf '%s\n' "$ALICE_VERIFY_TAMPER" | sed -n 's/^state=//p')"

stop_daemon "$DAEMON_C_PID"
DAEMON_C_PID=""

# ---------------------------------------------------------------------------
# 15. §6.1 rotating dest_hint (issue #26): the full Alice -> node A -> mule
#     -> node B -> Bob path with ROTATING hints, both endpoints running the
#     SHIPPED SPA engine headlessly (tests/helpers/hint_e2e.mjs; injected
#     clocks everywhere a boundary matters, so the leg is wall-clock safe):
#       - Alice derives the dest_hint from the SERVER-SET epoch of Bob's
#         directory entry (the node stamps epoch = floor(now/86400) at
#         upsert and IGNORES a spoofed client-supplied epoch member —
#         blindness preserved);
#       - GET /api/v1/directory carries the additive epoch member;
#       - Bob's engine recognizes and DECRYPTS mail addressed to the
#         current epoch (§15.7 h side: candidate set {legacy, E, E-1});
#       - an envelope addressed to the PREVIOUS epoch's hint (minted just
#         before a boundary) is still delivered (§15.7 g: one-boundary
#         window, no message loss) — simulated by advancing Bob's observed
#         epoch/clock one day;
#       - an envelope with the pre-1.6 STATIC hint is delivered during the
#         transition window (§15.7 h);
#       - a simulated post-deadline build (clock = HINT_TRANSITION_DEADLINE
#         + 1 day) no longer recognizes the static hint: the same legacy
#         envelope classifies as FOREIGN cargo and is never decrypted
#         (§15.7 i) — while the rotating candidates keep working.
# ---------------------------------------------------------------------------
HINT_E2E="$SCRIPT_DIR/helpers/hint_e2e.mjs"
NOW_T="$(date +%s)"
HINT_EPOCH_T="$((NOW_T / 86400))"
HINT_DEADLINE=1795996800   # §6.1 HINT_TRANSITION_DEADLINE = 2026-11-30T00:00:00Z
POST_DEADLINE_T="$((HINT_DEADLINE + 86400))"
POST_DEADLINE_EPOCH="$((POST_DEADLINE_T / 86400))"
# The during-window legacy leg is only assertable while the real clock is
# inside the §6.1 window; past the deadline the static candidate is dropped
# by design and the expectation flips (the post-deadline leg below stays
# deterministic either way via its injected clock).
LEGACY_EXPECTED_CLASS="mine"
if [ "$NOW_T" -ge "$HINT_DEADLINE" ]; then LEGACY_EXPECTED_CLASS="foreign"; fi

log "building the §6.1 rotating-hint fixture with the shipped SPA engine (clock = $NOW_T, epoch $HINT_EPOCH_T)"
node "$HINT_E2E" fixture "$WORK/hint_fixture.json" "$NOW_T" >"$WORK/hint_fixture.log" 2>&1 || {
    log "hint fixture build failed"; cat "$WORK/hint_fixture.log" >&2; exit 1;
}
FIX_EPOCH="$(sed -n 's/^epoch=//p' "$WORK/hint_fixture.log")"
FIX_HINT_CUR="$(sed -n 's/^hint_current=//p' "$WORK/hint_fixture.log")"
FIX_HINT_PREV="$(sed -n 's/^hint_prev=//p' "$WORK/hint_fixture.log")"
FIX_HINT_LEGACY="$(sed -n 's/^hint_legacy=//p' "$WORK/hint_fixture.log")"
check "§6.1 fixture epoch matches the harness epoch math" "$HINT_EPOCH_T" "$FIX_EPOCH"
check "§6.1 fixture: the three Bob hints are pairwise distinct" \
    "3" "$(printf '%s\n' "$FIX_HINT_CUR" "$FIX_HINT_PREV" "$FIX_HINT_LEGACY" | sort -u | wc -l | tr -d ' ')"

# Registration: Bob's body carries a SPOOFED epoch member the node must
# ignore (the epoch is server-set at upsert, §6.1/§10.3).
node -e 'const fx=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));require("fs").writeFileSync(process.argv[2],JSON.stringify(fx.alice_reg))' "$WORK/hint_fixture.json" "$WORK/hint_reg_alice.json"
node -e 'const fx=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));require("fs").writeFileSync(process.argv[2],JSON.stringify(fx.bob_reg))' "$WORK/hint_fixture.json" "$WORK/hint_reg_bob.json"

log "starting the §6.1 hint node pair: 127.0.0.1:$PORT_D and 127.0.0.1:$PORT_E (fresh databases)"
"$WORK/dtn-node" -addr "127.0.0.1:$PORT_D" -db "$WORK/node_hint_a.db" >"$WORK/node_hint_a.log" 2>&1 &
DAEMON_D_PID=$!
"$WORK/dtn-node" -addr "127.0.0.1:$PORT_E" -db "$WORK/node_hint_b.db" >"$WORK/node_hint_b.log" 2>&1 &
DAEMON_E_PID=$!
HINT_READY=0
if wait_ready "$PORT_D" && wait_ready "$PORT_E"; then HINT_READY=1; fi
check "hint node pair ready (§6.1 round trip)" "1" "$HINT_READY"
if [ "$HINT_READY" -ne 1 ]; then
    log "--- hint node A log ---"; cat "$WORK/node_hint_a.log" >&2 || true
    log "--- hint node B log ---"; cat "$WORK/node_hint_b.log" >&2 || true
    exit 1
fi

for PORT in "$PORT_D" "$PORT_E"; do
    code="$(http POST "http://127.0.0.1:$PORT/api/v1/directory" "$WORK/hint_reg_alice.json")"
    check "register alice_hint on hint node (port $PORT) -> 200" "200" "$code"
    code="$(http POST "http://127.0.0.1:$PORT/api/v1/directory" "$WORK/hint_reg_bob.json")"
    check "register bob_hint (with a spoofed epoch member) on hint node (port $PORT) -> 200" "200" "$code"
done

# Directory GET carries the additive epoch member, set from the NODE clock
# and unaffected by the spoofed client member.
code="$(http GET "http://127.0.0.1:$PORT_E/api/v1/directory")"
check "GET directory on hint node B -> 200" "200" "$code"
if grep -q '"epoch":' "$WORK/last_body"; then DEPOCH=present; else DEPOCH=absent; fi
check "directory entries carry the additive epoch member (§6.1)" "present" "$DEPOCH"
cp "$WORK/last_body" "$WORK/hint_dir_b.json"
BOB_DIR_EPOCH="$(node -e 'const d=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));const e=d.find(x=>x&&x.alias==="bob_hint");process.stdout.write(e&&typeof e.epoch==="number"?String(e.epoch):"missing")' "$WORK/hint_dir_b.json")"
check "bob's directory epoch is the SERVER-SET floor(node now / 86400), not the spoofed value" \
    "$HINT_EPOCH_T" "$BOB_DIR_EPOCH"

# Capabilities: the additive §6.1 members on a served document.
code="$(http GET "http://127.0.0.1:$PORT_E/api/v1/capabilities")"
check "GET capabilities on hint node B -> 200" "200" "$code"
cp "$WORK/last_body" "$WORK/hint_caps.json"
check "capabilities expose hint_epoch_seconds=86400 and an integer hint_epoch_current (§6.1)" \
    "ok" "$(node "$HINT_E2E" caps "$WORK/hint_caps.json" | sed -n 's/^result=//p')"

# ---- Leg 1 (current epoch): Alice addresses hint(entry.epoch); Bob
#      recognizes and decrypts at observed epoch E. ----
code="$(http GET "http://127.0.0.1:$PORT_D/api/v1/directory")"
check "alice reads the hint node A directory -> 200 (sender derives the epoch from the entry, §6.1)" "200" "$code"
cp "$WORK/last_body" "$WORK/hint_dir_a.json"
node "$HINT_E2E" send "$WORK/hint_fixture.json" "$WORK/hint_dir_a.json" "$WORK/hint_send_cur.json" current "$NOW_T" >"$WORK/hint_send_cur.log" 2>&1
check "§6.1 send (current): alice's engine used the entry's epoch" "$HINT_EPOCH_T" "$(sed -n 's/^used_epoch=//p' "$WORK/hint_send_cur.log")"
check "§6.1 send (current): the envelope carries exactly the engine's hint(E)" \
    "$FIX_HINT_CUR" "$(sed -n 's/^dest_hint=//p' "$WORK/hint_send_cur.log")"
code="$(http POST "http://127.0.0.1:$PORT_D/api/v1/sync" "$WORK/hint_send_cur.json")"
check "alice pushes the rotating-hint envelope to hint node A -> 200" "200" "$code"
CUR_ID="$(node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).push_envelopes[0].id)' "$WORK/hint_send_cur.json")"

make_sync_body "$WORK/hint_mule_a1.json" "[]" "[]"
code="$(http POST "http://127.0.0.1:$PORT_D/api/v1/sync" "$WORK/hint_mule_a1.json")"
check "mule pulls exactly 1 envelope (the current-epoch mail) from hint node A" "1" "$(json_count_envelopes)"
cp "$WORK/last_body" "$WORK/hint_mule_pull1.json"
node "$ACK_E2E" carry "$WORK/hint_mule_pull1.json" "$WORK/hint_mule_push1.json" >/dev/null 2>&1
code="$(http POST "http://127.0.0.1:$PORT_E/api/v1/sync" "$WORK/hint_mule_push1.json")"
check "mule drops the current-epoch envelope at hint node B -> 200" "200" "$code"

make_sync_body "$WORK/hint_bob_pull1.json" "[]" "[]"
code="$(http POST "http://127.0.0.1:$PORT_E/api/v1/sync" "$WORK/hint_bob_pull1.json")"
check "bob pulls exactly the current-epoch envelope from hint node B" "1" "$(json_count_envelopes)"
cp "$WORK/last_body" "$WORK/hint_bob_pull1.json"
BOB_CUR="$(node "$HINT_E2E" bob_check "$WORK/hint_fixture.json" "$WORK/hint_bob_pull1.json" "$HINT_EPOCH_T" "$NOW_T" 2>"$WORK/hint_bob_cur.log" || true)"
check "§6.1 bob (current epoch): the envelope is classified as MINE" "mine" "$(printf '%s\n' "$BOB_CUR" | sed -n 's/^classified=//p')"
check "§6.1 bob (current epoch): the envelope decrypts and verifies" "ok" "$(printf '%s\n' "$BOB_CUR" | sed -n 's/^decrypted=//p')"

# ---- Leg 2 (epoch boundary, §15.7 g): Bob's session advances one day
#      (observed epoch E+1, injected clock NOW+86400); the SAME envelope —
#      minted for E and in flight across the boundary — must still arrive. ----
BOB_BOUNDARY="$(node "$HINT_E2E" bob_check "$WORK/hint_fixture.json" "$WORK/hint_bob_pull1.json" "$((HINT_EPOCH_T + 1))" "$((NOW_T + 86400))" 2>"$WORK/hint_bob_boundary.log" || true)"
check "§6.1 bob across the boundary (observed E+1): the E-addressed envelope is still MINE" \
    "mine" "$(printf '%s\n' "$BOB_BOUNDARY" | sed -n 's/^classified=//p')"
check "§6.1 bob across the boundary: no message loss — it decrypts" \
    "ok" "$(printf '%s\n' "$BOB_BOUNDARY" | sed -n 's/^decrypted=//p')"

# ---- Leg 3 (previous epoch): an envelope addressed to hint(E-1) — minted
#      just before a boundary — is delivered while Bob observes E. ----
node "$HINT_E2E" send "$WORK/hint_fixture.json" "$WORK/hint_dir_a.json" "$WORK/hint_send_prev.json" prev "$NOW_T" >"$WORK/hint_send_prev.log" 2>&1
check "§6.1 send (prev): alice's engine used epoch E-1" "$((HINT_EPOCH_T - 1))" "$(sed -n 's/^used_epoch=//p' "$WORK/hint_send_prev.log")"
check "§6.1 send (prev): the envelope carries exactly the engine's hint(E-1)" \
    "$FIX_HINT_PREV" "$(sed -n 's/^dest_hint=//p' "$WORK/hint_send_prev.log")"
code="$(http POST "http://127.0.0.1:$PORT_D/api/v1/sync" "$WORK/hint_send_prev.json")"
check "alice pushes the previous-epoch envelope to hint node A -> 200" "200" "$code"
PREV_ID="$(node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).push_envelopes[0].id)' "$WORK/hint_send_prev.json")"

make_sync_body "$WORK/hint_mule_a2.json" "[\"$CUR_ID\"]" "[]"
code="$(http POST "http://127.0.0.1:$PORT_D/api/v1/sync" "$WORK/hint_mule_a2.json")"
check "mule pulls exactly 1 envelope (the previous-epoch mail) from hint node A" "1" "$(json_count_envelopes)"
cp "$WORK/last_body" "$WORK/hint_mule_pull2.json"
node "$ACK_E2E" carry "$WORK/hint_mule_pull2.json" "$WORK/hint_mule_push2.json" >/dev/null 2>&1
code="$(http POST "http://127.0.0.1:$PORT_E/api/v1/sync" "$WORK/hint_mule_push2.json")"
check "mule drops the previous-epoch envelope at hint node B -> 200" "200" "$code"

make_sync_body "$WORK/hint_bob_pull2.json" "[\"$CUR_ID\"]" "[]"
code="$(http POST "http://127.0.0.1:$PORT_E/api/v1/sync" "$WORK/hint_bob_pull2.json")"
check "bob pulls exactly the previous-epoch envelope from hint node B" "1" "$(json_count_envelopes)"
cp "$WORK/last_body" "$WORK/hint_bob_pull2.json"
BOB_PREV="$(node "$HINT_E2E" bob_check "$WORK/hint_fixture.json" "$WORK/hint_bob_pull2.json" "$HINT_EPOCH_T" "$NOW_T" 2>"$WORK/hint_bob_prev.log" || true)"
check "§6.1 bob (previous epoch): hint(E-1) mail is classified as MINE during the window" \
    "mine" "$(printf '%s\n' "$BOB_PREV" | sed -n 's/^classified=//p')"
check "§6.1 bob (previous epoch): the envelope decrypts" \
    "ok" "$(printf '%s\n' "$BOB_PREV" | sed -n 's/^decrypted=//p')"

# ---- Leg 4 (legacy static hint, §15.7 h): a pre-1.6 sender addresses the
#      §6.1 static hint; during the transition window it is delivered. ----
node "$HINT_E2E" send "$WORK/hint_fixture.json" "$WORK/hint_dir_a.json" "$WORK/hint_send_legacy.json" legacy "$NOW_T" >"$WORK/hint_send_legacy.log" 2>&1
check "§6.1 send (legacy): no epoch used — the pre-1.6 static derivation" \
    "none" "$(sed -n 's/^used_epoch=//p' "$WORK/hint_send_legacy.log")"
check "§6.1 send (legacy): the envelope carries exactly the static hint" \
    "$FIX_HINT_LEGACY" "$(sed -n 's/^dest_hint=//p' "$WORK/hint_send_legacy.log")"
code="$(http POST "http://127.0.0.1:$PORT_D/api/v1/sync" "$WORK/hint_send_legacy.json")"
check "the pre-1.6 sender pushes the static-hint envelope to hint node A -> 200" "200" "$code"

make_sync_body "$WORK/hint_mule_a3.json" "[\"$CUR_ID\",\"$PREV_ID\"]" "[]"
code="$(http POST "http://127.0.0.1:$PORT_D/api/v1/sync" "$WORK/hint_mule_a3.json")"
check "mule pulls exactly 1 envelope (the static-hint mail) from hint node A" "1" "$(json_count_envelopes)"
cp "$WORK/last_body" "$WORK/hint_mule_pull3.json"
node "$ACK_E2E" carry "$WORK/hint_mule_pull3.json" "$WORK/hint_mule_push3.json" >/dev/null 2>&1
code="$(http POST "http://127.0.0.1:$PORT_E/api/v1/sync" "$WORK/hint_mule_push3.json")"
check "mule drops the static-hint envelope at hint node B -> 200" "200" "$code"

make_sync_body "$WORK/hint_bob_pull3.json" "[\"$CUR_ID\",\"$PREV_ID\"]" "[]"
code="$(http POST "http://127.0.0.1:$PORT_E/api/v1/sync" "$WORK/hint_bob_pull3.json")"
check "bob pulls exactly the static-hint envelope from hint node B" "1" "$(json_count_envelopes)"
cp "$WORK/last_body" "$WORK/hint_bob_pull3.json"
BOB_LEGACY="$(node "$HINT_E2E" bob_check "$WORK/hint_fixture.json" "$WORK/hint_bob_pull3.json" "$HINT_EPOCH_T" "$NOW_T" 2>"$WORK/hint_bob_legacy.log" || true)"
check "§6.1 bob (legacy, during the window): expectation honors the real clock vs the deadline" \
    "$LEGACY_EXPECTED_CLASS" "$(printf '%s\n' "$BOB_LEGACY" | sed -n 's/^classified=//p')"

# ---- Leg 5 (post-deadline, §15.7 i): a simulated build AFTER
#      HINT_TRANSITION_DEADLINE (injected clock = deadline + 1 day) no
#      longer recognizes the static hint: the SAME envelope is foreign
#      cargo, never decrypted — while the rotating candidates keep working. ----
BOB_POSTDEADLINE="$(node "$HINT_E2E" bob_check "$WORK/hint_fixture.json" "$WORK/hint_bob_pull3.json" "$POST_DEADLINE_EPOCH" "$POST_DEADLINE_T" 2>"$WORK/hint_bob_postdeadline.log" || true)"
check "§6.1 bob after the simulated deadline: the legacy envelope is FOREIGN cargo" \
    "foreign" "$(printf '%s\n' "$BOB_POSTDEADLINE" | sed -n 's/^classified=//p')"
check "§6.1 bob after the simulated deadline: never decrypted (silently not mine, §6.1)" \
    "fail" "$(printf '%s\n' "$BOB_POSTDEADLINE" | sed -n 's/^decrypted=//p')"

stop_daemon "$DAEMON_D_PID"
DAEMON_D_PID=""
stop_daemon "$DAEMON_E_PID"
DAEMON_E_PID=""

# ---------------------------------------------------------------------------
# 16. §4.6 prekey bundles — forward secrecy (issue #27): the full Alice ->
#     node -> mule -> node -> Bob path with a PREKEY-published recipient,
#     both endpoints running the SHIPPED SPA engine headlessly
#     (tests/helpers/prekey_e2e.mjs):
#       - Bob registers WITH a bundle (the node admits it blind and the
#         directory GET round-trips it VERBATIM, ≤ 2 KiB, §10.3);
#       - Alice's engine picks a random ONE-TIME prekey from the SERVED
#         bundle as the box target while dest_hint stays derived from Bob's
#         STABLE identity key (hint_source=identity, §6.1 note);
#       - delivery + decrypt through the prekey trial path (opened_with
#         opk:...) and the OPK secret is wiped — the §4.6 FS event;
#       - the CAPTURED-TRAFFIC leg: the exact served envelope bytes are
#         re-decrypted by the harness with (a) an attacker view holding
#         ONLY Bob's extracted long-term identity secret and (b) Bob's
#         post-wipe device state — BOTH must fail (the issue's acceptance
#         criterion, proven end to end over real daemons);
#       - old-client → new recipient: an envelope addressed to Bob's
#         IDENTITY key (what a pre-1.7 sender emits) still opens through
#         the permanent identity trial path (no forward secrecy, the
#         documented transition tradeoff);
#       - new sender → legacy recipient: Alice's entry carries NO prekeys,
#         so the §4.6 sender rule falls back to identity addressing and
#         delivers;
#       - replenish: Bob's fixture stock carries a stale SPK anchor, so the
#         sync-time check triggers rotation — the fresh signed bundle is
#         published through the ORDINARY directory upsert, and the served
#         entry afterwards carries the NEW spk with the old batch gone.
# ---------------------------------------------------------------------------
PREKEY_E2E="$SCRIPT_DIR/helpers/prekey_e2e.mjs"
NOW_P="$(date +%s)"
PREKEY_EPOCH_P="$((NOW_P / 86400))"

log "building the §4.6 prekey fixture with the shipped SPA engine (clock = $NOW_P)"
node "$PREKEY_E2E" fixture "$WORK/prekey_fixture.json" "$NOW_P" >"$WORK/prekey_fixture.log" 2>&1 || {
    log "prekey fixture build failed"; cat "$WORK/prekey_fixture.log" >&2; exit 1;
}
check "§4.6 fixture built (deterministic Bob, stale-SPK stock, bundle signed)" \
    "ok" "$(sed -n 's/^RESULT=//p' "$WORK/prekey_fixture.log")"
PREKEY_BOB_OPKS="$(sed -n 's/^bob_opks=//p' "$WORK/prekey_fixture.log")"
check "§4.6 fixture: Bob's bundle carries the target OPK batch (12, within 8..16)" \
    "12" "$PREKEY_BOB_OPKS"
PREKEY_BUNDLE_BYTES="$(sed -n 's/^bundle_bytes=//p' "$WORK/prekey_fixture.log")"
check "§4.6 fixture: the serialized bundle is within the 2 KiB admission cap (§10.3)" \
    "ok" "$([ "$PREKEY_BUNDLE_BYTES" -le 2048 ] 2>/dev/null && echo ok || echo bad)"
BOB_HINT_CUR_P="$(node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).bob_hint_current)' "$WORK/prekey_fixture.json")"
ALICE_HINT_CUR_P="$(node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).alice_hint_current)' "$WORK/prekey_fixture.json")"

node -e 'const fx=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));require("fs").writeFileSync(process.argv[2],JSON.stringify(fx.alice_reg))' "$WORK/prekey_fixture.json" "$WORK/prekey_reg_alice.json"
node -e 'const fx=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));require("fs").writeFileSync(process.argv[2],JSON.stringify(fx.bob_reg))' "$WORK/prekey_fixture.json" "$WORK/prekey_reg_bob.json"

log "starting the §4.6 prekey node pair: 127.0.0.1:$PORT_D and 127.0.0.1:$PORT_E (fresh databases)"
"$WORK/dtn-node" -addr "127.0.0.1:$PORT_D" -db "$WORK/node_prekey_a.db" >"$WORK/node_prekey_a.log" 2>&1 &
DAEMON_D_PID=$!
"$WORK/dtn-node" -addr "127.0.0.1:$PORT_E" -db "$WORK/node_prekey_b.db" >"$WORK/node_prekey_b.log" 2>&1 &
DAEMON_E_PID=$!
PREKEY_READY=0
if wait_ready "$PORT_D" && wait_ready "$PORT_E"; then PREKEY_READY=1; fi
check "prekey node pair ready (§4.6 round trip)" "1" "$PREKEY_READY"
if [ "$PREKEY_READY" -ne 1 ]; then
    log "--- prekey node A log ---"; cat "$WORK/node_prekey_a.log" >&2 || true
    log "--- prekey node B log ---"; cat "$WORK/node_prekey_b.log" >&2 || true
    exit 1
fi

# Registration: Bob's body carries the prekeys bundle — the node must admit
# it blind (shape only, no signature verification, §1/§10.3) on BOTH nodes.
for PORT in "$PORT_D" "$PORT_E"; do
    code="$(http POST "http://127.0.0.1:$PORT/api/v1/directory" "$WORK/prekey_reg_alice.json")"
    check "register alice_fs (bundle-less) on prekey node (port $PORT) -> 200" "200" "$code"
    code="$(http POST "http://127.0.0.1:$PORT/api/v1/directory" "$WORK/prekey_reg_bob.json")"
    check "register bob_prekey WITH the prekeys bundle on prekey node (port $PORT) -> 200" "200" "$code"
done

# The directory GET round-trips the bundle verbatim (additive member).
code="$(http GET "http://127.0.0.1:$PORT_D/api/v1/directory")"
check "GET directory on prekey node A -> 200" "200" "$code"
cp "$WORK/last_body" "$WORK/prekey_dir_a.json"
if grep -q '"prekeys":' "$WORK/prekey_dir_a.json"; then BUNDLE=roundtripped; else BUNDLE=missing; fi
check "the served directory carries Bob's prekeys bundle (§10.3 additive member)" "roundtripped" "$BUNDLE"
FIX_SPK="$(node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).bob_bundle.spk)' "$WORK/prekey_fixture.json")"
if grep -qF "$FIX_SPK" "$WORK/prekey_dir_a.json"; then SPK=served; else SPK=missing; fi
check "the served bundle keeps Bob's signed spk verbatim (stored VERBATIM, §9)" "served" "$SPK"
if grep -q '"prekeys":' "$WORK/last_body"; then :; fi
code="$(http GET "http://127.0.0.1:$PORT_E/api/v1/directory")"
check "GET directory on prekey node B -> 200" "200" "$code"
cp "$WORK/last_body" "$WORK/prekey_dir_b.json"
if grep -qF "$FIX_SPK" "$WORK/prekey_dir_b.json"; then SPK2=served; else SPK2=missing; fi
check "both nodes serve the same bundle (upsert keyed by pubkey)" "served" "$SPK2"

# ---- Leg A: prekey-addressed mail, wipe-on-use, then the captured-
#      traffic attack. Alice reads node A's directory (the sender's view). ----
node "$PREKEY_E2E" send "$WORK/prekey_fixture.json" "$WORK/prekey_dir_a.json" "$WORK/prekey_send_a.json" prekey bob "$NOW_P" >"$WORK/prekey_send_a.log" 2>&1
check "§4.6 send (prekey): the engine targeted a ONE-TIME prekey" "opk" "$(sed -n 's/^target=//p' "$WORK/prekey_send_a.log")"
check "§4.6 send (prekey): dest_hint source is the STABLE identity key (§6.1 note)" \
    "identity" "$(sed -n 's/^hint_source=//p' "$WORK/prekey_send_a.log")"
check "§4.6 send (prekey): dest_hint is exactly hint_E(Bob's identity key)" \
    "$BOB_HINT_CUR_P" "$(sed -n 's/^dest_hint=//p' "$WORK/prekey_send_a.log")"
code="$(http POST "http://127.0.0.1:$PORT_D/api/v1/sync" "$WORK/prekey_send_a.json")"
check "alice pushes the prekey-addressed envelope to prekey node A -> 200" "200" "$code"
PREKEY_A_ID="$(node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).push_envelopes[0].id)' "$WORK/prekey_send_a.json")"

make_sync_body "$WORK/prekey_mule_a1.json" "[]" "[]"
code="$(http POST "http://127.0.0.1:$PORT_D/api/v1/sync" "$WORK/prekey_mule_a1.json")"
check "mule pulls exactly 1 envelope (the prekey mail) from prekey node A" "1" "$(json_count_envelopes)"
cp "$WORK/last_body" "$WORK/prekey_mule_pull1.json"
node "$ACK_E2E" carry "$WORK/prekey_mule_pull1.json" "$WORK/prekey_mule_push1.json" >/dev/null 2>&1
code="$(http POST "http://127.0.0.1:$PORT_E/api/v1/sync" "$WORK/prekey_mule_push1.json")"
check "mule drops the prekey mail at prekey node B -> 200" "200" "$code"

make_sync_body "$WORK/prekey_bob_pull1.json" "[]" "[]"
code="$(http POST "http://127.0.0.1:$PORT_E/api/v1/sync" "$WORK/prekey_bob_pull1.json")"
check "bob pulls exactly the prekey-addressed envelope from prekey node B" "1" "$(json_count_envelopes)"
cp "$WORK/last_body" "$WORK/prekey_bob_pull1.json"

node "$PREKEY_E2E" bob_receive "$WORK/prekey_fixture.json" "$WORK/prekey_bob_pull1.json" - "$WORK/prekey_state.json" "$NOW_P" >"$WORK/prekey_bob_receive1.log" 2>&1
check "§4.6 bob_receive (leg A): the envelope classifies as Bob's own" \
    "mine" "$(sed -n 's/^classified=//p' "$WORK/prekey_bob_receive1.log")"
check "§4.6 bob_receive (leg A): it decrypts through the prekey trial path" \
    "ok" "$(sed -n 's/^decrypted=//p' "$WORK/prekey_bob_receive1.log")"
check "§4.6 bob_receive (leg A): it opened through a ONE-TIME prekey" \
    "opk" "$(sed -n 's/^opened_with=//p' "$WORK/prekey_bob_receive1.log" | cut -d: -f1)"
check "§4.6 bob_receive (leg A): the OPK secret was WIPED on use (the FS event)" \
    "1" "$(sed -n 's/^wiped=//p' "$WORK/prekey_bob_receive1.log")"

# The captured-traffic leg: the served bytes above are exactly what a dead
# drop would hold. After the wipe, NEITHER the extracted long-term key
# (attack) NOR Bob's post-wipe device state may open them.
node "$PREKEY_E2E" fs_proof "$WORK/prekey_fixture.json" "$WORK/prekey_bob_pull1.json" "$WORK/prekey_state.json" "$NOW_P" >"$WORK/prekey_fs_proof.log" 2>&1
check "§4.6 FORWARD-SECRECY PROOF: captured bytes + extracted LONG-TERM key fail" \
    "fail" "$(sed -n 's/^attack=//p' "$WORK/prekey_fs_proof.log")"
check "§4.6 FORWARD-SECRECY PROOF: the post-wipe device state fails too" \
    "fail" "$(sed -n 's/^state=//p' "$WORK/prekey_fs_proof.log")"

# ---- Leg B: old-client -> new recipient (identity-addressed mail). ----
node "$PREKEY_E2E" send "$WORK/prekey_fixture.json" "$WORK/prekey_dir_a.json" "$WORK/prekey_send_b.json" legacy bob "$NOW_P" >"$WORK/prekey_send_b.log" 2>&1
check "§4.6 send (legacy, old client): addressed to the identity key" \
    "identity" "$(sed -n 's/^target=//p' "$WORK/prekey_send_b.log")"
check "§4.6 send (legacy, old client): the hint matches the identity derivation" \
    "$BOB_HINT_CUR_P" "$(sed -n 's/^dest_hint=//p' "$WORK/prekey_send_b.log")"
code="$(http POST "http://127.0.0.1:$PORT_D/api/v1/sync" "$WORK/prekey_send_b.json")"
check "the old-client envelope is pushed to prekey node A -> 200" "200" "$code"
PREKEY_B_ID="$(node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).push_envelopes[0].id)' "$WORK/prekey_send_b.json")"

make_sync_body "$WORK/prekey_mule_a2.json" "[\"$PREKEY_A_ID\"]" "[]"
code="$(http POST "http://127.0.0.1:$PORT_D/api/v1/sync" "$WORK/prekey_mule_a2.json")"
check "mule pulls exactly 1 envelope (the old-client mail) from prekey node A" "1" "$(json_count_envelopes)"
cp "$WORK/last_body" "$WORK/prekey_mule_pull2.json"
node "$ACK_E2E" carry "$WORK/prekey_mule_pull2.json" "$WORK/prekey_mule_push2.json" >/dev/null 2>&1
code="$(http POST "http://127.0.0.1:$PORT_E/api/v1/sync" "$WORK/prekey_mule_push2.json")"
check "mule drops the old-client mail at prekey node B -> 200" "200" "$code"

make_sync_body "$WORK/prekey_bob_pull2.json" "[\"$PREKEY_A_ID\"]" "[]"
code="$(http POST "http://127.0.0.1:$PORT_E/api/v1/sync" "$WORK/prekey_bob_pull2.json")"
check "bob pulls exactly the old-client envelope from prekey node B" "1" "$(json_count_envelopes)"
cp "$WORK/last_body" "$WORK/prekey_bob_pull2.json"
node "$PREKEY_E2E" bob_receive "$WORK/prekey_fixture.json" "$WORK/prekey_bob_pull2.json" "$WORK/prekey_state.json" "$WORK/prekey_state.json" "$NOW_P" >"$WORK/prekey_bob_receive2.log" 2>&1
check "§4.6 old-client mail to a prekey-published recipient still decrypts" \
    "ok" "$(sed -n 's/^decrypted=//p' "$WORK/prekey_bob_receive2.log")"
check "§4.6 old-client mail opens through the PERMANENT identity trial path (no FS, documented)" \
    "identity" "$(sed -n 's/^opened_with=//p' "$WORK/prekey_bob_receive2.log" | cut -d: -f1)"
check "§4.6 old-client mail consumes no prekey" \
    "0" "$(sed -n 's/^wiped=//p' "$WORK/prekey_bob_receive2.log")"

# ---- Leg C: new sender -> legacy (bundle-less) recipient. ----
node "$PREKEY_E2E" send "$WORK/prekey_fixture.json" "$WORK/prekey_dir_a.json" "$WORK/prekey_send_c.json" prekey alice "$NOW_P" >"$WORK/prekey_send_c.log" 2>&1
check "§4.6 send (bundle-less recipient): the sender falls back to the identity key" \
    "identity" "$(sed -n 's/^target=//p' "$WORK/prekey_send_c.log")"
check "§4.6 send (bundle-less recipient): the fallback reason is ABSENT (no bundle)" \
    "absent" "$(sed -n 's/^fallback_reason=//p' "$WORK/prekey_send_c.log")"
check "§4.6 send (bundle-less recipient): dest_hint is hint_E(Alice's identity key)" \
    "$ALICE_HINT_CUR_P" "$(sed -n 's/^dest_hint=//p' "$WORK/prekey_send_c.log")"
code="$(http POST "http://127.0.0.1:$PORT_D/api/v1/sync" "$WORK/prekey_send_c.json")"
check "the fallback envelope is pushed to prekey node A -> 200" "200" "$code"
PREKEY_C_ID="$(node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).push_envelopes[0].id)' "$WORK/prekey_send_c.json")"

make_sync_body "$WORK/prekey_mule_a3.json" "[\"$PREKEY_A_ID\",\"$PREKEY_B_ID\"]" "[]"
code="$(http POST "http://127.0.0.1:$PORT_D/api/v1/sync" "$WORK/prekey_mule_a3.json")"
check "mule pulls exactly 1 envelope (the fallback mail) from prekey node A" "1" "$(json_count_envelopes)"
cp "$WORK/last_body" "$WORK/prekey_mule_pull3.json"
node "$ACK_E2E" carry "$WORK/prekey_mule_pull3.json" "$WORK/prekey_mule_push3.json" >/dev/null 2>&1
code="$(http POST "http://127.0.0.1:$PORT_E/api/v1/sync" "$WORK/prekey_mule_push3.json")"
check "mule drops the fallback mail at prekey node B -> 200" "200" "$code"

make_sync_body "$WORK/prekey_alice_pull.json" "[\"$PREKEY_A_ID\",\"$PREKEY_B_ID\"]" "[]"
code="$(http POST "http://127.0.0.1:$PORT_E/api/v1/sync" "$WORK/prekey_alice_pull.json")"
check "alice pulls exactly the fallback envelope from prekey node B" "1" "$(json_count_envelopes)"
cp "$WORK/last_body" "$WORK/prekey_alice_pull.json"
node "$PREKEY_E2E" plain_receive "$WORK/prekey_fixture.json" "$WORK/prekey_alice_pull.json" alice "$NOW_P" >"$WORK/prekey_alice_receive.log" 2>&1
check "§4.6 new-sender -> old-recipient mail delivers through the plain §4.3 path" \
    "ok" "$(sed -n 's/^decrypted=//p' "$WORK/prekey_alice_receive.log")"

# ---- Replenish leg: the stale SPK triggers rotation; the fresh bundle is
#      published through the ORDINARY directory upsert. ----
node "$PREKEY_E2E" replenish "$WORK/prekey_fixture.json" "$WORK/prekey_state.json" "$WORK/prekey_replenish_body.json" "$WORK/prekey_state2.json" "$NOW_P" >"$WORK/prekey_replenish.log" 2>&1
check "§4.6 replenish: the stale-SPK trigger fired" \
    "spk_stale" "$(sed -n 's/^trigger=//p' "$WORK/prekey_replenish.log")"
check "§4.6 replenish: the SPK pair rotated" \
    "yes" "$(sed -n 's/^rotated=//p' "$WORK/prekey_replenish.log")"
check "§4.6 replenish: the old OPK batch left the published stock" \
    "yes" "$(sed -n 's/^old_opk_gone=//p' "$WORK/prekey_replenish.log")"
code="$(http POST "http://127.0.0.1:$PORT_E/api/v1/directory" "$WORK/prekey_replenish_body.json")"
check "the replenish rides the ordinary directory upsert -> 200" "200" "$code"

code="$(http GET "http://127.0.0.1:$PORT_E/api/v1/directory")"
check "GET directory after the replenish -> 200" "200" "$code"
cp "$WORK/last_body" "$WORK/prekey_dir_after.json"
NEW_SPK="$(node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).prekeys.spk)' "$WORK/prekey_replenish_body.json")"
OLD_OPK="$(node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).bob_bundle.opks[0])' "$WORK/prekey_fixture.json")"
if grep -qF "$NEW_SPK" "$WORK/prekey_dir_after.json"; then ROT=rotated; else ROT=stale; fi
check "the served entry now carries the ROTATED spk" "rotated" "$ROT"
if grep -qF "$OLD_OPK" "$WORK/prekey_dir_after.json"; then OLDGONE=served; else OLDGONE=gone; fi
check "the wiped batch's OPKs are gone from the served bundle" "gone" "$OLDGONE"

stop_daemon "$DAEMON_D_PID"
DAEMON_D_PID=""
stop_daemon "$DAEMON_E_PID"
DAEMON_E_PID=""

# ---------------------------------------------------------------------------
# 17. §4.7 identity QR — in-person contact exchange (issue #28): the
#     acceptance journey with both endpoints on the SHIPPED SPA engine
#     (tests/helpers/qr_e2e.mjs):
#       - Alice and Bob exchange OFFGRID1 QR payloads (engine-built and
#         engine-verified) and each saves the other as a CONTACT — the
#         node directory is NEVER consulted and stays EMPTY (the harness
#         proves it on both nodes before and after);
#       - a TAMPERED payload (one flipped Base64 character) is rejected
#         with a visible reason (bad_crc) and stores NOTHING;
#       - Alice sends to that contact with the directory endpoint unused:
#         the box targets the identity X25519 key (no bundle, §4.6) and
#         dest_hint is the §6.1 offline-cold STATIC hint — the directory
#         carries no entry for Bob at all, yet the mail arrives;
#       - Bob receives, decrypts, and REPLIES through his own contact
#         record the same way; both inboxes show both messages.
# ---------------------------------------------------------------------------
QR_E2E="$SCRIPT_DIR/helpers/qr_e2e.mjs"
NOW_Q="$(date +%s)"

log "building the §4.7 identity-QR fixture with the shipped SPA engine (clock = $NOW_Q)"
node "$QR_E2E" fixture "$WORK/qr_fixture.json" "$NOW_Q" >"$WORK/qr_fixture.log" 2>&1 || {
    log "qr fixture build failed"; cat "$WORK/qr_fixture.log" >&2; exit 1;
}
check "§4.7 fixture built (two identities, both payloads, tampered copy)" \
    "ok" "$(sed -n 's/^RESULT=//p' "$WORK/qr_fixture.log")"
check "§4.7 fixture: the tampered payload differs from the original" \
    "yes" "$(sed -n 's/^tamper_differs=//p' "$WORK/qr_fixture.log")"
QR_PAYLOAD_CHARS="$(sed -n 's/^payload_chars=//p' "$WORK/qr_fixture.log")"
check "§4.7 fixture: the payload fits the version-15 QR cap (≤ 421 chars)" \
    "ok" "$([ "$QR_PAYLOAD_CHARS" -le 421 ] 2>/dev/null && echo ok || echo bad)"

log "starting the §4.7 identity-QR node pair: 127.0.0.1:$PORT_D and 127.0.0.1:$PORT_E (fresh databases)"
"$WORK/dtn-node" -addr "127.0.0.1:$PORT_D" -db "$WORK/node_qr_a.db" >"$WORK/node_qr_a.log" 2>&1 &
DAEMON_D_PID=$!
"$WORK/dtn-node" -addr "127.0.0.1:$PORT_E" -db "$WORK/node_qr_b.db" >"$WORK/node_qr_b.log" 2>&1 &
DAEMON_E_PID=$!
QR_READY=0
if wait_ready "$PORT_D" && wait_ready "$PORT_E"; then QR_READY=1; fi
check "identity-QR node pair ready (§4.7 round trip)" "1" "$QR_READY"
if [ "$QR_READY" -ne 1 ]; then
    log "--- qr node A log ---"; cat "$WORK/node_qr_a.log" >&2 || true
    log "--- qr node B log ---"; cat "$WORK/node_qr_b.log" >&2 || true
    exit 1
fi

# The directory is ABSENT for this journey: no registration is ever POSTed,
# so both GETs answer an empty array — the exchange cannot lean on it.
for PORT in "$PORT_D" "$PORT_E"; do
    code="$(http GET "http://127.0.0.1:$PORT/api/v1/directory")"
    check "GET directory on qr node (port $PORT) -> 200" "200" "$code"
    check "directory on qr node (port $PORT) is EMPTY (no registration ever)" \
        "0" "$({ grep -o '"alias"' "$WORK/last_body" || true; } | wc -l | tr -d ' ')"
done

# ---- The QR exchange: each side imports the other's payload. ----
node -e 'const fx=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));require("fs").writeFileSync(process.argv[2],fx.bob_payload)' "$WORK/qr_fixture.json" "$WORK/qr_bob_payload.txt"
node -e 'const fx=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));require("fs").writeFileSync(process.argv[2],fx.alice_payload)' "$WORK/qr_fixture.json" "$WORK/qr_alice_payload.txt"

node "$QR_E2E" import "$WORK/qr_bob_payload.txt" "$WORK/qr_alice_contact_of_bob.json" "$NOW_Q" >"$WORK/qr_import_alice.log" 2>&1
check "§4.7 import: Alice parses and verifies Bob's payload" \
    "ok" "$(sed -n 's/^parsed=//p' "$WORK/qr_import_alice.log")"
check "§4.7 import: the saved contact carries Bob's scanned alias" \
    "qr_bob" "$(sed -n 's/^alias=//p' "$WORK/qr_import_alice.log")"
check "§4.7 import: the contact's identity key is Bob's Ed25519 key" \
    "$(node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).bob.signPublicB64)' "$WORK/qr_fixture.json")" \
    "$(sed -n 's/^ed=//p' "$WORK/qr_import_alice.log")"

# The tampered payload: VISIBLE rejection, nothing stored.
node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).tampered_payload)' "$WORK/qr_fixture.json" > "$WORK/qr_tampered_payload.txt"
rm -f "$WORK/qr_tampered_contact.json"
node "$QR_E2E" import "$WORK/qr_tampered_payload.txt" "$WORK/qr_tampered_contact.json" "$NOW_Q" >"$WORK/qr_import_tampered.log" 2>&1
check "§4.7 TAMPERED payload: import is REJECTED with a visible reason" \
    "fail" "$(sed -n 's/^parsed=//p' "$WORK/qr_import_tampered.log")"
check "§4.7 TAMPERED payload: the reason names the corruption (bad_crc)" \
    "bad_crc" "$(sed -n 's/^reason=//p' "$WORK/qr_import_tampered.log")"
check "§4.7 TAMPERED payload: NOTHING was stored (no contact file)" \
    "absent" "$([ -f "$WORK/qr_tampered_contact.json" ] && echo present || echo absent)"

node "$QR_E2E" import "$WORK/qr_alice_payload.txt" "$WORK/qr_bob_contact_of_alice.json" "$NOW_Q" >"$WORK/qr_import_bob.log" 2>&1
check "§4.7 import: Bob parses and verifies Alice's payload (two-way exchange)" \
    "ok" "$(sed -n 's/^parsed=//p' "$WORK/qr_import_bob.log")"

# ---- Alice sends to her CONTACT with the directory unused. ----
node -e 'const fx=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));require("fs").writeFileSync(process.argv[2],JSON.stringify(fx.alice))' "$WORK/qr_fixture.json" "$WORK/qr_alice_identity.json"
node -e 'const fx=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));require("fs").writeFileSync(process.argv[2],JSON.stringify(fx.bob))' "$WORK/qr_fixture.json" "$WORK/qr_bob_identity.json"

node "$QR_E2E" send "$WORK/qr_alice_identity.json" "$WORK/qr_alice_contact_of_bob.json" "$WORK/qr_send_a.json" "met at the node — no directory needed" "$NOW_Q" >"$WORK/qr_send_a.log" 2>&1
check "§4.7 send (contact-only): dest_hint is the §6.1 offline-cold STATIC hint" \
    "$(node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).bob_hint_legacy)' "$WORK/qr_fixture.json")" \
    "$(sed -n 's/^dest_hint=//p' "$WORK/qr_send_a.log")"
code="$(http POST "http://127.0.0.1:$PORT_D/api/v1/sync" "$WORK/qr_send_a.json")"
check "alice pushes the contact-addressed envelope to qr node A -> 200" "200" "$code"
QR_A_ID="$(node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).push_envelopes[0].id)' "$WORK/qr_send_a.json")"

make_sync_body "$WORK/qr_mule_a1.json" "[]" "[]"
code="$(http POST "http://127.0.0.1:$PORT_D/api/v1/sync" "$WORK/qr_mule_a1.json")"
check "mule pulls exactly 1 envelope (the contact mail) from qr node A" "1" "$(json_count_envelopes)"
cp "$WORK/last_body" "$WORK/qr_mule_pull1.json"
node "$ACK_E2E" carry "$WORK/qr_mule_pull1.json" "$WORK/qr_mule_push1.json" >/dev/null 2>&1
code="$(http POST "http://127.0.0.1:$PORT_E/api/v1/sync" "$WORK/qr_mule_push1.json")"
check "mule drops the contact mail at qr node B -> 200" "200" "$code"

make_sync_body "$WORK/qr_bob_pull1.json" "[]" "[]"
code="$(http POST "http://127.0.0.1:$PORT_E/api/v1/sync" "$WORK/qr_bob_pull1.json")"
check "bob pulls exactly the contact-addressed envelope from qr node B" "1" "$(json_count_envelopes)"
cp "$WORK/last_body" "$WORK/qr_bob_pull1.json"
node "$QR_E2E" receive "$WORK/qr_bob_identity.json" "$WORK/qr_bob_pull1.json" "$NOW_Q" >"$WORK/qr_receive_bob.log" 2>&1
check "§4.7 receive (bob): the static-hint envelope classifies as his own" \
    "mine" "$(sed -n 's/^classified=//p' "$WORK/qr_receive_bob.log")"
check "§4.7 receive (bob): it decrypts and verifies (inbox shows the message)" \
    "ok" "$(sed -n 's/^decrypted=//p' "$WORK/qr_receive_bob.log")"
check "§4.7 receive (bob): the text arrives intact" \
    "met at the node — no directory needed" "$(sed -n 's/^m=//p' "$WORK/qr_receive_bob.log")"

# ---- Bob replies through HIS contact record, same offline path. ----
node "$QR_E2E" send "$WORK/qr_bob_identity.json" "$WORK/qr_bob_contact_of_alice.json" "$WORK/qr_send_b.json" "reply from the contact exchange — still no directory" "$((NOW_Q + 1))" >"$WORK/qr_send_b.log" 2>&1
check "§4.7 reply (contact-only): dest_hint is Alice's offline-cold STATIC hint" \
    "$(node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).alice_hint_legacy)' "$WORK/qr_fixture.json")" \
    "$(sed -n 's/^dest_hint=//p' "$WORK/qr_send_b.log")"
code="$(http POST "http://127.0.0.1:$PORT_E/api/v1/sync" "$WORK/qr_send_b.json")"
check "bob pushes the reply to qr node B -> 200" "200" "$code"
QR_B_ID="$(node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).push_envelopes[0].id)' "$WORK/qr_send_b.json")"

make_sync_body "$WORK/qr_mule_a2.json" "[\"$QR_A_ID\"]" "[]"
code="$(http POST "http://127.0.0.1:$PORT_E/api/v1/sync" "$WORK/qr_mule_a2.json")"
check "mule pulls exactly 1 envelope (the reply) from qr node B" "1" "$(json_count_envelopes)"
cp "$WORK/last_body" "$WORK/qr_mule_pull2.json"
node "$ACK_E2E" carry "$WORK/qr_mule_pull2.json" "$WORK/qr_mule_push2.json" >/dev/null 2>&1
code="$(http POST "http://127.0.0.1:$PORT_D/api/v1/sync" "$WORK/qr_mule_push2.json")"
check "mule drops the reply at qr node A -> 200" "200" "$code"

make_sync_body "$WORK/qr_alice_pull.json" "[\"$QR_A_ID\"]" "[]"
code="$(http POST "http://127.0.0.1:$PORT_D/api/v1/sync" "$WORK/qr_alice_pull.json")"
check "alice pulls exactly the reply from qr node A" "1" "$(json_count_envelopes)"
cp "$WORK/last_body" "$WORK/qr_alice_pull.json"
node "$QR_E2E" receive "$WORK/qr_alice_identity.json" "$WORK/qr_alice_pull.json" "$((NOW_Q + 1))" >"$WORK/qr_receive_alice.log" 2>&1
check "§4.7 receive (alice): the reply decrypts and verifies (inbox shows the message)" \
    "ok" "$(sed -n 's/^decrypted=//p' "$WORK/qr_receive_alice.log")"
check "§4.7 receive (alice): the reply text arrives intact" \
    "reply from the contact exchange — still no directory" "$(sed -n 's/^m=//p' "$WORK/qr_receive_alice.log")"

# The directory was NEVER used: still empty on both nodes afterwards.
for PORT in "$PORT_D" "$PORT_E"; do
    code="$(http GET "http://127.0.0.1:$PORT/api/v1/directory")"
    check "directory on qr node (port $PORT) still EMPTY after the whole exchange" \
        "0" "$({ grep -o '"alias"' "$WORK/last_body" || true; } | wc -l | tr -d ' ')"
done

stop_daemon "$DAEMON_D_PID"
DAEMON_D_PID=""
stop_daemon "$DAEMON_E_PID"
DAEMON_E_PID=""

# ---------------------------------------------------------------------------
# Summary.
# ---------------------------------------------------------------------------
log "summary: $PASS_COUNT passed, $FAIL_COUNT failed"
if [ "$FAIL_COUNT" -gt 0 ]; then
    log "RESULT: FAIL"
    exit 1
fi
log "RESULT: PASS"
