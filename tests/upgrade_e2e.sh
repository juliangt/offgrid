#!/usr/bin/env bash
# tests/upgrade_e2e.sh — field-level node upgrade + rollback E2E (issue #22).
#
# The acceptance criterion of issue #22 is a TESTED upgrade path. This script
# drives the real upgrade machinery — raspberry/upgrade.sh, the very code
# `install.sh --upgrade` / `--rollback` run on a Pi — rootlessly against a
# temp "node" (env-overridable paths + overridden service functions) with a
# REAL populated store and REAL daemons:
#
#   0. structural pins on the field wiring the rootless run cannot execute:
#      install.sh --upgrade/--rollback/--from modes, the refusing-box guard,
#      the binding stop -> backup -> swap -> start -> gate order of
#      upgrade_node(), the provision.sh STEPS subset selector, and the
#      Makefile + docs wiring;
#   1. two binaries built from the CURRENT tree with distinct build ids
#      (-ldflags -X offgrid/dtn-node.build=...): the "deployed release" and
#      the "staged new release";
#   2. a v1-era store crafted with the sqlite3 CLI — the §9 schema verbatim,
#      user_version 0, no envelopes.v / directory.epoch / directory.prekeys,
#      3 envelopes + 2 directory rows (the standard field scenario);
#   3. §15.7 a at field level: starting the deployed binary against the
#      populated v1 store migrates it through the real chain (user_version
#      0 -> 4, every column appears, rows backfilled) while everything keeps
#      being served (envelope ids + byte-identical payloads, directory with
#      epoch-0 backfill);
#   4. the upgrade SUCCESS path through the library: stop -> backup
#      generation (db + previous binary + MANIFEST.txt) -> prune -> binary
#      swap -> start -> health gate (build identity + schema_version) ->
#      zero envelope loss, the write path accepts new mail, directory intact;
#   5. backup generation rotation: 4 generations -> prune keeps the newest 3,
#      and an explicit KEEP=1 keeps exactly the newest one;
#   6. the FAILED-migration rollback: the store marker is moved to 99 (the
#      §15.3 downgrade-refusal state — a release that cannot open the store),
#      the swapped daemon refuses to start naming both versions, the health
#      gate fails, upgrade_auto_rollback() restores the previous binary + db
#      backup (the refused store is preserved as pre-restore-<UTC> evidence)
#      and the node serves again — same envelope ids, same directory,
#      user_version back to 4;
#   7. the staged-binary probe and the negative gates: upgrade_probe_staged()
#      reports the staged binary's own identity; wrong expected build or
#      schema makes the gate fail against an otherwise healthy node.
#
# Rootless discipline (tests/sync_e2e.sh and tests/chaos/lib.sh style): the
# harness starts/stops its own daemons on a 127.0.0.1 port and cleans up
# after itself via the EXIT trap; the systemd actions of the library are
# overridden with plain background-process management, and every DTN_* path
# points into the temp "node" — so the exact library code that runs on the Pi
# runs here against real files and real HTTP.
#
# Usage:  bash tests/upgrade_e2e.sh
# Env:    PORT_MAIN (default 18101 — outside the sync_e2e 18091-18095 and
#         chaos 18095-18099 ranges).
# Needs:  go (daemon builds), curl, the sqlite3 CLI (the v1 fixture is crafted
#         with it, like tests/sync_e2e.sh §15), shasum (macOS) / sha256sum
#         (GNU).
# Exit:   0 = every assertion passed; 1 = at least one failed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PORT_MAIN="${PORT_MAIN:-18101}"

PASS_COUNT=0
FAIL_COUNT=0
NODE_PID=""

WORK="$(mktemp -d "${TMPDIR:-/tmp}/dtn-upgrade.XXXXXX")"
NODE_PID_FILE="$WORK/node.pid"
cleanup() {
    local status=$?
    reap_pid "$NODE_PID"
    reap_pid "$(cat "$NODE_PID_FILE" 2>/dev/null || true)"
    rm -rf "$WORK"
    exit "$status"
}
trap cleanup EXIT

log() { printf '%s\n' "upgrade: $*"; }

# check DESC EXPECTED ACTUAL — record one assertion (PASS or FAIL), exactly
# the sync_e2e.sh style.
check() {
    if [ "$2" = "$3" ]; then
        printf 'PASS: %s\n' "$1"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        printf 'FAIL: %s\n      expected [%s]\n      actual   [%s]\n' "$1" "$2" "$3"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

# fatal MSG — a setup failure that makes every downstream assertion
# meaningless (build failed, daemon never became ready).
fatal() {
    printf 'upgrade: FAIL: %s\n' "$*" >&2
    exit 1
}

# reap_pid PID — kill+wait one daemon pid, tolerating an already-dead or
# non-child process (a daemon started inside a command-substitution subshell
# is not a wait()able child of the parent shell — kill is still valid).
reap_pid() {
    [ -n "${1:-}" ] || return 0
    kill "$1" 2>/dev/null || true
    wait "$1" 2>/dev/null || true
}

sha256_file() {
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        sha256sum "$1" | awk '{print $1}'
    fi
}

hex_id() { printf '%064x\n' "$1"; }

# payload_b64 SEED — a valid §8.2 payload fixture: padded standard Base64 of
# exactly 248 decoded bytes (the §8.2 floor), deterministic per seed.
payload_b64() {
    local seed=${1:-0}
    { printf '%s' "$seed" | head -c 248; head -c 248 /dev/urandom; } | head -c 248 | base64 | tr -d '\n'
}

HTTP_BODY="$WORK/last_body"

# http METHOD URL [BODY_FILE] — JSON request against the canonical origin
# (Host header override, sync_e2e.sh style). Echoes the HTTP status code; the
# response body lands in $HTTP_BODY.
http() {
    local method=$1 url=$2 body=${3:-}
    local args=(-sS --max-time 10 -o "$HTTP_BODY" -w '%{http_code}' -H 'Host: offgrid.local:8080')
    if [ -n "$body" ]; then
        args+=(-H 'Content-Type: application/json' --data-binary @"$body")
    fi
    curl "${args[@]}" -X "$method" "$url" || true
}

make_sync_body() {
    printf '{"known_ids":%s,"push_envelopes":%s,"limit":200}' "$2" "$3" > "$1"
}

# pull_ids — POST a pull-all sync and echo the served envelope ids, sorted
# (the zero-loss ledger every leg compares against).
pull_ids() {
    printf '{"known_ids":[],"push_envelopes":[],"limit":200}' > "$WORK/pull.json"
    local code
    code="$(http POST "http://127.0.0.1:$PORT_MAIN/api/v1/sync" "$WORK/pull.json")"
    if [ "$code" != "200" ]; then
        printf 'PULL_FAILED_%s' "$code"
        return 0
    fi
    { grep -o '"id":"[0-9a-f]\{64\}"' "$HTTP_BODY" || true; } | sed -E 's/.*:"([0-9a-f]+)"/\1/' | sort
}

# directory_count — GET the directory and echo the entry count.
directory_count() {
    local code
    code="$(http GET "http://127.0.0.1:$PORT_MAIN/api/v1/directory")"
    if [ "$code" != "200" ]; then
        printf 'GET_FAILED_%s' "$code"
        return 0
    fi
    { grep -o '"alias"' "$HTTP_BODY" || true; } | wc -l | tr -d ' '
}

# wait_ready [TRIES] — poll GET /generate_204 until 302 (§10.2 probe), chaos
# lib style: a daemon that exits before serving fails the poll immediately.
# The daemon's own "listening on <addr>" startup line must ALSO appear in the
# log beyond the previous count: a FOREIGN process squatting on the port (e.g.
# a leftover daemon from an interrupted run) would otherwise answer the probe
# on the test's behalf and poison every cross-phase ledger comparison with
# its store.
LOG_MARK=0
wait_ready() {
    local tries=${1:-100} i code=000 listening
    for i in $(seq 1 "$tries"); do
        if [ -n "$NODE_PID" ] && ! kill -0 "$NODE_PID" 2>/dev/null; then
            printf 'upgrade: node (pid %s) exited before becoming ready; log tail:\n' "$NODE_PID" >&2
            tail -n 5 "$WORK/node.log" >&2 || true
            return 1
        fi
        listening="$({ grep -cF "listening on 127.0.0.1:$PORT_MAIN" "$WORK/node.log" 2>/dev/null || true; })"
        code="$(curl -s --max-time 3 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT_MAIN/generate_204" 2>/dev/null)" || code=000
        if [ "$code" = "302" ] && [ "$listening" -gt "$LOG_MARK" ]; then
            LOG_MARK="$listening"
            return 0
        fi
        sleep 0.2
    done
    printf 'upgrade: node on port %s did not become ready (last probe code %s, listening lines %s — is a foreign process squatting on the port?)\n' \
        "$PORT_MAIN" "$code" "$listening"
    return 1
}

# ---------------------------------------------------------------------------
# The "node": temp dirs wired into the upgrade library + service overrides.
# The env vars are set BEFORE sourcing raspberry/upgrade.sh so the library
# binds to the temp layout; the systemd actions are overridden with plain
# background-process management of whatever binary sits at the install path.
# The daemon pid is ALSO recorded in $NODE_PID_FILE: a svc_start inside a
# command substitution runs in a subshell whose NODE_PID assignment dies with
# it, and the parent must still be able to reap that daemon (the EXIT trap).
DTN_INSTALL_DIR="$WORK/opt/dtn-node"
DTN_DATA_DIR="$WORK/var/lib/dtn-node"
DTN_DB="$DTN_DATA_DIR/node_storage.db"
DTN_BACKUP_DIR="$DTN_DATA_DIR/backups"
DTN_HEALTH_URL="http://127.0.0.1:$PORT_MAIN/api/v1/health"
DTN_HEALTH_HOST="offgrid.local:8080"
DTN_HEALTH_TIMEOUT="${DTN_HEALTH_TIMEOUT:-20}"
export DTN_INSTALL_DIR DTN_DATA_DIR DTN_DB DTN_BACKUP_DIR \
    DTN_HEALTH_URL DTN_HEALTH_HOST DTN_HEALTH_TIMEOUT

# shellcheck source=../raspberry/upgrade.sh
. "$ROOT/raspberry/upgrade.sh"

upgrade_svc_stop() {
    reap_pid "$NODE_PID"
    NODE_PID=""
    reap_pid "$(cat "$NODE_PID_FILE" 2>/dev/null || true)"
    rm -f "$NODE_PID_FILE"
}
upgrade_svc_start() {
    "$DTN_INSTALL_DIR/dtn-node" -addr "127.0.0.1:$PORT_MAIN" -db "$DTN_DB" >>"$WORK/node.log" 2>&1 &
    NODE_PID=$!
    printf '%s\n' "$NODE_PID" > "$NODE_PID_FILE"
}
upgrade_svc_active() { [ -n "$NODE_PID" ] && kill -0 "$NODE_PID" 2>/dev/null; }

# ---------------------------------------------------------------------------
# 0. Structural pins: the field wiring the rootless run cannot execute.
# ---------------------------------------------------------------------------
log "section 0: structural pins on the field wiring"
for f in "$ROOT/raspberry/install.sh" "$ROOT/raspberry/upgrade.sh" "$ROOT/raspberry/provision.sh" "$SCRIPT_DIR/upgrade_e2e.sh"; do
    if bash -n "$f" 2>"$WORK/synerr"; then
        check "bash -n $(basename "$f") parses clean" "ok" "ok"
    else
        check "bash -n $(basename "$f") parses clean" "ok" "syntax error: $(cat "$WORK/synerr")"
    fi
done
check "install.sh exposes the --upgrade mode" "1" "$({ grep -cF -- '--upgrade)' "$ROOT/raspberry/install.sh" || true; })"
check "install.sh exposes the --rollback mode" "1" "$({ grep -cF -- '--rollback)' "$ROOT/raspberry/install.sh" || true; })"
check "install.sh exposes the --from generation picker" "1" "$({ grep -cF -- '--from)' "$ROOT/raspberry/install.sh" || true; })"
check "install.sh refuses a never-provisioned box before upgrading" \
    "ok" "$([ "$(grep -cF 'require_provisioned_node' "$ROOT/raspberry/install.sh")" -ge 2 ] && echo ok || echo missing)"
check "install.sh sources the tested upgrade library" \
    "ok" "$({ grep -qF 'upgrade.sh' "$ROOT/raspberry/install.sh" && echo ok || echo missing; })"
check "upgrade.sh keeps a bounded generation window (default 3)" \
    "1" "$({ grep -cE '^DTN_KEEP_GENERATIONS=' "$ROOT/raspberry/upgrade.sh" || true; })"
check "provision.sh carries the STEPS subset selector (issue #22 upgrade path)" \
    "1" "$({ grep -cE '^STEPS=' "$ROOT/raspberry/provision.sh" || true; })"

# AUDIT pins (docs/security-audit.md §5, SUPPLY-01/SUPPLY-03): the release
# verification chain. Every release asset install.sh USES must be verified
# against the release SHA256SUMS BEFORE it runs — the provisioning tarball is
# root-executed code — and the unverified local-checkout binary must warn.
IL="$ROOT/raspberry/install.sh"
LN_VDEF="$(grep -nF 'verify_sum()' "$IL" | head -n 1 | cut -d: -f1)"
LN_VBIN="$(grep -nF 'verify_sum "dtn-node-linux-$BINARCH"' "$IL" | head -n 1 | cut -d: -f1)"
LN_VTAR="$(grep -nF 'verify_sum "$(basename "$TARBALL")"' "$IL" | head -n 1 | cut -d: -f1)"
LN_UNTAR="$(grep -nF 'tar -xzf "$TARBALL"' "$IL" | head -n 1 | cut -d: -f1)"
if [ -n "$LN_VDEF" ] && [ -n "$LN_VBIN" ] && [ -n "$LN_VTAR" ] && [ -n "$LN_UNTAR" ] \
    && [ "$LN_VBIN" -gt "$LN_VDEF" ] && [ "$LN_VTAR" -gt "$LN_VBIN" ] \
    && [ "$LN_UNTAR" -gt "$LN_VTAR" ]; then
    VORDER=ok
else
    VORDER="broken (def=$LN_VDEF bin=$LN_VBIN tar=$LN_VTAR untar=$LN_UNTAR)"
fi
check "install.sh verification order: define verify_sum -> verify binary -> verify tarball -> only then extract" \
    "ok" "$VORDER"
check "install.sh fails closed on a missing SHA256SUMS entry AND on a hash mismatch" \
    "ok" "$([ "$(grep -cF 'die "no checksum for' "$IL")" -ge 1 ] && [ "$(grep -cF 'die "checksum mismatch for' "$IL")" -ge 1 ] && echo ok || echo missing)"
check "install.sh checksum match is exact-field (a substring of another asset's name cannot verify)" \
    "ok" "$({ grep -qF 'substr($NF, length($NF) - length(n)) == "/" n' "$IL" && echo ok || echo missing; })"
check "install.sh warns the local-checkout binary is unverified (SUPPLY-03)" \
    "2" "$({ grep -cF 'log "WARNING:' "$IL" || true; })"

# The binding order of upgrade_node(): stop -> BACK UP -> only then the
# provisioning subset (binary swap) -> start -> health gate.
sed -n '/^upgrade_node() {/,/^}/p' "$ROOT/raspberry/upgrade.sh" > "$WORK/unode.txt"
line_in_unode() {
    grep -nF -- "$1" "$WORK/unode.txt" | head -n 1 | cut -d: -f1
}
LN_STOP="$(line_in_unode 'upgrade_svc_stop')"
LN_BACKUP="$(line_in_unode 'upgrade_backup_generation')"
LN_SWAP="$(line_in_unode 'STEPS=')"
LN_START="$(line_in_unode 'upgrade_svc_start')"
LN_GATE="$(line_in_unode 'upgrade_health_gate')"
if [ -n "$LN_STOP" ] && [ -n "$LN_BACKUP" ] && [ -n "$LN_SWAP" ] && [ -n "$LN_START" ] && [ -n "$LN_GATE" ] \
    && [ "$LN_STOP" -lt "$LN_BACKUP" ] && [ "$LN_BACKUP" -lt "$LN_SWAP" ] \
    && [ "$LN_SWAP" -lt "$LN_START" ] && [ "$LN_START" -lt "$LN_GATE" ]; then
    ORDER=ok
else
    ORDER="broken (stop=$LN_STOP backup=$LN_BACKUP swap=$LN_SWAP start=$LN_START gate=$LN_GATE)"
fi
check "upgrade_node order: stop -> backup -> swap -> start -> gate (backup BEFORE touching anything)" "ok" "$ORDER"

check "Makefile runs the upgrade E2E in make test" \
    "1" "$({ grep -cF 'bash tests/upgrade_e2e.sh' "$ROOT/Makefile" || true; })"
check "docs/BUILD.md documents the upgrade path" \
    "ok" "$({ grep -qF 'install.sh --upgrade' "$ROOT/docs/BUILD.md" && grep -qF 'tests/upgrade_e2e.sh' "$ROOT/docs/BUILD.md" && echo ok || echo missing; })"
check "docs/RUNBOOK.md documents the upgrade + rollback runbook" \
    "ok" "$({ grep -qF 'install.sh --upgrade' "$ROOT/docs/RUNBOOK.md" && grep -qF -- '--rollback' "$ROOT/docs/RUNBOOK.md" && echo ok || echo missing; })"

# ---------------------------------------------------------------------------
# 1. Two binaries from the CURRENT tree with distinct build ids: the
#    "deployed release" (upgrade-test-old) and the "staged new release"
#    (upgrade-test-new). The build id is what the health gate identities.
# ---------------------------------------------------------------------------
log "section 1: building the deployed + staged binaries (distinct build ids)"
# -X main.build: the linker records the main package as "main" when built from
# source, so the stamping key is main.build (the module-path form does not
# apply — main.go's stamping note says the same).
(cd "$ROOT/node" && CGO_ENABLED=0 go build -ldflags "-X main.build=upgrade-test-old" -o "$WORK/dtn-old" .) \
    || fatal "old-binary build failed"
(cd "$ROOT/node" && CGO_ENABLED=0 go build -ldflags "-X main.build=upgrade-test-new" -o "$WORK/dtn-new" .) \
    || fatal "new-binary build failed"

# ---------------------------------------------------------------------------
# 2. The v1-era store: the §9 schema VERBATIM (no envelopes.v, no
#    directory.epoch, no directory.prekeys), user_version left at 0 (the §15.3
#    marker for schema 1), 3 envelopes + 2 directory rows inserted the old way.
#    Crafted BEFORE any daemon ever runs against it.
# ---------------------------------------------------------------------------
log "section 2: crafting the v1-era store (§9 schema, user_version 0)"
mkdir -p "$DTN_DATA_DIR" "$DTN_INSTALL_DIR" "$DTN_BACKUP_DIR"
NOW="$(date +%s)"
TTL=86400
HINT="9f3ab02c1d77e4c1"
E1="$(hex_id 1)"; E2="$(hex_id 2)"; E3="$(hex_id 3)"
P1="$(payload_b64 11)"; P2="$(payload_b64 22)"; P3="$(payload_b64 33)"

sqlite3 "$DTN_DB" >/dev/null <<SQL
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
  VALUES ('$E1', '$HINT', $NOW, $TTL, '$P1');
INSERT INTO envelopes (id, dest_hint, created_at, ttl, payload)
  VALUES ('$E2', '$HINT', $NOW, $TTL, '$P2');
INSERT INTO envelopes (id, dest_hint, created_at, ttl, payload)
  VALUES ('$E3', '$HINT', $NOW, $TTL, '$P3');

INSERT INTO directory (pubkey, x25519, alias, last_seen)
  VALUES ('bGVnYWN5X2FsaWNlX2tleV9hYWFhYWFhYWFhYWFhYWFhYWFh', 'bGVnYWN5X2FsaWNlX3gyNTVfOWFhYWFhYWFhYWFhYWFhYWFhYQ==', 'legacy_alice', 1700000000);
INSERT INTO directory (pubkey, x25519, alias, last_seen)
  VALUES ('bGVnYWN5X2JvYl9rZXlfYWFhYWFhYWFhYWFhYWFhYWFhYWFh', 'bGVnYWN5X2JvYl94MjU1XzliYWFhYWFhYWFhYWFhYWFhYWFhYQ==', 'legacy_bob', 1700000100);

PRAGMA user_version = 0;
SQL

check "v1 fixture: user_version is 0 (schema 1, unmarked, §15.3)" "0" "$(sqlite3 "$DTN_DB" 'PRAGMA user_version;')"
check "v1 fixture: 3 envelopes stored the old way" "3" "$(sqlite3 "$DTN_DB" 'SELECT COUNT(*) FROM envelopes;')"
check "v1 fixture: 2 directory entries" "2" "$(sqlite3 "$DTN_DB" 'SELECT COUNT(*) FROM directory;')"
check "v1 fixture: no envelopes.v column yet" "absent" "$(sqlite3 "$DTN_DB" 'PRAGMA table_info(envelopes);' | { grep -q '|v|' && echo present || echo absent; })"
check "v1 fixture: no directory.epoch column yet" "absent" "$(sqlite3 "$DTN_DB" 'PRAGMA table_info(directory);' | { grep -q '|epoch|' && echo present || echo absent; })"

IDS_BASELINE="$(printf '%s\n' "$E1" "$E2" "$E3" | sort)"

# ---------------------------------------------------------------------------
# 3. Leg A — the deployed release starts against the populated v1 store: the
#    §15.3 migration chain runs ON THE POPULATED DB (the field-level gap of
#    issue #22), and everything keeps being served.
# ---------------------------------------------------------------------------
log "section 3: deployed release starts on the v1 store (migration on populated db)"
upgrade_swap_binary "$WORK/dtn-old"
check "binary swap installs the deployed release" \
    "$(sha256_file "$WORK/dtn-old")" "$(sha256_file "$DTN_INSTALL_DIR/dtn-node")"
upgrade_svc_start
if ! wait_ready; then
    log "--- node log ---"; cat "$WORK/node.log" >&2 || true
    fatal "the deployed release never became ready on the v1 store"
fi
check "deployed release becomes ready on the v1 store (migration ran, not refused)" "ok" "ok"
check "store migrated to schema 4 (§15.3 chain 1->2->3->4)" "4" "$(upgrade_read_user_version)"
check "envelopes table gained the v column (step 1->2)" \
    "present" "$(sqlite3 "$DTN_DB" 'PRAGMA table_info(envelopes);' | { grep -q '|v|' && echo present || echo absent; })"
check "directory table gained the epoch column (step 2->3, §6.1)" \
    "present" "$(sqlite3 "$DTN_DB" 'PRAGMA table_info(directory);' | { grep -q '|epoch|' && echo present || echo absent; })"
check "directory table gained the prekeys column (step 3->4, §4.6)" \
    "present" "$(sqlite3 "$DTN_DB" 'PRAGMA table_info(directory);' | { grep -q '|prekeys|' && echo present || echo absent; })"

check "all 3 pre-existing envelopes served after the migration" "$IDS_BASELINE" "$(pull_ids)"
printf '{"known_ids":[],"push_envelopes":[],"limit":200}' > "$WORK/pull.json"
http POST "http://127.0.0.1:$PORT_MAIN/api/v1/sync" "$WORK/pull.json" >/dev/null
check "migrated envelopes served as v1 (DEFAULT 1 backfill, §15.3)" "3" "$({ grep -o '"v":1[,}]' "$HTTP_BODY" || true; } | wc -l | tr -d ' ')"
check "pre-existing payloads byte-identical through the migration" \
    "ok" "$({ grep -qF "$P1" "$HTTP_BODY" && grep -qF "$P2" "$HTTP_BODY" && grep -qF "$P3" "$HTTP_BODY" && echo ok || echo altered; })"

check "directory intact through the migration" "2" "$(directory_count)"
http GET "http://127.0.0.1:$PORT_MAIN/api/v1/directory" >/dev/null
check "legacy rows backfilled to epoch 0 (deliberately stale, §6.1)" \
    "2" "$({ grep -o '"epoch":0[,}]' "$HTTP_BODY" || true; } | wc -l | tr -d ' ')"
check "legacy rows carry no prekeys bundle (NULL omitted, §4.6)" \
    "absent" "$({ grep -qF '"prekeys"' "$HTTP_BODY" && echo present || echo absent; })"

check "health reports the deployed build" "upgrade-test-old" \
    "$(upgrade_health_member build "$(upgrade_running_health)")"
check "health reports schema_version 4" "4" \
    "$(upgrade_health_num schema_version "$(upgrade_running_health)")"

# ---------------------------------------------------------------------------
# 4. Leg B — the upgrade SUCCESS path through the library: stop -> backup
#    generation -> prune -> swap -> start -> health gate -> zero loss.
# ---------------------------------------------------------------------------
log "section 4: upgrade success path (backup, swap, health gate)"
OLD_BUILD="upgrade-test-old"
OLD_UV="$(upgrade_read_user_version)"
upgrade_svc_stop
GEN1="$(upgrade_backup_generation "" "$OLD_BUILD" "$OLD_UV")"
check "backup generation created under the backup dir" \
    "ok" "$([ -d "$GEN1" ] && echo ok || echo missing)"
check "backup holds the store" "ok" "$([ -f "$GEN1/node_storage.db" ] && echo ok || echo missing)"
check "backup holds the previous binary" \
    "ok" "$([ -f "$GEN1/dtn-node" ] && [ "$(sha256_file "$GEN1/dtn-node")" = "$(sha256_file "$WORK/dtn-old")" ] && echo ok || echo missing)"
check "backup manifest records the old build" "upgrade-test-old" \
    "$(upgrade_manifest_get old_build "$GEN1/MANIFEST.txt")"
check "backup manifest records the old schema version" "4" \
    "$(upgrade_manifest_get old_user_version "$GEN1/MANIFEST.txt")"
check "backed-up store is byte-identical to the live one" \
    "$(sha256_file "$DTN_DB")" "$(sha256_file "$GEN1/node_storage.db")"
upgrade_prune_generations

upgrade_swap_binary "$WORK/dtn-new"
upgrade_svc_start
check "health gate passes with the staged binary's expectations" \
    "0" "$(upgrade_health_gate 30 "upgrade-test-new" "4" && echo 0 || echo 1)"
check "serving build is the new release (identity changed)" "upgrade-test-new" \
    "$(upgrade_health_member build "$(upgrade_running_health)")"
check "zero envelope loss through the upgrade" "$IDS_BASELINE" "$(pull_ids)"

# The write path works on the migrated store: a NEW envelope is accepted and
# served (this one rides the ledger through the rollback leg below).
E4="$(hex_id 4)"
P4="$(payload_b64 44)"
printf '{"known_ids":["%s"],"push_envelopes":[{"v":1,"id":"%s","dest_hint":"%s","created_at":%s,"ttl":%s,"payload":"%s"}],"limit":200}' \
    "$E4" "$E4" "$HINT" "$NOW" "$TTL" "$P4" > "$WORK/push_new.json"
check "post-upgrade push accepted (write path on the migrated store)" \
    "200" "$(http POST "http://127.0.0.1:$PORT_MAIN/api/v1/sync" "$WORK/push_new.json")"
IDS_FULL="$(printf '%s\n' "$E1" "$E2" "$E3" "$E4" | sort)"
check "post-upgrade pull serves the full ledger" "$IDS_FULL" "$(pull_ids)"
check "post-upgrade payloads verbatim (pre- and post-upgrade mail)" \
    "ok" "$({ grep -qF "$P1" "$HTTP_BODY" && grep -qF "$P4" "$HTTP_BODY" && echo ok || echo altered; })"
check "directory intact after the upgrade" "2" "$(directory_count)"

# ---------------------------------------------------------------------------
# 5. Leg C — backup generation rotation: 4 generations -> KEEP=3 keeps the
#    newest 3; an explicit KEEP=1 keeps exactly the newest one. Labels are
#    creation-ordered (the prune contract), z-suffixed after the default
#    upgrade-test-old label so the name sort matches the age even within the
#    same UTC second.
# ---------------------------------------------------------------------------
log "section 5: backup generation rotation"
upgrade_svc_stop
sleep 1
TS="$(date -u +%Y%m%dT%H%M%SZ)"
upgrade_backup_generation "upgrade-${TS}-z2" "$OLD_BUILD" "$OLD_UV" >/dev/null
upgrade_backup_generation "upgrade-${TS}-z3" "$OLD_BUILD" "$OLD_UV" >/dev/null
GEN4="$(upgrade_backup_generation "upgrade-${TS}-z4" "$OLD_BUILD" "$OLD_UV")"
upgrade_prune_generations
check "rotation keeps exactly the last 3 generations" \
    "3" "$(upgrade_list_generations | wc -l | tr -d ' ')"
check "the oldest generation (the leg-B backup) was pruned" \
    "missing" "$([ -d "$GEN1" ] && echo present || echo missing)"
check "the newest generation survives the prune" \
    "ok" "$([ -d "$GEN4" ] && echo ok || echo missing)"
upgrade_prune_generations 1
check "explicit KEEP=1 keeps exactly one generation" \
    "1" "$(upgrade_list_generations | wc -l | tr -d ' ')"
check "KEEP=1 keeps the NEWEST generation" \
    "ok" "$([ -d "$GEN4" ] && echo ok || echo missing)"

# ---------------------------------------------------------------------------
# 6. Leg D — the FAILED-migration rollback (the acceptance criterion): the
#    store marker moves to 99 — the §15.3 state a release that cannot open
#    the store is faced with — the swapped daemon refuses to start naming
#    both versions, the health gate fails, and upgrade_auto_rollback()
#    restores the previous binary + db backup. The node serves again with
#    the full ledger and the refused store is kept as evidence.
# ---------------------------------------------------------------------------
log "section 6: failed migration -> automatic rollback"
# The daemon is stopped (leg C); GEN4 holds the current binary (dtn-new) and
# the current store (schema 4, full ledger). Simulate the bad new release:
sqlite3 "$DTN_DB" 'PRAGMA user_version = 99;'
check "store now carries the refused marker (user_version 99)" "99" "$(upgrade_read_user_version)"
upgrade_swap_binary "$WORK/dtn-old"   # a REAL binary that cannot open this store
upgrade_svc_start
REF_EXIT=""
for _ in $(seq 1 25); do
    if ! kill -0 "$NODE_PID" 2>/dev/null; then break; fi
    sleep 0.2
done
if kill -0 "$NODE_PID" 2>/dev/null; then
    REF_EXIT=still-running
else
    wait "$NODE_PID" >/dev/null 2>&1 || REF_EXIT="non-zero"
    NODE_PID=""
fi
check "the refusing daemon exited non-zero before ever serving" "non-zero" "$REF_EXIT"
check "refusal names both schema versions (99 vs 4, §15.3)" \
    "named" "$({ grep -qF 'database schema version is 99' "$WORK/node.log" && grep -qF 'supports at most schema version 4' "$WORK/node.log" && echo named || echo missing; })"
check "health gate FAILS against the refusing daemon" \
    "1" "$(upgrade_health_gate 4 "upgrade-test-old" "" && echo 0 || echo 1)"

check "upgrade_auto_rollback restores + re-verifies health" \
    "0" "$(upgrade_auto_rollback "$GEN4" "upgrade-test-new" "4" >&2 && echo 0 || echo 1)"
check "store restored to schema 4 (the pre-attempt marker)" "4" "$(upgrade_read_user_version)"
check "refused store preserved as pre-restore-<UTC> evidence" \
    "1" "$({ ls -1d "$DTN_DATA_DIR"/pre-restore-* 2>/dev/null || true; } | wc -l | tr -d ' ')"
check "serving build is the restored release" "upgrade-test-new" \
    "$(upgrade_health_member build "$(upgrade_running_health)")"
check "zero envelope loss through the failed upgrade + rollback" "$IDS_FULL" "$(pull_ids)"
check "directory intact after the rollback" "2" "$(directory_count)"

# ---------------------------------------------------------------------------
# 7. The staged-binary probe and the negative gates (the node still serves).
# ---------------------------------------------------------------------------
log "section 7: staged-binary probe + negative gate checks"
check "probe reports the staged binary's identity (build + schema)" \
    "upgrade-test-new 4" "$(upgrade_probe_staged "$WORK/dtn-new")"
check "probe fails for something that cannot run" \
    "1" "$(upgrade_probe_staged "$WORK/no-such-binary" >/dev/null 2>&1 && echo 0 || echo 1)"
check "gate rejects a wrong expected build" \
    "1" "$(upgrade_health_gate 3 "some-other-build" "" && echo 0 || echo 1)"
check "gate rejects a wrong expected schema" \
    "1" "$(upgrade_health_gate 3 "" "3" && echo 0 || echo 1)"
check "gate accepts the healthy node again (full expectations)" \
    "0" "$(upgrade_health_gate 10 "upgrade-test-new" "4" && echo 0 || echo 1)"

upgrade_svc_stop

# ---------------------------------------------------------------------------
# Summary.
# ---------------------------------------------------------------------------
log "summary: $PASS_COUNT passed, $FAIL_COUNT failed"
if [ "$FAIL_COUNT" -gt 0 ]; then
    log "RESULT: FAIL"
    exit 1
fi
log "RESULT: PASS"
