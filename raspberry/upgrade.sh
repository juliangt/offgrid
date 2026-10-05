# raspberry/upgrade.sh — non-destructive upgrade + rollback machinery for an
# already-provisioned node (issue #22).
#
# SOURCED, never executed: raspberry/install.sh sources it for its
# `--upgrade` / `--rollback` modes, and tests/upgrade_e2e.sh sources it to
# drive the very same functions ROOTLESSLY against a temp "node" — the
# automated acceptance test of the issue. Everything a Pi hardcodes is
# therefore overridable:
#
#   DTN_INSTALL_DIR       daemon binary directory    (default /opt/dtn-node)
#   DTN_DATA_DIR          state directory            (default /var/lib/dtn-node)
#   DTN_DB                SQLite store path          (default $DTN_DATA_DIR/node_storage.db)
#   DTN_BACKUP_DIR        backup generations         (default $DTN_DATA_DIR/backups)
#   DTN_KEEP_GENERATIONS  generations kept by prune  (default 3)
#   DTN_SERVICE           systemd unit name          (default dtn-node)
#   DTN_HEALTH_URL        health endpoint            (default http://127.0.0.1:8080/api/v1/health)
#   DTN_HEALTH_HOST       Host header value          (default offgrid.local:8080 — the
#                                                    canonical origin of §10.2, which the
#                                                    health endpoint answers behind)
#   DTN_HEALTH_TIMEOUT    health-gate budget seconds (default 120)
#   DTN_OWNER             store owner on restore     (default dtn:dtn; applied only when
#                                                    root AND that user exists)
#
# The three upgrade_svc_* functions are the ONLY systemctl-aware code: a test
# overrides them after sourcing this file (later definitions win in bash).
#
# Sequence contract (docs/BUILD.md §5 Path 4, docs/RUNBOOK.md §4.8), binding
# order enforced by upgrade_node():
#
#   stop service -> BACK UP (db + -wal/-shm + previous binary + MANIFEST.txt
#   into a generation dir, keep the last 3) -> only THEN touch anything
#   (idempotent provisioning subset: changed configs replaced with a .dtn-bak,
#   binary swapped) -> start -> health gate (GET /api/v1/health: HTTP 200 +
#   "status":"ok" + build identity + the live PRAGMA user_version equal to the
#   served schema_version) -> on ANY gate or provisioning failure: automatic
#   rollback (restore the generation, keep the post-attempt store as
#   pre-restore-<UTC> evidence, re-verify health, report loudly).
#
# Migration interplay (docs/protocol.md §15.3): the backup is taken BEFORE the
# new binary ever opens the database, so a failed migration is recovered by a
# file restore — consistent with the forward-only, downgrade-refusing chain.
# A binary-only manual downgrade on a migrated store refuses to start (the
# §15.3 refusal names both versions); that is the signal to run
# `install.sh --rollback` — not to swap the binary again — so the DB backup is
# restored together with the old binary.
#
# Style: assumes the caller's strict mode (set -euo pipefail), like every
# script in this repository; every fallible command is explicitly guarded so
# the library is safe to source under it.

DTN_INSTALL_DIR="${DTN_INSTALL_DIR:-/opt/dtn-node}"
DTN_DATA_DIR="${DTN_DATA_DIR:-/var/lib/dtn-node}"
DTN_DB="${DTN_DB:-$DTN_DATA_DIR/node_storage.db}"
DTN_BACKUP_DIR="${DTN_BACKUP_DIR:-$DTN_DATA_DIR/backups}"
DTN_KEEP_GENERATIONS="${DTN_KEEP_GENERATIONS:-3}"
DTN_SERVICE="${DTN_SERVICE:-dtn-node}"
DTN_HEALTH_URL="${DTN_HEALTH_URL:-http://127.0.0.1:8080/api/v1/health}"
DTN_HEALTH_HOST="${DTN_HEALTH_HOST:-offgrid.local:8080}"
DTN_HEALTH_TIMEOUT="${DTN_HEALTH_TIMEOUT:-120}"
DTN_OWNER="${DTN_OWNER:-dtn:dtn}"

upgrade_log() { echo "upgrade: $*"; }
upgrade_die() { echo "upgrade: ERROR: $*" >&2; exit 1; }

# --- service actions (the only systemctl-aware code; tests override these) ----

upgrade_svc_stop() { systemctl stop "$DTN_SERVICE"; }
upgrade_svc_start() { systemctl start "$DTN_SERVICE"; }
upgrade_svc_active() { systemctl is-active --quiet "$DTN_SERVICE"; }

# --- small helpers --------------------------------------------------------------

# upgrade_sha256 FILE — portable sha256 (macOS shasum / GNU sha256sum), empty
# when neither tool exists (every consumer tolerates the absence).
upgrade_sha256() {
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" 2>/dev/null | awk '{print $1}'
    elif command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" 2>/dev/null | awk '{print $1}'
    fi
}

# upgrade_health_member KEY JSON — value of one STRING member of the compact
# single-line JSON documents the daemon serves (§10.7 health / §15.5
# capabilities: member names are unique, so a greedy sed is exact). Empty
# when absent.
upgrade_health_member() {
    printf '%s' "$2" | sed -nE "s/.*\"$1\":\"([^\"]*)\".*/\1/p" | tail -n 1
}

# upgrade_health_num KEY JSON — value of one INTEGER member (a separate
# helper because [^"]* would swallow a trailing comma on numeric members).
upgrade_health_num() {
    printf '%s' "$2" | sed -nE "s/.*\"$1\":([0-9]+).*/\1/p" | tail -n 1
}

# upgrade_read_user_version — the store's PRAGMA user_version, read-only via
# the sqlite3 CLI when present; empty when the CLI or the store is missing
# (the health gate's migration check is best-effort by design: Raspberry Pi OS
# Lite does not ship sqlite3 and the upgrade must not depend on it).
upgrade_read_user_version() {
    command -v sqlite3 >/dev/null 2>&1 || return 0
    [ -f "$DTN_DB" ] || return 0
    sqlite3 -readonly "$DTN_DB" 'PRAGMA user_version;' 2>/dev/null || return 0
}

# upgrade_running_health — the health document of the RUNNING daemon (§10.7),
# empty when it does not answer within 3 s.
upgrade_running_health() {
    curl -s --max-time 3 -H "Host: $DTN_HEALTH_HOST" "$DTN_HEALTH_URL" 2>/dev/null || true
}

# upgrade_manifest_get KEY FILE — one key=value line of a generation's
# MANIFEST.txt (comments and unknown lines ignored).
upgrade_manifest_get() {
    sed -nE "s/^$1=(.*)\$/\1/p" "$2" 2>/dev/null | tail -n 1
}

# --- backup generations -----------------------------------------------------------

# upgrade_backup_generation [LABEL] [OLD_BUILD] [OLD_USER_VERSION] — snapshot
# the store (main db + any -wal/-shm sidecars) and the current daemon binary
# into a NEW generation directory under $DTN_BACKUP_DIR, plus a MANIFEST.txt
# the rollback gate reads its OLD expectations from. The service MUST already
# be stopped (the orchestrators enforce: stop, backup, only then swap).
# Echoes the generation directory path. Labels must sort in creation order —
# the default label guarantees it (UTC timestamp prefix, build id suffix,
# -N dedup), prune and "latest" both rely on it.
upgrade_backup_generation() {
    local label="${1:-}"
    local old_build="${2:-}"
    local old_uv="${3:-}"
    [ -f "$DTN_DB" ] || upgrade_die "no database at $DTN_DB — nothing to back up (is this a provisioned node?)"
    if [ -z "$label" ]; then
        label="upgrade-$(date -u +%Y%m%dT%H%M%SZ)-$(printf '%s' "${old_build:-unknown}" | tr -c 'A-Za-z0-9._-' '_')"
    fi
    local gen="$DTN_BACKUP_DIR/$label"
    local n=2
    while [ -e "$gen" ]; do
        gen="$DTN_BACKUP_DIR/$label-$n"
        n=$((n + 1))
    done
    mkdir -p "$gen"
    cp -p "$DTN_DB" "$gen/$(basename "$DTN_DB")"
    local sc
    for sc in "$DTN_DB-wal" "$DTN_DB-shm"; do
        if [ -f "$sc" ]; then
            cp -p "$sc" "$gen/"
        fi
    done
    if [ -f "$DTN_INSTALL_DIR/dtn-node" ]; then
        cp -p "$DTN_INSTALL_DIR/dtn-node" "$gen/dtn-node"
    fi
    {
        printf '# dtn-node upgrade backup generation (issue #22)\n'
        printf 'created_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf 'old_build=%s\n' "${old_build:-unknown}"
        printf 'old_user_version=%s\n' "${old_uv:-unknown}"
        printf 'db=%s\n' "$(basename "$DTN_DB")"
        printf 'db_sha256=%s\n' "$(upgrade_sha256 "$DTN_DB")"
        printf 'binary_sha256=%s\n' "$(upgrade_sha256 "$DTN_INSTALL_DIR/dtn-node")"
    } > "$gen/MANIFEST.txt"
    printf '%s' "$gen"
}

# upgrade_list_generations — generation names, oldest first (name sort).
upgrade_list_generations() {
    [ -d "$DTN_BACKUP_DIR" ] || return 0
    ls -1 "$DTN_BACKUP_DIR" | sort
}

# upgrade_prune_generations [KEEP] — delete the OLDEST generations beyond
# KEEP (default $DTN_KEEP_GENERATIONS = 3): the undo window stays bounded
# without ever deleting the newest state.
upgrade_prune_generations() {
    local keep="${1:-$DTN_KEEP_GENERATIONS}"
    [ -d "$DTN_BACKUP_DIR" ] || return 0
    local total cut g
    total="$(upgrade_list_generations | wc -l | tr -d ' ')"
    [ "$total" -gt "$keep" ] || return 0
    cut=$((total - keep))
    upgrade_list_generations | head -n "$cut" | while IFS= read -r g; do
        rm -rf "$DTN_BACKUP_DIR/$g"
        upgrade_log "pruned old backup generation $g"
    done
}

# --- binary swap --------------------------------------------------------------------

# upgrade_swap_binary SRC — replace ONLY the daemon binary (mode 0755). The
# Pi's --upgrade path swaps through provision.sh's install_binary instead
# (same file plus the root:root ownership it enforces); this primitive is
# what tests/upgrade_e2e.sh drives and what a manual binary-only refresh uses.
upgrade_swap_binary() {
    local src="$1"
    [ -f "$src" ] || upgrade_die "new binary not found: $src"
    install -m 0755 "$src" "$DTN_INSTALL_DIR/dtn-node"
}

# --- health gate ----------------------------------------------------------------------

# upgrade_probe_staged BIN — run the staged NEW binary against a THROWAWAY
# database (never the real store) on a loopback port and echo
# "<build> <schema_version>" read from its own /api/v1/health. This hands the
# post-restart gate exact expectations with zero extra tooling. The port is
# picked from the tool-reserved high range (disjoint from the test suites'
# 18091-18099 and the OS ephemeral ranges) with a retry when a daemon exits
# on "address already in use". Returns 1 when the binary cannot run on this
# host (foreign arch, no tooling) — callers tolerate it and the gate falls
# back to the weaker checks.
upgrade_probe_staged() {
    local bin="$1" scratch pid port doc logf build="" schema="" attempt i
    scratch="$(mktemp -d "${TMPDIR:-/tmp}/dtn-upgrade-probe.XXXXXX")"
    for attempt in 1 2 3; do
        port=$(( 21500 + (RANDOM % 400) ))
        logf="$scratch/log"
        rm -f "$logf" "$scratch/probe.db" "$scratch/probe.db-wal" "$scratch/probe.db-shm"
        "$bin" -addr "127.0.0.1:$port" -db "$scratch/probe.db" >"$logf" 2>&1 &
        pid=$!
        for i in $(seq 1 50); do
            if grep -qF "listening on 127.0.0.1:$port" "$logf" 2>/dev/null; then break; fi
            kill -0 "$pid" 2>/dev/null || break
            sleep 0.2
        done
        if grep -qF "listening on 127.0.0.1:$port" "$logf" 2>/dev/null; then
            doc="$(curl -s --max-time 3 -H "Host: $DTN_HEALTH_HOST" "http://127.0.0.1:$port/api/v1/health" 2>/dev/null || true)"
            build="$(upgrade_health_member build "$doc")"
            schema="$(upgrade_health_num schema_version "$doc")"
        fi
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
        if [ -n "$build" ]; then break; fi
    done
    rm -rf "$scratch"
    [ -n "$build" ] || return 1
    printf '%s %s' "$build" "$schema"
}

# upgrade_health_once [EXPECT_BUILD] [EXPECT_SCHEMA] — ONE health poll; 0
# only when every configured check passes:
#   * HTTP 200 from $DTN_HEALTH_URL (Host = the canonical origin, §10.2);
#   * "status":"ok" (§10.7 liveness — the process the watchdog supervises);
#   * the build member is non-empty, and equals EXPECT_BUILD when given
#     (the probe-derived identity of the staged binary — i.e. the swapped-in
#     build is actually the one serving);
#   * schema_version equals EXPECT_SCHEMA when given;
#   * when the sqlite3 CLI is available: the live PRAGMA user_version equals
#     the served schema_version — the §15.3 migration chain really landed.
upgrade_health_once() {
    local expect_build="${1:-}" expect_schema="${2:-}"
    local raw code body build schema uv
    raw="$(curl -s --max-time 3 -w '%{http_code}' -H "Host: $DTN_HEALTH_HOST" "$DTN_HEALTH_URL" 2>/dev/null)" || return 1
    code="${raw: -3}"
    [ "$code" = "200" ] || return 1
    body="${raw:0:${#raw}-3}"
    [ "$(upgrade_health_member status "$body")" = "ok" ] || return 1
    build="$(upgrade_health_member build "$body")"
    [ -n "$build" ] || return 1
    if [ -n "$expect_build" ] && [ "$build" != "$expect_build" ]; then return 1; fi
    schema="$(upgrade_health_num schema_version "$body")"
    if [ -n "$expect_schema" ] && [ -n "$schema" ] && [ "$schema" != "$expect_schema" ]; then return 1; fi
    uv="$(upgrade_read_user_version)"
    if [ -n "$uv" ] && [ -n "$schema" ] && [ "$uv" != "$schema" ]; then return 1; fi
    return 0
}

# upgrade_health_gate [TIMEOUT] [EXPECT_BUILD] [EXPECT_SCHEMA] — poll every
# second until the checks pass or the budget expires. 0 = healthy (the ONLY
# success verdict), 1 = gate FAILED (the orchestrator rolls back).
upgrade_health_gate() {
    local timeout="${1:-$DTN_HEALTH_TIMEOUT}" expect_build="${2:-}" expect_schema="${3:-}"
    local deadline
    deadline=$(( $(date +%s) + timeout ))
    while :; do
        if upgrade_health_once "$expect_build" "$expect_schema"; then
            return 0
        fi
        [ "$(date +%s)" -lt "$deadline" ] || return 1
        sleep 1
    done
}

# --- restore / rollback -----------------------------------------------------------------

# upgrade_chown_dtn_files — the restored store must stay writable by the
# unprivileged daemon user (provision.sh creates dtn:dtn). cp -p already
# preserves ownership when root; enforce it explicitly when we can.
upgrade_chown_dtn_files() {
    local user="${DTN_OWNER%%:*}"
    if [ "$(id -u)" = "0" ] && id "$user" >/dev/null 2>&1; then
        chown "$DTN_OWNER" "$DTN_DB" 2>/dev/null || true
        if [ -f "$DTN_DB-wal" ]; then chown "$DTN_OWNER" "$DTN_DB-wal" 2>/dev/null || true; fi
        if [ -f "$DTN_DB-shm" ]; then chown "$DTN_OWNER" "$DTN_DB-shm" 2>/dev/null || true; fi
    fi
}

# upgrade_rollback_generation NAME_OR_PATH — restore the previous binary +
# store from a backup generation (a bare generation NAME under $DTN_BACKUP_DIR
# or the full generation PATH upgrade_backup_generation echoed). The service
# MUST be stopped. Whatever the CURRENT store is (migrated by the failed new
# binary, marked newer, or half-touched) is preserved first as
# $DTN_DATA_DIR/pre-restore-<UTC>/ — loss with evidence, the same quarantine
# discipline as the corruption path.
upgrade_rollback_generation() {
    local name="$1"
    local gen="$DTN_BACKUP_DIR/$name"
    if [ ! -d "$gen" ] && [ -d "$name" ]; then
        gen="$name"
    fi
    local label db_name
    label="$(basename "$gen")"
    db_name="$(basename "$DTN_DB")"
    [ -d "$gen" ] || upgrade_die "no such backup generation: $gen"
    [ -f "$gen/$db_name" ] || upgrade_die "backup generation $label holds no $db_name"
    [ -f "$gen/dtn-node" ] || upgrade_die "backup generation $label holds no dtn-node binary"
    local ev="$DTN_DATA_DIR/pre-restore-$(date -u +%Y%m%dT%H%M%SZ)"
    if [ -f "$DTN_DB" ]; then
        mkdir -p "$ev"
        mv "$DTN_DB" "$ev/"
        if [ -f "$DTN_DB-wal" ]; then mv "$DTN_DB-wal" "$ev/"; fi
        if [ -f "$DTN_DB-shm" ]; then mv "$DTN_DB-shm" "$ev/"; fi
        upgrade_log "current store preserved as evidence: $ev"
    fi
    cp -p "$gen/$db_name" "$DTN_DB"
    if [ -f "$gen/$db_name-wal" ]; then cp -p "$gen/$db_name-wal" "$DTN_DB-wal"; fi
    if [ -f "$gen/$db_name-shm" ]; then cp -p "$gen/$db_name-shm" "$DTN_DB-shm"; fi
    upgrade_swap_binary "$gen/dtn-node"
    upgrade_chown_dtn_files
    upgrade_log "restored the binary + store from generation $label"
}

# --- orchestrators ------------------------------------------------------------------------

# upgrade_auto_rollback GEN [OLD_BUILD] [OLD_USER_VERSION] — the automatic
# recovery after a failed upgrade: stop, restore the generation, start, and
# re-run the health gate against the OLD binary's expectations. Returns 1
# (and says so loudly) when even the rolled-back node is not healthy.
upgrade_auto_rollback() {
    local gen="$1" old_build="${2:-}" old_uv="${3:-}"
    upgrade_log "ROLLBACK: stopping the service and restoring $gen"
    upgrade_svc_stop
    upgrade_rollback_generation "$gen"
    upgrade_svc_start
    if upgrade_health_gate "$DTN_HEALTH_TIMEOUT" "$old_build" "$old_uv"; then
        upgrade_log "ROLLBACK OK: the node serves again (build ${old_build:-previous}, store from $gen)"
        return 0
    fi
    upgrade_log "ROLLBACK INCOMPLETE: $gen is restored but the health gate still fails — needs manual attention (docs/RUNBOOK.md §4)"
    return 1
}

# upgrade_node BIN_SRC RASPBERRY_DIR — the full `install.sh --upgrade`
# sequence on a provisioned Pi (the caller has verified root, the board, the
# architecture and the release bundle). Binding order:
#   preflight notes -> probe the staged binary -> STOP -> BACK UP -> only
#   then the idempotent provisioning subset (changed configs + binary swap)
#   -> start -> health gate -> automatic rollback on ANY failure.
# The binary swap itself rides on provision.sh's install_binary (single
# source of truth for ownership/mode); the STEPS subset selector keeps every
# provisioning step idempotent and network-free (no apt on the offline Pi).
upgrade_node() {
    local bin_src="$1" raspberry_dir="$2"
    local old_build old_uv expected exp_build="" exp_schema="" gen

    old_build="$(upgrade_health_member build "$(upgrade_running_health)")"
    old_uv="$(upgrade_read_user_version)"
    upgrade_log "current build: ${old_build:-unknown}; store schema version (PRAGMA user_version): ${old_uv:-unknown (sqlite3 CLI absent)}"

    if expected="$(upgrade_probe_staged "$bin_src")"; then
        exp_build="${expected%% *}"
        exp_schema="${expected#* }"
        upgrade_log "staged binary self-reports build=$exp_build schema_version=$exp_schema"
    else
        upgrade_log "staged binary could not be probed on this host: the gate falls back to liveness + build-change checks"
    fi

    upgrade_log "stopping $DTN_SERVICE"
    upgrade_svc_stop

    # (issue #22) BACKUP FIRST, THEN touch anything: the store + the previous
    # binary are on disk before the new release can alter either.
    gen="$(upgrade_backup_generation "" "$old_build" "$old_uv")"
    upgrade_prune_generations
    upgrade_log "backup generation: $gen (keeping the last $DTN_KEEP_GENERATIONS)"

    upgrade_log "applying the idempotent provisioning subset (changed configs replaced with .dtn-bak, binary swapped)"
    if ! (cd "$raspberry_dir" && STEPS="preflight static_ip install_configs install_binary enable_units field_hardening persist_firewall" ./provision.sh); then
        upgrade_log "provisioning subset FAILED"
        upgrade_auto_rollback "$gen" "$old_build" "$old_uv" || true
        upgrade_die "upgrade aborted; the node was rolled back to $gen"
    fi

    upgrade_log "starting $DTN_SERVICE (storage migrations run on open, §15.3)"
    upgrade_svc_start

    if upgrade_health_gate "$DTN_HEALTH_TIMEOUT" "$exp_build" "$exp_schema"; then
        upgrade_log "UPGRADE OK: build=${exp_build:-changed} schema_version=${exp_schema:-n/a}; previous state preserved at $gen"
        return 0
    fi
    upgrade_log "HEALTH GATE FAILED after the upgrade"
    upgrade_auto_rollback "$gen" "$old_build" "$old_uv" || true
    upgrade_die "upgrade failed and was rolled back to $gen (the pre-upgrade store is intact; the post-attempt store is kept under $DTN_DATA_DIR/pre-restore-*)"
}

# upgrade_rollback_main [GENERATION] — the `install.sh --rollback` entry
# point: list the generations, restore the chosen (default: latest) one and
# verify health against the generation manifest's OLD binary expectations.
upgrade_rollback_main() {
    local want="${1:-}"
    local gens
    gens="$(upgrade_list_generations)"
    [ -n "$gens" ] || upgrade_die "no backup generations in $DTN_BACKUP_DIR — nothing to roll back to"
    upgrade_log "available backup generations:"
    printf '%s\n' "$gens" | sed 's/^/upgrade:   /'
    if [ -z "$want" ]; then
        want="$(printf '%s\n' "$gens" | tail -n 1)"
        upgrade_log "no generation requested: using the LATEST ($want) — pick one with install.sh --rollback --from NAME"
    fi
    [ -d "$DTN_BACKUP_DIR/$want" ] || upgrade_die "no such backup generation: $want"
    local manifest="$DTN_BACKUP_DIR/$want/MANIFEST.txt"
    local old_build="" old_uv=""
    if [ -f "$manifest" ]; then
        old_build="$(upgrade_manifest_get old_build "$manifest")"
        old_uv="$(upgrade_manifest_get old_user_version "$manifest")"
        if [ "$old_build" = "unknown" ]; then old_build=""; fi
        if [ "$old_uv" = "unknown" ]; then old_uv=""; fi
    fi
    upgrade_log "rolling back to $want (old build ${old_build:-unknown}, old schema ${old_uv:-unknown})"
    upgrade_svc_stop
    upgrade_rollback_generation "$want"
    upgrade_svc_start
    if upgrade_health_gate "$DTN_HEALTH_TIMEOUT" "$old_build" "$old_uv"; then
        upgrade_log "ROLLBACK OK: the node serves again from generation $want"
        return 0
    fi
    upgrade_die "rollback restored $want but the health gate fails — see docs/RUNBOOK.md §4 (the displaced store is under $DTN_DATA_DIR/pre-restore-*)"
}
