#!/usr/bin/env bash
# harden-services.sh — unprivileged daemon + SD-wear controls for the off-grid
# DTN dead-drop node (Module A, issue #16 Track 3).
# Repo path : raspberry/hardening/harden-services.sh
# Install   : /usr/local/sbin/dtn-harden-services.sh (provision.sh, step 8)
# Idempotent: every step check-then-act, safe to re-run at any time.
#
# Usage:
#   dtn-harden-services.sh            apply (root)
#   dtn-harden-services.sh --dry-run  print exactly what apply WOULD do — no
#                                     writes, no user/account mutations
#                                     (rootless-safe; what
#                                     tests/hardening_structure.sh exercises)
#
# WHAT (issue #16 Track 3, "hostile clients ... with zero manual SSH"):
#   1. the daemon's service account is a SYSTEM account: nologin shell, no
#      password login, home pinned to the data directory — created if
#      missing, REPAIRED if an older provisioning left it with a real shell;
#   2. the state directory is 0750 dtn:dtn (the only writable path the
#      daemon needs);
#   3. the installed dtn-node.service is verified to carry the full
#      hardening set (unprivileged User, NoNewPrivileges, ProtectSystem=
#      strict with ReadWritePaths limited to the state dir, Restart=always,
#      watchdog) — the set itself lives in the unit template
#      raspberry/systemd/dtn-node.service;
#   4. journald goes VOLATILE (RAM-only, size-capped) so log volume can
#      never wear the SD card (see the drop-in comment below).

set -euo pipefail

# Environment overrides (tests / non-standard deployments); defaults are the
# provisioned paths, matching provision.sh and systemd/dtn-node.service.
NODE_USER="${NODE_USER:-dtn}"
NODE_GROUP="${NODE_GROUP:-dtn}"
DATA_DIR="${DATA_DIR:-/var/lib/dtn-node}"
NODE_UNIT="${NODE_UNIT:-/etc/systemd/system/dtn-node.service}"
JOURNALD_CONF_DIR="${JOURNALD_CONF_DIR:-/etc/systemd/journald.conf.d}"
NOLOGIN_SHELL="${NOLOGIN_SHELL:-/usr/sbin/nologin}"

DRY_RUN=0
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        -h | --help)
            sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//; /^$/d; /Usage:/q' | head -n 20
            exit 0
            ;;
        *)
            echo "harden-services: ERROR: unknown option '$arg' (usage: harden-services.sh [--dry-run])" >&2
            exit 1
            ;;
    esac
done

log() { echo "harden-services: $*"; }
die() { echo "harden-services: ERROR: $*" >&2; exit 1; }

# --- DATA DURABILITY ON THIS BOX (issue #16 Track 3; read before changing) ---
#
# What IS (no partitioning scheme is invented here): Raspberry Pi OS ships a
# FAT boot partition mounted at /boot/firmware and ONE ext4 root partition.
# The database lives on that root filesystem at $DATA_DIR/node_storage.db
# (systemd/dtn-node.service -db path; provision.sh creates the directory).
# There is NO separate data partition — the durability design therefore is:
#
#   * ext4 journal, DEFAULT 5 s commit interval, KEPT AS IS on purpose.
#     Rationale: a power cut is ROUTINE here (solar + LiFePO4, docs/
#     hardware.md), so the question is the loss window, and the node's write
#     volume is tiny (protocol §8.1 caps: ≤ 5000 envelopes ≈ ≤ 5 MB hot
#     data; a mule sync is ~210 KiB). Lengthening commit= would shave SD
#     writes the card does not need (industrial/high-endurance cards are the
#     guidance, docs/hardware.md §5) while widening the post-cut loss window
#     for everything that relies on the FS flush — strictly worse here.
#   * SQLite WAL mode is already in place (node/internal/storage/storage.go,
#     journal_mode=WAL + fsync-per-commit, protocol §9): after a dirty cut,
#     ext4 journal replay at mount plus the first storage.Open replaying the
#     -wal brings the DB back consistent. This is the boot path: power cut →
#     reboot → journal replay (seconds) → dtn-node starts (Restart=always) →
#     WAL recovery → READY.
#   * journald is the only high-volume writer on a quiet node → made
#     VOLATILE below (RAM-only, dies at reboot, zero SD wear).
#   * read-only-root interplay: with the optional overlay root
#     (raspberry/hardening/enable-readonly-root.sh) EVERYTHING under /
#     becomes RAM-volatile — including the data dir, unless it is kept on
#     the real ext4. That script therefore bind-mounts
#     /overlay-lower/var/lib/dtn-node over the merged view; the overlay MUST
#     NOT be enabled without that bind-mount. Both scripts assert it.
#
# CAPABILITIES NOTE: the daemon binds :8080 — an unprivileged port, so the
# unprivileged account needs NO capabilities (no setcap, no
# AmbientCapabilities=). If the deployment port ever moved below 1024, the
# smallest correct change is `AmbientCapabilities=CAP_NET_BIND_SERVICE` on
# the unit — do NOT run the daemon as root to get a low port.

JOURNAL_DROPIN_COMMENT='# Managed by raspberry/hardening/harden-services.sh (issue #16 Track 3).
# VOLATILE journal ON PURPOSE: the node cuts power routinely (solar), so any
# on-disk journal is both an SD-wear accelerant and one more dirty-shutdown
# replay cost. Counters-based telemetry (raspberry/hardening/dtn-telemetry.sh)
# does not need persistent logs; if an operator needs a boot-local log for
# debugging, journalctl still has everything since the current boot.
'

JOURNAL_DROPIN_BODY='[Journal]
Storage=volatile
# Cap: 16 MiB of RAM is ~1.5% of a Zero 2 W and far more than a quiet node
# ever produces between reboots (shields log a few lines per cycle).
SystemMaxUse=16M
'

# verify_unit_hardening PATH — the daemon must run unprivileged with the full
# systemd hardening set. Checks the INSTALLED unit; the repo template is the
# source of truth (systemd/dtn-node.service).
verify_unit_hardening() {
    local unit="$1" directive
    for directive in \
        '^User='"$NODE_USER"'$' \
        '^NoNewPrivileges=' \
        '^ProtectSystem=strict$' \
        '^ReadWritePaths='"$DATA_DIR"'$' \
        '^Restart=always$' \
        '^WatchdogSec='; do
        grep -qE -- "$directive" "$unit" || return 1
    done
}

# passwd_shell USER — login shell of USER (empty when the account is absent).
passwd_shell() {
    getent passwd "$1" 2>/dev/null | cut -d: -f7
}

# --- 1. service account -------------------------------------------------------

if [ "$DRY_RUN" = "1" ]; then
    if id "$NODE_USER" >/dev/null 2>&1; then
        log "[dry-run] user $NODE_USER exists; would enforce shell=$NOLOGIN_SHELL and a locked password"
    else
        log "[dry-run] would create system user $NODE_USER (home $DATA_DIR, no home created, shell $NOLOGIN_SHELL)"
    fi
    log "[dry-run] would ensure $DATA_DIR exists 0750 $NODE_USER:$NODE_GROUP"
    if [ -f "$NODE_UNIT" ]; then
        if verify_unit_hardening "$NODE_UNIT"; then
            log "[dry-run] $NODE_UNIT carries the hardening set: OK"
        else
            log "[dry-run] WARNING: $NODE_UNIT is missing part of the hardening set (re-run provision.sh to install the current unit)"
        fi
    else
        log "[dry-run] $NODE_UNIT not installed yet (provision.sh installs it); unit check skipped"
    fi
    log "[dry-run] would install journald drop-in at $JOURNALD_CONF_DIR/dtn-volatile.conf (Storage=volatile, SystemMaxUse=16M)"
    exit 0
fi

[ "$(id -u)" -eq 0 ] || die "must run as root (user/account and /etc changes); try --dry-run"

if id "$NODE_USER" >/dev/null 2>&1; then
    log "user $NODE_USER already exists"
    # Repair path: older provisionings (or a careless operator) may have left
    # a real shell on the service account. Enforce nologin.
    cur_shell="$(passwd_shell "$NODE_USER")"
    if [ "$cur_shell" != "$NOLOGIN_SHELL" ]; then
        usermod -s "$NOLOGIN_SHELL" "$NODE_USER"
        log "repaired shell on $NODE_USER: '$cur_shell' -> $NOLOGIN_SHELL"
    fi
    # A service account must never carry a usable password hash. useradd
    # --system locks the field ("!"); enforce it if a hash ever appeared.
    if ! getent passwd "$NODE_USER" | cut -d: -f2 | grep -q '^[*!]'; then
        usermod -L "$NODE_USER"
        log "locked password of $NODE_USER (a hash was present)"
    fi
else
    # Same shape provision.sh creates: system account, home INSIDE the data
    # dir but not created by useradd (the dir is made below with exact perms).
    useradd --system --home-dir "$DATA_DIR" --no-create-home --shell "$NOLOGIN_SHELL" "$NODE_USER"
    log "created system user $NODE_USER (shell $NOLOGIN_SHELL)"
fi
[ "$(passwd_shell "$NODE_USER")" = "$NOLOGIN_SHELL" ] || die "post-check failed: $NODE_USER shell is not $NOLOGIN_SHELL"

# --- 2. state directory -------------------------------------------------------

install -d -m 0750 -o "$NODE_USER" -g "$NODE_GROUP" "$DATA_DIR"
[ "$(stat -c '%a %U %G' "$DATA_DIR")" = "750 $NODE_USER $NODE_GROUP" ] \
    || die "post-check failed: $DATA_DIR is not 0750 $NODE_USER:$NODE_GROUP"
log "state dir OK: $DATA_DIR 0750 $NODE_USER:$NODE_GROUP"

# --- 3. unit hardening set ----------------------------------------------------

if [ -f "$NODE_UNIT" ]; then
    verify_unit_hardening "$NODE_UNIT" \
        || die "$NODE_UNIT lacks the hardening set (unprivileged user / ProtectSystem=strict + ReadWritePaths / Restart=always / watchdog) — re-run provision.sh to install the current unit template"
    log "unit OK: $NODE_UNIT carries the full hardening set"
else
    log "NOTE: $NODE_UNIT not installed (fresh host?) — provision.sh installs it; nothing to verify here"
fi

# --- 4. journald volatile (SD-wear control) -----------------------------------

mkdir -p "$JOURNALD_CONF_DIR"
if [ -f "$JOURNALD_CONF_DIR/dtn-volatile.conf" ] \
    && grep -q '^Storage=volatile$' "$JOURNALD_CONF_DIR/dtn-volatile.conf" \
    && grep -q '^SystemMaxUse=16M$' "$JOURNALD_CONF_DIR/dtn-volatile.conf"; then
    log "journald drop-in already in place"
else
    {
        printf '%s\n' "$JOURNAL_DROPIN_COMMENT"
        printf '%s\n' "$JOURNAL_DROPIN_BODY"
    } > "$JOURNALD_CONF_DIR/dtn-volatile.conf"
    log "journald drop-in installed: $JOURNALD_CONF_DIR/dtn-volatile.conf (Storage=volatile, SystemMaxUse=16M)"
    log "NOTE: takes effect at the next reboot (provisioning never restarts services)"
fi

# --- 5. no interactive shells on service accounts -----------------------------
#
# Defense in depth beyond our own user: any uid<1000 account whose shell is a
# real shell is a surprise on a field node and is REPORTED (not silently
# "fixed" — deciding for the operator which of those accounts are intentional
# is the runbook's job, not a provisioning script's). The `dtn` account was
# already enforced to nologin above.
shell_audit=0
while IFS=: read -r name _ uid _ _ _ shell; do
    [ "$uid" -lt 1000 ] || continue
    [ "$name" = "root" ] && continue
    case "$shell" in
        */nologin | */false | /bin/sync) continue ;;
        *)
            log "WARNING: system account '$name' (uid $uid) has interactive shell '$shell'"
            shell_audit=1
            ;;
    esac
done < /etc/passwd
if [ "$shell_audit" = "0" ]; then
    log "shell audit clean: no interactive shells on system accounts"
fi

log "OK — daemon runs unprivileged, state dir isolated, journal volatile"
