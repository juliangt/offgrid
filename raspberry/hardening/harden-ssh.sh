#!/usr/bin/env bash
# harden-ssh.sh — minimal SSH attack surface for the off-grid DTN dead-drop
# node (Module A, issue #16 Track 3).
# Repo path : raspberry/hardening/harden-ssh.sh
# Install   : /usr/local/sbin/dtn-harden-ssh.sh (provision.sh, step 8)
# Run once per provisioning (idempotent: an identical drop-in is a no-op).
#
# Usage:
#   dtn-harden-ssh.sh            apply (root): validate the MERGED sshd config
#                                with "sshd -t", then install the drop-in
#   dtn-harden-ssh.sh --dry-run  print exactly what apply WOULD do; runs the
#                                read-only validation when possible and never
#                                writes (rootless-safe on a dev machine)
#
# WHAT it does: installs sshd-hardening.conf (same directory) as
# /etc/ssh/sshd_config.d/00-dtn-hardening.conf — key-only auth, no root
# login, tight auth/connection budgets, no agent/TCP forwarding. See the
# drop-in header for the precedence and threat reasoning.
#
# WHY validate BEFORE installing: "sshd -t" fails hard on bad syntax/keys,
# and a broken config means sshd refuses to (re)start — i.e. a locked-out
# operator. The validation here runs the drop-in EXACTLY as it will be
# parsed in production: Bookworm's sshd_config Includes
# /etc/ssh/sshd_config.d/*.conf at the TOP of the file and sshd applies
# first-match, so <drop-in> + <main file> concatenated is the same effective
# configuration the daemon will see. A failure aborts with the previous
# configuration untouched.
#
# ROLLBACK / LOCKOUT NOTE (read before deploying without a test key):
#   * Drop-in precedence also means recovery is one file away: the previous
#     configuration is preserved as
#     /etc/ssh/sshd_config.d/00-dtn-hardening.conf.dtn-bak, and deleting
#     (or moving) the drop-in restores the stock behaviour after
#     "systemctl restart ssh".
#   * The node is a headless island with no uplink. If you enable operator
#     SSH over the AP (ALLOW_SSH=1) you MUST install your key and verify a
#     key-based login BEFORE walking away — PasswordAuthentication no means
#     a lost key is not recoverable over the network.
#   * With keys missing and ALLOW_SSH=0 (default), the ONLY way back in is
#     the physical console: keyboard+monitor or a USB-serial TTL cable on
#     the Pi's UART (the power snippet keeps the PL011 UART available —
#     raspberry/power/config.txt.snippet disables Bluetooth for exactly that
#     reason). This is the documented field-ops path and will be expanded
#     into the operator runbook in a later phase (docs/BUILD.md §5 covers
#     the local-console provisioning access in the meantime).

set -euo pipefail

# Environment overrides so tests/redeploys can point at other paths; the
# defaults are the provisioned locations.
SSHD_BIN="${SSHD_BIN:-/usr/sbin/sshd}"
SSHD_MAIN_CONF="${SSHD_MAIN_CONF:-/etc/ssh/sshd_config}"
DROP_IN_DIR="${DROP_IN_DIR:-/etc/ssh/sshd_config.d}"
SCRIPT_DIR="${SCRIPT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
DROP_IN_SRC="${DROP_IN_SRC:-$SCRIPT_DIR/sshd-hardening.conf}"
# provision.sh stages the drop-in under the dtn- prefix next to the installed
# script; the repo checkout keeps the plain name. First one that exists wins.
[ -f "$DROP_IN_SRC" ] || DROP_IN_SRC="$SCRIPT_DIR/dtn-sshd-hardening.conf"
DROP_IN_NAME="00-dtn-hardening.conf"
DROP_IN_DEST="$DROP_IN_DIR/$DROP_IN_NAME"

DRY_RUN=0
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        -h | --help)
            sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//; /^$/d; /Usage:/q' | head -n 20
            exit 0
            ;;
        *)
            echo "harden-ssh: ERROR: unknown option '$arg' (usage: harden-ssh.sh [--dry-run])" >&2
            exit 1
            ;;
    esac
done

log() { echo "harden-ssh: $*"; }
die() { echo "harden-ssh: ERROR: $*" >&2; exit 1; }

# No sshd, no listener, nothing to harden (Raspberry Pi OS images without
# openssh-server): say so and exit 0 so provisioning never fails on this step.
if [ ! -x "$SSHD_BIN" ]; then
    log "sshd not installed at $SSHD_BIN: no SSH attack surface, nothing to do"
    exit 0
fi

[ -f "$DROP_IN_SRC" ] || die "drop-in source missing: $DROP_IN_SRC"
[ -f "$SSHD_MAIN_CONF" ] || die "main sshd config missing: $SSHD_MAIN_CONF"

# --- 1. validate the merged configuration (the production parse order) -------
#
# Concatenate drop-in + main file: the real sshd_config Includes *.conf at the
# top, and sshd's first-match semantics make this byte-order equivalent for
# every keyword the drop-in sets. Anything already ON disk in $DROP_IN_DIR is
# part of the production parse too — validate with those in place (the not-
# yet-installed 00-dtn file is exercised explicitly below instead).
merge_check() {
    local tmp
    tmp="$(mktemp)"
    {
        # Every drop-in that will exist AFTER this run, in Include order.
        # (if-statement form on purpose: a trailing "[ ... ] && cat" whose
        # guard fails would leave the group non-zero and trip set -e.)
        for f in "$DROP_IN_DIR"/*.conf; do
            if [ -f "$f" ] && [ "$(basename "$f")" != "$DROP_IN_NAME" ]; then
                cat "$f"
            fi
        done
        cat "$DROP_IN_SRC"
        cat "$SSHD_MAIN_CONF"
    } > "$tmp"
    "$SSHD_BIN" -t -f "$tmp"
    rm -f "$tmp"
}

if [ "$DRY_RUN" = "1" ]; then
    if [ "$(id -u)" -eq 0 ] && [ -d /etc/ssh ]; then
        # Best-effort read-only validation; host keys may not exist on a
        # dev machine, which is a skip, not a failure.
        if merge_check; then
            log "[dry-run] merged-config validation (sshd -t): OK"
        else
            log "[dry-run] merged-config validation skipped (host keys/config absent on this host?)"
        fi
    else
        log "[dry-run] validation needs root + /etc/ssh: skipped (dry-run is observational)"
    fi
    log "[dry-run] would install $DROP_IN_SRC -> $DROP_IN_DEST (0644)"
    exit 0
fi

[ "$(id -u)" -eq 0 ] || die "must run as root (installs into /etc/ssh/sshd_config.d); try --dry-run"

log "validating merged sshd configuration with $SSHD_BIN -t ..."
if ! merge_check; then
    die "sshd -t rejected the merged configuration — previous config left UNTOUCHED; fix sshd-hardening.conf and re-run (see the rollback note in this script's header)"
fi

# --- 2. install (idempotent, backup-on-diff like provision.sh) ---------------

if [ -f "$DROP_IN_DEST" ] && cmp -s "$DROP_IN_SRC" "$DROP_IN_DEST"; then
    log "$DROP_IN_DEST already up to date"
else
    mkdir -p "$DROP_IN_DIR"
    if [ -f "$DROP_IN_DEST" ]; then
        cp -a "$DROP_IN_DEST" "$DROP_IN_DEST.dtn-bak"
        log "backed up existing $DROP_IN_DEST to $DROP_IN_DEST.dtn-bak (restore = move back + 'systemctl restart ssh')"
    fi
    install -m 0644 "$DROP_IN_SRC" "$DROP_IN_DEST"
    log "drop-in installed: $DROP_IN_DEST"
fi

# Verify: the file on disk carries the two non-negotiable directives.
grep -q '^PermitRootLogin no$' "$DROP_IN_DEST" || die "post-check failed: PermitRootLogin no missing from $DROP_IN_DEST"
grep -q '^PasswordAuthentication no$' "$DROP_IN_DEST" || die "post-check failed: PasswordAuthentication no missing from $DROP_IN_DEST"

log "OK — takes effect on the next ssh restart/reboot (provisioning never restarts services: the reboot is the activation step)"
