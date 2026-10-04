#!/usr/bin/env bash
# enable-readonly-root.sh — overlayfs read-only root for the off-grid DTN
# dead-drop node (Module A, issue #16 Track 3: tamper resistance for field
# units). DEFAULT OFF — this is an explicit operator step, never run by
# provision.sh.
#
# Repo path : raspberry/hardening/enable-readonly-root.sh
# Run ON THE PI as root:  sudo raspberry/hardening/enable-readonly-root.sh
# Modes:
#   (no args)      apply (root): install the initramfs overlay, regenerate the
#                  initramfs, wire config.txt. ACTIVATION = REBOOT (the same
#                  discipline as the rest of provisioning).
#   --dry-run      print every step verbatim, write nothing (rootless-safe;
#                  what tests/hardening_structure.sh exercises)
#   --status       report whether the read-only root is configured/active
#                  (rootless-safe; exit 0 always)
#
# ----------------------------------------------------------------------------
# MECHANISM (one, deliberately; and why the alternatives lost):
#
# Raspberry Pi OS Bookworm has no supported "overlayfs=" boot flag — the
# blessed mechanism (what raspi-config's Performance Options -> "Overlay FS"
# does under the hood) is an INITRAMFS script that re-stacks the root at
# boot. We therefore ship our own initramfs-tools init-bottom script (clean,
# standard integration point) instead of shelling out to raspi-config, for
# ONE functional reason: raspi-config's overlay makes the ENTIRE root
# RAM-volatile, which is correct only for systems that keep persistent data
# on a separate partition. This node's only durable state — the SQLite
# database at /var/lib/dtn-node — sits on the SINGLE ext4 root partition
# (Raspberry Pi OS ships FAT boot + one ext4 root; no data partition exists
# and none is invented here, see harden-services.sh's durability block).
# A whole-root overlay would silently turn every power cut into a full data
# loss event. Our init-bottom script is therefore the stock overlay PLUS one
# bind-mount: /var/lib/dtn-node stays on the REAL ext4 root, durable across
# reboots, while everything else on / becomes a RAM-backed overlay layer.
# (The `overlayroot` package route was rejected for the same reason: its
# tmpfs upper covers the data dir unless a data partition is added.)
#
# HOW BOOT WORKS WITH IT (also the power-cut path):
#   firmware -> kernel + initramfs-dtn (config.txt "initramfs" line)
#   -> initramfs mounts the real ext4 root (journal replay after a dirty cut
#      happens HERE, at mount — fast, no full fsck pass)
#   -> init-bottom: tmpfs upper + overlay over the real root, bind-mount the
#      data dir from the lower (real) root, hand control to the real init
#   -> dtn-node.service starts, storage.Open replays the WAL — consistent
#      after any power cut (see the boot-path comment in dtn-node.service).
#
# WHAT STAYS WRITABLE, HONESTLY:
#   * /var/lib/dtn-node        -> REAL ext4 (the bind-mount): durable, the
#                                 design's whole point.
#   * /boot/firmware           -> the real FAT partition (fstab mount into
#                                 the merged view): still writable, so kernel
#                                 and firmware updates keep landing. If the
#                                 unit is physically accessible, remounting
#                                 it read-only is a runbook step (later
#                                 phase); not done here because a field
#                                 operator may need to drop a release bundle
#                                 on the boot partition (install.sh --offline).
#   * /tmp /run /dev/shm       -> tmpfs anyway (unaffected).
#   * EVERYTHING ELSE on /     -> RAM overlay upper layer: writable until
#                                 reboot, then GONE.
#
# FIELD-OPS TRADE-OFF (read before enabling): every durable configuration
# change — hostapd country code, SSH keys, dnsmasq tweaks — needs a remount
# cycle, not just a file edit: run disable-readonly-root.sh, reboot, make the
# change, run this script again, reboot. Editing files "live" only writes the
# RAM layer and evaporates at the next power cut. This will be a numbered
# runbook procedure in a later phase; until then this header is the contract.
#
# RAM BUDGET: the upper layer is a tmpfs sized by the kernel default (half of
# RAM: ~256 MB on a 512 MB board). The database does NOT consume it (real
# ext4 via the bind-mount); the budget bounds abuse-writes and runaway logs,
# and unattended-upgrades' /var/cache writes land in it (they vanish at
# reboot, which is fine — the apt lists rebuild on the next daily run).
# ----------------------------------------------------------------------------

set -euo pipefail

# Environment overrides (tests point these at a scratch tree); the defaults
# are the provisioned Raspberry Pi OS Bookworm paths.
BOOT_DIR="${BOOT_DIR:-$([ -d /boot/firmware ] && echo /boot/firmware || echo /boot)}"
INITRAMFS_SCRIPT="${INITRAMFS_SCRIPT:-/usr/share/initramfs-tools/scripts/init-bottom/dtn-overlayroot}"
POST_UPDATE_HOOK="${POST_UPDATE_HOOK:-/etc/initramfs/post-update.d/dtn-overlayroot-regen}"
MODULES_FILE="${MODULES_FILE:-/etc/initramfs-tools/modules}"
INITRAMFS_IMG_NAME="initramfs-dtn"
CONFIG_TXT="${CONFIG_TXT:-$BOOT_DIR/config.txt}"
DATA_DIR="${DATA_DIR:-/var/lib/dtn-node}"
MKINITRAMFS="${MKINITRAMFS:-mkinitramfs}"

CONFIG_MARKER="# --- dtn-node read-only-root snippet (added by enable-readonly-root.sh) ---"
MODULE_MARKER="# added by enable-readonly-root.sh: the init-bottom overlay needs this in the initramfs"

MODE="apply"
for arg in "$@"; do
    case "$arg" in
        --dry-run) MODE="dry-run" ;;
        --status) MODE="status" ;;
        -h | --help)
            sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//; /^$/d; /Modes:/q' | head -n 14
            exit 0
            ;;
        *)
            echo "enable-readonly-root: ERROR: unknown option '$arg' (usage: enable-readonly-root.sh [--dry-run|--status])" >&2
            exit 1
            ;;
    esac
done

log() { echo "enable-readonly-root: $*"; }
die() { echo "enable-readonly-root: ERROR: $*" >&2; exit 1; }

# --- --status: pure inspection, never fails -----------------------------------

if [ "$MODE" = "status" ]; then
    root_fs="$(awk '$2 == "/" { print $3; exit }' /proc/mounts 2>/dev/null || echo unknown)"
    config_state="no"
    [ -f "$CONFIG_TXT" ] && grep -q "^initramfs $INITRAMFS_IMG_NAME followkernel$" "$CONFIG_TXT" 2>/dev/null && config_state="yes"
    script_state="no"
    [ -x "$INITRAMFS_SCRIPT" ] && script_state="yes"
    img_state="no"
    [ -f "$BOOT_DIR/$INITRAMFS_IMG_NAME" ] && img_state="yes"
    hook_state="no"
    [ -x "$POST_UPDATE_HOOK" ] && hook_state="yes"
    echo "status: running root is            : $root_fs (overlay = ACTIVE this boot)"
    echo "status: init-bottom script        : $script_state ($INITRAMFS_SCRIPT)"
    echo "status: initramfs image           : $img_state ($BOOT_DIR/$INITRAMFS_IMG_NAME)"
    echo "status: kernel-upgrade regen hook : $hook_state ($POST_UPDATE_HOOK)"
    echo "status: config.txt initramfs line : $config_state ($CONFIG_TXT)"
    if [ "$root_fs" = "overlay" ]; then
        echo "status: READ-ONLY ROOT ACTIVE (data dir $DATA_DIR must show as a bind-mount: 'mount | grep $DATA_DIR')"
    elif [ "$script_state" = "yes" ] && [ "$config_state" = "yes" ] && [ "$img_state" = "yes" ]; then
        echo "status: CONFIGURED — active after the next reboot"
    else
        echo "status: OFF (default; enable with $0 as root on the Pi)"
    fi
    exit 0
fi

# --- --dry-run / apply ----------------------------------------------------------
#
# Preflights live in APPLY mode only: a dry-run is observational and must
# work rootless on any machine (the test suite runs it without /boot or
# initramfs-tools present).

if [ "$MODE" = "apply" ]; then
    [ "$(id -u)" -eq 0 ] || die "must run as root (writes /usr/share/initramfs-tools and the boot partition); try --dry-run or --status"
    [ -f "$CONFIG_TXT" ] || die "boot config not found at $CONFIG_TXT — run on the Pi (Bookworm mounts the firmware partition at /boot/firmware)"
    command -v "$MKINITRAMFS" >/dev/null 2>&1 || die "$MKINITRAMFS not found: run 'apt-get install -y initramfs-tools' first (it is standard on Raspberry Pi OS) and re-run"
fi

# The generated init-bottom script. Kept in ONE place as a heredoc so the
# apply path, the dry-run printout and the rollback twin can never drift
# apart (provision.sh's heredoc pattern).
init_bottom_script() {
    cat <<'INIT_BOTTOM_EOF'
#!/bin/sh
# Generated by raspberry/hardening/enable-readonly-root.sh (issue #16 Track 3)
# — DO NOT EDIT ON THE PI: edit the generator and re-run it.
# Installed at: /usr/share/initramfs-tools/scripts/init-bottom/dtn-overlayroot
#
# At init-bottom the real root filesystem is mounted read-write at
# ${rootmnt}; when this script returns, initramfs hands ${rootmnt} to the
# real init. The script stacks a RAM-backed overlayfs over the root and
# bind-mounts the daemon's data directory from the REAL root so it stays
# durable. See enable-readonly-root.sh's header for the design contract.
#
# FAIL-OPEN POLICY: any error here writes a kernel-ring marker and exits 0,
# leaving the root writable — a field node that boots unprotected beats one
# that does not boot at all (the AP is its raison d'etre).

fail_open() {
    echo "dtn-overlayroot: $1 — booting with a WRITABLE root this boot" > /dev/kmsg 2>/dev/null || true
    exit 0
}

prereqs() { echo ""; }
case "$1" in
    prereqs) prereqs; exit 0 ;;
esac

# The overlay module is pulled into the initramfs via
# /etc/initramfs-tools/modules; modprobe covers a module-path-only build.
modprobe overlay 2>/dev/null || fail_open "cannot load the overlay module"

# RAM upper layer: every write under / lands here and dies at the next
# power cut or reboot. That is the tamper-resistance property.
mkdir -p /overlay 2>/dev/null || fail_open "cannot create /overlay"
mount -t tmpfs -o mode=0755 tmpfs /overlay 2>/dev/null || fail_open "cannot mount the tmpfs upper layer"
mkdir -p /overlay/lower /overlay/upper /overlay/work || fail_open "cannot lay out /overlay"

# Move the real root out of the way, then stack the overlay on ${rootmnt}.
mount --move "${rootmnt}" /overlay/lower 2>/dev/null || fail_open "cannot move the rootfs to /overlay/lower"
if ! mount -t overlay -o "lowerdir=/overlay/lower,upperdir=/overlay/upper,workdir=/overlay/work" overlay "${rootmnt}" 2>/dev/null; then
    mount --move /overlay/lower "${rootmnt}" 2>/dev/null || true
    fail_open "cannot mount the overlay root"
fi

# THE ONE DURABLE PATH: keep /var/lib/dtn-node on the REAL ext4 root. The
# database must survive power cuts — without this bind-mount the SQLite WAL
# would live in the RAM upper layer and evaporate (enable-readonly-root.sh
# header: "what stays writable"). Fail-open with a LOUD marker if it ever
# fails: a volatile data dir is a silent data-loss bug, not a cosmetic one.
mkdir -p /overlay/lower/var/lib/dtn-node "${rootmnt}/var/lib/dtn-node" 2>/dev/null || true
if mount --bind /overlay/lower/var/lib/dtn-node "${rootmnt}/var/lib/dtn-node" 2>/dev/null; then
    echo "dtn-overlayroot: /var/lib/dtn-node bind-mounted to the real root (durable)" > /dev/kmsg 2>/dev/null || true
else
    echo "dtn-overlayroot: WARNING: data-dir bind-mount FAILED — database is RAM-only this boot" > /dev/kmsg 2>/dev/null || true
fi

# Pin /overlay into the new root: the overlay's upperdir/workdir must stay
# mounted for the whole lifetime of the boot, and pivot_root would otherwise
# drop their mount point.
mkdir -p "${rootmnt}/overlay" 2>/dev/null || true
mount --move /overlay "${rootmnt}/overlay" 2>/dev/null || true

exit 0
INIT_BOTTOM_EOF
}

# Kernel-upgrade wiring: Debian's update-initramfs runs
# /etc/initramfs/post-update.d/* with "$1" = kernel version after every
# regeneration, so the custom image tracks kernel updates forever. Without
# this hook a kernel upgrade would leave a stale initramfs-dtn whose modules
# no longer match, i.e. a node that does not boot — that is the one thing a
# power-cut-survival feature must never cause.
post_update_hook() {
    cat <<'HOOK_EOF'
#!/bin/sh
# Generated by raspberry/hardening/enable-readonly-root.sh (issue #16 Track 3).
# Regenerate the overlay initramfs after every kernel/initramfs update so it
# never goes stale. Args (per initramfs-tools): $1 = kernel version.
set -e
BOOT_DIR_GUESS=/boot/firmware
[ -d "$BOOT_DIR_GUESS" ] || BOOT_DIR_GUESS=/boot
mkinitramfs -o "$BOOT_DIR_GUESS/initramfs-dtn" "$1"
exit 0
HOOK_EOF
}

if [ "$MODE" = "dry-run" ]; then
    log "[dry-run] would ensure the 'overlay' module line in $MODULES_FILE (marker: '$MODULE_MARKER')"
    log "[dry-run] would install the init-bottom script at $INITRAMFS_SCRIPT (0755):"
    init_bottom_script | sed 's/^/[dry-run]     /'
    log "[dry-run] would install the kernel-upgrade hook at $POST_UPDATE_HOOK (0755):"
    post_update_hook | sed 's/^/[dry-run]     /'
    log "[dry-run] would regenerate the initramfs: $MKINITRAMFS -o $BOOT_DIR/$INITRAMFS_IMG_NAME"
    log "[dry-run] would append to $CONFIG_TXT:"
    printf '%s\n%s\n' "$CONFIG_MARKER" "initramfs $INITRAMFS_IMG_NAME followkernel" | sed 's/^/[dry-run]     /'
    log "[dry-run] activation = REBOOT (nothing is started in-place)"
    exit 0
fi

# --- apply (root already verified in the preflight above) ------------------------

# 1. overlay module in every future initramfs build (marker-guarded append).
if grep -qxF "$MODULE_MARKER" "$MODULES_FILE" 2>/dev/null; then
    log "overlay module line already present in $MODULES_FILE"
else
    if [ -f "$MODULES_FILE" ]; then
        cp -a "$MODULES_FILE" "$MODULES_FILE.dtn-bak"
    fi
    { echo "$MODULE_MARKER"; echo "overlay"; } >> "$MODULES_FILE"
    log "added 'overlay' to $MODULES_FILE"
fi

# 2. the init-bottom script (backup-on-diff, install_file pattern).
if [ -f "$INITRAMFS_SCRIPT" ] && ! grep -q "Generated by raspberry/hardening/enable-readonly-root.sh" "$INITRAMFS_SCRIPT"; then
    die "$INITRAMFS_SCRIPT exists but was not generated by this script — refusing to clobber a foreign init-bottom hook"
fi
if [ -f "$INITRAMFS_SCRIPT" ] && cmp -s <(init_bottom_script) "$INITRAMFS_SCRIPT"; then
    log "init-bottom script already up to date"
else
    [ -f "$INITRAMFS_SCRIPT" ] && cp -a "$INITRAMFS_SCRIPT" "$INITRAMFS_SCRIPT.dtn-bak"
    init_bottom_script > "$INITRAMFS_SCRIPT"
    chmod 0755 "$INITRAMFS_SCRIPT"
    log "init-bottom script installed: $INITRAMFS_SCRIPT"
fi

# 3. kernel-upgrade regeneration hook.
if [ -f "$POST_UPDATE_HOOK" ] && cmp -s <(post_update_hook) "$POST_UPDATE_HOOK"; then
    log "post-update hook already up to date"
else
    [ -f "$POST_UPDATE_HOOK" ] && cp -a "$POST_UPDATE_HOOK" "$POST_UPDATE_HOOK.dtn-bak"
    post_update_hook > "$POST_UPDATE_HOOK"
    chmod 0755 "$POST_UPDATE_HOOK"
    log "kernel-upgrade hook installed: $POST_UPDATE_HOOK"
fi

# 4. regenerate the initramfs WITH the overlay module and the new script.
#    Regenerated on every run on purpose: after a kernel update this is the
#    step that makes a manual re-run fix a stale image too.
log "regenerating $BOOT_DIR/$INITRAMFS_IMG_NAME (this takes ~30 s) ..."
"$MKINITRAMFS" -o "$BOOT_DIR/$INITRAMFS_IMG_NAME" || die "mkinitramfs failed — nothing was enabled (config.txt untouched); inspect the error above"
[ -s "$BOOT_DIR/$INITRAMFS_IMG_NAME" ] || die "initramfs image missing/empty after mkinitramfs"

# 5. config.txt: load the image at boot (marker-guarded, provision.sh pattern).
if grep -qxF "$CONFIG_MARKER" "$CONFIG_TXT"; then
    log "config.txt snippet already present"
else
    cp -a "$CONFIG_TXT" "$CONFIG_TXT.dtn-bak"
    { echo ""; echo "$CONFIG_MARKER"; echo "initramfs $INITRAMFS_IMG_NAME followkernel"; } >> "$CONFIG_TXT"
    log "config.txt updated (backup: $CONFIG_TXT.dtn-bak)"
fi
grep -qxF "initramfs $INITRAMFS_IMG_NAME followkernel" "$CONFIG_TXT" \
    || die "post-check failed: config.txt lacks the initramfs line"

# 6. the data-dir contract, asserted on the artifacts we just wrote (both this
#    script and harden-services.sh depend on it — see harden-services.sh's
#    durability block).
grep -q "mount --bind /overlay/lower/var/lib/dtn-node" "$INITRAMFS_SCRIPT" \
    || die "post-check failed: the init-bottom script lost the data-dir bind-mount — refusing to enable a root overlay that would make the database volatile"

log "OK — CONFIGURED. The read-only root activates on the next REBOOT."
log "Rollback any time: sudo disable-readonly-root.sh && sudo reboot"
log "Check state after reboot: $0 --status (root must show as overlay)"
