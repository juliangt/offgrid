#!/usr/bin/env bash
# install.sh — one-step installer for an off-grid DTN dead-drop node.
#
# It turns a fresh Raspberry Pi (Zero W, Zero 2 W, 3A+/3B+, 4, 400, 5, or any
# Pi with an AP-capable USB Wi-Fi adapter) into a provisioned node with a
# single command, then hands over to the verified raspberry/provision.sh
# (which still never starts services mid-run: the reboot is the activation
# step, docs/DEVELOPMENT_PLAN.md §1.6).
#
# ONLINE — one URL, run on the Pi (as root):
#
#   curl -fsSL https://raw.githubusercontent.com/juliangt/offgrid/main/raspberry/install.sh \
#     | sudo bash -s -- --country AR
#
#   The script detects the board architecture, downloads the matching release
#   binary plus the raspberry/ tree of the same release tag — both
#   checksum-verified against the release SHA256SUMS before anything runs.
#
# OFFLINE — no Internet on the Pi (the usual case for a field deployment):
#
#   1. Copy a release bundle (the release assets: the dtn-node-linux-*
#      binaries, SHA256SUMS and raspberry-<tag>.tar.gz) onto a USB stick or
#      the SD card's FAT partition.
#   2. On the Pi:  sudo ./install.sh --offline /media/usb --country AR
#
# LOCAL — running from a repository checkout that already carries a build
# (node/dtn-node-linux-* next to raspberry/): nothing is downloaded.
#
# UPGRADE — an already-provisioned node (issue #22: no reflash, no data loss):
#
#   sudo ./install.sh --upgrade --offline /media/usb   # from the release bundle
#   sudo ./install.sh --upgrade --ref vX.Y.Z           # online, pinned tag
#   sudo ./install.sh --rollback                       # back to the previous release
#
# The upgrade stops dtn-node, backs up the store (+ WAL) and the previous
# binary into a generationed backup dir (keeping the last 3 generations),
# re-runs the idempotent provisioning subset, swaps the binary, restarts and
# only declares success after the GET /api/v1/health gate (status ok + the
# new binary's schema_version + build identity). ANY failure rolls the node
# back automatically. See docs/BUILD.md §5 Path 4 and docs/RUNBOOK.md §4.8.
#
# Options:
#   --country XX    regulatory country for hostapd (default AR, passed through)
#   --allow-ssh     keep SSH reachable from AP clients (passed through)
#   --offline DIR   install from a release bundle in DIR instead of downloading
#   --repo R        GitHub repository as OWNER/REPO (default juliangt/offgrid)
#   --ref TAG       pin the release tag instead of the latest one
#   --reboot        reboot automatically after provisioning succeeds (fresh
#                   installs only; an upgrade activates via the service restart)
#   --upgrade       upgrade an ALREADY-PROVISIONED node instead of a fresh install
#   --rollback      restore the previous binary + store from a backup generation
#   --from NAME     backup generation for --rollback (default: the latest)
#   -h | --help     this help
#
# See docs/pi-models.md for the per-model support matrix, docs/BUILD.md §5
# for the manual (scp + provision.sh) deployment path and docs/BUILD.md §5
# Path 4 for the upgrade contract.

set -euo pipefail

REPO="${REPO:-juliangt/offgrid}"
TAG=""          # empty = latest release
OFFLINE_DIR=""
AUTO_REBOOT=0
LOCAL_TREE=0
MODE="install"  # install | upgrade | rollback (issue #22)
FROM_GEN=""
# The library's default, pre-seeded for set -u: the upgrade preflight
# (require_provisioned_node) runs BEFORE a lone install.sh resolves the
# bundle that carries raspberry/upgrade.sh. Sourcing the library later keeps
# this value (its own ${DTN_INSTALL_DIR:-...} assignment is a no-op then).
DTN_INSTALL_DIR="${DTN_INSTALL_DIR:-/opt/dtn-node}"
export COUNTRY="${COUNTRY:-AR}"
export ALLOW_SSH="${ALLOW_SSH:-0}"

log() { echo "install: $*"; }
die() { echo "install: ERROR: $*" >&2; exit 1; }

usage() {
    sed -n '/^# ONLINE/,/^# See docs\/pi-models/p' "$0" | sed 's/^# \?//'
}

while [ $# -gt 0 ]; do
    case "$1" in
        --country) COUNTRY="$2"; shift 2 ;;
        --allow-ssh) ALLOW_SSH=1; shift ;;
        --offline) OFFLINE_DIR="$2"; shift 2 ;;
        --repo) REPO="$2"; shift 2 ;;
        --ref) TAG="$2"; shift 2 ;;
        --reboot) AUTO_REBOOT=1; shift ;;
        --upgrade) MODE="upgrade"; shift ;;
        --rollback) MODE="rollback"; shift ;;
        --from) FROM_GEN="$2"; shift 2 ;;
        -h | --help) usage; exit 0 ;;
        *) die "unknown option: $1 (see --help)" ;;
    esac
done

# The upgrade/rollback machinery (issue #22) lives in its own file so the
# rootless acceptance test can source and drive it: tests/upgrade_e2e.sh
# exercises these very functions against a temp "node".
#
# It is SOURCED ONLY WHEN IT RIDES ALONG (repository checkout, extracted
# release tarball, bundle tree): the curl|bash one-liner (docs/BUILD.md §5
# Path 1) fetches install.sh ALONE — for it, $0 is the piped stdin and no
# sibling upgrade.sh exists; there the library arrives with the release
# bundle resolved further below and is sourced from $SRCDIR before the
# upgrade dispatch. Only --rollback needs the library with NO bundle, so it
# demands the tree explicitly (require_upgrade_lib).
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
UPGRADE_LIB=""
if [ -f "$SCRIPT_DIR/upgrade.sh" ]; then
    UPGRADE_LIB="$SCRIPT_DIR/upgrade.sh"
    # shellcheck source=upgrade.sh
    . "$UPGRADE_LIB"
fi
require_upgrade_lib() {
    [ -n "$UPGRADE_LIB" ] \
        || die "raspberry/upgrade.sh not found next to install.sh: --rollback needs the provisioning tree (run it from the release bundle or an extracted raspberry-<tag>.tar.gz)"
}

# --- preflight helpers ------------------------------------------------------------

require_root_pi() {
    [ "$(id -u)" -eq 0 ] || die "must run as root (sudo)"
    [ -f /proc/device-tree/model ] || die "no /proc/device-tree/model: this is not a Raspberry Pi"
    grep -q "Raspberry Pi" /proc/device-tree/model || die "$(tr -d '\0' < /proc/device-tree/model) is not a Raspberry Pi"
}

# require_provisioned_node — the upgrade/rollback modes are meaningless (and
# dangerous to improvise) on a box that was never provisioned: refuse with
# guidance instead of half-creating a deployment.
require_provisioned_node() {
    [ -f /etc/systemd/system/dtn-node.service ] \
        || die "no dtn-node unit at /etc/systemd/system/dtn-node.service: this box was never provisioned — use the fresh-install path (see --help)"
    [ -x "$DTN_INSTALL_DIR/dtn-node" ] \
        || die "no daemon binary at $DTN_INSTALL_DIR/dtn-node: nothing to upgrade — use the fresh-install path (see --help)"
}

# --- rollback mode: no bundle needed, just the backup generations ------------------

if [ "$MODE" = "rollback" ]; then
    require_root_pi
    require_upgrade_lib
    require_provisioned_node
    upgrade_rollback_main "$FROM_GEN"
    exit 0
fi

# --- preflight -----------------------------------------------------------------

require_root_pi
BOARD="$(tr -d '\0' < /proc/device-tree/model)"
ARCH="$(uname -m)"
case "$ARCH" in
    aarch64) BINARCH="arm64" ;;
    armv7l) BINARCH="armv7" ;;
    armv6l) BINARCH="armv6" ;;
    *) die "unsupported architecture '$ARCH' (need aarch64, armv7l or armv6l)" ;;
esac
log "board: $BOARD (userland $ARCH -> dtn-node-linux-$BINARCH)"

# An upgrade must find the deployment it is supposed to upgrade (issue #22:
# refuse a fresh box with guidance rather than half-provisioning it).
if [ "$MODE" = "upgrade" ]; then
    require_provisioned_node
fi

# fetch URL DEST — curl when present, wget otherwise (Raspberry Pi OS Lite
# does not guarantee curl on very old images).
fetch() {
    local url="$1" dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$dest"
    elif command -v wget >/dev/null 2>&1; then
        wget -q "$url" -O "$dest"
    else
        die "neither curl nor wget is installed; use the --offline mode from a USB stick"
    fi
}

# SRCDIR ends up holding the layout provision.sh expects:
#   $SRCDIR/raspberry/{provision.sh,hostapd/,...} and
#   $SRCDIR/node/dtn-node-linux-$BINARCH
# Only TMP is ever deleted on exit — never a checkout the user may have run
# this script from.
TMP=""
SRCDIR=""
cleanup() { [ -n "$TMP" ] && rm -rf "$TMP"; }
trap cleanup EXIT

if [ -n "$OFFLINE_DIR" ]; then
    # --- offline mode: everything comes from the mounted bundle --------------
    [ -d "$OFFLINE_DIR" ] || die "offline dir not found: $OFFLINE_DIR"
    for f in "dtn-node-linux-$BINARCH" "SHA256SUMS"; do
        [ -f "$OFFLINE_DIR/$f" ] || die "release bundle incomplete: $OFFLINE_DIR/$f missing"
    done
    TARBALL=""
    for f in "$OFFLINE_DIR"/raspberry-*.tar.gz; do
        if [ -f "$f" ]; then TARBALL="$f"; break; fi
    done
    [ -n "$TARBALL" ] || die "release bundle incomplete: raspberry-<tag>.tar.gz missing in $OFFLINE_DIR"
    log "offline mode: reading release bundle from $OFFLINE_DIR"
    TMP="$(mktemp -d /tmp/dtn-install.XXXXXX)"
    SRCDIR="$TMP/src"
    mkdir -p "$SRCDIR/node"
    install -m 0755 "$OFFLINE_DIR/dtn-node-linux-$BINARCH" "$SRCDIR/node/dtn-node-linux-$BINARCH"
    cp "$OFFLINE_DIR/SHA256SUMS" "$TMP/SHA256SUMS"
else
    if [ -f "$SCRIPT_DIR/provision.sh" ] && [ -f "$SCRIPT_DIR/../node/dtn-node-linux-$BINARCH" ]; then
        log "local checkout with a prebuilt binary detected: nothing to download"
        # AUDIT (SUPPLY-03, docs/security-audit.md §5): this path installs a
        # binary that no release SHA256SUMS can vouch for, and a stale local
        # build is invisible — say so loudly, twice, before it runs as root.
        log "WARNING: the LOCAL binary is installed AS IS — there is no SHA256SUMS here to verify it against."
        log "WARNING: confirm it is a current node/build.sh output; after activation check its build identity via GET /api/v1/health."
        LOCAL_TREE=1
        SRCDIR="$(cd "$SCRIPT_DIR/.." && pwd)"
    else
        if [ -z "$TAG" ]; then
            TAG="$(mktemp)" # reuse as the API response buffer
            fetch "https://api.github.com/repos/$REPO/releases/latest" "$TAG"
            TAG="$(sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' "$TAG" | head -n 1)"
            [ -n "$TAG" ] || die "could not resolve the latest release tag; pass --ref TAG or use --offline"
        fi
        log "release tag: $TAG"
        BASE="https://github.com/$REPO/releases/download/$TAG"
        TMP="$(mktemp -d /tmp/dtn-install.XXXXXX)"
        SRCDIR="$TMP/src"
        mkdir -p "$SRCDIR/node"
        fetch "$BASE/dtn-node-linux-$BINARCH" "$SRCDIR/node/dtn-node-linux-$BINARCH"
        chmod 0755 "$SRCDIR/node/dtn-node-linux-$BINARCH"
        fetch "$BASE/SHA256SUMS" "$TMP/SHA256SUMS"
        TARBALL="$TMP/raspberry-$TAG.tar.gz"
        fetch "$BASE/raspberry-$TAG.tar.gz" "$TARBALL"
    fi
fi

# --- checksum verification (online and offline; the local build has no sums) --
# AUDIT (SUPPLY-01, docs/security-audit.md §5): EVERY release asset this
# script USES is verified against the release SHA256SUMS before any of it
# runs — the daemon binary AND raspberry-<tag>.tar.gz, whose contents are
# the root-executed provisioning scripts below. (The SHA256SUMS file itself
# arrives over the same channel as the artifacts it pins — its designed
# successor, the signed release capsule, is docs/offline-maintenance.md §2.)
verify_sum() {
    local name="$1" file="$2" expected actual
    # SHA256SUMS fields end in the asset name; the binary is recorded with
    # its repository path prefix ("node/dtn-node-linux-..."), so match on
    # the exact last field or an exact "/<name>" suffix (never a substring).
    expected="$(awk -v n="$name" '$NF == n || substr($NF, length($NF) - length(n)) == "/" n { print $1; exit }' "$TMP/SHA256SUMS")"
    [ -n "$expected" ] || die "no checksum for $name in SHA256SUMS"
    actual="$(sha256sum "$file" | cut -d' ' -f1)"
    [ "$expected" = "$actual" ] || die "checksum mismatch for $name (expected $expected, got $actual)"
    log "checksum OK for $name"
}
if [ "$LOCAL_TREE" != "1" ]; then
    verify_sum "dtn-node-linux-$BINARCH" "$SRCDIR/node/dtn-node-linux-$BINARCH"
    verify_sum "$(basename "$TARBALL")" "$TARBALL"
    tar -xzf "$TARBALL" -C "$SRCDIR"
fi

# --- upgrade mode: backup -> swap -> health gate -> rollback-on-failure -----------
# When install.sh ran alone (curl|bash, a copied script), the library rides in
# with the resolved bundle; a tree-carrying checkout already sourced it above.
if [ -z "$UPGRADE_LIB" ] && [ -f "$SRCDIR/raspberry/upgrade.sh" ]; then
    # shellcheck source=upgrade.sh
    . "$SRCDIR/raspberry/upgrade.sh"
    UPGRADE_LIB="$SRCDIR/raspberry/upgrade.sh"
fi
if [ "$MODE" = "upgrade" ]; then
    require_upgrade_lib
    if [ "$AUTO_REBOOT" = "1" ]; then
        log "note: --reboot is ignored in --upgrade mode (the service restart is the activation step)"
    fi
    upgrade_node "$SRCDIR/node/dtn-node-linux-$BINARCH" "$SRCDIR/raspberry"
    exit 0
fi

# --- provision (verified, idempotent, never starts services) -----------------------
cd "$SRCDIR/raspberry"
log "handing over to provision.sh (COUNTRY=$COUNTRY ALLOW_SSH=$ALLOW_SSH)"
./provision.sh

# --- handoff -------------------------------------------------------------------------
echo
log "node provisioned successfully on $BOARD."
log "the ACTIVATION STEP IS A REBOOT (no service was started)."
if [ "$AUTO_REBOOT" = "1" ]; then
    log "rebooting now (--reboot)"
    reboot
elif [ -t 0 ]; then
    printf "install: press ENTER to reboot NOW (or Ctrl-C to reboot later): "
    read -r _
    reboot
else
    log "run 'sudo reboot' to activate the node (AP + portal come up on boot)."
fi
