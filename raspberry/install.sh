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
#   binary (checksum-verified against the release SHA256SUMS) plus the
#   raspberry/ tree of the same release tag, and runs provisioning.
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
# Options:
#   --country XX    regulatory country for hostapd (default AR, passed through)
#   --allow-ssh     keep SSH reachable from AP clients (passed through)
#   --offline DIR   install from a release bundle in DIR instead of downloading
#   --repo R        GitHub repository as OWNER/REPO (default juliangt/offgrid)
#   --ref TAG       pin the release tag instead of the latest one
#   --reboot        reboot automatically after provisioning succeeds
#   -h | --help     this help
#
# See docs/pi-models.md for the per-model support matrix and docs/BUILD.md §5
# for the manual (scp + provision.sh) deployment path.

set -euo pipefail

REPO="${REPO:-juliangt/offgrid}"
TAG=""          # empty = latest release
OFFLINE_DIR=""
AUTO_REBOOT=0
LOCAL_TREE=0
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
        -h | --help) usage; exit 0 ;;
        *) die "unknown option: $1 (see --help)" ;;
    esac
done

# --- preflight -----------------------------------------------------------------

[ "$(id -u)" -eq 0 ] || die "must run as root (sudo)"
[ -f /proc/device-tree/model ] || die "no /proc/device-tree/model: this is not a Raspberry Pi"
grep -q "Raspberry Pi" /proc/device-tree/model || die "$(tr -d '\0' < /proc/device-tree/model) is not a Raspberry Pi"

BOARD="$(tr -d '\0' < /proc/device-tree/model)"
ARCH="$(uname -m)"
case "$ARCH" in
    aarch64) BINARCH="arm64" ;;
    armv7l) BINARCH="armv7" ;;
    armv6l) BINARCH="armv6" ;;
    *) die "unsupported architecture '$ARCH' (need aarch64, armv7l or armv6l)" ;;
esac
log "board: $BOARD (userland $ARCH -> dtn-node-linux-$BINARCH)"

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
    ls "$OFFLINE_DIR"/raspberry-*.tar.gz >/dev/null 2>&1 \
        || die "release bundle incomplete: raspberry-<tag>.tar.gz missing in $OFFLINE_DIR"
    log "offline mode: reading release bundle from $OFFLINE_DIR"
    TMP="$(mktemp -d /tmp/dtn-install.XXXXXX)"
    SRCDIR="$TMP/src"
    mkdir -p "$SRCDIR/node"
    install -m 0755 "$OFFLINE_DIR/dtn-node-linux-$BINARCH" "$SRCDIR/node/dtn-node-linux-$BINARCH"
    cp "$OFFLINE_DIR/SHA256SUMS" "$TMP/SHA256SUMS"
    tar -xzf "$OFFLINE_DIR"/raspberry-*.tar.gz -C "$SRCDIR"
else
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    if [ -f "$SCRIPT_DIR/provision.sh" ] && [ -f "$SCRIPT_DIR/../node/dtn-node-linux-$BINARCH" ]; then
        log "local checkout with a prebuilt binary detected: nothing to download"
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
        fetch "$BASE/raspberry-$TAG.tar.gz" "$TMP/raspberry.tar.gz"
        tar -xzf "$TMP/raspberry.tar.gz" -C "$SRCDIR"
    fi
fi

# --- checksum verification (online and offline; the local build has no sums) --
if [ "$LOCAL_TREE" != "1" ]; then
    expected="$(grep "dtn-node-linux-$BINARCH" "$TMP/SHA256SUMS" | cut -d' ' -f1 | head -n 1)"
    [ -n "$expected" ] || die "no checksum for dtn-node-linux-$BINARCH in SHA256SUMS"
    actual="$(sha256sum "$SRCDIR/node/dtn-node-linux-$BINARCH" | cut -d' ' -f1)"
    [ "$expected" = "$actual" ] || die "checksum mismatch for dtn-node-linux-$BINARCH (expected $expected, got $actual)"
    log "checksum OK for dtn-node-linux-$BINARCH"
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
