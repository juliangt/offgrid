#!/usr/bin/env bash
# tests/chaos/chaos_full_disk.sh — fill the volume the database lives on and
# push against a FULL disk (issue #16 Phase 4, Track 4; the "full disk during
# write" row of FAILURE_MATRIX.md).
#
# Injection: create a small (8 MiB) loopback volume — no root needed on macOS
# (hdiutil DMG attach); on Linux a loop mount needs sudo (available on CI
# runners; SKIP when it is not). The daemon's database lives on that volume;
# junk files fill it to zero bytes free; a valid sync push then hits ENOSPC.
#
# Expected behavior (degrade + auto-recover, issue #16 Phase 2's 507 contract):
#   - the push fails CLEANLY in the shed family (507 storage_unavailable, or
#     429 node_full/rate_limited) — never a 500, never a hang;
#   - the daemon stays ALIVE: the read path still serves (capabilities +
#     pull-only sync answer 200 on the full volume);
#   - SQLite FULL is NOT corruption: zero .corrupt-* artifacts;
#   - recovery: once space is freed, pushes are accepted again (200) on the
#     very same database — no rebuild, no restart.
#
# Usage:  bash tests/chaos/chaos_full_disk.sh
# Env:    CHAOS_FULLDISK_PORT (default 18097; chaos suite owns 18095-18099)
# Needs:  go, curl; macOS: hdiutil. Linux: sudo + truncate + mkfs.ext2/ext4 +
#         losetup + mount (SKIP if unavailable — never fails the run for
#         missing volume tooling).
# Exit:   0 = every assertion passed (skips allowed); 1 = at least one failed.

set -euo pipefail

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

PORT="${CHAOS_FULLDISK_PORT:-18097}"

chaos_init chaos-fulldisk

# ---------------------------------------------------------------------------
# 0. Volume setup — macOS first-class (no root), Linux via sudo loop mount,
#    SKIP when the platform cannot produce a small volume.
# ---------------------------------------------------------------------------
MNT="$CHAOS_WORK/vol"
mkdir -p "$MNT"
case "$CHAOS_OS" in
    Darwin)
        IMG="$CHAOS_WORK/vol.dmg"
        # HFS+ is the primary test filesystem: unlike APFS it has no near-full
        # metadata reserve, so the fill really reaches 0 KiB free (verified:
        # APFS images refuse writes ~1 MiB early, which would fake ENOSPC).
        if ! hdiutil create -size 8m -fs "HFS+" -volname dtn-chaos "$IMG" >/dev/null 2>&1; then
            hdiutil create -size 8m -fs APFS -volname dtn-chaos "$IMG" >/dev/null 2>&1 || true
        fi
        if [ ! -s "$IMG" ]; then
            skip "macOS volume tooling unavailable (hdiutil create failed)"
            chaos_summary
        fi
        if ! hdiutil attach "$IMG" -mountpoint "$MNT" -nobrowse -quiet >/dev/null 2>&1; then
            skip "macOS volume tooling unavailable (hdiutil attach failed)"
            chaos_summary
        fi
        chaos_on_cleanup "hdiutil detach '$MNT' -force"
        ;;
    Linux)
        IMG="$CHAOS_WORK/vol.img"
        MKFS="$(command -v mkfs.ext2 || command -v mkfs.ext3 || command -v mkfs.ext4 || true)"
        if [ -z "$MKFS" ] || ! command -v truncate >/dev/null 2>&1 \
           || ! command -v losetup >/dev/null 2>&1 || ! command -v mount >/dev/null 2>&1 \
           || ! sudo -n true 2>/dev/null; then
            skip "Linux volume tooling unavailable (need sudo + truncate + mkfs.ext* + losetup + mount)"
            chaos_summary
        fi
        truncate -s 8m "$IMG"
        LOOP="$(sudo -n losetup --find --show "$IMG")"
        chaos_on_cleanup "sudo -n losetup -d '$LOOP'"
        chaos_on_cleanup "sudo -n umount '$MNT'"
        sudo -n "$MKFS" -q -b 1024 -F "$LOOP"
        sudo -n mount "$LOOP" "$MNT"
        sudo -n chown "$(id -u):$(id -g)" "$MNT"
        ;;
    *)
        skip "unsupported platform for the volume injection: $CHAOS_OS"
        chaos_summary
        ;;
esac
log "8 MiB volume mounted at $MNT"

build_daemon || fatal "daemon build failed"
DB="$MNT/node.db"
LOG="$CHAOS_WORK/node.log"

# df_avail — free kilobytes on the volume.
df_avail() { df -k "$MNT" | awk 'NR==2 {print $4}'; }

start_daemon "$PORT" "$DB" "$LOG"
wait_ready "$PORT" || { cat "$LOG" >&2; fatal "daemon never became ready on the volume"; }

# Baseline: the same push succeeds while there is space, so the post-fill
# failure is attributable to the disk and nothing else.
NOW="$(date +%s)"
e1="$(envelope_json "$(hex_id 1)" "$NOW" 3600 "$(payload_b64 baseline)")"
make_sync_body "$CHAOS_WORK/baseline.json" "[\"$(hex_id 1)\"]" "[$e1]"
code="$(http POST "http://127.0.0.1:$PORT/api/v1/sync" "$CHAOS_WORK/baseline.json")"
check "baseline push with free space -> 200" "200" "$code"

# ---------------------------------------------------------------------------
# 1. Injection: fill the volume to zero bytes free with junk files (the
#    daemon keeps running on it the whole time — the real "solar node's SD
#    card ate by abuse/flash-wear" condition).
# ---------------------------------------------------------------------------
log "filling the volume to 0 KiB free (daemon live on it)"
n=0
while :; do
    avail="$(df_avail)"
    if [ "$avail" -le 4 ]; then break; fi
    if ! dd if=/dev/zero of="$MNT/junk.$n" bs=4096 count=128 2>/dev/null; then
        break
    fi
    n=$((n + 1))
    if [ "$n" -gt 4096 ]; then break; fi
done
# Squeeze the remainder: 1 KiB bites until the filesystem refuses.
until ! dd if=/dev/zero of="$MNT/junk.tail" bs=1024 count=1 2>/dev/null; do
    : # each successful dd eats another KiB; the loop ends on the first ENOSPC
done
sync
# The true fullness proof is the 1 KiB write above hitting ENOSPC; df is the
# human-readable echo of it (a couple of metadata KiB of slack are allowed).
check "volume is full: the squeeze write hit ENOSPC and df shows <= 4 KiB free" \
    "yes" "$([ "$(df_avail)" -le 4 ] && echo yes || echo "no (df_avail=$(df_avail))")"

# ---------------------------------------------------------------------------
# 2. Push against the full disk: clean shed-family failure, daemon alive.
# ---------------------------------------------------------------------------
e1="$(envelope_json "$(hex_id 2)" "$(date +%s)" 3600 "$(payload_b64 onfull)")"
make_sync_body "$CHAOS_WORK/onfull.json" "[\"$(hex_id 2)\"]" "[$e1]"
code="$(http POST "http://127.0.0.1:$PORT/api/v1/sync" "$CHAOS_WORK/onfull.json")"
check "push on a full disk sheds cleanly in the 507/429 family (never 500, never a hang)" \
    "shed" "$([ "$code" = "507" ] || [ "$code" = "429" ] && echo shed || echo "got-$code")"

code="$(curl -s --max-time 10 --connect-timeout 3 -o /dev/null -w '%{http_code}' \
    -H 'Host: offgrid.local:8080' "http://127.0.0.1:$PORT/api/v1/capabilities")"
check "daemon stays alive on a full disk: capabilities -> 200" "200" "$code"

make_sync_body "$CHAOS_WORK/readpath.json" "[]" "[]"
code="$(http POST "http://127.0.0.1:$PORT/api/v1/sync" "$CHAOS_WORK/readpath.json")"
check "read path still serves on a full disk: pull-only sync -> 200" "200" "$code"

check "full disk is NOT corruption: zero .corrupt-* artifacts" \
    "0" "$(quarantine_count "$DB")"

# ---------------------------------------------------------------------------
# 3. Recovery: free the space, assert pushes are accepted again on the SAME
#    database, without a restart.
# ---------------------------------------------------------------------------
log "freeing the volume"
rm -f "$MNT"/junk.* "$MNT"/junk.tail
sync
if [ "$(df_avail)" -le 4 ]; then
    fatal "volume did not free up (cleanup is broken)"
fi

e1="$(envelope_json "$(hex_id 3)" "$(date +%s)" 3600 "$(payload_b64 recovered)")"
make_sync_body "$CHAOS_WORK/recovered.json" "[\"$(hex_id 3)\"]" "[$e1]"
code="$(http POST "http://127.0.0.1:$PORT/api/v1/sync" "$CHAOS_WORK/recovered.json")"
check "recovery: push accepted again after space is freed -> 200" "200" "$code"

make_sync_body "$CHAOS_WORK/verify.json" "[]" "[]"
code="$(http POST "http://127.0.0.1:$PORT/api/v1/sync" "$CHAOS_WORK/verify.json")"
check "recovery: the freed-space push round-trips -> 200" "200" "$code"
check "recovery: the pushed envelope is served" "1" \
    "$(grep -c "\"id\":\"$(hex_id 3)\"" "$CHAOS_WORK/last_body" 2>/dev/null || true)"

code="$(curl -s --max-time 10 --connect-timeout 3 -o /dev/null -w '%{http_code}' \
    -H 'Host: offgrid.local:8080' "http://127.0.0.1:$PORT/api/v1/capabilities")"
check "daemon alive after the whole episode -> 200" "200" "$code"

stop_daemon
chaos_summary
