# ESP32 node models — boards, flash procedure, limits (issue #39)

The per-board matrix for the ESP32 firmware, mirroring `docs/pi-models.md`
for the Pi. The design record (framework, budgets, storage engine, plan
status) is `docs/esp32-models.md`'s sibling: `docs/esp32-design.md`.

| Board class | Module | Flash | PSRAM | Envelope cap | OTA A/B | Flash via |
|---|---|---|---|---|---|---|
| **Reference** | ESP32-S3 N16R8 (WROVER-class) | 16 MB | 8 MB octal | **5000** (full §8.1 cap) | yes (`ota_0`/`ota_1`) | USB or OTA |
| **Minimum** | ESP32-WROOM-32 (DevKit v1 class) | 4 MB | none | **1000** (honest capacity — reported in `envelope_capacity`) | no (USB reflash) | USB |

Both boards present the identical network contract: open SSID
`offgrid.local`'s AP `offgrid-messages`, gateway `10.42.0.1`, portal at
`http://offgrid.local:8080`, wildcard DNS, port-80 probes — a phone cannot
tell the platforms apart (§12). Station ceiling: ~10 concurrent
associations on classic ESP32 (chip default; the dead-drop usage pattern is
short and bursty), higher on S3 — acceptable for field deployments, and a
documented difference from `hostapd`.

## Flashing (release assets)

Every release tag carries `dtn-node-esp32s3.bin` and `dtn-node-esp32.bin`
(merged, flashable at the partition offsets of `esp32/partitions_*.csv`)
plus their `SHA256SUMS` entries. One-line flash (ESP-IDF's `esptool`):

```bash
# reference board (ESP32-S3 N16R8) via USB:
esptool.py --chip esp32s3 --port /dev/ttyUSB0 --baud 921600 \
  write_flash @flash_args          # from a configured build dir
# — or with explicit offsets for the merged image:
esptool.py --chip esp32s3 --port /dev/ttyUSB0 --baud 921600 write_flash \
  0x0 dtn-node-esp32s3.bin
# minimum board (ESP32-WROOM-32):
esptool.py --chip esp32 --port /dev/ttyCOM* --baud 460800 write_flash \
  0x0 dtn-node-esp32.bin
```

Verify checksums first (`sha256sum -c SHA256SUMS`). The merged image
bundles bootloader, partition table and firmware at the documented
offsets — no other artifacts are needed.

## Failure states and recovery

| State | Meaning | Action |
|---|---|---|
| Boot log `store schema newer than firmware — downgrade refused` | The on-flash store was written by a newer firmware (§15.3 refusal: mounted NEVER, store untouched) | Flash the newer firmware back, or deliberately erase (data loss) |
| `/status` shows `BOOT STANCE: store failed to open` | LittleFS/I/O failure | Reflash; if persistent, erase the `store` partition |
| Boot log `corrupt store quarantined` | §13.6 stance: the store was renamed to `*.corrupt.log` and a fresh one created | Recover the corrupt file over USB for forensics, then let the node serve |
| Watchdog reset in logs | A task starved the hardware watchdog | File a bug with the coredump partition contents |
| Brownout in logs | Supply voltage collapsed mid-operation | Fix the power supply; the store survives (CRC-framed log) |

## Conformance runs (identical assertions to the Pi)

`tests/sync_e2e.sh` accepts `NODE_A_URL` / `NODE_B_URL`: join the node's AP
and run the harness from a laptop — the core §10.3/§10.4/§10.2/§15 walk
executes unchanged against the ESP32, which is also the mixed-fleet mule
walk when one URL is a Pi daemon and the other the ESP32. On-hardware
acceptance items beyond that (two-phone probe matrix, power-cycle during
writes, 72 h soak) are tracked in `docs/esp32-design.md` §9.
