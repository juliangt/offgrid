#!/bin/sh
# Cross-compiles the dtn-node daemon (Module B) as fully static binaries.
# CGO is disabled so the pure-Go SQLite driver (modernc.org/sqlite) links
# without libc: each output runs on Raspberry Pi OS with zero runtime
# dependencies.
#
# Outputs (all gitignored), one per Raspberry Pi ISA class:
#   dtn-node-linux-arm64   Pi Zero 2 W, 3, 4, 400, 5, CM4/CM5 (64-bit OS)
#   dtn-node-linux-armv7   Pi 2, or a 64-bit board running a 32-bit OS
#   dtn-node-linux-armv6   Pi Zero W, Pi 1, CM1 (ARMv6, 32-bit OS only)
#   dtn-node-dev           host OS/arch, for local development and testing
#
# The mapping from a running board to its binary is uname -m:
#   aarch64 -> arm64, armv7l -> armv7, armv6l -> armv6
# (raspberry/provision.sh and raspberry/install.sh implement it). GOARM=6
# matters: the Zero W's ARM1176 lacks the instructions a GOARM=7 binary
# emits and would abort with "Illegal instruction".

set -eu
cd "$(dirname "$0")"

# Build identifier (issue #22): stamped into every binary via -X so the
# upgrade health gate can verify WHICH binary is actually serving (the
# "build" member of GET /api/v1/health, §10.7). git describe names tags and
# commits; outside a git tree the fallback keeps the historical "dev".
# The -X key is main.build: the linker records a source-built main package as
# "main", so the module-path form does not resolve (main.go documents this).
BUILD_ID="$(git describe --always --dirty 2>/dev/null || echo dev)"
LDFLAGS="-s -w -X main.build=$BUILD_ID"

# 64-bit: Raspberry Pi Zero 2 W, 3, 4, 400, 5 and the CM4/CM5 (64-bit OS).
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="$LDFLAGS" -o dtn-node-linux-arm64 .

# 32-bit ARMv7: Pi 2, or any 64-bit board flashed with a 32-bit OS.
CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -trimpath -ldflags="$LDFLAGS" -o dtn-node-linux-armv7 .

# 32-bit ARMv6: Raspberry Pi Zero W, Pi 1 and CM1 (baseline low-cost node).
CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=6 go build -trimpath -ldflags="$LDFLAGS" -o dtn-node-linux-armv6 .

# Development: host OS/arch.
CGO_ENABLED=0 go build -trimpath -ldflags="$LDFLAGS" -o dtn-node-dev .

chmod +x dtn-node-linux-arm64 dtn-node-linux-armv7 dtn-node-linux-armv6 dtn-node-dev
echo "build complete:"
ls -l dtn-node-linux-arm64 dtn-node-linux-armv7 dtn-node-linux-armv6 dtn-node-dev
