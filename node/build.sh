#!/bin/sh
# Cross-compiles the dtn-node daemon (Module B) as fully static binaries.
# CGO is disabled so the pure-Go SQLite driver (modernc.org/sqlite) links
# without libc: each output runs on Raspberry Pi OS with zero runtime
# dependencies.
#
# Outputs (all gitignored):
#   dtn-node-linux-arm64  primary target: Raspberry Pi Zero 2 W (64-bit)
#   dtn-node-linux-arm    fallback target: 32-bit ARM (older Pi boards)
#   dtn-node-dev          host OS/arch, for local development and testing

set -eu
cd "$(dirname "$0")"

LDFLAGS="-s -w"

# Primary: Raspberry Pi Zero 2 W (linux/arm64).
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="$LDFLAGS" -o dtn-node-linux-arm64 .

# Fallback: 32-bit ARMv7.
CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -trimpath -ldflags="$LDFLAGS" -o dtn-node-linux-arm .

# Development: host OS/arch.
CGO_ENABLED=0 go build -trimpath -ldflags="$LDFLAGS" -o dtn-node-dev .

chmod +x dtn-node-linux-arm64 dtn-node-linux-arm dtn-node-dev
echo "build complete:"
ls -l dtn-node-linux-arm64 dtn-node-linux-arm dtn-node-dev
