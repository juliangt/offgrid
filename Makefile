# Makefile — developer entry points for the off-grid DTN node repository.
# Everything here wraps the documented commands of docs/BUILD.md (§4 "Run
# all tests" is the authoritative list); `make` is a convenience, never a
# requirement — every target works by copy-pasting its recipe.
#
#   make build       host dev binary (node/dtn-node-dev, the go:embeded SPA inside)
#   make build-all   the full cross-compile matrix of node/build.sh (arm64/armv7/armv6 + dev)
#   make test        the full suite: go test, the 3 headless SPA tests, the
#                    curl E2E and the Pi hardening structure test
#   make lint        the CI lint gates: gofmt -l (no output allowed) + go vet
#   make chaos       the chaos suite (tests/chaos/run_all.sh — break it on
#                    purpose, assert degrade + auto-recover; see
#                    tests/chaos/FAILURE_MATRIX.md)
#   make fuzz        parser fuzzing only (the chaos fuzz script: seed
#                    corpora + a small -fuzztime per target, FUZZTIME env
#                    to retune)
#
# No root is needed for any target. The test targets start and stop their
# own daemons on 127.0.0.1 ports 18091-18099 and clean up after themselves.

.PHONY: build build-all test lint chaos fuzz

GO ?= go

# Host development binary — the sync_e2e.sh build path (plain go build in
# node/, SPA embedded via go:embed). For deployment artifacts use build-all.
build:
	cd node && CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-s -w" -o dtn-node-dev .

# All four build.sh targets (arm64, armv7, armv6 for the Pi ISA classes, dev
# for the host) — what a release ships and raspberry/provision.sh maps by
# uname -m.
build-all:
	cd node && ./build.sh

# The exact full-suite sequence of docs/BUILD.md §4 — the one-command entry.
test:
	cd node && $(GO) test ./... -count=1
	node tests/crypto_roundtrip.mjs
	node tests/spa_structure.mjs
	node tests/version_migration.mjs
	bash tests/sync_e2e.sh
	bash tests/hardening_structure.sh

# Lint gates (docs/BUILD.md §4): gofmt must report nothing, vet nothing.
lint:
	cd node && test -z "$$($(GO)fmt -l .)" || { $(GO)fmt -l .; exit 1; }
	cd node && $(GO) vet ./...

# Chaos suite: every failure-mode injection of tests/chaos/FAILURE_MATRIX.md
# that can be automated on a dev machine (macOS and Linux; platform-missing
# injections SKIP instead of failing).
chaos:
	bash tests/chaos/run_all.sh

# Parser fuzzing only (seed corpora + one -fuzz round per target). FUZZTIME
# is a Go duration (default 20s per target; 0 disables the fuzzing phase).
fuzz:
	bash tests/chaos/chaos_fuzz_parsers.sh
