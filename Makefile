# Makefile — developer entry points for the off-grid DTN node repository.
# Everything here wraps the documented commands of docs/BUILD.md (§4 "Run
# all tests" is the authoritative list); `make` is a convenience, never a
# requirement — every target works by copy-pasting its recipe.
#
#   make build       host dev binary (node/dtn-node-dev, the go:embeded SPA inside)
#   make build-all   the full cross-compile matrix of node/build.sh (arm64/armv7/armv6 + dev)
#   make test        the full suite: go test, the headless SPA tests, the
#                    docs structure test (install-node guide, issue #35),
#                    the curl E2E, the node upgrade/rollback E2E (issue #22)
#                    and the Pi hardening structure test
#   make lint        the CI lint gates: gofmt -l (no output allowed) + go vet
#   make chaos       the chaos suite (tests/chaos/run_all.sh — break it on
#                    purpose, assert degrade + auto-recover; see
#                    tests/chaos/FAILURE_MATRIX.md)
#   make fuzz        parser fuzzing only (the chaos fuzz script: seed
#                    corpora + a small -fuzztime per target, FUZZTIME env
#                    to retune)
#   make field-kit   print the field-session checklist for executing
#                    docs/field-test.md on real hardware (issue #20)
#
# No root is needed for any target. The test targets start and stop their
# own daemons on 127.0.0.1 ports 18091-18099 (sync E2E + chaos) and 18101
# (upgrade E2E) and clean up after themselves.

.PHONY: build build-all test lint chaos fuzz field-kit

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
	node tests/prekeys.mjs
	node tests/hint_rotation.mjs
	node tests/spa_structure.mjs
	node tests/pwa_assets.mjs
	node tests/version_migration.mjs
	node tests/chunking.mjs
	node tests/acks.mjs
	node tests/qr_identity.mjs
	node tests/spa_security.mjs
	node tests/field_equiv.mjs
	node tests/install_node_structure.mjs
	bash tests/sync_e2e.sh
	bash tests/upgrade_e2e.sh
	bash tests/hardening_structure.sh

# Field-session entry point (issue #20): the physical acceptance cases of
# docs/field-test.md CANNOT be automated here — this target only verifies the
# kit is complete and prints what to bring/print. Execution results go into
# docs/field-test.md by hand, on site.
field-kit:
	@echo "field kit — issue #20 session checklist"
	@test -f docs/field-test.md || { echo "MISSING docs/field-test.md"; exit 1; }
	@test -f docs/quick-start.md || { echo "MISSING docs/quick-start.md"; exit 1; }
	@test -f docs/BUILD.md && grep -q 'Path 4' docs/BUILD.md \
		|| { echo "MISSING the release-kit path (docs/BUILD.md §5 Path 4)"; exit 1; }
	@echo "  [ok] docs/field-test.md   — the T1..T10 protocol + report scaffold (print 2)"
	@echo "  [ok] docs/quick-start.md  — the end-user guide (print 2; also served at /guide)"
	@echo "  [ok] release USB kit      — build per docs/BUILD.md §5 Path 4 (offline checklist there)"
	@echo "  hardware, phones and meter: see docs/field-test.md §1 (prerequisites table)"
	@echo "  after the session: fill the §12 matrices + §13 defect log, sign §14."

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
