# Makefile — developer entry points for the off-grid DTN node repository.
# Everything here wraps the documented commands of docs/BUILD.md (§4 "Run
# all tests" is the authoritative list); `make` is a convenience, never a
# requirement — every target works by copy-pasting its recipe.
#
#   make build       host dev binary (node/dtn-node-dev, the go:embeded SPA inside)
#   make build-all   the full cross-compile matrix of node/build.sh (arm64/armv7/armv6 + dev)
#   make test        the full suite: go test, the headless SPA tests, the
#                    docs structure tests (install-node guide, issue #35;
#                    audit deliverables, issue #14), the curl E2E, the node
#                    upgrade/rollback E2E (issue #22), the Pi hardening
#                    structure test, the node-plane multi-hop E2E
#                    (issue #33 P3.5 — ~15 s, `make test-node-plane` runs
#                    it alone) and the dtn_core ESP32 host tests (#39)
#   make lint        the CI lint gates: gofmt -l (no output allowed) + go vet
#   make chaos       the chaos suite (tests/chaos/run_all.sh — break it on
#                    purpose, assert degrade + auto-recover; see
#                    tests/chaos/FAILURE_MATRIX.md)
#   make fuzz        parser fuzzing only (the chaos fuzz script: seed
#                    corpora + a small -fuzztime per target, FUZZTIME env
#                    to retune)
#   make field-kit   print the field-session checklist for executing
#                    docs/field-test.md on real hardware (issue #20)
#   make firmware    build the ESP32 firmware for both targets (issue #39);
#                    needs ESP-IDF v5.5 (docs/esp32-design.md §5) — the CI
#                    container invocation is printed when idf.py is missing
#
# No root is needed for any target. The test targets start and stop their
# own daemons on 127.0.0.1 ports 18091-18099 (sync E2E + chaos), 18101
# (upgrade E2E) and 18271-18283 (node-plane E2E: HTTP 18271-18273, TCPCL
# 18281-18283) and clean up after themselves.

.PHONY: build build-all test lint chaos fuzz field-kit \
	firmware firmware-merge firmware-clean

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
	node tests/docs_structure.mjs
	bash tests/sync_e2e.sh
	bash tests/upgrade_e2e.sh
	bash tests/node_plane_e2e.sh
	bash tests/hardening_structure.sh
	$(MAKE) test-esp32-core

# The node-plane multi-hop gate alone (issue #33 P3.5, §11 row g): three
# real daemons on a line topology, the §7.1 epidemic sync end to end.
# Wired into `make test` as well — it costs ~15 s — this target exists for
# iterating on the node plane without the rest of the suite.
test-node-plane:
	bash tests/node_plane_e2e.sh

.PHONY: test-node-plane

# dtn_core host suite (issue #39): the ESP32 firmware's portable core runs
# the §15.7-adapted assertions next to the Go/SPA/E2E gates. Needs any C99
# compiler; skips with a loud marker when none exists.
test-esp32-core:
	@if command -v cc >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1 || command -v clang >/dev/null 2>&1; then \
	  sh esp32/components/dtn_core/host/run_tests.sh; \
	else \
	  echo "SKIP dtn_core host tests: no C99 compiler available"; \
	fi

.PHONY: test-esp32-core

# Field-session entry point (issue #20, extended by issue #33 P3.9): the
# physical acceptance cases of docs/field-test.md CANNOT be automated here —
# this target only verifies the kit is complete and prints what to bring/print.
# Execution results go into docs/field-test.md by hand, on site.
field-kit:
	@echo "field kit — issue #20 session checklist (+ the issue #33 P3.9 node-plane session, §15)"
	@test -f docs/field-test.md || { echo "MISSING docs/field-test.md"; exit 1; }
	@test -f docs/quick-start.md || { echo "MISSING docs/quick-start.md"; exit 1; }
	@test -f docs/BUILD.md && grep -q 'Path 4' docs/BUILD.md \
		|| { echo "MISSING the release-kit path (docs/BUILD.md §5 Path 4)"; exit 1; }
	@grep -q '## 15. Phase 3 node-plane session' docs/field-test.md \
		|| { echo "MISSING the Phase 3 node-plane session in docs/field-test.md (issue #33 P3.9 §15)"; exit 1; }
	@echo "  [ok] docs/field-test.md   — the T1..T10 protocol + report scaffold (print 2)"
	@echo "  [ok] docs/field-test.md   — the Phase 3 node-plane session N1..N14 (issue #33 P3.9; §15.2 kit; boundary: needs P3.3 bring-up)"
	@echo "  [ok] docs/quick-start.md  — the end-user guide (print 2; also served at /guide)"
	@echo "  [ok] release USB kit      — build per docs/BUILD.md §5 Path 4 (offline checklist there)"
	@echo "  hardware, phones and meter: see docs/field-test.md §1 (prerequisites table)"
	@echo "  node-plane hardware: see docs/field-test.md §15.2 (heads, attenuator, solar repeater kit)"
	@echo "  after a session: fill the §12/§15.6 matrices + the §13/§15.7 defect logs, sign §14/§15.8."

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

# ESP32 firmware (issue #39, docs/esp32-design.md §5): both targets —
# esp32s3 (reference, 16 MB) and esp32 (minimum, 4 MB). `make` is a
# convenience; the raw idf.py invocations are exactly the recipes below.
ESP32_IDF_VER ?= v5.5

firmware:
	@command -v idf.py >/dev/null 2>&1 || { \
	  echo "idf.py not on PATH — install ESP-IDF $(ESP32_IDF_VER) and load its environment:"; \
	  echo "  . \$\$IDF_PATH/export.sh"; \
	  echo "or use the CI container without installing anything:"; \
	  echo "  docker run --rm -v \"\$$PWD:/repo\" -w /repo espressif/idf:$(ESP32_IDF_VER) bash -lc '. \$$IDF_PATH/export.sh && cd esp32 && idf.py -DIDF_TARGET=esp32s3 -B build-esp32s3 build && idf.py -DIDF_TARGET=esp32 -B build-esp32 build'"; \
	  exit 1; }
	cd esp32 && idf.py -DIDF_TARGET=esp32s3 -B build-esp32s3 -DSDKCONFIG=sdkconfig.esp32s3 build
	cd esp32 && idf.py -DIDF_TARGET=esp32 -B build-esp32 -DSDKCONFIG=sdkconfig.esp32 build

# Merged, flashable image per target (what a release ships): esptool
# merge_bin over the build's own flash_args, so the offsets always match the
# partition tables of docs/esp32-design.md §2.
firmware-merge:
	cd esp32/build-esp32s3 && python3 $${IDF_PATH:-/opt/esp/idf}/components/esptool_py/esptool/esptool.py --chip esp32s3 merge_bin -o ../dtn-node-esp32s3.bin @flash_args
	cd esp32/build-esp32 && python3 $${IDF_PATH:-/opt/esp/idf}/components/esptool_py/esptool/esptool.py --chip esp32 merge_bin -o ../dtn-node-esp32.bin @flash_args
	ls -l esp32/dtn-node-*.bin

firmware-clean:
	rm -rf esp32/build-esp32s3 esp32/build-esp32 esp32/sdkconfig.esp32s3 esp32/sdkconfig.esp32
	rm -f esp32/dtn-node-esp32s3.bin esp32/dtn-node-esp32.bin
