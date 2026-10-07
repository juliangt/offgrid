#!/bin/sh
# run_tests.sh — build and run the dtn_core host suite (issue #39).
# Zero dependencies beyond a POSIX shell and any C99 compiler (cc/gcc/clang):
#   esp32/components/dtn_core/host/run_tests.sh
# Wired into `make test` (target test-esp32-core) and the CI test job.
set -e
cd "$(dirname "$0")"
CC=${CC:-cc}
mkdir -p build
# -Werror keeps the portable core clean under the ESP-IDF compiler too.
$CC -std=c99 -Wall -Wextra -Werror -O1 -I../include -Itests \
    tests/main.c tests/test_json.c tests/test_envelope.c tests/test_sync.c \
    tests/test_canonical.c tests/test_budget.c tests/test_docs.c \
    tests/test_store.c \
    ../src/dtn_core.c ../src/dtn_json.c ../src/dtn_base64.c \
    ../src/dtn_envelope.c ../src/dtn_canonical.c ../src/dtn_budget.c \
    ../src/dtn_docs.c ../src/dtn_sync.c ../src/dtn_store.c \
    ../src/dtn_prekeys.c \
    -o build/dtn_core_tests
exec ./build/dtn_core_tests
