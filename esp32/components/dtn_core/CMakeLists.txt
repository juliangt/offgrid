# dtn_core — the PORTABLE core of the ESP32 node (docs/esp32-design.md §1).
#
# No esp_* include may ever appear under include/ or src/: everything here
# compiles and unit-tests on the CI host (host/, wired into `make test`).
# The IDF build registers the same sources as a component; the host build
# has its own CMake in host/.
idf_component_register(
    SRCS "src/dtn_core.c"
         "src/dtn_json.c"
         "src/dtn_base64.c"
         "src/dtn_envelope.c"
         "src/dtn_canonical.c"
         "src/dtn_budget.c"
         "src/dtn_docs.c"
         "src/dtn_sync.c"
         "src/dtn_store.c"
         "src/dtn_prekeys.c"
         "src/dtn_sha256.c"
         "src/dtn_tweetnacl.c"
         "src/dtn_ed25519.c"
         "src/dtn_cbor.c"
         "src/dtn_nodeid.c"
         "src/dtn_rolecert.c"
    INCLUDE_DIRS "include"
)
