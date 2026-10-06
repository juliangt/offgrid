# dtn_core — the PORTABLE core of the ESP32 node (docs/esp32-design.md §1).
#
# No esp_* include may ever appear under include/ or src/: everything here
# compiles and unit-tests on the CI host (esp32/components/dtn_core/host/,
# wired into `make test`). The IDF build registers the same sources as a
# component; the host build has its own tiny CMake in host/.
idf_component_register(SRCS "src/dtn_core.c"
                       INCLUDE_DIRS "include")
