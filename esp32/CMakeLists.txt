# DTN node firmware (issue #39) — ESP-IDF project root.
#
# Targets (docs/esp32-design.md §2):
#   esp32s3 — reference board, 16 MB flash + octal PSRAM, full 5000-envelope cap
#   esp32   — minimum board,  4 MB flash, honest reduced cap (1000)
#
# The target selects its own sdkconfig.defaults.<target> overlays and
# partition file. Build with `make firmware` or directly:
#   idf.py -DIDF_TARGET=esp32s3 -B build-esp32s3 build
cmake_minimum_required(VERSION 3.16)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(dtn-node)
