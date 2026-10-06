# dtn_node — the ESP-IDF adapter layer (docs/esp32-design.md §1).
#
# Glue, not logic: httpd handlers, dns_server, LittleFS wiring, watchdog and
# task management live here; every protocol decision is delegated to dtn_core.
# The REQUIRES list grows in phase 3 with the actual IDF surfaces.
idf_component_register(SRCS "src/dtn_node.c"
                       INCLUDE_DIRS "include"
                       REQUIRES dtn_core)
