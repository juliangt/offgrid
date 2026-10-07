# dtn_node — the ESP-IDF adapter layer (docs/esp32-design.md §1).
#
# Glue, not logic: httpd handlers, dns_server, LittleFS wiring, watchdog and
# task management live here; every protocol decision is delegated to dtn_core.
idf_component_register(
    SRCS "src/dtn_node.c"
         "src/dtn_http.c"
         "src/dtn_netif.c"
         "src/dtn_tasks.c"
         "src/dtn_dns.c"
    INCLUDE_DIRS "include"
    REQUIRES dtn_core nvs_flash esp_wifi esp_netif esp_http_server
             esp_timer esp_timer lwip vfs
)

# The managed component (joltwallet/littlefs) is declared in
# main/idf_component.yml and resolves at CMake configure time.
idf_component_get_property(littlefs_lib joltwallet__littlefs COMPONENT_LIB)
if(littlefs_lib)
    target_link_libraries(${COMPONENT_LIB} PRIVATE ${littlefs_lib})
endif()
