# app entry (docs/esp32-design.md §3): netif reconfigured to 10.42.0.1,
# softAP "offgrid-messages" with the built-in DHCP server (node as gateway +
# DNS) and the wildcard dns_server; the SPA is embedded from node/web and
# served verbatim. Phase 0 seeds the entrypoint only — the bring-up lands in
# phase 3 (dtn_node adapters).
idf_component_register(SRCS "main.c"
                       INCLUDE_DIRS "."
                       REQUIRES dtn_core dtn_node)
