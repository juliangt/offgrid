/* dtn_node — ESP-IDF adapters for the DTN node (issue #39).
 *
 * Phase 0 seed: the component exists so the CI firmware gate compiles the
 * real project structure from day one. Phase 3 lands the adapters listed in
 * docs/esp32-design.md §8 (httpd on 8080 + 80, dns_server, LittleFS wiring,
 * janitor task, snapshot cache, watchdog). */
#ifndef DTN_NODE_H
#define DTN_NODE_H

#ifdef __cplusplus
extern "C" {
#endif

/* Marker for the phase-0 build gate; removed when the real adapters land. */
int dtn_node_adapter_seed(void);

#ifdef __cplusplus
}
#endif

#endif /* DTN_NODE_H */
