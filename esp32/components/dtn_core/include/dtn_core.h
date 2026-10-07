/*
 * dtn_core — the portable core of the ESP32 DTN node (issue #39).
 *
 * Everything under this component is free of ESP-IDF includes BY DESIGN:
 * envelope validation (§10.5/§15.3), the §8.1 limits, the §10.4 sync
 * processing order, the §10.2 canonical-host logic, the #16 budget math and
 * (phase 2) the flash storage engine live here, so the CI host can unit-test
 * every protocol decision the firmware will ever make. The normative source
 * for every rule implemented here is docs/protocol.md; node/internal/ is the
 * reference implementation consulted for interpretation, never transcribed.
 */
#ifndef DTN_CORE_H
#define DTN_CORE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Firmware/core identity. DTN_BUILD_STRING is supplied by the build (the
 * platform must be identifiable in the field: `esp32-v<x>-<hash>`, §15.5). */
#define DTN_CORE_VERSION_MAJOR 0
#define DTN_CORE_VERSION_MINOR 1
#define DTN_CORE_VERSION_PATCH 0

#ifndef DTN_BUILD_STRING
#define DTN_BUILD_STRING "esp32-dev"
#endif

/* Canonical origin of EVERY node in the network (§12) — the load-bearing
 * same-origin contract. Host comparisons are case-insensitive on the host
 * part only (§10.2); the port is fixed. */
#define DTN_CANONICAL_HOST "offgrid.local:8080"
#define DTN_CANONICAL_ORIGIN "http://offgrid.local:8080"

/* Network identity (§12): the AP/gateway IP every node must present. */
#define DTN_AP_SSID "offgrid-messages"
#define DTN_AP_IP "10.42.0.1"
#define DTN_AP_NETMASK "255.255.255.0"

/* Storage contract level implemented by this build (§15.3): the store is
 * new on this platform and natively implements schema version 4 (envelope v
 * column, directory epoch + prekeys). Forward-only from here. */
#define DTN_STORAGE_SCHEMA_VERSION 4

const char *dtn_core_version(void);

#ifdef __cplusplus
}
#endif

#endif /* DTN_CORE_H */
