/* DTN node firmware — app entry (issue #39).
 *
 * Phase 0: boot banner only, proving the toolchain, the component tree and
 * both build targets. Phase 3 wires the full bring-up documented in
 * docs/esp32-design.md §3 (softAP at 10.42.0.1, DHCP + wildcard DNS, the two
 * httpd listeners, the janitor and snapshot tasks, the watchdog).
 */
#include <stdio.h>

#include "dtn_core.h"
#include "dtn_node.h"

void app_main(void)
{
    printf("\n");
    printf("dtn-node %s — ESP32 firmware (issue #39)\n", dtn_core_version());
    printf("canonical origin %s, AP %s at %s, storage schema v%d\n",
           DTN_CANONICAL_ORIGIN, DTN_AP_SSID, DTN_AP_IP,
           DTN_STORAGE_SCHEMA_VERSION);
    printf("phase 0 scaffold: bring-up lands in phase 3\n");
    (void)dtn_node_adapter_seed();
}
