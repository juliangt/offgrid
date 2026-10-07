/* dtn_node — ESP-IDF adapters for the DTN node (issue #39).
 *
 * Glue, not logic: every protocol decision lives in dtn_core (host-tested);
 * this component wires it to the ESP-IDF surfaces:
 *   - dtn_node_http: the two httpd instances (§10.3 on :8080 behind the
 *     §10.2 canonical-host middleware; :80 serves only the captive probes
 *     and redirects — the ESP32 replacement for the Pi's iptables REDIRECT);
 *   - dtn_node_net: softAP "offgrid-messages" with the netif reconfigured
 *     to 10.42.0.1, the built-in DHCP server (node as gateway AND DNS) and
 *     the wildcard dns_server (the §12 same-origin trick);
 *   - dtn_node_tasks: the §10.6 janitor (15 min + boot) and the §10.7
 *     once-per-minute diagnostics sampler;
 *   - the §10.1 per-source-IP budgets and the §10.7 counters (RAM-only,
 *     never persisted, never logged per request — §13.6/A7);
 *   - the 1-second snapshot cache in front of /api/v1/health and /status.
 *
 * Concurrency: the store is single-writer (like the Go node's single SQLite
 * connection) — one mutex serializes every store access. The two httpd
 * instances each run their own task; only :8080 touches the store. */
#ifndef DTN_NODE_H
#define DTN_NODE_H

#include <stdbool.h>
#include <stdint.h>

#include "dtn_docs.h"
#include "dtn_store.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Start everything: mount the store filesystem, open the store, bring up
 * the AP (10.42.0.1) with DHCP + wildcard DNS, start both HTTP servers,
 * the janitor and the sampler. Does not return an error — a failure state
 * boots into the recovery stance (logged loudly, visible on /status) so an
 * operator sees WHY, mirroring the §15.3 refusal semantics. */
void dtn_node_start(void);

/* The enforced §8.1 cap of this board (from Kconfig: 5000 reference /
 * 1000 minimum) — the honest envelope_capacity of capabilities/health. */
int32_t dtn_node_envelope_capacity(void);

#ifdef __cplusplus
}
#endif

#endif /* DTN_NODE_H */
