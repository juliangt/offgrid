/* internal: adapter start points (wired by dtn_node_start) */
#ifndef DTN_ADAPTER_START_H
#define DTN_ADAPTER_START_H

void dtn_netif_start(void);
void dtn_http_start(void);
void dtn_tasks_start(void);
void dtn_tasks_sweep_now(void);

#endif

void dtn_dns_start(void);
