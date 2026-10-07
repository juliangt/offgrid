/* dtn_node_priv.h — shared internal state of the adapter layer. */
#ifndef DTN_NODE_PRIV_H
#define DTN_NODE_PRIV_H

#include <stdint.h>

#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include "dtn_budget.h"
#include "dtn_docs.h"
#include "dtn_store.h"

/* §10.1/§10.7 budgets: RAM-only, per source IP, capped table (oldest
 * entry evicted) — nothing persisted, nothing logged per request. */
#define DTN_CLIENTS_MAX 64

typedef struct {
    uint32_t ip;
    bool used;
    int64_t seen_ms;
    dtn_bucket request; /* burst 60, refill 1 per 2 s (§10.1) */
    dtn_bucket env;     /* burst 600, refill 600/h (§10.1) */
    dtn_bucket diag;    /* burst 60, refill 1/s, shared health+status (§10.7) */
} dtn_client;

/* §10.7 counters — process-lifetime RAM aggregates, reset on restart. */
typedef struct {
    int64_t pushes_accepted, pushes_rejected, dedup_hits;
    int64_t ttl_sweeps, ttl_swept_envelopes;
    int64_t rej_invalid, rej_rate_limited, rej_node_full, rej_storage,
        rej_too_large;
    int32_t active_clients; /* aggregate distinct write-path sources, 15 min */
} dtn_counters;

/* §10.7 projections: a fixed-capacity RAM ring of once-per-minute samples
 * (persistence was rejected — a reboot clears projections, §10.7). */
#define DTN_RING_MAX 24
typedef struct {
    int64_t at_ms;
    int64_t pushes_accepted;
    int64_t db_size;
} dtn_ring_sample;

typedef struct {
    dtn_ring_sample ring[DTN_RING_MAX];
    int n;
} dtn_ring;

typedef struct {
    dtn_store *store;
    SemaphoreHandle_t store_mu;  /* single-writer serialization */
    SemaphoreHandle_t state_mu;  /* counters/budgets/snapshot */
    dtn_counters counters;
    dtn_client clients[DTN_CLIENTS_MAX];
    /* the ≤1-second snapshot cache (§10.7): rendered JSON + page inputs */
    char snap_json[2048];
    dtn_health_snapshot snap;
    int64_t snap_built_ms;
    bool snap_valid;
    dtn_ring ring;
    bool boot_failed; /* refusal/recovery stance (§15.3 ESP32 semantics) */
    char boot_reason[128];
} dtn_node_state;

extern dtn_node_state g_node;

static inline int64_t now_ms(void)
{
    return (int64_t)(esp_timer_get_time() / 1000);
}
static inline int64_t boot_uptime_s(void)
{
    return esp_timer_get_time() / 1000000LL;
}

/* budgets: look up (or mint) the per-IP entry; returns NULL on table
 * exhaustion (admission then sheds — availability over attribution). */
dtn_client *dtn_node_client(uint32_t ip);

/* counters (state_mu held by caller or via these helpers) */
void dtn_node_count_reject(const char *code);
void dtn_node_count_accept(int64_t dedup_hits);

/* snapshot cache: build at most once per second (§10.7) */
const char *dtn_node_snapshot_json(void);
const dtn_health_snapshot *dtn_node_snapshot(void);

/* rendered by dtn_http for GET /status from the same snapshot */
long dtn_node_status_html(char *out, size_t cap,
                          const dtn_health_snapshot *s);

/* the embedded SPA (generated in main from node/web — weak default here) */
typedef struct {
    const char *path;   /* exact request path, e.g. "/css/portal.css" */
    const char *ctype;  /* exact §10.3 content type */
    const uint8_t *data;
    unsigned len;
} dtn_web_asset;
const dtn_web_asset *dtn_web_assets(int *count);

extern const char DTN_STORE_MOUNT[]; /* "/store" */

#endif /* DTN_NODE_PRIV_H */
