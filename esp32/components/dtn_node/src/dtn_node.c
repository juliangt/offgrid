/* dtn_node.c — adapter state and orchestration (issue #39 phase 3).
 * Every protocol decision is dtn_core's; this file holds the RAM-only
 * bookkeeping the §10 surface needs: budgets, counters, snapshot cache. */
#include "dtn_node_priv.h"

#include <stdio.h>
#include <string.h>

#include <esp_heap_caps.h>
#include <esp_log.h>

#include "dtn_core.h"
#include "dtn_netif.h"

static const char *TAG = "dtn-node";

dtn_node_state g_node;
const char DTN_STORE_MOUNT[] = "/store";

/* Overridden by main's generated asset table; the weak default serves an
 * empty portal (a build without the SPA still answers the API). */
__attribute__((weak)) const dtn_web_asset *dtn_web_assets(int *count)
{
    *count = 0;
    return NULL;
}

int32_t dtn_node_envelope_capacity(void)
{
    return CONFIG_DTN_ENVELOPE_CAPACITY;
}

dtn_client *dtn_node_client(uint32_t ip)
{
    xSemaphoreTake(g_node.state_mu, portMAX_DELAY);
    dtn_client *oldest = &g_node.clients[0];
    dtn_client *found = NULL;
    for (int i = 0; i < DTN_CLIENTS_MAX; i++) {
        dtn_client *c = &g_node.clients[i];
        if (c->used && c->ip == ip) {
            c->seen_ms = now_ms();
            found = c;
            break;
        }
        if (!oldest->used || (c->used && c->seen_ms < oldest->seen_ms)) {
            oldest = c;
        }
    }
    if (!found) {
        /* mint: reuse a free slot or evict the least-recently seen — the
         * eviction is aggregate state replacement, never a per-client log */
        found = oldest;
        memset(found, 0, sizeof(*found));
        found->ip = ip;
        found->used = true;
        found->seen_ms = now_ms();
        dtn_budget_request(&found->request, now_ms());
        dtn_budget_envelopes(&found->env, now_ms());
        dtn_budget_diagnostics(&found->diag, now_ms());
    }
    xSemaphoreGive(g_node.state_mu);
    return found;
}

void dtn_node_count_reject(const char *code)
{
    xSemaphoreTake(g_node.state_mu, portMAX_DELAY);
    g_node.counters.pushes_rejected++;
    if (!strcmp(code, "rate_limited")) g_node.counters.rej_rate_limited++;
    else if (!strcmp(code, "node_full")) g_node.counters.rej_node_full++;
    else if (!strcmp(code, "storage_unavailable")) g_node.counters.rej_storage++;
    else if (!strcmp(code, "body_too_large")) g_node.counters.rej_too_large++;
    else g_node.counters.rej_invalid++; /* every 400 shape is "invalid" */
    xSemaphoreGive(g_node.state_mu);
}

void dtn_node_count_accept(int64_t dedup_hits)
{
    xSemaphoreTake(g_node.state_mu, portMAX_DELAY);
    g_node.counters.pushes_accepted++;
    g_node.counters.dedup_hits += dedup_hits;
    xSemaphoreGive(g_node.state_mu);
}

/* ---- the ≤1-second snapshot cache (§10.7) ---- */

static void build_snapshot(dtn_health_snapshot *s)
{
    memset(s, 0, sizeof(*s));
    s->build = DTN_BUILD_STRING;
    s->now = (int64_t)boot_uptime_s(); /* monotonic base; the sampler ring
                                          tracks wall deltas */
    s->uptime_seconds = boot_uptime_s();
    s->envelope_capacity = dtn_node_envelope_capacity();

    xSemaphoreTake(g_node.store_mu, portMAX_DELAY);
    s->envelopes = dtn_store_envelope_count(g_node.store);
    s->directory_entries = dtn_store_dir_count(g_node.store);
    s->db_size_bytes = dtn_store_db_size(g_node.store);
    s->expiring_within_1h = dtn_store_expiring_within(g_node.store, s->now, 3600);
    s->expiring_within_6h = dtn_store_expiring_within(g_node.store, s->now, 6 * 3600);
    s->expiring_within_24h = dtn_store_expiring_within(g_node.store, s->now, 24 * 3600);
    xSemaphoreGive(g_node.store_mu);

    xSemaphoreTake(g_node.state_mu, portMAX_DELAY);
    s->pushes_accepted = g_node.counters.pushes_accepted;
    s->pushes_rejected = g_node.counters.pushes_rejected;
    s->dedup_hits = g_node.counters.dedup_hits;
    s->ttl_sweeps = g_node.counters.ttl_sweeps;
    s->ttl_swept_envelopes = g_node.counters.ttl_swept_envelopes;
    s->rej_invalid = g_node.counters.rej_invalid;
    s->rej_rate_limited = g_node.counters.rej_rate_limited;
    s->rej_node_full = g_node.counters.rej_node_full;
    s->rej_storage = g_node.counters.rej_storage;
    s->rej_too_large = g_node.counters.rej_too_large;
    s->active_clients = g_node.counters.active_clients;
    xSemaphoreGive(g_node.state_mu);

    /* system (§10.7 N/A convention: null where the platform has nothing) */
    s->mem_total_bytes = DTN_OPT_INT((int64_t)esp_get_minimum_free_heap_size() +
                                     esp_get_free_heap_size());
    s->mem_available_bytes = DTN_OPT_INT((int64_t)esp_get_free_heap_size());
    s->mem_used_bytes = DTN_OPT_INT((int64_t)esp_get_free_heap_size());
    s->system_uptime_seconds = DTN_OPT_INT(boot_uptime_s());
    /* load averages, SoC temperature, throttling, battery: the ESP32 has no
     * loadavg/thermal-zone contract — null, never fabricated (§10.7) */
    s->have_battery = false;

    /* last cleanup */
    if (g_node.store) {
        s->last_cleanup_unix = dtn_store_last_cleanup_unix(g_node.store);
        s->last_cleanup_deleted = dtn_store_last_cleanup_deleted(g_node.store);
    }

    /* projections from the once-per-minute ring (minimum-data rule) */
    xSemaphoreTake(g_node.state_mu, portMAX_DELAY);
    dtn_ring *r = &g_node.ring;
    s->proj_samples = r->n;
    if (r->n >= 2) {
        int64_t span_ms = r->ring[r->n - 1].at_ms - r->ring[0].at_ms;
        s->proj_window_hours = (double)span_ms / 3600000.0;
        s->enough_data = span_ms >= 30LL * 60 * 1000;
        if (s->enough_data) {
            double days = (double)span_ms / 86400000.0;
            int64_t dp =
                r->ring[r->n - 1].pushes_accepted - r->ring[0].pushes_accepted;
            int64_t dg = r->ring[r->n - 1].db_size - r->ring[0].db_size;
            s->pushes_per_day = DTN_OPT_NUM((double)dp / days);
            s->db_growth_bytes_per_day = DTN_OPT_NUM((double)dg / days);
            double net_per_day = (double)dp - (double)dg / 730.0;
            if (net_per_day > 1.0 && s->envelope_capacity > s->envelopes) {
                s->days_to_envelope_capacity =
                    DTN_OPT_NUM((double)(s->envelope_capacity - s->envelopes) /
                                net_per_day);
            }
            s->store_equilibrium = DTN_OPT_STR(
                net_per_day > 1.0 ? "growing"
                                  : net_per_day < -1.0 ? "shrinking" : "steady");
        }
    }
    xSemaphoreGive(g_node.state_mu);
}

const char *dtn_node_snapshot_json(void)
{
    int64_t now = now_ms();
    xSemaphoreTake(g_node.state_mu, portMAX_DELAY);
    if (g_node.snap_valid && now - g_node.snap_built_ms < 1000) {
        xSemaphoreGive(g_node.state_mu);
        return g_node.snap_json; /* a GET flood never reaches the store */
    }
    xSemaphoreGive(g_node.state_mu);

    dtn_health_snapshot s;
    build_snapshot(&s);

    xSemaphoreTake(g_node.state_mu, portMAX_DELAY);
    g_node.snap = s;
    long n = dtn_docs_health(g_node.snap_json, sizeof(g_node.snap_json), &s);
    g_node.snap_valid = n > 0;
    g_node.snap_built_ms = now;
    xSemaphoreGive(g_node.state_mu);
    return g_node.snap_json;
}

const dtn_health_snapshot *dtn_node_snapshot(void)
{
    dtn_node_snapshot_json(); /* refresh under the 1 s rule */
    return &g_node.snap;
}

void dtn_node_start(void)
{
    memset(&g_node, 0, sizeof(g_node));
    g_node.store_mu = xSemaphoreCreateMutex();
    g_node.state_mu = xSemaphoreCreateMutex();

    ESP_LOGI(TAG, "dtn-node %s — canonical origin %s, AP %s at %s", DTN_BUILD_STRING,
             DTN_CANONICAL_ORIGIN, DTN_AP_SSID, DTN_AP_IP);

    /* store */
    dtn_store_err err = dtn_store_open(&g_node.store, DTN_STORE_MOUNT,
                                       dtn_node_envelope_capacity());
    if (err == DTN_STORE_ERR_DOWNGRADE) {
        /* §15.3 refusal stance: refuse to mount/serve storage, loudly */
        g_node.boot_failed = true;
        snprintf(g_node.boot_reason, sizeof(g_node.boot_reason),
                 "store schema newer than firmware — downgrade refused");
        ESP_LOGE(TAG, "%s", g_node.boot_reason);
    } else if (err != DTN_STORE_OK) {
        g_node.boot_failed = true;
        snprintf(g_node.boot_reason, sizeof(g_node.boot_reason),
                 "store failed to open (err %d)", (int)err);
        ESP_LOGE(TAG, "%s", g_node.boot_reason);
    } else if (dtn_store_quarantined(g_node.store)) {
        ESP_LOGW(TAG, "corrupt store quarantined; serving a fresh store");
    }

    dtn_netif_start();         /* softAP 10.42.0.1 + DHCP + wildcard DNS */
    dtn_http_start();          /* :8080 (§10.3) + :80 (probes, §10.2) */
    dtn_tasks_start();         /* janitor 15 min + boot; sampler 1/min */

    /* the §10.6 boot sweep — once at daemon startup */
    if (g_node.store && !g_node.boot_failed) {
        dtn_tasks_sweep_now();
    }
}
