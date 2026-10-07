/* dtn_tasks.c — the two background loops: the §10.6 TTL janitor (every
 * 15 minutes plus once at boot, exclusive boundary) and the §10.7
 * once-per-minute diagnostics sampler feeding the projections ring. */
#include <string.h>

#include <esp_log.h>
#include <esp_timer.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#include "dtn_netif.h"
#include "dtn_node_priv.h"

static const char *TAG = "dtn-tasks";

static void sweep_locked(void)
{
    int32_t deleted = 0;
    xSemaphoreTake(g_node.store_mu, portMAX_DELAY);
    int rc = dtn_store_sweep(g_node.store, boot_uptime_s(), &deleted);
    xSemaphoreGive(g_node.store_mu);
    xSemaphoreTake(g_node.state_mu, portMAX_DELAY);
    g_node.counters.ttl_sweeps++;
    g_node.counters.ttl_swept_envelopes += deleted;
    xSemaphoreGive(g_node.state_mu);
    if (rc != 0) {
        ESP_LOGW(TAG, "sweep failed (storage) — shed 507 until it clears");
    } else if (deleted) {
        ESP_LOGI(TAG, "janitor: %ld expired envelopes removed", (long)deleted);
    }
}

void dtn_tasks_sweep_now(void) { sweep_locked(); }

static void janitor_task(void *arg)
{
    (void)arg;
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(DTN_JANITOR_INTERVAL_SECONDS * 1000));
        sweep_locked();
    }
}

static void sampler_task(void *arg)
{
    (void)arg;
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(60 * 1000));
        xSemaphoreTake(g_node.store_mu, portMAX_DELAY);
        int64_t db = dtn_store_db_size(g_node.store);
        xSemaphoreGive(g_node.store_mu);
        xSemaphoreTake(g_node.state_mu, portMAX_DELAY);
        dtn_ring *r = &g_node.ring;
        if (r->n == DTN_RING_MAX) {
            memmove(&r->ring[0], &r->ring[1],
                    sizeof(r->ring[0]) * (DTN_RING_MAX - 1));
            r->n--;
        }
        r->ring[r->n].at_ms = now_ms();
        r->ring[r->n].pushes_accepted = g_node.counters.pushes_accepted;
        r->ring[r->n].db_size = db;
        r->n++;
        /* the aggregate active-clients window is 15 min (§10.7): the count
         * itself is refreshed by the write path; here it decays to 0 when
         * no writes refreshed any entry in the window */
        bool any_recent = false;
        int64_t now = now_ms();
        for (int i = 0; i < DTN_CLIENTS_MAX; i++) {
            if (g_node.clients[i].used &&
                now - g_node.clients[i].seen_ms < 15LL * 60 * 1000) {
                any_recent = true;
                break;
            }
        }
        g_node.counters.active_clients = any_recent ? g_node.counters.active_clients : 0;
        int seen = 0;
        for (int i = 0; i < DTN_CLIENTS_MAX; i++) {
            if (g_node.clients[i].used &&
                now - g_node.clients[i].seen_ms < 15LL * 60 * 1000) {
                seen++;
            }
        }
        g_node.counters.active_clients = seen;
        xSemaphoreGive(g_node.state_mu);
    }
}

void dtn_tasks_start(void)
{
    xTaskCreate(janitor_task, "dtn-janitor", 4096, NULL, 5, NULL);
    xTaskCreate(sampler_task, "dtn-sampler", 4096, NULL, 3, NULL);
}
