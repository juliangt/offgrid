/* DTN node firmware — app entry (issue #39).
 *
 * The firmware IS the system: no OS userspace to supervise. dtn_node_start
 * brings up the store, the AP at 10.42.0.1 with DHCP + wildcard DNS, the
 * two HTTP listeners (§10.3 on :8080, probes on :80), the janitor and the
 * sampler; the hardware watchdog (esp_task_wdt) and the brownout detector
 * cover the shed → survive → self-recover contract (docs/hardening.md §4). */
#include <esp_log.h>
#include <esp_task_wdt.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <nvs_flash.h>

#include "dtn_node.h"

static const char *TAG = "main";

void app_main(void)
{
    /* NVS for the Wi-Fi driver's calibration data */
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES ||
        err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ESP_ERROR_CHECK(nvs_flash_init());
    }

    /* the app task itself feeds the hardware watchdog for its lifetime */
    esp_task_wdt_config_t wcfg = {
        .timeout_ms = 30000,
        .idle_core_mask = 0x3, /* idle tasks are watched: any task starvation
                                  resets — the recovery IS the reboot */
        .trigger_panic = true,
    };
    esp_task_wdt_reconfigure(&wcfg);
    esp_task_wdt_add(NULL);

    dtn_node_start();

    for (;;) {
        esp_task_wdt_reset();
        vTaskDelay(pdMS_TO_TICKS(5000));
    }
}
