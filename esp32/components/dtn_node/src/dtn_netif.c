/* dtn_netif.c — the §12 same-origin bring-up: softAP "offgrid-messages"
 * with the netif reconfigured to 10.42.0.1 (never the ESP32 default
 * 192.168.4.1), the built-in DHCP server handing out the node as gateway
 * AND DNS, and the wildcard dns_server answering every A query with the
 * portal IP. There is no routing path between stations (island by
 * construction); the on-hardware matrix verifies it (design note §9). */
#include <string.h>

#include <esp_event.h>
#include <esp_log.h>
#include <esp_netif.h>
#include <esp_wifi.h>
#include <lwip/dns.h>

#include "dtn_core.h"
#include "dtn_netif.h"
#include "dtn_netif.h"
#include "dtn_node_priv.h"

static const char *TAG = "dtn-net";

static void wifi_event_cb(void *arg, esp_event_base_t base, int32_t id,
                          void *data)
{
    if (base == WIFI_EVENT && id == WIFI_EVENT_AP_START) {
        /* wildcard address=/#/10.42.0.1 (§12): every name resolves to the
         * portal, offgrid.local included */
        dtn_dns_start();
        ESP_LOGI(TAG, "AP up: SSID %s, gateway %s, wildcard DNS on", DTN_AP_SSID,
                 DTN_AP_IP);
    }
}

void dtn_netif_start(void)
{
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    wifi_init_config_t wcfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&wcfg));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                               wifi_event_cb, NULL));

    esp_netif_t *ap = esp_netif_create_default_wifi_ap();

    /* stop the default DHCP server before reconfiguring the address */
    ESP_ERROR_CHECK(esp_netif_dhcps_stop(ap));

    esp_netif_ip_info_t info;
    memset(&info, 0, sizeof(info));
    info.ip.addr = ipaddr_addr(DTN_AP_IP);
    info.gw.addr = ipaddr_addr(DTN_AP_IP);
    info.netmask.addr = ipaddr_addr(DTN_AP_NETMASK);
    ESP_ERROR_CHECK(esp_netif_set_ip_info(ap, &info));

    /* the DHCP answer IS the captive-portal contract: this node as gateway
     * AND as the DNS server (the Pi's dnsmasq dhcp-option equivalent) */
    esp_netif_dhcps_option(ap, ESP_NETIF_OP_SET, ESP_NETIF_DOMAIN_NAME_SERVER,
                           &info.ip.addr, sizeof(info.ip.addr));
    ESP_ERROR_CHECK(esp_netif_dhcps_start(ap));

    wifi_config_t w = {
        .ap = {
            .ssid = DTN_AP_SSID,
            .ssid_len = sizeof(DTN_AP_SSID) - 1,
            .channel = 6,
            .authmode = WIFI_AUTH_OPEN, /* open AP, no password (§12) */
            .max_connection = 10, /* documented per board (esp32-models) */
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &w));
    ESP_ERROR_CHECK(esp_wifi_start());
}
