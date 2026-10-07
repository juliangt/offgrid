/* dtn_dns.c — the §12 wildcard DNS responder: a minimal UDP/53 server that
 * answers EVERY A query with the portal IP (the dnsmasq
 * `address=/#/10.42.0.1` equivalent; offgrid.local included). No upstream,
 * no cache, no recursion — the entire answer surface is "portal IP", which
 * is the whole point (§12/§13.6: there is nowhere to ride to).
 *
 * Query handling: echo the question, append one answer record (pointer to
 * the question name, A class IN, 60 s TTL, rdata = the 4 portal bytes).
 * Anything not a standard query for class IN is ignored. */
#include <arpa/inet.h>
#include <string.h>

#include <esp_log.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <lwip/sockets.h>

#include "dtn_core.h"
#include "dtn_netif.h"

static const char *TAG = "dtn-dns";

#define DNS_PORT 53
#define BUF_SZ 512

static int dns_sock = -1;

static struct sockaddr_in g_from;
static socklen_t g_from_len;

static void answer(const uint8_t *q, ssize_t qlen)
{
    uint8_t out[BUF_SZ];
    if (qlen < 12 || (size_t)qlen > sizeof(out)) return;

    uint16_t flags;
    memcpy(&flags, q + 2, 2);
    uint8_t opcode = (flags >> 11) & 0xF;
    bool is_query = (flags & 0x8000) == 0;
    if (opcode != 0 || !is_query) return; /* standard query only */

    /* header + question section verbatim, then set the response bits and
     * one answer record: name pointer to the question (offset 12), type A,
     * class IN, TTL 60, rdlength 4, the portal address */
    memcpy(out, q, (size_t)qlen);
    uint16_t resp_flags = htons(0x8180); /* response, RA, no error */
    memcpy(out + 2, &resp_flags, 2);
    uint16_t one = htons(1);
    memcpy(out + 6, &one, 2); /* ANCOUNT = 1 */

    static const uint8_t rec[] = {
        0xC0, 0x0C,             /* name: pointer to the question name */
        0x00, 0x01,             /* type A */
        0x00, 0x01,             /* class IN */
        0x00, 0x00, 0x00, 0x3C, /* TTL 60 */
        0x00, 0x04,             /* rdlength */
    };
    size_t pos = (size_t)qlen;
    if (pos + sizeof(rec) + 4 > sizeof(out)) return;
    memcpy(out + pos, rec, sizeof(rec));
    pos += sizeof(rec);
    uint32_t ip = ipaddr_addr(DTN_AP_IP);
    memcpy(out + pos, &ip, 4);
    pos += 4;

    sendto(dns_sock, out, pos, 0, (struct sockaddr *)&g_from, g_from_len);
}

static void dns_task(void *arg)
{
    (void)arg;
    dns_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (dns_sock < 0) {
        ESP_LOGE(TAG, "socket failed");
        vTaskDelete(NULL);
        return;
    }
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(DNS_PORT),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };
    if (bind(dns_sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        ESP_LOGE(TAG, "bind :53 failed");
        vTaskDelete(NULL);
        return;
    }
    ESP_LOGI(TAG, "wildcard DNS on :53 -> %s (§12)", DTN_AP_IP);
    for (;;) {
        uint8_t buf[BUF_SZ];
        g_from_len = sizeof(g_from);
        ssize_t n = recvfrom(dns_sock, buf, sizeof(buf), 0,
                             (struct sockaddr *)&g_from, &g_from_len);
        if (n <= 0) continue;
        answer(buf, n);
    }
}

void dtn_dns_start(void)
{
    xTaskCreate(dns_task, "dtn-dns", 3072, NULL, 5, NULL);
}
