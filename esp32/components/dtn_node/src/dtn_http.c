/* dtn_http.c — the exact §10.3 surface on :8080 behind the §10.2
 * canonical-host middleware and the issue-#14 security headers, plus the
 * :80 listener (captive probes + redirect to the canonical origin — the
 * ESP32 replacement for the Pi's iptables REDIRECT 80→8080).
 *
 * Every protocol decision delegates to dtn_core. The sync handler streams
 * the body through dtn_sync (the 1 MiB body is never resident) directly
 * into the store's pending batch. */
#include "dtn_node_priv.h"

#include <stdio.h>
#include <string.h>

#include <esp_http_server.h>
#include <esp_log.h>
#include <lwip/sockets.h>

#include "dtn_canonical.h"
#include "dtn_core.h"
#include "dtn_json.h"
#include "dtn_netif.h"
#include "dtn_prekeys.h"
#include "dtn_sync.h"

static const char *TAG = "dtn-http";

const char *code_status_name(int status);
static esp_err_t h_sync_get_405(httpd_req_t *req);

/* ---- response helpers ---- */

static void set_common_headers(httpd_req_t *req)
{
    /* issue #14 NODE-03: on EVERY response (HTML, JSON, errors, redirects) */
    httpd_resp_set_hdr(req, "X-Content-Type-Options", "nosniff");
    httpd_resp_set_hdr(req, "X-Frame-Options", "DENY");
    httpd_resp_set_hdr(req, "Referrer-Policy", "no-referrer");
}

static esp_err_t send_json_err(httpd_req_t *req, int status, const char *code)
{
    httpd_resp_set_status(req, code_status_name(status));
    httpd_resp_set_type(req, "application/json; charset=utf-8");
    char body[96];
    snprintf(body, sizeof(body), "{\"status\":\"error\",\"error\":\"%s\"}", code);
    if (status == 429) {
        /* Retry-After set by the caller before this */
    }
    set_common_headers(req);
    return httpd_resp_send(req, body, HTTPD_RESP_USE_STRLEN);
}

/* the Go net/http status lines this node answers with */
const char *code_status_name(int status)
{
    switch (status) {
    case 301: return "301 Moved Permanently";
    case 302: return "302 Found";
    case 400: return "400 Bad Request";
    case 404: return "404 Not Found";
    case 405: return "405 Method Not Allowed";
    case 413: return "413 Request Entity Too Large";
    case 429: return "429 Too Many Requests";
    case 500: return "500 Internal Server Error";
    case 507: return "507 Insufficient Storage";
    default: return "200 OK";
    }
}

/* §10.2 canonical-host gate + security headers; the captive-probe
 * exemption (path-keyed, host/method-agnostic). Returns -1 to continue
 * into the handler, or an esp_err_t already answered. */
static int gate(httpd_req_t *req)
{
    set_common_headers(req);
    char path[128];
    strlcpy(path, req->uri, sizeof(path)); /* uri = path?query: split */
    char *qm = strchr(path, '?');
    if (qm) *qm = '\0';
    char host[80] = "";
    if (httpd_req_get_hdr_value_str(req, "Host", host, sizeof(host)) != ESP_OK) {
        host[0] = '\0';
    }
    dtn_canon_verdict v = dtn_canonical_check(path, host);
    if (v == DTN_CANON_PASS) return -1;
    char loc[256];
    if (v == DTN_CANON_PROBE) {
        dtn_probe_location(loc, sizeof(loc));
        httpd_resp_set_status(req, code_status_name(302));
    } else {
        char uri[160];
        httpd_req_get_url_query_str(req, uri, sizeof(uri));
        char target[288];
        if (uri[0]) {
            snprintf(target, sizeof(target), "%s?%s", path, uri);
        } else {
            snprintf(target, sizeof(target), "%s", path);
        }
        dtn_canonical_location(loc, sizeof(loc), target);
        httpd_resp_set_status(req, code_status_name(301));
    }
    httpd_resp_set_hdr(req, "Location", loc);
    return httpd_resp_send(req, NULL, 0);
}

/* per-source-IP key (network layer only — forwarding headers are never
 * consulted, §10.1) */
static uint32_t client_ip(httpd_req_t *req)
{
    int fd = httpd_req_to_sockfd(req);
    struct sockaddr_storage ss;
    socklen_t sl = sizeof(ss);
    if (getpeername(fd, (struct sockaddr *)&ss, &sl) != 0) return 0;
    if (ss.ss_family == AF_INET) {
        return ((struct sockaddr_in *)&ss)->sin_addr.s_addr;
    }
    return 0; /* IPv4-only AP; v6-mapped falls into one shared bucket */
}

#include <stddef.h>
static bool budget_allow(httpd_req_t *req, size_t bucket_off, uint64_t cost)
{
    dtn_client *c = dtn_node_client(client_ip(req));
    if (!c) return false; /* table full: shed */
    dtn_bucket *b = (dtn_bucket *)((char *)c + bucket_off);
    int64_t wait = 0;
    if (dtn_bucket_allow(b, now_ms(), cost, &wait)) return true;
    char rs[16];
    snprintf(rs, sizeof(rs), "%lld", (long long)wait);
    httpd_resp_set_hdr(req, "Retry-After", rs);
    send_json_err(req, 429, "rate_limited");
    dtn_node_count_reject("rate_limited");
    return false;
}

/* ---- static assets (exact paths from the embedded table) ---- */

static esp_err_t serve_asset(httpd_req_t *req, const dtn_web_asset *a)
{
    httpd_resp_set_type(req, a->ctype);
    httpd_resp_set_hdr(req, "Cache-Control", "no-cache");
    set_common_headers(req);
    return httpd_resp_send(req, (const char *)a->start,
                           (int)dtn_web_asset_len(a));
}

static const dtn_web_asset *find_asset(const char *path)
{
    int n = 0;
    const dtn_web_asset *tab = dtn_web_assets(&n);
    for (int i = 0; i < n; i++) {
        if (!strcmp(tab[i].path, path)) return &tab[i];
    }
    return NULL;
}

/* ---- GET / and static ---- */

static esp_err_t h_static(httpd_req_t *req)
{
    int g = gate(req);
    if (g != -1) return g;
    char path[128];
    strlcpy(path, req->uri, sizeof(path));
    char *qm = strchr(path, '?');
    if (qm) *qm = '\0';
    if (!strcmp(path, "/")) strcpy(path, "/index.html");
    const dtn_web_asset *a = find_asset(path);
    if (!a) return send_json_err(req, 404, "not_found");
    return serve_asset(req, a);
}

static esp_err_t h_static_get_only(httpd_req_t *req)
{
    if (req->method != HTTP_GET) {
        httpd_resp_set_hdr(req, "Allow", "GET");
        return send_json_err(req, 405, "method_not_allowed");
    }
    return h_static(req);
}

/* ---- captive probes (§10.2: 302, never 204, any Host) ---- */

static esp_err_t h_probe(httpd_req_t *req)
{
    int g = gate(req); /* answers the 302 itself */
    if (g != -1) return g;
    return send_json_err(req, 404, "not_found");
}

/* ---- GET /api/v1/capabilities (§15.5) ---- */

static esp_err_t h_capabilities(httpd_req_t *req)
{
    int g = gate(req);
    if (g != -1) return g;
    char out[320];
    long n = dtn_docs_capabilities(out, sizeof(out), DTN_BUILD_STRING,
                                   boot_uptime_s(),
                                   DTN_STORAGE_SCHEMA_VERSION);
    httpd_resp_set_type(req, "application/json; charset=utf-8");
    set_common_headers(req);
    return httpd_resp_send(req, out, (int)n);
}

/* ---- diagnostics (§10.7): budgeted, 1-second snapshot cache ---- */

static esp_err_t h_health(httpd_req_t *req)
{
    int g = gate(req);
    if (g != -1) return g;
    if (!budget_allow(req, offsetof(dtn_client, diag), 1)) return ESP_OK;
    const char *doc = dtn_node_snapshot_json();
    httpd_resp_set_type(req, "application/json; charset=utf-8");
    set_common_headers(req);
    return httpd_resp_send(req, doc, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t h_status(httpd_req_t *req)
{
    int g = gate(req);
    if (g != -1) return g;
    if (!budget_allow(req, offsetof(dtn_client, diag), 1)) return ESP_OK;
    char page[1536];
    long n = dtn_node_status_html(page, sizeof(page), dtn_node_snapshot());
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    set_common_headers(req);
    return httpd_resp_send(req, page, (int)n);
}

/* ---- GET /api/v1/directory (§10.3) ---- */

struct dir_out {
    httpd_req_t *req;
    bool first;
};

static void dir_send_cb(void *ud, const char *alias, const char *pubkey,
                        const char *x25519, int64_t last_seen, int64_t epoch,
                        const char *prekeys)
{
    struct dir_out *o = ud;
    char ent[2600];
    long n = dtn_docs_dir_entry(ent, sizeof(ent), alias, pubkey, x25519,
                                last_seen, epoch, prekeys);
    if (n < 0) return;
    if (!o->first) httpd_resp_send_chunk(o->req, ",", 1);
    o->first = false;
    httpd_resp_send_chunk(o->req, ent, (int)n);
}

static esp_err_t h_dir_get(httpd_req_t *req)
{
    int g = gate(req);
    if (g != -1) return g;
    int32_t limit = DTN_DIRECTORY_MAX;
    char q[32];
    if (httpd_req_get_url_query_str(req, q, sizeof(q)) == ESP_OK) {
        char val[16];
        if (httpd_query_key_value(q, "limit", val, sizeof(val)) == ESP_OK) {
            char *end = NULL;
            long v = strtol(val, &end, 10);
            if (end == val || *end) {
                return send_json_err(req, 400, "invalid_limit");
            }
            if (v < 1) v = 1;
            if (v > DTN_DIRECTORY_MAX) v = DTN_DIRECTORY_MAX;
            limit = (int32_t)v;
        }
    }
    httpd_resp_set_type(req, "application/json; charset=utf-8");
    set_common_headers(req);
    httpd_resp_send_chunk(req, "[", 1);
    struct dir_out o = { req, true };
    xSemaphoreTake(g_node.store_mu, portMAX_DELAY);
    dtn_store_dir_get(g_node.store, limit, &o, dir_send_cb, NULL);
    xSemaphoreGive(g_node.store_mu);
    httpd_resp_send_chunk(req, "]", 1);
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

/* ---- POST /api/v1/directory (§10.3) ---- */

struct dir_req {
    /* captured members */
    char alias[DTN_ALIAS_MAX + 2];
    size_t alias_len;
    char pubkey[49];
    size_t pubkey_len;
    char x25519[49];
    size_t x25519_len;
    bool has_prekeys;
    dtn_prekeys_val pk;
    dtn_prekeys_members pkm;
    /* context */
    int st; /* 0 top members, 1 skip */
    int skip_depth;
    int cur; /* 0 alias 1 pubkey 2 x25519 3 prekeys -1 other */
    bool bad_type;
};

static void dirreq_event(void *ud, const dtn_json_event *ev)
{
    struct dir_req *r = ud;
    switch (ev->type) {
    case DTN_JSON_EV_BEGIN_OBJECT:
        if (r->st == 0) return; /* the body object */
        if (r->cur == 3 && !r->has_prekeys) {
            /* the prekeys member IS an object: validate it in place */
            r->has_prekeys = true;
            return;
        }
        r->st = 1;
        r->skip_depth = 1;
        return;
    case DTN_JSON_EV_BEGIN_ARRAY:
        r->st = 1;
        r->skip_depth = 1;
        r->bad_type = true; /* array where a string/member belongs */
        return;
    case DTN_JSON_EV_END_OBJECT:
    case DTN_JSON_EV_END_ARRAY:
        if (r->st == 1 && --r->skip_depth == 0) r->st = 0;
        return;
    case DTN_JSON_EV_KEY:
        if (r->st != 0) return;
        r->cur = -1;
        if (!ev->overflow) {
            if (!strcmp(ev->s, "alias")) r->cur = 0;
            else if (!strcmp(ev->s, "pubkey")) r->cur = 1;
            else if (!strcmp(ev->s, "x25519")) r->cur = 2;
            else if (!strcmp(ev->s, "prekeys")) r->cur = 3;
        }
        return;
    case DTN_JSON_EV_STRING:
        if (r->st != 0) return;
        if (ev->overflow) {
            if (r->cur == 0) r->alias_len = sizeof(r->alias);
            else if (r->cur >= 1 && r->cur <= 2) r->bad_type = true;
            return;
        }
        if (r->cur == 0) {
            if (ev->len > DTN_ALIAS_MAX) { r->alias_len = sizeof(r->alias); }
            else {
                memcpy(r->alias, ev->s, ev->len);
                r->alias[ev->len] = 0;
                r->alias_len = ev->len;
            }
        } else if (r->cur == 1) {
            if (ev->len >= sizeof(r->pubkey)) { r->bad_type = true; }
            else {
                memcpy(r->pubkey, ev->s, ev->len);
                r->pubkey[ev->len] = 0;
                r->pubkey_len = ev->len;
            }
        } else if (r->cur == 2) {
            if (ev->len >= sizeof(r->x25519)) { r->bad_type = true; }
            else {
                memcpy(r->x25519, ev->s, ev->len);
                r->x25519[ev->len] = 0;
                r->x25519_len = ev->len;
            }
        } else if (r->cur >= 3) {
            r->bad_type = true; /* string prekeys / string alias-extra */
        }
        return;
    case DTN_JSON_EV_NUMBER:
    case DTN_JSON_EV_TRUE:
    case DTN_JSON_EV_FALSE:
    case DTN_JSON_EV_NULL:
        if (r->st != 0 && r->has_prekeys) {
            /* feed the prekeys validator its subtree events */
            dtn_prekeys_val_feed(&r->pk, NULL, 0);
            return;
        }
        if (r->st == 0 && r->cur >= 0) r->bad_type = true;
        return;
    }
}

/* ---- POST /api/v1/sync (§10.4): the streaming fail-closed processor ---- */

struct sync_env {
    httpd_req_t *req;
    bool req_budget_checked;
};

static int sink_begin(void *ud)
{
    (void)ud;
    xSemaphoreTake(g_node.store_mu, portMAX_DELAY);
    int rc = dtn_store_batch_begin(g_node.store);
    xSemaphoreGive(g_node.store_mu);
    return rc;
}

static int sink_put(void *ud, const dtn_envelope *e, int *absorbed)
{
    (void)ud;
    xSemaphoreTake(g_node.store_mu, portMAX_DELAY);
    int rc = dtn_store_batch_put(g_node.store, e, absorbed);
    xSemaphoreGive(g_node.store_mu);
    *absorbed = (rc == 1); /* 1 = absorbed by dedup → sink contract 0 */
    return (rc < 0) ? rc : 0; /* -1 io (507), -2 cap (429 node_full) */
}

static int sink_commit(void *ud)
{
    (void)ud;
    xSemaphoreTake(g_node.store_mu, portMAX_DELAY);
    int rc = dtn_store_batch_commit(g_node.store);
    xSemaphoreGive(g_node.store_mu);
    return rc;
}

static void sink_abort(void *ud)
{
    (void)ud;
    xSemaphoreTake(g_node.store_mu, portMAX_DELAY);
    dtn_store_batch_abort(g_node.store);
    xSemaphoreGive(g_node.store_mu);
}

struct pull_env {
    httpd_req_t *req;
    bool first;
};

static void pull_send_cb(void *ud, const dtn_envelope *e)
{
    struct pull_env *o = ud;
    char buf[DTN_PAYLOAD_B64_MAX + 128];
    long n = dtn_envelope_write_json(buf, sizeof(buf), e);
    if (n < 0) return;
    if (!o->first) httpd_resp_send_chunk(o->req, ",", 1);
    o->first = false;
    httpd_resp_send_chunk(o->req, buf, (int)n);
}

static const dtn_sync_sink STORE_SINK = { NULL, sink_begin, sink_put,
                                         sink_commit, sink_abort };

static esp_err_t sync_answer_err(httpd_req_t *req, dtn_sync_err v)
{
    switch (v) {
    case DTN_SYNC_OK: return ESP_OK;
    case DTN_SYNC_ERR_BODY_TOO_LARGE:
        dtn_node_count_reject("body_too_large");
        return send_json_err(req, 413, "body_too_large");
    case DTN_SYNC_ERR_JSON:
        dtn_node_count_reject("invalid_json");
        return send_json_err(req, 400, "invalid_json");
    case DTN_SYNC_ERR_INVALID_LIMIT:
        dtn_node_count_reject("invalid_limit");
        return send_json_err(req, 400, "invalid_limit");
    case DTN_SYNC_ERR_TOO_MANY_KNOWN:
        dtn_node_count_reject("too_many_known_ids");
        return send_json_err(req, 400, "too_many_known_ids");
    case DTN_SYNC_ERR_INVALID_KNOWN:
        dtn_node_count_reject("invalid_known_id");
        return send_json_err(req, 400, "invalid_known_id");
    case DTN_SYNC_ERR_TOO_MANY_PUSH:
        dtn_node_count_reject("too_many_envelopes");
        return send_json_err(req, 400, "too_many_envelopes");
    case DTN_SYNC_ERR_RATE_LIMITED: /* already answered by the budget */
        dtn_node_count_reject("rate_limited");
        return send_json_err(req, 429, "rate_limited");
    case DTN_SYNC_ERR_INVALID_ENVELOPE:
        dtn_node_count_reject("invalid_envelope");
        return send_json_err(req, 400, "invalid_envelope");
    case DTN_SYNC_ERR_NODE_FULL:
        dtn_node_count_reject("node_full");
        return send_json_err(req, 429, "node_full");
    case DTN_SYNC_ERR_STORAGE:
        dtn_node_count_reject("storage_unavailable");
        return send_json_err(req, 507, "storage_unavailable");
    }
    return send_json_err(req, 500, "internal");
}

static esp_err_t h_sync(httpd_req_t *req)
{
    int g = gate(req);
    if (g != -1) return g;
    /* the request budget is checked BEFORE the body is read (§10.1) */
    if (!budget_allow(req, offsetof(dtn_client, request), 1)) return ESP_OK;
    if (req->content_len > DTN_BODY_MAX_BYTES) {
        dtn_node_count_reject("body_too_large");
        return send_json_err(req, 413, "body_too_large");
    }

    static char known_store[DTN_KNOWN_IDS_MAX][DTN_ID_LEN + 1]; /* single
        httpd task: scratch reused per request, never persisted (§13.6) */
    dtn_known_ids known = { known_store, DTN_KNOWN_IDS_MAX, 0 };
    dtn_sync sync;
    dtn_sync_init(&sync, boot_uptime_s(), &STORE_SINK, &known);

    char chunk[1024];
    for (;;) {
        int n = httpd_req_recv(req, chunk, sizeof(chunk));
        if (n == HTTPD_SOCK_ERR_TIMEOUT) continue;
        if (n < 0) break;
        if (n == 0) break;
        if (n == 0) break;
        if (dtn_sync_feed(&sync, chunk, (size_t)n) != DTN_JSONFEED_OK) break;
        /* the httpd buffers the whole body for us? no: it streams; the
         * remaining length drives the loop */
        if (dtn_sync_done(&sync)) break;
        if (req->content_len > 0 &&
            (int64_t)dtn_sync_consumed(&sync) >= req->content_len) break;
    }

    /* envelope budget: withdrawn atomically for the whole batch, before
     * the commit (pull-only syncs cost nothing, §10.1) */
    bool budget_ok = true;
    if (dtn_sync_pushed(&sync) > 0) {
        dtn_client *c = dtn_node_client(client_ip(req));
        int64_t wait = 0;
        budget_ok = c && dtn_bucket_allow(
            (dtn_bucket *)((char *)c + offsetof(dtn_client, env)), now_ms(),
                                          (uint64_t)dtn_sync_pushed(&sync),
                                          &wait);
        if (!budget_ok) {
            char rs[16];
            snprintf(rs, sizeof(rs), "%lld", (long long)wait);
            httpd_resp_set_hdr(req, "Retry-After", rs);
        }
    }
    dtn_sync_err v = dtn_sync_finish(&sync, budget_ok);
    if (v != DTN_SYNC_OK) return sync_answer_err(req, v);

    dtn_node_count_accept(dtn_sync_absorbed(&sync));

    /* pull (§10.4 step 3) and respond */
    const char *head = "{\"status\":\"ok\",\"pull_envelopes\":[";
    httpd_resp_set_type(req, "application/json; charset=utf-8");
    set_common_headers(req);
    httpd_resp_send_chunk(req, head, (int)strlen(head));
    struct pull_env pe = { req, true };
    int32_t served = 0;
    xSemaphoreTake(g_node.store_mu, portMAX_DELAY);
    dtn_store_pull(g_node.store, dtn_sync_known(&sync),
                   dtn_sync_limit(&sync), boot_uptime_s(), &pe, pull_send_cb,
                   &served);
    xSemaphoreGive(g_node.store_mu);
    httpd_resp_send_chunk(req, "]}", 2);
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

/* ---- POST /api/v1/directory ---- */

static esp_err_t h_dir_post(httpd_req_t *req)
{
    int g = gate(req);
    if (g != -1) return g;
    if (!budget_allow(req, offsetof(dtn_client, request), 1)) return ESP_OK;
    char ct[64] = "";
    size_t cl = sizeof(ct);
    httpd_req_get_hdr_value_str(req, "Content-Type", ct, cl);
    if (strncmp(ct, "application/json", 16) != 0) {
        dtn_node_count_reject("content_type");
        return send_json_err(req, 400, "content_type");
    }

    struct dir_req r;
    memset(&r, 0, sizeof(r));
    dtn_json_parser jp;
    dtn_json_init(&jp, dirreq_event, &r);

    char chunk[512];
    int64_t read_total = 0;
    for (;;) {
        int n = httpd_req_recv(req, chunk, sizeof(chunk));
        if (n < 0) break;
        if (n == 0) break;
        read_total += n;
        if (read_total > DTN_BODY_MAX_BYTES) {
            dtn_node_count_reject("body_too_large");
            return send_json_err(req, 413, "body_too_large");
        }
        if (dtn_json_feed(&jp, chunk, (size_t)n) != DTN_JSONFEED_OK) break;
        if ((int64_t)jp.consumed >= req->content_len && req->content_len > 0) {
            break;
        }
    }
    if (!r.has_prekeys) {
        dtn_prekeys_val_init(&r.pk, &r.pkm); /* absent member: clears (§9) */
    }

    /* §10.3 validation order and codes (parity with node/internal) */
    if (r.bad_type || r.alias_len == 0 || !dtn_valid_alias(r.alias)) {
        dtn_node_count_reject("invalid_alias");
        return send_json_err(req, 400, "invalid_alias");
    }
    if (r.pubkey_len == 0 ||
        !dtn_valid_base64_of_len(r.pubkey, 32)) {
        dtn_node_count_reject("invalid_pubkey");
        return send_json_err(req, 400, "invalid_pubkey");
    }
    if (r.x25519_len == 0 ||
        !dtn_valid_base64_of_len(r.x25519, 32)) {
        dtn_node_count_reject("invalid_x25519");
        return send_json_err(req, 400, "invalid_x25519");
    }
    const char *prekeys = NULL;
    char canon[2100];
    if (r.has_prekeys) {
        if (!dtn_prekeys_val_ok(&r.pk)) {
            dtn_node_count_reject("invalid_prekeys");
            return send_json_err(req, 400, "invalid_prekeys");
        }
        /* canonical compact re-serialization of the validated members
         * (docs/esp32-design.md §7: whitespace-only re-serialization
         * deviation — semantics and member set byte-equal, spacing
         * canonicalized) */
        int cn = snprintf(canon, sizeof(canon),
                          "{\"v\":%lld,\"spk\":\"%s\",\"spk_sig\":\"%s\","
                          "\"ts\":%lld,\"opks\":[",
                          (long long)r.pkm.v, r.pkm.spk, r.pkm.spk_sig,
                          (long long)r.pkm.ts);
        for (int i = 0; i < r.pkm.opk_count && cn < (int)sizeof(canon); i++) {
            cn += snprintf(canon + cn, sizeof(canon) - (size_t)cn,
                           "%s\"%s\"",
                           i ? "," : "", r.pkm.opks[i]);
        }
        if (cn < (int)sizeof(canon)) {
            cn += snprintf(canon + cn, sizeof(canon) - (size_t)cn, "]}");
        }
        if (cn >= (int)sizeof(canon)) {
            dtn_node_count_reject("invalid_prekeys");
            return send_json_err(req, 400, "invalid_prekeys");
        }
        prekeys = canon;
    }
    esp_err_t err;
    xSemaphoreTake(g_node.store_mu, portMAX_DELAY);
    int rc = dtn_store_dir_upsert(g_node.store, r.alias, r.pubkey, r.x25519,
                                  prekeys, boot_uptime_s());
    xSemaphoreGive(g_node.store_mu);
    if (rc == -2) {
        return send_json_err(req, 429, "node_full"); /* shipped row cap */
    }
    if (rc != 0) {
        return send_json_err(req, 507, "storage_unavailable");
    }
    httpd_resp_set_type(req, "application/json; charset=utf-8");
    set_common_headers(req);
    return httpd_resp_send(req, "{\"status\":\"ok\"}",
                           HTTPD_RESP_USE_STRLEN);
    (void)canon;
}

/* ---- registration ---- */

static const httpd_uri_t ROUTES_8080[] = {
    { "/", HTTP_GET, h_static, NULL },
    { "/guide", HTTP_GET, h_static_get_only, NULL },
    { "/generate_204", HTTP_GET, h_probe, NULL },
    { "/generate_204", HTTP_POST, h_probe, NULL },
    { "/hotspot-detect.html", HTTP_GET, h_probe, NULL },
    { "/api/v1/directory", HTTP_GET, h_dir_get, NULL },
    { "/api/v1/directory", HTTP_POST, h_dir_post, NULL },
    { "/api/v1/sync", HTTP_POST, h_sync, NULL },
    { "/api/v1/sync", HTTP_GET, h_sync_get_405, NULL },
    { "/api/v1/capabilities", HTTP_GET, h_capabilities, NULL },
    { "/api/v1/health", HTTP_GET, h_health, NULL },
    { "/status", HTTP_GET, h_status, NULL },
};

static esp_err_t h_sync_get_405(httpd_req_t *req)
{
    int g = gate(req);
    if (g != -1) return g;
    httpd_resp_set_hdr(req, "Allow", "POST");
    return send_json_err(req, 405, "method_not_allowed");
}

/* fallback: unknown paths → 404; wrong methods on known paths → 405
 * (httpd answers 404 itself for unregistered URIs — register the catch-all
 * by listing each path's alternates above). */

static httpd_handle_t start_server(uint16_t port, const httpd_uri_t *uris,
                                   size_t n)
{
    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.server_port = port;
    cfg.stack_size = CONFIG_DTN_HTTPD_STACK;
    cfg.max_uri_handlers = n + 2;
    cfg.lru_purge_enable = true;
    httpd_handle_t h = NULL;
    if (httpd_start(&h, &cfg) != ESP_OK) return NULL;
    for (int i = 0; i < (int)n; i++) {
        httpd_register_uri_handler(h, &uris[i]);
    }
    return h;
}

/* the :80 listener serves ONLY the two probes; everything else gets the
 * §10.2 redirect to the canonical origin (gate() answers both) */
static const httpd_uri_t ROUTES_80[] = {
    { "/generate_204", HTTP_GET, h_probe, NULL },
    { "/generate_204", HTTP_POST, h_probe, NULL },
    { "/hotspot-detect.html", HTTP_GET, h_probe, NULL },
    { "/hotspot-detect.html", HTTP_POST, h_probe, NULL },
};

void dtn_http_start(void)
{
    httpd_handle_t main_srv =
        start_server(8080, ROUTES_8080, sizeof(ROUTES_8080) / sizeof(ROUTES_8080[0]));
    httpd_handle_t legacy =
        start_server(80, ROUTES_80, sizeof(ROUTES_80) / sizeof(ROUTES_80[0]));
    if (!main_srv || !legacy) {
        ESP_LOGE(TAG, "httpd start failed");
    }
    (void)legacy;
}

/* ---- the operator status view (§10.7): server-rendered, no JavaScript,
 * aggregates only, N/A for everything unmeasured, linked from nowhere ---- */
long dtn_node_status_html(char *out, size_t cap,
                          const dtn_health_snapshot *s)
{
    size_t pos = 0;
#define W(...) pos += (size_t)snprintf(out + pos, cap - pos, __VA_ARGS__)
    W("<!doctype html><html><head><meta charset=\"utf-8\">"
      "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'\">"
      "<title>offgrid node — status</title></head><body><h1>offgrid node</h1>"
      "<p>build %s — liveness only; aggregates only (protocol §10.7).</p>"
      "<h2>Store</h2><ul>"
      "<li>envelopes: %ld / capacity %ld</li>"
      "<li>directory entries: %ld</li>"
      "<li>db size: %lld B</li>"
      "<li>last cleanup: %s (%ld deleted)</li>"
      "<li>expiring 1h/6h/24h: %ld / %ld / %ld</li></ul>"
      "<h2>Counters (RAM, since boot)</h2><ul>"
      "<li>pushes accepted: %lld, rejected: %lld</li>"
      "<li>dedup hits: %lld; TTL sweeps: %lld (%lld removed)</li>"
      "<li>active clients (15 min): %ld</li></ul>"
      "<h2>System</h2><ul><li>uptime: %lld s</li>"
      "<li>battery: N/A</li></ul>",
      s->build,
      (long)s->envelopes, (long)s->envelope_capacity,
      (long)s->directory_entries,
      s->db_size_bytes >= 0 ? (long long)s->db_size_bytes : 0LL,
      s->last_cleanup_unix ? "recent" : "none yet",
      (long)s->last_cleanup_deleted,
      (long)s->expiring_within_1h, (long)s->expiring_within_6h,
      (long)s->expiring_within_24h,
      (long long)s->pushes_accepted, (long long)s->pushes_rejected,
      (long long)s->dedup_hits, (long long)s->ttl_sweeps,
      (long long)s->ttl_swept_envelopes, (long)s->active_clients,
      (long long)s->uptime_seconds);
    if (g_node.boot_failed) {
        W("<p><strong>BOOT STANCE: %s</strong></p>", g_node.boot_reason);
    }
    W("</body></html>");
#undef W
    return (long)(pos < cap ? pos : cap - 1);
}
