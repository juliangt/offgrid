/* dtn_docs.c — capabilities/health/directory-entry rendering. See dtn_docs.h.
 * The member ORDER here is the fixed §15.5/§10.7/§10.3 order; floats render
 * like Go's encoding/json shortest form for the magnitudes involved. */
#include "dtn_docs.h"

#include <stdio.h>
#include <string.h>

/* ---- tiny writer ---- */
typedef struct {
    char *out;
    size_t cap;
    size_t pos;
    bool err;
} wr;

static void wr_raw(wr *w, const char *s, size_t n)
{
    if (w->pos + n + 1 > w->cap) {
        w->err = true;
        return;
    }
    memcpy(w->out + w->pos, s, n);
    w->pos += n;
}

static void wr_lit(wr *w, const char *s) { wr_raw(w, s, strlen(s)); }

static void wr_int(wr *w, int64_t v)
{
    char tmp[24];
    snprintf(tmp, sizeof(tmp), "%lld", (long long)v);
    wr_lit(w, tmp);
}

/* Go-compatible shortest float for the doc's magnitudes (≤ 6 significant
 * decimals are all the document ever carries). */
static void wr_num(wr *w, double v)
{
    char tmp[40];
    snprintf(tmp, sizeof(tmp), "%.10g", v);
    wr_lit(w, tmp);
}

static void wr_str(wr *w, const char *s, size_t n)
{
    wr_lit(w, "\"");
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        char buf[8];
        switch (c) {
        case '"': wr_lit(w, "\\\""); break;
        case '\\': wr_lit(w, "\\\\"); break;
        case '\b': wr_lit(w, "\\b"); break;
        case '\f': wr_lit(w, "\\f"); break;
        case '\n': wr_lit(w, "\\n"); break;
        case '\r': wr_lit(w, "\\r"); break;
        case '\t': wr_lit(w, "\\t"); break;
        default:
            if (c < 0x20) {
                snprintf(buf, sizeof(buf), "\\u%04x", c);
                wr_lit(w, buf);
            } else {
                wr_raw(w, (const char *)&c, 1);
            }
        }
    }
    wr_lit(w, "\"");
}

static void wr_json_str(wr *w, const char *s)
{
    wr_str(w, s ? s : "", s ? strlen(s) : 0);
}

static void wr_opt_num(wr *w, dtn_opt_num v)
{
    if (v.has) {
        wr_num(w, v.v);
    } else {
        wr_lit(w, "null");
    }
}

static void wr_opt_int(wr *w, dtn_opt_int v)
{
    if (v.has) {
        wr_int(w, v.v);
    } else {
        wr_lit(w, "null");
    }
}

static void wr_opt_str(wr *w, dtn_opt_str v)
{
    if (v.has) {
        wr_json_str(w, v.s);
    } else {
        wr_lit(w, "null");
    }
}

static void wr_tri(wr *w, dtn_tri v)
{
    if (v < 0) {
        wr_lit(w, "null");
    } else {
        wr_lit(w, v ? "true" : "false");
    }
}

/* ---- capabilities (§15.5) ---- */
long dtn_docs_capabilities(char *out, size_t cap, const char *build,
                           int64_t now, int schema_version)
{
    wr w = { out, cap, 0, false };
    wr_lit(&w, "{");
    wr_lit(&w, "\"api\":\"v1\",");
    wr_lit(&w, "\"envelope_versions\":[1,2],");
    wr_lit(&w, "\"min_envelope_version\":1,");
    wr_lit(&w, "\"max_envelope_version\":2,");
    wr_lit(&w, "\"schema_version\":");
    wr_int(&w, schema_version);
    wr_lit(&w, ",\"build\":");
    wr_json_str(&w, build);
    wr_lit(&w, ",\"hint_epoch_seconds\":");
    wr_int(&w, DTN_HINT_EPOCH_SECONDS);
    wr_lit(&w, ",\"hint_epoch_current\":");
    wr_int(&w, now / DTN_HINT_EPOCH_SECONDS);
    wr_lit(&w, "}");
    if (w.err) return -1;
    w.out[w.pos] = '\0';
    return (long)w.pos;
}

/* ---- health (§10.7) ---- */
long dtn_docs_health(char *out, size_t cap, const dtn_health_snapshot *s)
{
    wr w = { out, cap, 0, false };

    /* identity members — same source as capabilities by construction */
    wr_lit(&w, "{\"status\":\"ok\",");
    wr_lit(&w, "\"api\":\"v1\",");
    wr_lit(&w, "\"build\":");
    wr_json_str(&w, s->build);
    wr_lit(&w, ",\"envelope_versions\":[1,2],");
    wr_lit(&w, "\"schema_version\":");
    wr_int(&w, DTN_STORAGE_SCHEMA_VERSION);
    wr_lit(&w, ",\"uptime_seconds\":");
    wr_int(&w, s->uptime_seconds);
    wr_lit(&w, ",\"envelopes\":");
    wr_int(&w, s->envelopes);
    wr_lit(&w, ",\"envelope_capacity\":");
    wr_int(&w, s->envelope_capacity);
    wr_lit(&w, ",\"directory_entries\":");
    wr_int(&w, s->directory_entries);
    wr_lit(&w, ",\"db_size_bytes\":");
    if (s->db_size_bytes < 0) {
        wr_lit(&w, "null");
    } else {
        wr_int(&w, s->db_size_bytes);
    }
    wr_lit(&w, ",\"last_cleanup_unix\":");
    wr_int(&w, s->last_cleanup_unix);
    wr_lit(&w, ",\"last_cleanup_envelopes_deleted\":");
    wr_int(&w, s->last_cleanup_deleted);

    wr_lit(&w, ",\"counters\":{\"pushes_accepted\":");
    wr_int(&w, s->pushes_accepted);
    wr_lit(&w, ",\"pushes_rejected\":");
    wr_int(&w, s->pushes_rejected);
    wr_lit(&w, ",\"pushes_rejected_by_class\":{\"invalid\":");
    wr_int(&w, s->rej_invalid);
    wr_lit(&w, ",\"rate_limited\":");
    wr_int(&w, s->rej_rate_limited);
    wr_lit(&w, ",\"node_full\":");
    wr_int(&w, s->rej_node_full);
    wr_lit(&w, ",\"storage_unavailable\":");
    wr_int(&w, s->rej_storage);
    wr_lit(&w, ",\"too_large\":");
    wr_int(&w, s->rej_too_large);
    wr_lit(&w, "},\"dedup_hits\":");
    wr_int(&w, s->dedup_hits);
    wr_lit(&w, ",\"ttl_sweeps\":");
    wr_int(&w, s->ttl_sweeps);
    wr_lit(&w, ",\"ttl_swept_envelopes\":");
    wr_int(&w, s->ttl_swept_envelopes);
    wr_lit(&w, "}");

    /* battery (N/A convention: whole member null without a sampler) */
    wr_lit(&w, ",\"battery\":");
    if (!s->have_battery) {
        wr_lit(&w, "null");
    } else {
        wr_lit(&w, "{\"charge_state\":");
        wr_opt_str(&w, s->charge_state);
        wr_lit(&w, ",\"soc_percent\":");
        wr_opt_num(&w, s->soc_percent);
        wr_lit(&w, ",\"soc_source\":");
        wr_opt_str(&w, s->soc_source);
        wr_lit(&w, ",\"voltage_volts\":");
        wr_opt_num(&w, s->voltage_volts);
        wr_lit(&w, ",\"current_amps\":");
        wr_opt_num(&w, s->current_amps);
        wr_lit(&w, ",\"capacity_wh\":");
        wr_opt_num(&w, s->capacity_wh);
        wr_lit(&w, ",\"dod_floor_percent\":");
        wr_opt_int(&w, s->dod_floor_percent);
        wr_lit(&w, ",\"alert_band\":");
        wr_opt_str(&w, s->alert_band);
        wr_lit(&w, ",\"autonomy_hours\":");
        wr_opt_num(&w, s->autonomy_hours);
        wr_lit(&w, ",\"autonomy_nights\":");
        wr_opt_num(&w, s->autonomy_nights);
        wr_lit(&w, ",\"autonomy_basis\":");
        wr_opt_str(&w, s->autonomy_basis);
        wr_lit(&w, ",\"health_percent\":");
        wr_opt_num(&w, s->health_percent);
        wr_lit(&w, "}");
    }

    /* system */
    wr_lit(&w, ",\"system\":{\"load1\":");
    wr_opt_num(&w, s->load1);
    wr_lit(&w, ",\"load5\":");
    wr_opt_num(&w, s->load5);
    wr_lit(&w, ",\"load15\":");
    wr_opt_num(&w, s->load15);
    wr_lit(&w, ",\"cpu_saturated\":");
    wr_tri(&w, s->cpu_saturated);
    wr_lit(&w, ",\"mem_total_bytes\":");
    wr_opt_int(&w, s->mem_total_bytes);
    wr_lit(&w, ",\"mem_used_bytes\":");
    wr_opt_int(&w, s->mem_used_bytes);
    wr_lit(&w, ",\"mem_available_bytes\":");
    wr_opt_int(&w, s->mem_available_bytes);
    wr_lit(&w, ",\"disk_total_bytes\":");
    wr_opt_int(&w, s->disk_total_bytes);
    wr_lit(&w, ",\"disk_free_bytes\":");
    wr_opt_int(&w, s->disk_free_bytes);
    wr_lit(&w, ",\"disk_used_bytes\":");
    wr_opt_int(&w, s->disk_used_bytes);
    wr_lit(&w, ",\"disk_free_low\":");
    wr_tri(&w, s->disk_free_low);
    wr_lit(&w, ",\"soc_temp_celsius\":");
    wr_opt_num(&w, s->soc_temp_celsius);
    wr_lit(&w, ",\"cpu_throttled\":");
    wr_tri(&w, s->cpu_throttled);
    wr_lit(&w, ",\"system_uptime_seconds\":");
    wr_opt_int(&w, s->system_uptime_seconds);
    wr_lit(&w, "}");

    /* software (§10.7 display-only identity) */
    wr_lit(&w, ",\"software\":{\"schema_version_on_disk\":");
    wr_int(&w, DTN_STORAGE_SCHEMA_VERSION);
    wr_lit(&w, ",\"pending_migration\":false}");

    /* store member */
    wr_lit(&w, ",\"store\":{\"expiring_within_1h\":");
    wr_int(&w, s->expiring_within_1h);
    wr_lit(&w, ",\"expiring_within_6h\":");
    wr_int(&w, s->expiring_within_6h);
    wr_lit(&w, ",\"expiring_within_24h\":");
    wr_int(&w, s->expiring_within_24h);
    wr_lit(&w, ",\"active_clients\":");
    wr_int(&w, s->active_clients);
    wr_lit(&w, ",\"counters_delta\":");
    if (!s->have_counters_delta) {
        wr_lit(&w, "null"); /* minimum-data rule */
    } else {
        wr_lit(&w, "{\"window_hours\":");
        wr_num(&w, s->delta_window_hours);
        wr_lit(&w, ",\"pushes_accepted\":");
        wr_int(&w, s->delta_pushes_accepted);
        wr_lit(&w, ",\"pushes_rejected\":");
        wr_int(&w, s->delta_pushes_rejected);
        wr_lit(&w, ",\"dedup_hits\":");
        wr_int(&w, s->delta_dedup_hits);
        wr_lit(&w, ",\"ttl_swept_envelopes\":");
        wr_int(&w, s->delta_ttl_swept_envelopes);
        wr_lit(&w, "}");
    }
    wr_lit(&w, "}");

    /* projections (minimum-data rule binding) */
    wr_lit(&w, ",\"projections\":{\"samples\":");
    wr_int(&w, s->proj_samples);
    wr_lit(&w, ",\"window_hours\":");
    wr_num(&w, s->proj_window_hours);
    wr_lit(&w, ",\"enough_data\":");
    wr_lit(&w, s->enough_data ? "true" : "false");
    wr_lit(&w, ",\"pushes_per_day\":");
    wr_opt_num(&w, s->pushes_per_day);
    wr_lit(&w, ",\"expiries_per_day\":");
    wr_opt_num(&w, s->expiries_per_day);
    wr_lit(&w, ",\"db_growth_bytes_per_day\":");
    wr_opt_num(&w, s->db_growth_bytes_per_day);
    wr_lit(&w, ",\"battery_drain_wh_per_day\":");
    wr_opt_num(&w, s->battery_drain_wh_per_day);
    wr_lit(&w, ",\"days_to_envelope_capacity\":");
    wr_opt_num(&w, s->days_to_envelope_capacity);
    wr_lit(&w, ",\"days_to_disk_full\":");
    wr_opt_num(&w, s->days_to_disk_full);
    wr_lit(&w, ",\"store_equilibrium\":");
    wr_opt_str(&w, s->store_equilibrium);
    wr_lit(&w, ",\"battery_net\":");
    wr_opt_str(&w, s->battery_net);
    wr_lit(&w, "}}");

    if (w.err) return -1;
    w.out[w.pos] = '\0';
    return (long)w.pos;
}

/* ---- directory entry (§10.3) ---- */
long dtn_docs_dir_entry(char *out, size_t cap, const char *alias,
                        const char *pubkey, const char *x25519,
                        int64_t last_seen, int64_t epoch,
                        const char *prekeys_raw)
{
    wr w = { out, cap, 0, false };
    wr_lit(&w, "{\"alias\":");
    wr_json_str(&w, alias);
    wr_lit(&w, ",\"pubkey\":");
    wr_json_str(&w, pubkey);
    wr_lit(&w, ",\"x25519\":");
    wr_json_str(&w, x25519);
    wr_lit(&w, ",\"last_seen\":");
    wr_int(&w, last_seen);
    wr_lit(&w, ",\"epoch\":");
    wr_int(&w, epoch);
    if (prekeys_raw) {
        wr_lit(&w, ",\"prekeys\":");
        wr_lit(&w, prekeys_raw); /* stored verbatim (§9/§10.3) */
    }
    wr_lit(&w, "}");
    if (w.err) return -1;
    w.out[w.pos] = '\0';
    return (long)w.pos;
}
