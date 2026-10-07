/* dtn_docs.h — assembly of the two identity-bearing documents:
 * GET /api/v1/capabilities (§15.5) and GET /api/v1/health (§10.7).
 *
 * The four shared identity members (api, build, envelope_versions,
 * schema_version) are filled HERE, from one place, so the §10.7
 * "two documents, one identity" single-source guarantee holds by
 * construction. The §10.7 N/A convention is binding: an unavailable datum
 * is JSON null — never 0, never fabricated. */
#ifndef DTN_DOCS_H
#define DTN_DOCS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dtn_core.h"
#include "dtn_limits.h"

#ifdef __cplusplus
extern "C" {
#endif

/* nullable primitives for the §10.7 fixed member set */
typedef struct { bool has; double v; } dtn_opt_num;
typedef struct { bool has; int64_t v; } dtn_opt_int;
typedef struct { bool has; const char *s; } dtn_opt_str;
/* tri-state bool: 0 = false, 1 = true, -1 = null */
typedef int8_t dtn_tri;

#define DTN_OPT_NUM(x) ((dtn_opt_num){ true, (x) })
#define DTN_OPT_INT(x) ((dtn_opt_int){ true, (x) })
#define DTN_OPT_STR(x) ((dtn_opt_str){ true, (x) })
#define DTN_OPT_NULL_NUM ((dtn_opt_num){ false, 0 })
#define DTN_OPT_NULL_INT ((dtn_opt_int){ false, 0 })
#define DTN_OPT_NULL_STR ((dtn_opt_str){ false, NULL })

typedef struct {
    const char *build;      /* platform-identifying build string (§15.5) */
    int64_t now;            /* node clock, unix seconds */
    int64_t uptime_seconds;
    int envelope_capacity;  /* the enforced cap (honest capacity) */

    /* store figures — read from the store when the snapshot was taken */
    int32_t envelopes;
    int32_t directory_entries;
    int64_t db_size_bytes;      /* -1 → null */
    int64_t last_cleanup_unix;  /* 0 = no sweep completed yet (spec) */
    int32_t last_cleanup_deleted;

    /* process-lifetime RAM counters (§10.7) */
    int64_t pushes_accepted, pushes_rejected, dedup_hits;
    int64_t ttl_sweeps, ttl_swept_envelopes;
    int64_t rej_invalid, rej_rate_limited, rej_node_full, rej_storage,
        rej_too_large;

    /* battery — whole member null unless a sampler is wired */
    bool have_battery;
    dtn_opt_str charge_state;
    dtn_opt_num soc_percent;
    dtn_opt_str soc_source;
    dtn_opt_num voltage_volts;
    dtn_opt_num current_amps;
    dtn_opt_num capacity_wh;
    dtn_opt_int dod_floor_percent;
    dtn_opt_str alert_band;
    dtn_opt_num autonomy_hours;
    dtn_opt_num autonomy_nights;
    dtn_opt_str autonomy_basis;
    dtn_opt_num health_percent;

    /* system */
    dtn_opt_num load1, load5, load15;
    dtn_tri cpu_saturated;
    dtn_opt_int mem_total_bytes, mem_used_bytes, mem_available_bytes;
    dtn_opt_int disk_total_bytes, disk_free_bytes, disk_used_bytes;
    dtn_tri disk_free_low;
    dtn_opt_num soc_temp_celsius;
    dtn_tri cpu_throttled;
    dtn_opt_int system_uptime_seconds;

    /* store member (§10.7 issue-#36): buckets always present when the store
     * was readable (an unreadable store sheds 507 instead); counters_delta
     * is null until the minimum-data rule is satisfied */
    int32_t expiring_within_1h, expiring_within_6h, expiring_within_24h;
    int32_t active_clients;
    bool have_counters_delta;
    double delta_window_hours;
    int64_t delta_pushes_accepted, delta_pushes_rejected, delta_dedup_hits,
        delta_ttl_swept_envelopes;

    /* projections member (§10.7): minimum-data rule binding */
    bool enough_data;
    int32_t proj_samples;
    double proj_window_hours;
    dtn_opt_num pushes_per_day, expiries_per_day, db_growth_bytes_per_day,
        battery_drain_wh_per_day, days_to_envelope_capacity,
        days_to_disk_full;
    dtn_opt_str store_equilibrium; /* growing/shrinking/steady */
    dtn_opt_str battery_net;       /* net_positive/starving/steady */
} dtn_health_snapshot;

/* Render GET /api/v1/capabilities (§15.5, eight members). hint_epoch_current
 * is floor(now / 86400) — the same node clock that stamps directory entries.
 * Returns bytes written or -1 on out-cap. */
long dtn_docs_capabilities(char *out, size_t cap, const char *build,
                           int64_t now, int schema_version);

/* Render GET /api/v1/health (§10.7, fixed member set). Returns bytes
 * written or -1 on out-cap. Callers size the buffer generously: the fixed
 * shape is bounded at roughly 1.6 KB. */
long dtn_docs_health(char *out, size_t cap, const dtn_health_snapshot *snap);

/* Render one directory entry for GET /api/v1/directory (§10.3): the five
 * members in fixed order, plus the verbatim prekeys member when the row
 * carries one. prekeys_raw is the exact stored JSON (already validated at
 * upsert). Returns bytes written or -1 on out-cap. */
long dtn_docs_dir_entry(char *out, size_t cap, const char *alias,
                        const char *pubkey, const char *x25519,
                        int64_t last_seen, int64_t epoch,
                        const char *prekeys_raw);

#ifdef __cplusplus
}
#endif

#endif /* DTN_DOCS_H */
