/* dtn_budget.h — the §10.1 per-source-IP token budgets (issue #16) and the
 * §10.7 diagnostics budget (issue #31). RAM-only math; the per-IP keying and
 * the capped client table are adapter concerns (dtn_node), this module holds
 * the bucket arithmetic so the host tests can pin it.
 *
 * Buckets are fixed-point (milli-tokens, millisecond clock) so the math is
 * deterministic across the FreeRTOS/host builds — no floating point. */
#ifndef DTN_BUDGET_H
#define DTN_BUDGET_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t tokens_m;   /* milli-tokens available */
    uint64_t burst_m;    /* milli-token capacity */
    uint64_t refill_num; /* refill numerator, milli-tokens */
    uint64_t refill_den; /* refill denominator, per millisecond */
    int64_t last_ms;     /* last refill timestamp */
} dtn_bucket;

/* refill_num/refill_den: milli-tokens per millisecond, e.g. request budget
 * (1 request per 2 s) = 1000 / 2000. */
void dtn_bucket_init(dtn_bucket *b, uint64_t burst, uint64_t refill_num,
                     uint64_t refill_den, int64_t now_ms);

/* Try to withdraw cost (in whole units, e.g. 1 request or n envelopes).
 * Returns true and consumes when available; returns false with *retry_after
 * (whole seconds, ≥ 1 — the §10.1 Retry-After contract) when not. The
 * failed attempt consumes nothing (atomic per batch, §10.1). */
bool dtn_bucket_allow(dtn_bucket *b, int64_t now_ms, uint64_t cost,
                      int64_t *retry_after_s);

/* Standard budgets from §10.1/§10.7. */
void dtn_budget_request(dtn_bucket *b, int64_t now_ms);
void dtn_budget_envelopes(dtn_bucket *b, int64_t now_ms);
void dtn_budget_diagnostics(dtn_bucket *b, int64_t now_ms);

#ifdef __cplusplus
}
#endif

#endif /* DTN_BUDGET_H */
