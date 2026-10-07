/* dtn_budget.c — token-bucket arithmetic. See dtn_budget.h. */
#include "dtn_budget.h"

#include "dtn_limits.h"

#define MILLI 1000ULL

void dtn_bucket_init(dtn_bucket *b, uint64_t burst, uint64_t refill_num,
                     uint64_t refill_den, int64_t now_ms)
{
    b->burst_m = burst * MILLI;
    b->tokens_m = burst * MILLI;
    b->refill_num = refill_num;
    b->refill_den = refill_den;
    b->last_ms = now_ms;
}

void dtn_budget_request(dtn_bucket *b, int64_t now_ms)
{
    /* burst 60, refill 1 request per 2 s (§10.1) */
    dtn_bucket_init(b, DTN_BUDGET_REQUEST_BURST, MILLI, 2ULL * MILLI, now_ms);
}

void dtn_budget_envelopes(dtn_bucket *b, int64_t now_ms)
{
    /* burst 600, refill 600 envelopes per hour (§10.1) */
    dtn_bucket_init(b, DTN_BUDGET_ENVELOPE_BURST, 600ULL * MILLI,
                    3600ULL * MILLI, now_ms);
}

void dtn_budget_diagnostics(dtn_bucket *b, int64_t now_ms)
{
    /* burst 60, refill 1 request per second (§10.7) */
    dtn_bucket_init(b, DTN_BUDGET_DIAG_BURST, MILLI, MILLI, now_ms);
}

static void refill(dtn_bucket *b, int64_t now_ms)
{
    if (now_ms > b->last_ms) {
        uint64_t dt = (uint64_t)(now_ms - b->last_ms);
        uint64_t gain = b->tokens_m; /* clamp point */
        if (b->refill_den > 0) {
            /* milli-tokens gained = dt * refill_num / refill_den */
            uint64_t add_hi = dt / b->refill_den;
            uint64_t add_rem = dt % b->refill_den;
            gain = add_hi * b->refill_num +
                   (add_rem * b->refill_num) / b->refill_den;
        } else {
            gain = 0;
        }
        b->tokens_m += gain;
        if (b->tokens_m > b->burst_m) {
            b->tokens_m = b->burst_m;
        }
    }
    b->last_ms = now_ms > b->last_ms ? now_ms : b->last_ms;
}

bool dtn_bucket_allow(dtn_bucket *b, int64_t now_ms, uint64_t cost,
                      int64_t *retry_after_s)
{
    uint64_t need = cost * MILLI;
    refill(b, now_ms);
    if (b->tokens_m >= need) {
        b->tokens_m -= need;
        return true;
    }
    if (retry_after_s) {
        /* whole seconds until the full cost fits, minimum 1 (§10.1):
         * ms = ceil(deficit_m * refill_den / refill_num) — fixed point keeps
         * sub-milli-token rates (1 request per 2 s) exact */
        uint64_t deficit_m = need - b->tokens_m;
        uint64_t ms;
        if (b->refill_num == 0) {
            ms = 1000;
        } else {
            ms = (deficit_m * b->refill_den + b->refill_num - 1) /
                 b->refill_num;
        }
        *retry_after_s = (int64_t)(ms / MILLI);
        if (ms % MILLI) (*retry_after_s)++;
        if (*retry_after_s < 1) *retry_after_s = 1;
    }
    return false;
}
