/* test_budget.c — the §10.1/§10.7 token budgets (issue #16/#31). */
#include "harness.h"

#include "dtn_budget.h"

void test_budget(void)
{
    T_BEGIN("budget: request bucket — burst 60, refill 1 per 2 s");
    dtn_bucket b;
    int64_t t = 1000;
    dtn_budget_request(&b, t);
    for (int i = 0; i < 60; i++) {
        if (!dtn_bucket_allow(&b, t, 1, NULL)) {
            CHECK(false); /* burst must hold exactly 60 */
            break;
        }
    }
    int64_t retry = 0;
    CHECK(!dtn_bucket_allow(&b, t, 1, &retry)); /* the 61st refuses */
    CHECK(retry >= 1);                          /* Retry-After ≥ 1 s (§10.1) */
    CHECK(!dtn_bucket_allow(&b, t + 1000, 1, NULL)); /* 1 s: still empty */
    CHECK(dtn_bucket_allow(&b, t + 2000, 1, NULL));  /* 2 s: one refill */

    T_BEGIN("budget: failed attempt consumes nothing (atomic per batch)");
    /* two more seconds pass: one fresh token (the previous block consumed
     * the t+2000 refill) */
    CHECK(!dtn_bucket_allow(&b, t + 4000, 10, NULL)); /* needs 10, has 1 */
    CHECK(dtn_bucket_allow(&b, t + 4000, 1, NULL));   /* the 1 token remains */

    T_BEGIN("budget: envelope bucket — burst 600, refill 600/h, batch cost");
    dtn_bucket e;
    dtn_budget_envelopes(&e, 0);
    CHECK(dtn_bucket_allow(&e, 0, 600, NULL)); /* a full burst batch */
    CHECK(!dtn_bucket_allow(&e, 0, 1, NULL));
    /* after one hour: 600 refilled */
    CHECK(dtn_bucket_allow(&e, 3600 * 1000, 600, NULL));
    /* pull-only syncs cost nothing: allow(0) always succeeds */
    CHECK(dtn_bucket_allow(&e, 0, 0, NULL));

    T_BEGIN("budget: diagnostics bucket — burst 60, refill 1/s, shared");
    dtn_bucket d;
    dtn_budget_diagnostics(&d, 0);
    for (int i = 0; i < 60; i++) {
        if (!dtn_bucket_allow(&d, 0, 1, NULL)) {
            CHECK(false);
            break;
        }
    }
    CHECK(!dtn_bucket_allow(&d, 500, 1, NULL));
    CHECK(dtn_bucket_allow(&d, 1000, 1, NULL));
    CHECK(dtn_bucket_allow(&d, 1000, 1, NULL) == false); /* 1 s: only one */

    T_BEGIN("budget: retry-after rounding is ≥ 1 s and in whole seconds");
    dtn_bucket r;
    dtn_budget_request(&r, 0);
    int64_t wait = 0;
    for (int i = 0; i < 60; i++) dtn_bucket_allow(&r, 0, 1, NULL);
    CHECK(!dtn_bucket_allow(&r, 0, 1, &wait));
    CHECK_EQ_INT(wait, 2); /* 1 request per 2 s → the next token in 2 s */
}
