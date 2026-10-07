/* main.c — dtn_core host test suite runner (issue #39 phase 1).
 * Everything here runs on the CI host: the §15.7-adapted conformance
 * assertions and the shared fixture vectors of docs/protocol.md. */
#include "harness.h"

int t_total = 0;
int t_failed = 0;
const char *t_current = "(init)";

void test_json(void);
void test_envelope(void);
void test_sync(void);
void test_canonical(void);
void test_budget(void);
void test_docs(void);
void test_store(void);

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0); /* progress survives a hang/crash */
    printf("dtn_core host tests — issue #39\n");
    test_json();
    test_envelope();
    test_sync();
    test_canonical();
    test_budget();
    test_docs();
    test_store();
    return t_summary();
}

int t_summary(void)
{
    printf("\n%d checks, %d failures\n", t_total, t_failed);
    if (t_failed) {
        printf("dtn_core: HOST TESTS FAILED\n");
        return 1;
    }
    printf("dtn_core: host tests OK\n");
    return 0;
}
