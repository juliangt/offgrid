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
void test_nodeid(void);
void test_bundle(void);
void test_link(void);    /* P3.3 node-plane link layer (issue #33) */
void test_mac(void);     /* P3.3 node-plane MAC v1 (issue #33) */
void test_forward(void); /* P3.5 forwarding engine (issue #33) */

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
    test_nodeid();
    test_bundle();
    printf("dtn_core host tests — issue #33 P3.3 (node plane)\n");
    test_link();
    test_mac();
    test_forward();
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
