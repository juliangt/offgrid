/* harness.h — minimal test harness for the dtn_core host suite. */
#ifndef DTN_TEST_HARNESS_H
#define DTN_TEST_HARNESS_H

#include <stdio.h>
#include <string.h>

extern int t_total;
extern int t_failed;
extern const char *t_current;

#define T_BEGIN(name)                        \
    do {                                     \
        t_current = name;                    \
        printf("  - %s\n", name);            \
    } while (0)

#define CHECK(cond)                                                     \
    do {                                                                \
        t_total++;                                                      \
        if (!(cond)) {                                                  \
            t_failed++;                                                 \
            printf("    FAIL %s:%d  %s  (in %s)\n", __FILE__, __LINE__, \
                   #cond, t_current);                                   \
        }                                                               \
    } while (0)

#define CHECK_EQ_INT(a, b)                                              \
    do {                                                                \
        long long va_ = (long long)(a), vb_ = (long long)(b);           \
        t_total++;                                                      \
        if (va_ != vb_) {                                               \
            printf("    FAIL %s:%d  %s == %s  (%lld != %lld)  (in %s)\n",\
                   __FILE__, __LINE__, #a, #b, va_, vb_, t_current);    \
            t_failed++;                                                 \
        }                                                               \
    } while (0)

#define CHECK_STR(a, b)                                                 \
    do {                                                                \
        const char *sa_ = (a), *sb_ = (b);                              \
        t_total++;                                                      \
        if (!sa_ || !sb_ || strcmp(sa_, sb_) != 0) {                    \
            printf("    FAIL %s:%d  strings differ  (in %s)\n"          \
                   "      got:  %s\n      want: %s\n",                  \
                   __FILE__, __LINE__, t_current,                       \
                   sa_ ? sa_ : "(null)", sb_ ? sb_ : "(null)");         \
            t_failed++;                                                 \
        }                                                               \
    } while (0)

int t_summary(void);

#endif /* DTN_TEST_HARNESS_H */
