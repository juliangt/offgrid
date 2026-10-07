/* test_canonical.c — §10.2 canonical-host decisions, pinned to the matrix of
 * node/internal/api/api_test.go. */
#include "harness.h"

#include "dtn_canonical.h"

#include <string.h>

void test_canonical(void)
{
    char loc[128];

    T_BEGIN("canonical: host matrix (§10.2 / Go api_test)");
    CHECK_EQ_INT(dtn_canonical_check("/", "10.42.0.1:8080"),
                 DTN_CANON_REDIRECT);
    CHECK_EQ_INT(dtn_canonical_location(loc, sizeof(loc), "/"), 26);
    CHECK_STR(loc, "http://offgrid.local:8080/");

    CHECK_EQ_INT(dtn_canonical_check("/foo?bar=1", "evil.example.com"),
                 DTN_CANON_REDIRECT);
    dtn_canonical_location(loc, sizeof(loc), "/foo?bar=1");
    CHECK_STR(loc, "http://offgrid.local:8080/foo?bar=1");

    CHECK_EQ_INT(dtn_canonical_check("/", "offgrid.local"), DTN_CANON_REDIRECT);
    CHECK_EQ_INT(dtn_canonical_check("/", "OFFGRID.LOCAL:8080"),
                 DTN_CANON_PASS); /* case-insensitive whole header */
    CHECK_EQ_INT(dtn_canonical_check("/", "offgrid.local:8080"),
                 DTN_CANON_PASS);
    CHECK_EQ_INT(dtn_canonical_check("/", NULL), DTN_CANON_REDIRECT);
    CHECK_EQ_INT(dtn_canonical_check("/", ""), DTN_CANON_REDIRECT);

    T_BEGIN("canonical: probes exempt from the redirect on ANY host");
    CHECK_EQ_INT(dtn_canonical_check("/generate_204",
                                     "connectivitycheck.gstatic.com"),
                 DTN_CANON_PROBE);
    CHECK_EQ_INT(dtn_canonical_check("/hotspot-detect.html",
                                     "captive.apple.com"),
                 DTN_CANON_PROBE);
    CHECK_EQ_INT(dtn_canonical_check("/generate_204", "offgrid.local:8080"),
                 DTN_CANON_PROBE); /* path-keyed, method/host-agnostic */
    CHECK_EQ_INT(dtn_canonical_check("/generate_204/x", "x"), DTN_CANON_REDIRECT);
    CHECK_EQ_INT(dtn_canonical_check("/generate_205", "x"), DTN_CANON_REDIRECT);

    T_BEGIN("canonical: probe location is always the canonical root");
    dtn_probe_location(loc, sizeof(loc));
    CHECK_STR(loc, "http://offgrid.local:8080/");

    T_BEGIN("canonical: §12.1/§10.3 paths redirect onto the canonical origin");
    CHECK_EQ_INT(dtn_canonical_check("/manifest.json", "10.42.0.1:8080"),
                 DTN_CANON_REDIRECT);
    dtn_canonical_location(loc, sizeof(loc), "/icons/icon-192.png");
    CHECK_STR(loc, "http://offgrid.local:8080/icons/icon-192.png");
}
