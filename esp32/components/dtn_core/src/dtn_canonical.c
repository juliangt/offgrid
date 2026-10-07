/* dtn_canonical.c — §10.2 logic. Byte-parity with node/internal/api/middleware.go:
 * the Host comparison is EqualFold over the WHOLE host header (host:port),
 * the probe set is path-keyed, and redirects preserve path+query. */
#include "dtn_canonical.h"
#include "dtn_core.h"

#include <string.h>

static char fold(char c)
{
    if (c >= 'A' && c <= 'Z') return (char)(c - 'A' + 'a');
    return c;
}

static bool host_equal_fold(const char *a, const char *b)
{
    if (a == NULL || b == NULL) return false;
    while (*a && *b) {
        if (fold(*a) != fold(*b)) return false;
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

bool dtn_is_captive_probe(const char *path)
{
    return strcmp(path, "/generate_204") == 0 ||
           strcmp(path, "/hotspot-detect.html") == 0;
}

static long build_location(char *out, size_t cap, const char *path_query)
{
    size_t n = strlen(DTN_CANONICAL_ORIGIN);
    size_t q = path_query ? strlen(path_query) : 0;
    if (n + q + 1 > cap) return -1;
    memcpy(out, DTN_CANONICAL_ORIGIN, n);
    if (q) memcpy(out + n, path_query, q);
    out[n + q] = '\0';
    return (long)(n + q);
}

long dtn_canonical_location(char *out, size_t cap, const char *path_query)
{
    return build_location(out, cap, path_query);
}

long dtn_probe_location(char *out, size_t cap)
{
    return build_location(out, cap, "/");
}

dtn_canon_verdict dtn_canonical_check(const char *path, const char *host)
{
    if (dtn_is_captive_probe(path)) {
        return DTN_CANON_PROBE;
    }
    if (host_equal_fold(host, DTN_CANONICAL_HOST)) {
        return DTN_CANON_PASS;
    }
    return DTN_CANON_REDIRECT;
}
