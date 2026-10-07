/* dtn_canonical.h — the §10.2 canonical-host middleware logic and the
 * captive-probe exemption. Pure HTTP decision logic, no socket code. */
#ifndef DTN_CANONICAL_H
#define DTN_CANONICAL_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    DTN_CANON_PASS = 0,  /* Host is canonical (case-insensitive) */
    DTN_CANON_PROBE,     /* captive-probe path: answer 302 on ANY host */
    DTN_CANON_REDIRECT,  /* 301 to the canonical origin, path+query kept */
} dtn_canon_verdict;

/* Decide §10.2 for one request. host may be NULL/empty (HTTP/1.0). The probe
 * exemption is path-keyed and method-agnostic, exactly like the Go mux. */
dtn_canon_verdict dtn_canonical_check(const char *path, const char *host);

/* Build the §10.2 redirect target: "http://offgrid.local:8080" + path_query.
 * Returns bytes written or -1 on out-cap. */
long dtn_canonical_location(char *out, size_t cap, const char *path_query);

/* The two §10.2 probe paths (never 204; always 302 to the canonical root). */
bool dtn_is_captive_probe(const char *path);
/* Build the probe Location (always the canonical root). Same return rules. */
long dtn_probe_location(char *out, size_t cap);

#ifdef __cplusplus
}
#endif

#endif /* DTN_CANONICAL_H */
