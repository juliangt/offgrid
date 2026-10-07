/* dtn_core.c — phase 0 seed: identity only. The protocol machinery lands in
 * phases 1–2 (see docs/esp32-design.md §8); this file keeps the component
 * valid for the CI firmware build gate from day one. */
#include "dtn_core.h"

const char *dtn_core_version(void)
{
    return DTN_BUILD_STRING;
}
