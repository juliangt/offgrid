# app entry (docs/esp32-design.md §3): netif reconfigured to 10.42.0.1,
# softAP "offgrid-messages" with the built-in DHCP server (node as gateway +
# DNS) and the wildcard dns_server; the SPA is embedded from node/web and
# served verbatim — single-sourced with the Pi build, never copied.
idf_component_register(
    SRCS "main.c" "${CMAKE_CURRENT_BINARY_DIR}/web_assets.c"
    INCLUDE_DIRS "." "${CMAKE_CURRENT_BINARY_DIR}"
    REQUIRES dtn_core dtn_node nvs_flash
)

set(WEB_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../node/web")
file(GLOB_RECURSE WEB_FILES "${WEB_ROOT}/*")

set(ASSET_DECLS "")
set(ASSET_ROWS "")
foreach(f ${WEB_FILES})
    file(RELATIVE_PATH rel "${WEB_ROOT}" "${f}")
    string(REPLACE "/" "_" sym "web_${rel}")
    string(REGEX REPLACE "[^A-Za-z0-9_]" "_" sym "${sym}")
    target_add_binary_data(${COMPONENT_LIB} "${f}" "${sym}")
    string(APPEND ASSET_DECLS
        "extern const uint8_t _binary_${sym}_start[];\n"
        "extern const uint8_t _binary_${sym}_end[];\n")
    if(rel MATCHES "\\.css$")
        set(ct "text/css")
    elseif(rel MATCHES "\\.m?js$")
        set(ct "text/javascript")
    elseif(rel MATCHES "manifest\\.json$")
        set(ct "application/manifest+json")
    elseif(rel MATCHES "\\.png$")
        set(ct "image/png")
    elseif(rel MATCHES "\\.html?$")
        set(ct "text/html; charset=utf-8")
    else()
        set(ct "application/octet-stream")
    endif()
    string(APPEND ASSET_ROWS
        "    { \"/${rel}\", \"${ct}\", _binary_${sym}_start, (unsigned)(_binary_${sym}_end - _binary_${sym}_start) },\n")
endforeach()

file(GENERATE OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/web_assets.c" CONTENT
"/* GENERATED from node/web at build time — do not edit (issue #39).
 * The SPA is embedded VERBATIM and served byte-identical to the Pi build
 * (§10.3 exact-path static surface, closed content-type allow-list). */
#include \"dtn_node.h\"
#include <stddef.h>
${ASSET_DECLS}
static const dtn_web_asset ASSETS[] = {
${ASSET_ROWS}};
const dtn_web_asset *dtn_web_assets(int *count)
{
    *count = (int)(sizeof(ASSETS) / sizeof(ASSETS[0]));
    return ASSETS;
}
")
