/* test_docs.c — capabilities (§15.5) and health (§10.7) document shapes,
 * single-sourced identity members, N/A null convention, directory entries. */
#include "harness.h"

#include "dtn_docs.h"

#include <string.h>

void test_docs(void)
{
    char buf[4096];

    T_BEGIN("capabilities: exact §15.5 eight-member shape");
    long n = dtn_docs_capabilities(buf, sizeof(buf), "esp32-v1-test",
                                   1759500000, DTN_STORAGE_SCHEMA_VERSION);
    CHECK(n > 0);
    CHECK_STR(buf,
              "{\"api\":\"v1\",\"envelope_versions\":[1,2],"
              "\"min_envelope_version\":1,\"max_envelope_version\":2,"
              "\"schema_version\":4,\"build\":\"esp32-v1-test\","
              "\"hint_epoch_seconds\":86400,\"hint_epoch_current\":20364}");

    T_BEGIN("health: N/A convention — all-null snapshot, fixed member set");
    dtn_health_snapshot s;
    memset(&s, 0, sizeof(s));
    s.build = "esp32-v1-test";
    s.now = 1759500000;
    s.uptime_seconds = 1234;
    s.envelope_capacity = 5000;
    s.envelopes = 87;
    s.directory_entries = 12;
    s.db_size_bytes = -1; /* unknown → null */
    s.expiring_within_1h = 1;
    s.expiring_within_6h = 4;
    s.expiring_within_24h = 17;
    s.active_clients = 2;
    n = dtn_docs_health(buf, sizeof(buf), &s);
    CHECK(n > 0);

    /* identity members must equal capabilities' by construction */
    CHECK(strstr(buf, "\"api\":\"v1\"") != NULL);
    CHECK(strstr(buf, "\"build\":\"esp32-v1-test\"") != NULL);
    CHECK(strstr(buf, "\"envelope_versions\":[1,2]") != NULL);
    CHECK(strstr(buf, "\"schema_version\":4") != NULL);
    /* nulls for everything unmeasured */
    CHECK(strstr(buf, "\"battery\":null") != NULL);
    CHECK(strstr(buf, "\"counters_delta\":null") != NULL);
    CHECK(strstr(buf, "\"enough_data\":false") != NULL);
    CHECK(strstr(buf, "\"load1\":null") != NULL);
    CHECK(strstr(buf, "\"soc_temp_celsius\":null") != NULL);
    CHECK(strstr(buf, "\"db_size_bytes\":null") != NULL);
    /* fixed members present */
    CHECK(strstr(buf, "\"envelopes\":87") != NULL);
    CHECK(strstr(buf, "\"envelope_capacity\":5000") != NULL);
    CHECK(strstr(buf, "\"directory_entries\":12") != NULL);
    CHECK(strstr(buf, "\"expiring_within_1h\":1") != NULL);
    CHECK(strstr(buf, "\"active_clients\":2") != NULL);
    CHECK(strstr(buf, "\"software\":{\"schema_version_on_disk\":4,"
                      "\"pending_migration\":false}") != NULL);
    CHECK(strstr(buf, "\"pushes_rejected_by_class\":{\"invalid\":0,"
                      "\"rate_limited\":0,\"node_full\":0,"
                      "\"storage_unavailable\":0,\"too_large\":0}") != NULL);
    CHECK(strstr(buf, "\"store_equilibrium\":null") != NULL);

    T_BEGIN("health: counters and store deltas render when populated");
    s.pushes_accepted = 40;
    s.pushes_rejected = 5;
    s.rej_invalid = 2;
    s.rej_rate_limited = 1;
    s.rej_node_full = 1;
    s.rej_storage = 1;
    s.dedup_hits = 9;
    s.ttl_sweeps = 82;
    s.ttl_swept_envelopes = 31;
    s.have_counters_delta = true;
    s.delta_window_hours = 6.0;
    s.delta_pushes_accepted = 12;
    s.enough_data = true;
    s.pushes_per_day = DTN_OPT_NUM(48);
    s.store_equilibrium = DTN_OPT_STR("growing");
    n = dtn_docs_health(buf, sizeof(buf), &s);
    CHECK(n > 0);
    CHECK(strstr(buf, "\"pushes_accepted\":40") != NULL);
    CHECK(strstr(buf, "\"invalid\":2") != NULL);
    CHECK(strstr(buf, "\"dedup_hits\":9") != NULL);
    CHECK(strstr(buf, "\"counters_delta\":{\"window_hours\":6") != NULL);
    CHECK(strstr(buf, "\"pushes_per_day\":48") != NULL);
    CHECK(strstr(buf, "\"store_equilibrium\":\"growing\"") != NULL);
    CHECK(strstr(buf, "\"battery\":null") != NULL);

    T_BEGIN("directory entry: five members + verbatim prekeys");
    n = dtn_docs_dir_entry(buf, sizeof(buf), "alice_77",
                           "pk==", "xk==", 1759500000, 20364, NULL);
    CHECK(n > 0);
    CHECK_STR(buf, "{\"alias\":\"alice_77\",\"pubkey\":\"pk==\","
                   "\"x25519\":\"xk==\",\"last_seen\":1759500000,"
                   "\"epoch\":20364}");
    n = dtn_docs_dir_entry(buf, sizeof(buf), "alice_77", "pk==", "xk==",
                           1759500000, 20364, "{\"v\":1,\"spk\":\"z\"}");
    CHECK(strstr(buf, ",\"prekeys\":{\"v\":1,\"spk\":\"z\"}") != NULL);
}
