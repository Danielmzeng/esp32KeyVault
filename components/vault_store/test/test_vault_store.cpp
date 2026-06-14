#include "doctest/doctest.h"
#include "vault_store.h"
#include <cstring>

using namespace vault;

TEST_CASE("blob set/get round-trips through NVS") {
    Store store;
    const char* payload = "wrapped-dek-bytes";
    store.set_blob("t_dek", payload, strlen(payload));
    store.commit();

    char buf[64]; size_t len = sizeof buf;
    CHECK(store.get_blob("t_dek", buf, len));
    CHECK(len == strlen(payload));
    CHECK(memcmp(payload, buf, len) == 0);

    store.erase_key("t_dek");
    store.commit();
    len = sizeof buf;
    CHECK_FALSE(store.get_blob("t_dek", buf, len));   // absent now
}
