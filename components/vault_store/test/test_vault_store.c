#include "unity.h"
#include "vault_store.h"
#include "nvs.h"
#include <string.h>

TEST_CASE("blob set/get round-trips through NVS", "[vault_store]")
{
    TEST_ASSERT_EQUAL(ESP_OK, vs_init());
    const char *payload = "wrapped-dek-bytes";
    TEST_ASSERT_EQUAL(ESP_OK, vs_set_blob("t_dek", payload, strlen(payload)));
    TEST_ASSERT_EQUAL(ESP_OK, vs_commit());

    char buf[64]; size_t len = sizeof buf;
    TEST_ASSERT_EQUAL(ESP_OK, vs_get_blob("t_dek", buf, &len));
    TEST_ASSERT_EQUAL(strlen(payload), len);
    TEST_ASSERT_EQUAL_MEMORY(payload, buf, len);

    TEST_ASSERT_EQUAL(ESP_OK, vs_erase_key("t_dek"));
    TEST_ASSERT_EQUAL(ESP_OK, vs_commit());
    len = sizeof buf;
    TEST_ASSERT_EQUAL(ESP_ERR_NVS_NOT_FOUND, vs_get_blob("t_dek", buf, &len));
}
