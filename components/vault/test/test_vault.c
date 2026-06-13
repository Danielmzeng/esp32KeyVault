#include "unity.h"
#include "vault.h"
#include "vault_store.h"
#include <string.h>
#include <stdlib.h>

static void fresh(void)
{
    TEST_ASSERT_EQUAL(ESP_OK, vs_init());
    vs_erase_key("salt"); vs_erase_key("wdek"); vs_erase_key("entries");
    vs_erase_key("iter"); vs_erase_key("tsalt"); vs_erase_key("tverif");
    vs_commit();
    vault_lock();
}

TEST_CASE("setup then unlock with correct/incorrect password", "[vault]")
{
    fresh();
    TEST_ASSERT_FALSE(vault_is_initialized());
    TEST_ASSERT_EQUAL(ESP_OK, vault_setup("correct horse", 13));
    TEST_ASSERT_TRUE(vault_is_initialized());
    TEST_ASSERT_TRUE(vault_is_unlocked());

    vault_lock();
    TEST_ASSERT_FALSE(vault_is_unlocked());
    TEST_ASSERT_NOT_EQUAL(ESP_OK, vault_unlock("wrong", 5));
    TEST_ASSERT_FALSE(vault_is_unlocked());
    TEST_ASSERT_EQUAL(ESP_OK, vault_unlock("correct horse", 13));
    TEST_ASSERT_TRUE(vault_is_unlocked());
}

TEST_CASE("add, list, reveal, update, delete round-trip across re-unlock", "[vault]")
{
    fresh();
    TEST_ASSERT_EQUAL(ESP_OK, vault_setup("pw", 2));
    uint8_t id;
    TEST_ASSERT_EQUAL(ESP_OK, vault_add("GitHub", "dan", "tok123", &id));

    vault_lock();
    TEST_ASSERT_EQUAL(ESP_OK, vault_unlock("pw", 2));

    vault_entry_t list[VAULT_MAX_ENTRIES]; size_t n = 0;
    TEST_ASSERT_EQUAL(ESP_OK, vault_list(list, VAULT_MAX_ENTRIES, &n));
    TEST_ASSERT_EQUAL(1, n);
    TEST_ASSERT_EQUAL_STRING("GitHub", list[0].title);
    TEST_ASSERT_EQUAL_STRING("", list[0].secret);   /* not revealed in list */

    char secret[VAULT_FIELD_MAX];
    TEST_ASSERT_EQUAL(ESP_OK, vault_reveal(id, secret));
    TEST_ASSERT_EQUAL_STRING("tok123", secret);

    TEST_ASSERT_EQUAL(ESP_OK, vault_update(id, "GitHub", "dan", "tok999"));
    TEST_ASSERT_EQUAL(ESP_OK, vault_reveal(id, secret));
    TEST_ASSERT_EQUAL_STRING("tok999", secret);

    TEST_ASSERT_EQUAL(ESP_OK, vault_delete(id));
    TEST_ASSERT_EQUAL(ESP_OK, vault_list(list, VAULT_MAX_ENTRIES, &n));
    TEST_ASSERT_EQUAL(0, n);
}

TEST_CASE("CRUD blocked while locked", "[vault]")
{
    fresh();
    TEST_ASSERT_EQUAL(ESP_OK, vault_setup("pw", 2));
    vault_lock();
    uint8_t id;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_STATE, vault_add("x","y","z",&id));
}

TEST_CASE("change password keeps entries, invalidates old password", "[vault]")
{
    fresh();
    TEST_ASSERT_EQUAL(ESP_OK, vault_setup("old", 3));
    uint8_t id; TEST_ASSERT_EQUAL(ESP_OK, vault_add("S","u","sec",&id));

    TEST_ASSERT_NOT_EQUAL(ESP_OK, vault_change_password("bad", 3, "new", 3));
    TEST_ASSERT_EQUAL(ESP_OK, vault_change_password("old", 3, "new", 3));

    vault_lock();
    TEST_ASSERT_NOT_EQUAL(ESP_OK, vault_unlock("old", 3));
    TEST_ASSERT_EQUAL(ESP_OK, vault_unlock("new", 3));
    char secret[VAULT_FIELD_MAX];
    TEST_ASSERT_EQUAL(ESP_OK, vault_reveal(id, secret));
    TEST_ASSERT_EQUAL_STRING("sec", secret);
}

TEST_CASE("transfer password verifies correctly", "[vault]")
{
    fresh();
    TEST_ASSERT_EQUAL(ESP_OK, vault_setup("master", 6));
    TEST_ASSERT_EQUAL(ESP_OK, vault_set_transfer_password("xfer", 4));
    TEST_ASSERT_TRUE(vault_verify_transfer("xfer", 4));
    TEST_ASSERT_FALSE(vault_verify_transfer("nope", 4));
}

TEST_CASE("export/import round-trips; wrong transfer password rejected", "[vault]")
{
    fresh();
    TEST_ASSERT_EQUAL(ESP_OK, vault_setup("master", 6));
    TEST_ASSERT_EQUAL(ESP_OK, vault_set_transfer_password("xfer", 4));
    uint8_t id; TEST_ASSERT_EQUAL(ESP_OK, vault_add("GitHub", "dan", "tok", &id));

    uint8_t *bundle = NULL; size_t blen = 0;
    TEST_ASSERT_EQUAL(ESP_OK, vault_export("xfer", 4, &bundle, &blen));
    TEST_ASSERT_NOT_NULL(bundle);
    TEST_ASSERT_NOT_EQUAL(ESP_OK, vault_export("bad", 3, &bundle, &blen)); /* wrong pw */

    /* Simulate an empty target device by deleting the entry. */
    TEST_ASSERT_EQUAL(ESP_OK, vault_delete(id));
    vault_entry_t list[VAULT_MAX_ENTRIES]; size_t n = 0;
    vault_list(list, VAULT_MAX_ENTRIES, &n); TEST_ASSERT_EQUAL(0, n);

    TEST_ASSERT_NOT_EQUAL(ESP_OK, vault_import("wrong", 5, bundle, blen));
    TEST_ASSERT_EQUAL(ESP_OK, vault_import("xfer", 4, bundle, blen));
    vault_list(list, VAULT_MAX_ENTRIES, &n); TEST_ASSERT_EQUAL(1, n);
    TEST_ASSERT_EQUAL_STRING("GitHub", list[0].title);
    char sec[VAULT_FIELD_MAX];
    TEST_ASSERT_EQUAL(ESP_OK, vault_reveal(list[0].id, sec));
    TEST_ASSERT_EQUAL_STRING("tok", sec);
    free(bundle);
}

TEST_CASE("import merges by title+username (no duplicate)", "[vault]")
{
    fresh();
    TEST_ASSERT_EQUAL(ESP_OK, vault_setup("master", 6));
    TEST_ASSERT_EQUAL(ESP_OK, vault_set_transfer_password("x", 1));
    uint8_t id; TEST_ASSERT_EQUAL(ESP_OK, vault_add("Site", "u", "old", &id));

    uint8_t *bundle = NULL; size_t blen = 0;
    TEST_ASSERT_EQUAL(ESP_OK, vault_export("x", 1, &bundle, &blen));
    TEST_ASSERT_EQUAL(ESP_OK, vault_update(id, "Site", "u", "new"));
    TEST_ASSERT_EQUAL(ESP_OK, vault_import("x", 1, bundle, blen)); /* old replaces new */

    vault_entry_t list[VAULT_MAX_ENTRIES]; size_t n = 0;
    vault_list(list, VAULT_MAX_ENTRIES, &n);
    TEST_ASSERT_EQUAL(1, n);                       /* merged, not duplicated */
    char sec[VAULT_FIELD_MAX];
    vault_reveal(list[0].id, sec);
    TEST_ASSERT_EQUAL_STRING("old", sec);
    free(bundle);
}
