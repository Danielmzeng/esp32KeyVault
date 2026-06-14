#include "doctest/doctest.h"
#include "vault.h"
#include "vault_store.h"
#include <cstring>
#include <cstdlib>

using namespace vault;

// Each case builds its own Store + Vault and wipes the namespace first.
static void fresh(Store& store) {
    for (const char* k : {"salt","wdek","entries","iter","tsalt","tverif","vfmt","cats"})
        store.erase_key(k);
    store.commit();
}

TEST_CASE("setup then unlock with correct/incorrect password") {
    Store store; fresh(store);
    Vault v(store);
    CHECK_FALSE(v.is_initialized());
    v.setup("correct horse", 13);
    CHECK(v.is_initialized());
    CHECK(v.is_unlocked());

    v.lock();
    CHECK_FALSE(v.is_unlocked());
    CHECK_FALSE(v.unlock("wrong", 5));
    CHECK_FALSE(v.is_unlocked());
    CHECK(v.unlock("correct horse", 13));
    CHECK(v.is_unlocked());
}

TEST_CASE("add, list, reveal, update, delete round-trip across re-unlock") {
    Store store; fresh(store);
    Vault v(store);
    v.setup("pw", 2);
    uint8_t id = v.add("GitHub", "dan", "tok123", "https://gh", "note", 0);

    v.lock();
    CHECK(v.unlock("pw", 2));

    vault_entry_t list[VAULT_MAX_ENTRIES];
    size_t n = v.list(list, VAULT_MAX_ENTRIES);
    CHECK(n == 1);
    CHECK(strcmp(list[0].title, "GitHub") == 0);
    CHECK(strcmp(list[0].secret, "") == 0);   // not revealed in list

    char secret[VAULT_FIELD_MAX], url[VAULT_FIELD_MAX], comment[VAULT_FIELD_MAX];
    CHECK(v.reveal(id, secret, url, comment));
    CHECK(strcmp(secret, "tok123") == 0);

    CHECK(v.update(id, "GitHub", "dan", "tok999", "https://gh", "note", 0));
    CHECK(v.reveal(id, secret, url, comment));
    CHECK(strcmp(secret, "tok999") == 0);

    CHECK(v.remove(id));
    n = v.list(list, VAULT_MAX_ENTRIES);
    CHECK(n == 0);
}

TEST_CASE("CRUD blocked while locked") {
    Store store; fresh(store);
    Vault v(store);
    v.setup("pw", 2);
    v.lock();
    CHECK_THROWS_AS(v.add("x", "y", "z", "", "", 0), vault::Error);
}

TEST_CASE("change password keeps entries, invalidates old password") {
    Store store; fresh(store);
    Vault v(store);
    v.setup("old", 3);
    uint8_t id = v.add("S", "u", "sec", "", "", 0);

    CHECK_FALSE(v.change_password("bad", 3, "new", 3));
    CHECK(v.change_password("old", 3, "new", 3));

    v.lock();
    CHECK_FALSE(v.unlock("old", 3));
    CHECK(v.unlock("new", 3));
    char secret[VAULT_FIELD_MAX], url[VAULT_FIELD_MAX], comment[VAULT_FIELD_MAX];
    CHECK(v.reveal(id, secret, url, comment));
    CHECK(strcmp(secret, "sec") == 0);
}

TEST_CASE("transfer password verifies correctly") {
    Store store; fresh(store);
    Vault v(store);
    v.setup("master", 6);
    v.set_transfer_password("xfer", 4);
    CHECK(v.verify_transfer("xfer", 4));
    CHECK_FALSE(v.verify_transfer("nope", 4));
}

TEST_CASE("export/import round-trips; wrong transfer password rejected") {
    Store store; fresh(store);
    Vault v(store);
    v.setup("master", 6);
    v.set_transfer_password("xfer", 4);
    uint8_t id = v.add("GitHub", "dan", "tok", "", "", 0);

    uint8_t* bundle = nullptr; size_t blen = 0;
    CHECK(v.export_bundle("xfer", 4, &bundle, &blen));
    REQUIRE(bundle != nullptr);
    uint8_t* dummy = nullptr; size_t dlen = 0;
    CHECK_FALSE(v.export_bundle("bad", 3, &dummy, &dlen));   // wrong pw

    CHECK(v.remove(id));
    vault_entry_t list[VAULT_MAX_ENTRIES];
    CHECK(v.list(list, VAULT_MAX_ENTRIES) == 0);

    CHECK_FALSE(v.import_bundle("wrong", 5, bundle, blen));
    CHECK(v.import_bundle("xfer", 4, bundle, blen));
    CHECK(v.list(list, VAULT_MAX_ENTRIES) == 1);
    CHECK(strcmp(list[0].title, "GitHub") == 0);
    char sec[VAULT_FIELD_MAX], url[VAULT_FIELD_MAX], comment[VAULT_FIELD_MAX];
    CHECK(v.reveal(list[0].id, sec, url, comment));
    CHECK(strcmp(sec, "tok") == 0);
    free(bundle);
}

TEST_CASE("import merges by title+username (no duplicate)") {
    Store store; fresh(store);
    Vault v(store);
    v.setup("master", 6);
    v.set_transfer_password("x", 1);
    uint8_t id = v.add("Site", "u", "old", "", "", 0);

    uint8_t* bundle = nullptr; size_t blen = 0;
    CHECK(v.export_bundle("x", 1, &bundle, &blen));
    CHECK(v.update(id, "Site", "u", "new", "", "", 0));
    CHECK(v.import_bundle("x", 1, bundle, blen));   // old replaces new

    vault_entry_t list[VAULT_MAX_ENTRIES];
    CHECK(v.list(list, VAULT_MAX_ENTRIES) == 1);    // merged, not duplicated
    char sec[VAULT_FIELD_MAX], url[VAULT_FIELD_MAX], comment[VAULT_FIELD_MAX];
    v.reveal(list[0].id, sec, url, comment);
    CHECK(strcmp(sec, "old") == 0);
    free(bundle);
}
