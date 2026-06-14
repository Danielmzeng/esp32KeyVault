#pragma once
#include <cstdbool>
#include <cstddef>
#include <cstdint>
#include "esp_err.h"
#include "vault_store.h"
#include "vault_crypto.h"   // VC_KEY_LEN etc. for member buffers

#define VAULT_MAX_ENTRIES     64
#define VAULT_FIELD_MAX       128
#define VAULT_CAT_NAME_MAX    32
#define VAULT_MAX_CATEGORIES  32

typedef struct {
    uint8_t  id;
    uint8_t  category_id;               /* 0 = Uncategorized */
    char     title[VAULT_FIELD_MAX];
    char     username[VAULT_FIELD_MAX];
    char     url[VAULT_FIELD_MAX];      /* only populated after reveal */
    char     secret[VAULT_FIELD_MAX];   /* only populated after reveal */
    char     comment[VAULT_FIELD_MAX];  /* only populated after reveal */
} vault_entry_t;

typedef struct {
    uint8_t  id;                        /* 1..255; 0 reserved for Uncategorized */
    char     name[VAULT_CAT_NAME_MAX];
} vault_category_t;

namespace vault {

class Vault {
public:
    explicit Vault(Store& store) : store_(store) {}
    ~Vault();   // frees PSRAM buffers

    void init();              // boot-time format check / auto-reset
    bool is_initialized();
    bool is_unlocked() const { return unlocked_; }
    bool is_busy() const { return deriving_; }

    void setup(const char* master, size_t master_len);   // throws InvalidState if already init
    bool unlock(const char* master, size_t master_len);  // false on wrong pw; throws InvalidState if not init
    void lock();
    bool change_password(const char* cur, size_t cur_len,
                         const char* next, size_t next_len);  // false on wrong current pw

    // CRUD — throw vault::Error(ESP_ERR_INVALID_STATE) if locked.
    size_t list(vault_entry_t* out, size_t cap);           // returns count
    bool   reveal(uint8_t id, char secret_out[VAULT_FIELD_MAX],
                  char url_out[VAULT_FIELD_MAX],
                  char comment_out[VAULT_FIELD_MAX]);        // false if id not found
    uint8_t add(const char* title, const char* username, const char* secret,
                const char* url, const char* comment, uint8_t category_id); // returns new id; throws on full
    bool   update(uint8_t id, const char* title, const char* username,
                  const char* secret, const char* url, const char* comment,
                  uint8_t category_id);                      // false if id not found
    bool   remove(uint8_t id);                               // false if id not found
    void   clear_entries();

    // Categories — throw InvalidState if locked.
    size_t  category_list(vault_category_t* out, size_t cap);
    uint8_t category_add(const char* name);   // returns id; throws Error(ESP_ERR_INVALID_STATE) on duplicate
    bool    category_delete(uint8_t id);       // false if not found; throws InvalidArg if id==0

    void set_transfer_password(const char* pw, size_t len);
    bool verify_transfer(const char* pw, size_t len);

    // Binary bundle export/import (used by tests). out_bundle is malloc'd; caller frees.
    bool export_bundle(const char* transfer_pw, size_t len, uint8_t** out_bundle, size_t* out_len); // false on wrong pw
    void bulk_begin();
    void bulk_commit();                        // throws InvalidState if locked
    bool import_bundle(const char* transfer_pw, size_t len,
                       const uint8_t* bundle, size_t bundle_len);  // false on wrong pw / bad format

    void factory_reset();

private:
    // ---- helpers (were file-local statics) ----
    bool   ensure_buffers();   // allocate PSRAM buffers; returns false on OOM
    size_t serialize_entries(uint8_t* plain);
    void   persist_entries();  // throws on store/crypto fault
    void   load_entries();
    void   persist_cats();
    void   load_cats();
    void   load_kek(const char* master, size_t mlen, uint8_t kek[VC_KEY_LEN]); // throws InvalidState if no salt
    vault_entry_t* find(uint8_t id);
    uint8_t alloc_id();
    uint8_t alloc_cat_id();
    bool    category_valid(uint8_t id);

    Store& store_;
    bool   unlocked_ = false;
    uint8_t dek_[VC_KEY_LEN] = {0};
    vault_entry_t*   entries_   = nullptr;   // VAULT_MAX_ENTRIES (PSRAM)
    uint8_t*         io_plain_  = nullptr;   // PLAIN_MAX (PSRAM)
    uint8_t*         io_blob_   = nullptr;   // BLOB_MAX (PSRAM)
    size_t           count_     = 0;
    bool             bulk_      = false;
    volatile bool    deriving_  = false;
    vault_category_t cats_[VAULT_MAX_CATEGORIES] = {};
    size_t           cat_count_ = 0;
};

}  // namespace vault
