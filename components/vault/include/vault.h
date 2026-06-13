#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

#define VAULT_MAX_ENTRIES     64
#define VAULT_FIELD_MAX       128
#define VAULT_CAT_NAME_MAX    32
#define VAULT_MAX_CATEGORIES  32

typedef struct {
    uint8_t  id;
    uint8_t  category_id;               /* 0 = Uncategorized */
    char     title[VAULT_FIELD_MAX];
    char     username[VAULT_FIELD_MAX];
    char     url[VAULT_FIELD_MAX];      /* only populated after vault_reveal */
    char     secret[VAULT_FIELD_MAX];   /* only populated after vault_reveal */
    char     comment[VAULT_FIELD_MAX];  /* only populated after vault_reveal */
} vault_entry_t;

typedef struct {
    uint8_t  id;                        /* 1..255; 0 reserved for Uncategorized */
    char     name[VAULT_CAT_NAME_MAX];
} vault_category_t;

/* Call once at boot after vs_init: if a vault exists but predates the current
 * on-disk format, factory-reset it so the device comes up clean. */
esp_err_t vault_init(void);

bool      vault_is_initialized(void);   /* has setup ever run? */
bool      vault_is_unlocked(void);
bool      vault_is_busy(void);          /* a slow PBKDF2 derivation (unlock) is in progress */

esp_err_t vault_setup(const char *master, size_t master_len);   /* first run */
esp_err_t vault_unlock(const char *master, size_t master_len);  /* ESP_ERR_INVALID_STATE if not init; ESP_FAIL if wrong pw */
void      vault_lock(void);                                     /* wipes DEK from RAM */
esp_err_t vault_change_password(const char *cur, size_t cur_len,
                                const char *next, size_t next_len);

/* CRUD — require unlocked vault, else ESP_ERR_INVALID_STATE.
 * vault_list fills id/category_id/title/username; url/secret/comment are left
 * empty (the hidden fields are only returned by vault_reveal). */
esp_err_t vault_list(vault_entry_t *out, size_t cap, size_t *count);
esp_err_t vault_reveal(uint8_t id, char secret_out[VAULT_FIELD_MAX],
                       char url_out[VAULT_FIELD_MAX],
                       char comment_out[VAULT_FIELD_MAX]);
esp_err_t vault_add(const char *title, const char *username, const char *secret,
                    const char *url, const char *comment, uint8_t category_id,
                    uint8_t *out_id);
esp_err_t vault_update(uint8_t id, const char *title, const char *username,
                       const char *secret, const char *url, const char *comment,
                       uint8_t category_id);
esp_err_t vault_delete(uint8_t id);

/* Categories — require unlocked vault. The built-in "Uncategorized" (id 0) is
 * implicit and not returned by vault_category_list. */
esp_err_t vault_category_list(vault_category_t *out, size_t cap, size_t *count);
esp_err_t vault_category_add(const char *name, uint8_t *out_id);
esp_err_t vault_category_delete(uint8_t id);   /* reassigns its entries to id 0 */

/* Transfer password — set during first-run setup, gates/encrypts export. */
esp_err_t vault_set_transfer_password(const char *pw, size_t len);
bool      vault_verify_transfer(const char *pw, size_t len);

/* Export all entries as a portable bundle encrypted under the transfer
 * password. Requires unlocked vault + correct transfer password.
 * *out_bundle is malloc'd; caller frees. */
esp_err_t vault_export(const char *transfer_pw, size_t len,
                       uint8_t **out_bundle, size_t *out_len);

/* Bulk-edit window for import: while open, vault_add/vault_update mutate the
 * in-RAM table but defer the NVS commit; vault_bulk_commit() persists once (and
 * closes the window). Always pair begin with commit, even on the error path, or
 * later writes stay deferred. */
void      vault_bulk_begin(void);
esp_err_t vault_bulk_commit(void);

/* Import a bundle (decrypted with the supplied transfer password) and merge:
 * an imported entry replaces a local one with the same title+username; others
 * are added. Requires unlocked vault. Returns ESP_FAIL on wrong password. */
esp_err_t vault_import(const char *transfer_pw, size_t len,
                       const uint8_t *bundle, size_t bundle_len);

/* Erase all vault state from NVS and lock. Returns to uninitialized state. */
void vault_factory_reset(void);
