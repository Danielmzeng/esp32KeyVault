#pragma once
#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"

#define VAULT_MAX_ENTRIES 64
#define VAULT_FIELD_MAX   128

typedef struct {
    uint8_t  id;
    char     title[VAULT_FIELD_MAX];
    char     username[VAULT_FIELD_MAX];
    char     secret[VAULT_FIELD_MAX];   /* only populated after vault_reveal */
} vault_entry_t;

bool      vault_is_initialized(void);   /* has setup ever run? */
bool      vault_is_unlocked(void);

esp_err_t vault_setup(const char *master, size_t master_len);   /* first run */
esp_err_t vault_unlock(const char *master, size_t master_len);  /* ESP_ERR_INVALID_STATE if not init; ESP_FAIL if wrong pw */
void      vault_lock(void);                                     /* wipes DEK from RAM */
esp_err_t vault_change_password(const char *cur, size_t cur_len,
                                const char *next, size_t next_len);

/* CRUD — require unlocked vault, else ESP_ERR_INVALID_STATE. */
esp_err_t vault_list(vault_entry_t *out, size_t cap, size_t *count); /* secret[] left empty */
esp_err_t vault_reveal(uint8_t id, char secret_out[VAULT_FIELD_MAX]);
esp_err_t vault_add(const char *title, const char *username, const char *secret, uint8_t *out_id);
esp_err_t vault_update(uint8_t id, const char *title, const char *username, const char *secret);
esp_err_t vault_delete(uint8_t id);

/* Transfer password — set during first-run setup, gates/encrypts export. */
esp_err_t vault_set_transfer_password(const char *pw, size_t len);
bool      vault_verify_transfer(const char *pw, size_t len);

/* Export all entries as a portable bundle encrypted under the transfer
 * password. Requires unlocked vault + correct transfer password.
 * *out_bundle is malloc'd; caller frees. */
esp_err_t vault_export(const char *transfer_pw, size_t len,
                       uint8_t **out_bundle, size_t *out_len);

/* Import a bundle (decrypted with the supplied transfer password) and merge:
 * an imported entry replaces a local one with the same title+username; others
 * are added. Requires unlocked vault. Returns ESP_FAIL on wrong password. */
esp_err_t vault_import(const char *transfer_pw, size_t len,
                       const uint8_t *bundle, size_t bundle_len);

/* Erase all vault state from NVS (salt, iter, wrapped DEK, entries, transfer
 * verifier) and lock. Returns the vault to the uninitialized first-run state. */
void vault_factory_reset(void);
