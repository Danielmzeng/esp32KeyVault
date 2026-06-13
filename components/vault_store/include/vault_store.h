#pragma once
#include <stddef.h>
#include "esp_err.h"

/* Thin typed wrappers over an NVS namespace ("vault"). Blob keys are <=15 chars. */
esp_err_t vs_init(void);                                   /* nvs_flash_init */
esp_err_t vs_set_blob(const char *key, const void *data, size_t len);
/* On entry *len = buffer size; on success *len = bytes read. */
esp_err_t vs_get_blob(const char *key, void *out, size_t *len);
esp_err_t vs_erase_key(const char *key);
esp_err_t vs_commit(void);
