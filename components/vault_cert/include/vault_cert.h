#pragma once
#include <stddef.h>
#include "esp_err.h"

/* Loads a PEM cert+key pair from NVS, generating and persisting a new
 * self-signed pair on first call. Buffers are malloc'd; caller frees. */
esp_err_t vault_cert_get(char **cert_pem, size_t *cert_len,
                         char **key_pem,  size_t *key_len);
