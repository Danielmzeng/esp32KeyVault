#pragma once
#include "esp_err.h"
/* Starts the HTTPS server (binds all interfaces) with the given cert/key PEM. */
esp_err_t vault_api_start(const char *cert_pem, size_t cert_len,
                          const char *key_pem,  size_t key_len);
