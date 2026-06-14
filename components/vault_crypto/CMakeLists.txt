idf_component_register(SRCS "vault_crypto.cpp"
                       INCLUDE_DIRS "include"
                       REQUIRES mbedtls esp_hw_support vault_error)
