idf_component_register(SRCS "vault_api.cpp"
                       INCLUDE_DIRS "include"
                       REQUIRES esp_https_server cjson vault vault_session esp_timer mbedtls status_led vault_error
                       EMBED_FILES "www/index.html")
