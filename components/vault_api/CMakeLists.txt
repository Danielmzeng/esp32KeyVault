idf_component_register(SRCS "vault_api.c"
                       INCLUDE_DIRS "include"
                       REQUIRES esp_https_server cjson vault vault_session esp_timer mbedtls
                       EMBED_FILES "www/index.html" "www/app.js" "www/style.css")
