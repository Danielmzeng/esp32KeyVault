idf_component_register(SRCS "test_app_main.c"
                       INCLUDE_DIRS ""
                       REQUIRES unity vault_crypto vault_store vault vault_session vault_cert net_wifi_ap net_usb vault_api
                       WHOLE_ARCHIVE)
