idf_component_register(SRCS "main.c"
                       INCLUDE_DIRS ""
                       REQUIRES vault_store vault vault_session vault_cert vault_crypto
                                net_wifi_ap net_usb vault_api status_led esp_netif esp_event)
