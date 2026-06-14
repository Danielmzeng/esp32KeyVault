idf_component_register(SRCS "net_wifi_ap.cpp"
                       INCLUDE_DIRS "include"
                       REQUIRES esp_wifi esp_netif vault_error vault_store)
