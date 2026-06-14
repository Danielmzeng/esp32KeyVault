idf_component_register(SRCS "status_led.cpp"
                       INCLUDE_DIRS "include"
                       REQUIRES vault vault_session esp_timer led_strip vault_error)
