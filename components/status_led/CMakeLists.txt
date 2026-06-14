idf_component_register(SRCS "status_led.c"
                       INCLUDE_DIRS "include"
                       REQUIRES vault vault_session esp_timer led_strip)
