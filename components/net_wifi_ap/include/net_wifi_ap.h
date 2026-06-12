#pragma once
#include "esp_err.h"
/* Starts softAP "esp32key" with the given WPA2 password (>=8 chars).
 * Assumes esp_netif_init() and esp_event_loop_create_default() already called. */
esp_err_t net_wifi_ap_start(const char *password);
