#include "net_wifi_ap.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include <string.h>

esp_err_t net_wifi_ap_start(const char *password)
{
    esp_netif_create_default_wifi_ap();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    wifi_config_t ap = {0};
    strlcpy((char *)ap.ap.ssid, "esp32key", sizeof ap.ap.ssid);
    ap.ap.ssid_len = strlen("esp32key");
    ap.ap.channel = 1;
    ap.ap.max_connection = 2;
    ap.ap.authmode = WIFI_AUTH_WPA2_PSK;
    strlcpy((char *)ap.ap.password, password, sizeof ap.ap.password);
    if (strlen(password) < 8) ap.ap.authmode = WIFI_AUTH_OPEN; /* avoid silent fail */

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap));
    return esp_wifi_start();
}
