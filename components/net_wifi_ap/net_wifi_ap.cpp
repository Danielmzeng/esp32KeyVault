#include "net_wifi_ap.h"
#include "vault_error.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include <cstring>

namespace vault {

void WifiAp::start(const char* password) {
    esp_netif_create_default_wifi_ap();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    check(esp_wifi_init(&cfg), "wifi init");

    wifi_config_t ap = {};
    strlcpy((char*)ap.ap.ssid, "esp32key", sizeof ap.ap.ssid);
    ap.ap.ssid_len = strlen("esp32key");
    ap.ap.channel = 1;
    ap.ap.max_connection = 2;
    ap.ap.authmode = WIFI_AUTH_WPA2_PSK;
    strlcpy((char*)ap.ap.password, password, sizeof ap.ap.password);
    if (strlen(password) < 8) ap.ap.authmode = WIFI_AUTH_OPEN;  // avoid silent fail

    check(esp_wifi_set_mode(WIFI_MODE_AP), "wifi mode");
    check(esp_wifi_set_config(WIFI_IF_AP, &ap), "wifi config");
    check(esp_wifi_start(), "wifi start");
}

}  // namespace vault
