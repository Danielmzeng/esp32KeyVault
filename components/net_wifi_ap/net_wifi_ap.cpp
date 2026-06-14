#include "net_wifi_ap.h"
#include "vault_error.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include <cstring>

namespace vault {

namespace {
const char SSID_KEY[] = "ap_ssid";   // NVS keys (<=15 chars)
const char PW_KEY[]   = "ap_pw";
}

void WifiAp::load_or_default(const char* key, const char* def, char* buf, size_t buflen) {
    size_t len = buflen;
    bool got = false;
    try { got = store_.get_blob(key, buf, len); } catch (...) { got = false; }
    if (!got) { strlcpy(buf, def, buflen); return; }
    buf[len < buflen ? len : buflen - 1] = '\0';   // terminate at the bytes read (not the buffer end)
}

void WifiAp::start(const char* default_ssid, const char* default_password) {
    esp_netif_create_default_wifi_ap();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    check(esp_wifi_init(&cfg), "wifi init");

    char pw[64];
    load_or_default(SSID_KEY, default_ssid,     ssid_, sizeof ssid_);
    load_or_default(PW_KEY,   default_password, pw,    sizeof pw);

    wifi_config_t ap = {};
    /* The SSID field is 32 bytes and carries its length separately in ssid_len
     * (no NUL needed), so copy up to 32 bytes -- strlcpy would drop the 32nd
     * char of a max-length SSID reserving room for a NUL. */
    size_t slen = strnlen(ssid_, sizeof ap.ap.ssid);
    memcpy(ap.ap.ssid, ssid_, slen);
    ap.ap.ssid_len = slen;
    ap.ap.channel = 1;
    ap.ap.max_connection = 2;
    ap.ap.authmode = WIFI_AUTH_WPA2_PSK;
    strlcpy((char*)ap.ap.password, pw, sizeof ap.ap.password);
    if (strlen(pw) < 8) ap.ap.authmode = WIFI_AUTH_OPEN;  // avoid silent fail

    check(esp_wifi_set_mode(WIFI_MODE_AP), "wifi mode");
    check(esp_wifi_set_config(WIFI_IF_AP, &ap), "wifi config");
    check(esp_wifi_start(), "wifi start");
}

void WifiAp::set_credentials(const char* ssid, const char* password) {
    store_.set_blob(SSID_KEY, ssid, strlen(ssid) + 1);
    store_.set_blob(PW_KEY, password, strlen(password) + 1);
    store_.commit();
}

}  // namespace vault
