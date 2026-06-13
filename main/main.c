#include "esp_log.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "vault_store.h"
#include "vault.h"
#include "vault_session.h"
#include "vault_cert.h"
#include "vault_crypto.h"
#include "net_wifi_ap.h"
#include "net_usb.h"
#include "vault_api.h"
#include <stdlib.h>

static const char *TAG = "esp32key";

/* Default AP password — change via Settings after first boot. */
#define AP_PASSWORD "29028356267034"

void app_main(void)
{
    ESP_ERROR_CHECK(vc_init());
    ESP_ERROR_CHECK(vs_init());
    ESP_ERROR_CHECK(vault_init());   /* auto-reset if the on-disk format changed */
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    /* Wipe the DEK from RAM when a session idles out, not just on explicit logout. */
    vsess_set_expiry_cb(vault_lock);

    ESP_ERROR_CHECK(net_wifi_ap_start(AP_PASSWORD));
    ESP_ERROR_CHECK(net_usb_start());

    char *cert = NULL, *key = NULL; size_t clen = 0, klen = 0;
    ESP_ERROR_CHECK(vault_cert_get(&cert, &clen, &key, &klen));
    ESP_LOGI(TAG, "certificate ready (%u bytes)", (unsigned)clen);

    ESP_ERROR_CHECK(vault_api_start(cert, clen, key, klen));
    ESP_LOGI(TAG, "esp32key ready: https://192.168.4.1 (WiFi) / https://10.10.0.1 (USB)");
}
