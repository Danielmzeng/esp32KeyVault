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
#include "status_led.h"
#include <cstdlib>
#include <exception>

static const char *TAG = "esp32key";

/* Default AP password — change via Settings after first boot. */
#define AP_PASSWORD "29028356267034"

extern "C" void app_main(void)
{
    try {
        vault::crypto::init();

        // Process-lifetime singletons, owned here and injected by reference.
        static vault::Store   store;
        static vault::Vault   vault(store);
        vault.init();                       // auto-reset if the on-disk format changed

        static vault::Session   session;
        static vault::StatusLed led(vault, session);
        led.init();                         // WS2812 indicator: blue=setup, red=locked, green=unlocked

        ESP_ERROR_CHECK(esp_netif_init());
        ESP_ERROR_CHECK(esp_event_loop_create_default());

        // Wipe the DEK from RAM when a session idles out, not just on explicit logout.
        // `vault` has static storage duration, so the lambda uses it without capturing.
        session.set_expiry_cb([] { vault.lock(); });

        static vault::WifiAp wifi; wifi.start(AP_PASSWORD);
        static vault::UsbNet usb;  usb.start();

        static vault::Cert cert(store);
        char* cert_pem = nullptr; char* key_pem = nullptr;
        size_t clen = 0, klen = 0;
        cert.get(&cert_pem, &clen, &key_pem, &klen);
        ESP_LOGI(TAG, "certificate ready (%u bytes)", (unsigned)clen);

        static vault::ApiServer api(vault, session, led);
        api.start(cert_pem, clen, key_pem, klen);
        ESP_LOGI(TAG, "esp32key ready: https://192.168.4.1 (WiFi) / https://10.10.0.1 (USB)");
    } catch (const std::exception& e) {
        ESP_LOGE(TAG, "fatal init failure: %s", e.what());
        abort();   // mirror ESP_ERROR_CHECK's abort-on-fatal behavior
    }
}
