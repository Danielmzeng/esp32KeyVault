#pragma once
#include <cstddef>
#include "vault_store.h"

namespace vault {

// Brings up softAP with persisted SSID/password (or the passed factory defaults
// if none saved). WPA2 when the password is >=8 chars, else OPEN. Assumes
// esp_netif_init() + esp_event_loop_create_default() already ran.
class WifiAp {
public:
    explicit WifiAp(Store& store) : store_(store) {}

    // Load saved creds (or defaults) and start the AP. Throws vault::Error on failure.
    void start(const char* default_ssid, const char* default_password);

    // Persist new SSID + password to NVS (does NOT apply live; caller reboots).
    // Throws vault::Error on NVS fault.
    void set_credentials(const char* ssid, const char* password);

    const char* ssid() const { return ssid_; }   // active SSID (for UI prefill)

private:
    void load_or_default(const char* key, const char* def, char* buf, size_t buflen);

    Store& store_;
    char   ssid_[33] = "esp32key";   // 32-char 802.11 max + NUL
};

}  // namespace vault
