#pragma once
#include <cstddef>

namespace vault {

// Brings up softAP "esp32key" with the given WPA2 password (>=8 chars; falls back
// to OPEN if shorter). Assumes esp_netif_init() + esp_event_loop_create_default()
// already ran.
class WifiAp {
public:
    void start(const char* password);   // throws vault::Error on failure
};

}  // namespace vault
