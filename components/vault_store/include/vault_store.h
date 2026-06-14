#pragma once
#include <cstddef>
#include "esp_err.h"

namespace vault {

// Thin typed RAII wrapper over the "vault" NVS namespace. Blob keys are <=15 chars.
class Store {
public:
    Store();   // nvs_flash_init (erase+retry on version/space error); throws vault::Error on failure

    void set_blob(const char* key, const void* data, size_t len);   // throws on failure
    // On entry len = buffer size; on success len = bytes read. Returns false if the
    // key is absent. Pass out=nullptr to query the size (len receives it). Throws on
    // faults other than not-found.
    bool get_blob(const char* key, void* out, size_t& len);
    void erase_key(const char* key);   // tolerates a missing key; throws on other faults
    void commit();
};

}  // namespace vault
