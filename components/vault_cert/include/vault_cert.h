#pragma once
#include <cstddef>
#include "vault_store.h"

namespace vault {

// Loads a PEM cert+key pair from NVS (via Store), generating and persisting a new
// self-signed pair on first call or when the cached schema is stale. Output buffers
// are malloc'd; caller frees. Throws vault::Error on failure.
class Cert {
public:
    explicit Cert(Store& store) : store_(store) {}
    void get(char** cert_pem, size_t* cert_len, char** key_pem, size_t* key_len);
private:
    Store& store_;
};

}  // namespace vault
