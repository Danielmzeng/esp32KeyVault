#pragma once
#include <exception>
#include "esp_err.h"

namespace vault {

// Thrown on genuine faults (crypto/NVS/hardware failures, misuse). Carries the
// esp_err_t the C code would have returned, so boundary handlers can map it back.
// Expected outcomes (wrong password, tag mismatch, not-found) are NOT exceptions;
// they are return values.
class Error : public std::exception {
public:
    explicit Error(esp_err_t code, const char* what = "vault error") noexcept
        : code_(code), what_(what) {}
    esp_err_t code() const noexcept { return code_; }
    const char* what() const noexcept override { return what_; }
private:
    esp_err_t   code_;
    const char* what_;   // must point at a string literal / static storage
};

// Convenience: throw if an esp_err_t is not ESP_OK.
inline void check(esp_err_t e, const char* what = "esp error") {
    if (e != ESP_OK) throw Error(e, what);
}

}  // namespace vault
