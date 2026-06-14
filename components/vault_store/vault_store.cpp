#include "vault_store.h"
#include "vault_error.h"
#include "nvs_flash.h"
#include "nvs.h"

#define NS "vault"

namespace vault {

Store::Store() {
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        check(nvs_flash_erase(), "nvs erase");
        err = nvs_flash_init();
    }
    check(err, "nvs init");
}

void Store::set_blob(const char* key, const void* data, size_t len) {
    nvs_handle_t h;
    check(nvs_open(NS, NVS_READWRITE, &h), "nvs open");
    esp_err_t err = nvs_set_blob(h, key, data, len);
    nvs_close(h);
    check(err, "nvs set_blob");
}

bool Store::get_blob(const char* key, void* out, size_t& len) {
    nvs_handle_t h;
    esp_err_t err = nvs_open(NS, NVS_READONLY, &h);
    if (err == ESP_ERR_NVS_NOT_FOUND) return false;   // namespace not yet created
    check(err, "nvs open ro");
    err = nvs_get_blob(h, key, out, &len);
    nvs_close(h);
    if (err == ESP_ERR_NVS_NOT_FOUND) return false;
    check(err, "nvs get_blob");
    return true;
}

void Store::erase_key(const char* key) {
    nvs_handle_t h;
    check(nvs_open(NS, NVS_READWRITE, &h), "nvs open");
    esp_err_t err = nvs_erase_key(h, key);
    nvs_close(h);
    if (err == ESP_ERR_NVS_NOT_FOUND) return;   // already absent
    check(err, "nvs erase_key");
}

void Store::commit() {
    nvs_handle_t h;
    check(nvs_open(NS, NVS_READWRITE, &h), "nvs open");
    esp_err_t err = nvs_commit(h);
    nvs_close(h);
    check(err, "nvs commit");
}

}  // namespace vault
