#include "vault_store.h"
#include "nvs_flash.h"
#include "nvs.h"

#define NS "vault"

esp_err_t vs_init(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    return err;
}

esp_err_t vs_set_blob(const char *key, const void *data, size_t len)
{
    nvs_handle_t h; esp_err_t err = nvs_open(NS, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    err = nvs_set_blob(h, key, data, len);
    nvs_close(h);
    return err;
}

esp_err_t vs_get_blob(const char *key, void *out, size_t *len)
{
    nvs_handle_t h; esp_err_t err = nvs_open(NS, NVS_READONLY, &h);
    if (err != ESP_OK) return err;
    err = nvs_get_blob(h, key, out, len);
    nvs_close(h);
    return err;
}

esp_err_t vs_erase_key(const char *key)
{
    nvs_handle_t h; esp_err_t err = nvs_open(NS, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    err = nvs_erase_key(h, key);
    nvs_close(h);
    return err;
}

esp_err_t vs_commit(void)
{
    nvs_handle_t h; esp_err_t err = nvs_open(NS, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    err = nvs_commit(h);
    nvs_close(h);
    return err;
}
