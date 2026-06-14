#pragma once
#include <cstddef>
#include "esp_https_server.h"
#include "vault.h"
#include "vault_store.h"
#include "vault_session.h"
#include "status_led.h"
#include "net_wifi_ap.h"

namespace vault {

class ApiServer {
public:
    ApiServer(Vault& vault, Session& session, StatusLed& led, Store& store, WifiAp& wifi)
        : vault_(vault), session_(session), led_(led), store_(store), wifi_(wifi) {}
    // Starts the HTTPS server (binds all interfaces). Throws vault::Error on failure.
    void start(const char* cert_pem, size_t cert_len,
               const char* key_pem, size_t key_len);

private:
    // Extract and validate our session cookie.
    bool authed(httpd_req_t* r);

    // Request-handler implementations (wrapped by static trampolines).
    esp_err_t h_state_impl(httpd_req_t* r);
    esp_err_t h_idle_set_impl(httpd_req_t* r);
    esp_err_t h_wifi_get_impl(httpd_req_t* r);
    esp_err_t h_wifi_set_impl(httpd_req_t* r);
    esp_err_t h_setup_impl(httpd_req_t* r);
    esp_err_t h_login_impl(httpd_req_t* r);
    esp_err_t h_logout_impl(httpd_req_t* r);
    esp_err_t h_entries_list_impl(httpd_req_t* r);
    esp_err_t h_entries_add_impl(httpd_req_t* r);
    esp_err_t h_entry_secret_impl(httpd_req_t* r);
    esp_err_t h_entry_update_impl(httpd_req_t* r);
    esp_err_t h_entry_delete_impl(httpd_req_t* r);
    esp_err_t h_cats_list_impl(httpd_req_t* r);
    esp_err_t h_cats_add_impl(httpd_req_t* r);
    esp_err_t h_cat_delete_impl(httpd_req_t* r);
    esp_err_t h_change_pw_impl(httpd_req_t* r);
    esp_err_t h_change_transfer_impl(httpd_req_t* r);
    esp_err_t h_export_impl(httpd_req_t* r);
    esp_err_t h_reset_impl(httpd_req_t* r);
    esp_err_t h_import_impl(httpd_req_t* r);

    // Idle auto-lock callbacks (recover `this` from arg).
    static void idle_lock_work(void* arg);
    static void idle_timer_cb(void* arg);

    // Static trampolines (defined via the API_HANDLER macro in the .cpp): each
    // recovers `this` from r->user_ctx, calls the matching private *_impl member,
    // and wraps it in try/catch so a throw never escapes into the httpd C stack.
    // A static member converts to the plain function pointer httpd_uri_t wants.
    static esp_err_t h_state(httpd_req_t*);
    static esp_err_t h_idle_set(httpd_req_t*);
    static esp_err_t h_wifi_get(httpd_req_t*);
    static esp_err_t h_wifi_set(httpd_req_t*);
    static esp_err_t h_setup(httpd_req_t*);
    static esp_err_t h_login(httpd_req_t*);
    static esp_err_t h_logout(httpd_req_t*);
    static esp_err_t h_entries_list(httpd_req_t*);
    static esp_err_t h_entries_add(httpd_req_t*);
    static esp_err_t h_entry_secret(httpd_req_t*);
    static esp_err_t h_entry_update(httpd_req_t*);
    static esp_err_t h_entry_delete(httpd_req_t*);
    static esp_err_t h_cats_list(httpd_req_t*);
    static esp_err_t h_cats_add(httpd_req_t*);
    static esp_err_t h_cat_delete(httpd_req_t*);
    static esp_err_t h_change_pw(httpd_req_t*);
    static esp_err_t h_change_transfer(httpd_req_t*);
    static esp_err_t h_export(httpd_req_t*);
    static esp_err_t h_reset(httpd_req_t*);
    static esp_err_t h_import(httpd_req_t*);

    Vault&     vault_;
    Session&   session_;
    StatusLed& led_;
    Store&     store_;
    WifiAp&    wifi_;
    httpd_handle_t srv_ = nullptr;
};

}  // namespace vault
