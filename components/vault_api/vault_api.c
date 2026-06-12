#include "vault_api.h"
#include "vault.h"
#include "vault_session.h"
#include "esp_https_server.h"
#include "esp_timer.h"
#include "esp_log.h"
#include "cJSON.h"
#include <string.h>
#include <stdlib.h>

static const char *TAG = "vault_api";

extern const uint8_t index_html_start[] asm("_binary_index_html_start");
extern const uint8_t index_html_end[]   asm("_binary_index_html_end");
extern const uint8_t app_js_start[]     asm("_binary_app_js_start");
extern const uint8_t app_js_end[]       asm("_binary_app_js_end");
extern const uint8_t style_css_start[]  asm("_binary_style_css_start");
extern const uint8_t style_css_end[]    asm("_binary_style_css_end");

static uint64_t now_ms(void) { return (uint64_t)(esp_timer_get_time() / 1000); }

static esp_err_t send_json(httpd_req_t *r, int status, cJSON *obj)
{
    char *s = cJSON_PrintUnformatted(obj);
    httpd_resp_set_type(r, "application/json");
    if (status == 401) httpd_resp_set_status(r, "401 Unauthorized");
    else if (status == 400) httpd_resp_set_status(r, "400 Bad Request");
    else if (status == 403) httpd_resp_set_status(r, "403 Forbidden");
    else if (status == 500) httpd_resp_set_status(r, "500 Internal Server Error");
    esp_err_t e = httpd_resp_sendstr(r, s ? s : "{}");
    free(s); cJSON_Delete(obj);
    return e;
}

static esp_err_t err_json(httpd_req_t *r, int status, const char *msg)
{
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "error", msg);
    return send_json(r, status, o);
}

/* Read up to maxlen bytes of body into a NUL-terminated heap buffer; caller frees. */
static char *read_body_cap(httpd_req_t *r, size_t maxlen)
{
    if (r->content_len == 0 || r->content_len > maxlen) return NULL;
    char *buf = malloc(r->content_len + 1);
    if (!buf) return NULL;
    size_t got = 0;
    while (got < r->content_len) {
        int n = httpd_req_recv(r, buf + got, r->content_len - got);
        if (n <= 0) { free(buf); return NULL; }
        got += n;
    }
    buf[got] = '\0';
    return buf;
}
static char *read_body(httpd_req_t *r) { return read_body_cap(r, 2048); }

static int b64_sextet(unsigned char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

/* Decode base64 src into dst (capacity dcap). Returns decoded byte count, or
 * -1 on invalid input / overflow. Skips ASCII whitespace; '=' ends input. */
static int b64_decode(const char *src, size_t slen, uint8_t *dst, size_t dcap)
{
    uint32_t acc = 0; int nbits = 0; size_t out = 0;
    for (size_t i = 0; i < slen; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '=') break;
        if (c == '\r' || c == '\n' || c == ' ' || c == '\t') continue;
        int v = b64_sextet(c);
        if (v < 0) return -1;
        acc = (acc << 6) | (uint32_t)v;
        nbits += 6;
        if (nbits >= 8) {
            nbits -= 8;
            if (out >= dcap) return -1;
            dst[out++] = (uint8_t)((acc >> nbits) & 0xFF);
        }
    }
    return (int)out;
}

/* Look for our session cookie. */
static bool authed(httpd_req_t *r)
{
    char cookie[128];
    if (httpd_req_get_hdr_value_str(r, "Cookie", cookie, sizeof cookie) != ESP_OK) return false;
    char *p = strstr(cookie, "sid=");
    if (!p) return false;
    p += 4;
    char tok[VS_TOKEN_HEX] = {0};
    size_t i = 0;
    while (p[i] && p[i] != ';' && i < VS_TOKEN_HEX - 1) { tok[i] = p[i]; i++; }
    return vsess_validate(tok, now_ms());
}

/* ---- static files ---- */
static esp_err_t h_static(httpd_req_t *r, const uint8_t *start, const uint8_t *end, const char *type)
{
    httpd_resp_set_type(r, type);
    return httpd_resp_send(r, (const char *)start, end - start);
}
static esp_err_t h_index(httpd_req_t *r){ return h_static(r,index_html_start,index_html_end,"text/html"); }
static esp_err_t h_appjs(httpd_req_t *r){ return h_static(r,app_js_start,app_js_end,"application/javascript"); }
static esp_err_t h_css(httpd_req_t *r){ return h_static(r,style_css_start,style_css_end,"text/css"); }

/* ---- /api/state ---- */
static esp_err_t h_state(httpd_req_t *r)
{
    cJSON *o = cJSON_CreateObject();
    cJSON_AddBoolToObject(o, "initialized", vault_is_initialized());
    cJSON_AddBoolToObject(o, "unlocked", authed(r) && vault_is_unlocked());
    return send_json(r, 200, o);
}

static const char *json_str(cJSON *root, const char *k)
{
    cJSON *i = cJSON_GetObjectItem(root, k);
    return cJSON_IsString(i) ? i->valuestring : "";
}

/* ---- /api/setup ---- */
static esp_err_t h_setup(httpd_req_t *r)
{
    char *body = read_body(r); if (!body) return err_json(r,400,"bad body");
    cJSON *j = cJSON_Parse(body); free(body);
    if (!j) return err_json(r,400,"bad json");
    const char *pw = json_str(j,"password");
    const char *tpw = json_str(j,"transfer_password");
    if (strlen(pw) == 0 || strlen(tpw) == 0) { cJSON_Delete(j); return err_json(r,400,"both passwords required"); }
    esp_err_t e = vault_setup(pw, strlen(pw));
    if (e != ESP_OK) { cJSON_Delete(j); return err_json(r,400,"already initialized"); }
    e = vault_set_transfer_password(tpw, strlen(tpw));
    if (e != ESP_OK) { vault_factory_reset(); cJSON_Delete(j); return err_json(r,500,"setup failed, try again"); }
    cJSON_Delete(j);
    char tok[VS_TOKEN_HEX]; vsess_create(now_ms(), tok);
    char hdr[128]; snprintf(hdr,sizeof hdr,"sid=%s; HttpOnly; Secure; Path=/; SameSite=Strict", tok);
    httpd_resp_set_hdr(r, "Set-Cookie", hdr);
    return send_json(r, 200, cJSON_CreateObject());
}

/* ---- /api/login ---- */
static esp_err_t h_login(httpd_req_t *r)
{
    if (!vsess_login_allowed(now_ms())) return err_json(r,403,"locked out, try later");
    char *body = read_body(r); if (!body) return err_json(r,400,"bad body");
    cJSON *j = cJSON_Parse(body); free(body);
    if (!j) return err_json(r,400,"bad json");
    const char *pw = json_str(j,"password");
    esp_err_t e = vault_unlock(pw, strlen(pw));
    cJSON_Delete(j);
    vsess_note_login_result(e == ESP_OK, now_ms());
    if (e != ESP_OK) return err_json(r,401,"invalid password");
    char tok[VS_TOKEN_HEX]; vsess_create(now_ms(), tok);
    char hdr[128]; snprintf(hdr,sizeof hdr,"sid=%s; HttpOnly; Secure; Path=/; SameSite=Strict", tok);
    httpd_resp_set_hdr(r, "Set-Cookie", hdr);
    return send_json(r, 200, cJSON_CreateObject());
}

/* ---- /api/logout ---- */
static esp_err_t h_logout(httpd_req_t *r)
{
    vsess_destroy(); vault_lock();
    return send_json(r, 200, cJSON_CreateObject());
}

/* ---- GET /api/entries ---- */
static esp_err_t h_entries_list(httpd_req_t *r)
{
    if (!authed(r)) return err_json(r,401,"unauthorized");
    static vault_entry_t list[VAULT_MAX_ENTRIES]; size_t n = 0;
    if (vault_list(list, VAULT_MAX_ENTRIES, &n) != ESP_OK) return err_json(r,403,"locked");
    cJSON *o = cJSON_CreateObject(); cJSON *arr = cJSON_AddArrayToObject(o,"entries");
    for (size_t i=0;i<n;i++){ cJSON *e=cJSON_CreateObject();
        cJSON_AddNumberToObject(e,"id",list[i].id);
        cJSON_AddStringToObject(e,"title",list[i].title);
        cJSON_AddStringToObject(e,"username",list[i].username);
        cJSON_AddItemToArray(arr,e); }
    return send_json(r, 200, o);
}

/* ---- POST /api/entries ---- */
static esp_err_t h_entries_add(httpd_req_t *r)
{
    if (!authed(r)) return err_json(r,401,"unauthorized");
    char *body = read_body(r); if (!body) return err_json(r,400,"bad body");
    cJSON *j = cJSON_Parse(body); free(body);
    if (!j) return err_json(r,400,"bad json");
    uint8_t id;
    esp_err_t e = vault_add(json_str(j,"title"), json_str(j,"username"), json_str(j,"secret"), &id);
    cJSON_Delete(j);
    if (e != ESP_OK) return err_json(r,400,"add failed");
    cJSON *o=cJSON_CreateObject(); cJSON_AddNumberToObject(o,"id",id);
    return send_json(r, 200, o);
}

/* Parse trailing numeric id from URI, optionally with a suffix like "/secret". */
static int uri_id(httpd_req_t *r)
{
    const char *p = strstr(r->uri, "/api/entries/");
    if (!p) return -1;
    return atoi(p + strlen("/api/entries/"));
}

/* ---- GET /api/entries/{id}/secret ---- */
static esp_err_t h_entry_secret(httpd_req_t *r)
{
    if (!authed(r)) return err_json(r,401,"unauthorized");
    int id = uri_id(r); if (id < 0) return err_json(r,400,"bad id");
    char secret[VAULT_FIELD_MAX];
    if (vault_reveal((uint8_t)id, secret) != ESP_OK) return err_json(r,404,"not found");
    cJSON *o=cJSON_CreateObject(); cJSON_AddStringToObject(o,"secret",secret);
    return send_json(r, 200, o);
}

/* ---- PUT /api/entries/{id} ---- */
static esp_err_t h_entry_update(httpd_req_t *r)
{
    if (!authed(r)) return err_json(r,401,"unauthorized");
    int id = uri_id(r); if (id < 0) return err_json(r,400,"bad id");
    char *body = read_body(r); if (!body) return err_json(r,400,"bad body");
    cJSON *j = cJSON_Parse(body); free(body);
    if (!j) return err_json(r,400,"bad json");
    esp_err_t e = vault_update((uint8_t)id, json_str(j,"title"), json_str(j,"username"), json_str(j,"secret"));
    cJSON_Delete(j);
    if (e != ESP_OK) return err_json(r,404,"not found");
    return send_json(r, 200, cJSON_CreateObject());
}

/* ---- DELETE /api/entries/{id} ---- */
static esp_err_t h_entry_delete(httpd_req_t *r)
{
    if (!authed(r)) return err_json(r,401,"unauthorized");
    int id = uri_id(r); if (id < 0) return err_json(r,400,"bad id");
    if (vault_delete((uint8_t)id) != ESP_OK) return err_json(r,404,"not found");
    return send_json(r, 200, cJSON_CreateObject());
}

/* ---- POST /api/change-password ---- */
static esp_err_t h_change_pw(httpd_req_t *r)
{
    if (!authed(r)) return err_json(r,401,"unauthorized");
    char *body = read_body(r); if (!body) return err_json(r,400,"bad body");
    cJSON *j = cJSON_Parse(body); free(body);
    if (!j) return err_json(r,400,"bad json");
    const char *cur = json_str(j,"current"), *next = json_str(j,"next");
    esp_err_t e = vault_change_password(cur, strlen(cur), next, strlen(next));
    cJSON_Delete(j);
    if (e != ESP_OK) return err_json(r,403,"wrong current password");
    return send_json(r, 200, cJSON_CreateObject());
}

/* ---- POST /api/export ---- body {transfer_password}; returns binary bundle */
static esp_err_t h_export(httpd_req_t *r)
{
    if (!authed(r)) return err_json(r,401,"unauthorized");
    char *body = read_body(r); if (!body) return err_json(r,400,"bad body");
    cJSON *j = cJSON_Parse(body); free(body);
    if (!j) return err_json(r,400,"bad json");
    const char *tpw = json_str(j,"transfer_password");
    uint8_t *bundle = NULL; size_t blen = 0;
    esp_err_t e = vault_export(tpw, strlen(tpw), &bundle, &blen);
    cJSON_Delete(j);
    if (e != ESP_OK) return err_json(r,403,"wrong transfer password");
    httpd_resp_set_type(r, "application/octet-stream");
    httpd_resp_set_hdr(r, "Content-Disposition", "attachment; filename=esp32key-export.bin");
    esp_err_t s = httpd_resp_send(r, (const char *)bundle, blen);
    free(bundle);
    return s;
}

/* ---- POST /api/import ---- body {transfer_password, bundle(base64)} */
static esp_err_t h_import(httpd_req_t *r)
{
    if (!authed(r)) return err_json(r,401,"unauthorized");
    char *body = read_body_cap(r, 96 * 1024); if (!body) return err_json(r,400,"bad body");
    cJSON *j = cJSON_Parse(body); free(body);
    if (!j) return err_json(r,400,"bad json");
    const char *tpw = json_str(j,"transfer_password");
    const char *b64 = json_str(j,"bundle");
    size_t b64len = strlen(b64);
    size_t cap = (b64len / 4) * 3 + 4;
    uint8_t *raw = malloc(cap);
    if (!raw) { cJSON_Delete(j); return err_json(r,400,"oom"); }
    int rc = b64_decode(b64, b64len, raw, cap);
    if (rc < 0) { free(raw); cJSON_Delete(j); return err_json(r,400,"import failed (wrong password or bad file)"); }
    esp_err_t e = vault_import(tpw, strlen(tpw), raw, (size_t)rc);
    free(raw); cJSON_Delete(j);
    if (e != ESP_OK) return err_json(r,400,"import failed (wrong password or bad file)");
    return send_json(r, 200, cJSON_CreateObject());
}

esp_err_t vault_api_start(const char *cert_pem, size_t cert_len,
                          const char *key_pem, size_t key_len)
{
    httpd_ssl_config_t cfg = HTTPD_SSL_CONFIG_DEFAULT();
    cfg.servercert = (const uint8_t *)cert_pem;
    cfg.servercert_len = cert_len;
    cfg.prvtkey_pem = (const uint8_t *)key_pem;
    cfg.prvtkey_len = key_len;
    cfg.httpd.max_uri_handlers = 20;
    cfg.httpd.uri_match_fn = httpd_uri_match_wildcard;

    httpd_handle_t srv = NULL;
    esp_err_t e = httpd_ssl_start(&srv, &cfg);
    if (e != ESP_OK) { ESP_LOGE(TAG, "https start failed: %s", esp_err_to_name(e)); return e; }

    const httpd_uri_t routes[] = {
        {"/",                       HTTP_GET,    h_index,         NULL},
        {"/style.css",              HTTP_GET,    h_css,           NULL},
        {"/app.js",                 HTTP_GET,    h_appjs,         NULL},
        {"/api/state",              HTTP_GET,    h_state,         NULL},
        {"/api/setup",              HTTP_POST,   h_setup,         NULL},
        {"/api/login",              HTTP_POST,   h_login,         NULL},
        {"/api/logout",             HTTP_POST,   h_logout,        NULL},
        {"/api/change-password",    HTTP_POST,   h_change_pw,     NULL},
        {"/api/export",             HTTP_POST,   h_export,        NULL},
        {"/api/import",             HTTP_POST,   h_import,        NULL},
        {"/api/entries",            HTTP_GET,    h_entries_list,  NULL},
        {"/api/entries",            HTTP_POST,   h_entries_add,   NULL},
        {"/api/entries/*/secret",   HTTP_GET,    h_entry_secret,  NULL},
        {"/api/entries/*",          HTTP_PUT,    h_entry_update,  NULL},
        {"/api/entries/*",          HTTP_DELETE, h_entry_delete,  NULL},
    };
    for (size_t i = 0; i < sizeof routes / sizeof routes[0]; i++)
        httpd_register_uri_handler(srv, &routes[i]);
    return ESP_OK;
}
