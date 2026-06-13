#include "vault_api.h"
#include "vault.h"
#include "vault_session.h"
#include "esp_https_server.h"
#include "esp_timer.h"
#include "esp_log.h"
#include "cJSON.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>
#include <stdlib.h>

static const char *TAG = "vault_api";

extern const uint8_t index_html_start[] asm("_binary_index_html_start");
extern const uint8_t index_html_end[]   asm("_binary_index_html_end");
extern const uint8_t vault_png_start[]  asm("_binary_vault_png_start");
extern const uint8_t vault_png_end[]    asm("_binary_vault_png_end");

static uint64_t now_ms(void) { return (uint64_t)(esp_timer_get_time() / 1000); }

static esp_err_t send_json(httpd_req_t *r, int status, cJSON *obj)
{
    char *s = cJSON_PrintUnformatted(obj);
    httpd_resp_set_type(r, "application/json");
    /* httpd_resp_set_status stores the pointer, so only string literals here.
     * Any non-200 code we don't recognize falls back to 500 so an error is
     * never silently sent with the default 200 status. */
    switch (status) {
        case 200: break;
        case 400: httpd_resp_set_status(r, "400 Bad Request"); break;
        case 401: httpd_resp_set_status(r, "401 Unauthorized"); break;
        case 403: httpd_resp_set_status(r, "403 Forbidden"); break;
        case 404: httpd_resp_set_status(r, "404 Not Found"); break;
        default:  httpd_resp_set_status(r, "500 Internal Server Error"); break;
    }
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

/* Extract and validate our session cookie. httpd_req_get_cookie_val parses the
 * named cookie with framework-maintained RFC handling and reads only the "sid"
 * value, so it isn't defeated by other cookies or whole-header truncation. */
static bool authed(httpd_req_t *r)
{
    char tok[VS_TOKEN_HEX];
    size_t len = sizeof tok;
    if (httpd_req_get_cookie_val(r, "sid", tok, &len) != ESP_OK) return false;
    return vsess_validate(tok, now_ms());
}

/* ---- static files ---- */
static esp_err_t h_static(httpd_req_t *r, const uint8_t *start, const uint8_t *end, const char *type)
{
    httpd_resp_set_type(r, type);
    return httpd_resp_send(r, (const char *)start, end - start);
}
static esp_err_t h_index(httpd_req_t *r){ return h_static(r,index_html_start,index_html_end,"text/html"); }
static esp_err_t h_logo(httpd_req_t *r){ return h_static(r,vault_png_start,vault_png_end,"image/png"); }

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

static int json_int(cJSON *root, const char *k)
{
    cJSON *i = cJSON_GetObjectItem(root, k);
    return cJSON_IsNumber(i) ? i->valueint : 0;
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
    /* Two back-to-back PBKDF2 derivations on this task; yield so the idle task
     * runs and the task watchdog is satisfied between them. */
    vTaskDelay(pdMS_TO_TICKS(20));
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
    /* Reject empty password before counting it: otherwise empty-body POSTs
     * would burn the lockout budget and DoS the legitimate user. */
    if (strlen(pw) == 0) { cJSON_Delete(j); return err_json(r,400,"password required"); }
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
    if (!authed(r)) return err_json(r,401,"unauthorized");
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
        cJSON_AddNumberToObject(e,"category",list[i].category_id);
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
    esp_err_t e = vault_add(json_str(j,"title"), json_str(j,"username"), json_str(j,"secret"),
                            json_str(j,"url"), json_str(j,"comment"),
                            (uint8_t)json_int(j,"category"), &id);
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
    /* Trailing-wildcard route (matcher only honors a final asterisk), so require
     * the "/secret" suffix so only reveal requests reach this handler. */
    size_t ulen = strlen(r->uri);
    const char suf[] = "/secret";
    size_t slen = sizeof suf - 1;
    if (ulen < slen || strcmp(r->uri + ulen - slen, suf) != 0)
        return err_json(r,404,"not found");
    int id = uri_id(r); if (id < 0) return err_json(r,400,"bad id");
    char secret[VAULT_FIELD_MAX], url[VAULT_FIELD_MAX], comment[VAULT_FIELD_MAX];
    if (vault_reveal((uint8_t)id, secret, url, comment) != ESP_OK) return err_json(r,404,"not found");
    cJSON *o=cJSON_CreateObject();
    cJSON_AddStringToObject(o,"secret",secret);
    cJSON_AddStringToObject(o,"url",url);
    cJSON_AddStringToObject(o,"comment",comment);
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
    esp_err_t e = vault_update((uint8_t)id, json_str(j,"title"), json_str(j,"username"),
                               json_str(j,"secret"), json_str(j,"url"), json_str(j,"comment"),
                               (uint8_t)json_int(j,"category"));
    cJSON_Delete(j);
    if (e != ESP_OK) return err_json(r,404,"not found");
    return send_json(r, 200, cJSON_CreateObject());
}

/* ---- GET /api/categories ---- */
static esp_err_t h_cats_list(httpd_req_t *r)
{
    if (!authed(r)) return err_json(r,401,"unauthorized");
    static vault_category_t cats[VAULT_MAX_CATEGORIES]; size_t n = 0;
    if (vault_category_list(cats, VAULT_MAX_CATEGORIES, &n) != ESP_OK) return err_json(r,403,"locked");
    cJSON *o = cJSON_CreateObject(); cJSON *arr = cJSON_AddArrayToObject(o,"categories");
    for (size_t i=0;i<n;i++){ cJSON *c=cJSON_CreateObject();
        cJSON_AddNumberToObject(c,"id",cats[i].id);
        cJSON_AddStringToObject(c,"name",cats[i].name);
        cJSON_AddItemToArray(arr,c); }
    return send_json(r, 200, o);
}

/* ---- POST /api/categories ---- body {name} */
static esp_err_t h_cats_add(httpd_req_t *r)
{
    if (!authed(r)) return err_json(r,401,"unauthorized");
    char *body = read_body(r); if (!body) return err_json(r,400,"bad body");
    cJSON *j = cJSON_Parse(body); free(body);
    if (!j) return err_json(r,400,"bad json");
    const char *name = json_str(j,"name");
    uint8_t id;
    esp_err_t e = vault_category_add(name, &id);
    cJSON_Delete(j);
    if (e == ESP_ERR_INVALID_STATE) return err_json(r,409,"category exists");
    if (e != ESP_OK) return err_json(r,400,"add failed");
    cJSON *o=cJSON_CreateObject(); cJSON_AddNumberToObject(o,"id",id);
    return send_json(r, 200, o);
}

/* Parse trailing numeric id from a "/api/categories/{id}" URI. */
static int uri_cat_id(httpd_req_t *r)
{
    const char *p = strstr(r->uri, "/api/categories/");
    if (!p) return -1;
    return atoi(p + strlen("/api/categories/"));
}

/* ---- DELETE /api/categories/{id} ---- */
static esp_err_t h_cat_delete(httpd_req_t *r)
{
    if (!authed(r)) return err_json(r,401,"unauthorized");
    int id = uri_cat_id(r); if (id <= 0) return err_json(r,400,"bad id");
    if (vault_category_delete((uint8_t)id) != ESP_OK) return err_json(r,404,"not found");
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

/* ---- POST /api/export ---- body {transfer_password}; returns a PLAINTEXT JSON
 * file of every entry, for migrating into another password manager. The transfer
 * password is still required as an intent gate, but the file is NOT encrypted:
 * all secrets are in clear text. Category is emitted by name so it survives a
 * round-trip into a vault with different category ids. */
static esp_err_t h_export(httpd_req_t *r)
{
    if (!authed(r)) return err_json(r,401,"unauthorized");
    char *body = read_body(r); if (!body) return err_json(r,400,"bad body");
    cJSON *j = cJSON_Parse(body); free(body);
    if (!j) return err_json(r,400,"bad json");
    const char *tpw = json_str(j,"transfer_password");
    bool ok = vault_verify_transfer(tpw, strlen(tpw));
    cJSON_Delete(j);
    if (!ok) return err_json(r,403,"wrong transfer password");

    vault_entry_t *list = malloc(VAULT_MAX_ENTRIES * sizeof *list);
    if (!list) return err_json(r,500,"oom");
    size_t n = 0;
    if (vault_list(list, VAULT_MAX_ENTRIES, &n) != ESP_OK) { free(list); return err_json(r,403,"locked"); }
    static vault_category_t cats[VAULT_MAX_CATEGORIES]; size_t cn = 0;
    vault_category_list(cats, VAULT_MAX_CATEGORIES, &cn);

    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o,"format","esp32key-export");
    cJSON_AddNumberToObject(o,"version",1);
    cJSON *arr = cJSON_AddArrayToObject(o,"entries");
    for (size_t i = 0; i < n; i++) {
        char secret[VAULT_FIELD_MAX], url[VAULT_FIELD_MAX], comment[VAULT_FIELD_MAX];
        if (vault_reveal(list[i].id, secret, url, comment) != ESP_OK) { secret[0]=url[0]=comment[0]='\0'; }
        const char *cname = "";
        for (size_t k = 0; k < cn; k++) if (cats[k].id == list[i].category_id) { cname = cats[k].name; break; }
        cJSON *e = cJSON_CreateObject();
        cJSON_AddStringToObject(e,"title",list[i].title);
        cJSON_AddStringToObject(e,"username",list[i].username);
        cJSON_AddStringToObject(e,"url",url);
        cJSON_AddStringToObject(e,"secret",secret);
        cJSON_AddStringToObject(e,"comment",comment);
        cJSON_AddStringToObject(e,"category",cname);
        cJSON_AddItemToArray(arr,e);
        /* Don't leave plaintext on the stack between iterations. */
        memset(secret, 0, sizeof secret); memset(url, 0, sizeof url); memset(comment, 0, sizeof comment);
    }
    free(list);

    char *s = cJSON_Print(o);   /* pretty: the file is meant to be human-readable */
    cJSON_Delete(o);
    if (!s) return err_json(r,500,"oom");
    httpd_resp_set_type(r, "application/json");
    httpd_resp_set_hdr(r, "Content-Disposition", "attachment; filename=esp32key-export.json");
    esp_err_t st = httpd_resp_sendstr(r, s);
    memset(s, 0, strlen(s));    /* wipe the rendered cleartext before freeing */
    free(s);
    return st;
}

/* ---- POST /api/import ---- body is a plaintext export file
 * {format,version,entries:[{title,username,url,secret,comment,category}]}.
 * Merge: an imported entry replaces a local one with the same title+username;
 * others are added. Category is matched by name; unknown -> Uncategorized.
 * No transfer password: the file is already plaintext and the session cookie
 * already grants full write access. */
static esp_err_t h_import(httpd_req_t *r)
{
    if (!authed(r)) return err_json(r,401,"unauthorized");
    /* Must exceed the largest file h_export can produce, or the device can't
     * re-import its own export. Worst case: every char of every field escapes to
     * \uXXXX (6 bytes); ~6*VAULT_MAX_ENTRIES*6*VAULT_FIELD_MAX plus structure,
     * which is ~300 KB. 384 KB leaves headroom and is cheap from PSRAM. */
    char *body = read_body_cap(r, 384 * 1024); if (!body) return err_json(r,400,"bad body");
    cJSON *j = cJSON_Parse(body); free(body);
    if (!j) return err_json(r,400,"bad json");
    cJSON *arr = cJSON_GetObjectItem(j,"entries");
    if (!cJSON_IsArray(arr)) { cJSON_Delete(j); return err_json(r,400,"no entries in file"); }

    vault_entry_t *list = malloc(VAULT_MAX_ENTRIES * sizeof *list);
    if (!list) { cJSON_Delete(j); return err_json(r,500,"oom"); }
    size_t n = 0;
    if (vault_list(list, VAULT_MAX_ENTRIES, &n) != ESP_OK) { free(list); cJSON_Delete(j); return err_json(r,403,"locked"); }
    static vault_category_t cats[VAULT_MAX_CATEGORIES]; size_t cn = 0;
    vault_category_list(cats, VAULT_MAX_CATEGORIES, &cn);

    /* One NVS commit for the whole import, not one per entry: faster, far less
     * flash wear, and all-or-nothing on disk (a crash mid-loop leaves the old
     * vault, not a half-merged one). */
    vault_bulk_begin();
    int imported = 0;
    cJSON *e;
    cJSON_ArrayForEach(e, arr) {
        const char *title = json_str(e,"title");
        const char *user  = json_str(e,"username");
        if (title[0] == '\0') continue;           /* a title is required */
        const char *url   = json_str(e,"url");
        const char *sec   = json_str(e,"secret");
        const char *cmt   = json_str(e,"comment");
        const char *cname = json_str(e,"category");

        uint8_t cat = 0;
        if (cname[0]) for (size_t k = 0; k < cn; k++)
            if (strncmp(cats[k].name, cname, VAULT_CAT_NAME_MAX) == 0) { cat = cats[k].id; break; }

        /* Match against the live set (incl. entries added earlier this loop) so a
         * file with duplicate title+username collapses instead of duplicating. */
        int match_id = -1;
        for (size_t i = 0; i < n; i++)
            if (strncmp(list[i].title, title, VAULT_FIELD_MAX) == 0 &&
                strncmp(list[i].username, user, VAULT_FIELD_MAX) == 0) { match_id = list[i].id; break; }

        esp_err_t re;
        if (match_id >= 0) {
            re = vault_update((uint8_t)match_id, title, user, sec, url, cmt, cat);
        } else {
            uint8_t nid;
            re = vault_add(title, user, sec, url, cmt, cat, &nid);
            if (re == ESP_OK && n < VAULT_MAX_ENTRIES) {
                list[n].id = nid;
                strlcpy(list[n].title, title, VAULT_FIELD_MAX);
                strlcpy(list[n].username, user, VAULT_FIELD_MAX);
                n++;
            }
        }
        if (re == ESP_OK) imported++;
    }
    esp_err_t pe = vault_bulk_commit();
    free(list); cJSON_Delete(j);
    if (pe != ESP_OK) return err_json(r,500,"import save failed");
    cJSON *o = cJSON_CreateObject(); cJSON_AddNumberToObject(o,"imported",imported);
    return send_json(r, 200, o);
}

esp_err_t vault_api_start(const char *cert_pem, size_t cert_len,
                          const char *key_pem, size_t key_len)
{
    /* Clients rejecting our self-signed cert (and OS captive-portal probes)
     * abort the TLS handshake; that is expected, so don't spam it as errors. */
    esp_log_level_set("esp-tls-mbedtls", ESP_LOG_NONE);
    esp_log_level_set("esp_https_server", ESP_LOG_WARN);
    esp_log_level_set("httpd", ESP_LOG_ERROR);

    httpd_ssl_config_t cfg = HTTPD_SSL_CONFIG_DEFAULT();
    cfg.servercert = (const uint8_t *)cert_pem;
    cfg.servercert_len = cert_len;
    cfg.prvtkey_pem = (const uint8_t *)key_pem;
    cfg.prvtkey_len = key_len;
    cfg.httpd.max_uri_handlers = 20;
    cfg.httpd.uri_match_fn = httpd_uri_match_wildcard;
    /* Pin the server (TLS handshake + all API handlers) to CPU1, away from the
     * USB+Wi-Fi+system tasks that are all pinned to CPU0. */
    cfg.httpd.core_id = 1;

    httpd_handle_t srv = NULL;
    esp_err_t e = httpd_ssl_start(&srv, &cfg);
    if (e != ESP_OK) { ESP_LOGE(TAG, "https start failed: %s", esp_err_to_name(e)); return e; }

    const httpd_uri_t routes[] = {
        {"/",                       HTTP_GET,    h_index,         NULL},
        {"/vault.png",              HTTP_GET,    h_logo,          NULL},
        {"/api/state",              HTTP_GET,    h_state,         NULL},
        {"/api/setup",              HTTP_POST,   h_setup,         NULL},
        {"/api/login",              HTTP_POST,   h_login,         NULL},
        {"/api/logout",             HTTP_POST,   h_logout,        NULL},
        {"/api/change-password",    HTTP_POST,   h_change_pw,     NULL},
        {"/api/export",             HTTP_POST,   h_export,        NULL},
        {"/api/import",             HTTP_POST,   h_import,        NULL},
        {"/api/entries",            HTTP_GET,    h_entries_list,  NULL},
        {"/api/entries",            HTTP_POST,   h_entries_add,   NULL},
        {"/api/entries/*",          HTTP_GET,    h_entry_secret,  NULL},
        {"/api/entries/*",          HTTP_PUT,    h_entry_update,  NULL},
        {"/api/entries/*",          HTTP_DELETE, h_entry_delete,  NULL},
        {"/api/categories",         HTTP_GET,    h_cats_list,     NULL},
        {"/api/categories",         HTTP_POST,   h_cats_add,      NULL},
        {"/api/categories/*",       HTTP_DELETE, h_cat_delete,    NULL},
    };
    for (size_t i = 0; i < sizeof routes / sizeof routes[0]; i++)
        httpd_register_uri_handler(srv, &routes[i]);
    return ESP_OK;
}
