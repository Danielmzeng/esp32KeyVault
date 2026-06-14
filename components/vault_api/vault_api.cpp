#include "vault_api.h"
#include "vault.h"
#include "vault_session.h"
#include "status_led.h"
#include "vault_error.h"
#include "esp_https_server.h"
#include "esp_timer.h"
#include "esp_log.h"
#include "cJSON.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>
#include <stdlib.h>
#include <exception>

using vault::ApiServer;

static const char *TAG = "vault_api";

/* The uri_match_fn C callback has no context slot, and there is only ever one
 * server, so a pair of file-local pointers route the activity pulse. Both are
 * set at the top of start(). (Documented no-context workaround.) */
static ApiServer *s_instance = nullptr;
static vault::StatusLed *s_led = nullptr;

extern const uint8_t index_html_start[] asm("_binary_index_html_start");
extern const uint8_t index_html_end[]   asm("_binary_index_html_end");

namespace {

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
    char *buf = (char*)malloc(r->content_len + 1);
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

/* ---- static files ---- */
static esp_err_t h_static(httpd_req_t *r, const uint8_t *start, const uint8_t *end, const char *type)
{
    httpd_resp_set_type(r, type);
    return httpd_resp_send(r, (const char *)start, end - start);
}
static esp_err_t h_index(httpd_req_t *r){ return h_static(r,index_html_start,index_html_end,"text/html"); }

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

/* Parse trailing numeric id from URI, optionally with a suffix like "/secret". */
static int uri_id(httpd_req_t *r)
{
    const char *p = strstr(r->uri, "/api/entries/");
    if (!p) return -1;
    return atoi(p + strlen("/api/entries/"));
}

/* Parse trailing numeric id from a "/api/categories/{id}" URI. */
static int uri_cat_id(httpd_req_t *r)
{
    const char *p = strstr(r->uri, "/api/categories/");
    if (!p) return -1;
    return atoi(p + strlen("/api/categories/"));
}

/* URI matcher wrapper: the one chokepoint every request routes through. Pulse
 * the activity LED whenever a request matches an /api/ route, so the indicator
 * lives in a single place instead of every handler. Runs on the httpd task and
 * only sets a flag, so it adds nothing to the handler hot path. */
static bool uri_match_activity(const char *tpl, const char *uri, size_t upto)
{
    bool m = httpd_uri_match_wildcard(tpl, uri, upto);
    if (m && strncmp(tpl, "/api/", 5) == 0 && s_led) s_led->activity();
    return m;
}

}  // anonymous namespace

/* Extract and validate our session cookie. httpd_req_get_cookie_val parses the
 * named cookie with framework-maintained RFC handling and reads only the "sid"
 * value, so it isn't defeated by other cookies or whole-header truncation. */
bool ApiServer::authed(httpd_req_t *r)
{
    char tok[VS_TOKEN_HEX];
    size_t len = sizeof tok;
    if (httpd_req_get_cookie_val(r, "sid", tok, &len) != ESP_OK) return false;
    return session_.validate(tok, now_ms());
}

/* ---- /api/state ---- */
esp_err_t ApiServer::h_state_impl(httpd_req_t *r)
{
    cJSON *o = cJSON_CreateObject();
    cJSON_AddBoolToObject(o, "initialized", vault_.is_initialized());
    cJSON_AddBoolToObject(o, "unlocked", authed(r) && vault_.is_unlocked());
    /* Let the client mirror the server's idle auto-lock instead of hardcoding it. */
    cJSON_AddNumberToObject(o, "idle_ms", VS_IDLE_MS);
    return send_json(r, 200, o);
}

/* ---- /api/setup ---- */
esp_err_t ApiServer::h_setup_impl(httpd_req_t *r)
{
    char *body = read_body(r); if (!body) return err_json(r,400,"bad body");
    cJSON *j = cJSON_Parse(body); free(body);
    if (!j) return err_json(r,400,"bad json");
    const char *pw = json_str(j,"password");
    const char *tpw = json_str(j,"transfer_password");
    if (strlen(pw) == 0 || strlen(tpw) == 0) { cJSON_Delete(j); return err_json(r,400,"both passwords required"); }
    try { vault_.setup(pw, strlen(pw)); }
    catch (const vault::Error&) { cJSON_Delete(j); return err_json(r,400,"already initialized"); }
    /* Two back-to-back PBKDF2 derivations on this task; yield so the idle task
     * runs and the task watchdog is satisfied between them. */
    vTaskDelay(pdMS_TO_TICKS(20));
    try { vault_.set_transfer_password(tpw, strlen(tpw)); }
    catch (...) { vault_.factory_reset(); cJSON_Delete(j); return err_json(r,500,"setup failed, try again"); }
    cJSON_Delete(j);
    char tok[VS_TOKEN_HEX]; session_.create(now_ms(), tok);
    char hdr[128]; snprintf(hdr,sizeof hdr,"sid=%s; HttpOnly; Secure; Path=/; SameSite=Strict", tok);
    httpd_resp_set_hdr(r, "Set-Cookie", hdr);
    return send_json(r, 200, cJSON_CreateObject());
}

/* ---- /api/login ---- */
esp_err_t ApiServer::h_login_impl(httpd_req_t *r)
{
    if (!session_.login_allowed(now_ms())) return err_json(r,403,"locked out, try later");
    char *body = read_body(r); if (!body) return err_json(r,400,"bad body");
    cJSON *j = cJSON_Parse(body); free(body);
    if (!j) return err_json(r,400,"bad json");
    const char *pw = json_str(j,"password");
    /* Reject empty password before counting it: otherwise empty-body POSTs
     * would burn the lockout budget and DoS the legitimate user. */
    if (strlen(pw) == 0) { cJSON_Delete(j); return err_json(r,400,"password required"); }
    bool ok;
    try { ok = vault_.unlock(pw, strlen(pw)); }
    catch (const vault::Error&) { ok = false; }
    cJSON_Delete(j);
    session_.note_login_result(ok, now_ms());
    if (!ok) return err_json(r,401,"invalid password");
    char tok[VS_TOKEN_HEX]; session_.create(now_ms(), tok);
    char hdr[128]; snprintf(hdr,sizeof hdr,"sid=%s; HttpOnly; Secure; Path=/; SameSite=Strict", tok);
    httpd_resp_set_hdr(r, "Set-Cookie", hdr);
    return send_json(r, 200, cJSON_CreateObject());
}

/* ---- /api/logout ---- */
esp_err_t ApiServer::h_logout_impl(httpd_req_t *r)
{
    if (!authed(r)) return err_json(r,401,"unauthorized");
    session_.destroy(); vault_.lock();
    return send_json(r, 200, cJSON_CreateObject());
}

/* ---- GET /api/entries ---- */
esp_err_t ApiServer::h_entries_list_impl(httpd_req_t *r)
{
    if (!authed(r)) return err_json(r,401,"unauthorized");
    static vault_entry_t list[VAULT_MAX_ENTRIES]; size_t n = 0;
    try { n = vault_.list(list, VAULT_MAX_ENTRIES); }
    catch (const vault::Error&) { return err_json(r,403,"locked"); }
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
esp_err_t ApiServer::h_entries_add_impl(httpd_req_t *r)
{
    if (!authed(r)) return err_json(r,401,"unauthorized");
    char *body = read_body(r); if (!body) return err_json(r,400,"bad body");
    cJSON *j = cJSON_Parse(body); free(body);
    if (!j) return err_json(r,400,"bad json");
    uint8_t id;
    try { id = vault_.add(json_str(j,"title"), json_str(j,"username"), json_str(j,"secret"),
                          json_str(j,"url"), json_str(j,"comment"),
                          (uint8_t)json_int(j,"category")); }
    catch (const vault::Error&) { cJSON_Delete(j); return err_json(r,400,"add failed"); }
    cJSON_Delete(j);
    cJSON *o=cJSON_CreateObject(); cJSON_AddNumberToObject(o,"id",id);
    return send_json(r, 200, o);
}

/* ---- GET /api/entries/{id}/secret ---- */
esp_err_t ApiServer::h_entry_secret_impl(httpd_req_t *r)
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
    if (!vault_.reveal((uint8_t)id, secret, url, comment)) return err_json(r,404,"not found");
    cJSON *o=cJSON_CreateObject();
    cJSON_AddStringToObject(o,"secret",secret);
    cJSON_AddStringToObject(o,"url",url);
    cJSON_AddStringToObject(o,"comment",comment);
    return send_json(r, 200, o);
}

/* ---- PUT /api/entries/{id} ---- */
esp_err_t ApiServer::h_entry_update_impl(httpd_req_t *r)
{
    if (!authed(r)) return err_json(r,401,"unauthorized");
    int id = uri_id(r); if (id < 0) return err_json(r,400,"bad id");
    char *body = read_body(r); if (!body) return err_json(r,400,"bad body");
    cJSON *j = cJSON_Parse(body); free(body);
    if (!j) return err_json(r,400,"bad json");
    bool ok = vault_.update((uint8_t)id, json_str(j,"title"), json_str(j,"username"),
                            json_str(j,"secret"), json_str(j,"url"), json_str(j,"comment"),
                            (uint8_t)json_int(j,"category"));
    cJSON_Delete(j);
    if (!ok) return err_json(r,404,"not found");
    return send_json(r, 200, cJSON_CreateObject());
}

/* ---- GET /api/categories ---- */
esp_err_t ApiServer::h_cats_list_impl(httpd_req_t *r)
{
    if (!authed(r)) return err_json(r,401,"unauthorized");
    static vault_category_t cats[VAULT_MAX_CATEGORIES]; size_t n = 0;
    try { n = vault_.category_list(cats, VAULT_MAX_CATEGORIES); }
    catch (const vault::Error&) { return err_json(r,403,"locked"); }
    cJSON *o = cJSON_CreateObject(); cJSON *arr = cJSON_AddArrayToObject(o,"categories");
    for (size_t i=0;i<n;i++){ cJSON *c=cJSON_CreateObject();
        cJSON_AddNumberToObject(c,"id",cats[i].id);
        cJSON_AddStringToObject(c,"name",cats[i].name);
        cJSON_AddItemToArray(arr,c); }
    return send_json(r, 200, o);
}

/* ---- POST /api/categories ---- body {name} */
esp_err_t ApiServer::h_cats_add_impl(httpd_req_t *r)
{
    if (!authed(r)) return err_json(r,401,"unauthorized");
    char *body = read_body(r); if (!body) return err_json(r,400,"bad body");
    cJSON *j = cJSON_Parse(body); free(body);
    if (!j) return err_json(r,400,"bad json");
    const char *name = json_str(j,"name");
    uint8_t id;
    try { id = vault_.category_add(name); }
    catch (const vault::Error& e) {
        cJSON_Delete(j);
        if (e.code() == ESP_ERR_INVALID_STATE) return err_json(r,409,"category exists");
        return err_json(r,400,"add failed");
    }
    cJSON_Delete(j);
    cJSON *o=cJSON_CreateObject(); cJSON_AddNumberToObject(o,"id",id);
    return send_json(r, 200, o);
}

/* ---- DELETE /api/categories/{id} ---- */
esp_err_t ApiServer::h_cat_delete_impl(httpd_req_t *r)
{
    if (!authed(r)) return err_json(r,401,"unauthorized");
    int id = uri_cat_id(r); if (id <= 0) return err_json(r,400,"bad id");
    if (!vault_.category_delete((uint8_t)id)) return err_json(r,404,"not found");
    return send_json(r, 200, cJSON_CreateObject());
}

/* ---- DELETE /api/entries/{id} ---- */
esp_err_t ApiServer::h_entry_delete_impl(httpd_req_t *r)
{
    if (!authed(r)) return err_json(r,401,"unauthorized");
    int id = uri_id(r); if (id < 0) return err_json(r,400,"bad id");
    if (!vault_.remove((uint8_t)id)) return err_json(r,404,"not found");
    return send_json(r, 200, cJSON_CreateObject());
}

/* ---- POST /api/change-password ---- */
esp_err_t ApiServer::h_change_pw_impl(httpd_req_t *r)
{
    if (!authed(r)) return err_json(r,401,"unauthorized");
    char *body = read_body(r); if (!body) return err_json(r,400,"bad body");
    cJSON *j = cJSON_Parse(body); free(body);
    if (!j) return err_json(r,400,"bad json");
    const char *cur = json_str(j,"current"), *next = json_str(j,"next");
    if (next[0] == '\0') { cJSON_Delete(j); return err_json(r,400,"new password required"); }
    bool ok = vault_.change_password(cur, strlen(cur), next, strlen(next));
    cJSON_Delete(j);
    if (!ok) return err_json(r,403,"wrong current password");
    return send_json(r, 200, cJSON_CreateObject());
}

/* ---- POST /api/change-transfer ---- body {current, next}; rotate the transfer
 * password. Mirrors change-password: requires the unlocked session plus the
 * correct current transfer password. */
esp_err_t ApiServer::h_change_transfer_impl(httpd_req_t *r)
{
    if (!authed(r)) return err_json(r,401,"unauthorized");
    char *body = read_body(r); if (!body) return err_json(r,400,"bad body");
    cJSON *j = cJSON_Parse(body); free(body);
    if (!j) return err_json(r,400,"bad json");
    const char *cur = json_str(j,"current"), *next = json_str(j,"next");
    if (next[0] == '\0') { cJSON_Delete(j); return err_json(r,400,"new password required"); }
    bool changed = false;
    bool ok = vault_.verify_transfer(cur, strlen(cur));
    if (ok) {
        try { vault_.set_transfer_password(next, strlen(next)); changed = true; }
        catch (...) { changed = false; }
    }
    cJSON_Delete(j);
    if (!ok) return err_json(r,403,"wrong transfer password");
    if (!changed) return err_json(r,400,"change failed");
    return send_json(r, 200, cJSON_CreateObject());
}

/* ---- POST /api/export ---- body {transfer_password}; returns a PLAINTEXT JSON
 * file of every entry, for migrating into another password manager. The transfer
 * password is still required as an intent gate, but the file is NOT encrypted:
 * all secrets are in clear text. Category is emitted by name so it survives a
 * round-trip into a vault with different category ids. */
esp_err_t ApiServer::h_export_impl(httpd_req_t *r)
{
    if (!authed(r)) return err_json(r,401,"unauthorized");
    char *body = read_body(r); if (!body) return err_json(r,400,"bad body");
    cJSON *j = cJSON_Parse(body); free(body);
    if (!j) return err_json(r,400,"bad json");
    const char *tpw = json_str(j,"transfer_password");
    bool ok = vault_.verify_transfer(tpw, strlen(tpw));
    cJSON_Delete(j);
    if (!ok) return err_json(r,403,"wrong transfer password");

    vault_entry_t *list = (vault_entry_t*)malloc(VAULT_MAX_ENTRIES * sizeof *list);
    if (!list) return err_json(r,500,"oom");
    size_t n = 0;
    try { n = vault_.list(list, VAULT_MAX_ENTRIES); }
    catch (const vault::Error&) { free(list); return err_json(r,403,"locked"); }
    static vault_category_t cats[VAULT_MAX_CATEGORIES]; size_t cn = 0;
    cn = vault_.category_list(cats, VAULT_MAX_CATEGORIES);

    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o,"format","esp32key-export");
    cJSON_AddNumberToObject(o,"version",1);
    cJSON *arr = cJSON_AddArrayToObject(o,"entries");
    for (size_t i = 0; i < n; i++) {
        char secret[VAULT_FIELD_MAX], url[VAULT_FIELD_MAX], comment[VAULT_FIELD_MAX];
        if (!vault_.reveal(list[i].id, secret, url, comment)) { secret[0]=url[0]=comment[0]='\0'; }
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

/* ---- POST /api/reset ---- body {transfer_password}; deletes every entry.
 * Gated by the transfer password (same intent gate as export), not just the
 * session cookie, since it is irreversible. Categories and the master/transfer
 * passwords are preserved — the vault stays set up and unlocked. */
esp_err_t ApiServer::h_reset_impl(httpd_req_t *r)
{
    if (!authed(r)) return err_json(r,401,"unauthorized");
    char *body = read_body(r); if (!body) return err_json(r,400,"bad body");
    cJSON *j = cJSON_Parse(body); free(body);
    if (!j) return err_json(r,400,"bad json");
    const char *tpw = json_str(j,"transfer_password");
    bool ok = vault_.verify_transfer(tpw, strlen(tpw));
    cJSON_Delete(j);
    if (!ok) return err_json(r,403,"wrong transfer password");
    try { vault_.clear_entries(); }
    catch (...) { return err_json(r,500,"reset failed"); }
    cJSON *o = cJSON_CreateObject(); cJSON_AddBoolToObject(o,"ok",true);
    return send_json(r,200,o);
}

/* ---- POST /api/import ---- body is a plaintext export file
 * {format,version,entries:[{title,username,url,secret,comment,category}]}.
 * Merge: an imported entry replaces a local one with the same title+username;
 * others are added. Category is matched by name; unknown -> Uncategorized.
 * No transfer password: the file is already plaintext and the session cookie
 * already grants full write access. */
esp_err_t ApiServer::h_import_impl(httpd_req_t *r)
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

    vault_entry_t *list = (vault_entry_t*)malloc(VAULT_MAX_ENTRIES * sizeof *list);
    if (!list) { cJSON_Delete(j); return err_json(r,500,"oom"); }
    size_t n = 0;
    try { n = vault_.list(list, VAULT_MAX_ENTRIES); }
    catch (const vault::Error&) { free(list); cJSON_Delete(j); return err_json(r,403,"locked"); }
    static vault_category_t cats[VAULT_MAX_CATEGORIES]; size_t cn = 0;
    cn = vault_.category_list(cats, VAULT_MAX_CATEGORIES);

    /* One NVS commit for the whole import, not one per entry: faster, far less
     * flash wear, and all-or-nothing on disk (a crash mid-loop leaves the old
     * vault, not a half-merged one). */
    vault_.bulk_begin();
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

        if (match_id >= 0) {
            if (vault_.update((uint8_t)match_id, title, user, sec, url, cmt, cat)) imported++;
        } else {
            try {
                uint8_t nid = vault_.add(title, user, sec, url, cmt, cat);
                if (n < VAULT_MAX_ENTRIES) {
                    list[n].id = nid;
                    strlcpy(list[n].title, title, VAULT_FIELD_MAX);
                    strlcpy(list[n].username, user, VAULT_FIELD_MAX);
                    n++;
                }
                imported++;
            } catch (const vault::Error&) {
                /* capacity reached: stop adding, continue */
            }
        }
    }
    try { vault_.bulk_commit(); }
    catch (...) { free(list); cJSON_Delete(j); return err_json(r,500,"import save failed"); }
    free(list); cJSON_Delete(j);
    cJSON *o = cJSON_CreateObject(); cJSON_AddNumberToObject(o,"imported",imported);
    return send_json(r, 200, o);
}

/* Auto-lock idle sessions. An esp_timer callback runs on the timer task, but
 * vault/session state is otherwise only ever touched from the httpd task and is
 * not synchronized -- so the timer hands the check to the httpd task via
 * httpd_queue_work, keeping it serialized with request handlers. */
void ApiServer::idle_lock_work(void *arg)
{
    auto *self = static_cast<ApiServer*>(arg);
    try { self->session_.check_idle(now_ms()); } catch (...) {}
}

void ApiServer::idle_timer_cb(void *arg)
{
    auto *self = static_cast<ApiServer*>(arg);
    if (self->srv_) httpd_queue_work(self->srv_, idle_lock_work, self);
}

/* Each request handler gets a static trampoline that recovers `this` from
 * r->user_ctx, calls the matching _impl member, and maps any exception to a
 * 500 JSON error so a throw can never escape into the httpd C stack. */
#define API_HANDLER(NAME)                                                       \
    static esp_err_t NAME(httpd_req_t* r) {                                      \
        auto* self = static_cast<ApiServer*>(r->user_ctx);                       \
        try { return self->NAME##_impl(r); }                                     \
        catch (const vault::Error& e) { return err_json(r, 500, e.what()); }     \
        catch (const std::exception& e) { return err_json(r, 500, e.what()); }   \
        catch (...) { return err_json(r, 500, "internal error"); }               \
    }

/* These live at vault namespace scope (not anonymous) so the `friend` declarations
 * in the class refer to the same entities; `static` still gives them internal
 * linkage. */
namespace vault {
API_HANDLER(h_state)
API_HANDLER(h_setup)
API_HANDLER(h_login)
API_HANDLER(h_logout)
API_HANDLER(h_entries_list)
API_HANDLER(h_entries_add)
API_HANDLER(h_entry_secret)
API_HANDLER(h_entry_update)
API_HANDLER(h_entry_delete)
API_HANDLER(h_cats_list)
API_HANDLER(h_cats_add)
API_HANDLER(h_cat_delete)
API_HANDLER(h_change_pw)
API_HANDLER(h_change_transfer)
API_HANDLER(h_export)
API_HANDLER(h_reset)
API_HANDLER(h_import)
}  // namespace vault

void ApiServer::start(const char *cert_pem, size_t cert_len,
                      const char *key_pem, size_t key_len)
{
    s_instance = this;
    s_led = &led_;

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
    cfg.httpd.uri_match_fn = uri_match_activity;
    /* Pin the server (TLS handshake + all API handlers) to CPU1, away from the
     * USB+Wi-Fi+system tasks that are all pinned to CPU0. */
    cfg.httpd.core_id = 1;

    esp_err_t e = httpd_ssl_start(&srv_, &cfg);
    if (e != ESP_OK) { ESP_LOGE(TAG, "https start failed: %s", esp_err_to_name(e)); throw vault::Error(e, "https start"); }

    const httpd_uri_t routes[] = {
        {"/",                       HTTP_GET,    h_index,           this},
        {"/api/state",              HTTP_GET,    h_state,           this},
        {"/api/setup",              HTTP_POST,   h_setup,           this},
        {"/api/login",              HTTP_POST,   h_login,           this},
        {"/api/logout",             HTTP_POST,   h_logout,          this},
        {"/api/change-password",    HTTP_POST,   h_change_pw,       this},
        {"/api/change-transfer",    HTTP_POST,   h_change_transfer, this},
        {"/api/export",             HTTP_POST,   h_export,          this},
        {"/api/import",             HTTP_POST,   h_import,          this},
        {"/api/reset",              HTTP_POST,   h_reset,           this},
        {"/api/entries",            HTTP_GET,    h_entries_list,    this},
        {"/api/entries",            HTTP_POST,   h_entries_add,     this},
        {"/api/entries/*",          HTTP_GET,    h_entry_secret,    this},
        {"/api/entries/*",          HTTP_PUT,    h_entry_update,    this},
        {"/api/entries/*",          HTTP_DELETE, h_entry_delete,    this},
        {"/api/categories",         HTTP_GET,    h_cats_list,       this},
        {"/api/categories",         HTTP_POST,   h_cats_add,        this},
        {"/api/categories/*",       HTTP_DELETE, h_cat_delete,      this},
    };
    for (auto& route : routes)
        httpd_register_uri_handler(srv_, &route);

    /* Auto-lock after VS_IDLE_MS (3 min). Poll every 5 s so the lock (and the
     * LED's switch to red) lands promptly after the green fade bottoms out; the
     * lock itself runs on the httpd task (see idle_timer_cb) so it can't race a
     * live handler. */
    esp_timer_create_args_t idle_args = {};
    idle_args.callback = idle_timer_cb;
    idle_args.arg = this;
    idle_args.name = "idle_lock";
    esp_timer_handle_t idle_t;
    if (esp_timer_create(&idle_args, &idle_t) == ESP_OK)
        esp_timer_start_periodic(idle_t, 5ULL * 1000 * 1000);
    else
        ESP_LOGW(TAG, "idle-lock timer failed; vault still locks lazily on next request");
}
