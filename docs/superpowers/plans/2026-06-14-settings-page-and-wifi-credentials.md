# Settings Page + WiFi AP Credential Change Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a sidebar **Settings** page that hosts the Auto-lock control, Clear Entries, Reset Device, and a new **WiFi AP SSID/password** form; AP credentials persist in NVS and apply on an automatic reboot.

**Architecture:** `WifiAp` owns its credential storage — it reads `ap_ssid`/`ap_pw` from NVS at boot (falling back to factory defaults) and exposes `set_credentials()` + `ssid()`. `ApiServer` gains a `WifiAp&`, validates input on `POST /api/wifi`, persists via the setter, then arms a one-shot timer to `esp_restart()` so the device comes back up on the new credentials. The UI moves config/destructive actions off the sidebar into a new `renderSettings()` page.

**Tech Stack:** C++17, ESP-IDF v6.0.1 (esp_wifi, esp_timer, esp_system), NVS (`vault::Store`), esp_https_server, cJSON, vanilla JS/HTML.

---

## Reference: build commands

Builds run via the **PowerShell tool**, in the **background** (poll/await; first build of a project is slow, incrementals fast).

**Main firmware** (working dir `D:\Workspace\esp32key`):
```
$env:MSYSTEM = $null; . C:\esp\v6.0.1\esp-idf\export.ps1; idf.py build
```
**Test runner** (`test_app`):
```
Set-Location D:\Workspace\esp32key\test_app; $env:MSYSTEM = $null; . C:\esp\v6.0.1\esp-idf\export.ps1; idf.py build
```
Success prints `Project build complete`. Stale-generator CMake error → `Remove-Item -Recurse -Force <proj>\build` and rebuild.

**On tests:** the backend here (`net_wifi_ap`, `vault_api`) touches the WiFi radio / HTTP layer and is NOT host/doctest-testable — like the other net components, it has no unit tests. Verification for these tasks is a clean **build** of both projects (the `test_app` build confirms the existing doctest suite still compiles/links) plus the on-device checklist in Task 4. There are no TDD test-first steps in this plan.

---

## File Structure

- `components/net_wifi_ap/include/net_wifi_ap.h` — `Store&` ctor, new `start()` signature, `set_credentials()`, `ssid()`, members.
- `components/net_wifi_ap/net_wifi_ap.cpp` — NVS keys, load-or-default at start, setter, ssid cache.
- `components/net_wifi_ap/CMakeLists.txt` — add `vault_store` to `REQUIRES`.
- `components/vault_api/include/vault_api.h` — include + `WifiAp&` ctor/member + 2 handler decls/trampolines.
- `components/vault_api/vault_api.cpp` — reboot helper, `GET`/`POST /api/wifi`, route + trampoline registration, `max_uri_handlers` bump.
- `components/vault_api/CMakeLists.txt` — add `net_wifi_ap` to `REQUIRES`.
- `main/main.cpp` — new `WifiAp` ctor/start args; pass `wifi` into `ApiServer`.
- `components/vault_api/www/index.html` — sidebar Settings button; `renderSettings()`; Back targets in `renderClear`/`renderReset`.

---

## Task 1: `net_wifi_ap` — persist + load AP credentials

**Files:**
- Modify: `components/net_wifi_ap/include/net_wifi_ap.h`
- Modify: `components/net_wifi_ap/net_wifi_ap.cpp`
- Modify: `components/net_wifi_ap/CMakeLists.txt`
- Modify: `main/main.cpp`

- [ ] **Step 1: Rewrite the header**

Replace the entire contents of `components/net_wifi_ap/include/net_wifi_ap.h` with:
```cpp
#pragma once
#include <cstddef>
#include "vault_store.h"

namespace vault {

// Brings up softAP with persisted SSID/password (or the passed factory defaults
// if none saved). WPA2 when the password is >=8 chars, else OPEN. Assumes
// esp_netif_init() + esp_event_loop_create_default() already ran.
class WifiAp {
public:
    explicit WifiAp(Store& store) : store_(store) {}

    // Load saved creds (or defaults) and start the AP. Throws vault::Error on failure.
    void start(const char* default_ssid, const char* default_password);

    // Persist new SSID + password to NVS (does NOT apply live; caller reboots).
    // Throws vault::Error on NVS fault.
    void set_credentials(const char* ssid, const char* password);

    const char* ssid() const { return ssid_; }   // active SSID (for UI prefill)

private:
    void load_or_default(const char* key, const char* def, char* buf, size_t buflen);

    Store& store_;
    char   ssid_[33] = "esp32key";   // 32-char 802.11 max + NUL
};

}  // namespace vault
```

- [ ] **Step 2: Rewrite the implementation**

Replace the entire contents of `components/net_wifi_ap/net_wifi_ap.cpp` with:
```cpp
#include "net_wifi_ap.h"
#include "vault_error.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include <cstring>

namespace vault {

namespace {
const char SSID_KEY[] = "ap_ssid";   // NVS keys (<=15 chars)
const char PW_KEY[]   = "ap_pw";
}

void WifiAp::load_or_default(const char* key, const char* def, char* buf, size_t buflen) {
    size_t len = buflen;
    bool got = false;
    try { got = store_.get_blob(key, buf, len); } catch (...) { got = false; }
    if (!got) { strlcpy(buf, def, buflen); return; }
    buf[buflen - 1] = '\0';   // defensive: ensure NUL-terminated
}

void WifiAp::start(const char* default_ssid, const char* default_password) {
    esp_netif_create_default_wifi_ap();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    check(esp_wifi_init(&cfg), "wifi init");

    char pw[64];
    load_or_default(SSID_KEY, default_ssid,     ssid_, sizeof ssid_);
    load_or_default(PW_KEY,   default_password, pw,    sizeof pw);

    wifi_config_t ap = {};
    strlcpy((char*)ap.ap.ssid, ssid_, sizeof ap.ap.ssid);
    ap.ap.ssid_len = strlen(ssid_);
    ap.ap.channel = 1;
    ap.ap.max_connection = 2;
    ap.ap.authmode = WIFI_AUTH_WPA2_PSK;
    strlcpy((char*)ap.ap.password, pw, sizeof ap.ap.password);
    if (strlen(pw) < 8) ap.ap.authmode = WIFI_AUTH_OPEN;  // avoid silent fail

    check(esp_wifi_set_mode(WIFI_MODE_AP), "wifi mode");
    check(esp_wifi_set_config(WIFI_IF_AP, &ap), "wifi config");
    check(esp_wifi_start(), "wifi start");
}

void WifiAp::set_credentials(const char* ssid, const char* password) {
    store_.set_blob(SSID_KEY, ssid, strlen(ssid) + 1);
    store_.set_blob(PW_KEY, password, strlen(password) + 1);
    store_.commit();
}

}  // namespace vault
```

- [ ] **Step 3: Add `vault_store` to the component requires**

In `components/net_wifi_ap/CMakeLists.txt`, change the `REQUIRES` line to:
```cmake
idf_component_register(SRCS "net_wifi_ap.cpp"
                       INCLUDE_DIRS "include"
                       REQUIRES esp_wifi esp_netif vault_error vault_store)
```

- [ ] **Step 4: Update `main.cpp` to the new ctor/start signature**

In `main/main.cpp`, replace:
```cpp
        static vault::WifiAp wifi; wifi.start(AP_PASSWORD);
```
with:
```cpp
        static vault::WifiAp wifi(store); wifi.start("esp32key", AP_PASSWORD);
```
(Leave the `#define AP_PASSWORD ...` as the factory default. Leave the `ApiServer api(...)` line unchanged in this task — it is updated in Task 2.)

- [ ] **Step 5: Build the main firmware**

Run (PowerShell, background, await; working dir `D:\Workspace\esp32key`):
```
$env:MSYSTEM = $null; . C:\esp\v6.0.1\esp-idf\export.ps1; idf.py build
```
Expected: **`Project build complete`**. (`WifiAp` is self-consistent; `ApiServer` is untouched, so the tree still compiles.)

- [ ] **Step 6: Commit**

```bash
git add components/net_wifi_ap main/main.cpp
git commit -m "net_wifi_ap: persist AP SSID/password in NVS, load-or-default at boot"
```

---

## Task 2: `vault_api` — GET/POST /api/wifi + reboot-to-apply

**Files:**
- Modify: `components/vault_api/include/vault_api.h`
- Modify: `components/vault_api/vault_api.cpp`
- Modify: `components/vault_api/CMakeLists.txt`
- Modify: `main/main.cpp`

- [ ] **Step 1: Add `net_wifi_ap` to the component requires**

In `components/vault_api/CMakeLists.txt`, change the `REQUIRES` line to (append `net_wifi_ap`):
```cmake
                       REQUIRES esp_https_server cjson vault vault_store vault_session esp_timer mbedtls status_led vault_error net_wifi_ap
```

- [ ] **Step 2: Header — include, ctor arg, member, handler decls**

In `components/vault_api/include/vault_api.h`:

Add the include after `#include "status_led.h"`:
```cpp
#include "net_wifi_ap.h"
```

Change the constructor and member block. Replace:
```cpp
    ApiServer(Vault& vault, Session& session, StatusLed& led, Store& store)
        : vault_(vault), session_(session), led_(led), store_(store) {}
```
with:
```cpp
    ApiServer(Vault& vault, Session& session, StatusLed& led, Store& store, WifiAp& wifi)
        : vault_(vault), session_(session), led_(led), store_(store), wifi_(wifi) {}
```
And replace:
```cpp
    Vault&     vault_;
    Session&   session_;
    StatusLed& led_;
    Store&     store_;
    httpd_handle_t srv_ = nullptr;
```
with:
```cpp
    Vault&     vault_;
    Session&   session_;
    StatusLed& led_;
    Store&     store_;
    WifiAp&    wifi_;
    httpd_handle_t srv_ = nullptr;
```

Add the two `*_impl` declarations after `esp_err_t h_idle_set_impl(httpd_req_t* r);`:
```cpp
    esp_err_t h_wifi_get_impl(httpd_req_t* r);
    esp_err_t h_wifi_set_impl(httpd_req_t* r);
```
And the two static trampolines after `static esp_err_t h_idle_set(httpd_req_t*);`:
```cpp
    static esp_err_t h_wifi_get(httpd_req_t*);
    static esp_err_t h_wifi_set(httpd_req_t*);
```

- [ ] **Step 3: Add the `esp_system.h` include for `esp_restart`**

In `components/vault_api/vault_api.cpp`, add after `#include "esp_timer.h"`:
```cpp
#include "esp_system.h"
```

- [ ] **Step 4: Add the reboot helper in the anonymous namespace**

In `components/vault_api/vault_api.cpp`, inside the existing `namespace {` block (e.g. right after the `IDLE_MS_KEY` constant), add:
```cpp
/* One-shot esp_timer callback: reboot so a saved AP-credential change takes
 * effect. Armed ~1.5 s out so the HTTP 200 flushes before the restart. */
static void reboot_cb(void*) { esp_restart(); }
```

- [ ] **Step 5: Add the two handlers after `h_idle_set_impl`**

In `components/vault_api/vault_api.cpp`, immediately after the closing `}` of `h_idle_set_impl` (before `h_setup_impl`), add:
```cpp
/* ---- GET /api/wifi ---- current AP SSID (authed). Password is never returned. */
esp_err_t ApiServer::h_wifi_get_impl(httpd_req_t *r)
{
    if (!authed(r)) return err_json(r, 401, "locked");
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "ssid", wifi_.ssid());
    return send_json(r, 200, o);
}

/* ---- POST /api/wifi ---- set AP SSID+password (authed), persist, then reboot. */
esp_err_t ApiServer::h_wifi_set_impl(httpd_req_t *r)
{
    if (!authed(r)) return err_json(r, 401, "locked");
    char *body = read_body(r); if (!body) return err_json(r,400,"bad body");
    cJSON *j = cJSON_Parse(body); free(body);
    if (!j) return err_json(r,400,"bad json");
    const char *ssid_s = json_str(j, "ssid");
    const char *pw_s   = json_str(j, "password");
    size_t sl = strlen(ssid_s), pl = strlen(pw_s);
    if (sl < 1 || sl > 32) { cJSON_Delete(j); return err_json(r,400,"ssid must be 1-32 chars"); }
    if (pl < 8 || pl > 63) { cJSON_Delete(j); return err_json(r,400,"password must be 8-63 chars"); }
    /* Copy out before freeing j; lengths are validated so these can't truncate. */
    char ssid[33], pw[64];
    strlcpy(ssid, ssid_s, sizeof ssid);
    strlcpy(pw,   pw_s,   sizeof pw);
    cJSON_Delete(j);
    wifi_.set_credentials(ssid, pw);   // throws on NVS fault -> 500 via trampoline
    /* Reboot shortly so the AP restarts on the new creds; delay lets the 200 flush. */
    esp_timer_create_args_t ra = {}; ra.callback = reboot_cb; ra.name = "reboot";
    esp_timer_handle_t rt;
    if (esp_timer_create(&ra, &rt) == ESP_OK) esp_timer_start_once(rt, 1500ULL * 1000);
    return send_json(r, 200, cJSON_CreateObject());
}
```

- [ ] **Step 6: Register the trampolines**

In `components/vault_api/vault_api.cpp`, in the `API_HANDLER(...)` block, add after `API_HANDLER(h_idle_set)`:
```cpp
API_HANDLER(h_idle_set)
API_HANDLER(h_wifi_get)
API_HANDLER(h_wifi_set)
```

- [ ] **Step 7: Register the routes and bump the handler cap**

In `components/vault_api/vault_api.cpp`, in `start()`, change:
```cpp
    cfg.httpd.max_uri_handlers = 20;
```
to:
```cpp
    cfg.httpd.max_uri_handlers = 24;
```
And in the `routes[]` array, add after the `/api/idle` line:
```cpp
        {"/api/idle",               HTTP_POST,   h_idle_set,        this},
        {"/api/wifi",               HTTP_GET,    h_wifi_get,        this},
        {"/api/wifi",               HTTP_POST,   h_wifi_set,        this},
```

- [ ] **Step 8: Pass `wifi` into `ApiServer` in `main.cpp`**

In `main/main.cpp`, replace:
```cpp
        static vault::ApiServer api(vault, session, led, store);
```
with:
```cpp
        static vault::ApiServer api(vault, session, led, store, wifi);
```

- [ ] **Step 9: Build the main firmware**

Run (PowerShell, background, await; working dir `D:\Workspace\esp32key`):
```
$env:MSYSTEM = $null; . C:\esp\v6.0.1\esp-idf\export.ps1; idf.py build
```
Expected: **`Project build complete`**.

- [ ] **Step 10: Commit**

```bash
git add components/vault_api main/main.cpp
git commit -m "vault_api: GET/POST /api/wifi to change AP credentials, reboot to apply"
```

---

## Task 3: UI — Settings page + sidebar reorg

**Files:**
- Modify: `components/vault_api/www/index.html`

- [ ] **Step 1: Sidebar — drop Clear/Reset/Auto-lock, add Settings**

In `components/vault_api/www/index.html`, in `paint()`'s sidebar template, replace this block:
```html
      <div class=row style="margin-top:.6rem"><button id=xfer>Transfer Entries</button>
        <button id=lock>Lock</button></div>
      <div class=row style="margin-top:.4rem"><button id=clear>Clear Entries</button>
        <button id=reset>Reset Device</button></div>
      <div style="margin-top:.6rem">
        <label for=idlesec style="display:block;font-size:.8rem;font-weight:600;color:#555">Auto-lock after (seconds)</label>
        <input id=idlesec type=number min=30 max=3600 step=10>
        <button id=idlesave>Save timeout</button>
        <div class=warn id=idlemsg></div>
      </div>
```
with:
```html
      <div class=row style="margin-top:.6rem"><button id=xfer>Transfer Entries</button>
        <button id=lock>Lock</button></div>
      <div class=row style="margin-top:.4rem"><button id=settings>Settings</button></div>
```

- [ ] **Step 2: paint() handler wiring — remove idle + clear/reset, add settings**

In `paint()`, remove the moved Auto-lock wiring block (the `$('#idlesec').value = ...` line and the entire `$('#idlesave').onclick = async () => { ... };` handler):
```js
  $('#idlesec').value = Math.round(idleMs / 1000);
  $('#idlesave').onclick = async () => {
    const secs = Number($('#idlesec').value);
    const msg = $('#idlemsg');
    if (!Number.isInteger(secs) || secs < 30 || secs > 3600) {
      msg.style.color = '#b00'; msg.textContent = 'Enter 30–3600 seconds.'; return;
    }
    try {
      await api('/api/idle', {method:'POST', body:JSON.stringify({seconds:secs})});
      idleMs = secs * 1000;          // update the client mirror of the auto-lock window
      armIdle();                      // re-arm with the new window
      msg.style.color = '#070'; msg.textContent = 'Saved.';
    } catch (e) { msg.style.color = '#b00'; msg.textContent = e.message; }
  };
```
Then find the sidebar button wiring near the bottom of `paint()`:
```js
  $('#xfer').onclick = renderTransfer;
  $('#clear').onclick = renderClear;
  $('#reset').onclick = renderReset;
  const lock = async()=>{ try{ await api('/api/logout',{method:'POST'}); }catch(e){} boot(); };
  $('#lock').onclick = lock;
  $('#logolock').onclick = lock;   /* clicking the sidebar logo also locks */
```
and replace the `#clear`/`#reset` lines with a `#settings` line:
```js
  $('#xfer').onclick = renderTransfer;
  $('#settings').onclick = renderSettings;
  const lock = async()=>{ try{ await api('/api/logout',{method:'POST'}); }catch(e){} boot(); };
  $('#lock').onclick = lock;
  $('#logolock').onclick = lock;   /* clicking the sidebar logo also locks */
```

- [ ] **Step 3: Add `renderSettings()`**

In `components/vault_api/www/index.html`, add this function immediately BEFORE `function renderClear() {`:
```js
async function renderSettings() {
  let ssid = '';
  try { ssid = (await api('/api/wifi')).ssid || ''; } catch(_){}
  $('#app').innerHTML = `<img class=logo src="${LOGO}" alt="esp32key">
    <h2>Settings</h2>
    <h3>WiFi access point</h3>
    <p class=warn>Saving new WiFi settings restarts the device. You'll need to reconnect to the new network and unlock again.</p>
    <input id=apssid placeholder="AP name (SSID)" maxlength=32 value="${esc(ssid)}">
    <input id=appw type=password placeholder="New AP password (8-63 chars)" autocomplete="off">
    <button id=apsave>Save WiFi &amp; restart</button>
    <div class=warn id=apmsg></div>
    <h3>Auto-lock</h3>
    <label for=idlesec style="display:block;font-size:.8rem;font-weight:600;color:#555">Auto-lock after (seconds)</label>
    <input id=idlesec type=number min=30 max=3600 step=10>
    <button id=idlesave>Save timeout</button>
    <div class=warn id=idlemsg></div>
    <h3>Maintenance</h3>
    <div class=row><button id=goclear>Clear Entries</button>
      <button id=goreset>Reset Device</button></div>
    <div class=row style="margin-top:.6rem"><button id=back>Back</button></div>`;
  $('#back').onclick = renderVault;
  $('#goclear').onclick = renderClear;
  $('#goreset').onclick = renderReset;

  $('#apsave').onclick = async () => {
    const s = $('#apssid').value.trim(), p = $('#appw').value;
    const msg = $('#apmsg');
    if (s.length < 1 || s.length > 32) { msg.style.color='#b00'; msg.textContent='SSID must be 1–32 characters.'; return; }
    if (p.length < 8 || p.length > 63) { msg.style.color='#b00'; msg.textContent='Password must be 8–63 characters.'; return; }
    try {
      await api('/api/wifi', {method:'POST', body:JSON.stringify({ssid:s, password:p})});
      stopIdle();                       // device is rebooting; don't let the idle timer fire
      msg.style.color='#070';
      msg.textContent = `Saved — device is restarting. Reconnect to "${s}" and unlock again.`;
    } catch(e){ msg.style.color='#b00'; msg.textContent = e.message; }
  };

  $('#idlesec').value = Math.round(idleMs / 1000);
  $('#idlesave').onclick = async () => {
    const secs = Number($('#idlesec').value);
    const msg = $('#idlemsg');
    if (!Number.isInteger(secs) || secs < 30 || secs > 3600) {
      msg.style.color = '#b00'; msg.textContent = 'Enter 30–3600 seconds.'; return;
    }
    try {
      await api('/api/idle', {method:'POST', body:JSON.stringify({seconds:secs})});
      idleMs = secs * 1000; armIdle();
      msg.style.color = '#070'; msg.textContent = 'Saved.';
    } catch (e) { msg.style.color = '#b00'; msg.textContent = e.message; }
  };
}
```

- [ ] **Step 4: Point Clear/Reset Back at Settings**

In `renderClear()`, change its Back wiring:
```js
  $('#back').onclick = renderVault;
```
to:
```js
  $('#back').onclick = renderSettings;
```
(Leave `renderClear`'s success path `sel = 'all'; renderVault();` unchanged — after clearing, return to the vault.)

In `renderReset()`, change its Back wiring the same way:
```js
  $('#back').onclick = renderVault;
```
to:
```js
  $('#back').onclick = renderSettings;
```

- [ ] **Step 5: Build the main firmware (re-embeds the page)**

Run (PowerShell, background, await; working dir `D:\Workspace\esp32key`):
```
$env:MSYSTEM = $null; . C:\esp\v6.0.1\esp-idf\export.ps1; idf.py build
```
Expected: **`Project build complete`**.

- [ ] **Step 6: Commit**

```bash
git add components/vault_api/www/index.html
git commit -m "webui: Settings page (WiFi creds, auto-lock, clear/reset); slim sidebar"
```

---

## Task 4: Final verification

- [ ] **Step 1: Clean build of both projects from the committed tree**

Main firmware:
```
$env:MSYSTEM = $null; . C:\esp\v6.0.1\esp-idf\export.ps1; idf.py build
```
Test runner:
```
Set-Location D:\Workspace\esp32key\test_app; $env:MSYSTEM = $null; . C:\esp\v6.0.1\esp-idf\export.ps1; idf.py build
```
Expected: both `Project build complete`; `test_app` output lists the existing test components (`vault_session::test`, etc.).

- [ ] **Step 2: Manual on-board checklist (record results; not runnable in agent env)**

  1. Unlock; click **Settings**. The SSID field shows the current SSID (`esp32key` on a fresh device).
  2. **WiFi:** enter a new SSID + a valid password (≥8 chars), Save → "restarting, reconnect…" message; device reboots; the new SSID appears; reconnect with the new password over WiFi and unlock.
  3. Power-cycle again → the changed SSID/password persist.
  4. **Validation:** empty SSID or a <8-char password → client shows the range error; if forced via the API, server returns 400 and the device does NOT reboot.
  5. **Auto-lock** control works from Settings (set 30 s → vault locks at 30 s).
  6. **Clear Entries** and **Reset Device** open from Settings; their **Back** returns to Settings; Clear's success returns to the vault.
  7. Sidebar shows only Transfer Entries, Lock, Settings; the logo still locks on click.

---

## Self-Review notes

- **Spec coverage:** WifiAp persistence + load-or-default + setter + ssid getter (Task 1); CMake deps (Tasks 1, 2); `GET`/`POST /api/wifi` with auth + 1–32/8–63 validation + persist + reboot-to-apply + handler-cap bump (Task 2); DI wiring in main.cpp (Tasks 1, 2); Settings page hub with WiFi + auto-lock inline and Clear/Reset buttons, slimmed sidebar, Back→Settings (Task 3); both-projects build verification + manual checklist (Task 4). All spec sections mapped.
- **Naming consistency:** `WifiAp(Store&)`, `start(default_ssid, default_password)`, `set_credentials(ssid, password)`, `ssid()`, keys `ap_ssid`/`ap_pw`; `h_wifi_get`/`h_wifi_set` (+ `_impl`), routes `/api/wifi` (GET/POST), `reboot_cb`; DOM ids `apssid`/`appw`/`apsave`/`apmsg`/`settings`/`goclear`/`goreset`; `renderSettings`. Used identically across tasks.
- **No placeholders:** every code/command step is concrete.
- **Build-coupling note:** Task 1 keeps the tree compiling (WifiAp self-consistent, ApiServer untouched, main updated for the WifiAp signature only). Task 2 then changes the ApiServer signature and main's `api(...)` line together, so each task's commit builds.
