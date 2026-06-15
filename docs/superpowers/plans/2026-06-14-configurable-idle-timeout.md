# Configurable Idle Auto-Lock Timeout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an authenticated user set the vault's idle auto-lock timeout (30–3600 s) from the web UI sidebar, persisted across reboots in NVS.

**Architecture:** The timeout becomes runtime state on `vault::Session` (replacing the compile-time `VS_IDLE_MS` constant). `vault::ApiServer` gains a `Store&` dependency: it loads the saved value at `start()`, reports it via `/api/state`, and accepts a new authed `POST /api/idle` that validates, applies, and persists it. The sidebar gets a seconds input + Save button. `Session` stays NVS-free so its doctest suite is unaffected.

**Tech Stack:** C++17, ESP-IDF v6.0.1, esp_https_server, cJSON, NVS (`vault::Store`), doctest (on-target test runner), vanilla JS/HTML.

---

## Reference: build & test commands

Builds run via the **PowerShell tool**, in the background (first build of each project compiles all of ESP-IDF; poll for completion).

**Main firmware** (working dir is already `D:\Workspace\esp32key`):
```
$env:MSYSTEM = $null; . C:\esp\v6.0.1\esp-idf\export.ps1; idf.py build
```

**Test runner** (`test_app`):
```
Set-Location D:\Workspace\esp32key\test_app; $env:MSYSTEM = $null; . C:\esp\v6.0.1\esp-idf\export.ps1; idf.py build
```

**Important on tests:** the doctest cases compile *into* the `test_app` firmware and run **only on the ESP32-S3 board** (`idf.py -p <PORT> flash monitor`). The agent environment can only **build-verify** that tests compile — it cannot execute them. So each "verify it fails / passes" step below is satisfied by a successful `test_app` build plus a note that the on-board run is a manual follow-up.

---

## File Structure

- `components/vault_session/include/vault_session.h` — rename constant, add bounds + `idle_ms_` member, `set_idle_ms()`/`idle_ms()`.
- `components/vault_session/vault_session.cpp` — use `idle_ms_`; implement getter/setter with clamping.
- `components/vault_session/test/test_vault_session.cpp` — update refs; add runtime-timeout + clamp cases.
- `components/vault_api/include/vault_api.h` — constructor `Store&`; `store_` member; new handler decls.
- `components/vault_api/vault_api.cpp` — load at `start()`, register route, `/api/state` uses runtime value, new `h_idle_set_impl`.
- `components/vault_api/CMakeLists.txt` — add `vault_store` to `REQUIRES`.
- `components/vault_api/www/index.html` — sidebar control + save logic.
- `main/main.cpp` — pass `store` into `ApiServer`.

---

## Task 1: `Session` holds the idle timeout as runtime state

**Files:**
- Modify: `components/vault_session/include/vault_session.h`
- Modify: `components/vault_session/vault_session.cpp`
- Modify: `components/status_led/status_led.cpp` (also referenced the renamed `VS_IDLE_MS`)
- Modify: `components/vault_api/vault_api.cpp` (the `/api/state` read — only remaining `VS_IDLE_MS` use; the rename is atomic across the tree because `test_app` compiles every component)
- Test: `components/vault_session/test/test_vault_session.cpp`

> **Note (revised during execution):** Renaming `VS_IDLE_MS` breaks every call site, and both projects compile all components, so the rename must touch all consumers in one commit to keep the tree buildable: `status_led.cpp:green_level()` (use `session_.idle_ms()` as the fade's full-scale window) and `vault_api.cpp` `h_state_impl` (report `session_.idle_ms()`). The `/api/state` change was originally Task 2 Step 3; it moves here.

- [ ] **Step 1: Update the test file to the new API (the failing test)**

Replace the entire contents of `components/vault_session/test/test_vault_session.cpp` with:

```cpp
#include "doctest/doctest.h"
#include "vault_session.h"
#include <cstring>

using namespace vault;

TEST_CASE("token validates, expires on idle, dies on logout") {
    Session s;
    char tok[VS_TOKEN_HEX];
    s.create(1000, tok);
    CHECK(s.validate(tok, 1000 + VS_IDLE_DEFAULT_MS - 1));
    CHECK_FALSE(s.validate(tok, 1000 + 2 * VS_IDLE_DEFAULT_MS + 10));

    s.create(1, tok);
    CHECK(s.validate(tok, 2));
    s.destroy();
    CHECK_FALSE(s.validate(tok, 3));
}

TEST_CASE("bad token never validates") {
    Session s;
    char tok[VS_TOKEN_HEX]; s.create(1, tok);
    CHECK_FALSE(s.validate("deadbeef", 2));
    CHECK_FALSE(s.validate("", 2));
}

TEST_CASE("login lockout after repeated failures, clears after window") {
    Session s;
    for (int i = 0; i < VS_MAX_FAILS; i++) {
        CHECK(s.login_allowed(0));
        s.note_login_result(false, 0);
    }
    CHECK_FALSE(s.login_allowed(0));
    CHECK_FALSE(s.login_allowed(VS_LOCKOUT_MS - 1));
    CHECK(s.login_allowed(VS_LOCKOUT_MS + 1));

    s.note_login_result(true, VS_LOCKOUT_MS + 1);
    CHECK(s.login_allowed(VS_LOCKOUT_MS + 2));
}

TEST_CASE("idle window follows the runtime-configured timeout") {
    Session s;
    char tok[VS_TOKEN_HEX];
    s.set_idle_ms(30 * 1000);               // 30 s
    CHECK(s.idle_ms() == 30u * 1000);
    s.create(1000, tok);
    CHECK(s.validate(tok, 1000 + 30 * 1000 - 1));        // still inside window
    s.create(1000, tok);                                  // refresh (validate above moved last_seen)
    CHECK_FALSE(s.validate(tok, 1000 + 30 * 1000 + 10)); // past the 30 s window
}

TEST_CASE("set_idle_ms clamps to [MIN, MAX]") {
    Session s;
    s.set_idle_ms(1);                       // below 30 s floor
    CHECK(s.idle_ms() == VS_IDLE_MIN_MS);
    s.set_idle_ms(0xFFFFFFFFu);             // above 3600 s ceiling
    CHECK(s.idle_ms() == VS_IDLE_MAX_MS);
}
```

- [ ] **Step 2: Build `test_app` to verify it fails to compile**

Run (PowerShell, background):
```
Set-Location D:\Workspace\esp32key\test_app; $env:MSYSTEM = $null; . C:\esp\v6.0.1\esp-idf\export.ps1; idf.py build
```
Expected: **build FAILS** — `VS_IDLE_DEFAULT_MS`, `VS_IDLE_MIN_MS`, `VS_IDLE_MAX_MS`, `set_idle_ms`, and `idle_ms` are undeclared.

- [ ] **Step 3: Update the header**

In `components/vault_session/include/vault_session.h`, replace the line:
```cpp
#define VS_IDLE_MS     (3 * 60 * 1000)
```
with:
```cpp
#define VS_IDLE_DEFAULT_MS  (3 * 60 * 1000)   /* default idle auto-lock window */
#define VS_IDLE_MIN_MS      (30 * 1000)        /* 30 s floor  */
#define VS_IDLE_MAX_MS      (3600 * 1000)      /* 60 min ceiling */
```

In the same file, add the two public methods to `class Session` — place them right after the `idle_remaining_ms` declaration:
```cpp
    uint32_t idle_remaining_ms(uint64_t now_ms);  // ms until idle-out (0 if none/expired)
    void     set_idle_ms(uint32_t ms);            // set idle window; clamps to [MIN, MAX]
    uint32_t idle_ms() const { return idle_ms_; } // current idle window (ms)
```

And add the private member alongside the other state (after `lockout_until_ms_`):
```cpp
    uint64_t lockout_until_ms_ = 0;
    uint32_t idle_ms_ = VS_IDLE_DEFAULT_MS;
```

- [ ] **Step 4: Update the implementation**

In `components/vault_session/vault_session.cpp`:

Change `check_idle` to use the runtime member:
```cpp
bool Session::check_idle(uint64_t now_ms) {
    if (!active_) return false;
    if (now_ms - last_seen_ms_ > idle_ms_) {
        destroy();
        if (expiry_cb_) expiry_cb_();   // e.g. Vault::lock(): wipe DEK on idle
        return true;
    }
    return false;
}
```

Change `idle_remaining_ms` to use the runtime member:
```cpp
uint32_t Session::idle_remaining_ms(uint64_t now_ms) {
    if (!active_) return 0;
    uint64_t elapsed = now_ms - last_seen_ms_;
    if (elapsed >= idle_ms_) return 0;
    return (uint32_t)(idle_ms_ - elapsed);
}
```

Add the setter (place it just after `idle_remaining_ms`):
```cpp
void Session::set_idle_ms(uint32_t ms) {
    if (ms < VS_IDLE_MIN_MS) ms = VS_IDLE_MIN_MS;
    if (ms > VS_IDLE_MAX_MS) ms = VS_IDLE_MAX_MS;
    idle_ms_ = ms;
}
```

- [ ] **Step 5: Build `test_app` to verify it compiles (tests pass on-board)**

Run (PowerShell, background):
```
Set-Location D:\Workspace\esp32key\test_app; $env:MSYSTEM = $null; . C:\esp\v6.0.1\esp-idf\export.ps1; idf.py build
```
Expected: **build SUCCEEDS**, output lists `Test components: ... vault_session::test ...`. (On-board run via `idf.py -p <PORT> flash monitor` is a manual follow-up to confirm green.)

- [ ] **Step 6: Commit**

```bash
git add components/vault_session
git commit -m "vault_session: make idle timeout runtime-configurable with bounds"
```

---

## Task 2: API persistence, `/api/state` value, and `POST /api/idle`

**Files:**
- Modify: `components/vault_api/include/vault_api.h`
- Modify: `components/vault_api/vault_api.cpp`
- Modify: `components/vault_api/CMakeLists.txt`
- Modify: `main/main.cpp`

- [ ] **Step 1: Add `vault_store` to the component's requires**

In `components/vault_api/CMakeLists.txt`, change the `REQUIRES` line to include `vault_store`:
```cmake
idf_component_register(SRCS "vault_api.cpp"
                       INCLUDE_DIRS "include"
                       REQUIRES esp_https_server cjson vault vault_store vault_session esp_timer mbedtls status_led vault_error
                       EMBED_FILES "www/index.html")
```

- [ ] **Step 2: Update the header — constructor, member, handler decls**

In `components/vault_api/include/vault_api.h`:

Add the include near the top (after `#include "vault.h"`):
```cpp
#include "vault_store.h"
```

Change the constructor and add the member. Replace:
```cpp
    ApiServer(Vault& vault, Session& session, StatusLed& led)
        : vault_(vault), session_(session), led_(led) {}
```
with:
```cpp
    ApiServer(Vault& vault, Session& session, StatusLed& led, Store& store)
        : vault_(vault), session_(session), led_(led), store_(store) {}
```

Add the `store_` member next to the other references. Replace:
```cpp
    Vault&     vault_;
    Session&   session_;
    StatusLed& led_;
    httpd_handle_t srv_ = nullptr;
```
with:
```cpp
    Vault&     vault_;
    Session&   session_;
    StatusLed& led_;
    Store&     store_;
    httpd_handle_t srv_ = nullptr;
```

Add the new handler declarations. After the `h_state_impl` line in the `*_impl` group:
```cpp
    esp_err_t h_state_impl(httpd_req_t* r);
    esp_err_t h_idle_set_impl(httpd_req_t* r);
```
And after the `h_state` line in the static-trampoline group:
```cpp
    static esp_err_t h_state(httpd_req_t*);
    static esp_err_t h_idle_set(httpd_req_t*);
```

- [ ] **Step 3: `/api/state` reports the runtime value** — DONE IN TASK 1.

The `h_state_impl` change (`idle_ms` now reports `session_.idle_ms()`) was folded into Task 1 to keep the tree buildable after the `VS_IDLE_MS` rename. No action here; verify it is present.

- [ ] **Step 4: Add the `h_idle_set_impl` handler**

In `components/vault_api/vault_api.cpp`, add this handler immediately after `h_state_impl` (before `h_setup_impl`):
```cpp
/* ---- POST /api/idle ---- set idle auto-lock window (seconds), authed + persisted */
esp_err_t ApiServer::h_idle_set_impl(httpd_req_t *r)
{
    if (!authed(r)) return err_json(r, 401, "locked");
    char *body = read_body(r); if (!body) return err_json(r,400,"bad body");
    cJSON *j = cJSON_Parse(body); free(body);
    if (!j) return err_json(r,400,"bad json");
    int secs = json_int(j, "seconds");
    cJSON_Delete(j);
    if (secs < 30 || secs > 3600) return err_json(r,400,"timeout out of range (30-3600s)");
    uint32_t ms = (uint32_t)secs * 1000u;
    session_.set_idle_ms(ms);
    store_.set_blob("idle_ms", &ms, sizeof ms);   // throws on fault -> 500 via trampoline
    store_.commit();
    return send_json(r, 200, cJSON_CreateObject());
}
```

- [ ] **Step 5: Register the trampoline and route, and load the saved value at boot**

In `components/vault_api/vault_api.cpp`:

Add the trampoline next to the others (after `API_HANDLER(h_state)`):
```cpp
API_HANDLER(h_state)
API_HANDLER(h_idle_set)
```

Add the route to the `routes[]` array (after the `/api/state` line):
```cpp
        {"/api/state",              HTTP_GET,    h_state,           this},
        {"/api/idle",               HTTP_POST,   h_idle_set,        this},
```

Load the persisted value at the end of `start()`, just before the idle-lock timer is created (before the `esp_timer_create_args_t idle_args = {};` line):
```cpp
    /* Restore a previously-saved idle window; absent key keeps the default. */
    {
        uint32_t saved = 0; size_t len = sizeof saved;
        try { if (store_.get_blob("idle_ms", &saved, len) && len == sizeof saved)
                  session_.set_idle_ms(saved); }
        catch (...) { ESP_LOGW(TAG, "idle_ms load failed; using default"); }
    }
```

Note: `cfg.httpd.max_uri_handlers = 20` already accommodates the new route (19 total).

- [ ] **Step 6: Wire the new constructor argument in `main.cpp`**

In `main/main.cpp`, replace:
```cpp
        static vault::ApiServer api(vault, session, led);
```
with:
```cpp
        static vault::ApiServer api(vault, session, led, store);
```

- [ ] **Step 7: Build the main firmware to verify it compiles**

Run (PowerShell, background; working dir `D:\Workspace\esp32key`):
```
$env:MSYSTEM = $null; . C:\esp\v6.0.1\esp-idf\export.ps1; idf.py build
```
Expected: **build SUCCEEDS** (`Project build complete`, a `.bin` is produced).

- [ ] **Step 8: Commit**

```bash
git add components/vault_api main/main.cpp
git commit -m "vault_api: persist + serve configurable idle timeout via POST /api/idle"
```

---

## Task 3: Sidebar UI — set & save the idle timeout

**Files:**
- Modify: `components/vault_api/www/index.html`

- [ ] **Step 1: Add the sidebar control markup**

In `components/vault_api/www/index.html`, inside `paint()`'s sidebar (`<div class=side>`), add a new block right after the Clear/Reset row (the `<div class=row style="margin-top:.4rem">...Reset...</div>`), before the closing `</div>` of `.side`:
```html
      <div style="margin-top:.6rem">
        <label for=idlesec style="display:block;font-size:.8rem;font-weight:600;color:#555">Auto-lock after (seconds)</label>
        <input id=idlesec type=number min=30 max=3600 step=10>
        <button id=idlesave>Save timeout</button>
        <div class=warn id=idlemsg></div>
      </div>
```

- [ ] **Step 2: Populate the input and wire Save**

In `components/vault_api/www/index.html`, in `paint()` where the other sidebar handlers are wired (near `$('#addcat').onclick = ...`), add:
```javascript
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
      msg.style.color = '#080'; msg.textContent = 'Saved.';
    } catch (e) { msg.style.color = '#b00'; msg.textContent = e.message; }
  };
```

- [ ] **Step 3: Build the main firmware to verify the embedded page compiles**

Run (PowerShell, background; working dir `D:\Workspace\esp32key`):
```
$env:MSYSTEM = $null; . C:\esp\v6.0.1\esp-idf\export.ps1; idf.py build
```
Expected: **build SUCCEEDS** (the changed `index.html` is re-embedded via `EMBED_FILES`).

- [ ] **Step 4: Commit**

```bash
git add components/vault_api/www/index.html
git commit -m "webui: sidebar control to set the idle auto-lock timeout"
```

---

## Task 4: Final verification

- [ ] **Step 1: Confirm both projects build clean from the committed tree**

Main firmware (working dir `D:\Workspace\esp32key`):
```
$env:MSYSTEM = $null; . C:\esp\v6.0.1\esp-idf\export.ps1; idf.py build
```
Test runner:
```
Set-Location D:\Workspace\esp32key\test_app; $env:MSYSTEM = $null; . C:\esp\v6.0.1\esp-idf\export.ps1; idf.py build
```
Expected: both succeed; `test_app` output lists `vault_session::test`.

- [ ] **Step 2: Manual on-board checklist (record results; not runnable in agent env)**

  1. Flash, unlock, open the sidebar. The "Auto-lock after" input shows the current window (180).
  2. Set 30, click Save → "Saved.". Leave idle 30 s → vault locks, UI returns to unlock screen.
  3. Set 60, Save. Reboot the board. Unlock → sidebar shows 60 and locking honors 60 s. (Persistence confirmed.)
  4. Try 5 and 9999 → client shows the range error; if forced via API, server returns 400.

---

## Self-Review notes

- **Spec coverage:** Session runtime value + bounds (Task 1); NVS persistence + load-at-boot + `/api/state` runtime value + `POST /api/idle` with range check & auth (Task 2); sidebar input/save/mirror/re-arm (Task 3); tests for runtime window + clamp (Task 1); both-projects build verification (Task 4). All spec sections mapped.
- **Naming consistency:** `set_idle_ms`/`idle_ms`/`idle_ms_`, `VS_IDLE_DEFAULT_MS`/`VS_IDLE_MIN_MS`/`VS_IDLE_MAX_MS`, `h_idle_set_impl`/`h_idle_set`, blob key `"idle_ms"`, route `/api/idle`, JSON field `seconds`, DOM ids `idlesec`/`idlesave`/`idlemsg` — used identically across all tasks.
- **No placeholders:** every code/command step is concrete.
