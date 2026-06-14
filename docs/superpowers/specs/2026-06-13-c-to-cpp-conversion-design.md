# esp32key: C-to-C++ Conversion Design

**Date:** 2026-06-13
**Status:** Approved (high-level); pending spec review
**Scope:** Convert all ESP-IDF components and `main` from C to idiomatic C++ classes, component by component, bottom-up by dependency layer.

## Goals

- Replace file-static singleton state with encapsulated class instances.
- Instances are constructed once in `app_main` and injected by reference into their consumers (dependency injection); no global accessors.
- Use C++ exceptions for error reporting, caught at every ESP-IDF C-callback boundary so exceptions never unwind into C.
- Preserve all existing runtime behavior (crypto formats, NVS layout, HTTP API, LED semantics, idle/lockout timing).
- Move on-target tests from Unity to **doctest**.

## Non-Goals

- No change to the on-disk NVS format, the portable bundle format, the wire/HTTP API, or the web UI.
- No new features. This is a structural language port only.
- No RTTI (kept disabled). No host-side test harness (tests stay on-target).

## Constraints & Decisions

- **Exceptions on:** `CONFIG_COMPILER_CXX_EXCEPTIONS=y` in `sdkconfig.defaults`. RTTI stays off.
- **No heap in security paths:** crypto and key material use fixed-size buffers / `std::array`, never `std::string`/`std::vector`. Heap is acceptable only where the current code already uses it (cert PEM buffers, export bundle) and at the HTTP layer.
- **Error model:** internal C++ APIs throw on failure (a small exception hierarchy rooted at `vault::Error`, carrying an `esp_err_t`). Functions that today return `esp_err_t` to express an *expected* outcome (e.g. wrong password, tag mismatch) instead return a value (`bool`/`std::optional`) where the failure is a normal control-flow result; they throw only for genuine faults.
- **C-callback boundaries** wrap their entire body in `try/catch`, log, and return the appropriate `esp_err_t`/void. Boundaries: `app_main`, every httpd URI handler, every `esp_timer` callback, and any FreeRTOS task entry point.
- **Headers stay `.h`**, included only from C++ now. `extern "C"` is added *only* on the few symbols ESP-IDF C code links against — in practice just `app_main` (and any function registered directly as a C callback that isn't a local trampoline).
- **Build wiring:** each `.c` renamed to `.cpp`; `SRCS` updated in every `CMakeLists.txt`. ESP-IDF compiles `.cpp` automatically.

## Conversion strategy: bottom-up by dependency layer

Convert a whole layer, update the call sites in that layer's consumers, then verify the build and the on-target test app before moving up. Layers (from `REQUIRES` graph):

- **Layer 0 (leaves):** `vault_crypto`, `vault_store`, `net_wifi_ap`, `net_usb`
- **Layer 1:** `vault_session` (→crypto), `vault_cert` (→store), `vault` (→crypto, store)
- **Layer 2:** `status_led` (→vault, session)
- **Layer 3:** `vault_api` (→vault, session, status_led)
- **Layer 4:** `main` (→all) + test app + doctest migration

The tree need only build green at layer boundaries. No throwaway shims.

## Per-component design

Buffer-size and format macros (`VC_KEY_LEN`, `VAULT_FIELD_MAX`, bundle layout, etc.) and the POD record structs (`vault_entry_t`, `vault_category_t`) are kept as-is — they define formats and ABI and need no change. Classes wrap behavior, not these constants.

### `vault_crypto` → `crypto` namespace (Layer 0)
Stateless. Keep as free functions in a `vault::crypto` namespace rather than a class (no state to encapsulate).
- `void init();` — PSA init, idempotent (replaces `vc_init`).
- `void derive_key(password, salt, iterations, out_key);` — throws on failure.
- `void gcm_encrypt(...)`, `bool gcm_decrypt(...)` — decrypt returns `false` on tag-verify failure (expected), throws on misuse.
- `void random(buf, len);`
- DEK: `void dek_create(kek, out_dek, out_wrapped);`, `bool dek_unwrap(kek, wrapped, out_dek);`
- Bundle: `void bundle_pack(...)`, `bundle_unpack(...)` returns an enum/`std::optional` distinguishing wrong-password vs bad-magic vs bad-version vs size error (today's distinct `esp_err_t`s) — these are expected outcomes, not exceptions.

### `vault_store` → `Store` class (Layer 0)
Thin RAII wrapper over the `"vault"` NVS namespace.
- `Store();` constructor calls `nvs_flash_init` (replaces `vs_init`).
- `void set_blob(key, data, len);`, `bool get_blob(key, out, size_t& len);` (returns `false` if key absent — expected), `void erase_key(key);`, `void commit();`. Throw on real NVS faults.

### `net_wifi_ap` → `WifiAp` class (Layer 0)
- `void start(const char* password);` — throws on failure. Independent of vault.

### `net_usb` → `UsbNet` class (Layer 0)
- `void start();` — throws on failure. Independent of vault.

### `vault_session` → `Session` class (Layer 1)
All current file-statics (`s_token`, `s_active`, `s_last_seen_ms`, `s_fail_count`, `s_lockout_until_ms`) become members.
- Constructor takes nothing crypto-stateful; uses `crypto::random` for tokens (free functions, no injected dependency needed beyond the namespace).
- `using ExpiryCallback = std::function<void()>;` `void set_expiry_cb(ExpiryCallback);` (still used to wire `Vault::lock`).
- `bool login_allowed(now_ms)`, `void note_login_result(bool, now_ms)`, `void create(now_ms, out_token_hex)`, `bool validate(token_hex, now_ms)`, `bool check_idle(now_ms)`, `uint32_t idle_remaining_ms(now_ms)`, `void destroy()`, `void reset()`.
- Keeps the constant-time compare and hex helpers as private members / file-local functions. Same single-threaded (httpd task) contract documented today.

### `vault_cert` → `Cert` class (Layer 1)
- Constructor takes `Store&`.
- `void get(char** cert_pem, size_t* cert_len, char** key_pem, size_t* key_len);` — keeps the malloc'd-buffer contract (caller frees) to match the existing httpd/cert consumer, or returns owning buffers via out-params unchanged. Generates+persists a self-signed pair on first call.

### `vault` → `Vault` class (Layer 1)
The largest component. Constructor takes `Crypto` (namespace, so nothing to inject) and `Store&`. All internal state (DEK, unlock/busy flags, in-RAM entry table, bulk-edit window, category table) becomes members.
- Lifecycle: `void init()` (boot-time format check / auto-reset), `bool is_initialized()`, `bool is_unlocked()`, `bool is_busy()`.
- Auth: `void setup(master)`, `bool unlock(master)` — returns `false` on wrong password (today's `ESP_FAIL`, an expected outcome); throws `InvalidState` when the vault is not initialized (today's `ESP_ERR_INVALID_STATE`, a misuse). `void lock()`, `void change_password(cur, next)`.
- CRUD (all require unlocked, else throw `InvalidState`): `list`, `reveal`, `add`, `update`, `delete`, `clear_entries`.
- Categories: `category_list`, `category_add`, `category_delete`.
- Transfer/export/import: `set_transfer_password`, `verify_transfer`, `export_bundle` (malloc'd out, caller frees — unchanged), `bulk_begin`/`bulk_commit`, `import_bundle`.
- `void factory_reset();`
- Expected-outcome operations (wrong password, wrong transfer password) return `bool`; structural/programmer errors and NVS/crypto faults throw.

### `status_led` → `StatusLed` class (Layer 2)
- Constructor takes `Vault&` and `Session&`; owns the `esp_timer` and the WS2812 `led_strip` handle.
- `void init();` (was `status_led_init`) starts the low-rate mirror timer.
- `void activity();` (was `status_led_activity`) sets the activity flag.
- The `esp_timer` callback is a `static` trampoline that recovers `this` from the timer arg and wraps the body in `try/catch`. Reads live `Vault`/`Session` state to render blue/red/green + activity pulse, exactly as today.

### `vault_api` → `ApiServer` class (Layer 3)
- Constructor takes `Vault&`, `Session&`, `StatusLed&`.
- `void start(cert_pem, cert_len, key_pem, key_len);` registers httpd URI handlers.
- Each URI handler is a `static` `esp_err_t fn(httpd_req_t*)` trampoline that recovers the `ApiServer*` from `req->user_ctx`, then calls a private member, wrapping the body in `try/catch` to convert exceptions into HTTP error responses (never letting them escape into the httpd C task). cJSON usage and the embedded `index.html` are unchanged.

### `main` → `main.cpp` (Layer 4)
- `extern "C" void app_main(void)` — sole C-linkage entry point. Body wrapped in a top-level `try/catch` that logs and (on fatal init failure) aborts as `ESP_ERROR_CHECK` does today.
- Constructs components in dependency order, owns them for the process lifetime (function-local objects that never return, or `static`), and wires references:
  1. `crypto::init();`
  2. `Store store;`
  3. `Vault vault{store};` then `vault.init();`
  4. `Session session;`
  5. `StatusLed led{vault, session}; led.init();`
  6. `esp_netif_init(); esp_event_loop_create_default();`
  7. `session.set_expiry_cb([&]{ vault.lock(); });` (replaces `vsess_set_expiry_cb(vault_lock)`)
  8. `WifiAp wifi; wifi.start(AP_PASSWORD);` / `UsbNet usb; usb.start();`
  9. `Cert cert{store};` → `cert.get(...)`
  10. `ApiServer api{vault, session, led}; api.start(...);`

## Tests: Unity → doctest

- Add a `doctest` component (single-header `doctest.h` under `components/doctest/include`, with a `CMakeLists.txt` registering it as an INTERFACE/header-only component).
- `test_app/main/test_app_main.cpp`: `extern "C" void app_main(void)` constructs a `doctest::Context`, runs it, and reports results over the console (replaces `unity_run_menu()`).
- Each `components/<c>/test/test_<c>.cpp` rewrites the existing Unity `TEST_CASE`s as doctest `TEST_CASE`/`SUBCASE` with `CHECK`/`REQUIRE`/`REQUIRE_THROWS`, exercising the new class/namespace APIs. Tests construct their own instances (e.g. a `Store`, a `Session`) directly — no globals.
- Update each test `CMakeLists.txt` to `SRCS "test_<c>.cpp"` and `REQUIRES doctest <component>` (drop `unity`).
- Update `test_app/CMakeLists.txt` `TEST_COMPONENTS` as needed; the runner gains `REQUIRES doctest`.
- Crypto round-trip, GCM tamper-detection, DEK wrap/unwrap, and bundle pack/unpack assertions carry over one-to-one against the new `crypto::` API.

## Error handling boundary summary

| Boundary | Wrapping |
|---|---|
| `app_main` | top-level `try/catch`, log + abort on fatal |
| httpd URI handlers | `try/catch` → HTTP 4xx/5xx JSON error, return `ESP_OK` to httpd |
| `esp_timer` callbacks (status_led, session idle) | `try/catch` → log, swallow |
| FreeRTOS task entries (if any) | `try/catch` → log |

## Verification per layer

After each layer: `idf.py build` green, and (once Layer 4 lands) the doctest `test_app` builds and runs on-target with all cases passing. Build invocation follows the project's documented `idf.py` procedure (MSYSTEM gotcha; two projects: app + test_app).

## Risks

- **Binary size / heap from exceptions.** Enabling exceptions grows the image and pulls in unwind tables. Mitigation: measure image size after Layer 4; exceptions are reserved for fault paths, not normal control flow.
- **doctest on-target.** doctest is host-oriented; verify it compiles and runs under ESP-IDF (no RTTI, embedded newlib). If a blocker surfaces, fall back is out of scope here — raise it during implementation.
- **Cert/export malloc contracts.** Keeping caller-frees raw-pointer out-params is a deliberate ABI-preserving choice; flagged for the plan in case we prefer RAII owners there.
