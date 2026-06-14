# C-to-C++ Conversion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Convert all ESP-IDF components and `main` of the esp32key vault firmware from C to idiomatic C++ classes, bottom-up by dependency layer, preserving all runtime behavior and on-disk/wire formats.

**Architecture:** Each component becomes a C++ class (or namespace for the stateless crypto layer) in the `vault` namespace. File-static singleton state becomes member state. Components are constructed once in `app_main` and injected by reference (dependency injection). Errors are reported with C++ exceptions (a `vault::Error` hierarchy carrying an `esp_err_t`); *expected* outcomes (wrong password, tag mismatch, not-found) are return values (`bool`/count). Every ESP-IDF C-callback boundary (`app_main`, httpd handlers, esp_timer callbacks) wraps its body in `try/catch` so exceptions never unwind into C. Tests move from Unity to **doctest**, still run on-target via the existing `test_app`.

**Tech Stack:** ESP-IDF v6.0.1, C++23 (IDF default), mbedTLS 4.x / PSA crypto, FreeRTOS, esp_https_server, cJSON, led_strip, TinyUSB, doctest (vendored single-header).

---

## Conventions used throughout this plan

- **Build invocation** (from this project's memory): ESP-IDF is at `C:\esp\v6.0.1\esp-idf`, not on PATH, and `MSYSTEM` must be cleared. Build the **main app** from `D:\Workspace\esp32key` and the **test app** from `D:\Workspace\esp32key\test_app`. Run builds in the **background** (first build of each compiles all of ESP-IDF, 10–20 min) and poll.

  Main app build command (run from repo root):
  ```
  cmd /c 'set "MSYSTEM=" && call C:\esp\v6.0.1\esp-idf\export.bat && idf.py build'
  ```
  Test app build command (run from `test_app`):
  ```
  cmd /c 'set "MSYSTEM=" && call C:\esp\v6.0.1\esp-idf\export.bat && cd test_app && idf.py build'
  ```
  Unit tests **execute on the board only** (interactive flash+monitor). The agent environment can only **build-verify**. doctest cases therefore count as "passing" in this plan when (a) they compile and link into `test_app`, and (b) the dev later confirms on-target. Each test task's verification is the test-app build succeeding with the test TU compiled.

- **Namespace:** all new types live in `namespace vault {}`. The stateless crypto layer lives in `namespace vault::crypto {}`.

- **`delete` is a C++ keyword:** the vault entry-delete method is named `remove`, not `delete`.

- **Designated initializers:** ESP-IDF C code initializes structs with designated `.field =` syntax, including nested forms like `.flags.invert_out = false`. Nested designated initializers are **not valid standard C++** and out-of-order designated initializers are rejected in C++20+. **Rule:** when moving such initializers, rewrite them as zero-init + field assignment:
  ```cpp
  // C:  led_strip_config_t scfg = { .strip_gpio_num = LED_GPIO, .max_leds = 1, .flags.invert_out = false };
  // C++:
  led_strip_config_t scfg = {};
  scfg.strip_gpio_num = LED_GPIO;
  scfg.max_leds = 1;
  scfg.flags.invert_out = false;
  ```
  Macro initializers provided by ESP-IDF headers (`WIFI_INIT_CONFIG_DEFAULT()`, `ESP_NETIF_INHERENT_DEFAULT_ETH()`, `HTTPD_SSL_CONFIG_DEFAULT()`, `PSA_KEY_ATTRIBUTES_INIT`, etc.) are fine to keep — they are written to compile as C++ in IDF.

- **`_Static_assert` → `static_assert`** when moving the crypto code.

- **`malloc`/`free` casts:** in C++, `malloc` returns `void*` and needs an explicit cast. Rewrite `p = malloc(n);` as `p = (T*)malloc(n);` (or `static_cast<T*>`). Same for `heap_caps_malloc`/`heap_caps_calloc`.

- **Commit messages:** per the user's global instructions — concise, no `Co-Authored-By`, no "Generated with" footer, focused on the *why*. Commit only the files each task changed.

---

## Task 1: Enable C++ exceptions in both projects

**Files:**
- Create: `sdkconfig.defaults`
- Create: `test_app/sdkconfig.defaults`

> Neither project currently has an `sdkconfig.defaults`. Settings here are baked into a regenerated `sdkconfig` on the next build. Enabling exceptions is required before any `.cpp` that throws will build correctly.

- [ ] **Step 1: Create `sdkconfig.defaults`**

```
# Enable C++ exceptions (RTTI left at default-off). Required by the C++ port,
# which uses exceptions for fault paths.
CONFIG_COMPILER_CXX_EXCEPTIONS=y
```

- [ ] **Step 2: Create `test_app/sdkconfig.defaults`**

```
CONFIG_COMPILER_CXX_EXCEPTIONS=y
```

- [ ] **Step 3: Delete stale generated sdkconfig so defaults take effect**

The generated `sdkconfig` (if present) overrides defaults. Remove both so they regenerate from the new defaults on next build.
Run:
```
rm -f sdkconfig test_app/sdkconfig
```
Expected: no error (files may or may not exist).

- [ ] **Step 4: Commit**

```bash
git add sdkconfig.defaults test_app/sdkconfig.defaults
git commit -m "Enable C++ exceptions for both IDF projects ahead of C++ port"
```

---

## Task 2: Add the doctest component

**Files:**
- Create: `components/doctest/include/doctest/doctest.h` (vendored, downloaded)
- Create: `components/doctest/CMakeLists.txt`

> doctest is a single-header C++ test framework. We vendor a pinned version and register it as a header-only INTERFACE component. Embedded-relevant config (no POSIX signals, no threads) is set as interface compile definitions.

- [ ] **Step 1: Download the pinned doctest header**

Run:
```
mkdir -p components/doctest/include/doctest
curl -L -o components/doctest/include/doctest/doctest.h \
  https://raw.githubusercontent.com/doctest/doctest/v2.4.11/doctest/doctest.h
```
Expected: `doctest.h` exists and is ~250 KB.
Verify:
```
head -n 5 components/doctest/include/doctest/doctest.h
```
Expected: the doctest license/header banner.

- [ ] **Step 2: Create `components/doctest/CMakeLists.txt`**

```cmake
idf_component_register(INCLUDE_DIRS "include")

# Embedded build: no POSIX signal handlers, no std::thread, no colored TTY.
target_compile_definitions(${COMPONENT_LIB} INTERFACE
    DOCTEST_CONFIG_NO_POSIX_SIGNALS
    DOCTEST_CONFIG_NO_MULTITHREADING)
```

- [ ] **Step 3: Commit**

```bash
git add components/doctest
git commit -m "Vendor doctest v2.4.11 as a header-only test component"
```

---

## Task 3: Add the shared `vault::Error` exception type

**Files:**
- Create: `components/vault_error/include/vault_error.h`
- Create: `components/vault_error/CMakeLists.txt`

> A header-only component holding the exception base class, so every component can throw/catch a common type carrying an `esp_err_t`. Header-only keeps it dependency-light; components that throw add `vault_error` to their `REQUIRES`.

- [ ] **Step 1: Create `components/vault_error/include/vault_error.h`**

```cpp
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
```

- [ ] **Step 2: Create `components/vault_error/CMakeLists.txt`**

```cmake
idf_component_register(INCLUDE_DIRS "include")
```

- [ ] **Step 3: Commit**

```bash
git add components/vault_error
git commit -m "Add header-only vault::Error exception type for the C++ port"
```

---

## Task 4: Convert `vault_crypto` to the `vault::crypto` namespace

**Files:**
- Modify: `components/vault_crypto/include/vault_crypto.h`
- Rename+modify: `components/vault_crypto/vault_crypto.c` → `components/vault_crypto/vault_crypto.cpp`
- Modify: `components/vault_crypto/CMakeLists.txt`
- Rename+rewrite: `components/vault_crypto/test/test_vault_crypto.c` → `.cpp`
- Modify: `components/vault_crypto/test/CMakeLists.txt`

> Stateless layer → free functions in `vault::crypto`. Keep all `VC_*` macros and the binary formats exactly. Functions that today return `ESP_OK`/`ESP_FAIL` to mean "authentic / not authentic" become `bool`; the rest throw `vault::Error` on failure. `bundle_unpack` returns an enum to preserve today's distinct error codes (bad magic vs version vs size vs wrong-password).

- [ ] **Step 1: Write the failing test — `components/vault_crypto/test/test_vault_crypto.cpp`**

Replace the file contents entirely:
```cpp
#include "doctest/doctest.h"
#include "vault_crypto.h"
#include <cstring>

using namespace vault;

TEST_CASE("pbkdf2 is deterministic and salt-sensitive") {
    uint8_t salt1[VC_SALT_LEN] = {0};
    uint8_t salt2[VC_SALT_LEN] = {0};
    salt2[0] = 1;

    uint8_t k1[VC_KEY_LEN], k1b[VC_KEY_LEN], k2[VC_KEY_LEN];
    crypto::derive_key("hunter2", 7, salt1, 1000, k1);
    crypto::derive_key("hunter2", 7, salt1, 1000, k1b);
    crypto::derive_key("hunter2", 7, salt2, 1000, k2);

    CHECK(memcmp(k1, k1b, VC_KEY_LEN) == 0);   // deterministic
    CHECK(memcmp(k1, k2,  VC_KEY_LEN) != 0);   // salt changes key
}

TEST_CASE("gcm round-trips and detects tampering") {
    uint8_t key[VC_KEY_LEN];   crypto::random(key, sizeof key);
    uint8_t nonce[VC_NONCE_LEN]; crypto::random(nonce, sizeof nonce);
    const char* msg = "s3cr3t-password";
    size_t n = strlen(msg);

    uint8_t ct[64], pt[64], tag[VC_TAG_LEN];
    crypto::gcm_encrypt(key, nonce, nullptr, 0, (const uint8_t*)msg, n, ct, tag);
    CHECK(crypto::gcm_decrypt(key, nonce, nullptr, 0, ct, n, tag, pt));
    CHECK(memcmp(msg, pt, n) == 0);

    tag[0] ^= 0xFF;  // corrupt tag
    CHECK_FALSE(crypto::gcm_decrypt(key, nonce, nullptr, 0, ct, n, tag, pt));
}

TEST_CASE("dek wrap/unwrap round-trips; wrong kek fails") {
    uint8_t kek[VC_KEY_LEN]; crypto::random(kek, sizeof kek);
    uint8_t bad[VC_KEY_LEN]; crypto::random(bad, sizeof bad);

    uint8_t dek[VC_KEY_LEN], wrapped[VC_WRAPPED_DEK_LEN], out[VC_KEY_LEN];
    crypto::dek_create(kek, dek, wrapped);
    CHECK(crypto::dek_unwrap(kek, wrapped, out));
    CHECK(memcmp(dek, out, VC_KEY_LEN) == 0);

    CHECK_FALSE(crypto::dek_unwrap(bad, wrapped, out));
}

TEST_CASE("bundle pack/unpack round-trips; wrong password fails") {
    const char* msg = "entry-records-blob";
    size_t mlen = strlen(msg);
    uint8_t bundle[VC_BUNDLE_HDR + 64];
    size_t blen = sizeof bundle;
    crypto::bundle_pack("transfer-pw", 11, (const uint8_t*)msg, mlen, bundle, &blen);
    CHECK(blen == VC_BUNDLE_HDR + mlen);

    uint8_t out[64]; size_t olen = sizeof out;
    CHECK(crypto::bundle_unpack("transfer-pw", 11, bundle, blen, out, &olen)
          == crypto::BundleResult::Ok);
    CHECK(olen == mlen);
    CHECK(memcmp(msg, out, mlen) == 0);

    olen = sizeof out;
    CHECK(crypto::bundle_unpack("wrong-pw", 8, bundle, blen, out, &olen)
          == crypto::BundleResult::WrongPassword);

    bundle[0] ^= 0xFF;  // corrupt magic
    olen = sizeof out;
    CHECK(crypto::bundle_unpack("transfer-pw", 11, bundle, blen, out, &olen)
          == crypto::BundleResult::BadMagic);
}
```

- [ ] **Step 2: Rewrite the header — `components/vault_crypto/include/vault_crypto.h`**

Keep every `VC_*` macro exactly as today (`VC_SALT_LEN`, `VC_KEY_LEN`, `VC_NONCE_LEN`, `VC_TAG_LEN`, `VC_WRAPPED_DEK_LEN`, `VC_BUNDLE_HDR`, `VC_BUNDLE_VERSION`). Replace the function declarations with:
```cpp
#pragma once
#include <cstddef>
#include <cstdint>
#include "esp_err.h"

// ---- format constants (UNCHANGED) ----
#define VC_SALT_LEN   16
#define VC_KEY_LEN    32   /* AES-256 */
#define VC_NONCE_LEN  12   /* GCM */
#define VC_TAG_LEN    16   /* GCM */
#define VC_WRAPPED_DEK_LEN (VC_NONCE_LEN + VC_KEY_LEN + VC_TAG_LEN)
#define VC_BUNDLE_HDR (4 + 1 + VC_SALT_LEN + 4 + VC_NONCE_LEN + VC_TAG_LEN)
#define VC_BUNDLE_VERSION 1

namespace vault::crypto {

// Initialize PSA. Idempotent. Throws vault::Error on failure.
void init();

// PBKDF2-HMAC-SHA256. Throws vault::Error(ESP_ERR_INVALID_ARG) on null args.
void derive_key(const char* password, size_t password_len,
                const uint8_t salt[VC_SALT_LEN], uint32_t iterations,
                uint8_t out_key[VC_KEY_LEN]);

// AES-256-GCM. encrypt throws vault::Error on failure.
void gcm_encrypt(const uint8_t key[VC_KEY_LEN], const uint8_t nonce[VC_NONCE_LEN],
                 const uint8_t* aad, size_t aad_len,
                 const uint8_t* pt, size_t pt_len,
                 uint8_t* ct, uint8_t tag[VC_TAG_LEN]);

// Returns true only if the tag verifies (authentic). pt must hold ct_len bytes.
bool gcm_decrypt(const uint8_t key[VC_KEY_LEN], const uint8_t nonce[VC_NONCE_LEN],
                 const uint8_t* aad, size_t aad_len,
                 const uint8_t* ct, size_t ct_len,
                 const uint8_t tag[VC_TAG_LEN], uint8_t* pt);

void random(uint8_t* buf, size_t len);

// DEK wrap/unwrap. create throws on failure; unwrap returns false on wrong kek.
void dek_create(const uint8_t kek[VC_KEY_LEN], uint8_t out_dek[VC_KEY_LEN],
                uint8_t out_wrapped[VC_WRAPPED_DEK_LEN]);
bool dek_unwrap(const uint8_t kek[VC_KEY_LEN],
                const uint8_t wrapped[VC_WRAPPED_DEK_LEN], uint8_t out_dek[VC_KEY_LEN]);

// Portable bundle (format UNCHANGED). pack throws vault::Error(ESP_ERR_INVALID_SIZE)
// if *out_len < VC_BUNDLE_HDR + plain_len; on success *out_len = total length.
void bundle_pack(const char* password, size_t pw_len,
                 const uint8_t* plain, size_t plain_len,
                 uint8_t* out, size_t* out_len);

enum class BundleResult { Ok, WrongPassword, BadMagic, BadVersion, TooSmall };

// On entry *out_len = capacity; on Ok *out_len = plaintext length.
BundleResult bundle_unpack(const char* password, size_t pw_len,
                           const uint8_t* bundle, size_t bundle_len,
                           uint8_t* out_plain, size_t* out_len);

}  // namespace vault::crypto
```

- [ ] **Step 3: Convert the source — rename `.c` to `.cpp` and adapt**

Run:
```
git mv components/vault_crypto/vault_crypto.c components/vault_crypto/vault_crypto.cpp
```
Then edit `vault_crypto.cpp`:
- Add `#include "vault_error.h"` and wrap all definitions in `namespace vault::crypto {` … `}`.
- Change include guards: `#include <string.h>` is fine; the PSA/sha/freertos includes are unchanged.
- `vc_init` → `void init() { if (psa_crypto_init() != PSA_SUCCESS) throw Error(ESP_FAIL, "psa init"); }` (use `vault::Error` — in this namespace `Error` resolves via `vault::`; write `throw vault::Error(...)`).
- `vc_derive_key` → `void derive_key(...)`: replace `if (!password ...) return ESP_ERR_INVALID_ARG;` with `if (!password || !salt || !out_key) throw vault::Error(ESP_ERR_INVALID_ARG, "derive_key args");`. Replace `_Static_assert` with `static_assert`. Drop the final `return ESP_OK;` (now `void`). Body otherwise identical.
- `vc_random` → `void random(...)` (body identical).
- `import_aes_key` stays a file-local `static` helper (keep inside the namespace; returns `psa_status_t`).
- `vc_gcm_encrypt` → `void gcm_encrypt(...)`: keep the `goto done` body; at the end replace `return (status == PSA_SUCCESS) ? ESP_OK : ESP_FAIL;` with `if (status != PSA_SUCCESS) throw vault::Error(ESP_FAIL, "gcm encrypt");`. (The early `import_aes_key(...) != PSA_SUCCESS` path: `throw vault::Error(ESP_FAIL, "gcm key import");`.) **Note:** a `goto` may not jump *into* the scope of a variable with a non-trivial initializer; the existing labels jump only forward over POD assignments, which is legal in C++. Keep as-is.
- `vc_gcm_decrypt` → `bool gcm_decrypt(...)`: same structure, but the function returns `bool`. The import-failure and any setup-failure now mean "not authentic / failed" → `return false;` (matches today's `ESP_FAIL`). Final line: `return status == PSA_SUCCESS;`.
- `vc_dek_create` → `void dek_create(...)`: `vc_random`→`random`, `vc_gcm_encrypt`→`gcm_encrypt` (now void/throwing). Body otherwise identical; drop the return.
- `vc_dek_unwrap` → `bool dek_unwrap(...)`: `vc_gcm_decrypt`→`gcm_decrypt`; `return gcm_decrypt(kek, nonce, nullptr, 0, ct, VC_KEY_LEN, tag, out_dek);`.
- `vc_bundle_pack` → `void bundle_pack(...)`: replace `if (*out_len < ...) return ESP_ERR_INVALID_SIZE;` with `throw vault::Error(ESP_ERR_INVALID_SIZE, "bundle too small");`. Replace `vc_derive_key`→`derive_key` (now throwing; remove its error check). Replace `vc_gcm_encrypt`→`gcm_encrypt` (throwing). Set `*out_len = VC_BUNDLE_HDR + plain_len;` at the end; drop returns.
- `vc_bundle_unpack` → `BundleResult bundle_unpack(...)`: map the early returns to enum values — `bundle_len < VC_BUNDLE_HDR` → `return BundleResult::TooSmall;`; bad magic → `BadMagic`; bad version → `BadVersion`; `*out_len < ct_len` → `TooSmall`. Replace `vc_derive_key`→`derive_key` (throwing). Replace the decrypt: `if (!gcm_decrypt(...)) return BundleResult::WrongPassword;` then `*out_len = ct_len; return BundleResult::Ok;`.
- `BUNDLE_MAGIC` / `BUNDLE_ITERATIONS` stay file-local `static` constants inside the namespace.

- [ ] **Step 4: Update `components/vault_crypto/CMakeLists.txt`**

```cmake
idf_component_register(SRCS "vault_crypto.cpp"
                       INCLUDE_DIRS "include"
                       REQUIRES mbedtls esp_hw_support vault_error)
```

- [ ] **Step 5: Update `components/vault_crypto/test/CMakeLists.txt`**

```cmake
idf_component_register(SRCS "test_vault_crypto.cpp"
                       INCLUDE_DIRS "."
                       REQUIRES doctest vault_crypto)
```

- [ ] **Step 6: Rename the test file**

Run:
```
git mv components/vault_crypto/test/test_vault_crypto.c components/vault_crypto/test/test_vault_crypto.cpp
```
(The contents were already replaced in Step 1.)

- [ ] **Step 7: Build-verify the main app** (compiles the component; full test-app build happens in Task 13)

Run (background, then poll):
```
cmd /c 'set "MSYSTEM=" && call C:\esp\v6.0.1\esp-idf\export.bat && idf.py build'
```
Expected: build succeeds. (The app does not yet use the new API directly — `main.c` still calls `vc_init()` etc. **This will fail to link** because `vc_init` no longer exists.)

> **Important sequencing note:** the main app's `main.c` calls the old C API and will not build until Task 13. To keep build-verification meaningful per task, **defer the full main-app build to Task 13** and verify Layer-0/1/2/3 components by building the **test app** once doctest is wired (Task 13), OR temporarily build only the component via a throwaway. The pragmatic checkpoint: after each component task, run `idf.py build` and confirm the **error is only the expected `main.c` link error against the converted symbols**, not a compile error inside the converted component. Compile errors inside the component are real failures to fix now.

- [ ] **Step 8: Commit**

```bash
git add components/vault_crypto
git commit -m "Convert vault_crypto to vault::crypto namespace (C++); port tests to doctest"
```

---

## Task 5: Convert `vault_store` to the `vault::Store` class

**Files:**
- Modify: `components/vault_store/include/vault_store.h`
- Rename+modify: `components/vault_store/vault_store.c` → `.cpp`
- Modify: `components/vault_store/CMakeLists.txt`
- Rename+rewrite: `components/vault_store/test/test_vault_store.c` → `.cpp`
- Modify: `components/vault_store/test/CMakeLists.txt`

> RAII wrapper over the `"vault"` NVS namespace. Constructor does `nvs_flash_init` (with the erase-and-retry on version/space errors). `get_blob` returns `false` when the key is absent (today's `ESP_ERR_NVS_NOT_FOUND`) and throws on other faults. `erase_key` tolerates a missing key (factory-reset erases keys that may not exist) and throws on other faults.

- [ ] **Step 1: Write the failing test — `components/vault_store/test/test_vault_store.cpp`**

```cpp
#include "doctest/doctest.h"
#include "vault_store.h"
#include <cstring>

using namespace vault;

TEST_CASE("blob set/get round-trips through NVS") {
    Store store;
    const char* payload = "wrapped-dek-bytes";
    store.set_blob("t_dek", payload, strlen(payload));
    store.commit();

    char buf[64]; size_t len = sizeof buf;
    CHECK(store.get_blob("t_dek", buf, len));
    CHECK(len == strlen(payload));
    CHECK(memcmp(payload, buf, len) == 0);

    store.erase_key("t_dek");
    store.commit();
    len = sizeof buf;
    CHECK_FALSE(store.get_blob("t_dek", buf, len));   // absent now
}
```

- [ ] **Step 2: Rewrite the header — `components/vault_store/include/vault_store.h`**

```cpp
#pragma once
#include <cstddef>
#include "esp_err.h"

namespace vault {

// Thin typed RAII wrapper over the "vault" NVS namespace. Blob keys are <=15 chars.
class Store {
public:
    Store();   // nvs_flash_init (erase+retry on version/space error); throws vault::Error on failure

    void set_blob(const char* key, const void* data, size_t len);   // throws on failure
    // On entry len = buffer size; on success len = bytes read. Returns false if the
    // key is absent. Pass out=nullptr to query the size (len receives it). Throws on
    // faults other than not-found.
    bool get_blob(const char* key, void* out, size_t& len);
    void erase_key(const char* key);   // tolerates a missing key; throws on other faults
    void commit();
};

}  // namespace vault
```

- [ ] **Step 3: Convert the source**

Run:
```
git mv components/vault_store/vault_store.c components/vault_store/vault_store.cpp
```
Rewrite `vault_store.cpp`:
```cpp
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
```
> Behavior note: the original `get_blob` returned `nvs_open`'s error if the namespace didn't exist. Returning `false` for a not-yet-created namespace matches how callers use it (treat as "absent").

- [ ] **Step 4: Update `components/vault_store/CMakeLists.txt`**

```cmake
idf_component_register(SRCS "vault_store.cpp"
                       INCLUDE_DIRS "include"
                       REQUIRES nvs_flash vault_error)
```

- [ ] **Step 5: Update `components/vault_store/test/CMakeLists.txt`**

```cmake
idf_component_register(SRCS "test_vault_store.cpp"
                       INCLUDE_DIRS "."
                       REQUIRES doctest vault_store)
```

- [ ] **Step 6: Rename the test file**

```
git mv components/vault_store/test/test_vault_store.c components/vault_store/test/test_vault_store.cpp
```

- [ ] **Step 7: Commit**

```bash
git add components/vault_store
git commit -m "Convert vault_store to vault::Store RAII class (C++); port tests to doctest"
```

---

## Task 6: Convert `net_wifi_ap` to the `vault::WifiAp` class

**Files:**
- Modify: `components/net_wifi_ap/include/net_wifi_ap.h`
- Rename+modify: `components/net_wifi_ap/net_wifi_ap.c` → `.cpp`
- Modify: `components/net_wifi_ap/CMakeLists.txt`

> Independent leaf; no vault deps. `start` throws on failure.

- [ ] **Step 1: Rewrite the header**

```cpp
#pragma once
#include <cstddef>

namespace vault {

// Brings up softAP "esp32key" with the given WPA2 password (>=8 chars; falls back
// to OPEN if shorter). Assumes esp_netif_init() + esp_event_loop_create_default()
// already ran.
class WifiAp {
public:
    void start(const char* password);   // throws vault::Error on failure
};

}  // namespace vault
```

- [ ] **Step 2: Convert the source**

```
git mv components/net_wifi_ap/net_wifi_ap.c components/net_wifi_ap/net_wifi_ap.cpp
```
Rewrite `net_wifi_ap.cpp`:
```cpp
#include "net_wifi_ap.h"
#include "vault_error.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include <cstring>

namespace vault {

void WifiAp::start(const char* password) {
    esp_netif_create_default_wifi_ap();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    check(esp_wifi_init(&cfg), "wifi init");

    wifi_config_t ap = {};
    strlcpy((char*)ap.ap.ssid, "esp32key", sizeof ap.ap.ssid);
    ap.ap.ssid_len = strlen("esp32key");
    ap.ap.channel = 1;
    ap.ap.max_connection = 2;
    ap.ap.authmode = WIFI_AUTH_WPA2_PSK;
    strlcpy((char*)ap.ap.password, password, sizeof ap.ap.password);
    if (strlen(password) < 8) ap.ap.authmode = WIFI_AUTH_OPEN;  // avoid silent fail

    check(esp_wifi_set_mode(WIFI_MODE_AP), "wifi mode");
    check(esp_wifi_set_config(WIFI_IF_AP, &ap), "wifi config");
    check(esp_wifi_start(), "wifi start");
}

}  // namespace vault
```
> `wifi_config_t ap = {};` replaces `= {0}` (valid C++ value-init).

- [ ] **Step 3: Update `components/net_wifi_ap/CMakeLists.txt`**

```cmake
idf_component_register(SRCS "net_wifi_ap.cpp"
                       INCLUDE_DIRS "include"
                       REQUIRES esp_wifi esp_netif vault_error)
```

- [ ] **Step 4: Commit**

```bash
git add components/net_wifi_ap
git commit -m "Convert net_wifi_ap to vault::WifiAp class (C++)"
```

---

## Task 7: Convert `net_usb` to the `vault::UsbNet` class

**Files:**
- Modify: `components/net_usb/include/net_usb.h`
- Rename+modify: `components/net_usb/net_usb.c` → `.cpp`
- Modify: `components/net_usb/CMakeLists.txt`

> Independent leaf. The TinyUSB↔esp_netif glue callbacks (`rx_cb`, `netif_transmit`, `l2_free`) are C function pointers with no user-context slot, and the NCM interface is genuinely a singleton, so the `esp_netif_t*` stays a file-local `static`. The class is a thin wrapper over `start()`.

- [ ] **Step 1: Rewrite the header**

```cpp
#pragma once

namespace vault {

// Brings up a TinyUSB NCM interface with static IP 10.10.0.1 and a DHCP server
// handing out 10.10.0.2+ to the host.
class UsbNet {
public:
    void start();   // throws vault::Error on failure
};

}  // namespace vault
```

- [ ] **Step 2: Convert the source**

```
git mv components/net_usb/net_usb.c components/net_usb/net_usb.cpp
```
Edit `net_usb.cpp`:
- Add `#include "vault_error.h"`.
- Keep `static esp_netif_t* s_usb_netif;` and the three glue callbacks (`rx_cb`, `netif_transmit`, `l2_free`) as file-local `static` functions with **C++ linkage** (TinyUSB/esp_netif accept them as plain function pointers — fine). Put them and `start` inside `namespace vault {}` **except** keep the callbacks at file scope outside the namespace (or inside — either links; keep inside the namespace for tidiness, they're only referenced locally).
- Convert `net_usb_start` into `void UsbNet::start()`.
- Replace the designated initializers per the convention:
  ```cpp
  esp_netif_inherent_config_t base = ESP_NETIF_INHERENT_DEFAULT_ETH();
  base.if_desc = "usb";
  base.route_prio = 10;
  base.flags = (esp_netif_flags_t)(ESP_NETIF_DHCP_SERVER | ESP_NETIF_FLAG_AUTOUP);

  esp_netif_ip_info_t ip = {};
  ip.ip.addr      = ESP_IP4TOADDR(10, 10, 0, 1);
  ip.gw.addr      = ESP_IP4TOADDR(10, 10, 0, 1);
  ip.netmask.addr = ESP_IP4TOADDR(255, 255, 255, 0);
  base.ip_info = &ip;

  esp_netif_config_t cfg = {};
  cfg.base  = &base;
  cfg.driver = nullptr;
  cfg.stack = ESP_NETIF_NETSTACK_DEFAULT_ETH;
  s_usb_netif = esp_netif_new(&cfg);

  esp_netif_driver_ifconfig_t drv = {};
  drv.handle = (void*)1;
  drv.transmit = netif_transmit;
  drv.driver_free_rx_buffer = l2_free;
  check(esp_netif_set_driver_config(s_usb_netif, &drv), "usb netif driver");

  tinyusb_config_t tusb_cfg = {};
  tusb_cfg.external_phy = false;
  check(tinyusb_driver_install(&tusb_cfg), "tinyusb install");

  tinyusb_net_config_t net_cfg = {};
  net_cfg.on_recv_callback = rx_cb;
  memcpy(net_cfg.mac_addr, mac, 6);
  check(tinyusb_net_init(TINYUSB_USBDEV_0, &net_cfg), "tinyusb net init");
  ```
  > Note the `(esp_netif_flags_t)` cast: in C++, OR-ing two enum values yields `int`, which won't implicitly convert back to the enum field. Cast it.
- Replace the trailing `ESP_ERROR_CHECK(...)` macros that were already there with `check(...)` is optional; `ESP_ERROR_CHECK` still works in C++. Keep `esp_netif_action_start/connected` lines and the final `return ESP_OK;` becomes nothing (void).

- [ ] **Step 3: Update `components/net_usb/CMakeLists.txt`**

```cmake
idf_component_register(SRCS "net_usb.cpp"
                       INCLUDE_DIRS "include"
                       REQUIRES esp_netif vault_error)
```

- [ ] **Step 4: Commit**

```bash
git add components/net_usb
git commit -m "Convert net_usb to vault::UsbNet class (C++)"
```

---

## Task 8: Convert `vault_session` to the `vault::Session` class

**Files:**
- Modify: `components/vault_session/include/vault_session.h`
- Rename+modify: `components/vault_session/vault_session.c` → `.cpp`
- Modify: `components/vault_session/CMakeLists.txt`
- Rename+rewrite: `components/vault_session/test/test_vault_session.c` → `.cpp`
- Modify: `components/vault_session/test/CMakeLists.txt`

> All file-statics become members. Keep the `VS_*` macros. `set_expiry_cb` takes a `std::function<void()>`. Single-threaded (httpd task) contract unchanged. Uses `vault::crypto::random` for token bytes.

- [ ] **Step 1: Write the failing test — `components/vault_session/test/test_vault_session.cpp`**

```cpp
#include "doctest/doctest.h"
#include "vault_session.h"
#include <cstring>

using namespace vault;

TEST_CASE("token validates, expires on idle, dies on logout") {
    Session s;
    char tok[VS_TOKEN_HEX];
    s.create(1000, tok);
    CHECK(s.validate(tok, 1000 + VS_IDLE_MS - 1));
    // validation refreshed the timer above; advance from there
    CHECK_FALSE(s.validate(tok, 1000 + 2 * VS_IDLE_MS + 10));

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
    CHECK_FALSE(s.login_allowed(0));                  // locked out
    CHECK_FALSE(s.login_allowed(VS_LOCKOUT_MS - 1));
    CHECK(s.login_allowed(VS_LOCKOUT_MS + 1));        // window passed

    s.note_login_result(true, VS_LOCKOUT_MS + 1);     // success resets
    CHECK(s.login_allowed(VS_LOCKOUT_MS + 2));
}
```

- [ ] **Step 2: Rewrite the header — `components/vault_session/include/vault_session.h`**

Keep the `VS_*` macros exactly. Replace declarations:
```cpp
#pragma once
#include <cstdint>
#include <cstddef>
#include <functional>

#define VS_TOKEN_LEN   32          /* bytes; hex-encoded => 64 chars */
#define VS_TOKEN_HEX   (VS_TOKEN_LEN * 2 + 1)
#define VS_IDLE_MS     (3 * 60 * 1000)
#define VS_MAX_FAILS   5
#define VS_LOCKOUT_MS  (60 * 1000)

namespace vault {

class Session {
public:
    using ExpiryCallback = std::function<void()>;

    void reset();                                 // clear session + fail counter (test aid)
    void set_expiry_cb(ExpiryCallback cb);        // fired on idle expiry (e.g. Vault::lock)

    bool login_allowed(uint64_t now_ms);          // false if currently locked out
    void note_login_result(bool success, uint64_t now_ms);

    void create(uint64_t now_ms, char out_token_hex[VS_TOKEN_HEX]);
    bool validate(const char* token_hex, uint64_t now_ms);  // refreshes idle timer on success

    bool check_idle(uint64_t now_ms);             // expire + fire cb if idle too long
    uint32_t idle_remaining_ms(uint64_t now_ms);  // ms until idle-out (0 if none/expired)
    void destroy();                               // logout

private:
    char     token_[VS_TOKEN_HEX] = {0};
    bool     active_ = false;
    uint64_t last_seen_ms_ = 0;
    int      fail_count_ = 0;
    uint64_t lockout_until_ms_ = 0;
    ExpiryCallback expiry_cb_;
};

}  // namespace vault
```

- [ ] **Step 3: Convert the source**

```
git mv components/vault_session/vault_session.c components/vault_session/vault_session.cpp
```
Rewrite `vault_session.cpp`:
```cpp
#include "vault_session.h"
#include "vault_crypto.h"
#include <cstring>

namespace vault {

namespace {
void to_hex(const uint8_t* in, size_t n, char* out) {
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { out[2*i] = d[in[i] >> 4]; out[2*i+1] = d[in[i] & 0xf]; }
    out[2*n] = '\0';
}
// constant-time string compare
bool ct_eq(const char* a, const char* b) {
    size_t la = strlen(a), lb = strlen(b);
    if (la != lb) return false;
    uint8_t diff = 0;
    for (size_t i = 0; i < la; i++) diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}
}  // namespace

void Session::set_expiry_cb(ExpiryCallback cb) { expiry_cb_ = std::move(cb); }

void Session::reset() {
    active_ = false; token_[0] = '\0'; last_seen_ms_ = 0;
    fail_count_ = 0; lockout_until_ms_ = 0;
}

bool Session::login_allowed(uint64_t now_ms) {
    if (fail_count_ >= VS_MAX_FAILS && now_ms < lockout_until_ms_) return false;
    if (fail_count_ >= VS_MAX_FAILS && now_ms >= lockout_until_ms_) fail_count_ = 0;
    return true;
}

void Session::note_login_result(bool success, uint64_t now_ms) {
    if (success) { fail_count_ = 0; lockout_until_ms_ = 0; return; }
    fail_count_++;
    if (fail_count_ >= VS_MAX_FAILS) lockout_until_ms_ = now_ms + VS_LOCKOUT_MS;
}

void Session::create(uint64_t now_ms, char out_token_hex[VS_TOKEN_HEX]) {
    uint8_t raw[VS_TOKEN_LEN]; crypto::random(raw, sizeof raw);
    to_hex(raw, sizeof raw, token_);
    active_ = true; last_seen_ms_ = now_ms;
    strcpy(out_token_hex, token_);
}

bool Session::check_idle(uint64_t now_ms) {
    if (!active_) return false;
    if (now_ms - last_seen_ms_ > VS_IDLE_MS) {
        destroy();
        if (expiry_cb_) expiry_cb_();   // e.g. Vault::lock(): wipe DEK on idle
        return true;
    }
    return false;
}

uint32_t Session::idle_remaining_ms(uint64_t now_ms) {
    if (!active_) return 0;
    uint64_t elapsed = now_ms - last_seen_ms_;
    if (elapsed >= VS_IDLE_MS) return 0;
    return (uint32_t)(VS_IDLE_MS - elapsed);
}

bool Session::validate(const char* token_hex, uint64_t now_ms) {
    if (!active_ || !token_hex || token_hex[0] == '\0') return false;
    if (check_idle(now_ms)) return false;
    if (!ct_eq(token_hex, token_)) return false;
    last_seen_ms_ = now_ms;
    return true;
}

void Session::destroy() {
    active_ = false;
    memset(token_, 0, sizeof token_);
}

}  // namespace vault
```

- [ ] **Step 4: Update `components/vault_session/CMakeLists.txt`**

```cmake
idf_component_register(SRCS "vault_session.cpp"
                       INCLUDE_DIRS "include"
                       REQUIRES vault_crypto)
```

- [ ] **Step 5: Update `components/vault_session/test/CMakeLists.txt`**

```cmake
idf_component_register(SRCS "test_vault_session.cpp"
                       INCLUDE_DIRS "."
                       REQUIRES doctest vault_session)
```

- [ ] **Step 6: Rename the test file**

```
git mv components/vault_session/test/test_vault_session.c components/vault_session/test/test_vault_session.cpp
```

- [ ] **Step 7: Commit**

```bash
git add components/vault_session
git commit -m "Convert vault_session to vault::Session class (C++); port tests to doctest"
```

---

## Task 9: Convert `vault_cert` to the `vault::Cert` class

**Files:**
- Modify: `components/vault_cert/include/vault_cert.h`
- Rename+modify: `components/vault_cert/vault_cert.c` → `.cpp`
- Modify: `components/vault_cert/CMakeLists.txt`

> Takes a `Store&`. `get()` keeps the malloc'd-buffer / caller-frees contract (consumed by `app_main` → `ApiServer::start`). The two NVS helpers (`vs_get_blob`/`vs_set_blob`/`vs_commit`) become `store_.get_blob(...)` etc. The mbedTLS generation body is unchanged except the store calls and the malloc casts.

- [ ] **Step 1: Rewrite the header**

```cpp
#pragma once
#include <cstddef>
#include "vault_store.h"

namespace vault {

// Loads a PEM cert+key pair from NVS (via Store), generating and persisting a new
// self-signed pair on first call or when the cached schema is stale. Output buffers
// are malloc'd; caller frees. Throws vault::Error on failure.
class Cert {
public:
    explicit Cert(Store& store) : store_(store) {}
    void get(char** cert_pem, size_t* cert_len, char** key_pem, size_t* key_len);
private:
    Store& store_;
};

}  // namespace vault
```

- [ ] **Step 2: Convert the source**

```
git mv components/vault_cert/vault_cert.c components/vault_cert/vault_cert.cpp
```
Edit `vault_cert.cpp`:
- Replace `#include "vault_cert.h"` / `#include "vault_store.h"` and add `#include "vault_error.h"`. Wrap definitions in `namespace vault {}`.
- `generate(...)` becomes `void Cert::generate(...)` — **but** it's a private member now. Add it to the header as a private method `void generate(char** cert_pem, size_t* cert_len, char** key_pem, size_t* key_len);` OR keep it a file-local `static` helper that takes `Store&`. **Simplest:** keep `generate` as a file-local `static` function with an added `Store& store` parameter. Change its signature to `static void generate(Store& store, char** cert_pem, size_t* cert_len, char** key_pem, size_t* key_len);`.
- In `generate`: the `result`/`goto done` pattern returns `esp_err_t` today. Convert to throwing: on each `goto done` failure path, instead set up so that after `done:` cleanup, if not successful, `throw vault::Error(ESP_FAIL, "cert generate")`. Concretely: keep a local `bool ok = false;` initialized false; keep all the `goto done;` jumps; set `ok = true;` only after the final successful store-commit block; after the `done:` cleanup of mbedtls/psa, `if (!ok) throw vault::Error(...);`. Replace `result = ESP_ERR_NO_MEM;` paths with their own throw after cleanup (or set a code variable). To keep it simple: keep an `esp_err_t rc = ESP_FAIL;` exactly as the old `result`, do all cleanup under `done:`, then `if (rc != ESP_OK) throw vault::Error(rc, "cert generate");`.
- Replace `malloc` with casts: `*key_pem = (char*)malloc(*key_len);` etc.
- Replace `vs_set_blob(PKEY_KEY, ...)==ESP_OK && ...` chain: since `Store::set_blob`/`commit` throw on failure, rewrite the success block as straight calls; wrap in try/catch only if you need the old "free buffers on failure" behavior. Concretely:
  ```cpp
  uint8_t cver = CERT_SCHEMA_VERSION;
  try {
      store.set_blob(PKEY_KEY, *key_pem, *key_len);
      store.set_blob(CERT_KEY, *cert_pem, *cert_len);
      store.set_blob(CVER_KEY, &cver, sizeof cver);
      store.commit();
      rc = ESP_OK;
  } catch (...) {
      free(*key_pem);  *key_pem = nullptr;
      free(*cert_pem); *cert_pem = nullptr;
      throw;
  }
  ```
- `Cert::get(...)`: replace the `vs_get_blob` calls. `vs_get_blob(CVER_KEY,&cver,&cvlen)==ESP_OK && cver==...` → `size_t cvlen = sizeof cver; bool cver_ok = store_.get_blob(CVER_KEY, &cver, cvlen) && cver == CERT_SCHEMA_VERSION;`. The length-query calls `vs_get_blob(CERT_KEY, NULL, &clen)==ESP_OK` → `store_.get_blob(CERT_KEY, nullptr, clen)`. malloc casts. The final fall-through `return generate(cert_pem, ...);` → `generate(store_, cert_pem, cert_len, key_pem, key_len);` (now void/throwing). Remove the `if (!cert_pem||...) return ESP_ERR_INVALID_ARG;` guard or convert to `throw vault::Error(ESP_ERR_INVALID_ARG, "cert get args");`. The reused-cert success path sets the out params and returns (void). The `ESP_FAIL` read-back failure path → `throw vault::Error(ESP_FAIL, "cert read");` after freeing.

- [ ] **Step 3: Update `components/vault_cert/CMakeLists.txt`**

```cmake
idf_component_register(SRCS "vault_cert.cpp"
                       INCLUDE_DIRS "include"
                       REQUIRES mbedtls vault_store vault_error)
```

- [ ] **Step 4: Commit**

```bash
git add components/vault_cert
git commit -m "Convert vault_cert to vault::Cert class (C++)"
```

---

## Task 10: Convert `vault` to the `vault::Vault` class

**Files:**
- Modify: `components/vault/include/vault.h`
- Rename+modify: `components/vault/vault.c` → `.cpp`
- Modify: `components/vault/CMakeLists.txt`
- Rename+rewrite: `components/vault/test/test_vault.c` → `.cpp`
- Modify: `components/vault/test/CMakeLists.txt`

> The largest component. Keep the POD structs (`vault_entry_t`, `vault_category_t`) and all macros exactly. All `s_*` file-statics become members. The body moves nearly verbatim with the substitution table below. Constructor takes `Store&`. The entry-delete method is named **`remove`** (`delete` is reserved). A destructor frees the PSRAM buffers.

> **Existing test caveat:** `components/vault/test/test_vault.c` uses an OUTDATED API (`vault_add` with 4 args, `vault_reveal` with 2). The current header's signatures (7-arg add, 4-arg reveal, etc.) are authoritative. The doctest rewrite below targets the **current** signatures.

- [ ] **Step 1: Rewrite the header — `components/vault/include/vault.h`**

Keep the macros (`VAULT_MAX_ENTRIES`, `VAULT_FIELD_MAX`, `VAULT_CAT_NAME_MAX`, `VAULT_MAX_CATEGORIES`) and both `typedef struct {...} vault_entry_t;` / `vault_category_t` exactly as today. Replace the function declarations with a class:
```cpp
#pragma once
#include <cstdbool>
#include <cstddef>
#include <cstdint>
#include "esp_err.h"
#include "vault_store.h"
#include "vault_crypto.h"   // VC_KEY_LEN etc. for member buffers

#define VAULT_MAX_ENTRIES     64
#define VAULT_FIELD_MAX       128
#define VAULT_CAT_NAME_MAX    32
#define VAULT_MAX_CATEGORIES  32

typedef struct {
    uint8_t  id;
    uint8_t  category_id;               /* 0 = Uncategorized */
    char     title[VAULT_FIELD_MAX];
    char     username[VAULT_FIELD_MAX];
    char     url[VAULT_FIELD_MAX];      /* only populated after reveal */
    char     secret[VAULT_FIELD_MAX];   /* only populated after reveal */
    char     comment[VAULT_FIELD_MAX];  /* only populated after reveal */
} vault_entry_t;

typedef struct {
    uint8_t  id;                        /* 1..255; 0 reserved for Uncategorized */
    char     name[VAULT_CAT_NAME_MAX];
} vault_category_t;

namespace vault {

class Vault {
public:
    explicit Vault(Store& store) : store_(store) {}
    ~Vault();   // frees PSRAM buffers

    void init();              // boot-time format check / auto-reset
    bool is_initialized();
    bool is_unlocked() const { return unlocked_; }
    bool is_busy() const { return deriving_; }

    void setup(const char* master, size_t master_len);   // throws InvalidState if already init
    bool unlock(const char* master, size_t master_len);  // false on wrong pw; throws InvalidState if not init
    void lock();
    bool change_password(const char* cur, size_t cur_len,
                         const char* next, size_t next_len);  // false on wrong current pw

    // CRUD — throw vault::Error(ESP_ERR_INVALID_STATE) if locked.
    size_t list(vault_entry_t* out, size_t cap);           // returns count
    bool   reveal(uint8_t id, char secret_out[VAULT_FIELD_MAX],
                  char url_out[VAULT_FIELD_MAX],
                  char comment_out[VAULT_FIELD_MAX]);        // false if id not found
    uint8_t add(const char* title, const char* username, const char* secret,
                const char* url, const char* comment, uint8_t category_id); // returns new id; throws on full
    bool   update(uint8_t id, const char* title, const char* username,
                  const char* secret, const char* url, const char* comment,
                  uint8_t category_id);                      // false if id not found
    bool   remove(uint8_t id);                               // false if id not found
    void   clear_entries();

    // Categories — throw InvalidState if locked.
    size_t  category_list(vault_category_t* out, size_t cap);
    uint8_t category_add(const char* name);   // returns id; throws Error(ESP_ERR_INVALID_STATE) on duplicate
    bool    category_delete(uint8_t id);       // false if not found; throws InvalidArg if id==0

    void set_transfer_password(const char* pw, size_t len);
    bool verify_transfer(const char* pw, size_t len);

    // Binary bundle export/import (used by tests). out_bundle is malloc'd; caller frees.
    bool export_bundle(const char* transfer_pw, size_t len, uint8_t** out_bundle, size_t* out_len); // false on wrong pw
    void bulk_begin();
    void bulk_commit();                        // throws InvalidState if locked
    bool import_bundle(const char* transfer_pw, size_t len,
                       const uint8_t* bundle, size_t bundle_len);  // false on wrong pw / bad format

    void factory_reset();

private:
    // ---- helpers (were file-local statics) ----
    bool   ensure_buffers();   // allocate PSRAM buffers; returns false on OOM
    size_t serialize_entries(uint8_t* plain);
    void   persist_entries();  // throws on store/crypto fault
    void   load_entries();
    void   persist_cats();
    void   load_cats();
    void   load_kek(const char* master, size_t mlen, uint8_t kek[VC_KEY_LEN]); // throws InvalidState if no salt
    vault_entry_t* find(uint8_t id);
    uint8_t alloc_id();
    uint8_t alloc_cat_id();
    bool    category_valid(uint8_t id);

    Store& store_;
    bool   unlocked_ = false;
    uint8_t dek_[VC_KEY_LEN] = {0};
    vault_entry_t*   entries_   = nullptr;   // VAULT_MAX_ENTRIES (PSRAM)
    uint8_t*         io_plain_  = nullptr;   // PLAIN_MAX (PSRAM)
    uint8_t*         io_blob_   = nullptr;   // BLOB_MAX (PSRAM)
    size_t           count_     = 0;
    bool             bulk_      = false;
    volatile bool    deriving_  = false;
    vault_category_t cats_[VAULT_MAX_CATEGORIES] = {};
    size_t           cat_count_ = 0;
};

}  // namespace vault
```

- [ ] **Step 2: Convert the source — `git mv` then transform**

```
git mv components/vault/vault.c components/vault/vault.cpp
```
Edit `vault.cpp`. The `#define`s for internal layout (`ITERATIONS`, `VAULT_FORMAT_VERSION`, `REC_SIZE`, `PLAIN_MAX`, `ENTRIES_HDR`, `BLOB_MAX`, `CAT_REC_SIZE`, `CATS_PLAIN_MAX`, `CATS_BLOB_MAX`, `XFER_CHECK`, `TVERIF_LEN`) stay verbatim at file scope. Add `#include "vault_error.h"`. Wrap all definitions in `namespace vault {}`. Apply this **substitution table** to every function body (bodies otherwise move verbatim):

  | C (old) | C++ (new) |
  |---|---|
  | `s_unlocked` | `unlocked_` |
  | `s_dek` | `dek_` |
  | `s_entries` | `entries_` |
  | `s_io_plain` | `io_plain_` |
  | `s_io_blob` | `io_blob_` |
  | `s_count` | `count_` |
  | `s_bulk` | `bulk_` |
  | `s_deriving` | `deriving_` |
  | `s_cats` | `cats_` |
  | `s_cat_count` | `cat_count_` |
  | `vc_random(` | `crypto::random(` |
  | `vc_derive_key(...)` | `crypto::derive_key(...)` (throws; drop `!= ESP_OK` checks → on the wrong-pw paths it no longer fails, so those checks become unreachable; see per-function notes) |
  | `vc_gcm_encrypt(...) != ESP_OK` | wrap: it throws now; remove the check, or keep `crypto::gcm_encrypt(...)` and let it throw |
  | `vc_gcm_decrypt(...) == ESP_OK` | `crypto::gcm_decrypt(...)` (returns bool) |
  | `vc_dek_create(...) != ESP_OK` | `crypto::dek_create(...)` (throws) |
  | `vc_dek_unwrap(...) != ESP_OK` | `!crypto::dek_unwrap(...)` (returns bool) |
  | `vc_bundle_pack(...)` | `crypto::bundle_pack(...)` (throws on size) |
  | `vc_bundle_unpack(...) != ESP_OK` | `crypto::bundle_unpack(...) != crypto::BundleResult::Ok` |
  | `vs_get_blob(k, p, &len) == ESP_OK` | `store_.get_blob(k, p, len)` (note `&len`→`len`) |
  | `vs_get_blob(k, p, &len) == ESP_ERR_NVS_NOT_FOUND` | `!store_.get_blob(k, p, len)` |
  | `vs_set_blob(k, p, n)` | `store_.set_blob(k, p, n)` (throws) |
  | `vs_erase_key(k)` | `store_.erase_key(k)` |
  | `vs_commit()` | `store_.commit()` |
  | `heap_caps_calloc(...)` / `heap_caps_malloc(...)` | add cast: `(vault_entry_t*)heap_caps_calloc(...)`, `(uint8_t*)heap_caps_malloc(...)` |
  | `malloc(cap)` | `(uint8_t*)malloc(cap)` |

  Then apply these **per-function** adaptations (signatures change to match the header):

  - `vault_is_unlocked` / `vault_is_busy` are now inline in the header — **delete** their definitions from the .cpp.
  - `vault_is_initialized` → `bool Vault::is_initialized()`: `return store_.get_blob("wdek", wdek, len);` (get_blob already returns bool).
  - `ensure_buffers` → `bool Vault::ensure_buffers()`: returns `bool` (was esp_err). Replace `return ... ? ESP_OK : ESP_ERR_NO_MEM;` with `return entries_ && io_plain_ && io_blob_;`.
  - `vault_init` → `void Vault::init()`: `if (!is_initialized()) return;` … `if (store_.get_blob("vfmt", &fmt, flen) && fmt == VAULT_FORMAT_VERSION) return;` … `factory_reset();`.
  - `serialize_entries` → `size_t Vault::serialize_entries(uint8_t* plain)` (body verbatim).
  - `persist_entries` → `void Vault::persist_entries()`: `if (bulk_) return;` … the `vc_gcm_encrypt` throws; `store_.set_blob(...)` then `store_.commit();` (both throw). No return value.
  - `vault_bulk_begin` → `void Vault::bulk_begin() { bulk_ = true; }`.
  - `vault_bulk_commit` → `void Vault::bulk_commit()`: `bulk_ = false; if (!unlocked_) throw vault::Error(ESP_ERR_INVALID_STATE, "locked"); persist_entries();`.
  - `load_entries` → `void Vault::load_entries()`: `size_t blen = BLOB_MAX; bool found = store_.get_blob("entries", io_blob_, blen); count_ = 0; if (!found) return; if (blen < ENTRIES_HDR) throw vault::Error(ESP_FAIL, "corrupt entries"); ... if (!crypto::gcm_decrypt(...)) throw vault::Error(ESP_FAIL, "entries decrypt"); ...` (the decrypt failure here is a genuine fault, not wrong-pw, since the DEK is already correct — throw).
  - `persist_cats` → `void Vault::persist_cats()` (verbatim with substitutions; throws).
  - `load_cats` → `void Vault::load_cats()`: like `load_entries`; `if (!store_.get_blob("cats", blob, blen)) return;` (not-found → empty). Decrypt failure → throw.
  - `vault_setup` → `void Vault::setup(const char* master, size_t mlen)`: `if (is_initialized()) throw vault::Error(ESP_ERR_INVALID_STATE, "already initialized"); if (!ensure_buffers()) throw vault::Error(ESP_ERR_NO_MEM, "buffers"); ...` `crypto::derive_key(...)` (throws), `crypto::dek_create(...)` (throws), `store_.set_blob(...)` × N + `store_.commit()` (throw). `unlocked_ = true; count_ = 0; cat_count_ = 0; persist_cats(); persist_entries();`.
  - `load_kek` → `void Vault::load_kek(const char* master, size_t mlen, uint8_t kek[VC_KEY_LEN])`: `size_t slen = sizeof salt; if (!store_.get_blob("salt", salt, slen)) throw vault::Error(ESP_ERR_INVALID_STATE, "no salt"); uint32_t iter = ITERATIONS; size_t ilen = sizeof iter; store_.get_blob("iter", &iter, ilen); crypto::derive_key(master, mlen, salt, iter, kek);`.
  - `vault_unlock` → `bool Vault::unlock(const char* master, size_t mlen)`: `if (!is_initialized()) throw vault::Error(ESP_ERR_INVALID_STATE, "not initialized"); if (!ensure_buffers()) throw vault::Error(ESP_ERR_NO_MEM, "buffers"); uint8_t kek[VC_KEY_LEN]; deriving_ = true;` — wrap `load_kek` so the flag is always cleared: `try { load_kek(master, mlen, kek); } catch (...) { deriving_ = false; throw; } deriving_ = false;` (load_kek throws only when there's no salt, which `is_initialized()` already implies exists — but keep the guard). Then `uint8_t wdek[VC_WRAPPED_DEK_LEN]; size_t wlen = sizeof wdek; if (!store_.get_blob("wdek", wdek, wlen)) return false; if (!crypto::dek_unwrap(kek, wdek, dek_)) return false;  // wrong pw  unlocked_ = true; try { load_entries(); load_cats(); } catch (...) { lock(); throw; } return true;`.
  - `vault_lock` → `void Vault::lock()` (verbatim with substitutions).
  - `vault_factory_reset` → `void Vault::factory_reset()` (verbatim; `store_.erase_key(...)`, `store_.commit()`).
  - `vault_change_password` → `bool Vault::change_password(...)`: `uint8_t kek[VC_KEY_LEN], dek[VC_KEY_LEN]; load_kek(cur, clen, kek); if (!store_.get_blob("wdek", wdek, wlen)) return false; if (!crypto::dek_unwrap(kek, wdek, dek)) return false;  // wrong current pw` … `crypto::derive_key(next,...)` (throws), `crypto::gcm_encrypt(...)` (throws), store writes + commit (throw), `return true;`. (load_kek may throw if no salt — acceptable; the vault is initialized in all real call paths.)
  - `find`, `alloc_id`, `set_field`, `category_valid`, `alloc_cat_id` → private members / file-local statics. `set_field` has no state → keep as a file-local `static` function. `find`, `alloc_id`, `alloc_cat_id`, `category_valid` touch members → make them member functions (already declared).
  - `vault_list` → `size_t Vault::list(vault_entry_t* out, size_t cap)`: `if (!unlocked_) throw vault::Error(ESP_ERR_INVALID_STATE, "locked");` … `return n;`.
  - `vault_reveal` → `bool Vault::reveal(...)`: `if (!unlocked_) throw ...; auto* e = find(id); if (!e) return false; ...; return true;`.
  - `vault_add` → `uint8_t Vault::add(...)`: `if (!unlocked_) throw ...; if (count_ >= VAULT_MAX_ENTRIES) throw vault::Error(ESP_ERR_NO_MEM, "full"); uint8_t id = alloc_id(); if (id == 0) throw vault::Error(ESP_ERR_NO_MEM, "no id"); ...; persist_entries(); return e->id;`.
  - `vault_update` → `bool Vault::update(...)`: `if (!unlocked_) throw ...; auto* e = find(id); if (!e) return false; ...; persist_entries(); return true;`.
  - `vault_delete` → `bool Vault::remove(uint8_t id)`: `if (!unlocked_) throw ...;` loop; on match do the swap-delete, `persist_entries(); return true;`. After loop `return false;`.
  - `vault_clear_entries` → `void Vault::clear_entries()`: `if (!unlocked_) throw ...;` body verbatim; `persist_entries();`.
  - `vault_category_list` → `size_t Vault::category_list(...)`: `if (!unlocked_) throw ...; ... return n;`.
  - `vault_category_add` → `uint8_t Vault::category_add(const char* name)`: `if (!unlocked_) throw ...; if (!name || !name[0]) throw vault::Error(ESP_ERR_INVALID_ARG, "name"); if (cat_count_ >= VAULT_MAX_CATEGORIES) throw vault::Error(ESP_ERR_NO_MEM, "cats full");` dup check → `throw vault::Error(ESP_ERR_INVALID_STATE, "category exists");` … `persist_cats(); return id;`.
  - `vault_category_delete` → `bool Vault::category_delete(uint8_t id)`: `if (!unlocked_) throw ...; if (id == 0) throw vault::Error(ESP_ERR_INVALID_ARG, "uncategorized");` … if not found `return false;` … `persist_cats(); if (entries_changed) persist_entries(); return true;`.
  - `vault_set_transfer_password` → `void Vault::set_transfer_password(...)`: `crypto::derive_key` (throws), `crypto::gcm_encrypt` (throws), store writes + commit (throw). No return.
  - `vault_verify_transfer` → `bool Vault::verify_transfer(...)`: `if (!store_.get_blob("tsalt", tsalt, sl)) return false; crypto::derive_key(...); if (!store_.get_blob("tverif", verif, vl)) return false; ...; return crypto::gcm_decrypt(...) && memcmp(out, XFER_CHECK, 16) == 0;`.
  - `vault_export` → `bool Vault::export_bundle(const char* transfer_pw, size_t len, uint8_t** out_bundle, size_t* out_len)`: `if (!unlocked_) throw ...; if (!verify_transfer(transfer_pw, len)) return false; ...; uint8_t* buf = (uint8_t*)malloc(cap); if (!buf) throw vault::Error(ESP_ERR_NO_MEM, "export"); size_t blen = cap; try { crypto::bundle_pack(transfer_pw, len, io_plain_, plen, buf, &blen); } catch (...) { free(buf); throw; } *out_bundle = buf; *out_len = blen; return true;`.
  - `vault_import` → `bool Vault::import_bundle(...)`: `if (!unlocked_) throw ...; size_t plen = PLAIN_MAX; if (crypto::bundle_unpack(transfer_pw, len, bundle, bundle_len, io_plain_, &plen) != crypto::BundleResult::Ok) return false;` … the merge loop verbatim (it uses `find`-style inline loops over `entries_`/`count_`, `category_valid`, `alloc_id`, `set_field`) … `persist_entries(); return true;`.
  - Add the destructor at the end:
    ```cpp
    Vault::~Vault() {
        if (entries_)  { free(entries_);  entries_ = nullptr; }
        if (io_plain_) { free(io_plain_); io_plain_ = nullptr; }
        if (io_blob_)  { free(io_blob_);  io_blob_ = nullptr; }
    }
    ```
    > `heap_caps_*` allocations are freed with plain `free()` (heap_caps uses the same heap). Fine.

- [ ] **Step 3: Write the doctest — `components/vault/test/test_vault.cpp`** (targets the CURRENT signatures)

```cpp
#include "doctest/doctest.h"
#include "vault.h"
#include "vault_store.h"
#include <cstring>
#include <cstdlib>

using namespace vault;

// Each case builds its own Store + Vault and wipes the namespace first.
static void fresh(Store& store) {
    for (const char* k : {"salt","wdek","entries","iter","tsalt","tverif","vfmt","cats"})
        store.erase_key(k);
    store.commit();
}

TEST_CASE("setup then unlock with correct/incorrect password") {
    Store store; fresh(store);
    Vault v(store);
    CHECK_FALSE(v.is_initialized());
    v.setup("correct horse", 13);
    CHECK(v.is_initialized());
    CHECK(v.is_unlocked());

    v.lock();
    CHECK_FALSE(v.is_unlocked());
    CHECK_FALSE(v.unlock("wrong", 5));
    CHECK_FALSE(v.is_unlocked());
    CHECK(v.unlock("correct horse", 13));
    CHECK(v.is_unlocked());
}

TEST_CASE("add, list, reveal, update, delete round-trip across re-unlock") {
    Store store; fresh(store);
    Vault v(store);
    v.setup("pw", 2);
    uint8_t id = v.add("GitHub", "dan", "tok123", "https://gh", "note", 0);

    v.lock();
    CHECK(v.unlock("pw", 2));

    vault_entry_t list[VAULT_MAX_ENTRIES];
    size_t n = v.list(list, VAULT_MAX_ENTRIES);
    CHECK(n == 1);
    CHECK(strcmp(list[0].title, "GitHub") == 0);
    CHECK(strcmp(list[0].secret, "") == 0);   // not revealed in list

    char secret[VAULT_FIELD_MAX], url[VAULT_FIELD_MAX], comment[VAULT_FIELD_MAX];
    CHECK(v.reveal(id, secret, url, comment));
    CHECK(strcmp(secret, "tok123") == 0);

    CHECK(v.update(id, "GitHub", "dan", "tok999", "https://gh", "note", 0));
    CHECK(v.reveal(id, secret, url, comment));
    CHECK(strcmp(secret, "tok999") == 0);

    CHECK(v.remove(id));
    n = v.list(list, VAULT_MAX_ENTRIES);
    CHECK(n == 0);
}

TEST_CASE("CRUD blocked while locked") {
    Store store; fresh(store);
    Vault v(store);
    v.setup("pw", 2);
    v.lock();
    CHECK_THROWS_AS(v.add("x", "y", "z", "", "", 0), vault::Error);
}

TEST_CASE("change password keeps entries, invalidates old password") {
    Store store; fresh(store);
    Vault v(store);
    v.setup("old", 3);
    uint8_t id = v.add("S", "u", "sec", "", "", 0);

    CHECK_FALSE(v.change_password("bad", 3, "new", 3));
    CHECK(v.change_password("old", 3, "new", 3));

    v.lock();
    CHECK_FALSE(v.unlock("old", 3));
    CHECK(v.unlock("new", 3));
    char secret[VAULT_FIELD_MAX], url[VAULT_FIELD_MAX], comment[VAULT_FIELD_MAX];
    CHECK(v.reveal(id, secret, url, comment));
    CHECK(strcmp(secret, "sec") == 0);
}

TEST_CASE("transfer password verifies correctly") {
    Store store; fresh(store);
    Vault v(store);
    v.setup("master", 6);
    v.set_transfer_password("xfer", 4);
    CHECK(v.verify_transfer("xfer", 4));
    CHECK_FALSE(v.verify_transfer("nope", 4));
}

TEST_CASE("export/import round-trips; wrong transfer password rejected") {
    Store store; fresh(store);
    Vault v(store);
    v.setup("master", 6);
    v.set_transfer_password("xfer", 4);
    uint8_t id = v.add("GitHub", "dan", "tok", "", "", 0);

    uint8_t* bundle = nullptr; size_t blen = 0;
    CHECK(v.export_bundle("xfer", 4, &bundle, &blen));
    REQUIRE(bundle != nullptr);
    uint8_t* dummy = nullptr; size_t dlen = 0;
    CHECK_FALSE(v.export_bundle("bad", 3, &dummy, &dlen));   // wrong pw

    CHECK(v.remove(id));
    vault_entry_t list[VAULT_MAX_ENTRIES];
    CHECK(v.list(list, VAULT_MAX_ENTRIES) == 0);

    CHECK_FALSE(v.import_bundle("wrong", 5, bundle, blen));
    CHECK(v.import_bundle("xfer", 4, bundle, blen));
    CHECK(v.list(list, VAULT_MAX_ENTRIES) == 1);
    CHECK(strcmp(list[0].title, "GitHub") == 0);
    char sec[VAULT_FIELD_MAX], url[VAULT_FIELD_MAX], comment[VAULT_FIELD_MAX];
    CHECK(v.reveal(list[0].id, sec, url, comment));
    CHECK(strcmp(sec, "tok") == 0);
    free(bundle);
}

TEST_CASE("import merges by title+username (no duplicate)") {
    Store store; fresh(store);
    Vault v(store);
    v.setup("master", 6);
    v.set_transfer_password("x", 1);
    uint8_t id = v.add("Site", "u", "old", "", "", 0);

    uint8_t* bundle = nullptr; size_t blen = 0;
    CHECK(v.export_bundle("x", 1, &bundle, &blen));
    CHECK(v.update(id, "Site", "u", "new", "", "", 0));
    CHECK(v.import_bundle("x", 1, bundle, blen));   // old replaces new

    vault_entry_t list[VAULT_MAX_ENTRIES];
    CHECK(v.list(list, VAULT_MAX_ENTRIES) == 1);    // merged, not duplicated
    char sec[VAULT_FIELD_MAX], url[VAULT_FIELD_MAX], comment[VAULT_FIELD_MAX];
    v.reveal(list[0].id, sec, url, comment);
    CHECK(strcmp(sec, "old") == 0);
    free(bundle);
}
```

- [ ] **Step 4: Update `components/vault/CMakeLists.txt`**

```cmake
idf_component_register(SRCS "vault.cpp"
                       INCLUDE_DIRS "include"
                       REQUIRES vault_crypto vault_store vault_error)
```

- [ ] **Step 5: Update `components/vault/test/CMakeLists.txt`**

```cmake
idf_component_register(SRCS "test_vault.cpp"
                       INCLUDE_DIRS "."
                       REQUIRES doctest vault vault_store)
```

- [ ] **Step 6: Rename the test file**

```
git mv components/vault/test/test_vault.c components/vault/test/test_vault.cpp
```

- [ ] **Step 7: Commit**

```bash
git add components/vault
git commit -m "Convert vault to vault::Vault class (C++); port tests to doctest against current API"
```

---

## Task 11: Convert `status_led` to the `vault::StatusLed` class

**Files:**
- Modify: `components/status_led/include/status_led.h`
- Rename+modify: `components/status_led/status_led.c` → `.cpp`
- Modify: `components/status_led/CMakeLists.txt`

> Takes `Vault&` + `Session&`. Owns the `led_strip` handle and the esp_timer. The timer callback is a static trampoline recovering `this` from the timer `.arg`, wrapped in try/catch. State (`s_last`, `s_glevel`, `s_blink`, `s_activity_until`) becomes members.

- [ ] **Step 1: Rewrite the header**

```cpp
#pragma once
#include <cstdint>
#include "led_strip.h"
#include "vault.h"
#include "vault_session.h"

namespace vault {

class StatusLed {
public:
    StatusLed(Vault& vault, Session& session) : vault_(vault), session_(session) {}
    void init();       // start the mirror timer; non-fatal if the LED is absent
    void activity();   // pulse blue on API activity (sets a flag the timer reads)

private:
    static void tick_trampoline(void* arg);
    void tick();
    void set_rgb(uint32_t r, uint32_t g, uint32_t b);
    int  state_code();
    uint32_t green_level();

    Vault&   vault_;
    Session& session_;
    led_strip_handle_t strip_ = nullptr;
    int      last_   = -1;
    uint32_t glevel_ = 0;
    bool     blink_  = false;
    volatile uint32_t activity_until_ = 0;
};

}  // namespace vault
```

- [ ] **Step 2: Convert the source**

```
git mv components/status_led/status_led.c components/status_led/status_led.cpp
```
Rewrite `status_led.cpp`:
- Keep the `#define`s (`LED_GPIO`, `REFRESH_US`, `LVL`, `G_MIN`, `ACT_MS`) and `TAG`.
- Add `#include "vault_error.h"`. Wrap in `namespace vault {}`.
- `status_led_activity` → `void StatusLed::activity() { activity_until_ = (uint32_t)(esp_timer_get_time() / 1000) + ACT_MS; }`.
- `set_rgb` → `void StatusLed::set_rgb(...)` using `strip_`.
- `state_code` → `int StatusLed::state_code() { if (!vault_.is_initialized()) return 0; return vault_.is_unlocked() ? 2 : 1; }`.
- `draw(code)` was a file-local helper using `set_rgb`; fold it into `tick()` or keep as a private `void StatusLed::draw(int code)` (add to header) — simplest: keep a file-local lambda or inline the switch in `tick()`. Recommended: add `void draw(int code);` to the header private section and convert.
- `green_level` → `uint32_t StatusLed::green_level()`: `uint32_t rem = session_.idle_remaining_ms(now);` (was `vsess_idle_remaining_ms`).
- `tick(void* arg)` → split into the static trampoline + member:
  ```cpp
  void StatusLed::tick_trampoline(void* arg) {
      auto* self = static_cast<StatusLed*>(arg);
      try { self->tick(); } catch (...) { /* never let exceptions reach the timer task */ }
  }
  void StatusLed::tick() {
      if (vault_.is_busy()) { blink_ = !blink_; set_rgb(blink_ ? LVL : 0, 0, 0); last_ = -1; return; }
      uint32_t now = (uint32_t)(esp_timer_get_time() / 1000);
      if ((int32_t)(activity_until_ - now) > 0) { set_rgb(0, 0, LVL); last_ = -1; return; }
      int code = state_code();
      if (code == 2) { uint32_t g = green_level();
          if (code != last_ || g != glevel_) { set_rgb(0, g, 0); last_ = code; glevel_ = g; } return; }
      if (code != last_) { draw(code); last_ = code; }
  }
  ```
- `status_led_init` → `void StatusLed::init()`: build `led_strip_config_t scfg`/`led_strip_rmt_config_t rcfg` with the **zero-init + field assignment** convention (the original uses nested `.flags.invert_out` / `.flags.with_dma` designated initializers — must convert). On `led_strip_new_rmt_device` failure, log a warning and `return;` (non-fatal, as today). Then `tick();` for an immediate draw. Build the timer args with assignment and set `.arg = this`:
  ```cpp
  esp_timer_create_args_t targs = {};
  targs.callback = tick_trampoline;
  targs.arg = this;
  targs.name = "status_led";
  esp_timer_handle_t t;
  if (esp_timer_create(&targs, &t) != ESP_OK || esp_timer_start_periodic(t, REFRESH_US) != ESP_OK)
      ESP_LOGW(TAG, "status LED timer failed; LED shows only the boot-time state");
  ```
  `init()` returns void (the original returned ESP_OK unconditionally).

- [ ] **Step 3: Update `components/status_led/CMakeLists.txt`**

```cmake
idf_component_register(SRCS "status_led.cpp"
                       INCLUDE_DIRS "include"
                       REQUIRES vault vault_session esp_timer led_strip vault_error)
```

- [ ] **Step 4: Commit**

```bash
git add components/status_led
git commit -m "Convert status_led to vault::StatusLed class (C++)"
```

---

## Task 12: Convert `vault_api` to the `vault::ApiServer` class

**Files:**
- Modify: `components/vault_api/include/vault_api.h`
- Rename+modify: `components/vault_api/vault_api.c` → `.cpp`
- Modify: `components/vault_api/CMakeLists.txt`

> Takes `Vault&`, `Session&`, `StatusLed&`. Each httpd handler becomes a `static` trampoline that recovers `this` from `req->user_ctx` and wraps a private `*_impl` member in try/catch. The idle timer recovers `this` via `.arg`. The `uri_match_fn` C callback has no context slot, so a single file-local `static ApiServer* s_instance` (there is only ever one server) is used solely to route the activity pulse. The embedded `index.html`, cJSON usage, and all HTTP status codes are preserved.

- [ ] **Step 1: Rewrite the header**

```cpp
#pragma once
#include <cstddef>
#include "esp_https_server.h"
#include "vault.h"
#include "vault_session.h"
#include "status_led.h"

namespace vault {

class ApiServer {
public:
    ApiServer(Vault& vault, Session& session, StatusLed& led)
        : vault_(vault), session_(session), led_(led) {}
    // Starts the HTTPS server (binds all interfaces). Throws vault::Error on failure.
    void start(const char* cert_pem, size_t cert_len,
               const char* key_pem, size_t key_len);

private:
    Vault&     vault_;
    Session&   session_;
    StatusLed& led_;
    httpd_handle_t srv_ = nullptr;
};

}  // namespace vault
```

- [ ] **Step 2: Convert the source**

```
git mv components/vault_api/vault_api.c components/vault_api/vault_api.cpp
```
Rewrite `vault_api.cpp` with this structure. Add `#include "vault_api.h"` and `#include "vault_error.h"`; keep the cJSON/httpd/esp_timer includes. Replace the global `s_srv` with members; add a file-local `static ApiServer* s_instance;`.

- File-local helpers that need **no** instance state stay as file-local `static` functions, unchanged except C++ casts: `now_ms`, `send_json`, `err_json`, `read_body_cap`, `read_body`, `json_str`, `json_int`, `uri_id`, `uri_cat_id`, `h_static`. (In `read_body_cap`, cast `malloc`: `char* buf = (char*)malloc(...)`.) Put them in an anonymous namespace.

- `authed(r)` needs the session → make it take the server: replace the free `authed(httpd_req_t*)` with a private member `bool ApiServer::authed(httpd_req_t* r) { char tok[VS_TOKEN_HEX]; size_t len = sizeof tok; if (httpd_req_get_cookie_val(r, "sid", tok, &len) != ESP_OK) return false; return session_.validate(tok, now_ms()); }` (add to header private section).

- Each request handler `h_xxx(httpd_req_t* r)` becomes a **private member** `esp_err_t ApiServer::h_xxx_impl(httpd_req_t* r)` (add declarations to the header private section). Inside, apply this substitution table:

  | C (old free call) | C++ (member) |
  |---|---|
  | `authed(r)` | `authed(r)` (now a member — same spelling) |
  | `vault_is_initialized()` | `vault_.is_initialized()` |
  | `vault_is_unlocked()` | `vault_.is_unlocked()` |
  | `vsess_create(now_ms(), tok)` | `session_.create(now_ms(), tok)` |
  | `vsess_destroy()` | `session_.destroy()` |
  | `vsess_login_allowed(now_ms())` | `session_.login_allowed(now_ms())` |
  | `vsess_note_login_result(ok, now_ms())` | `session_.note_login_result(ok, now_ms())` |
  | `vault_lock()` | `vault_.lock()` |
  | `vault_setup(pw, n)` (returns esp_err) | `try { vault_.setup(pw, n); } catch (const vault::Error&) { return err_json(r,400,"already initialized"); }` |
  | `vault_set_transfer_password(tpw, n)` | wrap: on throw → `vault_.factory_reset(); return err_json(r,500,"setup failed, try again");` |
  | `vault_unlock(pw, n) == ESP_OK` | `bool ok = vault_.unlock(pw, n);` (catch vault::Error → treat as failure / invalid state) |
  | `vault_change_password(...)` (esp_err) | `bool ok = vault_.change_password(...);` then `if (!ok) return err_json(r,403,"wrong current password");` |
  | `vault_list(list, cap, &n)` | `size_t n = vault_.list(list, cap);` (throws if locked → caught by trampoline as 500; original returned 403 "locked" — to preserve, wrap in local try/catch mapping to 403) |
  | `vault_reveal(id, s,u,c) == ESP_OK` | `if (!vault_.reveal(id, s, u, c)) return err_json(r,404,"not found");` |
  | `vault_add(...) == ESP_OK` (out &id) | `uint8_t id; try { id = vault_.add(...); } catch (const vault::Error&) { return err_json(r,400,"add failed"); }` |
  | `vault_update(...) == ESP_OK` | `if (!vault_.update(...)) return err_json(r,404,"not found");` |
  | `vault_delete(id) == ESP_OK` | `if (!vault_.remove(id)) return err_json(r,404,"not found");` |
  | `vault_category_list(cats, cap, &n)` | `size_t n = vault_.category_list(cats, cap);` (locked → wrap to 403 as above) |
  | `vault_category_add(name, &id)` with `ESP_ERR_INVALID_STATE`→409 | `uint8_t id; try { id = vault_.category_add(name); } catch (const vault::Error& e) { if (e.code()==ESP_ERR_INVALID_STATE) return err_json(r,409,"category exists"); return err_json(r,400,"add failed"); }` |
  | `vault_category_delete(id) == ESP_OK` | `if (!vault_.category_delete(id)) return err_json(r,404,"not found");` |
  | `vault_verify_transfer(pw, n)` | `vault_.verify_transfer(pw, n)` |
  | `vault_clear_entries() == ESP_OK` | `try { vault_.clear_entries(); } catch (...) { return err_json(r,500,"reset failed"); }` |
  | `vault_bulk_begin()` | `vault_.bulk_begin();` |
  | `vault_bulk_commit() == ESP_OK` | `try { vault_.bulk_commit(); } catch (...) { return err_json(r,500,"import save failed"); }` |

  > For `h_entries_list` / `h_cats_list` / `h_export` / `h_import` the original returned **403 "locked"** when `vault_list`/`vault_category_list` failed. Since `list()`/`category_list()` now throw `Error(ESP_ERR_INVALID_STATE)` when locked, wrap those specific calls in a local `try { ... } catch (const vault::Error&) { /* free locals */ return err_json(r,403,"locked"); }` to preserve the 403. (The session cookie check `authed(r)` normally prevents reaching these while locked, so this is the rare-race path — keep behavior identical.) Remember to `free(list)` before returning in `h_export`/`h_import` error paths, as the original does.

  > In `h_import` the merge loop calls `vault_.update(...)` / `vault_.add(...)`. `add` throws on "full"; the original ignored add failure past capacity (`if (re == ESP_OK && n < MAX) ...`). Wrap the add in `try { uint8_t nid = vault_.add(...); if (n < VAULT_MAX_ENTRIES) { ... } imported++; } catch (const vault::Error&) { /* capacity reached: stop counting, continue */ }`. `update` returns bool; `if (vault_.update(...)) imported++;`.

  > `h_export` does **not** call `vault_export` (binary bundle); it builds plaintext JSON directly via `vault_.list` + `vault_.reveal` + `vault_.category_list`. Keep that logic, substituting per the table. `reveal` now returns bool — `if (!vault_.reveal(list[i].id, secret, url, comment)) { secret[0]=url[0]=comment[0]='\0'; }`.

- `idle_lock_work` / `idle_timer_cb`: 
  ```cpp
  void ApiServer::idle_lock_work(void* arg) {   // add to header private: static
      auto* self = static_cast<ApiServer*>(arg);
      try { self->session_.check_idle(now_ms()); } catch (...) {}
  }
  void ApiServer::idle_timer_cb(void* arg) {     // static
      auto* self = static_cast<ApiServer*>(arg);
      if (self->srv_) httpd_queue_work(self->srv_, idle_lock_work, self);
  }
  ```
  (Add `static void idle_lock_work(void*); static void idle_timer_cb(void*);` to the header private section.)

- `uri_match_activity` C callback (signature fixed by httpd, no ctx):
  ```cpp
  static bool uri_match_activity(const char* tpl, const char* uri, size_t upto) {
      bool m = httpd_uri_match_wildcard(tpl, uri, upto);
      if (m && strncmp(tpl, "/api/", 5) == 0 && s_instance) s_instance->led_.activity();
      return m;
  }
  ```
  (`led_` is private; make `uri_match_activity` a friend, OR add a private `void pulse_activity() { led_.activity(); }` and call `s_instance->pulse_activity();` — but that's still private. Simplest: declare `friend bool ::vault::uri_match_activity(...)`? Cleaner: add a **public** `void activity() { led_.activity(); }` to ApiServer, or just make `led_` accessible via a small public method. Recommended: add to ApiServer a private method and `friend` the function. To avoid friend complexity, give the file-local function access by adding a private static-free helper: store `StatusLed* s_led = nullptr;` file-local alongside `s_instance` and set both in `start()`, then call `s_led->activity()`. Use whichever is least friction; the `s_led` file-local is simplest and documented as the no-context workaround.)

- Each trampoline: define a macro near the top of the file and use it once per handler:
  ```cpp
  #define API_HANDLER(NAME)                                                   \
      static esp_err_t NAME(httpd_req_t* r) {                                 \
          auto* self = static_cast<ApiServer*>(r->user_ctx);                  \
          try { return self->NAME##_impl(r); }                                \
          catch (const vault::Error& e) { return err_json(r, 500, e.what()); }\
          catch (const std::exception& e) { return err_json(r, 500, e.what()); } \
          catch (...) { return err_json(r, 500, "internal error"); }          \
      }
  API_HANDLER(h_index)   // NOTE: h_index has no _impl; see below
  ```
  > `h_index` is trivial (static file) and never throws — keep it as a plain `static esp_err_t h_index(httpd_req_t* r) { return h_static(r, index_html_start, index_html_end, "text/html"); }` without the macro/`_impl`. Apply `API_HANDLER` to the other handlers, each having a matching `esp_err_t ApiServer::h_xxx_impl(httpd_req_t*)`.

- `ApiServer::start(...)`:
  - Set `s_instance = this; s_led = &led_;` at the top.
  - Keep the `esp_log_level_set` calls and `HTTPD_SSL_CONFIG_DEFAULT()` macro init (macro is C++-safe). Assign `cfg.servercert` etc. as today. Keep `cfg.httpd.uri_match_fn = uri_match_activity; cfg.httpd.core_id = 1; cfg.httpd.max_uri_handlers = 20;`.
  - `esp_err_t e = httpd_ssl_start(&srv_, &cfg); if (e != ESP_OK) throw vault::Error(e, "https start");`.
  - Build the routes array at runtime so `user_ctx = this`. Use positional init per element with the trampoline function and `this`:
    ```cpp
    const httpd_uri_t routes[] = {
        {"/",                    HTTP_GET,    h_index,           this},
        {"/api/state",           HTTP_GET,    h_state,           this},
        {"/api/setup",           HTTP_POST,   h_setup,           this},
        {"/api/login",           HTTP_POST,   h_login,           this},
        {"/api/logout",          HTTP_POST,   h_logout,          this},
        {"/api/change-password", HTTP_POST,   h_change_pw,       this},
        {"/api/change-transfer", HTTP_POST,   h_change_transfer, this},
        {"/api/export",          HTTP_POST,   h_export,          this},
        {"/api/import",          HTTP_POST,   h_import,          this},
        {"/api/reset",           HTTP_POST,   h_reset,           this},
        {"/api/entries",         HTTP_GET,    h_entries_list,    this},
        {"/api/entries",         HTTP_POST,   h_entries_add,     this},
        {"/api/entries/*",       HTTP_GET,    h_entry_secret,    this},
        {"/api/entries/*",       HTTP_PUT,    h_entry_update,    this},
        {"/api/entries/*",       HTTP_DELETE, h_entry_delete,    this},
        {"/api/categories",      HTTP_GET,    h_cats_list,       this},
        {"/api/categories",      HTTP_POST,   h_cats_add,        this},
        {"/api/categories/*",    HTTP_DELETE, h_cat_delete,      this},
    };
    for (auto& route : routes) httpd_register_uri_handler(srv_, &route);
    ```
    > `httpd_uri_t` fields after `user_ctx` (`is_websocket`, etc.) are left zero by the partial aggregate init — same as the original `NULL`-terminated rows.
  - Keep the idle timer block, using assignment-style args with `.arg = this`:
    ```cpp
    esp_timer_create_args_t idle_args = {};
    idle_args.callback = idle_timer_cb;
    idle_args.arg = this;
    idle_args.name = "idle_lock";
    esp_timer_handle_t idle_t;
    if (esp_timer_create(&idle_args, &idle_t) == ESP_OK)
        esp_timer_start_periodic(idle_t, 5ULL * 1000 * 1000);
    else
        ESP_LOGW(TAG, "idle-lock timer failed; vault still locks lazily on next request");
    ```
  - Return void.

- [ ] **Step 3: Update `components/vault_api/CMakeLists.txt`**

```cmake
idf_component_register(SRCS "vault_api.cpp"
                       INCLUDE_DIRS "include"
                       REQUIRES esp_https_server cjson vault vault_session esp_timer mbedtls status_led vault_error
                       EMBED_FILES "www/index.html")
```

- [ ] **Step 4: Commit**

```bash
git add components/vault_api
git commit -m "Convert vault_api to vault::ApiServer class (C++) with try/catch handler trampolines"
```

---

## Task 13: Convert `main` and the test-app runner; wire everything; build both projects

**Files:**
- Rename+rewrite: `main/main.c` → `main/main.cpp`
- Modify: `main/CMakeLists.txt`
- Rename+rewrite: `test_app/main/test_app_main.c` → `.cpp`
- Modify: `test_app/main/CMakeLists.txt`
- Modify: `test_app/CMakeLists.txt`

> This task closes the loop: `app_main` constructs every component in dependency order with DI, and the test runner switches from Unity's menu to doctest's runner. After this, BOTH projects must build green.

- [ ] **Step 1: Convert `main/main.c` → `main/main.cpp`**

```
git mv main/main.c main/main.cpp
```
Rewrite `main/main.cpp`:
```cpp
#include "esp_log.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "vault_store.h"
#include "vault.h"
#include "vault_session.h"
#include "vault_cert.h"
#include "vault_crypto.h"
#include "net_wifi_ap.h"
#include "net_usb.h"
#include "vault_api.h"
#include "status_led.h"
#include <cstdlib>

static const char* TAG = "esp32key";

// Default AP password — change via Settings after first boot.
#define AP_PASSWORD "29028356267034"

extern "C" void app_main(void)
{
    try {
        vault::crypto::init();

        // Process-lifetime singletons, owned here and injected by reference.
        static vault::Store   store;
        static vault::Vault   vault(store);
        vault.init();                       // auto-reset if the on-disk format changed

        static vault::Session  session;
        static vault::StatusLed led(vault, session);
        led.init();                         // WS2812 indicator: blue=setup, red=locked, green=unlocked

        ESP_ERROR_CHECK(esp_netif_init());
        ESP_ERROR_CHECK(esp_event_loop_create_default());

        // Wipe the DEK from RAM when a session idles out, not just on explicit logout.
        session.set_expiry_cb([&vault] { vault.lock(); });

        static vault::WifiAp wifi; wifi.start(AP_PASSWORD);
        static vault::UsbNet usb;  usb.start();

        static vault::Cert cert(store);
        char* cert_pem = nullptr; char* key_pem = nullptr;
        size_t clen = 0, klen = 0;
        cert.get(&cert_pem, &clen, &key_pem, &klen);
        ESP_LOGI(TAG, "certificate ready (%u bytes)", (unsigned)clen);

        static vault::ApiServer api(vault, session, led);
        api.start(cert_pem, clen, key_pem, klen);
        ESP_LOGI(TAG, "esp32key ready: https://192.168.4.1 (WiFi) / https://10.10.0.1 (USB)");
    } catch (const std::exception& e) {
        ESP_LOGE(TAG, "fatal init failure: %s", e.what());
        abort();   // mirror ESP_ERROR_CHECK's abort-on-fatal behavior
    }
}
```
> `static` locals in `app_main` (called exactly once) live for the process lifetime and are constructed in order on entry. The lambda captures `vault` by reference; it outlives the session.

- [ ] **Step 2: Update `main/CMakeLists.txt`**

```cmake
idf_component_register(SRCS "main.cpp"
                       INCLUDE_DIRS ""
                       REQUIRES vault_store vault vault_session vault_cert vault_crypto
                                net_wifi_ap net_usb vault_api status_led esp_netif esp_event)
```

- [ ] **Step 3: Convert the test runner `test_app/main/test_app_main.c` → `.cpp`**

```
git mv test_app/main/test_app_main.c test_app/main/test_app_main.cpp
```
Rewrite `test_app/main/test_app_main.cpp`:
```cpp
#define DOCTEST_CONFIG_IMPLEMENT
#include "doctest/doctest.h"
#include "esp_log.h"

extern "C" void app_main(void)
{
    doctest::Context ctx;
    ctx.setOption("no-breaks", true);   // don't try to break into a debugger on failure
    int res = ctx.run();                // runs all registered TEST_CASEs
    ESP_LOGI("doctest", "test run complete, result=%d", res);
}
```
> `DOCTEST_CONFIG_IMPLEMENT` must appear in exactly one TU — this one. Component test TUs only `#include "doctest/doctest.h"` and register cases.

- [ ] **Step 4: Update `test_app/main/CMakeLists.txt`**

```cmake
idf_component_register(SRCS "test_app_main.cpp"
                       INCLUDE_DIRS ""
                       REQUIRES doctest unity vault_crypto vault_store vault vault_session vault_cert net_wifi_ap net_usb vault_api
                       WHOLE_ARCHIVE)
```
> `unity` is kept in REQUIRES only because the ESP-IDF `TEST_COMPONENTS` machinery references it; the test code no longer uses it. If the build complains about an unused/unfound unity dependency, it is safe to remove `unity` from this line.

- [ ] **Step 5: Update `test_app/CMakeLists.txt`** (TEST_COMPONENTS unchanged — same four)

```cmake
cmake_minimum_required(VERSION 3.16)
set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/../components")
set(TEST_COMPONENTS vault_crypto vault_store vault vault_session)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(esp32key_tests)
```

- [ ] **Step 6: Build the main app (background, poll)**

Run:
```
cmd /c 'set "MSYSTEM=" && call C:\esp\v6.0.1\esp-idf\export.bat && idf.py build'
```
Expected: **build succeeds**, ending with `Project build complete` and a `esp32key.bin` artifact. Fix any compile/link errors before proceeding.

- [ ] **Step 7: Build the test app (background, poll)**

Run from `test_app`:
```
cmd /c 'set "MSYSTEM=" && call C:\esp\v6.0.1\esp-idf\export.bat && cd test_app && idf.py build'
```
Expected: build succeeds. In the configure output, confirm `Test components: vault_crypto::test vault_store::test vault::test vault_session::test` (doctest cases linked via WHOLE_ARCHIVE).

- [ ] **Step 8: Commit**

```bash
git add main/main.cpp main/CMakeLists.txt test_app/main/test_app_main.cpp test_app/main/CMakeLists.txt test_app/CMakeLists.txt
git commit -m "Wire C++ components in app_main via DI; switch test runner to doctest; both projects build"
```

---

## Task 14: Final verification sweep

**Files:** none (verification only)

- [ ] **Step 1: Confirm no `.c` source files remain in components/main**

Run:
```
find components main test_app/main -name '*.c' -not -path '*/build/*' -not -path '*/managed_components/*'
```
Expected: **no output** (every source file is now `.cpp`). (Vendored `managed_components` and `doctest.h` are exempt.)

- [ ] **Step 2: Confirm both build artifacts exist**

Run:
```
ls -la build/esp32key.bin test_app/build/esp32key_tests.bin
```
Expected: both binaries present and recently modified.

- [ ] **Step 3: On-target test pass (manual, dev-run — document, do not block)**

The agent environment cannot run on-target tests. Record this handoff note for the dev:
> Flash and run the test app interactively to confirm all doctest cases pass on hardware:
> ```
> cmd /c 'set "MSYSTEM=" && call C:\esp\v6.0.1\esp-idf\export.bat && cd test_app && idf.py -p <PORT> flash monitor'
> ```
> doctest runs all cases automatically at boot and prints a summary line (`test cases: N | N passed | 0 failed`). Confirm 0 failed.

- [ ] **Step 4: Final commit (if any verification fixups were needed)**

```bash
git add -A
git commit -m "Finalize C++ conversion: all components, main, and tests build on both projects"
```

---

## Self-review notes (addressed)

- **Spec coverage:** every component in the spec table (crypto, store, session, cert, vault, status_led, wifi_ap, usb, api) has a task; build config (Task 1), doctest (Task 2), shared error type (Task 3), main wiring + test runner (Task 13), and final verification (Task 14) are covered.
- **Exceptions-at-boundaries:** `app_main` (Task 13), httpd handler trampolines (Task 12), esp_timer callbacks for status_led (Task 11) and idle-lock (Task 12) all wrap bodies in try/catch.
- **Naming consistency:** entry delete is `remove` everywhere (header Task 10, api `h_entry_delete_impl` Task 12). `vault::crypto::*` free functions used identically in session (Task 8), vault (Task 10), and crypto tests (Task 4). `Store::get_blob` uses a `size_t&` (not pointer) consistently in store (Task 5), cert (Task 9), and vault (Task 10) call sites.
- **Stale-test trap flagged:** Task 10 explicitly notes the old `test_vault.c` used outdated signatures and the doctest rewrite targets the current header.
- **C++ pitfalls flagged:** designated-initializer rule (global conventions; applied in Tasks 6, 7, 11, 12), `malloc` casts, `_Static_assert`→`static_assert`, enum-OR cast in net_usb, `goto`-into-scope note in crypto.
