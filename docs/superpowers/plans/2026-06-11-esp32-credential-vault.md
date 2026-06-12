# ESP32-S3 Credential Vault Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build ESP-IDF firmware that turns a bare ESP32-S3 dev board into a personal encrypted credential vault, reachable over HTTPS via both its own WiFi AP and a USB network gadget.

**Architecture:** A pure, unit-tested crypto/storage core (PBKDF2 KEK → wrapped random DEK → per-entry AES-256-GCM, persisted in NVS) sits beneath a session layer and a thin JSON REST API. Two network interfaces (WiFi softAP + TinyUSB NCM) both feed one `esp_https_server` instance that serves an embedded single-page web UI. The decrypted DEK lives only in RAM and is wiped on logout / idle / reboot. A second **transfer password** (set at first-run setup) gates and encrypts a portable, device-independent export bundle so credentials can be moved to another ESP32-S3 (Tasks 12–14).

**Tech Stack:** ESP-IDF v6.0.1, ESP32-S3 (PSRAM enabled), mbedTLS (PBKDF2, AES-GCM, X.509 self-signed cert), NVS, esp_https_server, esp_wifi (softAP), esp_tinyusb (NCM network class), Unity (on-target unit tests).

---

## Conventions

- All `idf.py` commands run from an **ESP-IDF v6.0.1 terminal** (PowerShell with `C:\esp\v6.0.1\esp-idf\export.ps1` sourced, or the VS Code ESP-IDF terminal). Replace `<PORT>` with the board's serial port (e.g. `COM5`).
- Target is fixed to `esp32s3`.
- Unit tests use ESP-IDF's component-test pattern and run on the board via a dedicated `test_app` project; "Expected" output below is the Unity summary line.
- Commit after every task. Commit messages follow `feat:` / `test:` / `chore:` prefixes.

## File Structure

```
esp32key/
  CMakeLists.txt                 # top-level project
  sdkconfig.defaults             # target, PSRAM, TinyUSB, mbedTLS, https server
  partitions.csv                 # factory app + nvs
  main/
    CMakeLists.txt
    main.c                       # app_main: init NVS, bring up net + server
  components/
    vault_crypto/                # PURE, host/unit-testable: KDF, GCM, wrap/unwrap
      include/vault_crypto.h
      vault_crypto.c
      CMakeLists.txt
      test/test_vault_crypto.c
      test/CMakeLists.txt
    vault_store/                 # NVS persistence of vault blobs
      include/vault_store.h
      vault_store.c
      CMakeLists.txt
      test/test_vault_store.c
      test/CMakeLists.txt
    vault/                       # credential model, setup/unlock/lock, CRUD
      include/vault.h
      vault.c
      CMakeLists.txt
      test/test_vault.c
      test/CMakeLists.txt
    vault_session/               # session tokens, idle timeout, login lockout
      include/vault_session.h
      vault_session.c
      CMakeLists.txt
      test/test_vault_session.c
      test/CMakeLists.txt
    vault_cert/                  # self-signed cert generate + persist
      include/vault_cert.h
      vault_cert.c
      CMakeLists.txt
    net_wifi_ap/                 # softAP bring-up
      include/net_wifi_ap.h
      net_wifi_ap.c
      CMakeLists.txt
    net_usb/                     # TinyUSB NCM net interface + DHCP
      include/net_usb.h
      net_usb.c
      CMakeLists.txt
    vault_api/                   # esp_https_server + REST handlers + static files
      include/vault_api.h
      vault_api.c
      CMakeLists.txt
      www/index.html             # embedded SPA
      www/app.js
      www/style.css
  test_app/                      # IDF project that runs the component Unity tests
    CMakeLists.txt
    main/CMakeLists.txt
    main/test_app_main.c
```

Responsibility split: `vault_crypto` knows only bytes and keys (no storage, no app concepts). `vault_store` knows only NVS blobs (no crypto). `vault` composes them into the credential model and owns lock state. `vault_session` is independent of `vault`. `vault_api` is the only module that knows HTTP. Networking modules (`net_wifi_ap`, `net_usb`, `vault_cert`) are leaf hardware/setup modules.

---

## Task 0: Project scaffolding

**Files:**
- Create: `CMakeLists.txt`
- Create: `sdkconfig.defaults`
- Create: `partitions.csv`
- Create: `main/CMakeLists.txt`
- Create: `main/main.c`

- [ ] **Step 1: Create top-level `CMakeLists.txt`**

```cmake
cmake_minimum_required(VERSION 3.16)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(esp32key)
```

- [ ] **Step 2: Create `partitions.csv`**

```csv
# Name,   Type, SubType, Offset,   Size,    Flags
nvs,      data, nvs,     0x9000,   0x6000,
phy_init, data, phy,     0xf000,   0x1000,
factory,  app,  factory, 0x10000,  0x300000,
```

- [ ] **Step 3: Create `sdkconfig.defaults`** (target, PSRAM, partition table, TinyUSB, https server)

```ini
CONFIG_IDF_TARGET="esp32s3"

# PSRAM (Octal on most S3 modules; switch to QUAD if your module is quad)
CONFIG_SPIRAM=y
CONFIG_SPIRAM_MODE_OCT=y
CONFIG_SPIRAM_SPEED_80M=y
CONFIG_SPIRAM_USE_MALLOC=y

# Custom partition table
CONFIG_PARTITION_TABLE_CUSTOM=y
CONFIG_PARTITION_TABLE_CUSTOM_FILENAME="partitions.csv"

# USB OTG + TinyUSB networking (NCM)
CONFIG_TINYUSB_NET_MODE_NCM=y

# HTTPS server enabled
CONFIG_ESP_TLS_SERVER=y
CONFIG_ESP_HTTPS_SERVER_ENABLE=y

# Give mbedTLS room for cert generation
CONFIG_MBEDTLS_DYNAMIC_BUFFER=y
```

- [ ] **Step 4: Create placeholder `main/CMakeLists.txt`**

```cmake
idf_component_register(SRCS "main.c"
                       INCLUDE_DIRS "")
```

- [ ] **Step 5: Create minimal `main/main.c`**

```c
#include "esp_log.h"

static const char *TAG = "esp32key";

void app_main(void)
{
    ESP_LOGI(TAG, "esp32key boot");
}
```

- [ ] **Step 6: Set target and build**

Run: `idf.py set-target esp32s3 && idf.py build`
Expected: build succeeds; log line `Project build complete.`

- [ ] **Step 7: Flash and confirm boot**

Run: `idf.py -p <PORT> flash monitor`
Expected: serial shows `esp32key boot`. Press `Ctrl+]` to exit.

- [ ] **Step 8: Commit**

```bash
git init
git add CMakeLists.txt sdkconfig.defaults partitions.csv main/
git commit -m "chore: scaffold ESP-IDF esp32s3 project with PSRAM and TinyUSB NCM"
```

---

## Task 1: Test harness + `vault_crypto` KDF (TDD)

**Files:**
- Create: `components/vault_crypto/include/vault_crypto.h`
- Create: `components/vault_crypto/vault_crypto.c`
- Create: `components/vault_crypto/CMakeLists.txt`
- Test: `components/vault_crypto/test/test_vault_crypto.c`
- Test: `components/vault_crypto/test/CMakeLists.txt`
- Create: `test_app/CMakeLists.txt`, `test_app/main/CMakeLists.txt`, `test_app/main/test_app_main.c`

- [ ] **Step 1: Create the public header with the KDF declaration**

`components/vault_crypto/include/vault_crypto.h`:

```c
#pragma once
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

#define VC_SALT_LEN   16
#define VC_KEY_LEN    32   /* AES-256 */
#define VC_NONCE_LEN  12   /* GCM */
#define VC_TAG_LEN    16   /* GCM */

/* Derive a 32-byte key from a password using PBKDF2-HMAC-SHA256. */
esp_err_t vc_derive_key(const char *password, size_t password_len,
                        const uint8_t salt[VC_SALT_LEN], uint32_t iterations,
                        uint8_t out_key[VC_KEY_LEN]);
```

- [ ] **Step 2: Write the failing test**

`components/vault_crypto/test/test_vault_crypto.c`:

```c
#include "unity.h"
#include "vault_crypto.h"
#include <string.h>

TEST_CASE("pbkdf2 is deterministic and salt-sensitive", "[vault_crypto]")
{
    uint8_t salt1[VC_SALT_LEN] = {0};
    uint8_t salt2[VC_SALT_LEN] = {0};
    salt2[0] = 1;

    uint8_t k1[VC_KEY_LEN], k1b[VC_KEY_LEN], k2[VC_KEY_LEN];
    TEST_ASSERT_EQUAL(ESP_OK, vc_derive_key("hunter2", 7, salt1, 1000, k1));
    TEST_ASSERT_EQUAL(ESP_OK, vc_derive_key("hunter2", 7, salt1, 1000, k1b));
    TEST_ASSERT_EQUAL(ESP_OK, vc_derive_key("hunter2", 7, salt2, 1000, k2));

    TEST_ASSERT_EQUAL_MEMORY(k1, k1b, VC_KEY_LEN);   /* deterministic */
    TEST_ASSERT_NOT_EQUAL(0, memcmp(k1, k2, VC_KEY_LEN)); /* salt changes key */
}
```

- [ ] **Step 3: Create the component `CMakeLists.txt`**

`components/vault_crypto/CMakeLists.txt`:

```cmake
idf_component_register(SRCS "vault_crypto.c"
                       INCLUDE_DIRS "include"
                       REQUIRES mbedtls esp_hw_support)
```

- [ ] **Step 4: Create the test `CMakeLists.txt`**

`components/vault_crypto/test/CMakeLists.txt`:

```cmake
idf_component_register(SRCS "test_vault_crypto.c"
                       INCLUDE_DIRS "."
                       REQUIRES unity vault_crypto)
```

- [ ] **Step 5: Create the `test_app` project that runs component tests**

`test_app/CMakeLists.txt`:

```cmake
cmake_minimum_required(VERSION 3.16)
set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/../components")
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(esp32key_tests)
```

`test_app/main/CMakeLists.txt`:

```cmake
idf_component_register(SRCS "test_app_main.c"
                       INCLUDE_DIRS ""
                       REQUIRES unity vault_crypto vault_store vault vault_session
                       WHOLE_ARCHIVE)
```

`test_app/main/test_app_main.c`:

```c
#include "unity.h"

void app_main(void)
{
    unity_run_menu();
}
```

> Note: `REQUIRES` in the test_app lists every tested component so their `test/` cases link in. Components not yet created (e.g. `vault_store`) are added in later tasks; until then, remove the not-yet-existing names from this `REQUIRES` line so the test app builds. Re-add each as its task lands.

- [ ] **Step 6: Implement `vc_derive_key`**

`components/vault_crypto/vault_crypto.c`:

```c
#include "vault_crypto.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/md.h"

esp_err_t vc_derive_key(const char *password, size_t password_len,
                        const uint8_t salt[VC_SALT_LEN], uint32_t iterations,
                        uint8_t out_key[VC_KEY_LEN])
{
    if (!password || !salt || !out_key) return ESP_ERR_INVALID_ARG;
    int rc = mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256,
                                           (const unsigned char *)password, password_len,
                                           salt, VC_SALT_LEN,
                                           iterations, VC_KEY_LEN, out_key);
    return rc == 0 ? ESP_OK : ESP_FAIL;
}
```

- [ ] **Step 7: Build the test app**

Run: `cd test_app && idf.py set-target esp32s3 && idf.py build`
Expected: build succeeds.

- [ ] **Step 8: Flash and run the KDF test on the board**

Run: `idf.py -p <PORT> flash monitor`
Then at the Unity menu type `[vault_crypto]` and Enter.
Expected: `1 Tests 0 Failures 0 Ignored`.

- [ ] **Step 9: Commit**

```bash
git add components/vault_crypto test_app
git commit -m "feat: vault_crypto PBKDF2 key derivation with on-target unit tests"
```

---

## Task 2: `vault_crypto` AES-256-GCM encrypt/decrypt (TDD)

**Files:**
- Modify: `components/vault_crypto/include/vault_crypto.h`
- Modify: `components/vault_crypto/vault_crypto.c`
- Test: `components/vault_crypto/test/test_vault_crypto.c`

- [ ] **Step 1: Add GCM declarations to the header**

Append to `vault_crypto.h` (before the final blank line):

```c
/* AES-256-GCM. Caller supplies a unique nonce per encryption.
 * ct must have room for pt_len bytes; tag is VC_TAG_LEN bytes. */
esp_err_t vc_gcm_encrypt(const uint8_t key[VC_KEY_LEN],
                         const uint8_t nonce[VC_NONCE_LEN],
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *pt, size_t pt_len,
                         uint8_t *ct, uint8_t tag[VC_TAG_LEN]);

/* Returns ESP_OK only if the tag verifies (authentic). pt must have room
 * for ct_len bytes. */
esp_err_t vc_gcm_decrypt(const uint8_t key[VC_KEY_LEN],
                         const uint8_t nonce[VC_NONCE_LEN],
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *ct, size_t ct_len,
                         const uint8_t tag[VC_TAG_LEN],
                         uint8_t *pt);

/* Fill buf with cryptographically secure random bytes. */
void vc_random(uint8_t *buf, size_t len);
```

- [ ] **Step 2: Write the failing tests**

Append to `test_vault_crypto.c`:

```c
TEST_CASE("gcm round-trips and detects tampering", "[vault_crypto]")
{
    uint8_t key[VC_KEY_LEN]; vc_random(key, sizeof key);
    uint8_t nonce[VC_NONCE_LEN]; vc_random(nonce, sizeof nonce);
    const char *msg = "s3cr3t-password";
    size_t n = strlen(msg);

    uint8_t ct[64], pt[64], tag[VC_TAG_LEN];
    TEST_ASSERT_EQUAL(ESP_OK, vc_gcm_encrypt(key, nonce, NULL, 0,
                      (const uint8_t *)msg, n, ct, tag));
    TEST_ASSERT_EQUAL(ESP_OK, vc_gcm_decrypt(key, nonce, NULL, 0,
                      ct, n, tag, pt));
    TEST_ASSERT_EQUAL_MEMORY(msg, pt, n);

    tag[0] ^= 0xFF;  /* corrupt tag */
    TEST_ASSERT_NOT_EQUAL(ESP_OK, vc_gcm_decrypt(key, nonce, NULL, 0,
                          ct, n, tag, pt));
}
```

- [ ] **Step 3: Run the test to confirm it fails**

Run: build the test app (`cd test_app && idf.py build`).
Expected: FAIL — link error, `vc_gcm_encrypt` undefined.

- [ ] **Step 4: Implement GCM + RNG**

Append to `vault_crypto.c`:

```c
#include "mbedtls/gcm.h"
#include "esp_random.h"

void vc_random(uint8_t *buf, size_t len) { esp_fill_random(buf, len); }

esp_err_t vc_gcm_encrypt(const uint8_t key[VC_KEY_LEN],
                         const uint8_t nonce[VC_NONCE_LEN],
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *pt, size_t pt_len,
                         uint8_t *ct, uint8_t tag[VC_TAG_LEN])
{
    mbedtls_gcm_context g; mbedtls_gcm_init(&g);
    esp_err_t err = ESP_FAIL;
    if (mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, key, VC_KEY_LEN * 8) == 0 &&
        mbedtls_gcm_crypt_and_tag(&g, MBEDTLS_GCM_ENCRYPT, pt_len,
                                  nonce, VC_NONCE_LEN, aad, aad_len,
                                  pt, ct, VC_TAG_LEN, tag) == 0) {
        err = ESP_OK;
    }
    mbedtls_gcm_free(&g);
    return err;
}

esp_err_t vc_gcm_decrypt(const uint8_t key[VC_KEY_LEN],
                         const uint8_t nonce[VC_NONCE_LEN],
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *ct, size_t ct_len,
                         const uint8_t tag[VC_TAG_LEN],
                         uint8_t *pt)
{
    mbedtls_gcm_context g; mbedtls_gcm_init(&g);
    esp_err_t err = ESP_FAIL;
    if (mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, key, VC_KEY_LEN * 8) == 0 &&
        mbedtls_gcm_auth_decrypt(&g, ct_len, nonce, VC_NONCE_LEN,
                                 aad, aad_len, tag, VC_TAG_LEN,
                                 ct, pt) == 0) {
        err = ESP_OK;
    }
    mbedtls_gcm_free(&g);
    return err;
}
```

- [ ] **Step 5: Build, flash, run**

Run: `cd test_app && idf.py -p <PORT> flash monitor`, then run `[vault_crypto]`.
Expected: `2 Tests 0 Failures 0 Ignored`.

- [ ] **Step 6: Commit**

```bash
git add components/vault_crypto
git commit -m "feat: vault_crypto AES-256-GCM encrypt/decrypt and CSPRNG"
```

---

## Task 3: `vault_crypto` DEK generation + wrap/unwrap (TDD)

**Files:**
- Modify: `components/vault_crypto/include/vault_crypto.h`
- Modify: `components/vault_crypto/vault_crypto.c`
- Test: `components/vault_crypto/test/test_vault_crypto.c`

- [ ] **Step 1: Add wrap/unwrap declarations**

Append to `vault_crypto.h`:

```c
/* Wrapped-DEK blob layout: [nonce(12)][ct(32)][tag(16)] = 60 bytes. */
#define VC_WRAPPED_DEK_LEN (VC_NONCE_LEN + VC_KEY_LEN + VC_TAG_LEN)

/* Generate a random DEK and wrap it under kek. out_wrapped is VC_WRAPPED_DEK_LEN. */
esp_err_t vc_dek_create(const uint8_t kek[VC_KEY_LEN],
                        uint8_t out_dek[VC_KEY_LEN],
                        uint8_t out_wrapped[VC_WRAPPED_DEK_LEN]);

/* Unwrap a DEK. Returns ESP_OK only if kek is correct (tag verifies). */
esp_err_t vc_dek_unwrap(const uint8_t kek[VC_KEY_LEN],
                        const uint8_t wrapped[VC_WRAPPED_DEK_LEN],
                        uint8_t out_dek[VC_KEY_LEN]);
```

- [ ] **Step 2: Write the failing tests**

Append to `test_vault_crypto.c`:

```c
TEST_CASE("dek wrap/unwrap round-trips; wrong kek fails", "[vault_crypto]")
{
    uint8_t kek[VC_KEY_LEN]; vc_random(kek, sizeof kek);
    uint8_t bad[VC_KEY_LEN]; vc_random(bad, sizeof bad);

    uint8_t dek[VC_KEY_LEN], wrapped[VC_WRAPPED_DEK_LEN], out[VC_KEY_LEN];
    TEST_ASSERT_EQUAL(ESP_OK, vc_dek_create(kek, dek, wrapped));
    TEST_ASSERT_EQUAL(ESP_OK, vc_dek_unwrap(kek, wrapped, out));
    TEST_ASSERT_EQUAL_MEMORY(dek, out, VC_KEY_LEN);

    TEST_ASSERT_NOT_EQUAL(ESP_OK, vc_dek_unwrap(bad, wrapped, out));
}
```

- [ ] **Step 3: Run to confirm failure**

Run: `cd test_app && idf.py build`
Expected: FAIL — `vc_dek_create` undefined.

- [ ] **Step 4: Implement wrap/unwrap on top of GCM**

Append to `vault_crypto.c`:

```c
#include <string.h>

esp_err_t vc_dek_create(const uint8_t kek[VC_KEY_LEN],
                        uint8_t out_dek[VC_KEY_LEN],
                        uint8_t out_wrapped[VC_WRAPPED_DEK_LEN])
{
    vc_random(out_dek, VC_KEY_LEN);
    uint8_t *nonce = out_wrapped;
    uint8_t *ct    = out_wrapped + VC_NONCE_LEN;
    uint8_t *tag   = out_wrapped + VC_NONCE_LEN + VC_KEY_LEN;
    vc_random(nonce, VC_NONCE_LEN);
    return vc_gcm_encrypt(kek, nonce, NULL, 0, out_dek, VC_KEY_LEN, ct, tag);
}

esp_err_t vc_dek_unwrap(const uint8_t kek[VC_KEY_LEN],
                        const uint8_t wrapped[VC_WRAPPED_DEK_LEN],
                        uint8_t out_dek[VC_KEY_LEN])
{
    const uint8_t *nonce = wrapped;
    const uint8_t *ct    = wrapped + VC_NONCE_LEN;
    const uint8_t *tag   = wrapped + VC_NONCE_LEN + VC_KEY_LEN;
    return vc_gcm_decrypt(kek, nonce, NULL, 0, ct, VC_KEY_LEN, tag, out_dek);
}
```

- [ ] **Step 5: Build, flash, run**

Run: `cd test_app && idf.py -p <PORT> flash monitor`, run `[vault_crypto]`.
Expected: `3 Tests 0 Failures 0 Ignored`.

- [ ] **Step 6: Commit**

```bash
git add components/vault_crypto
git commit -m "feat: vault_crypto DEK generation and KEK wrap/unwrap"
```

---

## Task 4: `vault_store` NVS persistence (TDD)

**Files:**
- Create: `components/vault_store/include/vault_store.h`
- Create: `components/vault_store/vault_store.c`
- Create: `components/vault_store/CMakeLists.txt`
- Test: `components/vault_store/test/test_vault_store.c`
- Test: `components/vault_store/test/CMakeLists.txt`
- Modify: `test_app/main/CMakeLists.txt` (add `vault_store` to REQUIRES)

- [ ] **Step 1: Create the header**

`components/vault_store/include/vault_store.h`:

```c
#pragma once
#include <stddef.h>
#include "esp_err.h"

/* Thin typed wrappers over an NVS namespace ("vault"). Blob keys are <=15 chars. */
esp_err_t vs_init(void);                                   /* nvs_flash_init */
esp_err_t vs_set_blob(const char *key, const void *data, size_t len);
/* On entry *len = buffer size; on success *len = bytes read. */
esp_err_t vs_get_blob(const char *key, void *out, size_t *len);
esp_err_t vs_erase_key(const char *key);
esp_err_t vs_commit(void);
```

- [ ] **Step 2: Write the failing test**

`components/vault_store/test/test_vault_store.c`:

```c
#include "unity.h"
#include "vault_store.h"
#include <string.h>

TEST_CASE("blob set/get round-trips through NVS", "[vault_store]")
{
    TEST_ASSERT_EQUAL(ESP_OK, vs_init());
    const char *payload = "wrapped-dek-bytes";
    TEST_ASSERT_EQUAL(ESP_OK, vs_set_blob("t_dek", payload, strlen(payload)));
    TEST_ASSERT_EQUAL(ESP_OK, vs_commit());

    char buf[64]; size_t len = sizeof buf;
    TEST_ASSERT_EQUAL(ESP_OK, vs_get_blob("t_dek", buf, &len));
    TEST_ASSERT_EQUAL(strlen(payload), len);
    TEST_ASSERT_EQUAL_MEMORY(payload, buf, len);

    TEST_ASSERT_EQUAL(ESP_OK, vs_erase_key("t_dek"));
    TEST_ASSERT_EQUAL(ESP_OK, vs_commit());
    len = sizeof buf;
    TEST_ASSERT_EQUAL(ESP_ERR_NVS_NOT_FOUND, vs_get_blob("t_dek", buf, &len));
}
```

- [ ] **Step 3: Create component `CMakeLists.txt`**

`components/vault_store/CMakeLists.txt`:

```cmake
idf_component_register(SRCS "vault_store.c"
                       INCLUDE_DIRS "include"
                       REQUIRES nvs_flash)
```

- [ ] **Step 4: Create test `CMakeLists.txt`**

`components/vault_store/test/CMakeLists.txt`:

```cmake
idf_component_register(SRCS "test_vault_store.c"
                       INCLUDE_DIRS "."
                       REQUIRES unity vault_store)
```

- [ ] **Step 5: Implement `vault_store.c`**

`components/vault_store/vault_store.c`:

```c
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
```

- [ ] **Step 6: Add `vault_store` to the test app REQUIRES**

In `test_app/main/CMakeLists.txt`, ensure `vault_store` is in the `REQUIRES` list (added in Task 1 Step 5).

- [ ] **Step 7: Build, flash, run**

Run: `cd test_app && idf.py -p <PORT> flash monitor`, run `[vault_store]`.
Expected: `1 Tests 0 Failures 0 Ignored`.

- [ ] **Step 8: Commit**

```bash
git add components/vault_store test_app
git commit -m "feat: vault_store NVS blob persistence"
```

---

## Task 5: `vault` model — setup / unlock / lock / CRUD (TDD)

**Files:**
- Create: `components/vault/include/vault.h`
- Create: `components/vault/vault.c`
- Create: `components/vault/CMakeLists.txt`
- Test: `components/vault/test/test_vault.c`
- Test: `components/vault/test/CMakeLists.txt`
- Modify: `test_app/main/CMakeLists.txt`

- [ ] **Step 1: Create the header**

`components/vault/include/vault.h`:

```c
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"

#define VAULT_MAX_ENTRIES 64
#define VAULT_FIELD_MAX   128

typedef struct {
    uint8_t  id;
    char     title[VAULT_FIELD_MAX];
    char     username[VAULT_FIELD_MAX];
    char     secret[VAULT_FIELD_MAX];   /* only populated after vault_reveal */
} vault_entry_t;

bool      vault_is_initialized(void);   /* has setup ever run? */
bool      vault_is_unlocked(void);

esp_err_t vault_setup(const char *master, size_t master_len);   /* first run */
esp_err_t vault_unlock(const char *master, size_t master_len);  /* ESP_ERR_INVALID_STATE if not init; ESP_FAIL if wrong pw */
void      vault_lock(void);                                     /* wipes DEK from RAM */
esp_err_t vault_change_password(const char *cur, size_t cur_len,
                                const char *next, size_t next_len);

/* CRUD — require unlocked vault, else ESP_ERR_INVALID_STATE. */
esp_err_t vault_list(vault_entry_t *out, size_t cap, size_t *count); /* secret[] left empty */
esp_err_t vault_reveal(uint8_t id, char secret_out[VAULT_FIELD_MAX]);
esp_err_t vault_add(const char *title, const char *username, const char *secret, uint8_t *out_id);
esp_err_t vault_update(uint8_t id, const char *title, const char *username, const char *secret);
esp_err_t vault_delete(uint8_t id);
```

- [ ] **Step 2: Write the failing tests**

`components/vault/test/test_vault.c`:

```c
#include "unity.h"
#include "vault.h"
#include "vault_store.h"
#include <string.h>

static void fresh(void)
{
    TEST_ASSERT_EQUAL(ESP_OK, vs_init());
    vs_erase_key("salt"); vs_erase_key("wdek"); vs_erase_key("entries");
    vs_erase_key("iter"); vs_commit();
    vault_lock();
}

TEST_CASE("setup then unlock with correct/incorrect password", "[vault]")
{
    fresh();
    TEST_ASSERT_FALSE(vault_is_initialized());
    TEST_ASSERT_EQUAL(ESP_OK, vault_setup("correct horse", 13));
    TEST_ASSERT_TRUE(vault_is_initialized());
    TEST_ASSERT_TRUE(vault_is_unlocked());

    vault_lock();
    TEST_ASSERT_FALSE(vault_is_unlocked());
    TEST_ASSERT_NOT_EQUAL(ESP_OK, vault_unlock("wrong", 5));
    TEST_ASSERT_FALSE(vault_is_unlocked());
    TEST_ASSERT_EQUAL(ESP_OK, vault_unlock("correct horse", 13));
    TEST_ASSERT_TRUE(vault_is_unlocked());
}

TEST_CASE("add, list, reveal, update, delete round-trip across re-unlock", "[vault]")
{
    fresh();
    TEST_ASSERT_EQUAL(ESP_OK, vault_setup("pw", 2));
    uint8_t id;
    TEST_ASSERT_EQUAL(ESP_OK, vault_add("GitHub", "dan", "tok123", &id));

    vault_lock();
    TEST_ASSERT_EQUAL(ESP_OK, vault_unlock("pw", 2));

    vault_entry_t list[VAULT_MAX_ENTRIES]; size_t n = 0;
    TEST_ASSERT_EQUAL(ESP_OK, vault_list(list, VAULT_MAX_ENTRIES, &n));
    TEST_ASSERT_EQUAL(1, n);
    TEST_ASSERT_EQUAL_STRING("GitHub", list[0].title);
    TEST_ASSERT_EQUAL_STRING("", list[0].secret);   /* not revealed in list */

    char secret[VAULT_FIELD_MAX];
    TEST_ASSERT_EQUAL(ESP_OK, vault_reveal(id, secret));
    TEST_ASSERT_EQUAL_STRING("tok123", secret);

    TEST_ASSERT_EQUAL(ESP_OK, vault_update(id, "GitHub", "dan", "tok999"));
    TEST_ASSERT_EQUAL(ESP_OK, vault_reveal(id, secret));
    TEST_ASSERT_EQUAL_STRING("tok999", secret);

    TEST_ASSERT_EQUAL(ESP_OK, vault_delete(id));
    TEST_ASSERT_EQUAL(ESP_OK, vault_list(list, VAULT_MAX_ENTRIES, &n));
    TEST_ASSERT_EQUAL(0, n);
}

TEST_CASE("CRUD blocked while locked", "[vault]")
{
    fresh();
    TEST_ASSERT_EQUAL(ESP_OK, vault_setup("pw", 2));
    vault_lock();
    uint8_t id;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_STATE, vault_add("x","y","z",&id));
}

TEST_CASE("change password keeps entries, invalidates old password", "[vault]")
{
    fresh();
    TEST_ASSERT_EQUAL(ESP_OK, vault_setup("old", 3));
    uint8_t id; TEST_ASSERT_EQUAL(ESP_OK, vault_add("S","u","sec",&id));

    TEST_ASSERT_NOT_EQUAL(ESP_OK, vault_change_password("bad", 3, "new", 3));
    TEST_ASSERT_EQUAL(ESP_OK, vault_change_password("old", 3, "new", 3));

    vault_lock();
    TEST_ASSERT_NOT_EQUAL(ESP_OK, vault_unlock("old", 3));
    TEST_ASSERT_EQUAL(ESP_OK, vault_unlock("new", 3));
    char secret[VAULT_FIELD_MAX];
    TEST_ASSERT_EQUAL(ESP_OK, vault_reveal(id, secret));
    TEST_ASSERT_EQUAL_STRING("sec", secret);
}
```

- [ ] **Step 3: Create component + test CMakeLists**

`components/vault/CMakeLists.txt`:

```cmake
idf_component_register(SRCS "vault.c"
                       INCLUDE_DIRS "include"
                       REQUIRES vault_crypto vault_store)
```

`components/vault/test/CMakeLists.txt`:

```cmake
idf_component_register(SRCS "test_vault.c"
                       INCLUDE_DIRS "."
                       REQUIRES unity vault vault_store)
```

- [ ] **Step 4: Run to confirm failure**

Run: add `vault` to `test_app/main/CMakeLists.txt` REQUIRES, then `cd test_app && idf.py build`.
Expected: FAIL — `vault_setup` undefined.

- [ ] **Step 5: Implement `vault.c`**

The vault keeps entries as a single encrypted blob in NVS. Layout in NVS:
`salt`(16), `iter`(4, uint32), `wdek`(60, wrapped DEK), `entries`(encrypted blob = `nonce(12) | tag(16) | ciphertext`). The plaintext of `entries` is a packed array of `count` records, each `[id(1)][title(128)][user(128)][secret(128)]`.

`components/vault/vault.c`:

```c
#include "vault.h"
#include "vault_crypto.h"
#include "vault_store.h"
#include <string.h>

#define ITERATIONS    100000u
#define REC_SIZE      (1 + 3 * VAULT_FIELD_MAX)
#define PLAIN_MAX     (VAULT_MAX_ENTRIES * REC_SIZE)
#define ENTRIES_HDR   (VC_NONCE_LEN + VC_TAG_LEN)

static bool s_unlocked;
static uint8_t s_dek[VC_KEY_LEN];

/* In-RAM working copy, valid only while unlocked. */
static vault_entry_t s_entries[VAULT_MAX_ENTRIES];
static size_t s_count;
static uint8_t s_next_id = 1;

bool vault_is_unlocked(void) { return s_unlocked; }

bool vault_is_initialized(void)
{
    uint8_t wdek[VC_WRAPPED_DEK_LEN]; size_t len = sizeof wdek;
    return vs_get_blob("wdek", wdek, &len) == ESP_OK;
}

static esp_err_t load_kek(const char *master, size_t mlen, uint8_t kek[VC_KEY_LEN])
{
    uint8_t salt[VC_SALT_LEN]; size_t slen = sizeof salt;
    if (vs_get_blob("salt", salt, &slen) != ESP_OK) return ESP_ERR_INVALID_STATE;
    return vc_derive_key(master, mlen, salt, ITERATIONS, kek);
}

/* Encrypt s_entries -> NVS "entries". */
static esp_err_t persist_entries(void)
{
    static uint8_t plain[PLAIN_MAX];
    size_t off = 0;
    for (size_t i = 0; i < s_count; i++) {
        plain[off++] = s_entries[i].id;
        memcpy(plain + off, s_entries[i].title,    VAULT_FIELD_MAX); off += VAULT_FIELD_MAX;
        memcpy(plain + off, s_entries[i].username,  VAULT_FIELD_MAX); off += VAULT_FIELD_MAX;
        memcpy(plain + off, s_entries[i].secret,    VAULT_FIELD_MAX); off += VAULT_FIELD_MAX;
    }
    static uint8_t blob[ENTRIES_HDR + PLAIN_MAX];
    uint8_t *nonce = blob, *tag = blob + VC_NONCE_LEN, *ct = blob + ENTRIES_HDR;
    vc_random(nonce, VC_NONCE_LEN);
    esp_err_t err = vc_gcm_encrypt(s_dek, nonce, NULL, 0, plain, off, ct, tag);
    if (err != ESP_OK) return err;
    err = vs_set_blob("entries", blob, ENTRIES_HDR + off);
    if (err == ESP_OK) err = vs_commit();
    return err;
}

/* Decrypt NVS "entries" -> s_entries. Missing blob = empty vault. */
static esp_err_t load_entries(void)
{
    static uint8_t blob[ENTRIES_HDR + PLAIN_MAX];
    size_t blen = sizeof blob;
    esp_err_t err = vs_get_blob("entries", blob, &blen);
    s_count = 0; s_next_id = 1;
    if (err == ESP_ERR_NVS_NOT_FOUND) return ESP_OK;
    if (err != ESP_OK) return err;

    static uint8_t plain[PLAIN_MAX];
    uint8_t *nonce = blob, *tag = blob + VC_NONCE_LEN, *ct = blob + ENTRIES_HDR;
    size_t ctlen = blen - ENTRIES_HDR;
    err = vc_gcm_decrypt(s_dek, nonce, NULL, 0, ct, ctlen, tag, plain);
    if (err != ESP_OK) return err;

    size_t off = 0;
    while (off + REC_SIZE <= ctlen && s_count < VAULT_MAX_ENTRIES) {
        vault_entry_t *e = &s_entries[s_count++];
        e->id = plain[off++];
        memcpy(e->title,    plain + off, VAULT_FIELD_MAX); off += VAULT_FIELD_MAX;
        memcpy(e->username, plain + off, VAULT_FIELD_MAX); off += VAULT_FIELD_MAX;
        memcpy(e->secret,   plain + off, VAULT_FIELD_MAX); off += VAULT_FIELD_MAX;
        if (e->id >= s_next_id) s_next_id = e->id + 1;
    }
    return ESP_OK;
}

esp_err_t vault_setup(const char *master, size_t mlen)
{
    if (vault_is_initialized()) return ESP_ERR_INVALID_STATE;
    uint8_t salt[VC_SALT_LEN]; vc_random(salt, sizeof salt);
    uint32_t iter = ITERATIONS;
    uint8_t kek[VC_KEY_LEN];
    if (vc_derive_key(master, mlen, salt, iter, kek) != ESP_OK) return ESP_FAIL;
    uint8_t wdek[VC_WRAPPED_DEK_LEN];
    if (vc_dek_create(kek, s_dek, wdek) != ESP_OK) return ESP_FAIL;

    esp_err_t err;
    if ((err = vs_set_blob("salt", salt, sizeof salt)) != ESP_OK) return err;
    if ((err = vs_set_blob("iter", &iter, sizeof iter)) != ESP_OK) return err;
    if ((err = vs_set_blob("wdek", wdek, sizeof wdek)) != ESP_OK) return err;
    if ((err = vs_commit()) != ESP_OK) return err;

    s_unlocked = true; s_count = 0; s_next_id = 1;
    return persist_entries();
}

esp_err_t vault_unlock(const char *master, size_t mlen)
{
    if (!vault_is_initialized()) return ESP_ERR_INVALID_STATE;
    uint8_t kek[VC_KEY_LEN];
    if (load_kek(master, mlen, kek) != ESP_OK) return ESP_FAIL;
    uint8_t wdek[VC_WRAPPED_DEK_LEN]; size_t wlen = sizeof wdek;
    if (vs_get_blob("wdek", wdek, &wlen) != ESP_OK) return ESP_FAIL;
    if (vc_dek_unwrap(kek, wdek, s_dek) != ESP_OK) return ESP_FAIL;  /* wrong pw */
    s_unlocked = true;
    esp_err_t err = load_entries();
    if (err != ESP_OK) { vault_lock(); }
    return err;
}

void vault_lock(void)
{
    s_unlocked = false;
    memset(s_dek, 0, sizeof s_dek);
    memset(s_entries, 0, sizeof s_entries);
    s_count = 0;
}

esp_err_t vault_change_password(const char *cur, size_t clen,
                                const char *next, size_t nlen)
{
    uint8_t kek[VC_KEY_LEN], dek[VC_KEY_LEN];
    if (load_kek(cur, clen, kek) != ESP_OK) return ESP_FAIL;
    uint8_t wdek[VC_WRAPPED_DEK_LEN]; size_t wlen = sizeof wdek;
    if (vs_get_blob("wdek", wdek, &wlen) != ESP_OK) return ESP_FAIL;
    if (vc_dek_unwrap(kek, wdek, dek) != ESP_OK) return ESP_FAIL;  /* wrong current pw */

    uint8_t salt[VC_SALT_LEN]; vc_random(salt, sizeof salt);
    uint8_t nkek[VC_KEY_LEN], nwdek[VC_WRAPPED_DEK_LEN];
    if (vc_derive_key(next, nlen, salt, ITERATIONS, nkek) != ESP_OK) return ESP_FAIL;
    /* Re-wrap the SAME dek under the new kek. */
    uint8_t *nonce = nwdek, *ct = nwdek + VC_NONCE_LEN, *tag = nwdek + VC_NONCE_LEN + VC_KEY_LEN;
    vc_random(nonce, VC_NONCE_LEN);
    if (vc_gcm_encrypt(nkek, nonce, NULL, 0, dek, VC_KEY_LEN, ct, tag) != ESP_OK) return ESP_FAIL;

    esp_err_t err;
    if ((err = vs_set_blob("salt", salt, sizeof salt)) != ESP_OK) return err;
    if ((err = vs_set_blob("wdek", nwdek, sizeof nwdek)) != ESP_OK) return err;
    return vs_commit();
}

static vault_entry_t *find(uint8_t id)
{
    for (size_t i = 0; i < s_count; i++) if (s_entries[i].id == id) return &s_entries[i];
    return NULL;
}

static void set_field(char *dst, const char *src)
{
    memset(dst, 0, VAULT_FIELD_MAX);
    if (src) strncpy(dst, src, VAULT_FIELD_MAX - 1);
}

esp_err_t vault_list(vault_entry_t *out, size_t cap, size_t *count)
{
    if (!s_unlocked) return ESP_ERR_INVALID_STATE;
    size_t n = s_count < cap ? s_count : cap;
    for (size_t i = 0; i < n; i++) {
        out[i] = s_entries[i];
        memset(out[i].secret, 0, VAULT_FIELD_MAX);  /* never leak secret in list */
    }
    *count = n;
    return ESP_OK;
}

esp_err_t vault_reveal(uint8_t id, char secret_out[VAULT_FIELD_MAX])
{
    if (!s_unlocked) return ESP_ERR_INVALID_STATE;
    vault_entry_t *e = find(id);
    if (!e) return ESP_ERR_NOT_FOUND;
    memcpy(secret_out, e->secret, VAULT_FIELD_MAX);
    return ESP_OK;
}

esp_err_t vault_add(const char *title, const char *username, const char *secret, uint8_t *out_id)
{
    if (!s_unlocked) return ESP_ERR_INVALID_STATE;
    if (s_count >= VAULT_MAX_ENTRIES) return ESP_ERR_NO_MEM;
    vault_entry_t *e = &s_entries[s_count++];
    e->id = s_next_id++;
    set_field(e->title, title);
    set_field(e->username, username);
    set_field(e->secret, secret);
    if (out_id) *out_id = e->id;
    return persist_entries();
}

esp_err_t vault_update(uint8_t id, const char *title, const char *username, const char *secret)
{
    if (!s_unlocked) return ESP_ERR_INVALID_STATE;
    vault_entry_t *e = find(id);
    if (!e) return ESP_ERR_NOT_FOUND;
    set_field(e->title, title);
    set_field(e->username, username);
    set_field(e->secret, secret);
    return persist_entries();
}

esp_err_t vault_delete(uint8_t id)
{
    if (!s_unlocked) return ESP_ERR_INVALID_STATE;
    for (size_t i = 0; i < s_count; i++) {
        if (s_entries[i].id == id) {
            s_entries[i] = s_entries[--s_count];
            memset(&s_entries[s_count], 0, sizeof s_entries[s_count]);
            return persist_entries();
        }
    }
    return ESP_ERR_NOT_FOUND;
}
```

- [ ] **Step 6: Build, flash, run**

Run: `cd test_app && idf.py -p <PORT> flash monitor`, run `[vault]`.
Expected: `4 Tests 0 Failures 0 Ignored`.

- [ ] **Step 7: Commit**

```bash
git add components/vault test_app
git commit -m "feat: vault credential model with setup/unlock/lock/CRUD and password change"
```

---

## Task 6: `vault_session` — tokens, idle timeout, login lockout (TDD)

**Files:**
- Create: `components/vault_session/include/vault_session.h`
- Create: `components/vault_session/vault_session.c`
- Create: `components/vault_session/CMakeLists.txt`
- Test: `components/vault_session/test/test_vault_session.c`
- Test: `components/vault_session/test/CMakeLists.txt`
- Modify: `test_app/main/CMakeLists.txt`

Design note: time is injected (`now_ms` parameter) so the logic is testable without real delays.

- [ ] **Step 1: Create the header**

`components/vault_session/include/vault_session.h`:

```c
#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#define VS_TOKEN_LEN   32          /* bytes; hex-encoded => 64 chars */
#define VS_TOKEN_HEX   (VS_TOKEN_LEN * 2 + 1)
#define VS_IDLE_MS     (5 * 60 * 1000)
#define VS_MAX_FAILS   5
#define VS_LOCKOUT_MS  (60 * 1000)

void  vsess_reset(void);                       /* clear session + fail counter (test aid) */

/* Login gating. Returns false if currently locked out. */
bool  vsess_login_allowed(uint64_t now_ms);
void  vsess_note_login_result(bool success, uint64_t now_ms);

/* Create a session token after a successful unlock. out is VS_TOKEN_HEX chars. */
void  vsess_create(uint64_t now_ms, char out_token_hex[VS_TOKEN_HEX]);
/* Validate a presented token; refreshes idle timer on success. */
bool  vsess_validate(const char *token_hex, uint64_t now_ms);
void  vsess_destroy(void);                     /* logout */
```

- [ ] **Step 2: Write the failing tests**

`components/vault_session/test/test_vault_session.c`:

```c
#include "unity.h"
#include "vault_session.h"
#include <string.h>

TEST_CASE("token validates, expires on idle, dies on logout", "[vault_session]")
{
    vsess_reset();
    char tok[VS_TOKEN_HEX];
    vsess_create(1000, tok);
    TEST_ASSERT_TRUE(vsess_validate(tok, 1000 + VS_IDLE_MS - 1));
    /* validation refreshed the timer at the above call; advance from there */
    TEST_ASSERT_FALSE(vsess_validate(tok, 1000 + 2 * VS_IDLE_MS + 10));

    vsess_create(1, tok);
    TEST_ASSERT_TRUE(vsess_validate(tok, 2));
    vsess_destroy();
    TEST_ASSERT_FALSE(vsess_validate(tok, 3));
}

TEST_CASE("bad token never validates", "[vault_session]")
{
    vsess_reset();
    char tok[VS_TOKEN_HEX]; vsess_create(1, tok);
    TEST_ASSERT_FALSE(vsess_validate("deadbeef", 2));
    TEST_ASSERT_FALSE(vsess_validate("", 2));
}

TEST_CASE("login lockout after repeated failures, clears after window", "[vault_session]")
{
    vsess_reset();
    for (int i = 0; i < VS_MAX_FAILS; i++) {
        TEST_ASSERT_TRUE(vsess_login_allowed(0));
        vsess_note_login_result(false, 0);
    }
    TEST_ASSERT_FALSE(vsess_login_allowed(0));               /* locked out */
    TEST_ASSERT_FALSE(vsess_login_allowed(VS_LOCKOUT_MS - 1));
    TEST_ASSERT_TRUE(vsess_login_allowed(VS_LOCKOUT_MS + 1)); /* window passed */

    vsess_note_login_result(true, VS_LOCKOUT_MS + 1);        /* success resets */
    TEST_ASSERT_TRUE(vsess_login_allowed(VS_LOCKOUT_MS + 2));
}
```

- [ ] **Step 3: Create CMakeLists**

`components/vault_session/CMakeLists.txt`:

```cmake
idf_component_register(SRCS "vault_session.c"
                       INCLUDE_DIRS "include"
                       REQUIRES vault_crypto)
```

`components/vault_session/test/CMakeLists.txt`:

```cmake
idf_component_register(SRCS "test_vault_session.c"
                       INCLUDE_DIRS "."
                       REQUIRES unity vault_session)
```

- [ ] **Step 4: Run to confirm failure**

Run: add `vault_session` to `test_app/main/CMakeLists.txt` REQUIRES, then `cd test_app && idf.py build`.
Expected: FAIL — `vsess_create` undefined.

- [ ] **Step 5: Implement `vault_session.c`**

```c
#include "vault_session.h"
#include "vault_crypto.h"
#include <string.h>

static char     s_token[VS_TOKEN_HEX];
static bool     s_active;
static uint64_t s_last_seen_ms;

static int      s_fail_count;
static uint64_t s_lockout_until_ms;

static void to_hex(const uint8_t *in, size_t n, char *out)
{
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { out[2*i] = d[in[i] >> 4]; out[2*i+1] = d[in[i] & 0xf]; }
    out[2*n] = '\0';
}

/* constant-time string compare */
static bool ct_eq(const char *a, const char *b)
{
    size_t la = strlen(a), lb = strlen(b);
    if (la != lb) return false;
    uint8_t diff = 0;
    for (size_t i = 0; i < la; i++) diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}

void vsess_reset(void)
{
    s_active = false; s_token[0] = '\0'; s_last_seen_ms = 0;
    s_fail_count = 0; s_lockout_until_ms = 0;
}

bool vsess_login_allowed(uint64_t now_ms)
{
    if (s_fail_count >= VS_MAX_FAILS && now_ms < s_lockout_until_ms) return false;
    if (s_fail_count >= VS_MAX_FAILS && now_ms >= s_lockout_until_ms) s_fail_count = 0;
    return true;
}

void vsess_note_login_result(bool success, uint64_t now_ms)
{
    if (success) { s_fail_count = 0; s_lockout_until_ms = 0; return; }
    s_fail_count++;
    if (s_fail_count >= VS_MAX_FAILS) s_lockout_until_ms = now_ms + VS_LOCKOUT_MS;
}

void vsess_create(uint64_t now_ms, char out_token_hex[VS_TOKEN_HEX])
{
    uint8_t raw[VS_TOKEN_LEN]; vc_random(raw, sizeof raw);
    to_hex(raw, sizeof raw, s_token);
    s_active = true; s_last_seen_ms = now_ms;
    strcpy(out_token_hex, s_token);
}

bool vsess_validate(const char *token_hex, uint64_t now_ms)
{
    if (!s_active || !token_hex || token_hex[0] == '\0') return false;
    if (now_ms - s_last_seen_ms > VS_IDLE_MS) { vsess_destroy(); return false; }
    if (!ct_eq(token_hex, s_token)) return false;
    s_last_seen_ms = now_ms;
    return true;
}

void vsess_destroy(void)
{
    s_active = false;
    memset(s_token, 0, sizeof s_token);
}
```

- [ ] **Step 6: Build, flash, run**

Run: `cd test_app && idf.py -p <PORT> flash monitor`, run `[vault_session]`.
Expected: `3 Tests 0 Failures 0 Ignored`.

- [ ] **Step 7: Commit**

```bash
git add components/vault_session test_app
git commit -m "feat: vault_session tokens, idle timeout, and login lockout"
```

---

## Task 7: `vault_cert` — self-signed certificate generation + persistence

**Files:**
- Create: `components/vault_cert/include/vault_cert.h`
- Create: `components/vault_cert/vault_cert.c`
- Create: `components/vault_cert/CMakeLists.txt`

No unit test (depends on mbedTLS entropy + NVS); verified at integration in Task 11.

- [ ] **Step 1: Create the header**

`components/vault_cert/include/vault_cert.h`:

```c
#pragma once
#include <stddef.h>
#include "esp_err.h"

/* Loads a PEM cert+key pair from NVS, generating and persisting a new
 * self-signed pair on first call. Buffers are malloc'd; caller frees. */
esp_err_t vault_cert_get(char **cert_pem, size_t *cert_len,
                         char **key_pem,  size_t *key_len);
```

- [ ] **Step 2: Implement cert generation**

`components/vault_cert/vault_cert.c`:

```c
#include "vault_cert.h"
#include "vault_store.h"
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/x509write.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include <stdlib.h>
#include <string.h>

#define CERT_KEY "cert_pem"
#define PKEY_KEY "key_pem"
#define DN       "CN=esp32key.local,O=esp32key"

static esp_err_t generate(char **cert_pem, size_t *cert_len,
                          char **key_pem, size_t *key_len)
{
    mbedtls_pk_context key; mbedtls_pk_init(&key);
    mbedtls_x509write_cert crt; mbedtls_x509write_crt_init(&crt);
    mbedtls_ctr_drbg_context ctr; mbedtls_ctr_drbg_init(&ctr);
    mbedtls_entropy_context ent; mbedtls_entropy_init(&ent);
    mbedtls_mpi serial; mbedtls_mpi_init(&serial);
    esp_err_t result = ESP_FAIL;
    unsigned char keybuf[2048] = {0}, crtbuf[2048] = {0};

    const char *seed = "esp32key-cert";
    if (mbedtls_ctr_drbg_seed(&ctr, mbedtls_entropy_func, &ent,
            (const unsigned char *)seed, strlen(seed)) != 0) goto done;
    if (mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) != 0) goto done;
    if (mbedtls_rsa_gen_key(mbedtls_pk_rsa(key), mbedtls_ctr_drbg_random, &ctr,
            2048, 65537) != 0) goto done;
    if (mbedtls_pk_write_key_pem(&key, keybuf, sizeof keybuf) != 0) goto done;

    mbedtls_x509write_crt_set_subject_key(&crt, &key);
    mbedtls_x509write_crt_set_issuer_key(&crt, &key);   /* self-signed */
    if (mbedtls_x509write_crt_set_subject_name(&crt, DN) != 0) goto done;
    if (mbedtls_x509write_crt_set_issuer_name(&crt, DN) != 0) goto done;
    mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);
    mbedtls_mpi_lset(&serial, 1);
    mbedtls_x509write_crt_set_serial(&crt, &serial);
    mbedtls_x509write_crt_set_validity(&crt, "20240101000000", "20340101000000");
    if (mbedtls_x509write_crt_pem(&crt, crtbuf, sizeof crtbuf,
            mbedtls_ctr_drbg_random, &ctr) != 0) goto done;

    *key_len  = strlen((char *)keybuf) + 1;
    *cert_len = strlen((char *)crtbuf) + 1;
    *key_pem  = malloc(*key_len);
    *cert_pem = malloc(*cert_len);
    if (!*key_pem || !*cert_pem) goto done;
    memcpy(*key_pem, keybuf, *key_len);
    memcpy(*cert_pem, crtbuf, *cert_len);

    if (vs_set_blob(PKEY_KEY, *key_pem, *key_len) == ESP_OK &&
        vs_set_blob(CERT_KEY, *cert_pem, *cert_len) == ESP_OK &&
        vs_commit() == ESP_OK) {
        result = ESP_OK;
    }
done:
    mbedtls_mpi_free(&serial);
    mbedtls_entropy_free(&ent);
    mbedtls_ctr_drbg_free(&ctr);
    mbedtls_x509write_crt_free(&crt);
    mbedtls_pk_free(&key);
    return result;
}

esp_err_t vault_cert_get(char **cert_pem, size_t *cert_len,
                         char **key_pem, size_t *key_len)
{
    size_t clen = 0, klen = 0;
    if (vs_get_blob(CERT_KEY, NULL, &clen) == ESP_OK &&
        vs_get_blob(PKEY_KEY, NULL, &klen) == ESP_OK) {
        *cert_pem = malloc(clen); *key_pem = malloc(klen);
        if (!*cert_pem || !*key_pem) return ESP_ERR_NO_MEM;
        if (vs_get_blob(CERT_KEY, *cert_pem, &clen) == ESP_OK &&
            vs_get_blob(PKEY_KEY, *key_pem, &klen) == ESP_OK) {
            *cert_len = clen; *key_len = klen;
            return ESP_OK;
        }
        return ESP_FAIL;
    }
    return generate(cert_pem, cert_len, key_pem, key_len);
}
```

- [ ] **Step 3: Create `CMakeLists.txt`**

```cmake
idf_component_register(SRCS "vault_cert.c"
                       INCLUDE_DIRS "include"
                       REQUIRES mbedtls vault_store)
```

- [ ] **Step 4: Build (compile-check only) and commit**

Run: `cd test_app && idf.py build` (add `vault_cert` to REQUIRES to force compilation).
Expected: build succeeds.

```bash
git add components/vault_cert test_app
git commit -m "feat: vault_cert self-signed certificate generation and persistence"
```

---

## Task 8: `net_wifi_ap` — softAP bring-up

**Files:**
- Create: `components/net_wifi_ap/include/net_wifi_ap.h`
- Create: `components/net_wifi_ap/net_wifi_ap.c`
- Create: `components/net_wifi_ap/CMakeLists.txt`

- [ ] **Step 1: Create the header**

`components/net_wifi_ap/include/net_wifi_ap.h`:

```c
#pragma once
#include "esp_err.h"
/* Starts softAP "esp32key" with the given WPA2 password (>=8 chars).
 * Assumes esp_netif_init() and esp_event_loop_create_default() already called. */
esp_err_t net_wifi_ap_start(const char *password);
```

- [ ] **Step 2: Implement**

`components/net_wifi_ap/net_wifi_ap.c`:

```c
#include "net_wifi_ap.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include <string.h>

esp_err_t net_wifi_ap_start(const char *password)
{
    esp_netif_create_default_wifi_ap();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    wifi_config_t ap = {0};
    strlcpy((char *)ap.ap.ssid, "esp32key", sizeof ap.ap.ssid);
    ap.ap.ssid_len = strlen("esp32key");
    ap.ap.channel = 1;
    ap.ap.max_connection = 2;
    ap.ap.authmode = WIFI_AUTH_WPA2_PSK;
    strlcpy((char *)ap.ap.password, password, sizeof ap.ap.password);
    if (strlen(password) < 8) ap.ap.authmode = WIFI_AUTH_OPEN; /* avoid silent fail */

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap));
    return esp_wifi_start();
}
```

- [ ] **Step 3: Create `CMakeLists.txt`**

```cmake
idf_component_register(SRCS "net_wifi_ap.c"
                       INCLUDE_DIRS "include"
                       REQUIRES esp_wifi esp_netif)
```

- [ ] **Step 4: Commit** (integration-verified in Task 11)

```bash
git add components/net_wifi_ap
git commit -m "feat: net_wifi_ap WPA2 softAP bring-up"
```

---

## Task 9: `net_usb` — TinyUSB NCM network interface

**Files:**
- Create: `components/net_usb/include/net_usb.h`
- Create: `components/net_usb/net_usb.c`
- Create: `components/net_usb/CMakeLists.txt`
- Create: `components/net_usb/idf_component.yml` (pull in `esp_tinyusb`)

- [ ] **Step 1: Declare the managed dependency**

`components/net_usb/idf_component.yml`:

```yaml
dependencies:
  espressif/esp_tinyusb: "^1.4.0"
```

- [ ] **Step 2: Create the header**

`components/net_usb/include/net_usb.h`:

```c
#pragma once
#include "esp_err.h"
/* Brings up a TinyUSB NCM network interface with a static IP (10.10.0.1)
 * and a DHCP server handing out 10.10.0.2+ to the host. */
esp_err_t net_usb_start(void);
```

- [ ] **Step 3: Implement using the esp_tinyusb NCM driver**

`components/net_usb/net_usb.c`:

```c
#include "net_usb.h"
#include "esp_netif.h"
#include "tinyusb.h"
#include "tinyusb_net.h"
#include "esp_mac.h"
#include <string.h>

static esp_netif_t *s_usb_netif;

/* Glue: TinyUSB -> esp_netif (host->device frames). */
static esp_err_t rx_cb(void *buffer, uint16_t len, void *ctx)
{
    return esp_netif_receive(s_usb_netif, buffer, len, NULL);
}

/* Glue: esp_netif -> TinyUSB (device->host frames). */
static esp_err_t netif_transmit(void *h, void *buffer, size_t len)
{
    return tinyusb_net_send_sync(buffer, len, NULL, portMAX_DELAY);
}

static void l2_free(void *h, void *buffer) { (void)h; (void)buffer; }

esp_err_t net_usb_start(void)
{
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);

    /* Custom esp-netif config: static IP, no DHCP client, we run a DHCP server. */
    esp_netif_inherent_config_t base = ESP_NETIF_INHERENT_DEFAULT_ETH();
    base.if_desc = "usb";
    base.route_prio = 10;
    base.flags = ESP_NETIF_DHCP_SERVER | ESP_NETIF_FLAG_AUTOUP;

    esp_netif_ip_info_t ip = {0};
    ip.ip.addr      = ESP_IP4TOADDR(10, 10, 0, 1);
    ip.gw.addr      = ESP_IP4TOADDR(10, 10, 0, 1);
    ip.netmask.addr = ESP_IP4TOADDR(255, 255, 255, 0);
    base.ip_info = &ip;

    esp_netif_config_t cfg = {
        .base   = &base,
        .driver = NULL,
        .stack  = ESP_NETIF_NETSTACK_DEFAULT_ETH,
    };
    s_usb_netif = esp_netif_new(&cfg);

    esp_netif_driver_ifconfig_t drv = {
        .handle = (void *)1,
        .transmit = netif_transmit,
        .driver_free_rx_buffer = l2_free,
    };
    ESP_ERROR_CHECK(esp_netif_set_driver_config(s_usb_netif, &drv));

    const tinyusb_config_t tusb_cfg = { .external_phy = false };
    ESP_ERROR_CHECK(tinyusb_driver_install(&tusb_cfg));

    tinyusb_net_config_t net_cfg = {
        .on_recv_callback = rx_cb,
    };
    memcpy(net_cfg.mac_addr, mac, 6);
    ESP_ERROR_CHECK(tinyusb_net_init(TINYUSB_USBDEV_0, &net_cfg));

    esp_netif_action_start(s_usb_netif, NULL, 0, NULL);
    return ESP_OK;
}
```

> Note: the exact `tinyusb_net_*` symbol names/signatures track the `esp_tinyusb` version resolved by Step 1. If the build reports a signature mismatch, open `managed_components/espressif__esp_tinyusb/include/tinyusb_net.h` and align the callback prototypes — the structure (rx callback → `esp_netif_receive`, tx → `tinyusb_net_send_sync`) stays the same.

- [ ] **Step 4: Create `CMakeLists.txt`**

```cmake
idf_component_register(SRCS "net_usb.c"
                       INCLUDE_DIRS "include"
                       REQUIRES esp_netif)
```

- [ ] **Step 5: Commit** (integration-verified in Task 11)

```bash
git add components/net_usb
git commit -m "feat: net_usb TinyUSB NCM network interface with DHCP server"
```

---

## Task 10: `vault_api` — HTTPS server, REST handlers, embedded web UI

**Files:**
- Create: `components/vault_api/include/vault_api.h`
- Create: `components/vault_api/vault_api.c`
- Create: `components/vault_api/CMakeLists.txt`
- Create: `components/vault_api/www/index.html`
- Create: `components/vault_api/www/app.js`
- Create: `components/vault_api/www/style.css`

Uses cJSON for request/response bodies and `esp_https_server`. Time source for sessions is `esp_timer_get_time() / 1000`.

- [ ] **Step 1: Create the header**

`components/vault_api/include/vault_api.h`:

```c
#pragma once
#include "esp_err.h"
/* Starts the HTTPS server (binds all interfaces) with the given cert/key PEM. */
esp_err_t vault_api_start(const char *cert_pem, size_t cert_len,
                          const char *key_pem,  size_t key_len);
```

- [ ] **Step 2: Create the embedded web UI**

`components/vault_api/www/index.html`:

```html
<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>esp32key</title><link rel="stylesheet" href="/style.css"></head>
<body><div id="app">Loading…</div><script src="/app.js"></script></body></html>
```

`components/vault_api/www/style.css`:

```css
body{font-family:system-ui,sans-serif;max-width:560px;margin:2rem auto;padding:0 1rem}
input,button{font-size:1rem;padding:.5rem;margin:.25rem 0;width:100%;box-sizing:border-box}
.entry{border:1px solid #ccc;border-radius:6px;padding:.5rem;margin:.5rem 0}
.row{display:flex;gap:.5rem}.row button{width:auto}
.err{color:#b00}
```

`components/vault_api/www/app.js`:

```js
const $ = s => document.querySelector(s);
async function api(path, opts={}) {
  const r = await fetch(path, {credentials:'same-origin', headers:{'Content-Type':'application/json'}, ...opts});
  if (!r.ok) throw new Error((await r.json().catch(()=>({}))).error || r.statusText);
  return r.status === 204 ? null : r.json();
}
async function boot() {
  const st = await api('/api/state');
  if (!st.initialized) return renderSetup();
  if (!st.unlocked) return renderLogin();
  return renderVault();
}
function renderSetup() {
  $('#app').innerHTML = `<h2>Set master password</h2>
    <input id=pw type=password placeholder="Master password">
    <button id=go>Create vault</button><div class=err id=e></div>`;
  $('#go').onclick = async () => {
    try { await api('/api/setup',{method:'POST',body:JSON.stringify({password:$('#pw').value})}); boot(); }
    catch(e){ $('#e').textContent = e.message; }
  };
}
function renderLogin() {
  $('#app').innerHTML = `<h2>Unlock</h2>
    <input id=pw type=password placeholder="Master password">
    <button id=go>Unlock</button><div class=err id=e></div>`;
  $('#go').onclick = async () => {
    try { await api('/api/login',{method:'POST',body:JSON.stringify({password:$('#pw').value})}); boot(); }
    catch(e){ $('#e').textContent = e.message; }
  };
}
async function renderVault() {
  const {entries} = await api('/api/entries');
  $('#app').innerHTML = `<h2>Vault</h2>
    <div id=list></div><h3>Add</h3>
    <input id=t placeholder=Title><input id=u placeholder=Username>
    <input id=s placeholder=Secret>
    <div class=row><button id=add>Add</button><button id=lock>Lock</button></div>`;
  $('#list').innerHTML = entries.map(e=>`<div class=entry data-id=${e.id}>
    <b>${esc(e.title)}</b> — ${esc(e.username)}
    <div class=row><button class=rev>Reveal</button>
    <button class=del>Delete</button></div><div class=sec></div></div>`).join('') || '<p>No entries.</p>';
  document.querySelectorAll('.rev').forEach(b=>b.onclick=async ev=>{
    const d=ev.target.closest('.entry'); const {secret}=await api(`/api/entries/${d.dataset.id}/secret`);
    d.querySelector('.sec').textContent=secret;
  });
  document.querySelectorAll('.del').forEach(b=>b.onclick=async ev=>{
    const d=ev.target.closest('.entry'); await api(`/api/entries/${d.dataset.id}`,{method:'DELETE'}); renderVault();
  });
  $('#add').onclick=async()=>{ await api('/api/entries',{method:'POST',body:JSON.stringify(
    {title:$('#t').value,username:$('#u').value,secret:$('#s').value})}); renderVault(); };
  $('#lock').onclick=async()=>{ await api('/api/logout',{method:'POST'}); boot(); };
}
const esc = s => s.replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
boot();
```

- [ ] **Step 3: Implement the server + handlers**

`components/vault_api/vault_api.c`:

```c
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

/* Read body into a NUL-terminated heap buffer; caller frees. */
static char *read_body(httpd_req_t *r)
{
    if (r->content_len == 0 || r->content_len > 2048) return NULL;
    char *buf = malloc(r->content_len + 1);
    if (!buf) return NULL;
    int n = httpd_req_recv(r, buf, r->content_len);
    if (n <= 0) { free(buf); return NULL; }
    buf[n] = '\0';
    return buf;
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
    esp_err_t e = vault_setup(pw, strlen(pw));
    cJSON_Delete(j);
    if (e != ESP_OK) return err_json(r,400,"already initialized");
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

esp_err_t vault_api_start(const char *cert_pem, size_t cert_len,
                          const char *key_pem, size_t key_len)
{
    httpd_ssl_config_t cfg = HTTPD_SSL_CONFIG_DEFAULT();
    cfg.servercert = (const uint8_t *)cert_pem;
    cfg.servercert_len = cert_len;
    cfg.prvtkey_pem = (const uint8_t *)key_pem;
    cfg.prvtkey_len = key_len;
    cfg.httpd.max_uri_handlers = 16;
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
```

- [ ] **Step 4: Create `CMakeLists.txt` with embedded files**

`components/vault_api/CMakeLists.txt`:

```cmake
idf_component_register(SRCS "vault_api.c"
                       INCLUDE_DIRS "include"
                       REQUIRES esp_https_server json vault vault_session esp_timer
                       EMBED_FILES "www/index.html" "www/app.js" "www/style.css")
```

- [ ] **Step 5: Compile-check**

Run: add `vault_api` to `test_app/main/CMakeLists.txt` REQUIRES, `cd test_app && idf.py build`.
Expected: build succeeds.

- [ ] **Step 6: Commit**

```bash
git add components/vault_api test_app
git commit -m "feat: vault_api HTTPS server, REST handlers, and embedded web UI"
```

---

## Task 11: `main` — wire everything together + integration test

**Files:**
- Modify: `main/CMakeLists.txt`
- Modify: `main/main.c`

- [ ] **Step 1: Update `main/CMakeLists.txt`**

```cmake
idf_component_register(SRCS "main.c"
                       INCLUDE_DIRS ""
                       REQUIRES vault_store vault vault_session vault_cert
                                net_wifi_ap net_usb vault_api esp_netif esp_event)
```

- [ ] **Step 2: Implement `app_main`**

`main/main.c`:

```c
#include "esp_log.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "vault_store.h"
#include "vault_cert.h"
#include "net_wifi_ap.h"
#include "net_usb.h"
#include "vault_api.h"
#include <stdlib.h>

static const char *TAG = "esp32key";

/* Default AP password — change via Settings after first boot. */
#define AP_PASSWORD "esp32key-changeme"

void app_main(void)
{
    ESP_ERROR_CHECK(vs_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    ESP_ERROR_CHECK(net_wifi_ap_start(AP_PASSWORD));
    ESP_ERROR_CHECK(net_usb_start());

    char *cert = NULL, *key = NULL; size_t clen = 0, klen = 0;
    ESP_ERROR_CHECK(vault_cert_get(&cert, &clen, &key, &klen));
    ESP_LOGI(TAG, "certificate ready (%u bytes)", (unsigned)clen);

    ESP_ERROR_CHECK(vault_api_start(cert, clen, key, klen));
    ESP_LOGI(TAG, "esp32key ready: https://192.168.4.1 (WiFi) / https://10.10.0.1 (USB)");
}
```

- [ ] **Step 3: Build the firmware (the real app, not test_app)**

Run: `idf.py build`
Expected: build succeeds.

- [ ] **Step 4: Flash and boot**

Run: `idf.py -p <PORT> flash monitor`
Expected: log ends with `esp32key ready: https://192.168.4.1 ...` and no error/`abort()`.

- [ ] **Step 5: Integration test over WiFi AP**

1. On a laptop/phone, join WiFi network `esp32key` (password `esp32key-changeme`).
2. Browse to `https://192.168.4.1`, accept the certificate warning.
3. First load shows **Set master password** → create one → vault appears.
4. Add an entry (title/username/secret) → it appears in the list.
5. Click **Reveal** → secret shows. Click **Lock** → returns to unlock screen.
6. Unlock with the master password → entry still present (persisted + decrypts).
7. Power-cycle the board, reconnect → unlock → entry still present.

Expected: all steps succeed.

- [ ] **Step 6: Integration test over USB**

1. Plug the board's USB into the PC; it enumerates as a network adapter (10.10.0.x).
2. Browse to `https://10.10.0.1` → same UI, same vault contents, WiFi internet still available.

Expected: vault reachable over USB with WiFi internet intact.

- [ ] **Step 7: Negative checks**

- Wrong master password → "invalid password"; after 5 wrong tries → "locked out".
- Hitting `/api/entries` without a session cookie → 401.

Expected: behaves as described.

- [ ] **Step 8: Commit**

```bash
git add main
git commit -m "feat: wire NVS, WiFi AP, USB NCM, cert, and HTTPS API into app_main"
```

---

## Task 12: `vault_crypto` portable transfer bundle (TDD)

Adds a device-independent, password-encrypted bundle format for moving
credentials between devices. Purely additive to `vault_crypto`.

**Files:**
- Modify: `components/vault_crypto/include/vault_crypto.h`
- Modify: `components/vault_crypto/vault_crypto.c`
- Test: `components/vault_crypto/test/test_vault_crypto.c`

- [ ] **Step 1: Add bundle declarations to the header**

Append to `vault_crypto.h`:

```c
/* Portable bundle: [magic "EKV1"(4)][version(1)][salt(16)][iter(4 LE)]
 *                  [nonce(12)][tag(16)][ciphertext]. Self-contained; the
 * ciphertext is encrypted under KDF(password, salt). Not tied to any DEK. */
#define VC_BUNDLE_HDR (4 + 1 + VC_SALT_LEN + 4 + VC_NONCE_LEN + VC_TAG_LEN)
#define VC_BUNDLE_VERSION 1

/* Pack plaintext into out (must hold VC_BUNDLE_HDR + plain_len). On entry
 * *out_len = capacity; on success *out_len = total bundle length. */
esp_err_t vc_bundle_pack(const char *password, size_t pw_len,
                         const uint8_t *plain, size_t plain_len,
                         uint8_t *out, size_t *out_len);

/* Unpack/verify a bundle into out_plain (on entry *out_len = capacity; on
 * success *out_len = plaintext length). Returns ESP_FAIL on wrong password or
 * tampering, ESP_ERR_INVALID_ARG on bad magic, ESP_ERR_INVALID_VERSION on
 * unknown version, ESP_ERR_INVALID_SIZE if buffers are too small. */
esp_err_t vc_bundle_unpack(const char *password, size_t pw_len,
                           const uint8_t *bundle, size_t bundle_len,
                           uint8_t *out_plain, size_t *out_len);
```

- [ ] **Step 2: Write the failing tests**

Append to `test_vault_crypto.c`:

```c
TEST_CASE("bundle pack/unpack round-trips; wrong password fails", "[vault_crypto]")
{
    const char *msg = "entry-records-blob";
    size_t mlen = strlen(msg);
    uint8_t bundle[VC_BUNDLE_HDR + 64];
    size_t blen = sizeof bundle;
    TEST_ASSERT_EQUAL(ESP_OK, vc_bundle_pack("transfer-pw", 11,
                      (const uint8_t *)msg, mlen, bundle, &blen));
    TEST_ASSERT_EQUAL(VC_BUNDLE_HDR + mlen, blen);

    uint8_t out[64]; size_t olen = sizeof out;
    TEST_ASSERT_EQUAL(ESP_OK, vc_bundle_unpack("transfer-pw", 11, bundle, blen, out, &olen));
    TEST_ASSERT_EQUAL(mlen, olen);
    TEST_ASSERT_EQUAL_MEMORY(msg, out, mlen);

    olen = sizeof out;
    TEST_ASSERT_NOT_EQUAL(ESP_OK, vc_bundle_unpack("wrong-pw", 8, bundle, blen, out, &olen));

    bundle[0] ^= 0xFF;  /* corrupt magic */
    olen = sizeof out;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, vc_bundle_unpack("transfer-pw", 11, bundle, blen, out, &olen));
}
```

- [ ] **Step 3: Run to confirm failure**

Run: `cd test_app && idf.py build`
Expected: FAIL — `vc_bundle_pack` undefined.

- [ ] **Step 4: Implement pack/unpack**

Append to `vault_crypto.c`:

```c
#define BUNDLE_ITERATIONS 100000u
static const char BUNDLE_MAGIC[4] = {'E','K','V','1'};

esp_err_t vc_bundle_pack(const char *password, size_t pw_len,
                         const uint8_t *plain, size_t plain_len,
                         uint8_t *out, size_t *out_len)
{
    if (*out_len < VC_BUNDLE_HDR + plain_len) return ESP_ERR_INVALID_SIZE;
    uint8_t *p = out;
    memcpy(p, BUNDLE_MAGIC, 4); p += 4;
    *p++ = VC_BUNDLE_VERSION;
    uint8_t *salt = p; vc_random(salt, VC_SALT_LEN); p += VC_SALT_LEN;
    uint32_t iter = BUNDLE_ITERATIONS; memcpy(p, &iter, 4); p += 4;
    uint8_t *nonce = p; vc_random(nonce, VC_NONCE_LEN); p += VC_NONCE_LEN;
    uint8_t *tag = p; p += VC_TAG_LEN;
    uint8_t *ct = p;

    uint8_t key[VC_KEY_LEN];
    if (vc_derive_key(password, pw_len, salt, iter, key) != ESP_OK) return ESP_FAIL;
    esp_err_t e = vc_gcm_encrypt(key, nonce, NULL, 0, plain, plain_len, ct, tag);
    if (e != ESP_OK) return e;
    *out_len = VC_BUNDLE_HDR + plain_len;
    return ESP_OK;
}

esp_err_t vc_bundle_unpack(const char *password, size_t pw_len,
                           const uint8_t *bundle, size_t bundle_len,
                           uint8_t *out_plain, size_t *out_len)
{
    if (bundle_len < VC_BUNDLE_HDR) return ESP_ERR_INVALID_SIZE;
    if (memcmp(bundle, BUNDLE_MAGIC, 4) != 0) return ESP_ERR_INVALID_ARG;
    if (bundle[4] != VC_BUNDLE_VERSION) return ESP_ERR_INVALID_VERSION;
    const uint8_t *salt  = bundle + 5;
    uint32_t iter; memcpy(&iter, bundle + 5 + VC_SALT_LEN, 4);
    const uint8_t *nonce = bundle + 5 + VC_SALT_LEN + 4;
    const uint8_t *tag   = nonce + VC_NONCE_LEN;
    const uint8_t *ct    = tag + VC_TAG_LEN;
    size_t ct_len = bundle_len - VC_BUNDLE_HDR;
    if (*out_len < ct_len) return ESP_ERR_INVALID_SIZE;

    uint8_t key[VC_KEY_LEN];
    if (vc_derive_key(password, pw_len, salt, iter, key) != ESP_OK) return ESP_FAIL;
    esp_err_t e = vc_gcm_decrypt(key, nonce, NULL, 0, ct, ct_len, tag, out_plain);
    if (e != ESP_OK) return e;       /* wrong password / tamper */
    *out_len = ct_len;
    return ESP_OK;
}
```

- [ ] **Step 5: Build, flash, run**

Run: `cd test_app && idf.py -p <PORT> flash monitor`, run `[vault_crypto]`.
Expected: `4 Tests 0 Failures 0 Ignored`.

- [ ] **Step 6: Commit**

```bash
git add components/vault_crypto
git commit -m "feat: vault_crypto portable transfer bundle pack/unpack"
```

---

## Task 13: `vault` transfer password + export/import (TDD)

Adds the second password and device-to-device export/import. Additive to the
`vault` component; `vault_setup` and existing CRUD are unchanged.

**Files:**
- Modify: `components/vault/include/vault.h`
- Modify: `components/vault/vault.c`
- Test: `components/vault/test/test_vault.c`

- [ ] **Step 1: Add transfer declarations to `vault.h`**

Append to `vault.h` (before the final newline):

```c
/* Transfer password — set during first-run setup, gates/encrypts export. */
esp_err_t vault_set_transfer_password(const char *pw, size_t len);
bool      vault_verify_transfer(const char *pw, size_t len);

/* Export all entries as a portable bundle encrypted under the transfer
 * password. Requires unlocked vault + correct transfer password.
 * *out_bundle is malloc'd; caller frees. */
esp_err_t vault_export(const char *transfer_pw, size_t len,
                       uint8_t **out_bundle, size_t *out_len);

/* Import a bundle (decrypted with the supplied transfer password) and merge:
 * an imported entry replaces a local one with the same title+username; others
 * are added. Requires unlocked vault. Returns ESP_FAIL on wrong password. */
esp_err_t vault_import(const char *transfer_pw, size_t len,
                       const uint8_t *bundle, size_t bundle_len);
```

- [ ] **Step 2: Extend `fresh()` and write failing tests**

In `test_vault.c`, update the `fresh()` helper to also clear the transfer keys:

```c
static void fresh(void)
{
    TEST_ASSERT_EQUAL(ESP_OK, vs_init());
    vs_erase_key("salt"); vs_erase_key("wdek"); vs_erase_key("entries");
    vs_erase_key("iter"); vs_erase_key("tsalt"); vs_erase_key("tverif");
    vs_commit();
    vault_lock();
}
```

Append these test cases to `test_vault.c`:

```c
TEST_CASE("transfer password verifies correctly", "[vault]")
{
    fresh();
    TEST_ASSERT_EQUAL(ESP_OK, vault_setup("master", 6));
    TEST_ASSERT_EQUAL(ESP_OK, vault_set_transfer_password("xfer", 4));
    TEST_ASSERT_TRUE(vault_verify_transfer("xfer", 4));
    TEST_ASSERT_FALSE(vault_verify_transfer("nope", 4));
}

TEST_CASE("export/import round-trips; wrong transfer password rejected", "[vault]")
{
    fresh();
    TEST_ASSERT_EQUAL(ESP_OK, vault_setup("master", 6));
    TEST_ASSERT_EQUAL(ESP_OK, vault_set_transfer_password("xfer", 4));
    uint8_t id; TEST_ASSERT_EQUAL(ESP_OK, vault_add("GitHub", "dan", "tok", &id));

    uint8_t *bundle = NULL; size_t blen = 0;
    TEST_ASSERT_EQUAL(ESP_OK, vault_export("xfer", 4, &bundle, &blen));
    TEST_ASSERT_NOT_NULL(bundle);
    TEST_ASSERT_NOT_EQUAL(ESP_OK, vault_export("bad", 3, &bundle, &blen)); /* wrong pw */

    /* Simulate an empty target device by deleting the entry. */
    TEST_ASSERT_EQUAL(ESP_OK, vault_delete(id));
    vault_entry_t list[VAULT_MAX_ENTRIES]; size_t n = 0;
    vault_list(list, VAULT_MAX_ENTRIES, &n); TEST_ASSERT_EQUAL(0, n);

    TEST_ASSERT_NOT_EQUAL(ESP_OK, vault_import("wrong", 5, bundle, blen));
    TEST_ASSERT_EQUAL(ESP_OK, vault_import("xfer", 4, bundle, blen));
    vault_list(list, VAULT_MAX_ENTRIES, &n); TEST_ASSERT_EQUAL(1, n);
    TEST_ASSERT_EQUAL_STRING("GitHub", list[0].title);
    char sec[VAULT_FIELD_MAX];
    TEST_ASSERT_EQUAL(ESP_OK, vault_reveal(list[0].id, sec));
    TEST_ASSERT_EQUAL_STRING("tok", sec);
    free(bundle);
}

TEST_CASE("import merges by title+username (no duplicate)", "[vault]")
{
    fresh();
    TEST_ASSERT_EQUAL(ESP_OK, vault_setup("master", 6));
    TEST_ASSERT_EQUAL(ESP_OK, vault_set_transfer_password("x", 1));
    uint8_t id; TEST_ASSERT_EQUAL(ESP_OK, vault_add("Site", "u", "old", &id));

    uint8_t *bundle = NULL; size_t blen = 0;
    TEST_ASSERT_EQUAL(ESP_OK, vault_export("x", 1, &bundle, &blen));
    TEST_ASSERT_EQUAL(ESP_OK, vault_update(id, "Site", "u", "new"));
    TEST_ASSERT_EQUAL(ESP_OK, vault_import("x", 1, bundle, blen)); /* old replaces new */

    vault_entry_t list[VAULT_MAX_ENTRIES]; size_t n = 0;
    vault_list(list, VAULT_MAX_ENTRIES, &n);
    TEST_ASSERT_EQUAL(1, n);                       /* merged, not duplicated */
    char sec[VAULT_FIELD_MAX];
    vault_reveal(list[0].id, sec);
    TEST_ASSERT_EQUAL_STRING("old", sec);
    free(bundle);
}
```

- [ ] **Step 3: Run to confirm failure**

Run: `cd test_app && idf.py build`
Expected: FAIL — `vault_set_transfer_password` undefined.

- [ ] **Step 4: Implement transfer functions**

Append to `vault.c` (`#include <stdlib.h>` for `malloc`; `string.h` already included):

```c
#include <stdlib.h>

/* 16-byte known constant used as the transfer-password verifier plaintext. */
static const uint8_t XFER_CHECK[16] = "esp32key-xfer!!";  /* 15 chars + NUL */
#define TVERIF_LEN (VC_NONCE_LEN + 16 + VC_TAG_LEN)

esp_err_t vault_set_transfer_password(const char *pw, size_t len)
{
    uint8_t tsalt[VC_SALT_LEN]; vc_random(tsalt, sizeof tsalt);
    uint8_t tkey[VC_KEY_LEN];
    if (vc_derive_key(pw, len, tsalt, ITERATIONS, tkey) != ESP_OK) return ESP_FAIL;

    uint8_t verif[TVERIF_LEN];
    uint8_t *nonce = verif, *ct = verif + VC_NONCE_LEN, *tag = verif + VC_NONCE_LEN + 16;
    vc_random(nonce, VC_NONCE_LEN);
    if (vc_gcm_encrypt(tkey, nonce, NULL, 0, XFER_CHECK, 16, ct, tag) != ESP_OK) return ESP_FAIL;

    esp_err_t e;
    if ((e = vs_set_blob("tsalt", tsalt, sizeof tsalt)) != ESP_OK) return e;
    if ((e = vs_set_blob("tverif", verif, sizeof verif)) != ESP_OK) return e;
    return vs_commit();
}

bool vault_verify_transfer(const char *pw, size_t len)
{
    uint8_t tsalt[VC_SALT_LEN]; size_t sl = sizeof tsalt;
    if (vs_get_blob("tsalt", tsalt, &sl) != ESP_OK) return false;
    uint8_t tkey[VC_KEY_LEN];
    if (vc_derive_key(pw, len, tsalt, ITERATIONS, tkey) != ESP_OK) return false;
    uint8_t verif[TVERIF_LEN]; size_t vl = sizeof verif;
    if (vs_get_blob("tverif", verif, &vl) != ESP_OK) return false;
    uint8_t *nonce = verif, *ct = verif + VC_NONCE_LEN, *tag = verif + VC_NONCE_LEN + 16;
    uint8_t out[16];
    return vc_gcm_decrypt(tkey, nonce, NULL, 0, ct, 16, tag, out) == ESP_OK &&
           memcmp(out, XFER_CHECK, 16) == 0;
}

/* Serialize s_entries into plain[] (same record layout as persist_entries). */
static size_t serialize_entries(uint8_t *plain)
{
    size_t off = 0;
    for (size_t i = 0; i < s_count; i++) {
        plain[off++] = s_entries[i].id;
        memcpy(plain + off, s_entries[i].title,    VAULT_FIELD_MAX); off += VAULT_FIELD_MAX;
        memcpy(plain + off, s_entries[i].username,  VAULT_FIELD_MAX); off += VAULT_FIELD_MAX;
        memcpy(plain + off, s_entries[i].secret,    VAULT_FIELD_MAX); off += VAULT_FIELD_MAX;
    }
    return off;
}

esp_err_t vault_export(const char *transfer_pw, size_t len,
                       uint8_t **out_bundle, size_t *out_len)
{
    if (!s_unlocked) return ESP_ERR_INVALID_STATE;
    if (!vault_verify_transfer(transfer_pw, len)) return ESP_FAIL;

    static uint8_t plain[PLAIN_MAX];
    size_t plen = serialize_entries(plain);
    size_t cap = VC_BUNDLE_HDR + plen;
    uint8_t *buf = malloc(cap);
    if (!buf) return ESP_ERR_NO_MEM;
    size_t blen = cap;
    esp_err_t e = vc_bundle_pack(transfer_pw, len, plain, plen, buf, &blen);
    if (e != ESP_OK) { free(buf); return e; }
    *out_bundle = buf; *out_len = blen;
    return ESP_OK;
}

esp_err_t vault_import(const char *transfer_pw, size_t len,
                       const uint8_t *bundle, size_t bundle_len)
{
    if (!s_unlocked) return ESP_ERR_INVALID_STATE;
    static uint8_t plain[PLAIN_MAX];
    size_t plen = sizeof plain;
    esp_err_t e = vc_bundle_unpack(transfer_pw, len, bundle, bundle_len, plain, &plen);
    if (e != ESP_OK) return e;   /* wrong password / tamper / bad format */

    size_t off = 0;
    while (off + REC_SIZE <= plen) {
        const char *title = (const char *)(plain + off + 1);
        const char *user  = (const char *)(plain + off + 1 + VAULT_FIELD_MAX);
        const char *sec   = (const char *)(plain + off + 1 + 2 * VAULT_FIELD_MAX);
        off += REC_SIZE;

        vault_entry_t *match = NULL;
        for (size_t i = 0; i < s_count; i++) {
            if (strncmp(s_entries[i].title, title, VAULT_FIELD_MAX) == 0 &&
                strncmp(s_entries[i].username, user, VAULT_FIELD_MAX) == 0) {
                match = &s_entries[i]; break;
            }
        }
        if (match) {
            set_field(match->secret, sec);
        } else if (s_count < VAULT_MAX_ENTRIES) {
            vault_entry_t *en = &s_entries[s_count++];
            en->id = s_next_id++;
            set_field(en->title, title);
            set_field(en->username, user);
            set_field(en->secret, sec);
        }
    }
    return persist_entries();
}
```

- [ ] **Step 5: Build, flash, run**

Run: `cd test_app && idf.py -p <PORT> flash monitor`, run `[vault]`.
Expected: `7 Tests 0 Failures 0 Ignored`.

- [ ] **Step 6: Commit**

```bash
git add components/vault
git commit -m "feat: vault transfer password and device-to-device export/import"
```

---

## Task 14: `vault_api` — dual-password setup, export/import endpoints, Transfer UI

**Files:**
- Modify: `components/vault_api/vault_api.c`
- Modify: `components/vault_api/CMakeLists.txt`
- Modify: `components/vault_api/www/app.js`

- [ ] **Step 1: Add base64 + larger body support and the transfer header**

In `vault_api.c`, add the base64 include near the top includes:

```c
#include "mbedtls/base64.h"
```

Replace the existing `read_body` function with a capacity-parameterized version
plus a small wrapper (import bundles exceed the old 2 KB limit):

```c
/* Read up to maxlen bytes of body into a NUL-terminated heap buffer. */
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
```

- [ ] **Step 2: Update the setup handler to take both passwords**

In `vault_api.c`, replace the body of `h_setup` between parsing and the cookie
with dual-password handling:

```c
static esp_err_t h_setup(httpd_req_t *r)
{
    char *body = read_body(r); if (!body) return err_json(r,400,"bad body");
    cJSON *j = cJSON_Parse(body); free(body);
    if (!j) return err_json(r,400,"bad json");
    const char *pw = json_str(j,"password");
    const char *tpw = json_str(j,"transfer_password");
    if (strlen(pw) == 0 || strlen(tpw) == 0) { cJSON_Delete(j); return err_json(r,400,"both passwords required"); }
    esp_err_t e = vault_setup(pw, strlen(pw));
    if (e == ESP_OK) e = vault_set_transfer_password(tpw, strlen(tpw));
    cJSON_Delete(j);
    if (e != ESP_OK) return err_json(r,400,"already initialized");
    char tok[VS_TOKEN_HEX]; vsess_create(now_ms(), tok);
    char hdr[128]; snprintf(hdr,sizeof hdr,"sid=%s; HttpOnly; Secure; Path=/; SameSite=Strict", tok);
    httpd_resp_set_hdr(r, "Set-Cookie", hdr);
    return send_json(r, 200, cJSON_CreateObject());
}
```

- [ ] **Step 3: Add export and import handlers**

Add to `vault_api.c` (after `h_change_pw`):

```c
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
    size_t rawlen = 0;
    int rc = mbedtls_base64_decode(raw, cap, &rawlen,
                                   (const unsigned char *)b64, b64len);
    esp_err_t e = (rc == 0) ? vault_import(tpw, strlen(tpw), raw, rawlen) : ESP_FAIL;
    free(raw); cJSON_Delete(j);
    if (e != ESP_OK) return err_json(r,400,"import failed (wrong password or bad file)");
    return send_json(r, 200, cJSON_CreateObject());
}
```

- [ ] **Step 4: Register the new routes and raise the handler limit**

In `vault_api_start`, change `cfg.httpd.max_uri_handlers = 16;` to `= 20;`, and
add to the `routes[]` array:

```c
        {"/api/export",             HTTP_POST,   h_export,        NULL},
        {"/api/import",             HTTP_POST,   h_import,        NULL},
```

- [ ] **Step 5: Add `mbedtls` to the component REQUIRES**

In `components/vault_api/CMakeLists.txt`, add `mbedtls` to the `REQUIRES` list:

```cmake
idf_component_register(SRCS "vault_api.c"
                       INCLUDE_DIRS "include"
                       REQUIRES esp_https_server json vault vault_session esp_timer mbedtls
                       EMBED_FILES "www/index.html" "www/app.js" "www/style.css")
```

- [ ] **Step 6: Update the web UI — second setup field + Transfer screen**

In `components/vault_api/www/app.js`, replace `renderSetup` with the
two-password version and add a Transfer screen + button.

Replace `renderSetup`:

```js
function renderSetup() {
  $('#app').innerHTML = `<h2>Set up vault</h2>
    <input id=pw type=password placeholder="Master password (daily unlock)">
    <input id=tpw type=password placeholder="Transfer password (import/export)">
    <button id=go>Create vault</button><div class=err id=e></div>`;
  $('#go').onclick = async () => {
    try { await api('/api/setup',{method:'POST',body:JSON.stringify(
      {password:$('#pw').value, transfer_password:$('#tpw').value})}); boot(); }
    catch(e){ $('#e').textContent = e.message; }
  };
}
```

In `renderVault`, add a Transfer button to the bottom button row — change the
row line to:

```js
    <div class=row><button id=add>Add</button>
    <button id=xfer>Transfer</button><button id=lock>Lock</button></div>`;
```

and wire it (add alongside the other handlers in `renderVault`):

```js
  $('#xfer').onclick = renderTransfer;
```

Add the new `renderTransfer` function:

```js
function renderTransfer() {
  $('#app').innerHTML = `<h2>Transfer</h2>
    <h3>Export</h3>
    <input id=epw type=password placeholder="Transfer password">
    <button id=exp>Download export file</button>
    <h3>Import</h3>
    <input id=ipw type=password placeholder="Transfer password (of the file)">
    <input id=file type=file>
    <button id=imp>Import file</button>
    <div class=row><button id=back>Back</button></div>
    <div class=err id=e></div>`;
  $('#back').onclick = renderVault;
  $('#exp').onclick = async () => {
    try {
      const r = await fetch('/api/export', {method:'POST', credentials:'same-origin',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({transfer_password:$('#epw').value})});
      if (!r.ok) throw new Error((await r.json().catch(()=>({}))).error || r.statusText);
      const blob = await r.blob();
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob); a.download = 'esp32key-export.bin'; a.click();
      URL.revokeObjectURL(a.href);
    } catch(e){ $('#e').textContent = e.message; }
  };
  $('#imp').onclick = async () => {
    try {
      const f = $('#file').files[0];
      if (!f) throw new Error('choose a file');
      const buf = new Uint8Array(await f.arrayBuffer());
      let bin = ''; buf.forEach(b => bin += String.fromCharCode(b));
      const b64 = btoa(bin);
      await api('/api/import',{method:'POST',body:JSON.stringify(
        {transfer_password:$('#ipw').value, bundle:b64})});
      renderVault();
    } catch(e){ $('#e').textContent = e.message; }
  };
}
```

- [ ] **Step 7: Build the firmware**

Run: `idf.py build`
Expected: build succeeds.

- [ ] **Step 8: Flash and re-run first-run setup**

Run: `idf.py -p <PORT> erase-flash && idf.py -p <PORT> flash monitor`
(erase-flash clears the old single-password vault so setup runs fresh.)
Expected: boots to `esp32key ready`.

- [ ] **Step 9: Integration test — single device**

1. Join WiFi `esp32key`, browse `https://192.168.4.1`, accept cert.
2. Setup screen now asks for **master** and **transfer** passwords → create both.
3. Add an entry. Open **Transfer** → enter transfer password → **Download export
   file** → `esp32key-export.bin` downloads.
4. Wrong transfer password on export → "wrong transfer password".

Expected: all succeed.

- [ ] **Step 10: Integration test — device to device**

1. On a **second** ESP32-S3 flashed with the same firmware, run setup using the
   **same transfer password** (master may differ).
2. Open **Transfer** → Import → enter the transfer password → choose the
   `esp32key-export.bin` from device 1 → **Import file**.
3. The imported entry appears in device 2's vault; reveal shows the correct secret.
4. Importing with a wrong transfer password → "import failed".

Expected: credentials transferred; wrong password rejected.

- [ ] **Step 11: Commit**

```bash
git add components/vault_api
git commit -m "feat: dual-password setup, export/import API, and Transfer UI"
```

---

## Self-Review Notes (author checklist — already applied)

- **Spec coverage:** §2 connectivity → Tasks 8/9/11; §3 crypto + dual-password setup → Tasks 1–3,5,12,13; §3 password change w/ current-pw → Task 5 + `/api/change-password` Task 10; §4 NVS → Task 4; §5 UI/API → Tasks 10,14; §6 hardening (sessions, lockout, idle, per-entry reveal) → Tasks 6,10; §7 modules → one component each (transfer responsibilities fold into `vault_crypto`/`vault`); §8 import/export → Tasks 12 (bundle crypto), 13 (vault export/import + merge), 14 (API/UI + device-to-device test); §9 testing → Unity tasks + Tasks 11/14 integration; PSRAM → Task 0.
- **Type consistency:** `vc_*`, `vs_*`, `vault_*`, `vsess_*` prefixes are stable across tasks; wrapped-DEK layout (`nonce|ct|tag`) is identical in `vc_dek_*` (Task 3) and `vault_change_password` (Task 5); bundle layout (`magic|ver|salt|iter|nonce|tag|ct`) is shared between `vc_bundle_pack`/`vc_bundle_unpack` (Task 12) and consumed by `vault_export`/`vault_import` (Task 13); record layout (`id|title|user|secret`, `REC_SIZE`) is identical in `persist_entries`, `load_entries`, `serialize_entries`, and `vault_import`; session token sizing (`VS_TOKEN_HEX`) consistent between Tasks 6, 10, 14.
- **Additivity:** Tasks 12–14 do not change `vault_setup`'s signature or existing CRUD; the transfer password is set via the separate `vault_set_transfer_password` called from the setup API handler, so Tasks 0–11 stay green.
- **Known integration risk:** `net_usb` (Task 9) depends on the resolved `esp_tinyusb` API; Step 3's note explains how to reconcile callback signatures if they differ in the pinned version.
```
