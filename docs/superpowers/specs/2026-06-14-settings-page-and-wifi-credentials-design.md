# Settings Page + WiFi AP Credential Change — Design

**Date:** 2026-06-14
**Status:** Approved
**Branch:** task/Vault-Adjust_webui

## Problem

The web UI sidebar mixes everyday actions (Transfer, Lock) with occasional
configuration and destructive actions (Clear Entries, Reset Device, the
Auto-lock timeout). There is no way to change the WiFi AP credentials: the SSID
is hardcoded `"esp32key"` and the password comes from a compile-time
`AP_PASSWORD` in `main.cpp`, with no persistence or runtime change path.

## Goals

- Add a **Settings** page reached from the sidebar.
- Move the Auto-lock control, Clear Entries, and Reset Device off the sidebar
  into Settings.
- Let an authenticated user change the WiFi AP **SSID and password**, persisted
  across reboots.

## Non-Goals

- Changing WiFi channel, max connections, or auth mode (always WPA2).
- A separate "WiFi station" / client mode.
- Encrypting NVS (flash encryption is deferred to v2).

## Decisions

- **Apply model:** changing AP credentials **persists to NVS, returns 200, then
  reboots the device** (`esp_restart`) after a short delay so the AP comes up on
  the new credentials. (Applying live would drop the user's own WiFi connection
  before the response is sent.)
- **AP password policy:** WPA2, **8–63 characters** (reject otherwise). No open
  network.
- **SSID policy:** **1–32 characters**, non-empty (the 802.11 SSID limit).
- **Ownership (Approach A):** `WifiAp` owns AP-credential storage (it reads them
  at boot and exposes a setter + an `ssid()` getter). `ApiServer` validates
  input, calls the setter, and triggers the reboot. The NVS keys live in exactly
  one component.
- **Settings layout (hub):** the WiFi form and the Auto-lock control are inline
  on the Settings page; Clear Entries and Reset Device remain their existing
  multi-step confirmation pages, reached via buttons (Back returns to Settings).
- **Sidebar after:** Transfer Entries, Lock, Settings (the logo stays a Lock
  shortcut).

## Architecture

### 1. `net_wifi_ap` — persistence + runtime ownership

`include/net_wifi_ap.h`:
- Constructor `WifiAp(Store& store)` (was default-constructed).
- `void start(const char* default_ssid, const char* default_password)` — was
  `start(const char* password)`.
- `void set_credentials(const char* ssid, const char* password)` — persist both
  to NVS + commit; throws `vault::Error` on NVS fault. No live apply.
- `const char* ssid() const` — the active SSID (for prefill).

`net_wifi_ap.cpp`:
- NVS keys (file-local constants, ≤15 chars): `"ap_ssid"`, `"ap_pw"`.
- `start()`: read `ap_ssid`/`ap_pw` blobs into fixed buffers (NUL-terminated);
  if a key is absent, copy the passed default. Cache the active SSID in a member
  buffer. Bring up the AP exactly as today (WPA2; keep the existing
  `< 8 chars → WIFI_AUTH_OPEN` safety net, though the API now enforces ≥8).
- `set_credentials()`: `store_.set_blob("ap_ssid", ssid, strlen(ssid)+1)`,
  `store_.set_blob("ap_pw", password, strlen(password)+1)`, `store_.commit()`.
- Member buffers: `char ssid_[33]`, `Store& store_`.

`CMakeLists.txt`: add `vault_store` (and `vault_error`) to `REQUIRES`.

### 2. `vault_api`

`include/vault_api.h`:
- `#include "net_wifi_ap.h"`.
- Constructor `ApiServer(Vault&, Session&, StatusLed&, Store&, WifiAp& wifi)`;
  new member `WifiAp& wifi_;`.
- New handlers + trampolines: `h_wifi_get_impl`/`h_wifi_get`,
  `h_wifi_set_impl`/`h_wifi_set`.

`vault_api.cpp`:
- File-local one-shot reboot helper: a static `esp_timer` callback
  `reboot_cb` that calls `esp_restart()`.
- `GET /api/wifi` (`h_wifi_get_impl`, authed → 401): returns
  `{"ssid": wifi_.ssid()}`. Password is never returned.
- `POST /api/wifi` (`h_wifi_set_impl`, authed → 401): read body, parse JSON
  `ssid`/`password`; validate `strlen(ssid)` in 1..32 and `strlen(password)` in
  8..63 (else 400 with a specific message); `wifi_.set_credentials(ssid, pw)`
  (throws on NVS fault → 500); arm a one-shot `esp_timer` (~1.5 s) →
  `esp_restart`; return `200 {}`.
- Register both routes in `routes[]` and both trampolines via `API_HANDLER`.
  Route count becomes 21 — bump `cfg.httpd.max_uri_handlers` from 20 to 24.

`CMakeLists.txt`: add `net_wifi_ap` to `REQUIRES` (the header now uses `WifiAp&`).

### 3. `main.cpp`

```cpp
static vault::WifiAp wifi(store); wifi.start("esp32key", AP_PASSWORD);
...
static vault::ApiServer api(vault, session, led, store, wifi);
```
`AP_PASSWORD` stays as the factory-default password.

### 4. UI — `components/vault_api/www/index.html`

- **Sidebar (`paint()`):** keep Transfer Entries + Lock; remove the Clear/Reset
  row and the Auto-lock block; add a **Settings** button (`#settings`) wired to
  `renderSettings`. The logo (`#logolock`) stays a Lock shortcut.
- **New `renderSettings()`** (full-page render, like `renderClear`/`renderReset`):
  - **WiFi AP** section: `#apssid` text input (prefilled from `GET /api/wifi`,
    `maxlength=32`), `#appw` password input (blank, `placeholder="New AP
    password (8-63 chars)"`), `#apsave` button, `#apmsg` status line. On Save:
    client-validate (ssid 1–32, pw 8–63), `POST /api/wifi {ssid,password}`; on
    success show "Saved — device is restarting. Reconnect to *<ssid>* and unlock
    again." (no further client action; the device reboots).
  - **Auto-lock** section: the existing seconds control moved here verbatim
    (`#idlesec`/`#idlesave`/`#idlemsg`, populate from `idleMs/1000`,
    `POST /api/idle`, update `idleMs` + `armIdle()`).
  - **Buttons:** Clear Entries → `renderClear`; Reset Device → `renderReset`.
  - **Back** → `renderVault`.
- **`renderClear` / `renderReset`:** change their **Back** handler from
  `renderVault` to `renderSettings`. `renderClear`'s success path still calls
  `renderVault()` (after clearing, return to the vault).

## Data Flow

```
Save WiFi
  → POST /api/wifi {ssid,password}
      → authed? (401)
      → validate ssid 1..32, pw 8..63 (400)
      → wifi_.set_credentials → NVS set_blob x2 + commit
      → arm one-shot timer (1.5s) → esp_restart
      → 200
  → UI: "restarting, reconnect to <ssid>"
  → device reboots → WifiAp::start reads ap_ssid/ap_pw → AP up on new creds

Open Settings
  → GET /api/wifi → {ssid} → prefill #apssid
```

## Error Handling

- Not authed → 401 on both `/api/wifi` routes.
- ssid/password out of range → 400 with a specific message
  (`"ssid must be 1-32 chars"` / `"password must be 8-63 chars"`).
- Bad/missing body or JSON → 400 (matches existing handlers).
- NVS write fault → 500 via the handler trampoline; the reboot is armed only
  **after** `set_credentials` succeeds, so a failed save never reboots.
- Reboot wipes the DEK and session (vault returns to locked); the success
  message tells the user they must reconnect and unlock.
- Absent `ap_ssid`/`ap_pw` at boot → factory defaults.

## Security Notes

- The AP password is stored **plaintext** in NVS. This is unavoidable (WiFi
  needs the literal PSK to configure the radio) and consistent with the
  project's deferred flash-encryption limitation. It is distinct from the
  master/transfer passwords, which are never stored plaintext.
- The API is TLS + session-auth gated. The SSID is publicly broadcast by the AP,
  so returning it from `GET /api/wifi` is not a disclosure.

## Testing

- `net_wifi_ap` and `vault_api` touch the WiFi radio / HTTP integration and are
  not unit-testable in the doctest host runner (consistent with the existing
  net components). Validation is kept inline in the handler.
- **Build verification:** both projects (main firmware + `test_app`) must build
  clean.
- **Manual / on-device:**
  1. Open Settings; SSID field shows the current SSID.
  2. Set a new SSID + valid password (≥8); Save → "restarting" message; device
     reboots and the new SSID appears; reconnect with the new password and
     unlock.
  3. Reboot again (power-cycle) → the changed SSID/password persist.
  4. Invalid input (short password, empty SSID) → client and server both reject
     (400), no reboot.
  5. Auto-lock control still works from Settings; Clear Entries / Reset Device
     reachable from Settings and their Back returns to Settings.

## Build Verification

- Main firmware (`idf.py build`).
- `test_app` doctest runner (component unit tests still build/pass; no new test
  component is added).
