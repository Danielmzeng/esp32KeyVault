# ESP32-S3 Credential Vault — Design

**Date:** 2026-06-11
**Target:** ESP32-S3 bare dev board, ESP-IDF v6.0.1
**Status:** Approved design — pending implementation plan

## 1. Overview

Firmware that turns a bare ESP32-S3 dev board into a personal encrypted
credential vault. The user reaches it through a browser over **HTTPS**,
available simultaneously on two network interfaces:

- the device's own **WiFi AP** hotspot, and
- a **USB network gadget** (so the vault is reachable over the USB cable while
  the PC's WiFi stays connected to the internet).

Both interfaces serve the same web app and JSON API. Credentials are encrypted
at rest with a key derived from a master password (app-level encryption); a
flash dump without the master password is useless.

Out of scope for v1: BLE, WiFi station mode, hardware flash-encryption/secure
boot (a build-time option that can be enabled later), physical confirm button.

**Hardware config:** PSRAM is enabled (Octal/Quad per board) via sdkconfig
(`CONFIG_SPIRAM=y`), giving headroom for the TLS server, USB net buffers, and
the in-RAM decrypted working set. The KDF still uses a high iteration count;
PSRAM is for buffers, not for holding secrets long-term.

## 2. Access & Connectivity

- **WiFi AP** — softAP with a WPA2 password, built-in esp-netif DHCP server,
  served at a fixed address (e.g. `https://192.168.4.1`).
- **USB network gadget** — TinyUSB network class (NCM/RNDIS) presenting a second
  network interface over USB, with its own small DHCP server. The HTTPS server
  binds to both interfaces.
- **HTTPS** — `esp_https_server` (mbedTLS) with a **self-signed certificate
  generated on first boot** and persisted on-device (unique per board). The
  browser shows a one-time trust warning; the user can install the cert as
  trusted to silence it.

Note on the single-WiFi-interface tradeoff: in AP mode a PC with only one WiFi
radio must leave its home network to talk to the device. Accepted as minor for
short vault sessions; the USB network interface eliminates the conflict when the
device is plugged in.

## 3. Security / Crypto Model (core)

App-level encryption with a two-key (KEK/DEK) design.

- **Setup (first run):** the user sets **two** passwords — a **master password**
  (everyday unlock) and a **transfer password** (gates and encrypts
  import/export, see §9). The device:
  1. generates a random salt,
  2. derives a Key-Encrypting-Key `KEK = KDF(master_password, salt)`
     (PBKDF2-HMAC-SHA256, high iteration count),
  3. generates a random 256-bit Data-Encryption-Key `DEK`,
  4. stores the **DEK wrapped (AES-256-GCM) under the KEK**, plus the salt and
     KDF parameters,
  5. stores a **transfer-password verifier**: a separate random salt plus a
     known-constant encrypted under `KDF(transfer_password, transfer_salt)`, so
     the transfer password can be checked without storing it.

  Neither password is ever stored in plaintext.

- **Unlock:** the entered password re-derives the KEK, which is used to unwrap
  the DEK. AES-GCM's authentication tag *is* the password check — if it
  verifies, the password is correct and the DEK is held in RAM for the session;
  if it fails, the password was wrong.

- **Entries:** each credential is encrypted individually with the DEK
  (AES-256-GCM, a unique nonce per entry).

- **Locking:** the DEK is wiped from RAM on logout, idle timeout, or reboot. The
  vault is inaccessible until re-unlocked.

- **Password change:** re-wrap the DEK under a new KEK — no need to re-encrypt
  every entry. **The current password must be re-entered** to authorize a change
  (prevents an unlocked session from being silently re-keyed).

KDF choice: **PBKDF2-HMAC-SHA256** (built into mbedTLS). Argon2 is stronger but
requires an extra component; deferred unless desired.

## 4. Storage

An **NVS** partition holds: salt, KDF parameters, the wrapped DEK, the
self-signed cert/key, and the encrypted credential entries. NVS provides wear
leveling and is simple for small structured data. LittleFS is a fallback if
entries ever grow large (not expected).

## 5. Web UI & API

A static single-page app embedded in firmware.

Screens:
- **Setup** (first run — set master password **and** transfer password)
- **Login** (enter master password)
- **Vault** (search, add, edit, delete, reveal/copy a password)
- **Transfer** (export a bundle / import a bundle — requires transfer password)
- **Settings** (change master password, WiFi AP SSID/password)

API (all HTTPS, session-cookie protected):
- `POST /api/setup` — first-run creation of master + transfer passwords
- `POST /api/login` → sets session cookie
- `POST /api/logout`
- `GET /api/entries` — returns titles/usernames only (no secrets)
- `GET /api/entries/{id}/secret` — reveals one secret on demand
- `POST /api/entries` — create
- `PUT /api/entries/{id}` — update
- `DELETE /api/entries/{id}` — delete
- `POST /api/change-password`
- `POST /api/export` — body `{transfer_password}`; returns the encrypted bundle
- `POST /api/import` — multipart/body `{transfer_password, bundle}`; merges entries

Secrets are revealed **per-entry on demand** rather than dumping the whole vault
to the page, limiting exposure.

## 6. Auth Hardening & Error Handling

- Session = random, HttpOnly + Secure cookie; **idle auto-lock** wipes the DEK
  after inactivity.
- **Login rate-limiting / lockout** with backoff after repeated failures.
- Wrong password → generic failure + failure-counter increment (no oracle).
- Flash, cert-generation, and USB-enumeration errors surface cleanly; WiFi still
  works if USB does not enumerate.

## 7. Module Breakdown

Each module has one clear purpose and a well-defined interface:

| Module        | Responsibility                                        | Notes |
|---------------|-------------------------------------------------------|-------|
| `crypto`      | KDF, AES-256-GCM, DEK wrap/unwrap, portable bundle pack/unpack | Pure, host-testable |
| `vault`       | Credential CRUD, lock/unlock, transfer-pw setup/verify, export/import merge | |
| `store`       | NVS persistence                                       | |
| `session`     | Session tokens, idle timeout, login rate-limiting     | |
| `https_server`| TLS server, request routing, static file serving      | esp_https_server |
| `api`         | Thin REST handlers calling `vault`/`session`          | |
| `net_wifi_ap` | softAP bring-up + DHCP                                 | |
| `net_usb`     | TinyUSB network gadget + DHCP                          | |
| `webui`       | Static SPA assets (HTML/CSS/JS)                        | Embedded in firmware |

## 8. Import / Export (device-to-device transfer)

Lets the user move credentials to another ESP32-S3 device. Gated by the
**transfer password** (independent of the master password).

- **Bundle format** — a self-contained, portable blob, *not* tied to any
  device's DEK:
  `[magic(4)][version(1)][kdf_salt(16)][iterations(4)][nonce(12)][tag(16)][ciphertext]`.
  The ciphertext is the serialized entry list, AES-256-GCM-encrypted under
  `KDF(transfer_password, kdf_salt)`.

- **Export** — requires an unlocked vault and re-entry of the transfer password
  (verified against the stored verifier). The device serializes all entries,
  encrypts them under a freshly derived transfer key, and returns the bundle as
  a browser file download (`esp32key-export.bin`).

- **Import** — requires an unlocked vault and the transfer password that the
  bundle was encrypted with. The device derives the key from the entered
  password + the bundle's embedded salt, GCM-verifies/decrypts (wrong password
  or tampering fails cleanly), then **merges** entries into the local vault: an
  imported entry replaces a local one with the same `title`+`username`; all
  others are added. Merged entries are re-encrypted under the local DEK.

- **Workflow** — setting the **same transfer password on both devices** makes
  export→import seamless. A device's own stored transfer password controls
  access to the Transfer screen; the bundle itself only ever requires the
  password it was encrypted with.

## 9. Testing

- **Host-side unit tests** for `crypto`: KDF vectors, DEK wrap/unwrap round-trip,
  AES-GCM round-trip, tamper/auth-failure detection.
- **Unit tests** for the portable transfer bundle: export→import round-trip,
  wrong-transfer-password rejection, merge/replace-by-title+username semantics.
- **API tests** via `curl`/Python against the running device.
- **Manual CRUD + transfer** exercised over both WiFi AP and USB interfaces,
  including a real device-to-device export/import.
