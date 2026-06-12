# esp32key

A personal encrypted credential vault that runs on a bare ESP32-S3 dev board.
You reach it from a browser over HTTPS — on the device's own WiFi hotspot or
over the USB cable — unlock it with a master password, and manage your
credentials. A second "transfer password" lets you export an encrypted bundle
and move your credentials to another ESP32-S3.

Built with ESP-IDF v6.0.1.

## Features

- Encrypted credential vault: stored secrets are useless without the master
  password (app-level AES-256-GCM, key derived with PBKDF2).
- Browser-based web UI served over HTTPS, available on two interfaces at once:
  - WiFi softAP — `https://192.168.4.1`
  - USB network gadget (NCM) — `https://10.10.0.1` (use the vault while your
    PC's WiFi stays on the internet)
- Add / edit / delete credentials; secrets revealed per-entry on demand.
- Change the master password without re-encrypting every entry.
- Device-to-device export/import, protected by a separate transfer password.
- Session hardening: HttpOnly + Secure + SameSite cookie, idle auto-lock, and
  login rate-limiting / lockout.

## Security model

Two passwords are set during first-run setup:

- **Master password** — everyday unlock. PBKDF2-HMAC-SHA256 derives a
  Key-Encrypting-Key (KEK); a random 256-bit Data-Encryption-Key (DEK) is
  wrapped under the KEK and stored. Each credential is encrypted with the DEK
  (AES-256-GCM, unique nonce per entry). The DEK lives in RAM only while
  unlocked and is wiped on logout, idle timeout, or reboot. Neither password is
  ever stored in plaintext.
- **Transfer password** — gates and encrypts the export bundle. The bundle is
  self-contained (encrypted under a key derived from the transfer password) and
  not tied to any device's DEK, so it is portable. Set the same transfer
  password on two devices and export → import works directly between them.

Cryptography uses the PSA Crypto API (the classic mbedTLS primitives are private
in ESP-IDF v6). The TLS server uses a self-signed EC P-256 certificate generated
on first boot and stored on the device — your browser will show a one-time
"not secure" warning that you can accept (or trust the cert to silence it).

## Hardware

- An ESP32-S3 dev board with PSRAM and at least 4 MB flash.
- A USB cable (also used for the USB network interface).

PSRAM defaults to Octal mode (`CONFIG_SPIRAM_MODE_OCT`). If your module uses
Quad PSRAM, change that in `sdkconfig.defaults` and delete `sdkconfig` to
regenerate.

## Build and flash

ESP-IDF v6.0.1 must be installed. Activate the environment, set the target, and
build:

```sh
. $IDF_PATH/export.sh          # Linux/macOS
idf.py set-target esp32s3
idf.py -p <PORT> flash monitor
```

On Windows, `idf.py` can exit silently from PowerShell if `MSYSTEM` is set (e.g.
in a Git Bash environment). Use cmd with the batch export script:

```bat
set "MSYSTEM=" && call C:\esp\v6.0.1\esp-idf\export.bat && idf.py -p <PORT> flash monitor
```

The first build compiles all of ESP-IDF and can take 10-20 minutes.

## Usage

1. Power on the board. Join the WiFi network `esp32key` (default password
   `esp32key-changeme`), or plug in USB.
2. Browse to `https://192.168.4.1` (WiFi) or `https://10.10.0.1` (USB) and
   accept the certificate warning.
3. First run: the Setup screen asks for a master password and a transfer
   password. Create both.
4. Unlock with the master password to view, add, edit, delete, and reveal
   credentials.
5. Transfer screen: enter the transfer password to download an encrypted export
   file, or to import a file exported from another device.

## Project layout

```
components/
  vault_crypto/   PBKDF2, AES-256-GCM, DEK wrap/unwrap, portable bundle (PSA)
  vault_store/    NVS persistence
  vault/          credential model: setup/unlock/lock/CRUD, change-pw, export/import
  vault_session/  session tokens, idle timeout, login lockout
  vault_cert/     self-signed TLS cert generation + persistence
  net_wifi_ap/    WiFi softAP bring-up
  net_usb/        TinyUSB NCM network interface + DHCP server
  vault_api/      HTTPS server, REST API, embedded web UI
main/             app_main wiring
test_app/         on-target Unity test runner
docs/superpowers/ design spec and implementation plan
```

## Testing

Unit tests run on the board via a dedicated test runner:

```sh
cd test_app
idf.py -p <PORT> flash monitor
```

At the Unity menu, run each suite: `[vault_crypto]`, `[vault_store]`,
`[vault]`, `[vault_session]`.

## Known limitations

- App-level encryption only; ESP32 hardware flash-encryption / secure boot is
  not enabled (a possible future hardening step).
- Decrypted secrets may linger in scratch RAM after lock until overwritten.
- No Settings screen yet: the change-master-password API exists but has no UI,
  and the WiFi AP password is currently hardcoded in `main/main.c`.

## License

Personal project; no license specified.
