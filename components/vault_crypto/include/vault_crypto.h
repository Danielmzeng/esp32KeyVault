#pragma once
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

/* Initialize the PSA crypto subsystem. Call once early in app_main before any
 * other vault_crypto use. Idempotent. */
esp_err_t vc_init(void);

#define VC_SALT_LEN   16
#define VC_KEY_LEN    32   /* AES-256 */
#define VC_NONCE_LEN  12   /* GCM */
#define VC_TAG_LEN    16   /* GCM */

/* Derive a 32-byte key from a password using PBKDF2-HMAC-SHA256. */
esp_err_t vc_derive_key(const char *password, size_t password_len,
                        const uint8_t salt[VC_SALT_LEN], uint32_t iterations,
                        uint8_t out_key[VC_KEY_LEN]);

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
