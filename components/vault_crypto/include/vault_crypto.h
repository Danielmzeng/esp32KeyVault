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
