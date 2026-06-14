#include "vault_crypto.h"
#include "psa/crypto.h"
#include "sha/sha_core.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>

esp_err_t vc_init(void)
{
    return (psa_crypto_init() == PSA_SUCCESS) ? ESP_OK : ESP_FAIL;
}

/* HMAC-SHA256 hash block size. */
#define HMAC_BLK 64

/* PBKDF2-HMAC-SHA256 built directly on the ESP hardware SHA engine (esp_sha).
 *
 * Both the PSA key-derivation path and the mbedtls_md path route every hash
 * setup through the PSA SHA driver, which heap-allocates a DMA context per op;
 * doing that ~200k times for 100k iterations takes ~20s and trips the task
 * watchdog. esp_sha() drives the accelerator directly (no PSA, no per-op
 * malloc), so 100k iterations complete in well under a second.
 *
 * VC_KEY_LEN (32) equals the SHA-256 output, so the derived key is PBKDF2 block 1:
 *   U1 = HMAC(pw, salt || INT32BE(1)); Ui = HMAC(pw, U(i-1)); key = U1 ^ ... ^ Uc.
 * HMAC(pw, m) = SHA256(k_opad || SHA256(k_ipad || m)), pads precomputed once. */
esp_err_t vc_derive_key(const char *password, size_t password_len,
                        const uint8_t salt[VC_SALT_LEN], uint32_t iterations,
                        uint8_t out_key[VC_KEY_LEN])
{
    if (!password || !salt || !out_key) return ESP_ERR_INVALID_ARG;
    _Static_assert(VC_KEY_LEN == 32, "single-block PBKDF2 assumes 32-byte key");

    /* inner message is salt||idx (VC_SALT_LEN+4) for U1, or a 32-byte U thereafter;
     * size the buffer for whichever is larger. */
#define VC_INNER_MSG_MAX ((VC_SALT_LEN + 4) > 32 ? (VC_SALT_LEN + 4) : 32)
    uint8_t kb[HMAC_BLK] = {0}, k_ipad[HMAC_BLK], k_opad[HMAC_BLK];
    uint8_t inner_in[HMAC_BLK + VC_INNER_MSG_MAX];  /* k_ipad || (salt||idx) or (U) */
    uint8_t outer_in[HMAC_BLK + 32];                /* k_opad || inner-digest */
    uint8_t u[32], t[32];

    /* Key block: K zero-padded to 64B, or SHA256(K) if longer than the block. */
    if (password_len > HMAC_BLK) {
        esp_sha(SHA2_256, (const unsigned char *)password, password_len, kb);
    } else {
        memcpy(kb, password, password_len);
    }
    for (int i = 0; i < HMAC_BLK; i++) { k_ipad[i] = kb[i] ^ 0x36; k_opad[i] = kb[i] ^ 0x5c; }
    memcpy(outer_in, k_opad, HMAC_BLK);

    /* U1 = HMAC(pw, salt || INT32BE(1)) */
    memcpy(inner_in, k_ipad, HMAC_BLK);
    memcpy(inner_in + HMAC_BLK, salt, VC_SALT_LEN);
    inner_in[HMAC_BLK + VC_SALT_LEN + 0] = 0;
    inner_in[HMAC_BLK + VC_SALT_LEN + 1] = 0;
    inner_in[HMAC_BLK + VC_SALT_LEN + 2] = 0;
    inner_in[HMAC_BLK + VC_SALT_LEN + 3] = 1;
    esp_sha(SHA2_256, inner_in, HMAC_BLK + VC_SALT_LEN + 4, outer_in + HMAC_BLK);
    esp_sha(SHA2_256, outer_in, HMAC_BLK + 32, u);
    memcpy(t, u, sizeof t);

    /* Ui = HMAC(pw, U(i-1)); T ^= Ui.
     * Every SHA op on this chip funnels through the PSA driver's per-op hardware
     * acquire/clock-enable, so a 100k-iteration derivation runs many seconds and
     * would starve the idle task. Yield briefly every 1024 iterations so the idle
     * task runs and the task watchdog stays satisfied, whatever the iteration count. */
    for (uint32_t i = 1; i < iterations; i++) {
        memcpy(inner_in + HMAC_BLK, u, 32);
        esp_sha(SHA2_256, inner_in, HMAC_BLK + 32, outer_in + HMAC_BLK);
        esp_sha(SHA2_256, outer_in, HMAC_BLK + 32, u);
        for (size_t k = 0; k < sizeof t; k++) t[k] ^= u[k];
        if ((i & 0x3FF) == 0) vTaskDelay(1);
    }

    memcpy(out_key, t, VC_KEY_LEN);

    memset(kb, 0, sizeof kb);
    memset(k_ipad, 0, sizeof k_ipad);
    memset(k_opad, 0, sizeof k_opad);
    memset(inner_in, 0, sizeof inner_in);
    memset(outer_in, 0, sizeof outer_in);
    memset(u, 0, sizeof u);
    memset(t, 0, sizeof t);
    return ESP_OK;
}

#include "esp_random.h"

void vc_random(uint8_t *buf, size_t len) { esp_fill_random(buf, len); }

/* Helper: import a raw AES-256 key for AEAD and return its key_id.
 * Caller must call psa_destroy_key() when done. */
static psa_status_t import_aes_key(const uint8_t key[VC_KEY_LEN],
                                   psa_key_usage_t usage,
                                   psa_key_id_t *out_id)
{
    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, VC_KEY_LEN * 8);
    psa_set_key_algorithm(&attrs, PSA_ALG_GCM);
    psa_set_key_usage_flags(&attrs, usage);
    return psa_import_key(&attrs, key, VC_KEY_LEN, out_id);
}

esp_err_t vc_gcm_encrypt(const uint8_t key[VC_KEY_LEN],
                         const uint8_t nonce[VC_NONCE_LEN],
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *pt, size_t pt_len,
                         uint8_t *ct, uint8_t tag[VC_TAG_LEN])
{
    psa_key_id_t key_id = 0;
    if (import_aes_key(key, PSA_KEY_USAGE_ENCRYPT, &key_id) != PSA_SUCCESS) return ESP_FAIL;

    psa_aead_operation_t op = PSA_AEAD_OPERATION_INIT;
    psa_status_t status;
    size_t ct_written = 0, finish_written = 0, tag_len = 0;

    if ((status = psa_aead_encrypt_setup(&op, key_id, PSA_ALG_GCM)) != PSA_SUCCESS) goto done;
    if ((status = psa_aead_set_lengths(&op, aad_len, pt_len)) != PSA_SUCCESS) goto done;
    if ((status = psa_aead_set_nonce(&op, nonce, VC_NONCE_LEN)) != PSA_SUCCESS) goto done;
    if (aad_len && (status = psa_aead_update_ad(&op, aad, aad_len)) != PSA_SUCCESS) goto done;
    if ((status = psa_aead_update(&op, pt, pt_len, ct, pt_len, &ct_written)) != PSA_SUCCESS) goto done;
    status = psa_aead_finish(&op, ct + ct_written, pt_len - ct_written, &finish_written,
                             tag, VC_TAG_LEN, &tag_len);
done:
    if (status != PSA_SUCCESS) psa_aead_abort(&op);
    psa_destroy_key(key_id);
    return (status == PSA_SUCCESS) ? ESP_OK : ESP_FAIL;
}

esp_err_t vc_gcm_decrypt(const uint8_t key[VC_KEY_LEN],
                         const uint8_t nonce[VC_NONCE_LEN],
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *ct, size_t ct_len,
                         const uint8_t tag[VC_TAG_LEN],
                         uint8_t *pt)
{
    psa_key_id_t key_id = 0;
    if (import_aes_key(key, PSA_KEY_USAGE_DECRYPT, &key_id) != PSA_SUCCESS) return ESP_FAIL;

    psa_aead_operation_t op = PSA_AEAD_OPERATION_INIT;
    psa_status_t status;
    size_t pt_written = 0, verify_written = 0;

    if ((status = psa_aead_decrypt_setup(&op, key_id, PSA_ALG_GCM)) != PSA_SUCCESS) goto done;
    if ((status = psa_aead_set_lengths(&op, aad_len, ct_len)) != PSA_SUCCESS) goto done;
    if ((status = psa_aead_set_nonce(&op, nonce, VC_NONCE_LEN)) != PSA_SUCCESS) goto done;
    if (aad_len && (status = psa_aead_update_ad(&op, aad, aad_len)) != PSA_SUCCESS) goto done;
    if ((status = psa_aead_update(&op, ct, ct_len, pt, ct_len, &pt_written)) != PSA_SUCCESS) goto done;
    status = psa_aead_verify(&op, pt + pt_written, ct_len - pt_written, &verify_written,
                             tag, VC_TAG_LEN);
done:
    if (status != PSA_SUCCESS) psa_aead_abort(&op);
    psa_destroy_key(key_id);
    return (status == PSA_SUCCESS) ? ESP_OK : ESP_FAIL;
}

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
