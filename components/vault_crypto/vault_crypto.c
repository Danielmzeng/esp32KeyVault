#include "vault_crypto.h"
#include "psa/crypto.h"
#include <string.h>

esp_err_t vc_init(void)
{
    return (psa_crypto_init() == PSA_SUCCESS) ? ESP_OK : ESP_FAIL;
}

esp_err_t vc_derive_key(const char *password, size_t password_len,
                        const uint8_t salt[VC_SALT_LEN], uint32_t iterations,
                        uint8_t out_key[VC_KEY_LEN])
{
    if (!password || !salt || !out_key) return ESP_ERR_INVALID_ARG;

    psa_status_t status;
    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = 0;
    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;

    /* Import the password as a PSA PASSWORD key */
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attrs, PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256));
    psa_set_key_type(&attrs, PSA_KEY_TYPE_PASSWORD);
    psa_set_key_bits(&attrs, PSA_BYTES_TO_BITS(password_len));

    status = psa_import_key(&attrs, (const uint8_t *)password, password_len, &key_id);
    if (status != PSA_SUCCESS) return ESP_FAIL;

    /* Set up PBKDF2-HMAC-SHA256 derivation */
    status = psa_key_derivation_setup(&op, PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256));
    if (status != PSA_SUCCESS) goto cleanup_key;

    status = psa_key_derivation_input_integer(&op, PSA_KEY_DERIVATION_INPUT_COST,
                                              iterations);
    if (status != PSA_SUCCESS) goto cleanup_op;

    status = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT,
                                            salt, VC_SALT_LEN);
    if (status != PSA_SUCCESS) goto cleanup_op;

    status = psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_PASSWORD,
                                          key_id);
    if (status != PSA_SUCCESS) goto cleanup_op;

    status = psa_key_derivation_output_bytes(&op, out_key, VC_KEY_LEN);

cleanup_op:
    psa_key_derivation_abort(&op);
cleanup_key:
    psa_destroy_key(key_id);

    return (status == PSA_SUCCESS) ? ESP_OK : ESP_FAIL;
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
