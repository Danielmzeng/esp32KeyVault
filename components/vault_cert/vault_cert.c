#include "vault_cert.h"
#include "vault_store.h"

#include "psa/crypto.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509_crt.h"

#include <stdlib.h>
#include <string.h>

/*
 * ESP-IDF v6.0.1 ships mbedTLS 4.x (tf-psa-crypto restructure). The classic
 * mbedtls_rsa_gen_key / mbedtls_pk_setup(MBEDTLS_PK_RSA) / x509write.h path from
 * older mbedTLS is no longer part of the PUBLIC API:
 *   - mbedtls/rsa.h, mbedtls/ecp.h, mbedtls/entropy.h, mbedtls/ctr_drbg.h are all
 *     in .../private/ and are NOT on the public include path.
 *   - mbedtls/x509write.h does not exist; the mbedtls_x509write_crt_* API lives in
 *     mbedtls/x509_crt.h.
 *   - mbedtls_x509write_crt_pem() takes (ctx, buf, size) only -- no RNG callback
 *     (signing uses the PSA RNG internally).
 *   - mbedtls_x509write_crt_set_serial() is gone; use _set_serial_raw().
 *
 * The supported PUBLIC path for runtime key generation is PSA:
 *   psa_generate_key() (EC P-256 key pair, exportable) ->
 *   mbedtls_pk_copy_from_psa() to wrap it in an mbedtls_pk_context ->
 *   mbedtls_pk_write_key_pem() for the private key PEM ->
 *   mbedtls_x509write_crt_* + mbedtls_x509write_crt_pem() for the self-signed cert.
 *
 * Build requirement: CONFIG_MBEDTLS_X509_CREATE_C=y (defaults to n in IDF v6),
 * which pulls in MBEDTLS_X509_CRT_WRITE_C. PK_WRITE_C / PEM_WRITE_C default y.
 */

#define CERT_KEY "cert_pem"
#define PKEY_KEY "key_pem"
#define DN       "CN=esp32key.local,O=esp32key"

/* not_before / not_after in UTC "YYYYMMDDhhmmss" format. */
#define NOT_BEFORE "20240101000000"
#define NOT_AFTER  "20440101000000"

static esp_err_t generate(char **cert_pem, size_t *cert_len,
                          char **key_pem, size_t *key_len)
{
    mbedtls_pk_context key;
    mbedtls_x509write_cert crt;
    psa_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    esp_err_t result = ESP_FAIL;
    /* P-256 PEM private key ~250B, self-signed cert PEM well under 1K. */
    unsigned char keybuf[1024] = {0};
    unsigned char crtbuf[1024] = {0};
    const unsigned char serial[] = {0x01};

    mbedtls_pk_init(&key);
    mbedtls_x509write_crt_init(&crt);

    if (psa_crypto_init() != PSA_SUCCESS) {
        goto done;
    }

    /* Generate an exportable EC P-256 (secp256r1) key pair usable for ECDSA.
     * Exportable is required by mbedtls_pk_copy_from_psa(). */
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr,
            PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    if (psa_generate_key(&attr, &key_id) != PSA_SUCCESS) {
        goto done;
    }

    /* Wrap the PSA key into an mbedTLS pk context (independent copy). */
    if (mbedtls_pk_copy_from_psa(key_id, &key) != 0) {
        goto done;
    }

    /* Private key PEM. */
    if (mbedtls_pk_write_key_pem(&key, keybuf, sizeof keybuf) != 0) {
        goto done;
    }

    /* Build the self-signed certificate. */
    mbedtls_x509write_crt_set_subject_key(&crt, &key);
    mbedtls_x509write_crt_set_issuer_key(&crt, &key);   /* self-signed */
    if (mbedtls_x509write_crt_set_subject_name(&crt, DN) != 0) goto done;
    if (mbedtls_x509write_crt_set_issuer_name(&crt, DN) != 0) goto done;
    mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);
    if (mbedtls_x509write_crt_set_serial_raw(&crt,
            (unsigned char *)serial, sizeof serial) != 0) goto done;
    if (mbedtls_x509write_crt_set_validity(&crt, NOT_BEFORE, NOT_AFTER) != 0) goto done;
    if (mbedtls_x509write_crt_set_basic_constraints(&crt, 1, -1) != 0) goto done;
    if (mbedtls_x509write_crt_set_subject_key_identifier(&crt) != 0) goto done;
    if (mbedtls_x509write_crt_set_authority_key_identifier(&crt) != 0) goto done;

    /* PEM-encode the cert. No RNG argument in mbedTLS 4.x. */
    if (mbedtls_x509write_crt_pem(&crt, crtbuf, sizeof crtbuf) != 0) {
        goto done;
    }

    *key_len  = strlen((char *)keybuf) + 1;
    *cert_len = strlen((char *)crtbuf) + 1;
    *key_pem  = malloc(*key_len);
    *cert_pem = malloc(*cert_len);
    if (!*key_pem || !*cert_pem) {
        free(*key_pem);  *key_pem = NULL;
        free(*cert_pem); *cert_pem = NULL;
        result = ESP_ERR_NO_MEM;
        goto done;
    }
    memcpy(*key_pem, keybuf, *key_len);
    memcpy(*cert_pem, crtbuf, *cert_len);

    if (vs_set_blob(PKEY_KEY, *key_pem, *key_len) == ESP_OK &&
        vs_set_blob(CERT_KEY, *cert_pem, *cert_len) == ESP_OK &&
        vs_commit() == ESP_OK) {
        result = ESP_OK;
    } else {
        free(*key_pem);  *key_pem = NULL;
        free(*cert_pem); *cert_pem = NULL;
    }

done:
    if (!mbedtls_svc_key_id_is_null(key_id)) {
        psa_destroy_key(key_id);
    }
    mbedtls_x509write_crt_free(&crt);
    mbedtls_pk_free(&key);
    return result;
}

esp_err_t vault_cert_get(char **cert_pem, size_t *cert_len,
                         char **key_pem, size_t *key_len)
{
    if (!cert_pem || !cert_len || !key_pem || !key_len) {
        return ESP_ERR_INVALID_ARG;
    }

    size_t clen = 0, klen = 0;
    if (vs_get_blob(CERT_KEY, NULL, &clen) == ESP_OK &&
        vs_get_blob(PKEY_KEY, NULL, &klen) == ESP_OK) {
        *cert_pem = malloc(clen);
        *key_pem  = malloc(klen);
        if (!*cert_pem || !*key_pem) {
            free(*cert_pem); *cert_pem = NULL;
            free(*key_pem);  *key_pem = NULL;
            return ESP_ERR_NO_MEM;
        }
        if (vs_get_blob(CERT_KEY, *cert_pem, &clen) == ESP_OK &&
            vs_get_blob(PKEY_KEY, *key_pem, &klen) == ESP_OK) {
            *cert_len = clen;
            *key_len  = klen;
            return ESP_OK;
        }
        free(*cert_pem); *cert_pem = NULL;
        free(*key_pem);  *key_pem = NULL;
        return ESP_FAIL;
    }
    return generate(cert_pem, cert_len, key_pem, key_len);
}
