#include "unity.h"
#include "vault_crypto.h"
#include <string.h>
#include <stddef.h>

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
