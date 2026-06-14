#include "doctest/doctest.h"
#include "vault_crypto.h"
#include <cstring>

using namespace vault;

TEST_CASE("pbkdf2 is deterministic and salt-sensitive") {
    uint8_t salt1[VC_SALT_LEN] = {0};
    uint8_t salt2[VC_SALT_LEN] = {0};
    salt2[0] = 1;

    uint8_t k1[VC_KEY_LEN], k1b[VC_KEY_LEN], k2[VC_KEY_LEN];
    crypto::derive_key("hunter2", 7, salt1, 1000, k1);
    crypto::derive_key("hunter2", 7, salt1, 1000, k1b);
    crypto::derive_key("hunter2", 7, salt2, 1000, k2);

    CHECK(memcmp(k1, k1b, VC_KEY_LEN) == 0);
    CHECK(memcmp(k1, k2,  VC_KEY_LEN) != 0);
}

TEST_CASE("gcm round-trips and detects tampering") {
    uint8_t key[VC_KEY_LEN];   crypto::random(key, sizeof key);
    uint8_t nonce[VC_NONCE_LEN]; crypto::random(nonce, sizeof nonce);
    const char* msg = "s3cr3t-password";
    size_t n = strlen(msg);

    uint8_t ct[64], pt[64], tag[VC_TAG_LEN];
    crypto::gcm_encrypt(key, nonce, nullptr, 0, (const uint8_t*)msg, n, ct, tag);
    CHECK(crypto::gcm_decrypt(key, nonce, nullptr, 0, ct, n, tag, pt));
    CHECK(memcmp(msg, pt, n) == 0);

    tag[0] ^= 0xFF;
    CHECK_FALSE(crypto::gcm_decrypt(key, nonce, nullptr, 0, ct, n, tag, pt));
}

TEST_CASE("dek wrap/unwrap round-trips; wrong kek fails") {
    uint8_t kek[VC_KEY_LEN]; crypto::random(kek, sizeof kek);
    uint8_t bad[VC_KEY_LEN]; crypto::random(bad, sizeof bad);

    uint8_t dek[VC_KEY_LEN], wrapped[VC_WRAPPED_DEK_LEN], out[VC_KEY_LEN];
    crypto::dek_create(kek, dek, wrapped);
    CHECK(crypto::dek_unwrap(kek, wrapped, out));
    CHECK(memcmp(dek, out, VC_KEY_LEN) == 0);

    CHECK_FALSE(crypto::dek_unwrap(bad, wrapped, out));
}

TEST_CASE("bundle pack/unpack round-trips; wrong password fails") {
    const char* msg = "entry-records-blob";
    size_t mlen = strlen(msg);
    uint8_t bundle[VC_BUNDLE_HDR + 64];
    size_t blen = sizeof bundle;
    crypto::bundle_pack("transfer-pw", 11, (const uint8_t*)msg, mlen, bundle, &blen);
    CHECK(blen == VC_BUNDLE_HDR + mlen);

    uint8_t out[64]; size_t olen = sizeof out;
    CHECK(crypto::bundle_unpack("transfer-pw", 11, bundle, blen, out, &olen)
          == crypto::BundleResult::Ok);
    CHECK(olen == mlen);
    CHECK(memcmp(msg, out, mlen) == 0);

    olen = sizeof out;
    CHECK(crypto::bundle_unpack("wrong-pw", 8, bundle, blen, out, &olen)
          == crypto::BundleResult::WrongPassword);

    bundle[0] ^= 0xFF;
    olen = sizeof out;
    CHECK(crypto::bundle_unpack("transfer-pw", 11, bundle, blen, out, &olen)
          == crypto::BundleResult::BadMagic);
}
