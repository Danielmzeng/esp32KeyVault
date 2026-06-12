#include "vault.h"
#include "vault_crypto.h"
#include "vault_store.h"
#include "nvs.h"
#include <string.h>
#include <stdlib.h>

#define ITERATIONS    100000u
#define REC_SIZE      (1 + 3 * VAULT_FIELD_MAX)
#define PLAIN_MAX     (VAULT_MAX_ENTRIES * REC_SIZE)
#define ENTRIES_HDR   (VC_NONCE_LEN + VC_TAG_LEN)

static bool s_unlocked;
static uint8_t s_dek[VC_KEY_LEN];

/* In-RAM working copy, valid only while unlocked. */
static vault_entry_t s_entries[VAULT_MAX_ENTRIES];
static size_t s_count;
static uint8_t s_next_id = 1;

bool vault_is_unlocked(void) { return s_unlocked; }

bool vault_is_initialized(void)
{
    uint8_t wdek[VC_WRAPPED_DEK_LEN]; size_t len = sizeof wdek;
    return vs_get_blob("wdek", wdek, &len) == ESP_OK;
}

static esp_err_t load_kek(const char *master, size_t mlen, uint8_t kek[VC_KEY_LEN])
{
    uint8_t salt[VC_SALT_LEN]; size_t slen = sizeof salt;
    if (vs_get_blob("salt", salt, &slen) != ESP_OK) return ESP_ERR_INVALID_STATE;
    return vc_derive_key(master, mlen, salt, ITERATIONS, kek);
}

/* Encrypt s_entries -> NVS "entries". */
static esp_err_t persist_entries(void)
{
    static uint8_t plain[PLAIN_MAX];
    size_t off = 0;
    for (size_t i = 0; i < s_count; i++) {
        plain[off++] = s_entries[i].id;
        memcpy(plain + off, s_entries[i].title,    VAULT_FIELD_MAX); off += VAULT_FIELD_MAX;
        memcpy(plain + off, s_entries[i].username,  VAULT_FIELD_MAX); off += VAULT_FIELD_MAX;
        memcpy(plain + off, s_entries[i].secret,    VAULT_FIELD_MAX); off += VAULT_FIELD_MAX;
    }
    static uint8_t blob[ENTRIES_HDR + PLAIN_MAX];
    uint8_t *nonce = blob, *tag = blob + VC_NONCE_LEN, *ct = blob + ENTRIES_HDR;
    vc_random(nonce, VC_NONCE_LEN);
    esp_err_t err = vc_gcm_encrypt(s_dek, nonce, NULL, 0, plain, off, ct, tag);
    if (err != ESP_OK) return err;
    err = vs_set_blob("entries", blob, ENTRIES_HDR + off);
    if (err == ESP_OK) err = vs_commit();
    return err;
}

/* Decrypt NVS "entries" -> s_entries. Missing blob = empty vault. */
static esp_err_t load_entries(void)
{
    static uint8_t blob[ENTRIES_HDR + PLAIN_MAX];
    size_t blen = sizeof blob;
    esp_err_t err = vs_get_blob("entries", blob, &blen);
    s_count = 0; s_next_id = 1;
    if (err == ESP_ERR_NVS_NOT_FOUND) return ESP_OK;
    if (err != ESP_OK) return err;

    static uint8_t plain[PLAIN_MAX];
    uint8_t *nonce = blob, *tag = blob + VC_NONCE_LEN, *ct = blob + ENTRIES_HDR;
    size_t ctlen = blen - ENTRIES_HDR;
    err = vc_gcm_decrypt(s_dek, nonce, NULL, 0, ct, ctlen, tag, plain);
    if (err != ESP_OK) return err;

    size_t off = 0;
    while (off + REC_SIZE <= ctlen && s_count < VAULT_MAX_ENTRIES) {
        vault_entry_t *e = &s_entries[s_count++];
        e->id = plain[off++];
        memcpy(e->title,    plain + off, VAULT_FIELD_MAX); off += VAULT_FIELD_MAX;
        memcpy(e->username, plain + off, VAULT_FIELD_MAX); off += VAULT_FIELD_MAX;
        memcpy(e->secret,   plain + off, VAULT_FIELD_MAX); off += VAULT_FIELD_MAX;
        if (e->id >= s_next_id) s_next_id = e->id + 1;
    }
    return ESP_OK;
}

esp_err_t vault_setup(const char *master, size_t mlen)
{
    if (vault_is_initialized()) return ESP_ERR_INVALID_STATE;
    uint8_t salt[VC_SALT_LEN]; vc_random(salt, sizeof salt);
    uint32_t iter = ITERATIONS;
    uint8_t kek[VC_KEY_LEN];
    if (vc_derive_key(master, mlen, salt, iter, kek) != ESP_OK) return ESP_FAIL;
    uint8_t wdek[VC_WRAPPED_DEK_LEN];
    if (vc_dek_create(kek, s_dek, wdek) != ESP_OK) return ESP_FAIL;

    esp_err_t err;
    if ((err = vs_set_blob("salt", salt, sizeof salt)) != ESP_OK) return err;
    if ((err = vs_set_blob("iter", &iter, sizeof iter)) != ESP_OK) return err;
    if ((err = vs_set_blob("wdek", wdek, sizeof wdek)) != ESP_OK) return err;
    if ((err = vs_commit()) != ESP_OK) return err;

    s_unlocked = true; s_count = 0; s_next_id = 1;
    return persist_entries();
}

esp_err_t vault_unlock(const char *master, size_t mlen)
{
    if (!vault_is_initialized()) return ESP_ERR_INVALID_STATE;
    uint8_t kek[VC_KEY_LEN];
    if (load_kek(master, mlen, kek) != ESP_OK) return ESP_FAIL;
    uint8_t wdek[VC_WRAPPED_DEK_LEN]; size_t wlen = sizeof wdek;
    if (vs_get_blob("wdek", wdek, &wlen) != ESP_OK) return ESP_FAIL;
    if (vc_dek_unwrap(kek, wdek, s_dek) != ESP_OK) return ESP_FAIL;  /* wrong pw */
    s_unlocked = true;
    esp_err_t err = load_entries();
    if (err != ESP_OK) { vault_lock(); }
    return err;
}

void vault_lock(void)
{
    s_unlocked = false;
    memset(s_dek, 0, sizeof s_dek);
    memset(s_entries, 0, sizeof s_entries);
    s_count = 0;
}

void vault_factory_reset(void)
{
    vault_lock();
    vs_erase_key("salt");
    vs_erase_key("iter");
    vs_erase_key("wdek");
    vs_erase_key("entries");
    vs_erase_key("tsalt");
    vs_erase_key("tverif");
    vs_commit();
}

esp_err_t vault_change_password(const char *cur, size_t clen,
                                const char *next, size_t nlen)
{
    uint8_t kek[VC_KEY_LEN], dek[VC_KEY_LEN];
    if (load_kek(cur, clen, kek) != ESP_OK) return ESP_FAIL;
    uint8_t wdek[VC_WRAPPED_DEK_LEN]; size_t wlen = sizeof wdek;
    if (vs_get_blob("wdek", wdek, &wlen) != ESP_OK) return ESP_FAIL;
    if (vc_dek_unwrap(kek, wdek, dek) != ESP_OK) return ESP_FAIL;  /* wrong current pw */

    uint8_t salt[VC_SALT_LEN]; vc_random(salt, sizeof salt);
    uint8_t nkek[VC_KEY_LEN], nwdek[VC_WRAPPED_DEK_LEN];
    if (vc_derive_key(next, nlen, salt, ITERATIONS, nkek) != ESP_OK) return ESP_FAIL;
    /* Re-wrap the SAME dek under the new kek. */
    uint8_t *nonce = nwdek, *ct = nwdek + VC_NONCE_LEN, *tag = nwdek + VC_NONCE_LEN + VC_KEY_LEN;
    vc_random(nonce, VC_NONCE_LEN);
    if (vc_gcm_encrypt(nkek, nonce, NULL, 0, dek, VC_KEY_LEN, ct, tag) != ESP_OK) return ESP_FAIL;

    esp_err_t err;
    if ((err = vs_set_blob("salt", salt, sizeof salt)) != ESP_OK) return err;
    if ((err = vs_set_blob("wdek", nwdek, sizeof nwdek)) != ESP_OK) return err;
    return vs_commit();
}

static vault_entry_t *find(uint8_t id)
{
    for (size_t i = 0; i < s_count; i++) if (s_entries[i].id == id) return &s_entries[i];
    return NULL;
}

static void set_field(char *dst, const char *src)
{
    memset(dst, 0, VAULT_FIELD_MAX);
    if (src) strncpy(dst, src, VAULT_FIELD_MAX - 1);
}

esp_err_t vault_list(vault_entry_t *out, size_t cap, size_t *count)
{
    if (!s_unlocked) return ESP_ERR_INVALID_STATE;
    size_t n = s_count < cap ? s_count : cap;
    for (size_t i = 0; i < n; i++) {
        out[i] = s_entries[i];
        memset(out[i].secret, 0, VAULT_FIELD_MAX);  /* never leak secret in list */
    }
    *count = n;
    return ESP_OK;
}

esp_err_t vault_reveal(uint8_t id, char secret_out[VAULT_FIELD_MAX])
{
    if (!s_unlocked) return ESP_ERR_INVALID_STATE;
    vault_entry_t *e = find(id);
    if (!e) return ESP_ERR_NOT_FOUND;
    memcpy(secret_out, e->secret, VAULT_FIELD_MAX);
    return ESP_OK;
}

esp_err_t vault_add(const char *title, const char *username, const char *secret, uint8_t *out_id)
{
    if (!s_unlocked) return ESP_ERR_INVALID_STATE;
    if (s_count >= VAULT_MAX_ENTRIES) return ESP_ERR_NO_MEM;
    vault_entry_t *e = &s_entries[s_count++];
    e->id = s_next_id++;
    set_field(e->title, title);
    set_field(e->username, username);
    set_field(e->secret, secret);
    if (out_id) *out_id = e->id;
    return persist_entries();
}

esp_err_t vault_update(uint8_t id, const char *title, const char *username, const char *secret)
{
    if (!s_unlocked) return ESP_ERR_INVALID_STATE;
    vault_entry_t *e = find(id);
    if (!e) return ESP_ERR_NOT_FOUND;
    set_field(e->title, title);
    set_field(e->username, username);
    set_field(e->secret, secret);
    return persist_entries();
}

esp_err_t vault_delete(uint8_t id)
{
    if (!s_unlocked) return ESP_ERR_INVALID_STATE;
    for (size_t i = 0; i < s_count; i++) {
        if (s_entries[i].id == id) {
            s_entries[i] = s_entries[--s_count];
            memset(&s_entries[s_count], 0, sizeof s_entries[s_count]);
            return persist_entries();
        }
    }
    return ESP_ERR_NOT_FOUND;
}

/* 16-byte known constant used as the transfer-password verifier plaintext. */
static const uint8_t XFER_CHECK[16] = "esp32key-xfer!!";  /* 15 chars + NUL */
#define TVERIF_LEN (VC_NONCE_LEN + 16 + VC_TAG_LEN)

esp_err_t vault_set_transfer_password(const char *pw, size_t len)
{
    uint8_t tsalt[VC_SALT_LEN]; vc_random(tsalt, sizeof tsalt);
    uint8_t tkey[VC_KEY_LEN];
    if (vc_derive_key(pw, len, tsalt, ITERATIONS, tkey) != ESP_OK) return ESP_FAIL;

    uint8_t verif[TVERIF_LEN];
    uint8_t *nonce = verif, *ct = verif + VC_NONCE_LEN, *tag = verif + VC_NONCE_LEN + 16;
    vc_random(nonce, VC_NONCE_LEN);
    if (vc_gcm_encrypt(tkey, nonce, NULL, 0, XFER_CHECK, 16, ct, tag) != ESP_OK) return ESP_FAIL;

    esp_err_t e;
    if ((e = vs_set_blob("tsalt", tsalt, sizeof tsalt)) != ESP_OK) return e;
    if ((e = vs_set_blob("tverif", verif, sizeof verif)) != ESP_OK) return e;
    return vs_commit();
}

bool vault_verify_transfer(const char *pw, size_t len)
{
    uint8_t tsalt[VC_SALT_LEN]; size_t sl = sizeof tsalt;
    if (vs_get_blob("tsalt", tsalt, &sl) != ESP_OK) return false;
    uint8_t tkey[VC_KEY_LEN];
    if (vc_derive_key(pw, len, tsalt, ITERATIONS, tkey) != ESP_OK) return false;
    uint8_t verif[TVERIF_LEN]; size_t vl = sizeof verif;
    if (vs_get_blob("tverif", verif, &vl) != ESP_OK) return false;
    uint8_t *nonce = verif, *ct = verif + VC_NONCE_LEN, *tag = verif + VC_NONCE_LEN + 16;
    uint8_t out[16];
    return vc_gcm_decrypt(tkey, nonce, NULL, 0, ct, 16, tag, out) == ESP_OK &&
           memcmp(out, XFER_CHECK, 16) == 0;
}

/* Serialize s_entries into plain[] (same record layout as persist_entries). */
static size_t serialize_entries(uint8_t *plain)
{
    size_t off = 0;
    for (size_t i = 0; i < s_count; i++) {
        plain[off++] = s_entries[i].id;
        memcpy(plain + off, s_entries[i].title,    VAULT_FIELD_MAX); off += VAULT_FIELD_MAX;
        memcpy(plain + off, s_entries[i].username,  VAULT_FIELD_MAX); off += VAULT_FIELD_MAX;
        memcpy(plain + off, s_entries[i].secret,    VAULT_FIELD_MAX); off += VAULT_FIELD_MAX;
    }
    return off;
}

esp_err_t vault_export(const char *transfer_pw, size_t len,
                       uint8_t **out_bundle, size_t *out_len)
{
    if (!s_unlocked) return ESP_ERR_INVALID_STATE;
    if (!vault_verify_transfer(transfer_pw, len)) return ESP_FAIL;

    static uint8_t plain[PLAIN_MAX];
    size_t plen = serialize_entries(plain);
    size_t cap = VC_BUNDLE_HDR + plen;
    uint8_t *buf = malloc(cap);
    if (!buf) return ESP_ERR_NO_MEM;
    size_t blen = cap;
    esp_err_t e = vc_bundle_pack(transfer_pw, len, plain, plen, buf, &blen);
    if (e != ESP_OK) { free(buf); return e; }
    *out_bundle = buf; *out_len = blen;
    return ESP_OK;
}

esp_err_t vault_import(const char *transfer_pw, size_t len,
                       const uint8_t *bundle, size_t bundle_len)
{
    if (!s_unlocked) return ESP_ERR_INVALID_STATE;
    static uint8_t plain[PLAIN_MAX];
    size_t plen = sizeof plain;
    esp_err_t e = vc_bundle_unpack(transfer_pw, len, bundle, bundle_len, plain, &plen);
    if (e != ESP_OK) return e;   /* wrong password / tamper / bad format */

    size_t off = 0;
    while (off + REC_SIZE <= plen) {
        const char *title = (const char *)(plain + off + 1);
        const char *user  = (const char *)(plain + off + 1 + VAULT_FIELD_MAX);
        const char *sec   = (const char *)(plain + off + 1 + 2 * VAULT_FIELD_MAX);
        off += REC_SIZE;

        vault_entry_t *match = NULL;
        for (size_t i = 0; i < s_count; i++) {
            if (strncmp(s_entries[i].title, title, VAULT_FIELD_MAX) == 0 &&
                strncmp(s_entries[i].username, user, VAULT_FIELD_MAX) == 0) {
                match = &s_entries[i]; break;
            }
        }
        if (match) {
            set_field(match->secret, sec);
        } else if (s_count < VAULT_MAX_ENTRIES) {
            vault_entry_t *en = &s_entries[s_count++];
            en->id = s_next_id++;
            set_field(en->title, title);
            set_field(en->username, user);
            set_field(en->secret, sec);
        }
    }
    return persist_entries();
}
