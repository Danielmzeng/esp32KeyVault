#include "vault.h"
#include "vault_crypto.h"
#include "vault_store.h"
#include "nvs.h"
#include "esp_heap_caps.h"
#include <string.h>
#include <stdlib.h>

#define ITERATIONS            100000u
#define VAULT_FORMAT_VERSION  2u      /* bump when the on-disk record layout changes */

/* Entry record: [id][category_id][title][username][url][secret][comment]. */
#define REC_SIZE      (2 + 5 * VAULT_FIELD_MAX)
#define PLAIN_MAX     (VAULT_MAX_ENTRIES * REC_SIZE)
#define ENTRIES_HDR   (VC_NONCE_LEN + VC_TAG_LEN)
#define BLOB_MAX      (ENTRIES_HDR + PLAIN_MAX)

/* Category record: [id][name]. */
#define CAT_REC_SIZE   (1 + VAULT_CAT_NAME_MAX)
#define CATS_PLAIN_MAX (VAULT_MAX_CATEGORIES * CAT_REC_SIZE)
#define CATS_BLOB_MAX  (ENTRIES_HDR + CATS_PLAIN_MAX)

static bool s_unlocked;
static uint8_t s_dek[VC_KEY_LEN];

/* In-RAM working copies, valid only while unlocked. The big entry table and
 * the serialize/encrypt scratch buffers live in PSRAM (see ensure_buffers):
 * the entry record grew with url/comment, so keeping three ~40 KB arrays in
 * internal RAM would crowd out WiFi/TLS. Categories are tiny and stay static. */
static vault_entry_t   *s_entries;       /* VAULT_MAX_ENTRIES */
static uint8_t         *s_io_plain;      /* PLAIN_MAX */
static uint8_t         *s_io_blob;       /* BLOB_MAX */
static size_t           s_count;
static bool             s_bulk;          /* defer entry persistence (import) */

static vault_category_t s_cats[VAULT_MAX_CATEGORIES];
static size_t           s_cat_count;

static size_t serialize_entries(uint8_t *plain);
static esp_err_t persist_cats(void);

bool vault_is_unlocked(void) { return s_unlocked; }

bool vault_is_initialized(void)
{
    uint8_t wdek[VC_WRAPPED_DEK_LEN]; size_t len = sizeof wdek;
    return vs_get_blob("wdek", wdek, &len) == ESP_OK;
}

/* Allocate the PSRAM-backed working buffers once. Called before the vault is
 * populated (setup/unlock). */
static esp_err_t ensure_buffers(void)
{
    if (!s_entries)
        s_entries = heap_caps_calloc(VAULT_MAX_ENTRIES, sizeof(vault_entry_t), MALLOC_CAP_SPIRAM);
    if (!s_io_plain)
        s_io_plain = heap_caps_malloc(PLAIN_MAX, MALLOC_CAP_SPIRAM);
    if (!s_io_blob)
        s_io_blob = heap_caps_malloc(BLOB_MAX, MALLOC_CAP_SPIRAM);
    return (s_entries && s_io_plain && s_io_blob) ? ESP_OK : ESP_ERR_NO_MEM;
}

esp_err_t vault_init(void)
{
    if (!vault_is_initialized()) return ESP_OK;     /* fresh device, nothing to do */
    uint8_t fmt = 0; size_t flen = sizeof fmt;
    if (vs_get_blob("vfmt", &fmt, &flen) == ESP_OK && fmt == VAULT_FORMAT_VERSION)
        return ESP_OK;                              /* current format */
    vault_factory_reset();                          /* incompatible old format */
    return ESP_OK;
}

/* ---- entries serialization ---- */

static size_t serialize_entries(uint8_t *plain)
{
    size_t off = 0;
    for (size_t i = 0; i < s_count; i++) {
        plain[off++] = s_entries[i].id;
        plain[off++] = s_entries[i].category_id;
        memcpy(plain + off, s_entries[i].title,    VAULT_FIELD_MAX); off += VAULT_FIELD_MAX;
        memcpy(plain + off, s_entries[i].username,  VAULT_FIELD_MAX); off += VAULT_FIELD_MAX;
        memcpy(plain + off, s_entries[i].url,       VAULT_FIELD_MAX); off += VAULT_FIELD_MAX;
        memcpy(plain + off, s_entries[i].secret,    VAULT_FIELD_MAX); off += VAULT_FIELD_MAX;
        memcpy(plain + off, s_entries[i].comment,   VAULT_FIELD_MAX); off += VAULT_FIELD_MAX;
    }
    return off;
}

static esp_err_t persist_entries(void)
{
    if (s_bulk) return ESP_OK;   /* inside a bulk window; vault_bulk_commit flushes */
    size_t off = serialize_entries(s_io_plain);
    uint8_t *nonce = s_io_blob, *tag = s_io_blob + VC_NONCE_LEN, *ct = s_io_blob + ENTRIES_HDR;
    vc_random(nonce, VC_NONCE_LEN);
    esp_err_t err = vc_gcm_encrypt(s_dek, nonce, NULL, 0, s_io_plain, off, ct, tag);
    if (err != ESP_OK) return err;
    err = vs_set_blob("entries", s_io_blob, ENTRIES_HDR + off);
    if (err == ESP_OK) err = vs_commit();
    return err;
}

/* Bulk-edit window: vault_add/vault_update keep changes in RAM and skip their
 * per-call NVS commit until vault_bulk_commit() writes once. Lets import avoid
 * one flash erase/write cycle per entry and stay all-or-nothing on disk. */
void vault_bulk_begin(void) { s_bulk = true; }

esp_err_t vault_bulk_commit(void)
{
    s_bulk = false;
    if (!s_unlocked) return ESP_ERR_INVALID_STATE;
    return persist_entries();
}

static esp_err_t load_entries(void)
{
    size_t blen = BLOB_MAX;
    esp_err_t err = vs_get_blob("entries", s_io_blob, &blen);
    s_count = 0;
    if (err == ESP_ERR_NVS_NOT_FOUND) return ESP_OK;
    if (err != ESP_OK) return err;
    if (blen < ENTRIES_HDR) return ESP_FAIL;   /* truncated/corrupt blob */

    uint8_t *nonce = s_io_blob, *tag = s_io_blob + VC_NONCE_LEN, *ct = s_io_blob + ENTRIES_HDR;
    size_t ctlen = blen - ENTRIES_HDR;
    err = vc_gcm_decrypt(s_dek, nonce, NULL, 0, ct, ctlen, tag, s_io_plain);
    if (err != ESP_OK) return err;

    size_t off = 0;
    while (off + REC_SIZE <= ctlen && s_count < VAULT_MAX_ENTRIES) {
        vault_entry_t *e = &s_entries[s_count++];
        e->id          = s_io_plain[off++];
        e->category_id = s_io_plain[off++];
        memcpy(e->title,    s_io_plain + off, VAULT_FIELD_MAX); off += VAULT_FIELD_MAX;
        memcpy(e->username, s_io_plain + off, VAULT_FIELD_MAX); off += VAULT_FIELD_MAX;
        memcpy(e->url,      s_io_plain + off, VAULT_FIELD_MAX); off += VAULT_FIELD_MAX;
        memcpy(e->secret,   s_io_plain + off, VAULT_FIELD_MAX); off += VAULT_FIELD_MAX;
        memcpy(e->comment,  s_io_plain + off, VAULT_FIELD_MAX); off += VAULT_FIELD_MAX;
    }
    return ESP_OK;
}

/* ---- categories serialization (small, stack scratch) ---- */

static esp_err_t persist_cats(void)
{
    uint8_t plain[CATS_PLAIN_MAX];
    size_t off = 0;
    for (size_t i = 0; i < s_cat_count; i++) {
        plain[off++] = s_cats[i].id;
        memcpy(plain + off, s_cats[i].name, VAULT_CAT_NAME_MAX); off += VAULT_CAT_NAME_MAX;
    }
    uint8_t blob[CATS_BLOB_MAX];
    uint8_t *nonce = blob, *tag = blob + VC_NONCE_LEN, *ct = blob + ENTRIES_HDR;
    vc_random(nonce, VC_NONCE_LEN);
    esp_err_t err = vc_gcm_encrypt(s_dek, nonce, NULL, 0, plain, off, ct, tag);
    if (err != ESP_OK) return err;
    err = vs_set_blob("cats", blob, ENTRIES_HDR + off);
    if (err == ESP_OK) err = vs_commit();
    return err;
}

static esp_err_t load_cats(void)
{
    uint8_t blob[CATS_BLOB_MAX]; size_t blen = sizeof blob;
    s_cat_count = 0;
    esp_err_t err = vs_get_blob("cats", blob, &blen);
    if (err == ESP_ERR_NVS_NOT_FOUND) return ESP_OK;
    if (err != ESP_OK) return err;
    if (blen < ENTRIES_HDR) return ESP_FAIL;

    uint8_t plain[CATS_PLAIN_MAX];
    uint8_t *nonce = blob, *tag = blob + VC_NONCE_LEN, *ct = blob + ENTRIES_HDR;
    size_t ctlen = blen - ENTRIES_HDR;
    if (ctlen > sizeof plain) return ESP_FAIL;
    err = vc_gcm_decrypt(s_dek, nonce, NULL, 0, ct, ctlen, tag, plain);
    if (err != ESP_OK) return err;

    size_t off = 0;
    while (off + CAT_REC_SIZE <= ctlen && s_cat_count < VAULT_MAX_CATEGORIES) {
        vault_category_t *c = &s_cats[s_cat_count++];
        c->id = plain[off++];
        memcpy(c->name, plain + off, VAULT_CAT_NAME_MAX); off += VAULT_CAT_NAME_MAX;
    }
    return ESP_OK;
}

esp_err_t vault_setup(const char *master, size_t mlen)
{
    if (vault_is_initialized()) return ESP_ERR_INVALID_STATE;
    if (ensure_buffers() != ESP_OK) return ESP_ERR_NO_MEM;
    uint8_t salt[VC_SALT_LEN]; vc_random(salt, sizeof salt);
    uint32_t iter = ITERATIONS;
    uint8_t kek[VC_KEY_LEN];
    if (vc_derive_key(master, mlen, salt, iter, kek) != ESP_OK) return ESP_FAIL;
    uint8_t wdek[VC_WRAPPED_DEK_LEN];
    if (vc_dek_create(kek, s_dek, wdek) != ESP_OK) return ESP_FAIL;

    esp_err_t err;
    uint8_t fmt = VAULT_FORMAT_VERSION;
    if ((err = vs_set_blob("salt", salt, sizeof salt)) != ESP_OK) return err;
    if ((err = vs_set_blob("iter", &iter, sizeof iter)) != ESP_OK) return err;
    if ((err = vs_set_blob("wdek", wdek, sizeof wdek)) != ESP_OK) return err;
    if ((err = vs_set_blob("vfmt", &fmt, sizeof fmt)) != ESP_OK) return err;
    if ((err = vs_commit()) != ESP_OK) return err;

    s_unlocked = true; s_count = 0; s_cat_count = 0;
    err = persist_cats();
    if (err != ESP_OK) return err;
    return persist_entries();
}

static esp_err_t load_kek(const char *master, size_t mlen, uint8_t kek[VC_KEY_LEN])
{
    uint8_t salt[VC_SALT_LEN]; size_t slen = sizeof salt;
    if (vs_get_blob("salt", salt, &slen) != ESP_OK) return ESP_ERR_INVALID_STATE;
    /* Use the iteration count stored at setup; fall back to the current default
     * if absent. This keeps old vaults unlockable if ITERATIONS is ever bumped. */
    uint32_t iter = ITERATIONS; size_t ilen = sizeof iter;
    vs_get_blob("iter", &iter, &ilen);
    return vc_derive_key(master, mlen, salt, iter, kek);
}

esp_err_t vault_unlock(const char *master, size_t mlen)
{
    if (!vault_is_initialized()) return ESP_ERR_INVALID_STATE;
    if (ensure_buffers() != ESP_OK) return ESP_ERR_NO_MEM;
    uint8_t kek[VC_KEY_LEN];
    if (load_kek(master, mlen, kek) != ESP_OK) return ESP_FAIL;
    uint8_t wdek[VC_WRAPPED_DEK_LEN]; size_t wlen = sizeof wdek;
    if (vs_get_blob("wdek", wdek, &wlen) != ESP_OK) return ESP_FAIL;
    if (vc_dek_unwrap(kek, wdek, s_dek) != ESP_OK) return ESP_FAIL;  /* wrong pw */
    s_unlocked = true;
    esp_err_t err = load_entries();
    if (err == ESP_OK) err = load_cats();
    if (err != ESP_OK) { vault_lock(); }
    return err;
}

void vault_lock(void)
{
    s_unlocked = false;
    memset(s_dek, 0, sizeof s_dek);
    if (s_entries)  memset(s_entries, 0, VAULT_MAX_ENTRIES * sizeof(vault_entry_t));
    if (s_io_plain) memset(s_io_plain, 0, PLAIN_MAX);
    if (s_io_blob)  memset(s_io_blob, 0, BLOB_MAX);
    memset(s_cats, 0, sizeof s_cats);
    s_count = 0;
    s_cat_count = 0;
}

void vault_factory_reset(void)
{
    vault_lock();
    vs_erase_key("salt");
    vs_erase_key("iter");
    vs_erase_key("wdek");
    vs_erase_key("vfmt");
    vs_erase_key("entries");
    vs_erase_key("cats");
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
    uint32_t iter = ITERATIONS;
    uint8_t nkek[VC_KEY_LEN], nwdek[VC_WRAPPED_DEK_LEN];
    if (vc_derive_key(next, nlen, salt, iter, nkek) != ESP_OK) return ESP_FAIL;
    /* Re-wrap the SAME dek under the new kek. */
    uint8_t *nonce = nwdek, *ct = nwdek + VC_NONCE_LEN, *tag = nwdek + VC_NONCE_LEN + VC_KEY_LEN;
    vc_random(nonce, VC_NONCE_LEN);
    if (vc_gcm_encrypt(nkek, nonce, NULL, 0, dek, VC_KEY_LEN, ct, tag) != ESP_OK) return ESP_FAIL;

    esp_err_t err;
    if ((err = vs_set_blob("salt", salt, sizeof salt)) != ESP_OK) return err;
    if ((err = vs_set_blob("iter", &iter, sizeof iter)) != ESP_OK) return err;
    if ((err = vs_set_blob("wdek", nwdek, sizeof nwdek)) != ESP_OK) return err;
    return vs_commit();
}

/* ---- entries CRUD ---- */

static vault_entry_t *find(uint8_t id)
{
    for (size_t i = 0; i < s_count; i++) if (s_entries[i].id == id) return &s_entries[i];
    return NULL;
}

/* Lowest unused entry id in 1..255 (ids are one byte in the record format).
 * Returns 0 only if all 255 ids are taken — impossible while
 * VAULT_MAX_ENTRIES <= 64, so callers treat 0 as "no space". */
static uint8_t alloc_id(void)
{
    for (uint16_t cand = 1; cand <= 255; cand++)
        if (!find((uint8_t)cand)) return (uint8_t)cand;
    return 0;
}

static void set_field(char *dst, const char *src)
{
    memset(dst, 0, VAULT_FIELD_MAX);
    if (src) strncpy(dst, src, VAULT_FIELD_MAX - 1);
}

/* True if id is 0 (Uncategorized) or names an existing category. */
static bool category_valid(uint8_t id)
{
    if (id == 0) return true;
    for (size_t i = 0; i < s_cat_count; i++) if (s_cats[i].id == id) return true;
    return false;
}

esp_err_t vault_list(vault_entry_t *out, size_t cap, size_t *count)
{
    if (!s_unlocked) return ESP_ERR_INVALID_STATE;
    size_t n = s_count < cap ? s_count : cap;
    for (size_t i = 0; i < n; i++) {
        out[i] = s_entries[i];
        /* never leak the reveal-gated fields in the list */
        memset(out[i].url,     0, VAULT_FIELD_MAX);
        memset(out[i].secret,  0, VAULT_FIELD_MAX);
        memset(out[i].comment, 0, VAULT_FIELD_MAX);
    }
    *count = n;
    return ESP_OK;
}

esp_err_t vault_reveal(uint8_t id, char secret_out[VAULT_FIELD_MAX],
                       char url_out[VAULT_FIELD_MAX],
                       char comment_out[VAULT_FIELD_MAX])
{
    if (!s_unlocked) return ESP_ERR_INVALID_STATE;
    vault_entry_t *e = find(id);
    if (!e) return ESP_ERR_NOT_FOUND;
    memcpy(secret_out,  e->secret,  VAULT_FIELD_MAX);
    memcpy(url_out,     e->url,     VAULT_FIELD_MAX);
    memcpy(comment_out, e->comment, VAULT_FIELD_MAX);
    return ESP_OK;
}

esp_err_t vault_add(const char *title, const char *username, const char *secret,
                    const char *url, const char *comment, uint8_t category_id,
                    uint8_t *out_id)
{
    if (!s_unlocked) return ESP_ERR_INVALID_STATE;
    if (s_count >= VAULT_MAX_ENTRIES) return ESP_ERR_NO_MEM;
    uint8_t id = alloc_id();
    if (id == 0) return ESP_ERR_NO_MEM;
    vault_entry_t *e = &s_entries[s_count++];
    e->id = id;
    e->category_id = category_valid(category_id) ? category_id : 0;
    set_field(e->title, title);
    set_field(e->username, username);
    set_field(e->secret, secret);
    set_field(e->url, url);
    set_field(e->comment, comment);
    if (out_id) *out_id = e->id;
    return persist_entries();
}

esp_err_t vault_update(uint8_t id, const char *title, const char *username,
                       const char *secret, const char *url, const char *comment,
                       uint8_t category_id)
{
    if (!s_unlocked) return ESP_ERR_INVALID_STATE;
    vault_entry_t *e = find(id);
    if (!e) return ESP_ERR_NOT_FOUND;
    e->category_id = category_valid(category_id) ? category_id : 0;
    set_field(e->title, title);
    set_field(e->username, username);
    set_field(e->secret, secret);
    set_field(e->url, url);
    set_field(e->comment, comment);
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

/* ---- categories CRUD ---- */

static uint8_t alloc_cat_id(void)
{
    for (uint16_t cand = 1; cand <= 255; cand++) {
        bool taken = false;
        for (size_t i = 0; i < s_cat_count; i++)
            if (s_cats[i].id == (uint8_t)cand) { taken = true; break; }
        if (!taken) return (uint8_t)cand;
    }
    return 0;
}

esp_err_t vault_category_list(vault_category_t *out, size_t cap, size_t *count)
{
    if (!s_unlocked) return ESP_ERR_INVALID_STATE;
    size_t n = s_cat_count < cap ? s_cat_count : cap;
    for (size_t i = 0; i < n; i++) out[i] = s_cats[i];
    *count = n;
    return ESP_OK;
}

esp_err_t vault_category_add(const char *name, uint8_t *out_id)
{
    if (!s_unlocked) return ESP_ERR_INVALID_STATE;
    if (!name || !name[0]) return ESP_ERR_INVALID_ARG;
    if (s_cat_count >= VAULT_MAX_CATEGORIES) return ESP_ERR_NO_MEM;
    /* reject a duplicate name (case-sensitive) */
    for (size_t i = 0; i < s_cat_count; i++)
        if (strncmp(s_cats[i].name, name, VAULT_CAT_NAME_MAX) == 0) return ESP_ERR_INVALID_STATE;
    uint8_t id = alloc_cat_id();
    if (id == 0) return ESP_ERR_NO_MEM;
    vault_category_t *c = &s_cats[s_cat_count++];
    c->id = id;
    memset(c->name, 0, VAULT_CAT_NAME_MAX);
    strncpy(c->name, name, VAULT_CAT_NAME_MAX - 1);
    if (out_id) *out_id = id;
    return persist_cats();
}

esp_err_t vault_category_delete(uint8_t id)
{
    if (!s_unlocked) return ESP_ERR_INVALID_STATE;
    if (id == 0) return ESP_ERR_INVALID_ARG;   /* Uncategorized is built-in */
    size_t idx = VAULT_MAX_CATEGORIES; bool found = false;
    for (size_t i = 0; i < s_cat_count; i++) if (s_cats[i].id == id) { idx = i; found = true; break; }
    if (!found) return ESP_ERR_NOT_FOUND;

    bool entries_changed = false;
    for (size_t i = 0; i < s_count; i++)
        if (s_entries[i].category_id == id) { s_entries[i].category_id = 0; entries_changed = true; }

    s_cats[idx] = s_cats[--s_cat_count];
    memset(&s_cats[s_cat_count], 0, sizeof s_cats[s_cat_count]);

    esp_err_t err = persist_cats();
    if (err == ESP_OK && entries_changed) err = persist_entries();
    return err;
}

/* ---- transfer password + export/import ---- */

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

esp_err_t vault_export(const char *transfer_pw, size_t len,
                       uint8_t **out_bundle, size_t *out_len)
{
    if (!s_unlocked) return ESP_ERR_INVALID_STATE;
    if (!vault_verify_transfer(transfer_pw, len)) return ESP_FAIL;

    size_t plen = serialize_entries(s_io_plain);
    size_t cap = VC_BUNDLE_HDR + plen;
    uint8_t *buf = malloc(cap);
    if (!buf) return ESP_ERR_NO_MEM;
    size_t blen = cap;
    esp_err_t e = vc_bundle_pack(transfer_pw, len, s_io_plain, plen, buf, &blen);
    if (e != ESP_OK) { free(buf); return e; }
    *out_bundle = buf; *out_len = blen;
    return ESP_OK;
}

esp_err_t vault_import(const char *transfer_pw, size_t len,
                       const uint8_t *bundle, size_t bundle_len)
{
    if (!s_unlocked) return ESP_ERR_INVALID_STATE;
    size_t plen = PLAIN_MAX;
    esp_err_t e = vc_bundle_unpack(transfer_pw, len, bundle, bundle_len, s_io_plain, &plen);
    if (e != ESP_OK) return e;   /* wrong password / tamper / bad format */

    size_t off = 0;
    while (off + REC_SIZE <= plen) {
        uint8_t cat        = s_io_plain[off + 1];
        const char *title  = (const char *)(s_io_plain + off + 2);
        const char *user   = (const char *)(s_io_plain + off + 2 + VAULT_FIELD_MAX);
        const char *url    = (const char *)(s_io_plain + off + 2 + 2 * VAULT_FIELD_MAX);
        const char *sec    = (const char *)(s_io_plain + off + 2 + 3 * VAULT_FIELD_MAX);
        const char *cmt    = (const char *)(s_io_plain + off + 2 + 4 * VAULT_FIELD_MAX);
        off += REC_SIZE;

        /* Category ids are local to the source vault; keep only if it happens to
         * be a valid id here, otherwise drop to Uncategorized. */
        if (!category_valid(cat)) cat = 0;

        vault_entry_t *match = NULL;
        for (size_t i = 0; i < s_count; i++) {
            if (strncmp(s_entries[i].title, title, VAULT_FIELD_MAX) == 0 &&
                strncmp(s_entries[i].username, user, VAULT_FIELD_MAX) == 0) {
                match = &s_entries[i]; break;
            }
        }
        if (match) {
            match->category_id = cat;
            set_field(match->secret, sec);
            set_field(match->url, url);
            set_field(match->comment, cmt);
        } else if (s_count < VAULT_MAX_ENTRIES) {
            uint8_t nid = alloc_id();
            if (nid == 0) break;   /* id space exhausted */
            vault_entry_t *en = &s_entries[s_count++];
            en->id = nid;
            en->category_id = cat;
            set_field(en->title, title);
            set_field(en->username, user);
            set_field(en->url, url);
            set_field(en->secret, sec);
            set_field(en->comment, cmt);
        }
    }
    return persist_entries();
}
