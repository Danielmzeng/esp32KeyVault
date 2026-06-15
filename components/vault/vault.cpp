#include "vault.h"
#include "vault_crypto.h"
#include "vault_store.h"
#include "vault_error.h"
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

namespace vault {

bool Vault::is_initialized()
{
    uint8_t wdek[VC_WRAPPED_DEK_LEN]; size_t len = sizeof wdek;
    return store_.get_blob("wdek", wdek, len);
}

/* Allocate the PSRAM-backed working buffers once. Called before the vault is
 * populated (setup/unlock). */
bool Vault::ensure_buffers()
{
    if (!entries_)
        entries_ = (vault_entry_t*)heap_caps_calloc(VAULT_MAX_ENTRIES, sizeof(vault_entry_t), MALLOC_CAP_SPIRAM);
    if (!io_plain_)
        io_plain_ = (uint8_t*)heap_caps_malloc(PLAIN_MAX, MALLOC_CAP_SPIRAM);
    if (!io_blob_)
        io_blob_ = (uint8_t*)heap_caps_malloc(BLOB_MAX, MALLOC_CAP_SPIRAM);
    return entries_ && io_plain_ && io_blob_;
}

void Vault::init()
{
    if (!is_initialized()) return;     /* fresh device, nothing to do */
    uint8_t fmt = 0; size_t flen = sizeof fmt;
    if (store_.get_blob("vfmt", &fmt, flen) && fmt == VAULT_FORMAT_VERSION)
        return;                              /* current format */
    factory_reset();                          /* incompatible old format */
}

/* ---- entries serialization ---- */

size_t Vault::serialize_entries(uint8_t *plain)
{
    size_t off = 0;
    for (size_t i = 0; i < count_; i++) {
        plain[off++] = entries_[i].id;
        plain[off++] = entries_[i].category_id;
        memcpy(plain + off, entries_[i].title,    VAULT_FIELD_MAX); off += VAULT_FIELD_MAX;
        memcpy(plain + off, entries_[i].username,  VAULT_FIELD_MAX); off += VAULT_FIELD_MAX;
        memcpy(plain + off, entries_[i].url,       VAULT_FIELD_MAX); off += VAULT_FIELD_MAX;
        memcpy(plain + off, entries_[i].secret,    VAULT_FIELD_MAX); off += VAULT_FIELD_MAX;
        memcpy(plain + off, entries_[i].comment,   VAULT_FIELD_MAX); off += VAULT_FIELD_MAX;
    }
    return off;
}

void Vault::persist_entries()
{
    if (bulk_) return;   /* inside a bulk window; bulk_commit flushes */
    size_t off = serialize_entries(io_plain_);
    uint8_t *nonce = io_blob_, *tag = io_blob_ + VC_NONCE_LEN, *ct = io_blob_ + ENTRIES_HDR;
    crypto::random(nonce, VC_NONCE_LEN);
    crypto::gcm_encrypt(dek_, nonce, NULL, 0, io_plain_, off, ct, tag);
    store_.set_blob("entries", io_blob_, ENTRIES_HDR + off);
    store_.commit();
}

/* Bulk-edit window: add/update keep changes in RAM and skip their
 * per-call NVS commit until bulk_commit() writes once. Lets import avoid
 * one flash erase/write cycle per entry and stay all-or-nothing on disk. */
void Vault::bulk_begin() { bulk_ = true; }

void Vault::bulk_commit()
{
    bulk_ = false;
    if (!unlocked_) throw vault::Error(ESP_ERR_INVALID_STATE, "locked");
    persist_entries();
}

void Vault::load_entries()
{
    size_t blen = BLOB_MAX;
    bool found = store_.get_blob("entries", io_blob_, blen);
    count_ = 0;
    if (!found) return;
    if (blen < ENTRIES_HDR) throw vault::Error(ESP_FAIL, "corrupt entries");   /* truncated/corrupt blob */

    uint8_t *nonce = io_blob_, *tag = io_blob_ + VC_NONCE_LEN, *ct = io_blob_ + ENTRIES_HDR;
    size_t ctlen = blen - ENTRIES_HDR;
    if (!crypto::gcm_decrypt(dek_, nonce, NULL, 0, ct, ctlen, tag, io_plain_))
        throw vault::Error(ESP_FAIL, "entries decrypt");

    size_t off = 0;
    while (off + REC_SIZE <= ctlen && count_ < VAULT_MAX_ENTRIES) {
        vault_entry_t *e = &entries_[count_++];
        e->id          = io_plain_[off++];
        e->category_id = io_plain_[off++];
        memcpy(e->title,    io_plain_ + off, VAULT_FIELD_MAX); off += VAULT_FIELD_MAX;
        memcpy(e->username, io_plain_ + off, VAULT_FIELD_MAX); off += VAULT_FIELD_MAX;
        memcpy(e->url,      io_plain_ + off, VAULT_FIELD_MAX); off += VAULT_FIELD_MAX;
        memcpy(e->secret,   io_plain_ + off, VAULT_FIELD_MAX); off += VAULT_FIELD_MAX;
        memcpy(e->comment,  io_plain_ + off, VAULT_FIELD_MAX); off += VAULT_FIELD_MAX;
    }
}

/* ---- categories serialization (small, stack scratch) ---- */

void Vault::persist_cats()
{
    uint8_t plain[CATS_PLAIN_MAX];
    size_t off = 0;
    for (size_t i = 0; i < cat_count_; i++) {
        plain[off++] = cats_[i].id;
        memcpy(plain + off, cats_[i].name, VAULT_CAT_NAME_MAX); off += VAULT_CAT_NAME_MAX;
    }
    uint8_t blob[CATS_BLOB_MAX];
    uint8_t *nonce = blob, *tag = blob + VC_NONCE_LEN, *ct = blob + ENTRIES_HDR;
    crypto::random(nonce, VC_NONCE_LEN);
    crypto::gcm_encrypt(dek_, nonce, NULL, 0, plain, off, ct, tag);
    store_.set_blob("cats", blob, ENTRIES_HDR + off);
    store_.commit();
}

void Vault::load_cats()
{
    uint8_t blob[CATS_BLOB_MAX]; size_t blen = sizeof blob;
    cat_count_ = 0;
    if (!store_.get_blob("cats", blob, blen)) return;
    if (blen < ENTRIES_HDR) throw vault::Error(ESP_FAIL, "corrupt cats");

    uint8_t plain[CATS_PLAIN_MAX];
    uint8_t *nonce = blob, *tag = blob + VC_NONCE_LEN, *ct = blob + ENTRIES_HDR;
    size_t ctlen = blen - ENTRIES_HDR;
    if (ctlen > sizeof plain) throw vault::Error(ESP_FAIL, "corrupt cats");
    if (!crypto::gcm_decrypt(dek_, nonce, NULL, 0, ct, ctlen, tag, plain))
        throw vault::Error(ESP_FAIL, "cats decrypt");

    size_t off = 0;
    while (off + CAT_REC_SIZE <= ctlen && cat_count_ < VAULT_MAX_CATEGORIES) {
        vault_category_t *c = &cats_[cat_count_++];
        c->id = plain[off++];
        memcpy(c->name, plain + off, VAULT_CAT_NAME_MAX); off += VAULT_CAT_NAME_MAX;
    }
}

void Vault::setup(const char *master, size_t mlen)
{
    if (is_initialized()) throw vault::Error(ESP_ERR_INVALID_STATE, "already initialized");
    if (!ensure_buffers()) throw vault::Error(ESP_ERR_NO_MEM, "buffers");
    uint8_t salt[VC_SALT_LEN]; crypto::random(salt, sizeof salt);
    uint32_t iter = ITERATIONS;
    uint8_t kek[VC_KEY_LEN];
    crypto::derive_key(master, mlen, salt, iter, kek);
    uint8_t wdek[VC_WRAPPED_DEK_LEN];
    crypto::dek_create(kek, dek_, wdek);

    uint8_t fmt = VAULT_FORMAT_VERSION;
    store_.set_blob("salt", salt, sizeof salt);
    store_.set_blob("iter", &iter, sizeof iter);
    store_.set_blob("wdek", wdek, sizeof wdek);
    store_.set_blob("vfmt", &fmt, sizeof fmt);
    store_.commit();

    unlocked_ = true; count_ = 0; cat_count_ = 0;
    persist_cats();
    persist_entries();
}

void Vault::load_kek(const char *master, size_t mlen, uint8_t kek[VC_KEY_LEN])
{
    uint8_t salt[VC_SALT_LEN]; size_t slen = sizeof salt;
    if (!store_.get_blob("salt", salt, slen)) throw vault::Error(ESP_ERR_INVALID_STATE, "no salt");
    /* Use the iteration count stored at setup; fall back to the current default
     * if absent. This keeps old vaults unlockable if ITERATIONS is ever bumped. */
    uint32_t iter = ITERATIONS; size_t ilen = sizeof iter;
    store_.get_blob("iter", &iter, ilen);
    crypto::derive_key(master, mlen, salt, iter, kek);
}

bool Vault::unlock(const char *master, size_t mlen)
{
    if (!is_initialized()) throw vault::Error(ESP_ERR_INVALID_STATE, "not initialized");
    if (!ensure_buffers()) throw vault::Error(ESP_ERR_NO_MEM, "buffers");
    uint8_t kek[VC_KEY_LEN];
    /* PBKDF2 here is the ~1s wait; flag it so the status LED can blink "working". */
    deriving_ = true;
    try { load_kek(master, mlen, kek); } catch (...) { deriving_ = false; throw; }
    deriving_ = false;
    uint8_t wdek[VC_WRAPPED_DEK_LEN]; size_t wlen = sizeof wdek;
    if (!store_.get_blob("wdek", wdek, wlen)) return false;
    if (!crypto::dek_unwrap(kek, wdek, dek_)) return false;  /* wrong pw */
    unlocked_ = true;
    try { load_entries(); load_cats(); } catch (...) { lock(); throw; }
    return true;
}

void Vault::lock()
{
    unlocked_ = false;
    memset(dek_, 0, sizeof dek_);
    if (entries_)  memset(entries_, 0, VAULT_MAX_ENTRIES * sizeof(vault_entry_t));
    if (io_plain_) memset(io_plain_, 0, PLAIN_MAX);
    if (io_blob_)  memset(io_blob_, 0, BLOB_MAX);
    memset(cats_, 0, sizeof cats_);
    count_ = 0;
    cat_count_ = 0;
}

void Vault::factory_reset()
{
    lock();
    store_.erase_key("salt");
    store_.erase_key("iter");
    store_.erase_key("wdek");
    store_.erase_key("vfmt");
    store_.erase_key("entries");
    store_.erase_key("cats");
    store_.erase_key("tsalt");
    store_.erase_key("tverif");
    store_.commit();
}

bool Vault::change_password(const char *cur, size_t clen,
                            const char *next, size_t nlen)
{
    uint8_t kek[VC_KEY_LEN], dek[VC_KEY_LEN];
    load_kek(cur, clen, kek);
    uint8_t wdek[VC_WRAPPED_DEK_LEN]; size_t wlen = sizeof wdek;
    if (!store_.get_blob("wdek", wdek, wlen)) return false;
    if (!crypto::dek_unwrap(kek, wdek, dek)) return false;  /* wrong current pw */

    uint8_t salt[VC_SALT_LEN]; crypto::random(salt, sizeof salt);
    uint32_t iter = ITERATIONS;
    uint8_t nkek[VC_KEY_LEN], nwdek[VC_WRAPPED_DEK_LEN];
    crypto::derive_key(next, nlen, salt, iter, nkek);
    /* Re-wrap the SAME dek under the new kek. */
    uint8_t *nonce = nwdek, *ct = nwdek + VC_NONCE_LEN, *tag = nwdek + VC_NONCE_LEN + VC_KEY_LEN;
    crypto::random(nonce, VC_NONCE_LEN);
    crypto::gcm_encrypt(nkek, nonce, NULL, 0, dek, VC_KEY_LEN, ct, tag);

    store_.set_blob("salt", salt, sizeof salt);
    store_.set_blob("iter", &iter, sizeof iter);
    store_.set_blob("wdek", nwdek, sizeof nwdek);
    store_.commit();
    return true;
}

/* ---- entries CRUD ---- */

vault_entry_t *Vault::find(uint8_t id)
{
    for (size_t i = 0; i < count_; i++) if (entries_[i].id == id) return &entries_[i];
    return NULL;
}

/* Lowest unused entry id in 1..255 (ids are one byte in the record format).
 * Returns 0 only if all 255 ids are taken — impossible while
 * VAULT_MAX_ENTRIES <= 64, so callers treat 0 as "no space". */
uint8_t Vault::alloc_id()
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
bool Vault::category_valid(uint8_t id)
{
    if (id == 0) return true;
    for (size_t i = 0; i < cat_count_; i++) if (cats_[i].id == id) return true;
    return false;
}

size_t Vault::list(vault_entry_t *out, size_t cap)
{
    if (!unlocked_) throw vault::Error(ESP_ERR_INVALID_STATE, "locked");
    size_t n = count_ < cap ? count_ : cap;
    for (size_t i = 0; i < n; i++) {
        out[i] = entries_[i];
        /* never leak the reveal-gated fields in the list */
        memset(out[i].url,     0, VAULT_FIELD_MAX);
        memset(out[i].secret,  0, VAULT_FIELD_MAX);
        memset(out[i].comment, 0, VAULT_FIELD_MAX);
    }
    return n;
}

bool Vault::reveal(uint8_t id, char secret_out[VAULT_FIELD_MAX],
                   char url_out[VAULT_FIELD_MAX],
                   char comment_out[VAULT_FIELD_MAX])
{
    if (!unlocked_) throw vault::Error(ESP_ERR_INVALID_STATE, "locked");
    vault_entry_t *e = find(id);
    if (!e) return false;
    memcpy(secret_out,  e->secret,  VAULT_FIELD_MAX);
    memcpy(url_out,     e->url,     VAULT_FIELD_MAX);
    memcpy(comment_out, e->comment, VAULT_FIELD_MAX);
    return true;
}

uint8_t Vault::add(const char *title, const char *username, const char *secret,
                   const char *url, const char *comment, uint8_t category_id)
{
    if (!unlocked_) throw vault::Error(ESP_ERR_INVALID_STATE, "locked");
    if (count_ >= VAULT_MAX_ENTRIES) throw vault::Error(ESP_ERR_NO_MEM, "full");
    uint8_t id = alloc_id();
    if (id == 0) throw vault::Error(ESP_ERR_NO_MEM, "no id");
    vault_entry_t *e = &entries_[count_++];
    e->id = id;
    e->category_id = category_valid(category_id) ? category_id : 0;
    set_field(e->title, title);
    set_field(e->username, username);
    set_field(e->secret, secret);
    set_field(e->url, url);
    set_field(e->comment, comment);
    try {
        persist_entries();
    } catch (...) {
        /* Persist failed (e.g. NVS full): roll back the in-RAM insert so the
         * reported failure matches what the list returns and what survives a
         * reboot. Without this the entry lingers in RAM and reappears on
         * refresh despite "add failed". */
        memset(e, 0, sizeof *e);
        count_--;
        throw;
    }
    return e->id;
}

bool Vault::update(uint8_t id, const char *title, const char *username,
                   const char *secret, const char *url, const char *comment,
                   uint8_t category_id)
{
    if (!unlocked_) throw vault::Error(ESP_ERR_INVALID_STATE, "locked");
    vault_entry_t *e = find(id);
    if (!e) return false;
    e->category_id = category_valid(category_id) ? category_id : 0;
    set_field(e->title, title);
    set_field(e->username, username);
    set_field(e->secret, secret);
    set_field(e->url, url);
    set_field(e->comment, comment);
    persist_entries();
    return true;
}

bool Vault::remove(uint8_t id)
{
    if (!unlocked_) throw vault::Error(ESP_ERR_INVALID_STATE, "locked");
    for (size_t i = 0; i < count_; i++) {
        if (entries_[i].id == id) {
            entries_[i] = entries_[--count_];
            memset(&entries_[count_], 0, sizeof entries_[count_]);
            persist_entries();
            return true;
        }
    }
    return false;
}

void Vault::clear_entries()
{
    if (!unlocked_) throw vault::Error(ESP_ERR_INVALID_STATE, "locked");
    memset(entries_, 0, count_ * sizeof *entries_);   /* wipe plaintext fields */
    count_ = 0;
    persist_entries();
}

/* ---- categories CRUD ---- */

uint8_t Vault::alloc_cat_id()
{
    for (uint16_t cand = 1; cand <= 255; cand++) {
        bool taken = false;
        for (size_t i = 0; i < cat_count_; i++)
            if (cats_[i].id == (uint8_t)cand) { taken = true; break; }
        if (!taken) return (uint8_t)cand;
    }
    return 0;
}

size_t Vault::category_list(vault_category_t *out, size_t cap)
{
    if (!unlocked_) throw vault::Error(ESP_ERR_INVALID_STATE, "locked");
    size_t n = cat_count_ < cap ? cat_count_ : cap;
    for (size_t i = 0; i < n; i++) out[i] = cats_[i];
    return n;
}

uint8_t Vault::category_add(const char *name)
{
    if (!unlocked_) throw vault::Error(ESP_ERR_INVALID_STATE, "locked");
    if (!name || !name[0]) throw vault::Error(ESP_ERR_INVALID_ARG, "name");
    if (cat_count_ >= VAULT_MAX_CATEGORIES) throw vault::Error(ESP_ERR_NO_MEM, "cats full");
    /* reject a duplicate name (case-sensitive) */
    for (size_t i = 0; i < cat_count_; i++)
        if (strncmp(cats_[i].name, name, VAULT_CAT_NAME_MAX) == 0) throw vault::Error(ESP_ERR_INVALID_STATE, "category exists");
    uint8_t id = alloc_cat_id();
    if (id == 0) throw vault::Error(ESP_ERR_NO_MEM, "cats full");
    vault_category_t *c = &cats_[cat_count_++];
    c->id = id;
    memset(c->name, 0, VAULT_CAT_NAME_MAX);
    strncpy(c->name, name, VAULT_CAT_NAME_MAX - 1);
    persist_cats();
    return id;
}

bool Vault::category_delete(uint8_t id)
{
    if (!unlocked_) throw vault::Error(ESP_ERR_INVALID_STATE, "locked");
    if (id == 0) throw vault::Error(ESP_ERR_INVALID_ARG, "uncategorized");   /* Uncategorized is built-in */
    size_t idx = VAULT_MAX_CATEGORIES; bool found = false;
    for (size_t i = 0; i < cat_count_; i++) if (cats_[i].id == id) { idx = i; found = true; break; }
    if (!found) return false;

    bool entries_changed = false;
    for (size_t i = 0; i < count_; i++)
        if (entries_[i].category_id == id) { entries_[i].category_id = 0; entries_changed = true; }

    cats_[idx] = cats_[--cat_count_];
    memset(&cats_[cat_count_], 0, sizeof cats_[cat_count_]);

    persist_cats();
    if (entries_changed) persist_entries();
    return true;
}

/* ---- transfer password + export/import ---- */

/* 16-byte known constant used as the transfer-password verifier plaintext. */
static const uint8_t XFER_CHECK[16] = "esp32key-xfer!!";  /* 15 chars + NUL */
#define TVERIF_LEN (VC_NONCE_LEN + 16 + VC_TAG_LEN)

void Vault::set_transfer_password(const char *pw, size_t len)
{
    uint8_t tsalt[VC_SALT_LEN]; crypto::random(tsalt, sizeof tsalt);
    uint8_t tkey[VC_KEY_LEN];
    crypto::derive_key(pw, len, tsalt, ITERATIONS, tkey);

    uint8_t verif[TVERIF_LEN];
    uint8_t *nonce = verif, *ct = verif + VC_NONCE_LEN, *tag = verif + VC_NONCE_LEN + 16;
    crypto::random(nonce, VC_NONCE_LEN);
    crypto::gcm_encrypt(tkey, nonce, NULL, 0, XFER_CHECK, 16, ct, tag);

    store_.set_blob("tsalt", tsalt, sizeof tsalt);
    store_.set_blob("tverif", verif, sizeof verif);
    store_.commit();
}

bool Vault::verify_transfer(const char *pw, size_t len)
{
    uint8_t tsalt[VC_SALT_LEN]; size_t sl = sizeof tsalt;
    if (!store_.get_blob("tsalt", tsalt, sl)) return false;
    uint8_t tkey[VC_KEY_LEN];
    crypto::derive_key(pw, len, tsalt, ITERATIONS, tkey);
    uint8_t verif[TVERIF_LEN]; size_t vl = sizeof verif;
    if (!store_.get_blob("tverif", verif, vl)) return false;
    uint8_t *nonce = verif, *ct = verif + VC_NONCE_LEN, *tag = verif + VC_NONCE_LEN + 16;
    uint8_t out[16];
    return crypto::gcm_decrypt(tkey, nonce, NULL, 0, ct, 16, tag, out) &&
           memcmp(out, XFER_CHECK, 16) == 0;
}

bool Vault::export_bundle(const char *transfer_pw, size_t len,
                          uint8_t **out_bundle, size_t *out_len)
{
    if (!unlocked_) throw vault::Error(ESP_ERR_INVALID_STATE, "locked");
    if (!verify_transfer(transfer_pw, len)) return false;

    size_t plen = serialize_entries(io_plain_);
    size_t cap = VC_BUNDLE_HDR + plen;
    uint8_t *buf = (uint8_t*)malloc(cap);
    if (!buf) throw vault::Error(ESP_ERR_NO_MEM, "export");
    size_t blen = cap;
    try {
        crypto::bundle_pack(transfer_pw, len, io_plain_, plen, buf, &blen);
    } catch (...) {
        free(buf);
        throw;
    }
    *out_bundle = buf; *out_len = blen;
    return true;
}

bool Vault::import_bundle(const char *transfer_pw, size_t len,
                          const uint8_t *bundle, size_t bundle_len)
{
    if (!unlocked_) throw vault::Error(ESP_ERR_INVALID_STATE, "locked");
    size_t plen = PLAIN_MAX;
    if (crypto::bundle_unpack(transfer_pw, len, bundle, bundle_len, io_plain_, &plen) != crypto::BundleResult::Ok)
        return false;   /* wrong password / tamper / bad format */

    size_t off = 0;
    while (off + REC_SIZE <= plen) {
        uint8_t cat        = io_plain_[off + 1];
        const char *title  = (const char *)(io_plain_ + off + 2);
        const char *user   = (const char *)(io_plain_ + off + 2 + VAULT_FIELD_MAX);
        const char *url    = (const char *)(io_plain_ + off + 2 + 2 * VAULT_FIELD_MAX);
        const char *sec    = (const char *)(io_plain_ + off + 2 + 3 * VAULT_FIELD_MAX);
        const char *cmt    = (const char *)(io_plain_ + off + 2 + 4 * VAULT_FIELD_MAX);
        off += REC_SIZE;

        /* Category ids are local to the source vault; keep only if it happens to
         * be a valid id here, otherwise drop to Uncategorized. */
        if (!category_valid(cat)) cat = 0;

        vault_entry_t *match = NULL;
        for (size_t i = 0; i < count_; i++) {
            if (strncmp(entries_[i].title, title, VAULT_FIELD_MAX) == 0 &&
                strncmp(entries_[i].username, user, VAULT_FIELD_MAX) == 0) {
                match = &entries_[i]; break;
            }
        }
        if (match) {
            match->category_id = cat;
            set_field(match->secret, sec);
            set_field(match->url, url);
            set_field(match->comment, cmt);
        } else if (count_ < VAULT_MAX_ENTRIES) {
            uint8_t nid = alloc_id();
            if (nid == 0) break;   /* id space exhausted */
            vault_entry_t *en = &entries_[count_++];
            en->id = nid;
            en->category_id = cat;
            set_field(en->title, title);
            set_field(en->username, user);
            set_field(en->url, url);
            set_field(en->secret, sec);
            set_field(en->comment, cmt);
        }
    }
    persist_entries();
    return true;
}

Vault::~Vault() {
    lock();   /* zeroize the DEK and the decrypted-entry / scratch buffers before
                 returning them to the heap, so secrets don't outlive the vault */
    if (entries_)  { free(entries_);  entries_ = nullptr; }
    if (io_plain_) { free(io_plain_); io_plain_ = nullptr; }
    if (io_blob_)  { free(io_blob_);  io_blob_ = nullptr; }
}

}  // namespace vault
