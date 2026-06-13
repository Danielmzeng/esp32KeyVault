#include "vault_session.h"
#include "vault_crypto.h"
#include <string.h>

static char     s_token[VS_TOKEN_HEX];
static bool     s_active;
static uint64_t s_last_seen_ms;

static int      s_fail_count;
static uint64_t s_lockout_until_ms;

static vsess_expiry_cb_t s_expiry_cb;

void vsess_set_expiry_cb(vsess_expiry_cb_t cb) { s_expiry_cb = cb; }

static void to_hex(const uint8_t *in, size_t n, char *out)
{
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { out[2*i] = d[in[i] >> 4]; out[2*i+1] = d[in[i] & 0xf]; }
    out[2*n] = '\0';
}

/* constant-time string compare */
static bool ct_eq(const char *a, const char *b)
{
    size_t la = strlen(a), lb = strlen(b);
    if (la != lb) return false;
    uint8_t diff = 0;
    for (size_t i = 0; i < la; i++) diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}

void vsess_reset(void)
{
    s_active = false; s_token[0] = '\0'; s_last_seen_ms = 0;
    s_fail_count = 0; s_lockout_until_ms = 0;
}

bool vsess_login_allowed(uint64_t now_ms)
{
    if (s_fail_count >= VS_MAX_FAILS && now_ms < s_lockout_until_ms) return false;
    if (s_fail_count >= VS_MAX_FAILS && now_ms >= s_lockout_until_ms) s_fail_count = 0;
    return true;
}

void vsess_note_login_result(bool success, uint64_t now_ms)
{
    if (success) { s_fail_count = 0; s_lockout_until_ms = 0; return; }
    s_fail_count++;
    if (s_fail_count >= VS_MAX_FAILS) s_lockout_until_ms = now_ms + VS_LOCKOUT_MS;
}

void vsess_create(uint64_t now_ms, char out_token_hex[VS_TOKEN_HEX])
{
    uint8_t raw[VS_TOKEN_LEN]; vc_random(raw, sizeof raw);
    to_hex(raw, sizeof raw, s_token);
    s_active = true; s_last_seen_ms = now_ms;
    strcpy(out_token_hex, s_token);
}

bool vsess_validate(const char *token_hex, uint64_t now_ms)
{
    if (!s_active || !token_hex || token_hex[0] == '\0') return false;
    if (now_ms - s_last_seen_ms > VS_IDLE_MS) {
        vsess_destroy();
        if (s_expiry_cb) s_expiry_cb();   /* e.g. vault_lock(): wipe DEK on idle */
        return false;
    }
    if (!ct_eq(token_hex, s_token)) return false;
    s_last_seen_ms = now_ms;
    return true;
}

void vsess_destroy(void)
{
    s_active = false;
    memset(s_token, 0, sizeof s_token);
}
