#include "vault_session.h"
#include "vault_crypto.h"
#include <cstring>

namespace vault {

namespace {
void to_hex(const uint8_t* in, size_t n, char* out) {
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { out[2*i] = d[in[i] >> 4]; out[2*i+1] = d[in[i] & 0xf]; }
    out[2*n] = '\0';
}
// constant-time string compare
bool ct_eq(const char* a, const char* b) {
    size_t la = strlen(a), lb = strlen(b);
    if (la != lb) return false;
    uint8_t diff = 0;
    for (size_t i = 0; i < la; i++) diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}
}  // namespace

void Session::set_expiry_cb(ExpiryCallback cb) { expiry_cb_ = std::move(cb); }

void Session::reset() {
    active_ = false; token_[0] = '\0'; last_seen_ms_ = 0;
    fail_count_ = 0; lockout_until_ms_ = 0;
}

bool Session::login_allowed(uint64_t now_ms) {
    if (fail_count_ >= VS_MAX_FAILS && now_ms < lockout_until_ms_) return false;
    if (fail_count_ >= VS_MAX_FAILS && now_ms >= lockout_until_ms_) fail_count_ = 0;
    return true;
}

void Session::note_login_result(bool success, uint64_t now_ms) {
    if (success) { fail_count_ = 0; lockout_until_ms_ = 0; return; }
    fail_count_++;
    if (fail_count_ >= VS_MAX_FAILS) lockout_until_ms_ = now_ms + VS_LOCKOUT_MS;
}

void Session::create(uint64_t now_ms, char out_token_hex[VS_TOKEN_HEX]) {
    uint8_t raw[VS_TOKEN_LEN]; crypto::random(raw, sizeof raw);
    to_hex(raw, sizeof raw, token_);
    active_ = true; last_seen_ms_ = now_ms;
    strcpy(out_token_hex, token_);
}

bool Session::check_idle(uint64_t now_ms) {
    if (!active_) return false;
    if (now_ms - last_seen_ms_ > idle_ms_) {
        destroy();
        if (expiry_cb_) expiry_cb_();   // e.g. Vault::lock(): wipe DEK on idle
        return true;
    }
    return false;
}

uint32_t Session::idle_remaining_ms(uint64_t now_ms) {
    if (!active_) return 0;
    uint64_t elapsed = now_ms - last_seen_ms_;
    if (elapsed >= idle_ms_) return 0;
    return (uint32_t)(idle_ms_ - elapsed);
}

void Session::set_idle_ms(uint32_t ms) {
    if (ms < VS_IDLE_MIN_MS) ms = VS_IDLE_MIN_MS;
    if (ms > VS_IDLE_MAX_MS) ms = VS_IDLE_MAX_MS;
    idle_ms_ = ms;
}

bool Session::validate(const char* token_hex, uint64_t now_ms) {
    if (!active_ || !token_hex || token_hex[0] == '\0') return false;
    if (check_idle(now_ms)) return false;
    if (!ct_eq(token_hex, token_)) return false;
    last_seen_ms_ = now_ms;
    return true;
}

void Session::destroy() {
    active_ = false;
    memset(token_, 0, sizeof token_);
}

}  // namespace vault
