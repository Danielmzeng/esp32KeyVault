#pragma once
#include <cstdint>
#include <cstddef>
#include <functional>

#define VS_TOKEN_LEN   32          /* bytes; hex-encoded => 64 chars */
#define VS_TOKEN_HEX   (VS_TOKEN_LEN * 2 + 1)
#define VS_IDLE_DEFAULT_MS  (3 * 60 * 1000)   /* default idle auto-lock window */
#define VS_IDLE_MIN_MS      (30 * 1000)        /* 30 s floor  */
#define VS_IDLE_MAX_MS      (3600 * 1000)      /* 60 min ceiling */
#define VS_MAX_FAILS   5
#define VS_LOCKOUT_MS  (60 * 1000)

namespace vault {

class Session {
public:
    using ExpiryCallback = std::function<void()>;

    void reset();                                 // clear session + fail counter (test aid)
    void set_expiry_cb(ExpiryCallback cb);        // fired on idle expiry (e.g. Vault::lock)

    bool login_allowed(uint64_t now_ms);          // false if currently locked out
    void note_login_result(bool success, uint64_t now_ms);

    void create(uint64_t now_ms, char out_token_hex[VS_TOKEN_HEX]);
    bool validate(const char* token_hex, uint64_t now_ms);  // refreshes idle timer on success

    bool check_idle(uint64_t now_ms);             // expire + fire cb if idle too long
    uint32_t idle_remaining_ms(uint64_t now_ms);  // ms until idle-out (0 if none/expired)
    void     set_idle_ms(uint32_t ms);            // set idle window; clamps to [MIN, MAX]
    uint32_t idle_ms() const { return idle_ms_; } // current idle window (ms)
    void destroy();                               // logout

private:
    char     token_[VS_TOKEN_HEX] = {0};
    bool     active_ = false;
    uint64_t last_seen_ms_ = 0;
    int      fail_count_ = 0;
    uint64_t lockout_until_ms_ = 0;
    /* Written on the httpd task (set_idle_ms), read on the LED timer task
     * (idle_ms/check_idle). Single writer + aligned 32-bit store/load is atomic
     * on this core, so volatile (no torn reads) is sufficient -- no lock needed. */
    volatile uint32_t idle_ms_ = VS_IDLE_DEFAULT_MS;
    ExpiryCallback expiry_cb_;
};

}  // namespace vault
