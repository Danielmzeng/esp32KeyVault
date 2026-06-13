#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#define VS_TOKEN_LEN   32          /* bytes; hex-encoded => 64 chars */
#define VS_TOKEN_HEX   (VS_TOKEN_LEN * 2 + 1)
#define VS_IDLE_MS     (3 * 60 * 1000)
#define VS_MAX_FAILS   5
#define VS_LOCKOUT_MS  (60 * 1000)

void  vsess_reset(void);                       /* clear session + fail counter (test aid) */

/* Register a callback invoked when a session expires due to idle timeout
 * (e.g. vault_lock to wipe the DEK). Keeps this module independent of the vault.
 * Pass NULL to clear. */
typedef void (*vsess_expiry_cb_t)(void);
void  vsess_set_expiry_cb(vsess_expiry_cb_t cb);

/* Login gating. Returns false if currently locked out. */
bool  vsess_login_allowed(uint64_t now_ms);
void  vsess_note_login_result(bool success, uint64_t now_ms);

/* Create a session token after a successful unlock. out is VS_TOKEN_HEX chars. */
void  vsess_create(uint64_t now_ms, char out_token_hex[VS_TOKEN_HEX]);
/* Validate a presented token; refreshes idle timer on success. */
bool  vsess_validate(const char *token_hex, uint64_t now_ms);

/* If a session is active and has been idle longer than VS_IDLE_MS, destroy it and
 * fire the expiry callback. Returns true if it expired. Lets a periodic timer
 * lock the vault even when no request comes in to drive vsess_validate. Must be
 * called from the same context as vsess_validate (the httpd task) -- it is not
 * internally synchronized. */
bool  vsess_check_idle(uint64_t now_ms);

/* Milliseconds until the active session idles out (0 if expired or no session).
 * Lets the status LED show a countdown toward auto-lock. */
uint32_t vsess_idle_remaining_ms(uint64_t now_ms);

void  vsess_destroy(void);                     /* logout */
