#pragma once
#include <cstdint>
#include "led_strip.h"
#include "vault.h"
#include "vault_session.h"

/* Drive the onboard WS2812 RGB LED (GPIO48) as a vault security indicator:
 *   blue  = no vault yet (run setup)
 *   red   = vault locked
 *   green = vault unlocked
 * Brightness is kept low. A low-rate timer mirrors the live vault state, so
 * transitions the user didn't trigger directly -- notably idle auto-lock -- are
 * reflected without any hook in the request handlers. Call init() once after
 * the vault is constructed; it works even if the LED is absent (just won't light). */

namespace vault {

class StatusLed {
public:
    StatusLed(Vault& vault, Session& session) : vault_(vault), session_(session) {}

    /* Start the mirror timer; non-fatal if the LED is absent. */
    void init();

    /* Pulse the LED blue briefly to signal API activity (any request handled),
     * then return to mirroring the steady vault state. Safe to call from any task:
     * it only sets a flag the LED timer reads, so no LED I/O races -- and because
     * the timer renders it, a slow/busy request handler can't suppress the pulse. */
    void activity();

private:
    static void tick_trampoline(void* arg);
    void tick();
    void set_rgb(uint32_t r, uint32_t g, uint32_t b);
    int  state_code();
    void draw(int code);
    uint32_t green_level();

    Vault&   vault_;
    Session& session_;
    led_strip_handle_t strip_ = nullptr;
    int      last_   = -1;           /* last state drawn; skip redundant refreshes */
    uint32_t glevel_ = 0;            /* last green level drawn (unlocked fade) */
    bool     blink_  = false;        /* toggles each tick while busy */
    volatile uint32_t activity_until_ = 0;  /* ms: show blue pulse until this time */
};

}  // namespace vault
