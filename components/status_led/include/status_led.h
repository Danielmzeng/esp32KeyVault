#pragma once
#include "esp_err.h"

/* Drive the onboard WS2812 RGB LED (GPIO48) as a vault security indicator:
 *   blue  = no vault yet (run setup)
 *   red   = vault locked
 *   green = vault unlocked
 * Brightness is kept low. A low-rate timer mirrors the live vault state, so
 * transitions the user didn't trigger directly -- notably idle auto-lock -- are
 * reflected without any hook in the request handlers. Call once after
 * vault_init(). Returns ESP_OK even if the LED is absent; it just won't light. */
esp_err_t status_led_init(void);

/* Pulse the LED blue briefly to signal API activity (any request handled),
 * then return to mirroring the steady vault state. Safe to call from any task:
 * it only sets a flag the LED timer reads, so no LED I/O races -- and because
 * the timer renders it, a slow/busy request handler can't suppress the pulse. */
void status_led_activity(void);
