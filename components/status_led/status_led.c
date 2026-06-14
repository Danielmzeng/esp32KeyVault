#include "status_led.h"
#include "vault.h"
#include "vault_session.h"
#include "led_strip.h"
#include "esp_timer.h"
#include "esp_log.h"

/* Onboard WS2812 on the ESP32-S3-DevKitC-1. (DevKitM / some clones use GPIO38.) */
#define LED_GPIO        48
#define REFRESH_US      (150 * 1000)   /* mirror vault state; also the busy-blink rate */
#define LVL             24             /* dim: per-channel level, 0-255 */
#define G_MIN           1              /* darkest still-lit green (idle window nearly up) */
#define ACT_MS          300            /* ~0.3s blue pulse per API request */

static const char *TAG = "status_led";
static led_strip_handle_t s_strip;
static int      s_last = -1;           /* last state drawn; skip redundant refreshes */
static uint32_t s_glevel;              /* last green level drawn (unlocked fade) */
static bool     s_blink;               /* toggles each tick while busy */
static volatile uint32_t s_activity_until;  /* ms: show blue pulse until this time */

/* Stamp an expiry the LED timer reads. Using a deadline that only this (httpd)
 * task writes -- rather than a counter the timer also decrements -- avoids the
 * read-modify-write race between the two tasks; a 32-bit store/load is atomic. */
void status_led_activity(void) { s_activity_until = (uint32_t)(esp_timer_get_time() / 1000) + ACT_MS; }

static void set_rgb(uint32_t r, uint32_t g, uint32_t b)
{
    if (led_strip_set_pixel(s_strip, 0, r, g, b) == ESP_OK)
        led_strip_refresh(s_strip);
}

/* 0 = needs setup (blue), 1 = locked (red), 2 = unlocked (green). */
static int state_code(void)
{
    if (!vault_is_initialized()) return 0;
    return vault_is_unlocked() ? 2 : 1;
}

static void draw(int code)
{
    switch (code) {
        case 0: set_rgb(0, 0, LVL); break;   /* blue  : uninitialized */
        case 1: set_rgb(LVL, 0, 0); break;   /* red   : locked */
        default: set_rgb(0, LVL, 0); break;  /* green : unlocked */
    }
}

/* Unlocked green brightness: fades from LVL (bright, fresh activity) down to
 * G_MIN (dark) as the idle window counts down toward auto-lock. */
static uint32_t green_level(void)
{
    uint64_t now = (uint64_t)(esp_timer_get_time() / 1000);
    uint32_t rem = vsess_idle_remaining_ms(now);   /* 0 .. VS_IDLE_MS */
    if (rem > VS_IDLE_MS) rem = VS_IDLE_MS;
    return G_MIN + (uint32_t)((uint64_t)rem * (LVL - G_MIN) / VS_IDLE_MS);
}

/* esp_timer callback: cheap, and only touches the LED when something changed. */
static void tick(void *arg)
{
    (void)arg;
    if (vault_is_busy()) {             /* unlocking (PBKDF2): blink red as "working" */
        s_blink = !s_blink;
        set_rgb(s_blink ? LVL : 0, 0, 0);
        s_last = -1;                   /* force a redraw of the steady state when done */
        return;
    }
    uint32_t now = (uint32_t)(esp_timer_get_time() / 1000);
    if ((int32_t)(s_activity_until - now) > 0) {   /* API activity: blue pulse (wrap-safe) */
        set_rgb(0, 0, LVL);
        s_last = -1;                   /* force a steady-state redraw when the pulse ends */
        return;
    }
    int code = state_code();
    if (code == 2) {                   /* unlocked: green fades toward the auto-lock */
        uint32_t g = green_level();
        if (code != s_last || g != s_glevel) { set_rgb(0, g, 0); s_last = code; s_glevel = g; }
        return;
    }
    if (code != s_last) { draw(code); s_last = code; }
}

esp_err_t status_led_init(void)
{
    led_strip_config_t scfg = {
        .strip_gpio_num         = LED_GPIO,
        .max_leds               = 1,
        .led_model              = LED_MODEL_WS2812,
        .color_component_format = LED_STRIP_COLOR_COMPONENT_FMT_GRB,
        .flags.invert_out       = false,
    };
    led_strip_rmt_config_t rcfg = {
        .clk_src           = RMT_CLK_SRC_DEFAULT,
        .resolution_hz     = 10 * 1000 * 1000,
        .mem_block_symbols = 0,
        .flags.with_dma    = false,
    };
    esp_err_t e = led_strip_new_rmt_device(&scfg, &rcfg, &s_strip);
    if (e != ESP_OK) {
        ESP_LOGW(TAG, "WS2812 init on GPIO%d failed: %s (no status LED)", LED_GPIO, esp_err_to_name(e));
        return ESP_OK;   /* non-fatal: the vault works without the indicator */
    }

    tick(NULL);          /* show the current state at once */

    const esp_timer_create_args_t targs = { .callback = tick, .name = "status_led" };
    esp_timer_handle_t t;
    if (esp_timer_create(&targs, &t) != ESP_OK ||
        esp_timer_start_periodic(t, REFRESH_US) != ESP_OK)
        ESP_LOGW(TAG, "status LED timer failed; LED shows only the boot-time state");
    return ESP_OK;
}
