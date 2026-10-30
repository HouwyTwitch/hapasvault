/*
 * pmtoken: главный цикл прошивки. USB CDC <-> token_handle.
 *
 * Кадры [u32 le длина][кадр] собираются из потока (core/framer.c). Сброс DTR
 * (программа на ПК закрыла порт), отключение USB и сторожевой таймер —
 * всё это блокирует хранилище: ключ K_vault живёт только в RAM.
 */
#include "board.h"
#include "framer.h"
#include "hal.h"
#include "proto.h"
#include "token.h"

#include "hardware/watchdog.h"
#include "pico/stdlib.h"
#include "tusb.h"

#define WATCHDOG_MS  8000u     /* худший случай — запись слота хранилища, < 1 с */
#define TX_TIMEOUT_MS 5000u

/* Один буфер на запрос и ответ: token_handle это допускает (RAM — 264 КБ). */
static uint8_t   g_buf[PM_MAX_FRAME + 64];
static pm_framer g_framer;
static bool      g_host;       /* DTR поднят: программа держит порт */
static uint64_t  g_last_rx;

static bool write_all(const uint8_t *p, size_t n)
{
    uint64_t deadline = hal_millis() + TX_TIMEOUT_MS;
    while (n) {
        if (!tud_cdc_connected() || hal_millis() > deadline) return false;
        uint32_t k = tud_cdc_write(p, (uint32_t)n);
        p += k;
        n -= k;
        if (n) {
            tud_cdc_write_flush();
            tud_task();
            watchdog_update();
        }
    }
    tud_cdc_write_flush();
    return true;
}

static void host_gone(void)
{
    token_disconnect();
    pm_framer_reset(&g_framer);
    tud_cdc_read_flush();
}

static void on_bytes(const uint8_t *p, size_t n)
{
    while (n) {
        size_t used = 0;
        long len = pm_framer_feed(&g_framer, g_buf, PM_MAX_FRAME, p, n, &used);
        p += used;
        n -= used;
        if (len <= 0) continue;
        size_t out = token_handle(g_buf, (size_t)len, g_buf, sizeof g_buf);
        uint8_t hdr[4];
        pm_framer_header(hdr, out);
        if (!write_all(hdr, 4) || !write_all(g_buf, out)) {
            host_gone();
            return;
        }
    }
}

/* USB отключён или хост усыпил шину */
void tud_umount_cb(void) { if (g_host) { g_host = false; host_gone(); } }
void tud_suspend_cb(bool remote_wakeup_en) { (void)remote_wakeup_en; tud_umount_cb(); }

int main(void)
{
    if (board_init() != 0) {
        /* прошивка пересекается с областью хранилища: не трогаем flash */
        for (;;) { hal_led(LED_ERROR); board_led_task(); sleep_ms(50); }
    }
    token_init();
    pm_framer_reset(&g_framer);
    tud_init(0);                   /* единственный USB-контроллер RP2040/RP2350 */
    watchdog_enable(WATCHDOG_MS, true);

    for (;;) {
        watchdog_update();
        tud_task();
        token_tick();
        board_led_task();

        bool host = tud_cdc_connected();
        if (g_host && !host) host_gone();
        g_host = host;
        if (!host) continue;

        if (pm_framer_busy(&g_framer) && hal_millis() - g_last_rx > PM_FRAMER_STALE_MS)
            pm_framer_reset(&g_framer);

        uint8_t chunk[256];
        uint32_t n = tud_cdc_available() ? tud_cdc_read(chunk, sizeof chunk) : 0;
        if (n == 0) continue;
        g_last_rx = hal_millis();
        on_bytes(chunk, n);
    }
}
