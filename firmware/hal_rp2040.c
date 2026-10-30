/*
 * HAL для RP2040 (Pico) и RP2350 (Pico 2).
 *
 * flash: последние STORE_TOTAL_BYTES внешней QSPI-flash; запись посекторно через
 *        flash_safe_execute (прерывания выключены только на один сектор).
 * RNG:   пул BLAKE2b из нескольких независимых источников (pico_rand — на RP2350
 *        это аппаратный TRNG; биты ROSC; шум АЦП датчика температуры; время),
 *        выдача — «быстрое стирание ключа»: каждый вызов перешифровывает пул.
 * LED:   встроенный светодиод платы (GPIO 25 на Pico/Pico 2).
 */
#include "board.h"
#include "hal.h"
#include "monocypher.h"
#include "store.h"

#include "hardware/adc.h"
#include "hardware/flash.h"
#include "hardware/structs/rosc.h"
#include "hardware/sync.h"
#include "pico/flash.h"
#include "pico/rand.h"
#include "pico/stdlib.h"
#include "pico/unique_id.h"
#include <string.h>

#define REGION_SIZE  STORE_TOTAL_BYTES
#define REGION_OFF   (PICO_FLASH_SIZE_BYTES - REGION_SIZE)

_Static_assert(REGION_SIZE % FLASH_SECTOR_SIZE == 0, "область токена — целые секторы");
_Static_assert(HAL_FLASH_SECTOR == FLASH_SECTOR_SIZE, "размер сектора");

extern char __flash_binary_end;   /* из линкер-скрипта pico-sdk */

/* ---------------- время ---------------- */

uint64_t hal_millis(void) { return time_us_64() / 1000u; }

/* ---------------- flash ---------------- */

uint32_t hal_flash_size(void) { return REGION_SIZE; }

int hal_flash_read(uint32_t off, void *buf, uint32_t len)
{
    if (off > REGION_SIZE || len > REGION_SIZE - off) return -1;
    memcpy(buf, (const void *)(XIP_BASE + REGION_OFF + off), len);
    return 0;
}

typedef struct {
    uint32_t       off;     /* от начала flash */
    const uint8_t *data;    /* в RAM */
} sector_job;

static void write_sector(void *p)
{
    const sector_job *j = p;
    flash_range_erase(j->off, FLASH_SECTOR_SIZE);
    flash_range_program(j->off, j->data, FLASH_SECTOR_SIZE);
}

int hal_flash_write_sectors(uint32_t off, const void *buf, uint32_t len)
{
    if (off % FLASH_SECTOR_SIZE || len % FLASH_SECTOR_SIZE) return -1;
    if (off > REGION_SIZE || len > REGION_SIZE - off) return -1;
    const uint8_t *src = buf;
    for (uint32_t done = 0; done < len; done += FLASH_SECTOR_SIZE) {
        sector_job j = {REGION_OFF + off + done, src + done};
        if (flash_safe_execute(write_sector, &j, 1000) != PICO_OK) return -1;
        /* проверка записи: XIP-кэш сброшен flash_range_program */
        if (memcmp((const void *)(XIP_BASE + j.off), j.data, FLASH_SECTOR_SIZE) != 0) return -1;
    }
    return 0;
}

/* ---------------- RNG ---------------- */

static uint8_t  g_pool[64];
static uint64_t g_counter;

static void mix(crypto_blake2b_ctx *ctx, const void *p, size_t n) { crypto_blake2b_update(ctx, p, n); }

static void gather_entropy(void)
{
    crypto_blake2b_ctx ctx;
    crypto_blake2b_init(&ctx, sizeof g_pool);
    mix(&ctx, "pmtoken rng v1", 14);

    /* pico_rand: RP2350 — TRNG; RP2040 — ROSC, счётчики шины, время */
    for (int i = 0; i < 8; i++) {
        rng_128_t r;
        get_rand_128(&r);
        mix(&ctx, &r, sizeof r);
    }

    /* сырые биты кольцевого генератора: его частота дрожит от температуры и питания */
    uint8_t bits[64];
    for (size_t i = 0; i < sizeof bits; i++) {
        uint8_t b = 0;
        for (int k = 0; k < 8; k++) {
            busy_wait_us_32(1);
            b = (uint8_t)(b << 1 | (rosc_hw->randombit & 1u));
        }
        bits[i] = b;
    }
    mix(&ctx, bits, sizeof bits);

    /* младшие биты АЦП датчика температуры — тепловой шум */
    adc_init();
    adc_set_temp_sensor_enabled(true);
    adc_select_input(ADC_TEMPERATURE_CHANNEL_NUM);
    uint16_t samples[128];
    for (size_t i = 0; i < 128; i++) samples[i] = adc_read();
    adc_set_temp_sensor_enabled(false);
    mix(&ctx, samples, sizeof samples);

    pico_unique_board_id_t id;
    pico_get_unique_board_id(&id);
    mix(&ctx, &id, sizeof id);
    uint64_t t = time_us_64();
    mix(&ctx, &t, sizeof t);

    crypto_blake2b_final(&ctx, g_pool);
    crypto_wipe(bits, sizeof bits);
    crypto_wipe(samples, sizeof samples);
}

void hal_rng(void *buf, size_t len)
{
    uint8_t *out = buf;
    while (len) {
        uint8_t block[64], msg[8 + 16 + 1];
        rng_128_t fresh;
        get_rand_128(&fresh);              /* свежая добавка на каждый блок */
        memcpy(msg, &g_counter, 8);
        memcpy(msg + 8, &fresh, 16);
        msg[24] = 'o';
        crypto_blake2b_keyed(block, sizeof block, g_pool, sizeof g_pool, msg, sizeof msg);
        msg[24] = 'k';                     /* новый пул: прошлые выдачи не восстановить */
        crypto_blake2b_keyed(g_pool, sizeof g_pool, g_pool, sizeof g_pool, msg, sizeof msg);
        g_counter++;
        size_t n = len < sizeof block ? len : sizeof block;
        memcpy(out, block, n);
        crypto_wipe(block, sizeof block);
        out += n;
        len -= n;
    }
}

/* ---------------- светодиод ---------------- */

static hal_led_t g_led = LED_IDLE;
static uint64_t  g_error_until;

void hal_led(hal_led_t state)
{
    if (state == LED_ERROR) g_error_until = hal_millis() + 1500;
    else g_led = state;
}

void board_led_task(void)
{
#ifdef PICO_DEFAULT_LED_PIN
    uint64_t t = hal_millis();
    bool on;
    if (t < g_error_until) on = (t / 100) % 2;                     /* часто: ошибка */
    else switch (g_led) {
    case LED_UNLOCKED: on = true; break;                           /* горит: хранилище открыто */
    case LED_SESSION:  on = t % 1000 < 80; break;                  /* раз в секунду: сессия */
    default:           on = t % 3000 < 30; break;                  /* редкая вспышка: ждёт */
    }
    gpio_put(PICO_DEFAULT_LED_PIN, on);
#endif
}

int board_init(void)
{
#ifdef PICO_DEFAULT_LED_PIN
    gpio_init(PICO_DEFAULT_LED_PIN);
    gpio_set_dir(PICO_DEFAULT_LED_PIN, GPIO_OUT);
#endif
    gather_entropy();
    /* прошивка не должна заходить в область хранилища */
    if ((uintptr_t)&__flash_binary_end > XIP_BASE + REGION_OFF) return -1;
    return 0;
}
