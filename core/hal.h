/*
 * HAL — единственное, что отличает симулятор от реального RP2040.
 * Ядро (token.c, vault.c, session.c) вызывает только эти функции.
 *
 * Реализации:
 *   sim/hal_sim.c      — ПК: flash = файл, RNG = ОС, время = монотонные часы
 *   firmware/hal_rp2040.c (следующий этап) — flash_range_erase/program,
 *                         pico_rand, time_us_64()
 */
#ifndef PM_HAL_H
#define PM_HAL_H

#include <stddef.h>
#include <stdint.h>

#define HAL_FLASH_SECTOR 4096u          /* как у RP2040 */

/* Размер области flash, отданной токену (байт, кратно сектору). */
uint32_t hal_flash_size(void);

/* Чтение из области токена. 0 = ок. */
int hal_flash_read(uint32_t off, void *buf, uint32_t len);

/* Стереть и записать целые секторы (off и len кратны HAL_FLASH_SECTOR).
 * На RP2040: flash_range_erase + flash_range_program. 0 = ок. */
int hal_flash_write_sectors(uint32_t off, const void *buf, uint32_t len);

/* Криптографически стойкие случайные байты. */
void hal_rng(void *buf, size_t len);

/* Миллисекунды с момента включения (монотонно). */
uint64_t hal_millis(void);

/* Индикация состояния (WS2812 на плате; в симуляторе — лог). */
typedef enum { LED_IDLE, LED_SESSION, LED_UNLOCKED, LED_ERROR } hal_led_t;
void hal_led(hal_led_t state);

#endif
