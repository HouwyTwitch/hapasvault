/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Универсальная плата на RP2040: китайские клоны (RP2040_USB с USB-A на плате,
 * RP2040 Super Mini, YD-RP2040 и подобные), на которых прошивка для Pico
 * не запускается: после копирования .uf2 диск пропадает, а COM-порт не появляется.
 *
 * Отличия от pico.h:
 *  - флеш неизвестного производителя: boot2_generic_03h — обычное чтение 0x03
 *    без Quad-режима. Его понимает любая SPI NOR-флеш. boot2_w25q080 из pico.h
 *    включает Quad командами Winbond (0x35/0x01, чтение 0xEB), и на флеш
 *    Macronix/ISSI/части клонов процессор после загрузчика просто зависает;
 *  - частота флеш clk_sys/4 = 31 МГц: команда 0x03 у большинства чипов — до 50 МГц;
 *  - кварц: ждать запуска 64 мс вместо 6 (как у плат Adafruit): дешёвые кварцы
 *    стартуют медленно, и тогда PLL/USB не поднимаются;
 *  - светодиод: обычный на GPIO 25 (как у Pico) и WS2812 на GPIO 16 (как у
 *    RP2040-Zero) одновременно — на клоне неизвестно, какой из двух стоит.
 *    Невыведенные GPIO 16–25 на таких платах ни к чему другому не подключены.
 *
 * Объём флеш прошивка определяет сама по JEDEC ID (hal_rp2040.c); 2 МБ —
 * запасное значение на случай, если чип не ответил.
 */

// pico_cmake_set PICO_PLATFORM=rp2040

#ifndef _BOARDS_PMTOKEN_RP2040_GENERIC_H
#define _BOARDS_PMTOKEN_RP2040_GENERIC_H

#define PMTOKEN_RP2040_GENERIC

#ifndef PICO_DEFAULT_LED_PIN
#define PICO_DEFAULT_LED_PIN 25
#endif

#ifndef PICO_DEFAULT_WS2812_PIN
#define PICO_DEFAULT_WS2812_PIN 16
#endif

#ifndef PICO_BOOT_STAGE2_CHOOSE_GENERIC_03H
#define PICO_BOOT_STAGE2_CHOOSE_GENERIC_03H 1
#endif

#ifndef PICO_FLASH_SPI_CLKDIV
#define PICO_FLASH_SPI_CLKDIV 4
#endif

// pico_cmake_set_default PICO_FLASH_SIZE_BYTES = (2 * 1024 * 1024)
#ifndef PICO_FLASH_SIZE_BYTES
#define PICO_FLASH_SIZE_BYTES (2 * 1024 * 1024)
#endif

#ifndef PICO_XOSC_STARTUP_DELAY_MULTIPLIER
#define PICO_XOSC_STARTUP_DELAY_MULTIPLIER 64
#endif

#endif
