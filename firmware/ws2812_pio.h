/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Программа PIO для WS2812 — ассемблированный ws2812.pio (вывод pioasm, сверен).
 * pioasm не используется: в pico-sdk 2.1.1 он не собирается новыми GCC (нет <cstdint>),
 * а программа — четыре инструкции. Меняете ws2812.pio — обновите коды здесь.
 */
#pragma once
#include "hardware/pio.h"

#define ws2812_wrap_target 0
#define ws2812_wrap        3
#define ws2812_T1 3
#define ws2812_T2 3
#define ws2812_T3 4

static const uint16_t ws2812_program_instructions[] = {
    0x6321, /* 0: out    x, 1      side 0 [3] */
    0x1223, /* 1: jmp    !x, 3     side 1 [2] */
    0x1200, /* 2: jmp    0         side 1 [2] */
    0xa242, /* 3: nop              side 0 [2] */
};

static const struct pio_program ws2812_program = {
    .instructions = ws2812_program_instructions,
    .length = 4,
    .origin = -1,
    .pio_version = 0,
#if PICO_PIO_VERSION > 0
    .used_gpio_ranges = 0x0,
#endif
};

static inline pio_sm_config ws2812_program_get_default_config(uint offset)
{
    pio_sm_config c = pio_get_default_sm_config();
    sm_config_set_wrap(&c, offset + ws2812_wrap_target, offset + ws2812_wrap);
    sm_config_set_sideset(&c, 1, false, false);
    return c;
}
