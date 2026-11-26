/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * pmdiag: диагностика платы на RP2040, на которой не запускается pmtoken.
 *
 * Работает целиком из RAM (no_flash UF2: загрузчик RP2040 кладёт её в память и
 * запускает), поэтому не зависит от флеш-памяти и не стирает прошивку. Проверяет:
 * чип и загрузчик, частоты, флеш (JEDEC, SFDP, регистры состояния, чтение на разных
 * скоростях, загрузчик второй стадии из флеша, запись в свободный сектор) и что
 * лежит во флеше. Отчёт — файл REPORT.TXT на USB-диске «PMDIAG» и тот же текст
 * в COM-порт. Заодно ищет светодиод: мигает по очереди GPIO 16–25.
 *
 * Рискованные этапы (общение с флешем) под сторожевым таймером: если этап завис,
 * через 4 с диагностика перезапускается в себя (RAM не стирается), этап
 * пропускается и в отчёте отмечен как зависший.
 *
 * PMDIAG_FLASH=1 (цель pmdiag_flash): та же диагностика как обычная прошивка во флеш.
 * Отвечает на вопрос «запускается ли с этой платы хоть что-то из флеш» и по одному
 * прогоняет настоящие шаги запуска pmtoken (board_init, token_init — тот же код,
 * что в прошивке) под сторожевым таймером; зависший шаг попадает в отчёт.
 * Прямые тесты флеш (SSI, запись) здесь не делаются: код сам исполняется из флеш.
 */
#include "diag_disk.h"

#include "hardware/clocks.h"
#include "hardware/gpio.h"
#include "hardware/pio.h"
#include "hardware/structs/clocks.h"
#include "hardware/structs/ioqspi.h"
#include "hardware/structs/ssi.h"
#include "hardware/structs/sysinfo.h"
#include "hardware/structs/vreg_and_chip_reset.h"
#include "hardware/structs/watchdog.h"
#include "hardware/structs/xosc.h"
#include "hardware/watchdog.h"
#include "pico/bootrom.h"
#include "pico/stdlib.h"
#include "tusb.h"
#include "../ws2812_pio.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#ifndef PMDIAG_FLASH
#define PMDIAG_FLASH 0
#endif
#if PMDIAG_FLASH
#include "hardware/adc.h"
#include "hardware/flash.h"
#include "pico/flash.h"
#include "pico/rand.h"
int  board_init(void);                 /* firmware/hal_rp2040.c */
void token_init(void);                 /* core/token.c */
#endif

#define DIAG_VERSION "2"

/* ---------------- отчёт ---------------- */

static char   g_rep[16 * 1024];      /* отчёт ~3 КБ; диск вмещает до DISK_FILE_MAX */
static size_t g_len;

static void line(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    size_t room = sizeof g_rep - g_len;
    int n = vsnprintf(g_rep + g_len, room, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    g_len += (size_t)n < room ? (size_t)n : room - 1;
    if (sizeof g_rep - g_len > 2) { g_rep[g_len++] = '\r'; g_rep[g_len++] = '\n'; g_rep[g_len] = 0; }
}

static void __unused hex(const char *label, const uint8_t *p, size_t n)
{
    char buf[3 * 64 + 1];
    size_t k = 0;
    for (size_t i = 0; i < n && i < 64; i++) k += (size_t)snprintf(buf + k, sizeof buf - k, "%02X ", p[i]);
    if (k) buf[k - 1] = 0; else buf[0] = 0;
    line("%s%s", label, buf);
}

/* ---------------- сторожевой таймер для рискованных этапов ---------------- */

enum { ST_JEDEC = 1, ST_READ, ST_SPEED, ST_WRITE, ST_BOOT2,
       ST_ADC, ST_RAND, ST_FLASHCMD, ST_BOARD, ST_TOKEN, ST_COUNT };
static const char *const st_name[ST_COUNT] = {
    [ST_JEDEC] = "опрос флеш (JEDEC/SFDP/регистры)",
    [ST_READ]  = "чтение флеш",
    [ST_SPEED] = "чтение флеш на разных скоростях",
    [ST_WRITE] = "запись флеш",
    [ST_BOOT2] = "загрузчик второй стадии из флеш",
    [ST_ADC]   = "АЦП: датчик температуры",
    [ST_RAND]  = "pico_rand",
    [ST_FLASHCMD] = "flash_safe_execute + команда флеш",
    [ST_BOARD] = "board_init прошивки",
    [ST_TOKEN] = "token_init прошивки",
};

#define WD_STAGE 0x504D4400u          /* scratch0: «PMD» + номер идущего этапа */
#define WD_HUNG  0x5D1A0000u          /* scratch1: маска этапов, зависших раньше */
static uint32_t g_hung;
static bool     g_restarted;

static void guard_init(void)
{
    uint32_t s0 = watchdog_hw->scratch[0], s1 = watchdog_hw->scratch[1];
    if ((s1 & 0xFFFF0000u) == WD_HUNG) g_hung = s1 & 0xFFFFu;
    if ((s0 & 0xFFFFFF00u) == WD_STAGE && (s0 & 0xFFu) < ST_COUNT) {
        g_hung |= 1u << (s0 & 0xFFu);
        g_restarted = true;
    }
    watchdog_hw->scratch[0] = 0;
    watchdog_hw->scratch[1] = WD_HUNG | g_hung;
}

static bool stage_begin(int st)
{
    if (g_hung & (1u << st)) {
        line("  ! этап «%s» завис в прошлый запуск (сработал сторожевой таймер) — пропущен", st_name[st]);
        return false;
    }
    watchdog_hw->scratch[0] = WD_STAGE | (uint32_t)st;
#if PMDIAG_FLASH
    watchdog_reboot(0, 0, 4000);                  /* зависли — обычная перезагрузка из флеш */
#else
    watchdog_reboot(SRAM_BASE, SRAM_END, 4000);   /* зависли — перезапуск в себя (RAM цела) */
#endif
    return true;
}

static void stage_end(void)
{
    hw_clear_bits(&watchdog_hw->ctrl, WATCHDOG_CTRL_ENABLE_BITS);
    watchdog_hw->scratch[0] = 0;
    watchdog_hw->scratch[4] = 0;
}

/* CRC-32 без отражения, полином 0x04C11DB7 (как у загрузчика второй стадии) */
static uint32_t crc32_mpeg(const uint8_t *p, size_t n, uint32_t crc)
{
    while (n--) {
        crc ^= (uint32_t)*p++ << 24;
        for (int k = 0; k < 8; k++) crc = crc & 0x80000000u ? crc << 1 ^ 0x04C11DB7u : crc << 1;
    }
    return crc;
}

#if !PMDIAG_FLASH
/* ---------------- флеш напрямую через SSI ---------------- */

static void cs_force(bool high)
{
    hw_write_masked(&ioqspi_hw->io[1].ctrl,
                    (high ? IO_QSPI_GPIO_QSPI_SS_CTRL_OUTOVER_VALUE_HIGH : IO_QSPI_GPIO_QSPI_SS_CTRL_OUTOVER_VALUE_LOW)
                        << IO_QSPI_GPIO_QSPI_SS_CTRL_OUTOVER_LSB,
                    IO_QSPI_GPIO_QSPI_SS_CTRL_OUTOVER_BITS);
}

/* Последовательный режим SSI (как у ROM), частота clk_sys/div. */
static void spi_begin(uint32_t div)
{
    rom_connect_internal_flash();
    rom_flash_exit_xip();
    ssi_hw->ssienr = 0;
    ssi_hw->baudr = div;
    ssi_hw->rx_sample_dly = 0;
    ssi_hw->ssienr = 1;
}

/* Вернуть XIP (ROM: команда 0x03) — для чтения через окно XIP. */
static void xip_begin(uint32_t div, uint32_t rxdly)
{
    rom_connect_internal_flash();
    rom_flash_exit_xip();
    rom_flash_enter_cmd_xip();
    ssi_hw->ssienr = 0;
    ssi_hw->baudr = div;
    ssi_hw->rx_sample_dly = rxdly;
    ssi_hw->ssienr = 1;
    rom_flash_flush_cache();
}

/* hdr уходит во флеш, затем nd байт читаются в data (в это время шлём нули). 0 = таймаут. */
static bool spi_cmd(const uint8_t *hdr, size_t nh, uint8_t *data, size_t nd)
{
    size_t n = nh + nd, txi = 0, rxi = 0;
    uint32_t t0 = time_us_32();
    bool ok = true;
    cs_force(false);
    while (rxi < n) {
        if (time_us_32() - t0 > 300000u) { ok = false; break; }
        uint32_t f = ssi_hw->sr;
        if ((f & SSI_SR_TFNF_BITS) && txi < n && txi - rxi < 14) {
            ssi_hw->dr0 = txi < nh ? hdr[txi] : 0;
            txi++;
        }
        if ((f & SSI_SR_RFNE_BITS) && rxi < txi) {
            uint8_t b = (uint8_t)ssi_hw->dr0;
            if (rxi >= nh && data) data[rxi - nh] = b;
            rxi++;
        }
    }
    cs_force(true);
    return ok;
}

static bool spi_op(uint8_t op, uint8_t *data, size_t nd) { return spi_cmd(&op, 1, data, nd); }

static bool spi_read(uint32_t addr, uint8_t *data, size_t n)
{
    while (n) {
        size_t k = n < 4096 ? n : 4096;
        uint8_t h[4] = {0x03, (uint8_t)(addr >> 16), (uint8_t)(addr >> 8), (uint8_t)addr};
        if (!spi_cmd(h, 4, data, k)) return false;
        addr += (uint32_t)k;
        data += k;
        n -= k;
        watchdog_update();
    }
    return true;
}

#endif /* !PMDIAG_FLASH */

/* ---------------- этапы ---------------- */

#if !PMDIAG_FLASH
static uint8_t g_jedec[3];
static uint8_t g_boot2[256];
static bool    g_boot2_ok;
#define REF_BYTES (64u * 1024u)
static uint8_t g_ref[REF_BYTES];      /* эталон: медленное чтение первых 64 КБ */
static uint8_t g_tmp[4096];
static bool    g_ref_ok;
#endif

static uint32_t fc_khz(uint32_t src)
{
    uint32_t t0 = time_us_32();
    while (clocks_hw->fc0.status & CLOCKS_FC0_STATUS_RUNNING_BITS)
        if (time_us_32() - t0 > 50000u) return 0;
    clocks_hw->fc0.ref_khz = clock_get_hz(clk_ref) / 1000u;
    clocks_hw->fc0.interval = 10;
    clocks_hw->fc0.min_khz = 0;
    clocks_hw->fc0.max_khz = 0xFFFFFFFFu;
    clocks_hw->fc0.src = src;
    t0 = time_us_32();
    while (!(clocks_hw->fc0.status & CLOCKS_FC0_STATUS_DONE_BITS))
        if (time_us_32() - t0 > 50000u) return 0;
    return clocks_hw->fc0.result >> CLOCKS_FC0_RESULT_KHZ_LSB;
}

static void report_chip(void)
{
    uint32_t id = sysinfo_hw->chip_id;
    uint32_t rev = (id & SYSINFO_CHIP_ID_REVISION_BITS) >> SYSINFO_CHIP_ID_REVISION_LSB;
    uint32_t part = (id & SYSINFO_CHIP_ID_PART_BITS) >> SYSINFO_CHIP_ID_PART_LSB;
    uint8_t rom = rp2040_rom_version();
    line("[Чип]");
    line("  CHIP_ID 0x%08lX: part 0x%04lX, revision %lu; загрузчик ROM v%u (%s)", (unsigned long)id,
         (unsigned long)part, (unsigned long)rev, rom, rom == 1 ? "B0" : rom == 2 ? "B1" : rom == 3 ? "B2" : "?");
    uint32_t r = vreg_and_chip_reset_hw->chip_reset;
    line("  причина сброса: %s%s%s", r & VREG_AND_CHIP_RESET_CHIP_RESET_HAD_POR_BITS ? "питание " : "",
         r & VREG_AND_CHIP_RESET_CHIP_RESET_HAD_RUN_BITS ? "кнопка/RUN " : "",
         r & VREG_AND_CHIP_RESET_CHIP_RESET_HAD_PSM_RESTART_BITS ? "отладчик " : "");
    uint32_t vsel = (vreg_and_chip_reset_hw->vreg & VREG_AND_CHIP_RESET_VREG_VSEL_BITS) >> VREG_AND_CHIP_RESET_VREG_VSEL_LSB;
    line("  ядро: VSEL=%lu (11 = 1,10 В по умолчанию)", (unsigned long)vsel);
    if (g_restarted) line("  диагностика перезапускалась сторожевым таймером: один из этапов завис");
    line("");

    line("[Частоты] (кГц, измерены счётчиком частоты от кварца)");
    line("  clk_sys %lu, pll_sys %lu, pll_usb %lu, clk_usb %lu, rosc %lu, xosc %lu",
         (unsigned long)fc_khz(CLOCKS_FC0_SRC_VALUE_CLK_SYS), (unsigned long)fc_khz(CLOCKS_FC0_SRC_VALUE_PLL_SYS_CLKSRC_PRIMARY),
         (unsigned long)fc_khz(CLOCKS_FC0_SRC_VALUE_PLL_USB_CLKSRC_PRIMARY), (unsigned long)fc_khz(CLOCKS_FC0_SRC_VALUE_CLK_USB),
         (unsigned long)fc_khz(CLOCKS_FC0_SRC_VALUE_ROSC_CLKSRC), (unsigned long)fc_khz(CLOCKS_FC0_SRC_VALUE_XOSC_CLKSRC));
    line("  ожидается: clk_sys 125000, pll_usb/clk_usb 48000, xosc 12000 (0 — счётчик не ответил)");
    line("  XOSC: STATUS 0x%08lX, STARTUP %lu (64 мс = 3008)", (unsigned long)xosc_hw->status,
         (unsigned long)(xosc_hw->startup & XOSC_STARTUP_DELAY_BITS));
    line("");
}

#if !PMDIAG_FLASH
static const char *vendor(uint8_t m)
{
    switch (m) {
    case 0xEF: return "Winbond";
    case 0xC8: return "GigaDevice";
    case 0xC2: return "Macronix";
    case 0x9D: return "ISSI";
    case 0x85: return "Puya";
    case 0x68: return "BoYa";
    case 0x0B: return "XTX";
    case 0x5E: return "Zbit";
    case 0x20: return "XMC/Micron";
    case 0x1F: return "Adesto";
    case 0xBA: return "Zetta";
    case 0xA1: return "Fudan";
    case 0x1C: return "EON";
    case 0xE0: return "PCT/Paragon";
    default:   return "неизвестный";
    }
}

static void report_flash_id(void)
{
    line("[Флеш: опознание]");
    if (!stage_begin(ST_JEDEC)) { line(""); return; }
    spi_begin(32);                    /* ~3,9 МГц: заведомо медленно */
    bool ok = spi_op(0x9F, g_jedec, 3);
    line("  JEDEC ID: %02X %02X %02X — %s%s", g_jedec[0], g_jedec[1], g_jedec[2], vendor(g_jedec[0]),
         ok ? "" : " (ТАЙМАУТ SSI)");
    if (g_jedec[2] >= 0x10 && g_jedec[2] <= 0x19)
        line("  объём по JEDEC: %lu КБ", (unsigned long)((1u << g_jedec[2]) / 1024u));
    if ((g_jedec[0] == 0 && g_jedec[1] == 0) || g_jedec[0] == 0xFF)
        line("  ! флеш не отвечает на 0x9F: нет связи по SPI (пайка, питание флеш, линия CS/SCK/SD0/SD1)");

    uint8_t sr1 = 0, sr2 = 0, sr3 = 0;
    spi_op(0x05, &sr1, 1);
    /* 0x35 у Macronix и ISSI — «войти в QPI», а не «прочитать SR2»: не трогаем */
    bool qpi35 = g_jedec[0] == 0xC2 || g_jedec[0] == 0x9D;
    if (!qpi35) spi_op(0x35, &sr2, 1);
    spi_op(0x15, &sr3, 1);
    if (qpi35) line("  SR1 %02X, 0x15 %02X (SR2 не читаем: 0x35 у этого производителя включает QPI)", sr1, sr3);
    else line("  SR1 %02X, SR2 %02X, SR3 %02X; QE (SR2 бит 1) = %d, защита BP (SR1 биты 2-4) = %d", sr1, sr2, sr3,
              (sr2 >> 1) & 1, (sr1 >> 2) & 7);

    uint8_t uid[8] = {0};
    uint8_t h4b[5] = {0x4B, 0, 0, 0, 0};
    spi_cmd(h4b, 5, uid, 8);
    hex("  уникальный ID (0x4B): ", uid, 8);

    uint8_t sfdp[16] = {0};
    uint8_t hs[5] = {0x5A, 0, 0, 0, 0};
    spi_cmd(hs, 5, sfdp, 16);
    if (memcmp(sfdp, "SFDP", 4) == 0) {
        uint32_t ptr = sfdp[12] | (uint32_t)sfdp[13] << 8 | (uint32_t)sfdp[14] << 16;
        uint32_t ndw = sfdp[11];
        line("  SFDP %u.%u, таблица BFPT: %lu слов по адресу 0x%06lX", sfdp[5], sfdp[4], (unsigned long)ndw,
             (unsigned long)ptr);
        uint8_t bf[64] = {0};
        uint8_t hb[5] = {0x5A, (uint8_t)(ptr >> 16), (uint8_t)(ptr >> 8), (uint8_t)ptr, 0};
        if (ndw > 16) ndw = 16;
        spi_cmd(hb, 5, bf, ndw * 4);
        uint32_t d2 = bf[4] | (uint32_t)bf[5] << 8 | (uint32_t)bf[6] << 16 | (uint32_t)bf[7] << 24;
        if (d2 && d2 != 0xFFFFFFFFu) {
            uint32_t kb = d2 & 0x80000000u ? (1u << ((d2 & 0x7FFFFFFFu) - 13)) : (d2 + 1u) / 8192u;
            line("  объём по SFDP: %lu КБ", (unsigned long)kb);
        }
        if (ndw >= 15) {
            uint32_t d15 = bf[56] | (uint32_t)bf[57] << 8 | (uint32_t)bf[58] << 16 | (uint32_t)bf[59] << 24;
            uint32_t qer = (d15 >> 20) & 7;
            static const char *const q[8] = {
                "000 — нет бита QE", "001 — бит 1 SR2, запись 0x01 двумя байтами",
                "010 — бит 6 SR1 (как Macronix/ISSI)", "011 — бит 7 SR2 (0x3E/0x3F)",
                "100 — бит 1 SR2, запись 0x01 двумя байтами", "101 — бит 1 SR2, чтение 0x35, запись 0x01",
                "110 — бит 1 SR2, чтение 0x35, запись 0x31", "111 — резерв"};
            line("  включение Quad (QER) %s", q[qer]);
            line("  (boot2 для Pico пишет SR2 командой 0x01 двумя байтами: подходит для 001/100/101)");
        }
    } else {
        hex("  SFDP нет; ответ: ", sfdp, 8);
    }
    stage_end();
    line("");
}

static void report_flash_content(void)
{
    line("[Флеш: что записано]");
    if (!stage_begin(ST_READ)) { line(""); return; }
    spi_begin(32);
    bool ok = spi_read(0, g_ref, REF_BYTES);
    size_t bad = 0, first = 0;
    for (uint32_t off = 0; ok && off < REF_BYTES; off += sizeof g_tmp) {   /* второе чтение — сверка */
        ok = spi_read(off, g_tmp, sizeof g_tmp);
        for (size_t i = 0; ok && i < sizeof g_tmp; i++)
            if (g_tmp[i] != g_ref[off + i]) { if (!bad) first = off + i; bad++; }
    }
    g_ref_ok = ok && !bad;
    if (!ok) line("  ! таймаут SSI при чтении");
    else if (bad)
        line("  ! два медленных чтения первых 64 КБ не совпали: %lu байт, первое — 0x%05lX. Флеш читается нестабильно",
             (unsigned long)bad, (unsigned long)first);
    else line("  два медленных чтения первых 64 КБ совпали");

    memcpy(g_boot2, g_ref, sizeof g_boot2);
    uint32_t want = g_boot2[252] | (uint32_t)g_boot2[253] << 8 | (uint32_t)g_boot2[254] << 16 | (uint32_t)g_boot2[255] << 24;
    uint32_t crc = crc32_mpeg(g_boot2, 252, 0xFFFFFFFFu);
    bool blank = true;
    for (int i = 0; i < 256; i++) if (g_boot2[i] != 0xFF) { blank = false; break; }
    g_boot2_ok = !blank && crc == want;
    bool quad = false;
    for (int i = 0; i + 1 < 252; i += 2) if (g_boot2[i] == 0x35 && g_boot2[i + 1] == 0x20) quad = true;  /* movs r0, #0x35 */
    if (blank) line("  boot2: флеш пуста (0xFF) — прошивки нет");
    else line("  boot2: CRC %s (0x%08lX, в образе 0x%08lX), %s", g_boot2_ok ? "верна" : "НЕВЕРНА", (unsigned long)crc,
              (unsigned long)want, quad ? "Quad с командами Winbond (сборка для Pico/Zero)" : "без команды 0x35 (универсальная или чужая)");
    hex("  boot2[0..16): ", g_boot2, 16);

    /* искать подпись pmtoken в первых 256 КБ через окно XIP (ROM, 0x03, медленно) */
    xip_begin(16, 0);
    const uint8_t *x = (const uint8_t *)XIP_BASE;          /* через кэш: строками по 8 байт */
    long at = -1;
    for (uint32_t i = 0; i + 7 <= 256u * 1024u && at < 0; i++) {
        if (x[i] == 'p' && memcmp(x + i, "pmtoken", 7) == 0) at = (long)i;
        if ((i & 0xFFFF) == 0) watchdog_update();
    }
    if (at >= 0) line("  строка «pmtoken» найдена по смещению 0x%05lX — прошивка токена записана", at);
    else line("  строки «pmtoken» в первых 256 КБ нет — прошивка токена не записана или испорчена");

    line("  CRC по 4 КБ первых 128 КБ (для сверки с .uf2):");
    for (uint32_t blk = 0; blk < 32; blk += 4) {
        uint32_t c[4];
        for (int k = 0; k < 4; k++) {
            uint32_t off = (blk + (uint32_t)k) * 4096u;
            if (off + 4096u <= REF_BYTES) c[k] = crc32_mpeg(g_ref + off, 4096, 0xFFFFFFFFu);
            else { memcpy(g_tmp, x + off, 4096); c[k] = crc32_mpeg(g_tmp, 4096, 0xFFFFFFFFu); }
        }
        line("    %05lX: %08lX %08lX %08lX %08lX", (unsigned long)(blk * 4096u), (unsigned long)c[0],
             (unsigned long)c[1], (unsigned long)c[2], (unsigned long)c[3]);
    }
    stage_end();
    line("");
}

/* Прочитать первые 64 КБ через уже настроенное окно XIP и сравнить с эталоном. */
static void xip_compare(const char *what)
{
    const uint8_t *x = (const uint8_t *)XIP_NOCACHE_NOALLOC_BASE;
    size_t bad = 0, first = 0;
    for (size_t i = 0; i < REF_BYTES; i++) {
        if (x[i] != g_ref[i]) { if (!bad) first = i; bad++; }
        if ((i & 0x3FFF) == 0) watchdog_update();
    }
    if (!bad) line("  %s: 64 КБ совпали", what);
    else line("  %s: НЕ совпало %lu байт из 65536, первое по 0x%05lX", what, (unsigned long)bad, (unsigned long)first);
}

static void report_speed(void)
{
    line("[Флеш: чтение 0x03 через XIP на разных частотах] (эталон — медленное чтение)");
    if (!g_ref_ok) { line("  пропущено: нет надёжного эталона"); line(""); return; }
    if (!stage_begin(ST_SPEED)) { line(""); return; }
    xip_begin(8, 0);  xip_compare("clk_sys/8 = 15,6 МГц");
    xip_begin(4, 0);  xip_compare("clk_sys/4 = 31,3 МГц (универсальная прошивка)");
    xip_begin(2, 1);  xip_compare("clk_sys/2 = 62,5 МГц (выше нормы 0x03 у многих чипов)");
    stage_end();
    line("");
}

#define TEST_SECTOR 0x3F000u           /* последний сектор места под прошивку: pmtoken его не использует */

static bool all_ff(const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++) if (p[i] != 0xFF) return false;
    return true;
}

static void report_write(void)
{
    line("[Флеш: запись] (сектор 0x%05lX — свободен и у pmtoken, после проверки стирается)", (unsigned long)TEST_SECTOR);
    if (!stage_begin(ST_WRITE)) { line(""); return; }
    static uint8_t pat[256];
    for (int i = 0; i < 256; i++) pat[i] = (uint8_t)(i * 7 + 0x5A);

    spi_begin(32);
    rom_flash_range_erase(TEST_SECTOR, 4096, 1u << 16, 0xD8);
    spi_begin(32);
    spi_read(TEST_SECTOR, g_tmp, 4096);
    bool erased = all_ff(g_tmp, 4096);
    watchdog_update();

    spi_begin(32);                    /* каждый вызов ROM — с чистого подключения флеш */
    rom_flash_range_program(TEST_SECTOR, pat, sizeof pat);
    spi_begin(32);
    spi_read(TEST_SECTOR, g_tmp, sizeof pat);
    bool programmed = memcmp(g_tmp, pat, sizeof pat) == 0;
    watchdog_update();

    spi_begin(32);
    rom_flash_range_erase(TEST_SECTOR, 4096, 1u << 16, 0xD8);
    spi_begin(32);
    spi_read(TEST_SECTOR, g_tmp, 4096);
    bool erased2 = all_ff(g_tmp, 4096);
    rom_flash_flush_cache();

    line("  стирание: %s; запись: %s; повторное стирание: %s", erased ? "ок" : "НЕ стёрлось",
         programmed ? "ок" : "НЕ записалось", erased2 ? "ок" : "НЕ стёрлось");
    if (!erased || !programmed) line("  ! флеш не принимает запись: защита (биты BP) или несовместимые команды");
    stage_end();
    line("");
}

/* Выполнить boot2 из флеш так же, как это делает загрузчик ROM, и проверить чтение через XIP. */
static void report_boot2(void)
{
    line("[Загрузчик второй стадии из флеш]");
    if (!g_boot2_ok) { line("  пропущено: boot2 во флеш нет или CRC неверна"); line(""); return; }
    if (!g_ref_ok) { line("  пропущено: нет надёжного эталона"); line(""); return; }
    if (!stage_begin(ST_BOOT2)) { line(""); return; }
    static uint32_t code[64];         /* boot2 позиционно-независим: SDK так же копирует его в RAM */
    memcpy(code, g_boot2, sizeof code);
    rom_connect_internal_flash();
    rom_flash_exit_xip();
    ((void (*)(void))((uintptr_t)code | 1u))();
    rom_flash_flush_cache();
    xip_compare("после boot2 из флеш");
    line("  SSI: BAUDR %lu, CTRLR0 0x%08lX, SPI_CTRLR0 0x%08lX", (unsigned long)ssi_hw->baudr,
         (unsigned long)ssi_hw->ctrlr0, (unsigned long)ssi_hw->spi_ctrlr0);
    xip_begin(16, 0);                 /* назад в простой режим 0x03 (выход из continuous read) */
    stage_end();
    line("");
}
#endif /* !PMDIAG_FLASH */

#if PMDIAG_FLASH
static uint64_t g_t_main;

static void jedec_cb(void *p)
{
    uint8_t tx[4] = {0x9F, 0, 0, 0}, rx[4] = {0};
    flash_do_cmd(tx, rx, sizeof tx);
    memcpy(p, rx + 1, 3);
}

static void report_flash_boot(void)
{
    line("[Запуск из флеш]");
    line("  диагностика запустилась из флеш: значит, загрузка с флеш на этой плате работает");
    line("  таймер при входе в main: %lu мс", (unsigned long)(g_t_main / 1000u));
    uint8_t b2[256];
    memcpy(b2, (const void *)XIP_BASE, sizeof b2);
    uint32_t want = b2[252] | (uint32_t)b2[253] << 8 | (uint32_t)b2[254] << 16 | (uint32_t)b2[255] << 24;
    bool quad = false;
    for (int i = 0; i + 1 < 252; i += 2) if (b2[i] == 0x35 && b2[i + 1] == 0x20) quad = true;
    line("  boot2: CRC %s, %s", crc32_mpeg(b2, 252, 0xFFFFFFFFu) == want ? "верна" : "НЕВЕРНА",
         quad ? "Quad с командами Winbond" : "generic_03h");
    line("");
}

/* Шаги запуска pmtoken в том же порядке, что в прошивке, до включения USB. */
static void report_pmtoken_steps(void)
{
    line("[Шаги запуска pmtoken] (по одному, под сторожевым таймером, до включения USB — как в прошивке)");
    uint64_t t;
    if (stage_begin(ST_ADC)) {
        t = time_us_64();
        adc_init();
        adc_set_temp_sensor_enabled(true);
        adc_select_input(ADC_TEMPERATURE_CHANNEL_NUM);
        uint16_t lo = 0xFFFF, hi = 0;
        for (int i = 0; i < 128; i++) {
            uint16_t v = adc_read();
            if (v < lo) lo = v;
            if (v > hi) hi = v;
        }
        adc_set_temp_sensor_enabled(false);
        stage_end();
        line("  АЦП, датчик температуры (128 замеров): ок за %lu мкс, значения %u..%u",
             (unsigned long)(time_us_64() - t), lo, hi);
    }
    if (stage_begin(ST_RAND)) {
        t = time_us_64();
        rng_128_t r;
        for (int i = 0; i < 8; i++) get_rand_128(&r);
        stage_end();
        line("  pico_rand (8 x 128 бит): ок за %lu мкс", (unsigned long)(time_us_64() - t));
    }
    if (stage_begin(ST_FLASHCMD)) {
        uint8_t id[3] = {0};
        t = time_us_64();
        int rc = flash_safe_execute(jedec_cb, id, 1000);
        stage_end();
        line("  flash_safe_execute + JEDEC: rc=%d (0 = ок), %02X %02X %02X, за %lu мкс", rc, id[0], id[1], id[2],
             (unsigned long)(time_us_64() - t));
    }
    if (stage_begin(ST_BOARD)) {
        t = time_us_64();
        int rc = board_init();
        stage_end();
        line("  board_init (светодиод, энтропия, размер флеш): rc=%d (0 = ок), за %lu мс", rc,
             (unsigned long)((time_us_64() - t) / 1000u));
    }
    if (stage_begin(ST_TOKEN)) {
        t = time_us_64();
        token_init();
        stage_end();
        line("  token_init (хранилище во флеш): ок за %lu мс", (unsigned long)((time_us_64() - t) / 1000u));
    }
    line("  все шаги прошли — значит, pmtoken должен доходить до USB; ищем дальше");
    line("");
}
#endif

/* ---------------- поиск светодиода ---------------- */

#define LED_FIRST 16
#define LED_LAST  25

static PIO      g_pio = pio0;
static int      g_sm = -1;
static uint     g_prog;

static void ws_attach(uint pin)
{
    if (g_sm < 0) return;
    pio_sm_set_enabled(g_pio, (uint)g_sm, false);
    pio_gpio_init(g_pio, pin);
    pio_sm_set_consecutive_pindirs(g_pio, (uint)g_sm, pin, 1, true);
    pio_sm_config c = ws2812_program_get_default_config(g_prog);
    sm_config_set_sideset_pins(&c, pin);
    sm_config_set_out_shift(&c, false, true, 24);
    sm_config_set_fifo_join(&c, PIO_FIFO_JOIN_TX);
    float bit_cycles = ws2812_T1 + ws2812_T2 + ws2812_T3;
    sm_config_set_clkdiv(&c, (float)clock_get_hz(clk_sys) / (800000.0f * bit_cycles));
    pio_sm_init(g_pio, (uint)g_sm, g_prog, &c);
    pio_sm_set_enabled(g_pio, (uint)g_sm, true);
}

static void ws_put(uint32_t grb)
{
    if (g_sm >= 0 && !pio_sm_is_tx_fifo_full(g_pio, (uint)g_sm)) pio_sm_put(g_pio, (uint)g_sm, grb << 8u);
}

/* Фаза 0 — обычный светодиод (GPIO на выход), фаза 1 — WS2812 (зелёный).
 * Пин N мигает (N − 15) раз, между пинами пауза. */
static int      g_phase, g_pin = LED_FIRST, g_flash;
static bool     g_on;
static uint64_t g_next;

static void led_release(int pin)
{
    gpio_init((uint)pin);             /* SIO, вход */
    gpio_disable_pulls((uint)pin);
}

static void led_task(void)
{
    uint64_t now = time_us_64();
    if (now < g_next) return;
    int count = g_pin - LED_FIRST + 1;
    if (!g_on && g_flash == 0) {      /* начало группы для пина */
        if (g_phase == 0) { gpio_init((uint)g_pin); gpio_set_dir((uint)g_pin, GPIO_OUT); }
        else ws_attach((uint)g_pin);
    }
    if (!g_on) {
        g_on = true;
        if (g_phase == 0) gpio_put((uint)g_pin, 1); else ws_put(0x300000u);   /* GRB: зелёный */
        g_next = now + 200000u;
        return;
    }
    g_on = false;
    if (g_phase == 0) gpio_put((uint)g_pin, 0); else ws_put(0);
    if (++g_flash < count) { g_next = now + 250000u; return; }
    g_flash = 0;
    g_next = now + 1300000u;          /* пауза между пинами */
    if (g_phase == 1) { busy_wait_us(100); pio_sm_set_enabled(g_pio, (uint)g_sm, false); }
    led_release(g_pin);
    if (++g_pin > LED_LAST) {
        g_pin = LED_FIRST;
        g_phase ^= 1;
        g_next = now + 3000000u;
    }
}

static void led_init(void)
{
    if (pio_can_add_program(g_pio, &ws2812_program)) {
        g_prog = pio_add_program(g_pio, &ws2812_program);
        g_sm = pio_claim_unused_sm(g_pio, false);
    }
    g_next = time_us_64() + 1000000u;
}

/* ---------------- USB ---------------- */

static bool   g_dtr;
static size_t g_sent;

static void cdc_task(void)
{
    bool dtr = tud_cdc_connected();
    if (dtr && !g_dtr) g_sent = 0;     /* порт открыли — отчёт с начала */
    g_dtr = dtr;
    if (!dtr || g_sent >= g_len) return;
    uint32_t n = tud_cdc_write(g_rep + g_sent, (uint32_t)(g_len - g_sent));
    g_sent += n;
    tud_cdc_write_flush();
}

int main(void)
{
#if PMDIAG_FLASH
    g_t_main = time_us_64();
#endif
    guard_init();
#if PMDIAG_FLASH
    line("HapasVault pmdiag v" DIAG_VERSION " (флеш) — диагностика платы RP2040, записана во флеш вместо прошивки");
#else
    line("HapasVault pmdiag v" DIAG_VERSION " — диагностика платы RP2040 (работает из RAM, флеш не стирает)");
#endif
    line("Пришлите этот файл целиком. Файл: REPORT.TXT на диске PMDIAG.");
    line("");
    report_chip();
#if PMDIAG_FLASH
    report_flash_boot();
    report_pmtoken_steps();
#else
    report_flash_id();
    report_flash_content();
    report_speed();
    report_write();
    report_boot2();                   /* последним: boot2 для Pico может перевести чужую флеш в QPI */
#endif

    line("[Светодиод]");
    line("  Сейчас по очереди мигают GPIO 16-25: сначала как обычный светодиод, потом как WS2812 (зелёным).");
    line("  Посчитайте вспышки в группе: GPIO = 15 + число вспышек. Например, 10 вспышек — GPIO 25.");
    line("  Напишите, сколько вспышек и какого цвета (обычные или зелёные), или что светодиод не мигает вовсе.");
    line("");
    line("Конец отчёта.");

    disk_set_file(g_rep, g_len);
    led_init();
    tud_init(0);
    for (;;) {
        tud_task();
        cdc_task();
        led_task();
    }
}
