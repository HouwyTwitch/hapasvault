/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * FAT12 на 128 секторов по 512 байт, собирается на лету:
 *   0      загрузочный сектор (BPB)
 *   1      FAT (одна копия)
 *   2      корневой каталог (16 записей): метка тома и REPORT.TXT
 *   3..127 данные: кластер = сектор, файл лежит подряд с кластера 2
 */
#include "diag_disk.h"
#include <string.h>

static const char *g_text;
static size_t      g_len;

void disk_set_file(const char *text, size_t len)
{
    g_text = text;
    g_len = len > DISK_FILE_MAX ? DISK_FILE_MAX : len;
}

static void put16(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void put32(uint8_t *p, uint32_t v) { put16(p, v); put16(p + 2, v >> 16); }

static void boot_sector(uint8_t *b)
{
    static const uint8_t jump[3] = {0xEB, 0x3C, 0x90};
    memcpy(b, jump, 3);
    memcpy(b + 3, "MSDOS5.0", 8);
    put16(b + 11, DISK_SECTOR);        /* байт в секторе */
    b[13] = 1;                         /* секторов в кластере */
    put16(b + 14, 1);                  /* зарезервировано (сам загрузочный) */
    b[16] = 1;                         /* копий FAT */
    put16(b + 17, 16);                 /* записей в корневом каталоге: 1 сектор */
    put16(b + 19, DISK_SECTORS);
    b[21] = 0xF8;                      /* несъёмный диск */
    put16(b + 22, 1);                  /* секторов в FAT */
    put16(b + 24, 1);                  /* секторов на дорожке */
    put16(b + 26, 1);                  /* головок */
    b[36] = 0x80;
    b[38] = 0x29;                      /* расширенный BPB */
    put32(b + 39, 0x504D4447u);        /* серийный номер тома */
    memcpy(b + 43, "PMDIAG     ", 11);
    memcpy(b + 54, "FAT12   ", 8);
    b[510] = 0x55;
    b[511] = 0xAA;
}

static void fat12_set(uint8_t *fat, uint32_t n, uint32_t v)
{
    uint8_t *p = fat + n * 3 / 2;
    if (n & 1) { p[0] = (uint8_t)((p[0] & 0x0F) | (v << 4)); p[1] = (uint8_t)(v >> 4); }
    else       { p[0] = (uint8_t)v; p[1] = (uint8_t)((p[1] & 0xF0) | ((v >> 8) & 0x0F)); }
}

static uint32_t file_clusters(void) { return (uint32_t)((g_len + DISK_SECTOR - 1) / DISK_SECTOR); }

static void fat_sector(uint8_t *b)
{
    fat12_set(b, 0, 0xFF8);
    fat12_set(b, 1, 0xFFF);
    uint32_t n = file_clusters();
    for (uint32_t i = 0; i < n; i++) fat12_set(b, 2 + i, i + 1 < n ? 3 + i : 0xFFF);
}

static void dir_entry(uint8_t *e, const char name83[11], uint8_t attr, uint16_t cluster, uint32_t size)
{
    memcpy(e, name83, 11);
    e[11] = attr;
    put16(e + 14, 0);                  /* время создания */
    put16(e + 16, (46u << 9) | (11u << 5) | 26u);   /* дата создания: 2026-11-26 */
    put16(e + 18, (46u << 9) | (11u << 5) | 26u);
    put16(e + 22, 0);
    put16(e + 24, (46u << 9) | (11u << 5) | 26u);
    put16(e + 26, cluster);
    put32(e + 28, size);
}

static void root_sector(uint8_t *b)
{
    dir_entry(b, "PMDIAG     ", 0x08, 0, 0);                      /* метка тома */
    dir_entry(b + 32, "REPORT  TXT", 0x01, g_len ? 2 : 0, (uint32_t)g_len);   /* только чтение */
}

void disk_read_sector(uint32_t lba, uint8_t *buf)
{
    memset(buf, 0, DISK_SECTOR);
    if (lba == 0) boot_sector(buf);
    else if (lba == 1) fat_sector(buf);
    else if (lba == 2) root_sector(buf);
    else if (lba < DISK_SECTORS) {
        size_t off = (size_t)(lba - DISK_DATA_FIRST) * DISK_SECTOR;
        if (off < g_len) {
            size_t n = g_len - off < DISK_SECTOR ? g_len - off : DISK_SECTOR;
            memcpy(buf, g_text + off, n);
        }
    }
}
