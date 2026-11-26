/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Диск только для чтения (FAT12) с одним файлом REPORT.TXT — для USB MSC. */
#ifndef PM_DIAG_DISK_H
#define PM_DIAG_DISK_H

#include <stddef.h>
#include <stdint.h>

#define DISK_SECTOR      512u
#define DISK_SECTORS     128u           /* 64 КБ */
#define DISK_DATA_FIRST  3u             /* загрузочный сектор, FAT, корневой каталог */
#define DISK_FILE_MAX    ((DISK_SECTORS - DISK_DATA_FIRST) * DISK_SECTOR)

/* Содержимое файла (текст живёт у вызывающего; len обрезается до DISK_FILE_MAX). */
void disk_set_file(const char *text, size_t len);

/* Сектор lba (< DISK_SECTORS) в buf[DISK_SECTOR]. */
void disk_read_sector(uint32_t lba, uint8_t *buf);

#endif
