/*
 * Транспорт настоящего токена: USB CDC (виртуальный COM-порт). Драйвер
 * встроен в Windows 10+, Linux и macOS. Кадры — как у симулятора:
 * [u32 le длина][кадр]. Порт открывается монопольно: пока HapasVault
 * держит токен, другие программы его не откроют.
 */
#ifndef PM_SERIAL_H
#define PM_SERIAL_H

#include <stddef.h>
#include <stdint.h>
#include "proto.h"   /* PM_USB_VID, PM_USB_PID */

typedef intptr_t pm_serial;
#define PM_BAD_SERIAL ((pm_serial)-1)

/* Найти подключённый токен. Windows: "COM5", Linux: "/dev/ttyACM0".
 * 1 = найден, 0 = нет. */
int       pm_serial_find(char *path, size_t cap);

/* Открыть порт (сырой режим, монопольно). timeout_ms — на каждую операцию.
 * При ошибке *busy = 1, если порт занят другой программой. */
pm_serial pm_serial_open(const char *path, int timeout_ms, int *busy);
void      pm_serial_close(pm_serial s);

/* Функция обмена для pm_client: ctx = (pm_serial*). */
long      pm_serial_xfer(void *ctx, const uint8_t *req, size_t req_len, uint8_t *resp, size_t cap);

#endif
