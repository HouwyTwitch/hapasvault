/*
 * Сборка кадров из потока байт: [u32 le длина][кадр].
 * Так кадры идут по TCP симулятора и по USB CDC прошивки; поток может
 * приходить кусками любого размера.
 */
#ifndef PM_FRAMER_H
#define PM_FRAMER_H

#include <stddef.h>
#include <stdint.h>

/* Недособранный кадр старше этого — мусор (клиент упал посреди записи). */
#define PM_FRAMER_STALE_MS 2000u

typedef struct {
    uint8_t  hdr[4];
    uint32_t hdr_n;      /* сколько байт заголовка принято */
    uint32_t need;       /* длина кадра из заголовка */
    uint32_t have;       /* сколько байт кадра принято */
} pm_framer;

void pm_framer_reset(pm_framer *f);

/* Идёт ли сборка кадра (для сброса по PM_FRAMER_STALE_MS). */
int pm_framer_busy(const pm_framer *f);

/* Скормить n байт. *used — сколько потреблено (остаток — начало следующего кадра).
 * Возвращает длину готового кадра в buf, 0 — нужно ещё, -1 — длина 0 или больше cap
 * (сборщик сброшен, байты потреблены). */
long pm_framer_feed(pm_framer *f, uint8_t *buf, size_t cap,
                    const uint8_t *data, size_t n, size_t *used);

/* Заголовок для отправки кадра длины len. */
void pm_framer_header(uint8_t hdr[4], size_t len);

#endif
