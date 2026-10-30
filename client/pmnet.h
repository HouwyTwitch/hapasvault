/*
 * Транспорт симулятора: TCP только на 127.0.0.1, кадры [u32 le длина][кадр].
 * Настоящий токен — USB CDC с теми же кадрами (pmserial.h).
 */
#ifndef PM_NET_H
#define PM_NET_H

#include <stddef.h>
#include <stdint.h>

#define PM_SIM_PORT 47123

typedef intptr_t pm_sock;
#define PM_BAD_SOCK ((pm_sock)-1)

int     pm_net_init(void);
pm_sock pm_net_listen(uint16_t port);                 /* только loopback */
pm_sock pm_net_accept(pm_sock ls);
pm_sock pm_net_connect(const char *host, uint16_t port);
/* 1 = есть данные, 0 = таймаут, -1 = ошибка */
int     pm_net_wait(pm_sock s, int timeout_ms);
int     pm_net_send_frame(pm_sock s, const uint8_t *buf, size_t len);
long    pm_net_recv_frame(pm_sock s, uint8_t *buf, size_t cap);
void    pm_net_close(pm_sock s);
/* Таймаут приёма/передачи (0 = без таймаута). По истечении recv/send дают ошибку. */
int     pm_net_set_timeout(pm_sock s, int timeout_ms);

/* Функция обмена для pm_client поверх сокета: ctx = (pm_sock*). */
long    pm_net_xfer(void *ctx, const uint8_t *req, size_t req_len, uint8_t *resp, size_t cap);

#endif
