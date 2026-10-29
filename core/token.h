/*
 * Логика токена — не зависит от железа.
 * Транспорт (TCP в симуляторе, USB HID на RP2040) просто передаёт кадры сюда.
 */
#ifndef PM_TOKEN_H
#define PM_TOKEN_H

#include <stddef.h>
#include <stdint.h>

/* Политики */
#define TOKEN_IDLE_TIMEOUT_MS   (5u * 60u * 1000u)  /* простой -> блокировка */
#define TOKEN_RATE_N            10u                 /* не больше N расшифровок ... */
#define TOKEN_RATE_WINDOW_MS    60000u              /* ... за это окно */
#define TOKEN_FREE_ATTEMPTS     3u                  /* неверных паролей без задержки */
#define TOKEN_LOG_SIZE          32u

void token_init(void);

/* Обработать входящий кадр, записать ответ в out. Возвращает длину ответа. */
size_t token_handle(const uint8_t *in, size_t len, uint8_t *out, size_t cap);

/* Вызывать периодически: таймаут простоя. */
void token_tick(void);

/* Транспорт закрыт (USB отключён / сокет закрыт): блокировка и сброс сессии. */
void token_disconnect(void);

/* Для отладки/тестов: публичный ключ токена. */
void token_public_key(uint8_t pub[32]);

#endif
