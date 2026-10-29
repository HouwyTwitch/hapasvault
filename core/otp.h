/*
 * Одноразовые коды, которые считает токен (секрет не покидает его):
 *   TOTP (RFC 6238): HMAC-SHA1/SHA256, 6–8 цифр, период 15–120 с;
 *   Steam Guard: HMAC-SHA1 с периодом 30 с, 5 символов из алфавита Steam.
 *
 * Параметры записи: [u8 type][u8 alg][u8 digits][u8 period][secret ...]
 */
#ifndef PM_OTP_H
#define PM_OTP_H

#include <stddef.h>
#include <stdint.h>

#define OTP_NONE   0
#define OTP_TOTP   1
#define OTP_STEAM  2

#define OTP_PARAMS      4u
#define OTP_SECRET_MIN  10u    /* 80 бит, минимум RFC 4226 */
#define OTP_SECRET_MAX  64u
#define OTP_BLOB_MAX    (OTP_PARAMS + OTP_SECRET_MAX)
#define OTP_CODE_MAX    10u

/* Проверить параметры (тип, алгоритм, цифры, период, длина секрета). 0 = ок. */
int pm_otp_validate(const uint8_t *blob, size_t len);

/* Код на момент unix_time (секунды). code — нуль-терминированная строка.
 * Возвращает длину кода или -1. */
int pm_otp_code(const uint8_t *blob, size_t len, uint64_t unix_time, char code[OTP_CODE_MAX + 1]);

#endif
