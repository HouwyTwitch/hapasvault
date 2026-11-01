/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Одноразовые коды, которые считает токен (секрет не покидает его):
 *   TOTP (RFC 6238): HMAC-SHA1/SHA256, 6–8 цифр, период 15–120 с;
 *   Steam Guard: HMAC-SHA1 с периодом 30 с, 5 символов из алфавита Steam;
 *   Steam Guard с подтверждениями: то же плюс identity_secret — ключи для
 *   мобильных подтверждений (обмены, торговая площадка, смена данных аккаунта).
 *
 * Параметры записи:
 *   TOTP, STEAM:   [u8 type][u8 alg][u8 digits][u8 period][secret ...]
 *   STEAM_MOBILE:  [u8 type=3][u8 1][u8 5][u8 30]
 *                  [u8 n][shared_secret n][u8 m][identity_secret m]
 *                  [u64 le steamid][u8 r][revocation_code r]
 */
#ifndef PM_OTP_H
#define PM_OTP_H

#include <stddef.h>
#include <stdint.h>

#define OTP_NONE   0
#define OTP_TOTP   1
#define OTP_STEAM  2
#define OTP_STEAM_MOBILE 3

#define STEAM_REVOCATION_MAX 16u
#define STEAM_TAG_MAX        32u   /* тег подтверждения: conf, details123, allow… */
#define STEAM_CONF_KEY       20u   /* HMAC-SHA1 */

#define OTP_PARAMS      4u
#define OTP_SECRET_MIN  10u    /* 80 бит, минимум RFC 4226 */
#define OTP_SECRET_MAX  64u
#define OTP_BLOB_MAX    (OTP_PARAMS + 2u * (1u + OTP_SECRET_MAX) + 8u + 1u + STEAM_REVOCATION_MAX)
#define OTP_CODE_MAX    10u

/* Проверить параметры (тип, алгоритм, цифры, период, длина секрета). 0 = ок. */
int pm_otp_validate(const uint8_t *blob, size_t len);

/* Код на момент unix_time (секунды). code — нуль-терминированная строка.
 * Возвращает длину кода или -1. */
int pm_otp_code(const uint8_t *blob, size_t len, uint64_t unix_time, char code[OTP_CODE_MAX + 1]);

/* Разбор STEAM_MOBILE. Любой указатель может быть NULL. 0 = ок. */
int pm_steam_parts(const uint8_t *blob, size_t len,
                   const uint8_t **shared, size_t *shared_len,
                   const uint8_t **identity, size_t *identity_len,
                   uint64_t *steamid, const uint8_t **revocation, size_t *revocation_len);

/* Тег подтверждения допустим: 1..32 символа [a-z0-9]. */
int pm_steam_tag_ok(const uint8_t *tag, size_t len);

/* Тег одобряет или отклоняет операцию (allow/accept/cancel/reject) — пишется в журнал. */
int pm_steam_tag_is_action(const uint8_t *tag, size_t len);

/* Ключ подтверждения: HMAC-SHA1(identity_secret, u64 be time || tag). 0 = ок. */
int pm_steam_conf_key(const uint8_t *blob, size_t len, uint64_t unix_time,
                      const uint8_t *tag, size_t tag_len, uint8_t key[STEAM_CONF_KEY]);

#endif
