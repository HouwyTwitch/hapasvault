/*
 * Протокол обмена ПК <-> токен.
 *
 * Внешний кадр (транспорт: TCP в симуляторе, HID-отчёты на устройстве):
 *     [u8 type][payload...]
 *
 *   FR_PAIR   (открыто, только пока токен не сопряжён)
 *       ПК -> [pc_static_pub 32]        токен -> [token_static_pub 32]
 *   FR_HELLO  (открыто, начало сессии; рукопожатие в духе Noise KK)
 *       ПК -> [pc_ephemeral_pub 32]     токен -> [token_ephemeral_pub 32]
 *   FR_DATA   (зашифровано XChaCha20-Poly1305, счётчик-нонс на направление)
 *       ПК -> [mac 16][ciphertext]      токен -> [mac 16][ciphertext]
 *   FR_ERROR  (токен -> ПК, открыто) [u8 err]
 *
 * Внутри FR_DATA:
 *   запрос:  [u8 cmd][аргументы]
 *   ответ:   [u8 status][данные]
 *
 * Строки кодируются как [u8 len][bytes] (пароль — [u16 le len][bytes]).
 * otp = [u8 len][len байт: u8 type, u8 alg, u8 digits, u8 period, secret] (len = 0 — нет),
 * см. otp.h. Режим UPDATE: 0 — убрать OTP, 1 — задать (далее otp), 2 — оставить прежний.
 */
#ifndef PM_PROTO_H
#define PM_PROTO_H

#define PM_PROTO_VERSION   2   /* 2: OTP, UPDATE, тип OTP в LIST */

/* Типы кадров */
#define FR_PAIR    0x01
#define FR_HELLO   0x02
#define FR_DATA    0x03
#define FR_ERROR   0x7F

/* Ошибки внешнего уровня (FR_ERROR) */
#define FE_BAD_FRAME      1
#define FE_ALREADY_PAIRED 2
#define FE_NOT_PAIRED     3
#define FE_NO_SESSION     4
#define FE_DECRYPT        5   /* сессия сброшена */

/* Команды (внутри FR_DATA) */
#define CMD_INFO          0x10  /* -> [u8 flags][u8 proto][u16 count][u32 uptime_s] */
#define CMD_SETUP_BEGIN   0x20  /* [rand_pc 32] -> [rand_token 32] */
#define CMD_SETUP_COMMIT  0x21  /* [pw_hash 32] -> ok (хранилище создано и открыто) */
#define CMD_RESTORE       0x22  /* [k_token 32][k_pc 32][pw_hash 32][backup...] -> ok */
#define CMD_UNLOCK        0x30  /* [k_pc 32][pw_hash 32] -> ok */
#define CMD_LOCK          0x31  /* -> ok */
#define CMD_LIST          0x40  /* -> [u16 n] n * {u32 id, str cat, str name, u8 otp_type} */
#define CMD_GET           0x41  /* [u32 id] -> [str login][pw password] (секрет OTP не выдаётся) */
#define CMD_ADD           0x42  /* [str cat][str name][str login][pw password][otp] -> [u32 id] */
#define CMD_DELETE        0x43  /* [u32 id] -> ok */
#define CMD_UPDATE        0x44  /* [u32 id][str cat][str name][str login][pw password][u8 mode][otp если mode=1] -> ok */
#define CMD_OTP           0x45  /* [u32 id][u64 unix_time] -> [u8 type][u8 period][str code] */
#define CMD_LOG           0x50  /* -> [u8 n] n * {u32 uptime_s, u8 cmd, u8 status, u32 id} */
#define CMD_BACKUP        0x51  /* -> зашифрованный блоб хранилища как есть */
#define CMD_FACTORY_RESET 0x60  /* (только открытое) -> ok, стирает всё, включая сопряжение */

/* Флаги CMD_INFO */
#define INFO_PAIRED       0x01
#define INFO_SETUP_DONE   0x02
#define INFO_UNLOCKED     0x04

/* Статусы ответа */
#define ST_OK             0x00
#define ST_BAD_ARGS       0x01
#define ST_LOCKED         0x02
#define ST_NOT_SETUP      0x03
#define ST_ALREADY_SETUP  0x04
#define ST_WRONG_KEY      0x05  /* неверный мастер-пароль или половина ключа */
#define ST_NOT_FOUND      0x06
#define ST_RATE_LIMIT     0x07
#define ST_FULL           0x08
#define ST_BACKOFF        0x09  /* слишком много неверных попыток, подождите */
#define ST_FLASH          0x0A
#define ST_UNKNOWN_CMD    0x0B
#define ST_NO_OTP         0x0C  /* у записи нет OTP */
#define ST_BAD_TIME       0x0D  /* время ПК убежало вперёд относительно часов токена */

/* Ограничения */
#define PM_MAX_FRAME      (40u * 1024u)
#define PM_MAX_STR        255u
#define PM_MAX_PASSWORD   1024u

#endif
