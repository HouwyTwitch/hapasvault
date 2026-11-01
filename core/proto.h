/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Протокол обмена ПК <-> токен.
 *
 * Внешний кадр (транспорт: TCP в симуляторе, USB CDC на устройстве; поток
 * [u32 le длина][кадр], см. framer.h):
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

#define PM_PROTO_VERSION   5   /* 5: до 4 ПК на токен (привязка по 24 словам), WHO, HELLO с ключом ПК;
                                   4: ёмкость по RAM/flash, LIST страницами, бэкап частями;
                                   3: подтверждения Steam; 2: OTP, UPDATE, тип OTP в LIST */

/* Типы кадров (открытые, до сессии):
 *   FR_WHO         -> [FR_WHO][token_pub 32][u8 флаги: 1 — настроен][u8 сколько ПК привязано]
 *   FR_PAIR        [pc_pub 32] -> [token_pub 32]   первый ПК чистого (не настроенного) токена
 *   FR_PAIR_PROOF  [pc_pub 32][proof 32] -> [token_pub 32]   ещё один ПК, proof — kdf.h pm_pair_proof
 *   FR_HELLO       [pc_pub 32][epk 32] -> [epk 32]   сессия Noise KK с привязанным ПК */
#define FR_PAIR       0x01
#define FR_HELLO      0x02
#define FR_DATA       0x03
#define FR_WHO        0x04
#define FR_PAIR_PROOF 0x05
#define FR_ERROR      0x7F

/* Ошибки внешнего уровня (FR_ERROR) */
#define FE_BAD_FRAME      1
#define FE_ALREADY_PAIRED 2
#define FE_NOT_PAIRED     3
#define FE_NO_SESSION     4
#define FE_DECRYPT        5   /* сессия сброшена */
#define FE_NEED_PROOF     6   /* токен настроен: новый ПК — только по 24 словам */
#define FE_PAIR_FULL      7   /* уже привязано 4 ПК */
#define FE_BAD_PROOF      8   /* подпись привязки не сошлась: не та фраза */

/* Команды (внутри FR_DATA) */
#define CMD_INFO          0x10  /* -> [u8 flags][u8 proto][u16 count][u32 uptime_s][u32 used][u32 capacity]
                                         used/capacity — байты открытого хранилища (used = 0, если закрыто) */
#define CMD_SETUP_BEGIN   0x20  /* [rand_pc 32] -> [rand_token 32] */
#define CMD_SETUP_COMMIT  0x21  /* [pw_hash 32] -> ok (хранилище создано и открыто) */
#define CMD_RESTORE       0x22  /* [k_token 32][k_pc 32][pw_hash 32][u8 с бэкапом] -> ok (бэкап — из RESTORE_DATA) */
#define CMD_RESTORE_DATA  0x23  /* [u32 off][u32 total][часть бэкапа] -> ok; только до настройки, по порядку */
#define CMD_UNLOCK        0x30  /* [k_pc 32][pw_hash 32] -> ok */
#define CMD_LOCK          0x31  /* -> ok */
#define CMD_LIST          0x40  /* [u32 пропустить первые] -> [u16 n][u8 ещё] n * {u32 id, str cat, str name, u8 otp_type} */
#define CMD_GET           0x41  /* [u32 id] -> [str login][pw password] (секрет OTP не выдаётся) */
#define CMD_ADD           0x42  /* [str cat][str name][str login][pw password][otp] -> [u32 id] */
#define CMD_DELETE        0x43  /* [u32 id] -> ok */
#define CMD_UPDATE        0x44  /* [u32 id][str cat][str name][str login][pw password][u8 mode][otp если mode=1] -> ok */
#define CMD_OTP           0x45  /* [u32 id][u64 unix_time] -> [u8 type][u8 period][str code] */
#define CMD_STEAM_CONF    0x46  /* [u32 id][u64 unix_time][u8 n][tag n] -> [key 20] (HMAC identity_secret) */
#define CMD_STEAM_INFO    0x47  /* [u32 id][u8 flags] -> [u64 steamid][u8 n][revocation n, если flags&1] */
#define CMD_PC_LIST       0x52  /* (открытое) -> [u8 n] n * {u8 slot, u8 это_вы, pub 8 (отпечаток), str имя} */
#define CMD_PC_REMOVE     0x53  /* (открытое) [u8 slot] -> ok; отвязанный ПК больше не установит сессию */
#define CMD_PC_LABEL      0x54  /* [str имя] -> ok; имя текущего ПК (видно в списке на других ПК) */
#define CMD_LOG           0x50  /* -> [u8 n] n * {u32 uptime_s, u8 cmd, u8 status, u32 id} */
#define CMD_BACKUP        0x51  /* [u32 off] -> [u32 total][часть зашифрованного блоба хранилища] */
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
/* USB-идентификаторы прошивки. 1209:0001 — тестовый PID pid.codes, им пользуются
 * и другие самоделки, поэтому клиент проверяет ещё и имя устройства (строку
 * продукта / интерфейса USB). Свой PID: pid.codes или Raspberry Pi (VID 2E8A) —
 * меняется здесь, клиент и прошивка берут значения отсюда. */
#define PM_USB_VID        0x1209u
#define PM_USB_PID        0x0001u
#define PM_USB_PRODUCT    "pmtoken"

#define PM_MAX_FRAME      (8u * 1024u)   /* хранилище больше кадра: бэкап и список — частями */
#define PM_BACKUP_CHUNK   4096u
#define PM_MAX_BACKUP     (1024u * 1024u)  /* верхняя граница бэкапа для буферов ПК */
#define PM_MAX_STR        255u
#define PM_MAX_PASSWORD   1024u

#endif
