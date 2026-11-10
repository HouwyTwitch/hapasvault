/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * pmapi — C ABI для GUI (C# P/Invoke). Собирается в pmapi.dll / pmapi.so.
 *
 * Обёртка над pm_client + TCP-транспортом симулятора с непрозрачным хэндлом:
 * GUI не знает раскладку pm_client и не держит ключи в управляемой памяти.
 * Файл идентичности сохраняется здесь же после pair/setup/restore/reset.
 *
 * Коды возврата — как у pmc_* (см. pmclient.h). Вызовы не потокобезопасны:
 * один хэндл — один поток за раз.
 */
#ifndef PM_API_H
#define PM_API_H

#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#  ifdef PMAPI_BUILD
#    define PMAPI __declspec(dllexport)
#  else
#    define PMAPI __declspec(dllimport)
#  endif
#else
#  define PMAPI __attribute__((visibility("default")))
#endif

#define PMAPI_VERSION 9   /* 9: pmapi_has_simulator, протокол 6 (эпоха привязки);
                             8: до 4 токенов на ПК и 4 ПК на токен; 7: бэкап частями */

typedef struct pmapi pmapi;

typedef struct {
    int32_t  paired, setup_done, unlocked;
    uint32_t proto, count, uptime_s;
    uint32_t used, capacity;       /* байты хранилища на токене (used = 0, если закрыто) */
} pmapi_info_t;

/* otp_type: 0 — нет, 1 — TOTP, 2 — Steam Guard */
typedef void (*pmapi_list_cb)(void *ctx, uint32_t id, const char *category, const char *name, uint8_t otp_type);
typedef void (*pmapi_log_cb)(void *ctx, uint32_t uptime_s, uint8_t cmd, uint8_t status, uint32_t id);

PMAPI int     pmapi_version(void);
PMAPI uint32_t pmapi_max_backup(void);

/* Хэндл и файл идентичности ПК (отсутствие файла — не ошибка). */
PMAPI pmapi  *pmapi_create(const char *identity_path);
PMAPI void    pmapi_destroy(pmapi *h);
PMAPI int     pmapi_is_paired(const pmapi *h);
PMAPI int     pmapi_has_key(const pmapi *h);
PMAPI void    pmapi_set_argon(pmapi *h, uint32_t kib, uint32_t passes);

/* 1 — в библиотеке есть транспорт симулятора (предрелизные и локальные сборки),
 * 0 — стабильная сборка (CMake -DPM_SIMULATOR=OFF): только USB. */
PMAPI int     pmapi_has_simulator(void);
/* Транспорт: подключиться к симулятору (127.0.0.1:port) и, если ПК сопряжён,
 * установить сессию. detach = «выдернуть токен», хранилище блокируется.
 * Без симулятора — сразу PMC_E_NO_DEVICE, сокет не открывается. */
PMAPI int     pmapi_attach(pmapi *h, uint16_t port);
/* Настоящий токен по USB: найти по VID/PID и подключиться.
 * PMC_E_NO_DEVICE — не подключён, PMC_E_BUSY — порт занят другой программой. */
PMAPI int     pmapi_attach_usb(pmapi *h);
/* То же для явно заданного порта ("COM5", "/dev/ttyACM0", pty в тестах). */
PMAPI int     pmapi_attach_serial(pmapi *h, const char *path);
/* Имя порта подключённого USB-токена; 1 = найден. Ничего не открывает. */
PMAPI int     pmapi_find_usb(char *path, size_t cap);
PMAPI void    pmapi_detach(pmapi *h);
PMAPI int     pmapi_is_attached(const pmapi *h);
/* 0 — не подключён, 1 — симулятор (TCP), 2 — USB/последовательный порт. */
PMAPI int     pmapi_transport(const pmapi *h);

PMAPI int     pmapi_pair(pmapi *h);               /* первый ПК чистого токена */
PMAPI int     pmapi_pair_words(pmapi *h, const char *words);   /* ещё один ПК настроенного токена */
PMAPI int     pmapi_forget_pairing(pmapi *h);   /* забыть подключённый токен (сброшен без этого ПК) */

/* Подключённый токен: 8 байт отпечатка ключа, настроен ли, сколько ПК привязано (до сессии). */
PMAPI int     pmapi_who(pmapi *h, uint8_t token_id[8], int *setup, int *pcs);

/* Токены, известные этому ПК (до 4): выбор при подключении — сам, по ключу токена. */
PMAPI int     pmapi_token_count(const pmapi *h);
PMAPI int     pmapi_token_get(const pmapi *h, int index, uint8_t token_id[8], char *label, size_t cap, int *active);
PMAPI int     pmapi_token_rename(pmapi *h, int index, const char *label);
PMAPI int     pmapi_token_forget(pmapi *h, int index);

/* Компьютеры, привязанные к подключённому токену (до 4; нужно открытое хранилище). */
typedef void (*pmapi_pc_cb)(void *ctx, int slot, int is_me, const uint8_t id[8], const char *label);
PMAPI int     pmapi_pc_list(pmapi *h, pmapi_pc_cb cb, void *ctx);
PMAPI int     pmapi_pc_remove(pmapi *h, int slot);
PMAPI int     pmapi_pc_label(pmapi *h, const char *label);
PMAPI int     pmapi_connect(pmapi *h);
PMAPI int     pmapi_info(pmapi *h, pmapi_info_t *info);

PMAPI int     pmapi_setup_begin(pmapi *h, char *words, size_t cap);
PMAPI int     pmapi_setup_commit(pmapi *h, const char *master_password);
PMAPI int     pmapi_restore(pmapi *h, const char *words, const char *master_password,
                            const uint8_t *backup, size_t backup_len);
PMAPI int     pmapi_unlock(pmapi *h, const char *master_password);
PMAPI int     pmapi_lock(pmapi *h);

PMAPI int     pmapi_list(pmapi *h, pmapi_list_cb cb, void *ctx);
PMAPI int     pmapi_get(pmapi *h, uint32_t id, char *login, size_t login_cap,
                        char *password, size_t pw_cap);
PMAPI int     pmapi_add(pmapi *h, const char *category, const char *name, const char *login,
                        const char *password, uint32_t *id_out);
PMAPI int     pmapi_delete(pmapi *h, uint32_t id);

/* OTP: blob = [u8 type][u8 alg][u8 digits][u8 period][secret] (core/otp.h).
 * Секрет уходит на токен и больше никогда не выдаётся. */
PMAPI int     pmapi_add_otp(pmapi *h, const char *category, const char *name, const char *login,
                            const char *password, const uint8_t *otp, size_t otp_len, uint32_t *id_out);
/* otp_mode: 0 — убрать, 1 — задать otp, 2 — оставить прежний. */
PMAPI int     pmapi_update(pmapi *h, uint32_t id, const char *category, const char *name, const char *login,
                           const char *password, int otp_mode, const uint8_t *otp, size_t otp_len);
PMAPI int     pmapi_otp(pmapi *h, uint32_t id, uint64_t unix_time, char *code, size_t cap,
                        uint8_t *type, uint8_t *period);
/* Steam: ключ подтверждения (20 байт) и SteamID / код восстановления записи. */
PMAPI int     pmapi_steam_conf(pmapi *h, uint32_t id, uint64_t unix_time, const char *tag, uint8_t key[20]);
PMAPI int     pmapi_steam_info(pmapi *h, uint32_t id, uint64_t *steamid, char *revocation, size_t cap);
PMAPI int     pmapi_log(pmapi *h, pmapi_log_cb cb, void *ctx);
PMAPI int     pmapi_backup(pmapi *h, uint8_t *out, size_t cap, size_t *len);
PMAPI int     pmapi_factory_reset(pmapi *h);

PMAPI const char *pmapi_strerror(int code);

/* Словарь BIP39 (i = 0..2047, иначе NULL) и локальная проверка фразы без
 * обращения к токену: 0 = ок, -1 = неизвестное слово, -2 = не 24 слова,
 * -3 = контрольная сумма. */
PMAPI const char *pmapi_bip39_word(int i);
PMAPI int     pmapi_check_phrase(const char *words);

/* Затереть буфер так, чтобы компилятор не выкинул запись. */
PMAPI void    pmapi_wipe(void *buf, size_t len);

#endif
