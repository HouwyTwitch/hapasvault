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

#define PMAPI_VERSION 1

typedef struct pmapi pmapi;

typedef struct {
    int32_t  paired, setup_done, unlocked;
    uint32_t proto, count, uptime_s;
} pmapi_info_t;

typedef void (*pmapi_list_cb)(void *ctx, uint32_t id, const char *category, const char *name);
typedef void (*pmapi_log_cb)(void *ctx, uint32_t uptime_s, uint8_t cmd, uint8_t status, uint32_t id);

PMAPI int     pmapi_version(void);
PMAPI uint32_t pmapi_max_backup(void);

/* Хэндл и файл идентичности ПК (отсутствие файла — не ошибка). */
PMAPI pmapi  *pmapi_create(const char *identity_path);
PMAPI void    pmapi_destroy(pmapi *h);
PMAPI int     pmapi_is_paired(const pmapi *h);
PMAPI int     pmapi_has_key(const pmapi *h);
PMAPI void    pmapi_set_argon(pmapi *h, uint32_t kib, uint32_t passes);

/* Транспорт: подключиться к токену (127.0.0.1:port) и, если ПК сопряжён,
 * установить сессию. detach = «выдернуть токен», хранилище блокируется. */
PMAPI int     pmapi_attach(pmapi *h, uint16_t port);
PMAPI void    pmapi_detach(pmapi *h);
PMAPI int     pmapi_is_attached(const pmapi *h);

PMAPI int     pmapi_pair(pmapi *h, uint32_t *code);
PMAPI int     pmapi_forget_pairing(pmapi *h);   /* токен сброшен без этого ПК */
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
