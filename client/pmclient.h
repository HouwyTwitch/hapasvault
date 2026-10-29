/*
 * Клиентская библиотека (сторона ПК). Чистый C, без глобального состояния —
 * её же соберём в DLL для GUI с радиальным меню (C# P/Invoke).
 *
 * Возвращаемые значения функций pmc_*:
 *    0   — успех
 *   >0   — статус от токена (ST_* из proto.h)
 *   <0   — ошибка на стороне ПК (PMC_E_*)
 */
#ifndef PM_CLIENT_H
#define PM_CLIENT_H

#include <stddef.h>
#include <stdint.h>
#include "session.h"
#include "proto.h"

#define PMC_E_IO         (-1)   /* транспорт */
#define PMC_E_PROTO      (-2)   /* неожиданный ответ */
#define PMC_E_NO_SESSION (-3)
#define PMC_E_NOT_PAIRED (-4)
#define PMC_E_SEED       (-5)   /* фраза: неизвестное слово/не 24 слова/контрольная сумма */
#define PMC_E_NO_KEY     (-6)   /* нет K_pc (не было настройки на этом ПК) */
#define PMC_E_MEMORY     (-7)
#define PMC_E_FILE       (-8)
#define PMC_E_BUF        (-9)   /* мал буфер */
#define PMC_E_TOKEN      (-100) /* -100 - FE_*: ошибка кадра от токена */

/* Обмен кадрами: отправить req, получить ответ. Возвращает длину или <0. */
typedef long (*pmc_xfer_fn)(void *ctx, const uint8_t *req, size_t req_len,
                            uint8_t *resp, size_t cap);

typedef struct {
    pmc_xfer_fn xfer;
    void       *xfer_ctx;

    /* постоянные данные ПК (файл идентичности) */
    uint8_t sk[32], pk[32];        /* статический X25519 ПК */
    uint8_t token_pk[32];
    uint8_t k_pc[32];              /* половина ключа хранилища */
    int     paired, have_kpc;

    /* настройка Argon2id */
    uint32_t argon_blocks;         /* КиБ памяти, по умолчанию 65536 = 64 МиБ */
    uint32_t argon_passes;

    /* временное */
    pm_session sess;
    uint8_t    pending_seed[32];
    int        seed_pending;
    uint8_t    buf_out[PM_MAX_FRAME + 64];
    uint8_t    buf_in[PM_MAX_FRAME + 64];
    uint8_t    plain[PM_MAX_FRAME];
} pm_client;

typedef struct {
    int      paired, setup_done, unlocked;
    unsigned proto, count;
    uint32_t uptime_s;
} pmc_info_t;

typedef void (*pmc_list_cb)(void *ctx, uint32_t id, const char *category, const char *name);
typedef void (*pmc_log_cb)(void *ctx, uint32_t uptime_s, uint8_t cmd, uint8_t status, uint32_t id);

/* Создание и идентичность */
void pmc_init(pm_client *c, pmc_xfer_fn xfer, void *ctx);   /* генерирует ключ ПК */
int  pmc_identity_save(const pm_client *c, const char *path); /* Windows: DPAPI */
int  pmc_identity_load(pm_client *c, const char *path);
void pmc_wipe(pm_client *c);

/* Сопряжение (один раз): code — 6 цифр для сверки с токеном/второй стороной */
int  pmc_pair(pm_client *c, uint32_t *code);

/* Сессия */
int  pmc_connect(pm_client *c);
int  pmc_info(pm_client *c, pmc_info_t *info);

/* Первичная настройка: begin выдаёт 24 слова (буфер >= 256 байт),
 * commit — после того как пользователь их записал и подтвердил. */
int  pmc_setup_begin(pm_client *c, char *words, size_t cap);
int  pmc_setup_commit(pm_client *c, const char *master_password);

/* Восстановление на новом токене/ПК из 24 слов (+ необязательный бэкап) */
int  pmc_restore(pm_client *c, const char *words, const char *master_password,
                 const uint8_t *backup, size_t backup_len);

int  pmc_unlock(pm_client *c, const char *master_password);
int  pmc_lock(pm_client *c);

int  pmc_list(pm_client *c, pmc_list_cb cb, void *ctx);
int  pmc_get(pm_client *c, uint32_t id, char *login, size_t login_cap,
             char *password, size_t pw_cap);
int  pmc_add(pm_client *c, const char *category, const char *name, const char *login,
             const char *password, uint32_t *id_out);
int  pmc_delete(pm_client *c, uint32_t id);
int  pmc_log(pm_client *c, pmc_log_cb cb, void *ctx);
int  pmc_backup(pm_client *c, uint8_t *out, size_t cap, size_t *len);
int  pmc_factory_reset(pm_client *c);

const char *pmc_strerror(int code);

#endif
