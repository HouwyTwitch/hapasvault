/*
 * Хранение на flash токена.
 *
 * Разметка (секторы по 4 КБ):
 *   [0]      конфигурация, копия A
 *   [1]      конфигурация, копия B
 *   [2..10]  хранилище, слот A (36 КБ)
 *   [11..19] хранилище, слот B (36 КБ)
 *
 * Каждая запись несёт счётчик seq и контрольную сумму BLAKE2b. Запись всегда
 * идёт в слот, где лежит СТАРАЯ копия, поэтому выдёргивание токена во время
 * записи оставляет предыдущую версию целой (A/B-схема).
 *
 * На flash в открытом виде: статический ключ токена, публичный ключ ПК,
 * K_token. Это осознанно: без K_pc и мастер-пароля они бесполезны.
 * Сами записи хранятся только зашифрованными ключом K_vault.
 */
#ifndef PM_STORE_H
#define PM_STORE_H

#include <stddef.h>
#include <stdint.h>

#define STORE_CFG_SECTORS     2u
#define STORE_SLOT_SECTORS    9u
#define STORE_SLOT_BYTES      (STORE_SLOT_SECTORS * 4096u)
#define STORE_VAULT_HDR       84u          /* см. store.c */
#define STORE_CT_MAX          (STORE_SLOT_BYTES - STORE_VAULT_HDR)
#define STORE_PLAIN_MAX       32768u       /* ~200-300 записей */
#define STORE_TOTAL_BYTES     ((STORE_CFG_SECTORS + 2u * STORE_SLOT_SECTORS) * 4096u)

#define CFG_PAIRED 0x01
#define CFG_SETUP  0x02

typedef struct {
    uint32_t seq;
    uint8_t  flags;
    uint8_t  token_sk[32];     /* статический X25519 токена */
    uint8_t  pc_pub[32];       /* статический X25519 сопряжённого ПК */
    uint8_t  k_token[32];      /* половина ключа хранилища */
    uint32_t fails;            /* неверных паролей подряд: переживает перезагрузку */
} pm_config;

/* Загрузить самую свежую целую копию конфигурации. 0 = ок, -1 = нет. */
int store_config_load(pm_config *cfg);
/* Записать (seq увеличивается автоматически). 0 = ок. */
int store_config_save(pm_config *cfg);

/* Есть ли хотя бы одна целая копия хранилища. */
int store_vault_exists(void);

/* Зашифровать и записать открытый текст хранилища. 0 = ок. */
int store_vault_save(const uint8_t k_vault[32], const uint8_t *plain, size_t len);

/* Расшифровать самую свежую целую копию.
 * 0 = ок, -1 = нет хранилища, -2 = неверный ключ. */
int store_vault_load(const uint8_t k_vault[32], uint8_t *plain, size_t *len);

/* Выдать сырую (зашифрованную) копию слота для резервного копирования.
 * Возвращает длину или -1. */
long store_vault_raw(uint8_t *out, size_t cap);

/* Положить сырую копию из бэкапа (проверяется только целостность формата). */
int store_vault_put_raw(const uint8_t *blob, size_t len);

/* Стереть всё. */
int store_wipe(void);

#endif
