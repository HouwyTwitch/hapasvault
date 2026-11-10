/* SPDX-License-Identifier: GPL-3.0-or-later */
#define PMAPI_BUILD
#include "pmapi.h"
#include "bip39.h"
#include "pmclient.h"
#include "pmnet.h"
#include "pmserial.h"
#include "monocypher.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Поток после таймаута рассинхронизирован, поэтому при PMC_E_IO соединение
 * закрывается: следующий вызов вернёт PMC_E_IO сразу, GUI переподключится. */
#define PMAPI_IO_TIMEOUT_MS 5000
/* USB: запись полного хранилища на плате — секунды (сотни секторов flash) */
#define PMAPI_USB_TIMEOUT_MS 20000

enum { T_NONE, T_TCP, T_SERIAL };

struct pmapi {
    pm_client c;
    int       transport;
    pm_sock   sock;
    pm_serial serial;
    char     *id_path;
};

static long xfer(void *ctx, const uint8_t *req, size_t req_len, uint8_t *resp, size_t cap)
{
    pmapi *h = ctx;
    switch (h->transport) {
    case T_TCP:    return pm_net_xfer(&h->sock, req, req_len, resp, cap);
    case T_SERIAL: return pm_serial_xfer(&h->serial, req, req_len, resp, cap);
    default:       return -1;
    }
}

static int io(pmapi *h, int rc)
{
    if (rc == PMC_E_IO) pmapi_detach(h);
    return rc;
}

static int save_id(pmapi *h)
{
    return h->id_path ? pmc_identity_save(&h->c, h->id_path) : 0;
}

int pmapi_version(void) { return PMAPI_VERSION; }
uint32_t pmapi_max_backup(void) { return PM_MAX_BACKUP; }

pmapi *pmapi_create(const char *identity_path)
{
    if (pm_net_init() != 0) return NULL;
    pmapi *h = calloc(1, sizeof *h);
    if (!h) return NULL;
    h->sock = PM_BAD_SOCK;
    h->serial = PM_BAD_SERIAL;
    pmc_init(&h->c, xfer, h);
    if (identity_path) {
        size_t n = strlen(identity_path) + 1;
        h->id_path = malloc(n);
        if (!h->id_path) { free(h); return NULL; }
        memcpy(h->id_path, identity_path, n);
        /* нет файла или он чужой — остаёмся с новым ключом, ПК «не сопряжён»
         * (pmc_identity_load меняет клиента только при успехе) */
        pmc_identity_load(&h->c, identity_path);
    }
    return h;
}

void pmapi_destroy(pmapi *h)
{
    if (!h) return;
    pmapi_detach(h);
    pmc_wipe(&h->c);
    free(h->id_path);
    free(h);
}

int pmapi_is_paired(const pmapi *h) { return h->c.paired; }
int pmapi_has_key(const pmapi *h) { return h->c.have_kpc; }

void pmapi_set_argon(pmapi *h, uint32_t kib, uint32_t passes)
{
    if (kib >= 8) h->c.argon_blocks = kib;
    if (passes >= 1) h->c.argon_passes = passes;
}

/* После подключения: известный токен — сессия; незнакомый — не ошибка, программа предложит
 * привязку (pmapi_is_paired() == 0, pmapi_who() скажет, чистый он или настроенный). */
static int attach_connect(pmapi *h)
{
    if (h->c.known_n == 0 && !h->c.paired) return 0;
    int rc = pmc_connect(&h->c);
    return rc == PMC_E_NOT_PAIRED ? 0 : rc;
}

/* Симулятор (тестовый токен на 127.0.0.1) — только в предрелизных и локальных сборках:
 * любой локальный процесс может слушать этот порт и выдать себя за токен. В стабильной
 * сборке (PM_NO_SIMULATOR) символ остаётся для таблицы P/Invoke, но сокет не открывается. */
int pmapi_has_simulator(void)
{
#ifdef PM_NO_SIMULATOR
    return 0;
#else
    return 1;
#endif
}

int pmapi_attach(pmapi *h, uint16_t port)
{
    pmapi_detach(h);
#ifdef PM_NO_SIMULATOR
    (void)port;
    return PMC_E_NO_DEVICE;
#else
    h->sock = pm_net_connect("127.0.0.1", port);
    if (h->sock == PM_BAD_SOCK) return PMC_E_IO;
    /* токен отвечает за миллисекунды; молчание = занят другим клиентом или завис */
    pm_net_set_timeout(h->sock, PMAPI_IO_TIMEOUT_MS);
    h->transport = T_TCP;
    return io(h, attach_connect(h));
#endif
}

int pmapi_find_usb(char *path, size_t cap) { return pm_serial_find(path, cap); }

int pmapi_attach_serial(pmapi *h, const char *path)
{
    pmapi_detach(h);
    /* X25519 на Cortex-M0+ — десятки миллисекунд, рукопожатие и запись flash — до секунды */
    int busy = 0;
    h->serial = pm_serial_open(path, PMAPI_USB_TIMEOUT_MS, &busy);
    if (h->serial == PM_BAD_SERIAL) return busy ? PMC_E_BUSY : PMC_E_NO_DEVICE;
    h->transport = T_SERIAL;
    return io(h, attach_connect(h));
}

int pmapi_attach_usb(pmapi *h)
{
    char path[64];
    if (!pm_serial_find(path, sizeof path)) {
        pmapi_detach(h);
        return PMC_E_NO_DEVICE;
    }
    return pmapi_attach_serial(h, path);
}

void pmapi_detach(pmapi *h)
{
    pm_net_close(h->sock);
    pm_serial_close(h->serial);
    h->sock = PM_BAD_SOCK;
    h->serial = PM_BAD_SERIAL;
    h->transport = T_NONE;
    pm_session_clear(&h->c.sess);
}

int pmapi_is_attached(const pmapi *h) { return h->transport != T_NONE; }

int pmapi_transport(const pmapi *h) { return h->transport; }

int pmapi_pair(pmapi *h)
{
    int rc = io(h, pmc_pair(&h->c));
    if (rc != 0) return rc;
    rc = save_id(h);
    return rc != 0 ? rc : io(h, pmc_connect(&h->c));
}

int pmapi_pair_words(pmapi *h, const char *words)
{
    int rc = io(h, pmc_pair_words(&h->c, words));
    if (rc != 0) return rc;
    rc = save_id(h);
    return rc != 0 ? rc : io(h, pmc_connect(&h->c));
}

int pmapi_forget_pairing(pmapi *h)
{
    pmc_forget_token(&h->c, -1);
    return save_id(h);
}

int pmapi_who(pmapi *h, uint8_t token_id[8], int *setup, int *pcs)
{
    uint8_t pk[32];
    int rc = io(h, pmc_who(&h->c, pk, setup, pcs));
    if (rc == 0) memcpy(token_id, pk, 8);
    return rc;
}

int pmapi_token_count(const pmapi *h) { return h->c.known_n; }

int pmapi_token_get(const pmapi *h, int index, uint8_t token_id[8], char *label, size_t cap, int *active)
{
    if (index < 0 || index >= h->c.known_n || cap == 0) return PMC_E_BUF;
    const pmc_token *t = &h->c.known[index];
    memcpy(token_id, t->token_pk, 8);
    snprintf(label, cap, "%s", t->label);
    *active = h->c.paired && crypto_verify32(t->token_pk, h->c.token_pk) == 0;
    return 0;
}

int pmapi_token_rename(pmapi *h, int index, const char *label)
{
    if (index < 0 || index >= h->c.known_n) return PMC_E_BUF;
    size_t l = strlen(label);
    if (l >= PMC_LABEL) l = PMC_LABEL - 1;
    while (l && ((unsigned char)label[l] & 0xC0) == 0x80) l--;   /* не резать символ UTF-8 */
    memset(h->c.known[index].label, 0, PMC_LABEL);
    memcpy(h->c.known[index].label, label, l);
    return save_id(h);
}

int pmapi_token_forget(pmapi *h, int index)
{
    pmc_forget_token(&h->c, index);
    return save_id(h);
}

int pmapi_pc_list(pmapi *h, pmapi_pc_cb cb, void *ctx) { return io(h, pmc_pc_list(&h->c, cb, ctx)); }
int pmapi_pc_remove(pmapi *h, int slot) { return io(h, pmc_pc_remove(&h->c, slot)); }
int pmapi_pc_label(pmapi *h, const char *label) { return io(h, pmc_pc_label(&h->c, label)); }

int pmapi_connect(pmapi *h) { return io(h, pmc_connect(&h->c)); }

int pmapi_info(pmapi *h, pmapi_info_t *info)
{
    pmc_info_t i;
    int rc = io(h, pmc_info(&h->c, &i));
    if (rc != 0) return rc;
    info->paired = i.paired;
    info->setup_done = i.setup_done;
    info->unlocked = i.unlocked;
    info->proto = i.proto;
    info->count = i.count;
    info->uptime_s = i.uptime_s;
    info->used = i.used;
    info->capacity = i.capacity;
    return 0;
}

int pmapi_setup_begin(pmapi *h, char *words, size_t cap) { return io(h, pmc_setup_begin(&h->c, words, cap)); }

int pmapi_setup_commit(pmapi *h, const char *master_password)
{
    int rc = io(h, pmc_setup_commit(&h->c, master_password));
    return rc == 0 ? save_id(h) : rc;
}

int pmapi_restore(pmapi *h, const char *words, const char *master_password,
                  const uint8_t *backup, size_t backup_len)
{
    int rc = io(h, pmc_restore(&h->c, words, master_password, backup, backup_len));
    return rc == 0 ? save_id(h) : rc;
}

int pmapi_unlock(pmapi *h, const char *master_password) { return io(h, pmc_unlock(&h->c, master_password)); }
int pmapi_lock(pmapi *h) { return io(h, pmc_lock(&h->c)); }

int pmapi_list(pmapi *h, pmapi_list_cb cb, void *ctx) { return io(h, pmc_list(&h->c, cb, ctx)); }

int pmapi_get(pmapi *h, uint32_t id, char *login, size_t login_cap, char *password, size_t pw_cap)
{
    return io(h, pmc_get(&h->c, id, login, login_cap, password, pw_cap));
}

int pmapi_add(pmapi *h, const char *category, const char *name, const char *login,
              const char *password, uint32_t *id_out)
{
    return io(h, pmc_add(&h->c, category, name, login, password, id_out));
}

int pmapi_delete(pmapi *h, uint32_t id) { return io(h, pmc_delete(&h->c, id)); }

int pmapi_add_otp(pmapi *h, const char *category, const char *name, const char *login,
                  const char *password, const uint8_t *otp, size_t otp_len, uint32_t *id_out)
{
    return io(h, pmc_add_otp(&h->c, category, name, login, password, otp, otp_len, id_out));
}

int pmapi_update(pmapi *h, uint32_t id, const char *category, const char *name, const char *login,
                 const char *password, int otp_mode, const uint8_t *otp, size_t otp_len)
{
    return io(h, pmc_update(&h->c, id, category, name, login, password, otp_mode, otp, otp_len));
}

int pmapi_otp(pmapi *h, uint32_t id, uint64_t unix_time, char *code, size_t cap, uint8_t *type, uint8_t *period)
{
    return io(h, pmc_otp(&h->c, id, unix_time, code, cap, type, period));
}
int pmapi_steam_conf(pmapi *h, uint32_t id, uint64_t unix_time, const char *tag, uint8_t key[20])
{
    return io(h, pmc_steam_conf(&h->c, id, unix_time, tag, key));
}
int pmapi_steam_info(pmapi *h, uint32_t id, uint64_t *steamid, char *revocation, size_t cap)
{
    return io(h, pmc_steam_info(&h->c, id, steamid, revocation, cap));
}
int pmapi_log(pmapi *h, pmapi_log_cb cb, void *ctx) { return io(h, pmc_log(&h->c, cb, ctx)); }

int pmapi_backup(pmapi *h, uint8_t *out, size_t cap, size_t *len)
{
    return io(h, pmc_backup(&h->c, out, cap, len));
}

int pmapi_factory_reset(pmapi *h)
{
    int rc = io(h, pmc_factory_reset(&h->c));
    return rc == 0 ? save_id(h) : rc;
}

const char *pmapi_strerror(int code) { return pmc_strerror(code); }

const char *pmapi_bip39_word(int i) { return i >= 0 && i < 2048 ? bip39_english[i] : NULL; }

int pmapi_check_phrase(const char *words)
{
    uint8_t seed[32];
    int rc = bip39_decode(words, seed);
    crypto_wipe(seed, sizeof seed);
    return rc;
}

void pmapi_wipe(void *buf, size_t len) { crypto_wipe(buf, len); }
