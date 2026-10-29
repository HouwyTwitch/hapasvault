#define PMAPI_BUILD
#include "pmapi.h"
#include "bip39.h"
#include "pmclient.h"
#include "pmnet.h"
#include "monocypher.h"
#include <stdlib.h>
#include <string.h>

/* Поток после таймаута рассинхронизирован, поэтому при PMC_E_IO соединение
 * закрывается: следующий вызов вернёт PMC_E_IO сразу, GUI переподключится. */
#define PMAPI_IO_TIMEOUT_MS 5000

struct pmapi {
    pm_client c;
    pm_sock   sock;
    char     *id_path;
};

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
uint32_t pmapi_max_backup(void) { return PM_MAX_FRAME; }

pmapi *pmapi_create(const char *identity_path)
{
    if (pm_net_init() != 0) return NULL;
    pmapi *h = calloc(1, sizeof *h);
    if (!h) return NULL;
    h->sock = PM_BAD_SOCK;
    pmc_init(&h->c, pm_net_xfer, &h->sock);
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

int pmapi_attach(pmapi *h, uint16_t port)
{
    pmapi_detach(h);
    h->sock = pm_net_connect("127.0.0.1", port);
    if (h->sock == PM_BAD_SOCK) return PMC_E_IO;
    /* токен отвечает за миллисекунды; молчание = занят другим клиентом или завис */
    pm_net_set_timeout(h->sock, PMAPI_IO_TIMEOUT_MS);
    return io(h, h->c.paired ? pmc_connect(&h->c) : 0);
}

void pmapi_detach(pmapi *h)
{
    pm_net_close(h->sock);
    h->sock = PM_BAD_SOCK;
    pm_session_clear(&h->c.sess);
}

int pmapi_is_attached(const pmapi *h) { return h->sock != PM_BAD_SOCK; }

int pmapi_pair(pmapi *h)
{
    int rc = io(h, pmc_pair(&h->c));
    if (rc != 0) return rc;
    /* новый токен: старая половина ключа к нему не подходит */
    h->c.have_kpc = 0;
    crypto_wipe(h->c.k_pc, 32);
    rc = save_id(h);
    return rc != 0 ? rc : io(h, pmc_connect(&h->c));
}

int pmapi_forget_pairing(pmapi *h)
{
    pm_session_clear(&h->c.sess);
    h->c.paired = 0;
    h->c.have_kpc = 0;
    crypto_wipe(h->c.token_pk, 32);
    crypto_wipe(h->c.k_pc, 32);
    return save_id(h);
}

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
