#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <bcrypt.h>
#  include <wincrypt.h>
#else
#  define _POSIX_C_SOURCE 200809L
#  include <fcntl.h>
#  include <sys/stat.h>
#  include <unistd.h>
#endif

#include "pmclient.h"
#include "bip39.h"
#include "kdf.h"
#include "monocypher.h"
#include "wire.h"
#include "otp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void os_rng(void *buf, size_t len)
{
#ifdef _WIN32
    if (BCryptGenRandom(NULL, (PUCHAR)buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) abort();
#else
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f || fread(buf, 1, len, f) != len) abort();
    fclose(f);
#endif
}

void pmc_init(pm_client *c, pmc_xfer_fn xfer, void *ctx)
{
    memset(c, 0, sizeof *c);
    c->xfer = xfer;
    c->xfer_ctx = ctx;
    c->argon_blocks = 65536;   /* 64 МиБ */
    c->argon_passes = 3;
    os_rng(c->sk, 32);
    crypto_x25519_public_key(c->pk, c->sk);
}

void pmc_wipe(pm_client *c) { crypto_wipe(c, sizeof *c); }

/* ---------------- файлы ----------------
 * Пути приходят в UTF-8 (из GUI). На Windows fopen понимает их как ANSI и
 * не откроет профиль с кириллицей в имени пользователя — нужны W-функции.
 */
#ifdef _WIN32
static int widen(const char *utf8, wchar_t *out, int cap)
{
    return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8, -1, out, cap) > 0;
}
#endif

static FILE *open_utf8(const char *path, const char *mode)
{
#ifdef _WIN32
    wchar_t wp[MAX_PATH * 2], wm[8];
    if (!widen(path, wp, MAX_PATH * 2) || !widen(mode, wm, 8)) return NULL;
    return _wfopen(wp, wm);
#else
    return fopen(path, mode);
#endif
}

/* Запись через временный файл и переименование: сбой посреди записи не
 * портит единственную копию ключа ПК. На POSIX файл сразу создаётся 0600. */
static int write_atomic(const char *path, const uint8_t *data, size_t len)
{
    char tmp[1024];
    if (strlen(path) + 5 > sizeof tmp) return PMC_E_FILE;
    strcpy(tmp, path);
    strcat(tmp, ".tmp");
#ifdef _WIN32
    wchar_t wtmp[MAX_PATH * 2], wpath[MAX_PATH * 2];
    if (!widen(tmp, wtmp, MAX_PATH * 2) || !widen(path, wpath, MAX_PATH * 2)) return PMC_E_FILE;
    HANDLE hf = CreateFileW(wtmp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) return PMC_E_FILE;
    DWORD wr = 0;
    BOOL ok = WriteFile(hf, data, (DWORD)len, &wr, NULL) && wr == len && FlushFileBuffers(hf);
    CloseHandle(hf);
    if (!ok || !MoveFileExW(wtmp, wpath, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(wtmp);
        return PMC_E_FILE;
    }
    return 0;
#else
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return PMC_E_FILE;
    size_t off = 0;
    while (off < len) {
        ssize_t k = write(fd, data + off, len - off);
        if (k <= 0) { close(fd); unlink(tmp); return PMC_E_FILE; }
        off += (size_t)k;
    }
    if (fsync(fd) != 0 || close(fd) != 0 || rename(tmp, path) != 0) { unlink(tmp); return PMC_E_FILE; }
    return 0;
#endif
}

/* ---------------- файл идентичности ----------------
 * [4 "PMID"][1 ver][1 flags][sk 32][token_pk 32][k_pc 32]
 * Windows: содержимое шифруется DPAPI (привязка к учётной записи Windows).
 */
#define ID_LEN 102

int pmc_identity_save(const pm_client *c, const char *path)
{
    uint8_t b[ID_LEN];
    memcpy(b, "PMID", 4);
    b[4] = 1;
    b[5] = (uint8_t)((c->paired ? 1 : 0) | (c->have_kpc ? 2 : 0));
    memcpy(b + 6, c->sk, 32);
    memcpy(b + 38, c->token_pk, 32);
    memcpy(b + 70, c->k_pc, 32);

    const uint8_t *data = b;
    size_t data_len = sizeof b;
#ifdef _WIN32
    DATA_BLOB in = {(DWORD)sizeof b, b}, out = {0, NULL};
    if (!CryptProtectData(&in, L"pmtoken identity", NULL, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &out)) {
        crypto_wipe(b, sizeof b);
        return PMC_E_FILE;
    }
    data = out.pbData;
    data_len = out.cbData;
#endif
    int rc = write_atomic(path, data, data_len);
#ifdef _WIN32
    LocalFree(out.pbData);
#endif
    crypto_wipe(b, sizeof b);
    return rc;
}

int pmc_identity_load(pm_client *c, const char *path)
{
    uint8_t raw[1024];
    FILE *f = open_utf8(path, "rb");
    if (!f) return PMC_E_FILE;
    size_t n = fread(raw, 1, sizeof raw, f);
    fclose(f);

    const uint8_t *b = raw;
    size_t len = n;
#ifdef _WIN32
    DATA_BLOB in = {(DWORD)n, raw}, out = {0, NULL};
    if (!CryptUnprotectData(&in, NULL, NULL, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &out))
        return PMC_E_FILE;
    b = out.pbData;
    len = out.cbData;
#endif
    int rc = 0;
    if (len != ID_LEN || memcmp(b, "PMID", 4) != 0 || b[4] != 1) {
        rc = PMC_E_FILE;
    } else {
        c->paired = b[5] & 1;
        c->have_kpc = (b[5] >> 1) & 1;
        memcpy(c->sk, b + 6, 32);
        crypto_x25519_public_key(c->pk, c->sk);
        memcpy(c->token_pk, b + 38, 32);
        memcpy(c->k_pc, b + 70, 32);
    }
#ifdef _WIN32
    SecureZeroMemory(out.pbData, out.cbData);
    LocalFree(out.pbData);
#endif
    crypto_wipe(raw, sizeof raw);
    return rc;
}

/* ---------------- обмен ---------------- */

static long raw_xfer(pm_client *c, size_t out_len)
{
    long n = c->xfer(c->xfer_ctx, c->buf_out, out_len, c->buf_in, sizeof c->buf_in);
    if (n < 1) return PMC_E_IO;
    if (c->buf_in[0] == FR_ERROR) {
        if (n >= 2 && c->buf_in[1] == FE_DECRYPT) pm_session_clear(&c->sess);
        return n >= 2 ? PMC_E_TOKEN - c->buf_in[1] : PMC_E_PROTO;
    }
    return n;
}

/* Зашифрованный запрос. resp, resp_len — данные после статуса. */
static int request(pm_client *c, const uint8_t *req, size_t len,
                   const uint8_t **resp, size_t *resp_len)
{
    if (!c->sess.active) return PMC_E_NO_SESSION;
    if (len + PM_MAC_LEN + 1 > sizeof c->buf_out) return PMC_E_BUF;
    c->buf_out[0] = FR_DATA;
    size_t n = 1 + pm_session_seal(&c->sess, c->buf_out + 1, req, len);
    long r = raw_xfer(c, n);
    crypto_wipe(c->buf_out, n);
    if (r < 0) return (int)r;
    if (c->buf_in[0] != FR_DATA) return PMC_E_PROTO;
    long pl = pm_session_open(&c->sess, c->plain, c->buf_in + 1, (size_t)r - 1);
    if (pl < 1) { pm_session_clear(&c->sess); return PMC_E_PROTO; }
    if (resp) *resp = c->plain + 1;
    if (resp_len) *resp_len = (size_t)pl - 1;
    return c->plain[0];
}

static int simple_cmd(pm_client *c, uint8_t cmd)
{
    return request(c, &cmd, 1, NULL, NULL);
}

/* ---------------- сопряжение и сессия ---------------- */

int pmc_pair(pm_client *c)
{
    c->buf_out[0] = FR_PAIR;
    memcpy(c->buf_out + 1, c->pk, 32);
    long r = raw_xfer(c, 33);
    if (r < 0) return (int)r;
    if (r != 33 || c->buf_in[0] != FR_PAIR) return PMC_E_PROTO;
    memcpy(c->token_pk, c->buf_in + 1, 32);
    c->paired = 1;
    return 0;
}

int pmc_connect(pm_client *c)
{
    if (!c->paired) return PMC_E_NOT_PAIRED;
    uint8_t esk[32], epk[32];
    os_rng(esk, 32);
    crypto_x25519_public_key(epk, esk);
    c->buf_out[0] = FR_HELLO;
    memcpy(c->buf_out + 1, epk, 32);
    long r = raw_xfer(c, 33);
    if (r < 0) { crypto_wipe(esk, 32); return (int)r; }
    if (r != 33 || c->buf_in[0] != FR_HELLO) { crypto_wipe(esk, 32); return PMC_E_PROTO; }
    int e = pm_session_establish(&c->sess, PM_INITIATOR, c->sk, c->pk, esk, epk,
                                 c->token_pk, c->buf_in + 1);
    crypto_wipe(esk, 32);
    if (e != 0) return PMC_E_PROTO;
    /* Проверка ключей: если токен чужой, INFO не расшифруется */
    pmc_info_t info;
    int st = pmc_info(c, &info);
    if (st != 0) return st;
    if (info.proto != PM_PROTO_VERSION) {
        pm_session_clear(&c->sess);
        return PMC_E_VERSION;
    }
    return 0;
}

int pmc_info(pm_client *c, pmc_info_t *info)
{
    const uint8_t *d;
    size_t n;
    uint8_t cmd = CMD_INFO;
    int st = request(c, &cmd, 1, &d, &n);
    if (st != ST_OK) return st;
    if (n < 8) return PMC_E_PROTO;
    info->paired = (d[0] & INFO_PAIRED) != 0;
    info->setup_done = (d[0] & INFO_SETUP_DONE) != 0;
    info->unlocked = (d[0] & INFO_UNLOCKED) != 0;
    info->proto = d[1];
    info->count = (unsigned)(d[2] | d[3] << 8);
    info->uptime_s = wire_get32(d + 4);
    return 0;
}

/* ---------------- ключи ---------------- */

static int password_hash(pm_client *c, const char *password, uint8_t pw_hash[32])
{
    uint8_t salt[16];
    pm_salt_from_kpc(c->k_pc, salt);
    void *work = malloc((size_t)c->argon_blocks * 1024u);
    if (!work) return PMC_E_MEMORY;
    crypto_argon2_config cfg = {CRYPTO_ARGON2_ID, c->argon_blocks, c->argon_passes, 1};
    crypto_argon2_inputs in = {(const uint8_t *)password, salt, (uint32_t)strlen(password), 16};
    crypto_argon2(pw_hash, 32, work, cfg, in, crypto_argon2_no_extras);
    crypto_wipe(work, (size_t)c->argon_blocks * 1024u);
    free(work);
    return 0;
}

int pmc_setup_begin(pm_client *c, char *words, size_t cap)
{
    if (cap < 256) return PMC_E_BUF;
    uint8_t req[33], rand_pc[32];
    os_rng(rand_pc, 32);
    req[0] = CMD_SETUP_BEGIN;
    memcpy(req + 1, rand_pc, 32);
    const uint8_t *d;
    size_t n;
    int st = request(c, req, sizeof req, &d, &n);
    if (st == ST_OK && n != 32) st = PMC_E_PROTO;
    if (st == ST_OK) {
        /* seed = f(rand_token, rand_pc): ни одна сторона не выбирает его одна */
        pm_seed_from_rand(c->pending_seed, d, rand_pc);
        c->seed_pending = 1;
        bip39_to_string(c->pending_seed, words, cap);
    }
    crypto_wipe(rand_pc, 32);
    crypto_wipe(req, sizeof req);
    return st;
}

int pmc_setup_commit(pm_client *c, const char *master_password)
{
    if (!c->seed_pending) return PMC_E_SEED;
    uint8_t k_token[32], req[33];
    pm_keys_from_seed(c->pending_seed, k_token, c->k_pc);
    crypto_wipe(k_token, 32);          /* K_token ПК не хранит */
    req[0] = CMD_SETUP_COMMIT;
    int rc = password_hash(c, master_password, req + 1);
    if (rc == 0) rc = request(c, req, sizeof req, NULL, NULL);
    crypto_wipe(req, sizeof req);
    if (rc == ST_OK) {
        c->have_kpc = 1;
        crypto_wipe(c->pending_seed, 32);
        c->seed_pending = 0;
    }
    return rc;
}

int pmc_restore(pm_client *c, const char *words, const char *master_password,
                const uint8_t *backup, size_t backup_len)
{
    uint8_t seed[32];
    if (bip39_decode(words, seed) != 0) return PMC_E_SEED;
    size_t len = 1 + 96 + backup_len;
    uint8_t *req = malloc(len);
    if (!req) { crypto_wipe(seed, 32); return PMC_E_MEMORY; }
    req[0] = CMD_RESTORE;
    pm_keys_from_seed(seed, req + 1, c->k_pc);
    memcpy(req + 33, c->k_pc, 32);
    crypto_wipe(seed, 32);
    int rc = password_hash(c, master_password, req + 65);
    if (backup_len) memcpy(req + 97, backup, backup_len);
    if (rc == 0) rc = request(c, req, len, NULL, NULL);
    crypto_wipe(req, len);
    free(req);
    if (rc == ST_OK) c->have_kpc = 1;
    else { crypto_wipe(c->k_pc, 32); c->have_kpc = 0; }
    return rc;
}

int pmc_unlock(pm_client *c, const char *master_password)
{
    if (!c->have_kpc) return PMC_E_NO_KEY;
    uint8_t req[65];
    req[0] = CMD_UNLOCK;
    memcpy(req + 1, c->k_pc, 32);
    int rc = password_hash(c, master_password, req + 33);
    if (rc == 0) rc = request(c, req, sizeof req, NULL, NULL);
    crypto_wipe(req, sizeof req);
    return rc;
}

int pmc_lock(pm_client *c) { return simple_cmd(c, CMD_LOCK); }

/* ---------------- записи ---------------- */

static void copy_str(wire_r *r, char *dst, size_t cap, size_t len_bytes)
{
    size_t l = len_bytes == 1 ? wire_u8(r) : wire_u16(r);
    const uint8_t *s = wire_bytes(r, l);
    if (!s) return;
    if (l >= cap) l = cap ? cap - 1 : 0;
    if (cap) { memcpy(dst, s, l); dst[l] = 0; }
}

int pmc_list(pm_client *c, pmc_list_cb cb, void *ctx)
{
    const uint8_t *d;
    size_t n;
    int st = request(c, (const uint8_t[]){CMD_LIST}, 1, &d, &n);
    if (st != ST_OK) return st;
    wire_r r = {d, n, 0};
    unsigned cnt = wire_u16(&r);
    for (unsigned i = 0; i < cnt && !r.err; i++) {
        char cat[256], name[256];
        uint32_t id = wire_u32(&r);
        copy_str(&r, cat, sizeof cat, 1);
        copy_str(&r, name, sizeof name, 1);
        uint8_t otp = wire_u8(&r);
        if (!r.err && cb) cb(ctx, id, cat, name, otp);
    }
    return r.err ? PMC_E_PROTO : 0;
}

int pmc_get(pm_client *c, uint32_t id, char *login, size_t login_cap,
            char *password, size_t pw_cap)
{
    uint8_t req[5] = {CMD_GET};
    wire_put32(req + 1, id);
    const uint8_t *d;
    size_t n;
    int st = request(c, req, sizeof req, &d, &n);
    if (st != ST_OK) return st;
    wire_r r = {d, n, 0};
    copy_str(&r, login, login_cap, 1);
    copy_str(&r, password, pw_cap, 2);
    crypto_wipe(c->plain, sizeof c->plain);
    return r.err ? PMC_E_PROTO : 0;
}

/* [cat][name][login][pw] — общая часть ADD и UPDATE. */
static int put_fields(wire_w *w, const char *category, const char *name, const char *login,
                      const char *password)
{
    size_t pl = strlen(password);
    if (strlen(category) > PM_MAX_STR || strlen(name) > PM_MAX_STR ||
        strlen(login) > PM_MAX_STR || pl > PM_MAX_PASSWORD)
        return ST_BAD_ARGS;
    wire_put_str(w, category);
    wire_put_str(w, name);
    wire_put_str(w, login);
    wire_put_u16(w, (uint16_t)pl);
    wire_put_bytes(w, password, pl);
    return 0;
}

static void put_otp(wire_w *w, const uint8_t *otp, size_t otp_len)
{
    wire_put_u8(w, (uint8_t)otp_len);
    if (otp_len) wire_put_bytes(w, otp, otp_len);
}

#define FIELDS_MAX (3 * 256 + 2 + PM_MAX_PASSWORD + 1 + OTP_BLOB_MAX)

int pmc_add_otp(pm_client *c, const char *category, const char *name, const char *login,
                const char *password, const uint8_t *otp, size_t otp_len, uint32_t *id_out)
{
    if (otp_len > OTP_BLOB_MAX || (otp_len && pm_otp_validate(otp, otp_len) != 0)) return ST_BAD_ARGS;
    uint8_t req[1 + FIELDS_MAX];
    wire_w w = {req, sizeof req, 0, 0};
    wire_put_u8(&w, CMD_ADD);
    int st = put_fields(&w, category, name, login, password);
    if (st == 0) {
        put_otp(&w, otp, otp_len);
        const uint8_t *d;
        size_t n;
        st = w.err ? ST_BAD_ARGS : request(c, req, w.n, &d, &n);
        if (st == ST_OK && id_out) *id_out = n >= 4 ? wire_get32(d) : 0;
    }
    crypto_wipe(req, sizeof req);
    return st;
}

int pmc_add(pm_client *c, const char *category, const char *name, const char *login,
            const char *password, uint32_t *id_out)
{
    return pmc_add_otp(c, category, name, login, password, NULL, 0, id_out);
}

int pmc_update(pm_client *c, uint32_t id, const char *category, const char *name, const char *login,
               const char *password, int otp_mode, const uint8_t *otp, size_t otp_len)
{
    if (otp_mode < PMC_OTP_REMOVE || otp_mode > PMC_OTP_KEEP) return ST_BAD_ARGS;
    if (otp_mode == PMC_OTP_SET && (otp_len == 0 || otp_len > OTP_BLOB_MAX || pm_otp_validate(otp, otp_len) != 0))
        return ST_BAD_ARGS;
    uint8_t req[1 + 4 + FIELDS_MAX + 1];
    wire_w w = {req, sizeof req, 0, 0};
    wire_put_u8(&w, CMD_UPDATE);
    wire_put_u32(&w, id);
    int st = put_fields(&w, category, name, login, password);
    if (st == 0) {
        wire_put_u8(&w, (uint8_t)otp_mode);
        if (otp_mode == PMC_OTP_SET) put_otp(&w, otp, otp_len);
        st = w.err ? ST_BAD_ARGS : request(c, req, w.n, NULL, NULL);
    }
    crypto_wipe(req, sizeof req);
    return st;
}

int pmc_otp(pm_client *c, uint32_t id, uint64_t unix_time, char *code, size_t cap,
            uint8_t *type, uint8_t *period)
{
    uint8_t req[13] = {CMD_OTP};
    wire_put32(req + 1, id);
    wire_put32(req + 5, (uint32_t)unix_time);
    wire_put32(req + 9, (uint32_t)(unix_time >> 32));
    const uint8_t *d;
    size_t n;
    int st = request(c, req, sizeof req, &d, &n);
    if (st != ST_OK) return st;
    wire_r r = {d, n, 0};
    uint8_t t = wire_u8(&r), p = wire_u8(&r);
    if (cap == 0) return PMC_E_BUF;
    copy_str(&r, code, cap, 1);
    crypto_wipe(c->plain, sizeof c->plain);
    if (r.err) return PMC_E_PROTO;
    if (type) *type = t;
    if (period) *period = p;
    return 0;
}

int pmc_delete(pm_client *c, uint32_t id)
{
    uint8_t req[5] = {CMD_DELETE};
    wire_put32(req + 1, id);
    return request(c, req, sizeof req, NULL, NULL);
}

int pmc_log(pm_client *c, pmc_log_cb cb, void *ctx)
{
    const uint8_t *d;
    size_t n;
    int st = request(c, (const uint8_t[]){CMD_LOG}, 1, &d, &n);
    if (st != ST_OK) return st;
    wire_r r = {d, n, 0};
    unsigned cnt = wire_u8(&r);
    for (unsigned i = 0; i < cnt && !r.err; i++) {
        uint32_t t = wire_u32(&r);
        uint8_t cmd = wire_u8(&r), s = wire_u8(&r);
        uint32_t id = wire_u32(&r);
        if (!r.err && cb) cb(ctx, t, cmd, s, id);
    }
    return r.err ? PMC_E_PROTO : 0;
}

int pmc_backup(pm_client *c, uint8_t *out, size_t cap, size_t *len)
{
    const uint8_t *d;
    size_t n;
    int st = request(c, (const uint8_t[]){CMD_BACKUP}, 1, &d, &n);
    if (st != ST_OK) return st;
    if (n > cap) return PMC_E_BUF;
    memcpy(out, d, n);
    *len = n;
    return 0;
}

int pmc_factory_reset(pm_client *c)
{
    int st = simple_cmd(c, CMD_FACTORY_RESET);
    if (st == ST_OK) {
        pm_session_clear(&c->sess);
        c->paired = 0;
        c->have_kpc = 0;
        crypto_wipe(c->token_pk, 32);
        crypto_wipe(c->k_pc, 32);
    }
    return st;
}

const char *pmc_strerror(int code)
{
    switch (code) {
    case 0: return "ok";
    case ST_BAD_ARGS: return "неверные аргументы";
    case ST_LOCKED: return "хранилище заблокировано (нужен unlock)";
    case ST_NOT_SETUP: return "токен не настроен";
    case ST_ALREADY_SETUP: return "токен уже настроен";
    case ST_WRONG_KEY: return "неверный мастер-пароль или ключ";
    case ST_NOT_FOUND: return "запись не найдена";
    case ST_RATE_LIMIT: return "слишком часто (лимит расшифровок), подождите";
    case ST_FULL: return "хранилище заполнено";
    case ST_BACKOFF: return "много неверных попыток, подождите";
    case ST_FLASH: return "ошибка flash";
    case ST_UNKNOWN_CMD: return "неизвестная команда";
    case ST_NO_OTP: return "у записи нет одноразовых кодов";
    case ST_BAD_TIME: return "часы компьютера ушли вперёд относительно токена";
    case PMC_E_VERSION: return "версия протокола токена не совпадает с программой";
    case PMC_E_IO: return "нет связи с токеном";
    case PMC_E_PROTO: return "ошибка протокола";
    case PMC_E_NO_SESSION: return "нет сессии (connect)";
    case PMC_E_NOT_PAIRED: return "ПК не сопряжён с токеном";
    case PMC_E_SEED: return "фраза восстановления неверна";
    case PMC_E_NO_KEY: return "на этом ПК нет половины ключа (setup/restore)";
    case PMC_E_MEMORY: return "не хватает памяти";
    case PMC_E_FILE: return "ошибка файла идентичности";
    case PMC_E_BUF: return "мал буфер";
    case PMC_E_TOKEN - FE_ALREADY_PAIRED: return "токен уже сопряжён с другим ПК";
    case PMC_E_TOKEN - FE_NOT_PAIRED: return "токен не сопряжён";
    case PMC_E_TOKEN - FE_NO_SESSION: return "сессия токена закрыта";
    case PMC_E_TOKEN - FE_DECRYPT: return "токен не смог расшифровать кадр (чужой ПК?)";
    case PMC_E_TOKEN - FE_BAD_FRAME: return "токен отверг кадр";
    default: return "неизвестная ошибка";
    }
}
