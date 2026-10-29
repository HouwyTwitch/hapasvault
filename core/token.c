#include "token.h"
#include "hal.h"
#include "kdf.h"
#include "monocypher.h"
#include "otp.h"
#include "proto.h"
#include "session.h"
#include "store.h"
#include "wire.h"
#include <string.h>

/* ---------------- состояние ---------------- */

static pm_config  g_cfg;
static pm_session g_sess;

static int      g_unlocked;
static uint8_t  g_kvault[32];
static uint8_t  g_plain[STORE_PLAIN_MAX];  /* расшифрованное хранилище (только в RAM) */
static size_t   g_plain_len;

static int      g_setup_pending;
static uint8_t  g_seed[32];

static uint64_t g_last_activity;
static uint64_t g_get_times[TOKEN_RATE_N];
static unsigned g_get_pos;
static uint64_t g_otp_times[TOKEN_OTP_RATE_N];
static unsigned g_otp_pos;
static uint64_t g_backoff_until;

/* Часов у токена нет: время для OTP присылает ПК. Чтобы ПК не мог заранее
 * набрать коды «из будущего», токен помнит самое позднее принятое время и
 * дальше разрешает ему идти только вместе со своими монотонными часами. */
static uint64_t g_otp_time;      /* unix-секунды, 0 — ещё не было */
static uint64_t g_otp_at;        /* hal_millis() в момент g_otp_time */

typedef struct { uint32_t t; uint8_t cmd, st; uint32_t id; } log_ent;
static log_ent  g_log[TOKEN_LOG_SIZE];
static unsigned g_log_pos, g_log_cnt;

static uint8_t  g_req[PM_MAX_FRAME];
static uint8_t  g_resp[PM_MAX_FRAME];

/* ---------------- утилиты ---------------- */

static void log_event(uint8_t cmd, uint8_t st, uint32_t id)
{
    log_ent *e = &g_log[g_log_pos];
    e->t = (uint32_t)(hal_millis() / 1000u);
    e->cmd = cmd; e->st = st; e->id = id;
    g_log_pos = (g_log_pos + 1) % TOKEN_LOG_SIZE;
    if (g_log_cnt < TOKEN_LOG_SIZE) g_log_cnt++;
}

static void lock_vault(void)
{
    crypto_wipe(g_kvault, sizeof g_kvault);
    crypto_wipe(g_plain, sizeof g_plain);
    g_plain_len = 0;
    g_unlocked = 0;
    if (g_setup_pending) { crypto_wipe(g_seed, sizeof g_seed); g_setup_pending = 0; }
}

static void drop_session(void)
{
    lock_vault();
    pm_session_clear(&g_sess);
    hal_led(LED_IDLE);
}

static uint32_t backoff_ms(uint32_t fails);

void token_public_key(uint8_t pub[32]) { crypto_x25519_public_key(pub, g_cfg.token_sk); }

void token_init(void)
{
    lock_vault();
    if (store_config_load(&g_cfg) != 0) {
        /* первое включение: свой статический ключ */
        memset(&g_cfg, 0, sizeof g_cfg);
        hal_rng(g_cfg.token_sk, 32);
        store_config_save(&g_cfg);
    }
    /* неверные пароли пережили перезагрузку: задержка действует и после неё */
    g_backoff_until = hal_millis() + backoff_ms(g_cfg.fails);
    g_last_activity = hal_millis();
    hal_led(LED_IDLE);
}

void token_disconnect(void) { drop_session(); }

void token_tick(void)
{
    if (g_sess.active && hal_millis() - g_last_activity > TOKEN_IDLE_TIMEOUT_MS) drop_session();
}

static size_t frame_err(uint8_t *out, uint8_t code)
{
    out[0] = FR_ERROR;
    out[1] = code;
    return 2;
}

/* ---------------- записи хранилища ----------------
 * Открытый текст: [u16 count][u32 next_id | версия << 24] затем записи
 *   v1: [u32 id][str cat][str name][str login][pw password]
 *   v2: то же + [u8 otp_len][otp]  (otp.h)
 * Хранилище v1 переводится в v2 при открытии.
 */
#define VH 6u
#define V_FORMAT 2u

static uint16_t v_count(void) { return (uint16_t)(g_plain[0] | g_plain[1] << 8); }
static void v_set_count(uint16_t n) { g_plain[0] = (uint8_t)n; g_plain[1] = (uint8_t)(n >> 8); }
static uint32_t v_next_id(void) { return wire_get32(g_plain + 2) & 0x00FFFFFFu; }
static unsigned v_format(void) { return g_plain[5] ? g_plain[5] : 1u; }
static void v_set_next_id(uint32_t id) { wire_put32(g_plain + 2, (id & 0x00FFFFFFu) | V_FORMAT << 24); }

/* Размер записи в буфере buf[0..len) по смещению off (0 если повреждена). */
static size_t entry_size(const uint8_t *buf, size_t len, size_t off, unsigned format)
{
    size_t p = off + 4;
    for (int i = 0; i < 3; i++) {
        if (p >= len) return 0;
        p += 1u + buf[p];
    }
    if (p + 2 > len) return 0;
    p += 2u + (size_t)(buf[p] | buf[p + 1] << 8);
    if (format >= 2) {
        if (p >= len) return 0;
        p += 1u + buf[p];
    }
    return p > len ? 0 : p - off;
}

static size_t v_entry_size(size_t off) { return entry_size(g_plain, g_plain_len, off, V_FORMAT); }

/* Начало поля OTP ([u8 len][blob]) в записи. */
static const uint8_t *v_entry_otp(size_t off)
{
    const uint8_t *e = g_plain + off + 4;
    for (int i = 0; i < 3; i++) e += 1u + e[0];
    return e + 2u + (size_t)(e[0] | e[1] << 8);
}

/* Перевести открытое хранилище v1 в v2 (добавить пустое поле OTP). 0 = ок. */
static int v_migrate(void)
{
    if (v_format() >= 2) return 0;
    static uint8_t tmp[STORE_PLAIN_MAX];
    size_t in = VH, out = VH, n = v_count();
    memcpy(tmp, g_plain, VH);
    for (size_t i = 0; i < n; i++) {
        size_t sz = entry_size(g_plain, g_plain_len, in, 1);
        if (!sz || out + sz + 1 > STORE_PLAIN_MAX) { crypto_wipe(tmp, sizeof tmp); return -1; }
        memcpy(tmp + out, g_plain + in, sz);
        tmp[out + sz] = 0;
        in += sz;
        out += sz + 1;
    }
    memcpy(g_plain, tmp, out);
    crypto_wipe(tmp, sizeof tmp);
    g_plain_len = out;
    v_set_next_id(wire_get32(g_plain + 2));
    return store_vault_save(g_kvault, g_plain, g_plain_len);
}

static long v_find(uint32_t id)
{
    size_t off = VH;
    for (unsigned i = 0; i < v_count(); i++) {
        size_t sz = v_entry_size(off);
        if (!sz) return -1;
        if (wire_get32(g_plain + off) == id) return (long)off;
        off += sz;
    }
    return -1;
}

static void v_init_empty(void)
{
    memset(g_plain, 0, VH);
    v_set_next_id(1);
    g_plain_len = VH;
}

static int v_save(void) { return store_vault_save(g_kvault, g_plain, g_plain_len); }

/* ---------------- команды ---------------- */

/* Скользящее окно: не больше n событий за TOKEN_RATE_WINDOW_MS. */
static int window_ok(uint64_t *times, unsigned n, unsigned *pos)
{
    uint64_t now = hal_millis();
    uint64_t oldest = times[*pos];   /* самая старая из последних n */
    if (oldest && now - oldest < TOKEN_RATE_WINDOW_MS) return 0;
    times[*pos] = now ? now : 1;
    *pos = (*pos + 1) % n;
    return 1;
}

static int rate_ok(void) { return window_ok(g_get_times, TOKEN_RATE_N, &g_get_pos); }

static uint32_t backoff_ms(uint32_t fails)
{
    if (fails < TOKEN_FREE_ATTEMPTS) return 0;
    uint32_t e = fails - TOKEN_FREE_ATTEMPTS;
    uint32_t ms = 1000u << (e > 12 ? 12 : e);    /* 1, 2, 4 ... с, не больше часа */
    return ms > TOKEN_BACKOFF_MAX_MS ? TOKEN_BACKOFF_MAX_MS : ms;
}

/* Счётчик пишется во flash ДО ответа: выдёргивание токена после неверного
 * пароля не сбрасывает задержку. */
static void register_fail(void)
{
    if (g_cfg.fails < 0xFFFFFFFFu) g_cfg.fails++;
    store_config_save(&g_cfg);
    g_backoff_until = hal_millis() + backoff_ms(g_cfg.fails);
}

static void reset_fails(void)
{
    if (!g_cfg.fails) return;
    g_cfg.fails = 0;
    store_config_save(&g_cfg);
}

/* Время ПК для OTP: не дальше вперёд, чем позволяют часы токена. */
static int otp_time_ok(uint64_t t)
{
    if (t < 1500000000u) return 0;                    /* 2017 год: заведомо неверные часы */
    uint64_t now = hal_millis();
    if (g_otp_time) {
        uint64_t expected = g_otp_time + (now - g_otp_at) / 1000u;
        if (t > expected + TOKEN_OTP_SKEW_S) return 0;
    }
    if (t > g_otp_time) {
        g_otp_time = t;
        g_otp_at = now;
    }
    return 1;
}

/* Разобрать [u8 len][otp] из запроса; out_len = 0 — нет OTP. 0 = ок. */
static int read_otp(wire_r *r, const uint8_t **blob, size_t *out_len)
{
    size_t l = wire_u8(r);
    *blob = wire_bytes(r, l);
    *out_len = l;
    if (r->err) return -1;
    return l == 0 || pm_otp_validate(*blob, l) == 0 ? 0 : -1;
}

static size_t do_command(const uint8_t *req, size_t len, uint8_t *resp)
{
    wire_r r = {req, len, 0};
    wire_w w = {resp, PM_MAX_FRAME - PM_MAC_LEN - 1, 0, 0};
    uint8_t cmd = wire_u8(&r);
    uint8_t st = ST_OK;
    uint32_t log_id = 0;
    int do_log = 0;

    wire_put_u8(&w, ST_OK);   /* статус перезаписывается в конце */

    switch (cmd) {
    case CMD_INFO: {
        uint8_t flags = INFO_PAIRED;
        if (g_cfg.flags & CFG_SETUP) flags |= INFO_SETUP_DONE;
        if (g_unlocked) flags |= INFO_UNLOCKED;
        wire_put_u8(&w, flags);
        wire_put_u8(&w, PM_PROTO_VERSION);
        wire_put_u16(&w, g_unlocked ? v_count() : 0);
        wire_put_u32(&w, (uint32_t)(hal_millis() / 1000u));
        break;
    }

    case CMD_SETUP_BEGIN: {
        const uint8_t *rand_pc = wire_bytes(&r, 32);
        if (r.err || r.n) { st = ST_BAD_ARGS; break; }
        if (g_cfg.flags & CFG_SETUP) { st = ST_ALREADY_SETUP; break; }
        uint8_t rand_tok[32];
        hal_rng(rand_tok, 32);
        pm_seed_from_rand(g_seed, rand_tok, rand_pc);
        g_setup_pending = 1;
        wire_put_bytes(&w, rand_tok, 32);
        crypto_wipe(rand_tok, 32);
        break;
    }

    case CMD_SETUP_COMMIT: {
        const uint8_t *pw_hash = wire_bytes(&r, 32);
        if (r.err || r.n || !g_setup_pending) { st = ST_BAD_ARGS; break; }
        uint8_t k_pc[32];
        pm_keys_from_seed(g_seed, g_cfg.k_token, k_pc);
        pm_vault_key(g_kvault, g_cfg.k_token, k_pc, pw_hash);
        crypto_wipe(k_pc, 32);
        crypto_wipe(g_seed, 32);
        g_setup_pending = 0;
        v_init_empty();
        g_cfg.flags |= CFG_SETUP;
        if (v_save() != 0 || store_config_save(&g_cfg) != 0) {
            g_cfg.flags &= (uint8_t)~CFG_SETUP;
            lock_vault();
            st = ST_FLASH;
            break;
        }
        g_unlocked = 1;
        hal_led(LED_UNLOCKED);
        do_log = 1;
        break;
    }

    case CMD_RESTORE: {
        const uint8_t *k_tok = wire_bytes(&r, 32);
        const uint8_t *k_pc = wire_bytes(&r, 32);
        const uint8_t *pw_hash = wire_bytes(&r, 32);
        if (r.err) { st = ST_BAD_ARGS; break; }
        if (g_cfg.flags & CFG_SETUP) { st = ST_ALREADY_SETUP; break; }
        const uint8_t *blob = r.p;
        size_t blob_len = r.n;
        pm_vault_key(g_kvault, k_tok, k_pc, pw_hash);
        if (blob_len) {
            size_t pl;
            if (store_vault_put_raw(blob, blob_len) != 0) { st = ST_BAD_ARGS; lock_vault(); break; }
            if (store_vault_load(g_kvault, g_plain, &pl) != 0) {
                store_wipe();                           /* не тот ключ: не оставляем мусор */
                store_config_save(&g_cfg);
                st = ST_WRONG_KEY; lock_vault(); break;
            }
            g_plain_len = pl;
            if (v_migrate() != 0) { st = ST_FULL; lock_vault(); break; }
        } else {
            v_init_empty();
            if (v_save() != 0) { st = ST_FLASH; lock_vault(); break; }
        }
        memcpy(g_cfg.k_token, k_tok, 32);
        g_cfg.flags |= CFG_SETUP;
        if (store_config_save(&g_cfg) != 0) { st = ST_FLASH; lock_vault(); break; }
        g_unlocked = 1;
        hal_led(LED_UNLOCKED);
        do_log = 1;
        break;
    }

    case CMD_UNLOCK: {
        const uint8_t *k_pc = wire_bytes(&r, 32);
        const uint8_t *pw_hash = wire_bytes(&r, 32);
        if (r.err || r.n) { st = ST_BAD_ARGS; break; }
        if (!(g_cfg.flags & CFG_SETUP)) { st = ST_NOT_SETUP; break; }
        if (hal_millis() < g_backoff_until) { st = ST_BACKOFF; break; }
        lock_vault();
        pm_vault_key(g_kvault, g_cfg.k_token, k_pc, pw_hash);
        size_t pl;
        int lr = store_vault_load(g_kvault, g_plain, &pl);
        if (lr != 0) {
            lock_vault();
            if (lr == -2) register_fail();
            st = lr == -2 ? ST_WRONG_KEY : ST_FLASH;
        } else {
            g_plain_len = pl;
            reset_fails();
            if (v_migrate() != 0) { lock_vault(); st = ST_FULL; break; }
            g_unlocked = 1;
            hal_led(LED_UNLOCKED);
        }
        do_log = 1;
        break;
    }

    case CMD_LOCK:
        lock_vault();
        hal_led(LED_SESSION);
        break;

    case CMD_LIST: {
        if (!g_unlocked) { st = ST_LOCKED; break; }
        uint16_t n = v_count();
        wire_put_u16(&w, n);
        size_t off = VH;
        for (unsigned i = 0; i < n; i++) {
            size_t sz = v_entry_size(off);
            if (!sz) break;
            const uint8_t *e = g_plain + off;
            wire_put_u32(&w, wire_get32(e));
            wire_put_bytes(&w, e + 4, 1u + e[4]);                 /* cat */
            wire_put_bytes(&w, e + 5 + e[4], 1u + e[5 + e[4]]);   /* name */
            const uint8_t *otp = v_entry_otp(off);
            wire_put_u8(&w, otp[0] ? otp[1] : OTP_NONE);
            off += sz;
        }
        break;
    }

    case CMD_GET: {
        uint32_t id = wire_u32(&r);
        if (r.err || r.n) { st = ST_BAD_ARGS; break; }
        if (!g_unlocked) { st = ST_LOCKED; break; }
        log_id = id; do_log = 1;
        long off = v_find(id);
        if (off < 0) { st = ST_NOT_FOUND; break; }
        if (!rate_ok()) { st = ST_RATE_LIMIT; break; }
        const uint8_t *e = g_plain + off + 4;
        e += 1u + e[0];                    /* пропустить cat */
        e += 1u + e[0];                    /* пропустить name */
        size_t login_sz = 1u + e[0];
        size_t pw_sz = 2u + (size_t)(e[login_sz] | e[login_sz + 1] << 8);
        wire_put_bytes(&w, e, login_sz + pw_sz);
        break;
    }

    case CMD_ADD: {
        if (!g_unlocked) { st = ST_LOCKED; break; }
        size_t start = r.n;
        const uint8_t *body = r.p;
        size_t cl = wire_u8(&r); wire_bytes(&r, cl);
        size_t nl = wire_u8(&r); wire_bytes(&r, nl);
        size_t ll = wire_u8(&r); wire_bytes(&r, ll);
        size_t pl = wire_u16(&r); wire_bytes(&r, pl);
        const uint8_t *otp = NULL;
        size_t ol = 0;
        int no_otp_field = !r.err && r.n == 0;          /* старый клиент: поля OTP нет */
        if (!no_otp_field && read_otp(&r, &otp, &ol) != 0) { st = ST_BAD_ARGS; break; }
        if (r.err || r.n || nl == 0 || pl > PM_MAX_PASSWORD) { st = ST_BAD_ARGS; break; }
        size_t body_len = start - (no_otp_field ? 0 : 1 + ol);
        if (g_plain_len + 4 + body_len + 1 + ol > STORE_PLAIN_MAX || v_count() == 0xFFFF ||
            v_next_id() >= 0x00FFFFFFu) { st = ST_FULL; break; }
        uint32_t id = v_next_id();
        size_t old_len = g_plain_len;
        wire_put32(g_plain + g_plain_len, id);
        memcpy(g_plain + g_plain_len + 4, body, body_len);
        g_plain_len += 4 + body_len;
        g_plain[g_plain_len++] = (uint8_t)ol;
        if (ol) memcpy(g_plain + g_plain_len, otp, ol);
        g_plain_len += ol;
        v_set_count((uint16_t)(v_count() + 1));
        v_set_next_id(id + 1);
        if (v_save() != 0) {                       /* откат в RAM */
            crypto_wipe(g_plain + old_len, g_plain_len - old_len);
            g_plain_len = old_len;
            v_set_count((uint16_t)(v_count() - 1));
            v_set_next_id(id);
            st = ST_FLASH; break;
        }
        wire_put_u32(&w, id);
        log_id = id; do_log = 1;
        break;
    }

    case CMD_UPDATE: {
        uint32_t id = wire_u32(&r);
        if (!g_unlocked) { st = ST_LOCKED; break; }
        const uint8_t *body = r.p;
        size_t cl = wire_u8(&r); wire_bytes(&r, cl);
        size_t nl = wire_u8(&r); wire_bytes(&r, nl);
        size_t ll = wire_u8(&r); wire_bytes(&r, ll);
        size_t pl = wire_u16(&r); wire_bytes(&r, pl);
        size_t body_len = (size_t)(r.p - body);
        uint8_t mode = wire_u8(&r);
        const uint8_t *otp = NULL;
        size_t ol = 0;
        if (mode == 1 && (read_otp(&r, &otp, &ol) != 0 || ol == 0)) { st = ST_BAD_ARGS; break; }
        if (r.err || r.n || nl == 0 || pl > PM_MAX_PASSWORD || mode > 2) { st = ST_BAD_ARGS; break; }
        log_id = id; do_log = 1;
        long off = v_find(id);
        if (off < 0) { st = ST_NOT_FOUND; break; }
        if (mode == 2) {
            const uint8_t *old = v_entry_otp((size_t)off);
            ol = old[0];
            otp = old + 1;
        }
        /* новая запись собирается отдельно: старая ещё нужна (mode 2 берёт её OTP) */
        static uint8_t entry[4 + 3 * 256 + 2 + PM_MAX_PASSWORD + 1 + OTP_BLOB_MAX];
        size_t el = 0;
        wire_put32(entry, id);
        memcpy(entry + 4, body, body_len);
        el = 4 + body_len;
        entry[el++] = (uint8_t)ol;
        if (ol) memcpy(entry + el, otp, ol);
        el += ol;
        size_t sz = v_entry_size((size_t)off);
        if (g_plain_len - sz + el > STORE_PLAIN_MAX) { crypto_wipe(entry, el); st = ST_FULL; break; }
        size_t tail = g_plain_len - (size_t)off - sz;
        memmove(g_plain + off + el, g_plain + off + sz, tail);
        memcpy(g_plain + off, entry, el);
        crypto_wipe(entry, el);
        if (sz > el) crypto_wipe(g_plain + g_plain_len - (sz - el), sz - el);
        g_plain_len = g_plain_len - sz + el;
        if (v_save() != 0) { st = ST_FLASH; lock_vault(); }   /* RAM уже изменён: перечитать при unlock */
        break;
    }

    case CMD_OTP: {
        uint32_t id = wire_u32(&r);
        uint64_t t = wire_u64(&r);
        if (r.err || r.n) { st = ST_BAD_ARGS; break; }
        if (!g_unlocked) { st = ST_LOCKED; break; }
        log_id = id; do_log = 1;
        long off = v_find(id);
        if (off < 0) { st = ST_NOT_FOUND; break; }
        const uint8_t *otp = v_entry_otp((size_t)off);
        if (!otp[0]) { st = ST_NO_OTP; break; }
        if (!otp_time_ok(t)) { st = ST_BAD_TIME; break; }
        if (!window_ok(g_otp_times, TOKEN_OTP_RATE_N, &g_otp_pos)) { st = ST_RATE_LIMIT; break; }
        char code[OTP_CODE_MAX + 1];
        int cl = pm_otp_code(otp + 1, otp[0], t, code);
        if (cl < 0) { st = ST_FLASH; break; }
        wire_put_u8(&w, otp[1]);       /* тип */
        wire_put_u8(&w, otp[4]);       /* период */
        wire_put_u8(&w, (uint8_t)cl);
        wire_put_bytes(&w, code, (size_t)cl);
        crypto_wipe(code, sizeof code);
        break;
    }

    case CMD_DELETE: {
        uint32_t id = wire_u32(&r);
        if (r.err || r.n) { st = ST_BAD_ARGS; break; }
        if (!g_unlocked) { st = ST_LOCKED; break; }
        log_id = id; do_log = 1;
        long off = v_find(id);
        if (off < 0) { st = ST_NOT_FOUND; break; }
        size_t sz = v_entry_size((size_t)off);
        memmove(g_plain + off, g_plain + off + sz, g_plain_len - (size_t)off - sz);
        g_plain_len -= sz;
        crypto_wipe(g_plain + g_plain_len, sz);
        v_set_count((uint16_t)(v_count() - 1));
        if (v_save() != 0) { st = ST_FLASH; lock_vault(); }   /* RAM уже изменён: перечитать при unlock */
        break;
    }

    case CMD_LOG: {
        if (!g_unlocked) { st = ST_LOCKED; break; }
        wire_put_u8(&w, (uint8_t)g_log_cnt);
        for (unsigned i = 0; i < g_log_cnt; i++) {
            const log_ent *e = &g_log[(g_log_pos + TOKEN_LOG_SIZE - g_log_cnt + i) % TOKEN_LOG_SIZE];
            wire_put_u32(&w, e->t);
            wire_put_u8(&w, e->cmd);
            wire_put_u8(&w, e->st);
            wire_put_u32(&w, e->id);
        }
        break;
    }

    case CMD_BACKUP: {
        if (!g_unlocked) { st = ST_LOCKED; break; }
        long n = store_vault_raw(w.p + w.n, w.cap - w.n);
        if (n < 0) { st = ST_FLASH; break; }
        w.n += (size_t)n;
        do_log = 1;
        break;
    }

    case CMD_FACTORY_RESET:
        if (!g_unlocked) { st = ST_LOCKED; break; }
        store_wipe();
        crypto_wipe(&g_cfg, sizeof g_cfg);
        lock_vault();
        g_log_cnt = g_log_pos = 0;
        token_init();          /* новый статический ключ, не сопряжён */
        /* ответ уйдёт по текущей сессии, после чего она закрывается вызывающим */
        break;

    default:
        st = ST_UNKNOWN_CMD;
    }

    if (do_log) log_event(cmd, st, log_id);
    if (st != ST_OK || w.err) {
        w.n = 1;
        if (w.err && st == ST_OK) st = ST_FULL;
    }
    resp[0] = st;
    return w.n;
}

/* ---------------- кадры ---------------- */

size_t token_handle(const uint8_t *in, size_t len, uint8_t *out, size_t cap)
{
    if (len < 1 || cap < 64) return frame_err(out, FE_BAD_FRAME);
    g_last_activity = hal_millis();

    switch (in[0]) {
    case FR_PAIR: {
        if (len != 33) return frame_err(out, FE_BAD_FRAME);
        if (g_cfg.flags & CFG_PAIRED) return frame_err(out, FE_ALREADY_PAIRED);
        memcpy(g_cfg.pc_pub, in + 1, 32);
        g_cfg.flags |= CFG_PAIRED;
        if (store_config_save(&g_cfg) != 0) {
            g_cfg.flags &= (uint8_t)~CFG_PAIRED;
            return frame_err(out, FE_BAD_FRAME);
        }
        out[0] = FR_PAIR;
        token_public_key(out + 1);
        return 33;
    }

    case FR_HELLO: {
        if (len != 33) return frame_err(out, FE_BAD_FRAME);
        if (!(g_cfg.flags & CFG_PAIRED)) return frame_err(out, FE_NOT_PAIRED);
        drop_session();              /* новая сессия = заново unlock */
        uint8_t esk[32], epk[32], spk[32];
        hal_rng(esk, 32);
        crypto_x25519_public_key(epk, esk);
        token_public_key(spk);
        int r = pm_session_establish(&g_sess, PM_RESPONDER, g_cfg.token_sk, spk, esk, epk,
                                     g_cfg.pc_pub, in + 1);
        crypto_wipe(esk, 32);
        if (r != 0) return frame_err(out, FE_BAD_FRAME);
        hal_led(LED_SESSION);
        out[0] = FR_HELLO;
        memcpy(out + 1, epk, 32);
        return 33;
    }

    case FR_DATA: {
        if (!g_sess.active) return frame_err(out, FE_NO_SESSION);
        if (len - 1 > sizeof g_req + PM_MAC_LEN) return frame_err(out, FE_BAD_FRAME);
        long pl = pm_session_open(&g_sess, g_req, in + 1, len - 1);
        if (pl < 1) {
            drop_session();          /* подмена/повтор: рвём сессию */
            hal_led(LED_ERROR);
            return frame_err(out, FE_DECRYPT);
        }
        int was_reset = g_req[0] == CMD_FACTORY_RESET;
        size_t rl = do_command(g_req, (size_t)pl, g_resp);
        crypto_wipe(g_req, (size_t)pl);
        if (rl + PM_MAC_LEN + 1 > cap) { rl = 1; g_resp[0] = ST_FULL; }
        out[0] = FR_DATA;
        size_t n = 1 + pm_session_seal(&g_sess, out + 1, g_resp, rl);
        crypto_wipe(g_resp, rl);
        /* после сброса сессия недействительна: ответ уже зашифрован старым ключом */
        if (was_reset && !(g_cfg.flags & CFG_PAIRED)) pm_session_clear(&g_sess);
        return n;
    }

    default:
        return frame_err(out, FE_BAD_FRAME);
    }
}
