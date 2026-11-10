/* SPDX-License-Identifier: GPL-3.0-or-later */
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
static int        g_sess_pc = -1;   /* какой ПК (pcs[]) в текущей сессии */
static uint64_t   g_proof_after;    /* после неверной подписи привязки — пауза */

static int      g_unlocked;
static uint8_t  g_kvault[32];
static uint8_t *g_plain;          /* расшифрованное хранилище (только в RAM), буфер от HAL */
static size_t   g_plain_cap;      /* размер буфера */
static size_t   g_cap;            /* ёмкость хранилища: min(буфер, слот flash) */
static size_t   g_plain_len;
static size_t   g_restore_total, g_restore_have;   /* бэкап, принятый RESTORE_DATA в g_plain */

static int      g_setup_pending;
static uint8_t  g_seed[32];

static uint64_t g_last_activity;
static uint64_t g_get_times[TOKEN_RATE_N];
static unsigned g_get_pos;
static uint64_t g_otp_times[TOKEN_OTP_RATE_N];
static unsigned g_otp_pos;
static uint64_t g_steam_times[TOKEN_STEAM_RATE_N];
static unsigned g_steam_pos;
static uint64_t g_label_times[TOKEN_LABEL_RATE_N];
static unsigned g_label_pos;
static uint64_t g_backoff_until;

/* Часов у токена нет: время для OTP присылает ПК. Чтобы ПК не мог заранее
 * набрать коды «из будущего», токен помнит самое позднее принятое время и
 * дальше разрешает ему идти только вместе со своими монотонными часами.
 * Грубая копия (g_cfg.otp_time) переживает выключение: назад дальше неё нельзя. */
static uint64_t g_otp_time;      /* unix-секунды, 0 — ещё не было */
static uint64_t g_otp_at;        /* hal_millis() в момент g_otp_time */
static int      g_otp_live;      /* время уже принято после включения */

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
    if (g_plain) crypto_wipe(g_plain, g_plain_cap);
    g_plain_len = 0;
    g_restore_total = g_restore_have = 0;
    g_unlocked = 0;
    if (g_setup_pending) { crypto_wipe(g_seed, sizeof g_seed); g_setup_pending = 0; }
}

static void drop_session(void)
{
    lock_vault();
    pm_session_clear(&g_sess);
    g_sess_pc = -1;
    hal_led(LED_IDLE);
}

static uint32_t backoff_ms(uint32_t fails);

void token_public_key(uint8_t pub[32]) { crypto_x25519_public_key(pub, g_cfg.token_sk); }

void token_init(void)
{
    if (!g_plain) g_plain = hal_vault_buffer(&g_plain_cap);
    lock_vault();
    g_cap = store_init(g_plain, g_plain_cap);
    if (store_config_load(&g_cfg) != 0) {
        /* первое включение: свой статический ключ */
        memset(&g_cfg, 0, sizeof g_cfg);
        hal_rng(g_cfg.token_sk, 32);
        store_config_save(&g_cfg);
    }
    /* неверные пароли пережили перезагрузку: задержка действует и после неё */
    g_backoff_until = hal_millis() + backoff_ms(g_cfg.fails);
    g_last_activity = hal_millis();
    g_otp_time = g_cfg.otp_time;          /* нижняя граница; вперёд — с первого запроса */
    g_otp_at = hal_millis();
    g_otp_live = 0;
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

/* Перевести открытое хранилище v1 в v2 (добавить пустое поле OTP). 0 = ок.
 * На месте, без второго буфера на 32 КБ: RAM RP2040 — 264 КБ. */
static int v_migrate(void)
{
    if (v_format() >= 2) return 0;
    size_t off = VH, len = g_plain_len, n = v_count();
    for (size_t i = 0; i < n; i++) {
        size_t sz = entry_size(g_plain, len, off, 1);
        if (!sz || len + 1 > g_cap) return -1;
        memmove(g_plain + off + sz + 1, g_plain + off + sz, len - off - sz);
        g_plain[off + sz] = 0;
        len++;
        off += sz + 1;
    }
    g_plain_len = len;
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

/* 1 — хранилище разобрано целиком и все поля в допустимых пределах.
 * Проверяется один раз после загрузки: содержимое бэкапа задаёт тот, кто знает ключи,
 * а команды дальше доверяют длинам полей. */
static int v_valid(void)
{
    if (g_plain_len < VH) return 0;
    size_t off = VH;
    for (unsigned i = 0; i < v_count(); i++) {
        size_t sz = v_entry_size(off);
        if (!sz) return 0;
        const uint8_t *e = g_plain + off + 4;
        for (int k = 0; k < 3; k++) e += 1u + e[0];
        if ((size_t)(e[0] | e[1] << 8) > PM_MAX_PASSWORD) return 0;
        const uint8_t *otp = v_entry_otp(off);
        if (otp[0] && pm_otp_validate(otp + 1, otp[0]) != 0) return 0;
        off += sz;
    }
    return 1;
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

/* Бесплатные попытки: счётчик пишется во flash после неверного пароля, но ДО ответа —
 * выдёргивание токена после ответа задержку не сбрасывает. Сбой записи не отменяет
 * счёт и задержку в RAM. 0 = записано. */
static int register_fail(void)
{
    if (g_cfg.fails < 0xFFFFFFFFu) g_cfg.fails++;
    int r = store_config_save(&g_cfg);
    g_backoff_until = hal_millis() + backoff_ms(g_cfg.fails);
    return r;
}

static void reset_fails(void)
{
    if (!g_cfg.fails) return;
    g_cfg.fails = 0;
    store_config_save(&g_cfg);
}

/* Время ПК для OTP: не дальше вперёд, чем позволяют часы токена, и не раньше
 * сохранённого во flash (код прошедшего момента бесполезен, а «отмотать назад и
 * набрать окно заново» так не выйдет). Без питания часов нет: после включения
 * первое время вперёд не ограничено — закрыть это могут только RTC или кнопка. */
static int otp_time_ok(uint64_t t)
{
    if (t < 1500000000u) return 0;                    /* 2017 год: заведомо неверные часы */
    if (g_cfg.otp_time > TOKEN_OTP_SKEW_S && t < g_cfg.otp_time - TOKEN_OTP_SKEW_S) return 0;
    uint64_t now = hal_millis();
    if (g_otp_live) {
        uint64_t expected = g_otp_time + (now - g_otp_at) / 1000u;
        if (t > expected + TOKEN_OTP_SKEW_S) return 0;
    }
    if (t > g_otp_time || !g_otp_live) {
        if (t > g_otp_time) g_otp_time = t;
        g_otp_at = now;
        g_otp_live = 1;
    }
    /* грубая копия во flash: не чаще раза в сутки использования */
    if (g_otp_time >= g_cfg.otp_time + TOKEN_OTP_SAVE_S) {
        uint64_t before = g_cfg.otp_time;
        g_cfg.otp_time = g_otp_time;
        if (store_config_save(&g_cfg) != 0) g_cfg.otp_time = before;
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
        /* занято / всего: сколько ещё записей поместится — видно в настройках */
        wire_put_u32(&w, g_unlocked ? (uint32_t)g_plain_len : 0u);
        wire_put_u32(&w, g_cap);
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

    case CMD_RESTORE_DATA: {
        /* бэкап больше кадра: части по порядку копятся в буфере хранилища (оно ещё не открыто) */
        uint32_t off = wire_u32(&r), total = wire_u32(&r);
        if (r.err || g_unlocked) { st = r.err ? ST_BAD_ARGS : ST_ALREADY_SETUP; break; }
        if (g_cfg.flags & CFG_SETUP) { st = ST_ALREADY_SETUP; break; }
        if (total < STORE_VAULT_HDR || total > g_cap + STORE_VAULT_HDR || r.n > total - off ||
            off != g_restore_have || (off && total != g_restore_total)) {
            g_restore_total = g_restore_have = 0;
            st = total > g_cap + STORE_VAULT_HDR ? ST_FULL : ST_BAD_ARGS;
            break;
        }
        memcpy(g_plain + off, r.p, r.n);
        g_restore_total = total;
        g_restore_have = off + r.n;
        break;
    }

    case CMD_RESTORE: {
        const uint8_t *k_tok = wire_bytes(&r, 32);
        const uint8_t *k_pc = wire_bytes(&r, 32);
        const uint8_t *pw_hash = wire_bytes(&r, 32);
        uint8_t with_backup = wire_u8(&r);
        if (r.err || r.n) { st = ST_BAD_ARGS; break; }
        if (g_cfg.flags & CFG_SETUP) { st = ST_ALREADY_SETUP; break; }
        if (with_backup && (g_restore_total == 0 || g_restore_have != g_restore_total)) { st = ST_BAD_ARGS; break; }
        size_t blob_len = with_backup ? g_restore_total : 0;
        g_restore_total = g_restore_have = 0;
        pm_vault_key(g_kvault, k_tok, k_pc, pw_hash);
        if (blob_len) {
            size_t pl;
            if (store_vault_put_raw(g_plain, blob_len) != 0) { st = ST_BAD_ARGS; lock_vault(); break; }
            if (store_vault_load(g_kvault, g_plain, g_plain_cap, &pl) != 0) {
                store_wipe();                           /* не тот ключ: не оставляем мусор */
                store_config_save(&g_cfg);
                st = ST_WRONG_KEY; lock_vault(); break;
            }
            g_plain_len = pl;
            if (v_migrate() != 0) { st = ST_FULL; lock_vault(); break; }
            if (!v_valid()) {                           /* ключи верны, но содержимое собрано руками */
                store_wipe();
                store_config_save(&g_cfg);
                st = ST_BAD_ARGS; lock_vault(); break;
            }
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
        /* После бесплатных попыток попытка засчитывается во flash ДО проверки: по задержке
         * ответа не угадать исход и не успеть выдернуть токен до записи счётчика. */
        uint32_t fails_before = g_cfg.fails;
        int counted = fails_before >= TOKEN_FREE_ATTEMPTS;
        if (counted) {
            if (g_cfg.fails < 0xFFFFFFFFu) g_cfg.fails++;
            if (store_config_save(&g_cfg) != 0) { g_cfg.fails = fails_before; st = ST_FLASH; break; }
        }
        pm_vault_key(g_kvault, g_cfg.k_token, k_pc, pw_hash);
        size_t pl;
        int lr = store_vault_load(g_kvault, g_plain, g_plain_cap, &pl);
        if (lr != 0) {
            lock_vault();
            if (lr == -2) {
                if (counted) g_backoff_until = hal_millis() + backoff_ms(g_cfg.fails);
                else register_fail();          /* сбой записи: счёт и задержка остаются в RAM */
            } else if (counted) {
                g_cfg.fails = fails_before;    /* не пароль: попытку не считаем */
                store_config_save(&g_cfg);
            }
            st = lr == -2 ? ST_WRONG_KEY : ST_FLASH;
        } else {
            g_plain_len = pl;
            reset_fails();
            if (v_migrate() != 0) { lock_vault(); st = ST_FULL; break; }
            if (!v_valid()) { lock_vault(); st = ST_FLASH; break; }   /* не пароль: счётчик не трогаем */
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
        /* страницами: клиент просит пропустить уже полученные записи */
        uint32_t skip = wire_u32(&r);
        if (r.err || r.n) { st = ST_BAD_ARGS; break; }
        if (!g_unlocked) { st = ST_LOCKED; break; }
        size_t head = w.n;
        wire_put_u16(&w, 0);
        wire_put_u8(&w, 0);
        uint16_t n = 0, total = v_count();
        size_t off = VH;
        for (unsigned i = 0; i < total; i++) {
            size_t sz = v_entry_size(off);
            if (!sz) break;
            const uint8_t *e = g_plain + off;
            off += sz;
            if (i < skip) continue;
            size_t need = 4u + 1u + e[4] + 1u + e[5 + e[4]] + 1u;
            if (w.cap - w.n < need) { w.p[head + 2] = 1; break; }   /* ещё есть */
            wire_put_u32(&w, wire_get32(e));
            wire_put_bytes(&w, e + 4, 1u + e[4]);                 /* cat */
            wire_put_bytes(&w, e + 5 + e[4], 1u + e[5 + e[4]]);   /* name */
            const uint8_t *otp = v_entry_otp(off - sz);
            wire_put_u8(&w, otp[0] ? otp[1] : OTP_NONE);
            n++;
        }
        w.p[head] = (uint8_t)n;
        w.p[head + 1] = (uint8_t)(n >> 8);
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
        if (g_plain_len + 4 + body_len + 1 + ol > g_cap || v_count() == 0xFFFF ||
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
        /* OTP из хранилища (бэкап мог собрать кто угодно, знающий ключи): не длиннее буфера entry */
        if (ol > OTP_BLOB_MAX) { st = ST_BAD_ARGS; break; }
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
        if (g_plain_len - sz + el > g_cap) { crypto_wipe(entry, el); st = ST_FULL; break; }
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

    case CMD_STEAM_CONF: {
        uint32_t id = wire_u32(&r);
        uint64_t t = wire_u64(&r);
        size_t tl = wire_u8(&r);
        const uint8_t *tag = wire_bytes(&r, tl);
        if (r.err || r.n || !pm_steam_tag_ok(tag, tl)) { st = ST_BAD_ARGS; break; }
        if (!g_unlocked) { st = ST_LOCKED; break; }
        /* журнал — только одобрения и отказы: список запрашивается часто */
        int action = pm_steam_tag_is_action(tag, tl);
        log_id = id; do_log = action;
        long off = v_find(id);
        if (off < 0) { st = ST_NOT_FOUND; break; }
        const uint8_t *otp = v_entry_otp((size_t)off);
        if (!otp[0] || otp[1] != OTP_STEAM_MOBILE) { st = ST_NO_OTP; break; }
        if (!otp_time_ok(t)) { st = ST_BAD_TIME; break; }
        if (!window_ok(g_steam_times, TOKEN_STEAM_RATE_N, &g_steam_pos)) { st = ST_RATE_LIMIT; break; }
        uint8_t key[STEAM_CONF_KEY];
        if (pm_steam_conf_key(otp + 1, otp[0], t, tag, tl, key) != 0) { st = ST_FLASH; break; }
        wire_put_bytes(&w, key, sizeof key);
        crypto_wipe(key, sizeof key);
        break;
    }

    case CMD_STEAM_INFO: {
        uint32_t id = wire_u32(&r);
        uint8_t flags = wire_u8(&r);
        if (r.err || r.n || flags > 1) { st = ST_BAD_ARGS; break; }
        if (!g_unlocked) { st = ST_LOCKED; break; }
        log_id = id; do_log = flags & 1;
        long off = v_find(id);
        if (off < 0) { st = ST_NOT_FOUND; break; }
        const uint8_t *otp = v_entry_otp((size_t)off);
        uint64_t sid;
        const uint8_t *rev;
        size_t rl;
        if (!otp[0] || pm_steam_parts(otp + 1, otp[0], NULL, NULL, NULL, NULL, &sid, &rev, &rl) != 0) {
            st = ST_NO_OTP;
            break;
        }
        /* код восстановления отключает Steam Guard — выдаётся как пароль, с лимитом */
        if ((flags & 1) && !rate_ok()) { st = ST_RATE_LIMIT; break; }
        wire_put_u64(&w, sid);
        if (!(flags & 1)) rl = 0;
        wire_put_u8(&w, (uint8_t)rl);
        wire_put_bytes(&w, rev, rl);
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
        uint32_t boff = wire_u32(&r);
        if (r.err || r.n) { st = ST_BAD_ARGS; break; }
        if (!g_unlocked) { st = ST_LOCKED; break; }
        size_t total = 0, room = w.cap - w.n - 4;
        if (room > PM_BACKUP_CHUNK) room = PM_BACKUP_CHUNK;
        long n = store_vault_raw(boff, w.p + w.n + 4, room, &total);
        if (n < 0) { st = boff ? ST_BAD_ARGS : ST_FLASH; break; }
        wire_put_u32(&w, (uint32_t)total);
        w.n += (size_t)n;
        do_log = boff == 0;             /* в журнал — один раз на копию */
        break;
    }

    case CMD_PC_LIST: {
        if (!g_unlocked) { st = ST_LOCKED; break; }
        wire_put_u8(&w, g_cfg.pc_count);
        for (int i = 0; i < g_cfg.pc_count; i++) {
            wire_put_u8(&w, (uint8_t)i);
            wire_put_u8(&w, i == g_sess_pc);
            wire_put_bytes(&w, g_cfg.pcs[i].pub, 8);
            wire_put_str(&w, g_cfg.pcs[i].label);
        }
        break;
    }

    case CMD_PC_REMOVE: {
        uint8_t slot = wire_u8(&r);
        if (r.err || r.n) { st = ST_BAD_ARGS; break; }
        if (!g_unlocked) { st = ST_LOCKED; break; }
        if (slot >= g_cfg.pc_count) { st = ST_NOT_FOUND; break; }
        pm_config before = g_cfg;
        for (int i = slot; i + 1 < g_cfg.pc_count; i++) g_cfg.pcs[i] = g_cfg.pcs[i + 1];
        g_cfg.pc_count--;
        g_cfg.pair_epoch++;              /* записанные раньше подписи привязки больше не годятся */
        crypto_wipe(&g_cfg.pcs[g_cfg.pc_count], sizeof g_cfg.pcs[0]);
        if (store_config_save(&g_cfg) != 0) { g_cfg = before; st = ST_FLASH; }
        else if (g_sess_pc == slot) g_sess_pc = -2;      /* себя: ответ уйдёт, потом сессия закроется */
        else if (g_sess_pc > slot) g_sess_pc--;
        crypto_wipe(&before, sizeof before);
        do_log = 1;
        break;
    }

    case CMD_PC_LABEL: {
        size_t l = wire_u8(&r);
        const uint8_t *name = wire_bytes(&r, l);
        if (r.err || r.n || l >= STORE_PC_LABEL) { st = ST_BAD_ARGS; break; }
        if (g_sess_pc < 0) { st = ST_NOT_FOUND; break; }
        char *dst = g_cfg.pcs[g_sess_pc].label;
        if (strlen(dst) == l && memcmp(dst, name, l) == 0) break;   /* без лишней записи во flash */
        /* работает и до unlock (имя ставится сразу после подключения): частоту записей
           ограничиваем, иначе любой привязанный ПК изнашивает сектор конфигурации */
        if (!window_ok(g_label_times, TOKEN_LABEL_RATE_N, &g_label_pos)) { st = ST_RATE_LIMIT; break; }
        memset(dst, 0, STORE_PC_LABEL);
        memcpy(dst, name, l);
        if (store_config_save(&g_cfg) != 0) st = ST_FLASH;
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
    /* простой отсчитывается только от кадров сессии: открытые WHO/PAIR его не продлевают */

    switch (in[0]) {
    case FR_WHO:
        if (len != 1) return frame_err(out, FE_BAD_FRAME);
        out[0] = FR_WHO;
        token_public_key(out + 1);
        out[33] = (g_cfg.flags & CFG_SETUP) ? 1 : 0;
        out[34] = g_cfg.pc_count;
        wire_put32(out + 35, g_cfg.pair_epoch);
        return 39;

    case FR_PAIR: {
        /* первый ПК — только у чистого токена: настроенный принимает новые ПК по 24 словам */
        if (len != 33) return frame_err(out, FE_BAD_FRAME);
        if (g_cfg.pc_count) return frame_err(out, FE_ALREADY_PAIRED);
        if (g_cfg.flags & CFG_SETUP) return frame_err(out, FE_NEED_PROOF);
        memset(&g_cfg.pcs[0], 0, sizeof g_cfg.pcs[0]);
        memcpy(g_cfg.pcs[0].pub, in + 1, 32);
        g_cfg.pc_count = 1;
        if (store_config_save(&g_cfg) != 0) {
            g_cfg.pc_count = 0;
            return frame_err(out, FE_BAD_FRAME);
        }
        out[0] = FR_PAIR;
        token_public_key(out + 1);
        return 33;
    }

    case FR_PAIR_PROOF: {
        if (len != 65) return frame_err(out, FE_BAD_FRAME);
        if (!(g_cfg.flags & CFG_SETUP)) return frame_err(out, FE_NOT_PAIRED);
        if (hal_millis() < g_proof_after) return frame_err(out, FE_BAD_PROOF);
        uint8_t spk[32], want[32];
        token_public_key(spk);
        pm_pair_proof(want, g_cfg.k_token, in + 1, spk, g_cfg.pair_epoch);
        int ok = crypto_verify32(want, in + 33) == 0;
        crypto_wipe(want, sizeof want);
        if (!ok) {
            g_proof_after = hal_millis() + 1000;          /* подпись 256 бит, но перебор всё равно гасим */
            return frame_err(out, FE_BAD_PROOF);
        }
        int found = -1;
        for (int i = 0; i < g_cfg.pc_count; i++)
            if (crypto_verify32(g_cfg.pcs[i].pub, in + 1) == 0) found = i;
        if (found < 0) {
            if (g_cfg.pc_count >= STORE_MAX_PCS) return frame_err(out, FE_PAIR_FULL);
            pm_pc *p = &g_cfg.pcs[g_cfg.pc_count];
            memset(p, 0, sizeof *p);
            memcpy(p->pub, in + 1, 32);
            g_cfg.pc_count++;
            if (store_config_save(&g_cfg) != 0) {
                g_cfg.pc_count--;
                return frame_err(out, FE_BAD_FRAME);
            }
        }
        out[0] = FR_PAIR_PROOF;
        memcpy(out + 1, spk, 32);
        return 33;
    }

    case FR_HELLO: {
        if (len != 65) return frame_err(out, FE_BAD_FRAME);
        int pc = -1;
        for (int i = 0; i < g_cfg.pc_count; i++)
            if (crypto_verify32(g_cfg.pcs[i].pub, in + 1) == 0) pc = i;
        if (pc < 0) return frame_err(out, FE_NOT_PAIRED);     /* не привязан или отвязан */
        drop_session();              /* новая сессия = заново unlock */
        uint8_t esk[32], epk[32], spk[32];
        hal_rng(esk, 32);
        crypto_x25519_public_key(epk, esk);
        token_public_key(spk);
        int r = pm_session_establish(&g_sess, PM_RESPONDER, g_cfg.token_sk, spk, esk, epk,
                                     g_cfg.pcs[pc].pub, in + 33);
        crypto_wipe(esk, 32);
        if (r != 0) return frame_err(out, FE_BAD_FRAME);
        g_sess_pc = pc;
        g_last_activity = hal_millis();
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
        g_last_activity = hal_millis();
        int was_reset = g_req[0] == CMD_FACTORY_RESET;
        size_t rl = do_command(g_req, (size_t)pl, g_resp);
        crypto_wipe(g_req, (size_t)pl);
        if (rl + PM_MAC_LEN + 1 > cap) { rl = 1; g_resp[0] = ST_FULL; }
        out[0] = FR_DATA;
        size_t n = 1 + pm_session_seal(&g_sess, out + 1, g_resp, rl);
        crypto_wipe(g_resp, rl);
        /* после сброса или отвязки себя сессия недействительна: ответ уже зашифрован */
        if ((was_reset && g_cfg.pc_count == 0) || g_sess_pc == -2) { pm_session_clear(&g_sess); g_sess_pc = -1; }
        return n;
    }

    default:
        return frame_err(out, FE_BAD_FRAME);
    }
}
