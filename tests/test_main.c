/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Тесты: клиент и токен в одном процессе, транспорт — прямой вызов token_handle().
 */
#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#else
#  define _DEFAULT_SOURCE
#  include <sys/stat.h>
#  include <unistd.h>
#endif

#include "bip39.h"
#include "hal.h"
#include "hal_sim.h"
#include "kdf.h"
#include "monocypher.h"
#include "pmclient.h"
#include "proto.h"
#include "session.h"
#include "store.h"
#include "token.h"
#include "sha.h"
#include "otp.h"
#include "framer.h"
#include "pmserial.h"
#include "wire.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail, g_pass;
#define CHECK(cond, msg) do { if (cond) g_pass++; else { g_fail++; \
    printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, msg); } } while (0)
#define CHECK_RC(expr, want, msg) do { int _r = (expr); if (_r == (want)) g_pass++; else { \
    g_fail++; printf("  FAIL %s:%d: %s: получено %d (%s), ожидалось %d\n", __FILE__, __LINE__, \
    msg, _r, pmc_strerror(_r), (want)); } } while (0)

static void section(const char *s) { printf("== %s\n", s); }

static uint8_t g_tok_out[PM_MAX_FRAME + 64];
static long direct_xfer(void *ctx, const uint8_t *req, size_t len, uint8_t *resp, size_t cap)
{
    (void)ctx;
    size_t n = token_handle(req, len, g_tok_out, sizeof g_tok_out);
    if (n > cap) return -1;
    memcpy(resp, g_tok_out, n);
    return (long)n;
}

static void new_client(pm_client *c)
{
    pmc_init(c, direct_xfer, NULL);
    c->argon_blocks = 64;      /* быстро для тестов; по умолчанию 64 МиБ */
    c->argon_passes = 1;
}

static void hex(const char *h, uint8_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++) { unsigned v; sscanf(h + 2 * i, "%2x", &v); out[i] = (uint8_t)v; }
}

static int count_cb_n;
static char seen_names[16][64];
static void count_cb(void *ctx, uint32_t id, const char *cat, const char *name, uint8_t otp)
{
    (void)ctx; (void)id; (void)cat; (void)otp;
    if (count_cb_n < 16) snprintf(seen_names[count_cb_n], 64, "%s", name);
    count_cb_n++;
}
static int list_count(pm_client *c)
{
    count_cb_n = 0;
    int r = pmc_list(c, count_cb, NULL);
    return r == 0 ? count_cb_n : -1;
}
static int seen(const char *name)
{
    for (int i = 0; i < count_cb_n && i < 16; i++) if (!strcmp(seen_names[i], name)) return 1;
    return 0;
}

static int memfind(const uint8_t *hay, size_t n, const void *needle, size_t m)
{
    for (size_t i = 0; i + m <= n; i++) if (!memcmp(hay + i, needle, m)) return 1;
    return 0;
}

static int g_log_n, g_log_wrong;
static uint8_t g_log_cmd[64];
static void log_cb(void *ctx, uint32_t t, uint8_t cmd, uint8_t st, uint32_t id)
{
    (void)ctx; (void)t; (void)id;
    if (g_log_n < 64) g_log_cmd[g_log_n] = cmd;
    g_log_n++;
    if (cmd == CMD_UNLOCK && st == ST_WRONG_KEY) g_log_wrong++;
}

static void reboot_token(void) { token_disconnect(); token_init(); }

/* ------------------------------------------------------------------ */

static void test_vectors(void)
{
    section("тест-векторы SHA-256 и BIP39");
    uint8_t h[32], want[32];
    pm_sha256((const uint8_t *)"abc", 3, h);
    hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", want, 32);
    CHECK(!memcmp(h, want, 32), "SHA-256(abc)");
    uint8_t big[200];
    memset(big, 'a', sizeof big);
    pm_sha256(big, sizeof big, h);
    hex("c2a908d98f5df987ade41b5fce213067efbcc21ef2240212a41e54b5e7c28ae5", want, 32);
    CHECK(!memcmp(h, want, 32), "SHA-256(200 x 'a')");

    char s[300];
    uint8_t e[32], d[32];
    memset(e, 0, 32);
    bip39_to_string(e, s, sizeof s);
    CHECK(!strcmp(s, "abandon abandon abandon abandon abandon abandon abandon abandon abandon "
                     "abandon abandon abandon abandon abandon abandon abandon abandon abandon "
                     "abandon abandon abandon abandon abandon art"), "BIP39 вектор 00..00");
    memset(e, 0x7f, 32);
    bip39_to_string(e, s, sizeof s);
    CHECK(!strcmp(s, "legal winner thank year wave sausage worth useful legal winner thank year "
                     "wave sausage worth useful legal winner thank year wave sausage worth title"),
          "BIP39 вектор 7f..7f");
    memset(e, 0xff, 32);
    bip39_to_string(e, s, sizeof s);
    CHECK(!strcmp(s, "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo "
                     "zoo zoo zoo zoo zoo vote"), "BIP39 вектор ff..ff");

    CHECK(bip39_decode("  LEGAL winn thank year wave saus worth usef legal winner thank year "
                       "wave sausage worth useful legal winner thank year wave sausage worth titl",
                       d) == 0, "декодирование с префиксами и в любом регистре");
    memset(e, 0x7f, 32);
    CHECK(!memcmp(d, e, 32), "префиксы дают ту же энтропию");
    CHECK(bip39_decode("legal winner thank year wave sausage worth useful legal winner thank year "
                       "wave sausage worth useful legal winner thank year wave sausage worth zoo",
                       d) == -3, "неверная контрольная сумма отвергается");
    CHECK(bip39_decode("abandon abandon", d) == -2, "не 24 слова");
    CHECK(bip39_decode("abandon qwerty abandon", d) == -1, "неизвестное слово");
}

static void test_session(void)
{
    section("зашифрованный канал");
    uint8_t ask[32], apk[32], bsk[32], bpk[32], ae[32], aep[32], be[32], bep[32];
    for (int i = 0; i < 32; i++) { ask[i] = (uint8_t)i; bsk[i] = (uint8_t)(100 + i);
                                   ae[i] = (uint8_t)(50 + i); be[i] = (uint8_t)(150 + i); }
    crypto_x25519_public_key(apk, ask); crypto_x25519_public_key(bpk, bsk);
    crypto_x25519_public_key(aep, ae);  crypto_x25519_public_key(bep, be);
    pm_session a, b;
    CHECK(pm_session_establish(&a, PM_INITIATOR, ask, apk, ae, aep, bpk, bep) == 0, "init");
    CHECK(pm_session_establish(&b, PM_RESPONDER, bsk, bpk, be, bep, apk, aep) == 0, "resp");
    uint8_t ct[64], pt[64], ct2[64];
    size_t n = pm_session_seal(&a, ct, (const uint8_t *)"hello", 5);
    memcpy(ct2, ct, n);
    CHECK(pm_session_open(&b, pt, ct, n) == 5 && !memcmp(pt, "hello", 5), "расшифровка");
    CHECK(pm_session_open(&b, pt, ct2, n) == -1, "повтор кадра отвергнут");
    n = pm_session_seal(&a, ct, (const uint8_t *)"x", 1);
    ct[n - 1] ^= 1;
    CHECK(pm_session_open(&b, pt, ct, n) == -1, "подмена кадра отвергнута");

    uint8_t zero[32] = {0};
    CHECK(pm_session_establish(&a, PM_INITIATOR, ask, apk, ae, aep, bpk, zero) == -1,
          "нулевой эфемерный ключ отвергнут");
}

static const char *PW = "correct horse battery staple";
static char g_words[512 + 256];
static uint8_t g_backup[PM_MAX_BACKUP];
static size_t g_backup_len;

static void test_full_flow(void)
{
    pm_client c, imp;
    pmc_info_t info;
    uint32_t id1, id2, id3;
    char login[256], pw[PM_MAX_PASSWORD + 1];

    section("сопряжение");
    hal_sim_open(NULL);
    token_init();
    new_client(&c);
    CHECK_RC(pmc_connect(&c), PMC_E_NOT_PAIRED, "connect до сопряжения");
    CHECK_RC(pmc_pair(&c), 0, "pair");
    uint8_t tpk[32];
    token_public_key(tpk);
    CHECK(memcmp(c.token_pk, tpk, 32) == 0, "ПК получил статический ключ токена");
    new_client(&imp);
    CHECK_RC(pmc_pair(&imp), PMC_E_TOKEN - FE_ALREADY_PAIRED, "второй ПК не может сопрячься");

    section("сессия и настройка");
    CHECK_RC(pmc_connect(&c), 0, "connect");
    CHECK_RC(pmc_info(&c, &info), 0, "info");
    CHECK(info.paired && !info.setup_done && !info.unlocked, "флаги до настройки");
    CHECK_RC(pmc_unlock(&c, PW), PMC_E_NO_KEY, "unlock без настройки");
    CHECK_RC(pmc_setup_begin(&c, g_words, sizeof g_words), 0, "setup_begin");
    uint8_t seed[32];
    CHECK(bip39_decode(g_words, seed) == 0 && !memcmp(seed, c.pending_seed, 32), "24 слова = seed");
    CHECK_RC(pmc_setup_commit(&c, PW), 0, "setup_commit");
    CHECK_RC(pmc_info(&c, &info), 0, "info");
    CHECK(info.setup_done && info.unlocked && info.count == 0, "настроен и открыт");
    CHECK_RC(pmc_setup_begin(&c, g_words + 256, 256), ST_ALREADY_SETUP, "повторная настройка запрещена");

    section("записи");
    CHECK_RC(pmc_add(&c, "Почта", "Gmail", "me@gmail.com", "S3cr3t-Gmail!", &id1), 0, "add 1");
    CHECK_RC(pmc_add(&c, "Почта", "Proton", "me@proton.me", "pr0t0n-pass", &id2), 0, "add 2");
    CHECK_RC(pmc_add(&c, "Работа", "GitLab", "ivan", "gitlab#2026", &id3), 0, "add 3");
    CHECK(id1 == 1 && id2 == 2 && id3 == 3, "id по порядку");
    CHECK_RC(pmc_add(&c, "x", "", "y", "z", NULL), ST_BAD_ARGS, "пустое название отвергнуто");
    CHECK(list_count(&c) == 3 && seen("Gmail") && seen("GitLab"), "list");
    CHECK_RC(pmc_get(&c, id2, login, sizeof login, pw, sizeof pw), 0, "get");
    CHECK(!strcmp(login, "me@proton.me") && !strcmp(pw, "pr0t0n-pass"), "логин/пароль верны");
    CHECK_RC(pmc_get(&c, 99, login, sizeof login, pw, sizeof pw), ST_NOT_FOUND, "нет такой записи");
    CHECK_RC(pmc_delete(&c, id2), 0, "delete");
    CHECK(list_count(&c) == 2 && !seen("Proton"), "после удаления");
    CHECK_RC(pmc_get(&c, id3, login, sizeof login, pw, sizeof pw), 0, "get после удаления соседа");
    CHECK(!strcmp(pw, "gitlab#2026"), "соседняя запись цела");

    section("дамп flash не содержит секретов в открытом виде");
    const uint8_t *fl = hal_sim_flash();
    CHECK(!memfind(fl, hal_flash_size(), "S3cr3t-Gmail!", 13), "пароль не виден в flash");
    CHECK(!memfind(fl, hal_flash_size(), "Gmail", 5), "название не видно в flash");
    CHECK(!memfind(fl, hal_flash_size(), c.k_pc, 32), "K_pc не хранится на токене");

    section("блокировка, неверный пароль, задержки");
    CHECK_RC(pmc_lock(&c), 0, "lock");
    CHECK_RC(pmc_get(&c, id1, login, sizeof login, pw, sizeof pw), ST_LOCKED, "get после lock");
    CHECK_RC(pmc_list(&c, NULL, NULL), ST_LOCKED, "list после lock");
    for (int i = 0; i < 3; i++) CHECK_RC(pmc_unlock(&c, "wrong"), ST_WRONG_KEY, "неверный пароль");
    CHECK_RC(pmc_unlock(&c, PW), ST_BACKOFF, "после 3 ошибок — задержка даже для верного");
    hal_sim_advance_ms(1100);
    CHECK_RC(pmc_unlock(&c, PW), 0, "после задержки — открывается");

    section("ограничение частоты расшифровок");
    hal_sim_advance_ms(TOKEN_RATE_WINDOW_MS + 10);   /* забыть предыдущие get */
    int ok = 1;
    for (unsigned i = 0; i < TOKEN_RATE_N; i++)
        ok &= pmc_get(&c, id1, login, sizeof login, pw, sizeof pw) == 0;
    CHECK(ok, "первые N расшифровок проходят");
    CHECK_RC(pmc_get(&c, id1, login, sizeof login, pw, sizeof pw), ST_RATE_LIMIT, "N+1 — отказ");
    hal_sim_advance_ms(TOKEN_RATE_WINDOW_MS + 10);
    CHECK_RC(pmc_get(&c, id1, login, sizeof login, pw, sizeof pw), 0, "после окна снова можно");

    section("чужой ПК");
    imp.paired = 1;
    memcpy(imp.token_pk, c.token_pk, 32);
    CHECK_RC(pmc_connect(&imp), PMC_E_TOKEN - FE_NOT_PAIRED, "ПК с чужим ключом не получает сессию (токен его не знает)");
    imp.buf_out[0] = FR_HELLO;                      /* и напрямую: HELLO с чужим ключом ПК */
    memcpy(imp.buf_out + 1, imp.pk, 32);
    memset(imp.buf_out + 33, 7, 32);
    CHECK(token_handle(imp.buf_out, 65, imp.buf_in, sizeof imp.buf_in) == 2 && imp.buf_in[1] == FE_NOT_PAIRED,
          "токен отвечает «не привязан»");
    CHECK_RC(pmc_connect(&c), 0, "свой ПК переподключается");
    CHECK_RC(pmc_info(&c, &info), 0, "info");
    CHECK(!info.unlocked, "новая сессия начинается заблокированной");

    section("отключение и таймаут");
    CHECK_RC(pmc_unlock(&c, PW), 0, "unlock");
    token_disconnect();
    CHECK_RC(pmc_info(&c, &info), PMC_E_TOKEN - FE_NO_SESSION, "после выдёргивания сессии нет");
    CHECK_RC(pmc_connect(&c), 0, "connect");
    CHECK_RC(pmc_unlock(&c, PW), 0, "unlock");
    hal_sim_advance_ms(TOKEN_IDLE_TIMEOUT_MS + 1000);
    token_tick();
    CHECK_RC(pmc_info(&c, &info), PMC_E_TOKEN - FE_NO_SESSION, "таймаут простоя закрыл сессию");

    section("перезагрузка токена: данные на flash");
    reboot_token();
    CHECK_RC(pmc_connect(&c), 0, "connect после перезагрузки");
    CHECK_RC(pmc_unlock(&c, PW), 0, "unlock после перезагрузки");
    CHECK(list_count(&c) == 2, "записи на месте");

    section("журнал");
    g_log_n = g_log_wrong = 0;
    CHECK_RC(pmc_log(&c, log_cb, NULL), 0, "log");
    CHECK(g_log_n > 0 && g_log_wrong >= 3, "в журнале есть операции и неверные пароли");

    section("выдёргивание во время записи (A/B)");
    uint32_t id4;
    CHECK_RC(pmc_add(&c, "Тест", "Unsaved", "u", "p", &id4), 0, "add");
    /* портим самую свежую копию — как будто запись прервалась */
    uint8_t *f = hal_sim_flash();
    uint32_t offA = store_slot_offset(0), offB = store_slot_offset(1);
    uint32_t seqA = f[offA + 4] | f[offA + 5] << 8, seqB = f[offB + 4] | f[offB + 5] << 8;
    uint32_t newest = seqA > seqB ? offA : offB;
    f[newest + STORE_VAULT_HDR + 3] ^= 0x55;
    reboot_token();
    CHECK_RC(pmc_connect(&c), 0, "connect");
    CHECK_RC(pmc_unlock(&c, PW), 0, "открывается предыдущая целая версия");
    CHECK(list_count(&c) == 2 && !seen("Unsaved"), "последняя (испорченная) запись откатилась");

    section("резервная копия");
    CHECK_RC(pmc_backup(&c, g_backup, sizeof g_backup, &g_backup_len), 0, "backup");
    CHECK(g_backup_len > STORE_VAULT_HDR, "размер бэкапа");
    CHECK(!memfind(g_backup, g_backup_len, "gitlab#2026", 11), "бэкап зашифрован");

    section("идентичность ПК в файле");
    CHECK_RC(pmc_identity_save(&c, "test_identity.bin"), 0, "save");
    pm_client c2;
    new_client(&c2);
    CHECK_RC(pmc_identity_load(&c2, "test_identity.bin"), 0, "load");
    CHECK(!memcmp(c2.sk, c.sk, 32) && !memcmp(c2.k_pc, c.k_pc, 32) && c2.paired && c2.have_kpc,
          "данные совпадают");
    remove("test_identity.bin");
    pmc_wipe(&c);
    pmc_wipe(&imp);
}

static void test_restore(void)
{
    pm_client c;
    char login[256], pw[PM_MAX_PASSWORD + 1];

    section("восстановление: новая плата + новый ПК + 24 слова + бэкап");
    token_disconnect();
    hal_sim_erase();         /* «новая плата» */
    token_init();
    new_client(&c);          /* «новый ПК» */
    CHECK_RC(pmc_pair(&c), 0, "pair");
    CHECK_RC(pmc_connect(&c), 0, "connect");

    char bad[768];
    snprintf(bad, sizeof bad, "%s", g_words);
    char *last = strrchr(bad, ' ');
    snprintf(last + 1, 8, "%s", strcmp(last + 1, "zoo") ? "zoo" : "abandon");
    /* Опечатка ловится контрольной суммой BIP39 (255/256) или, если сумма
       случайно сошлась (1/256), токеном: ключ не тот */
    int rr = pmc_restore(&c, bad, PW, g_backup, g_backup_len);
    CHECK(rr == PMC_E_SEED || rr == ST_WRONG_KEY, "опечатка в фразе отвергается");
    CHECK_RC(pmc_restore(&c, g_words, "wrong pass", g_backup, g_backup_len), ST_WRONG_KEY,
             "неверный пароль");
    CHECK_RC(pmc_restore(&c, g_words, PW, g_backup, g_backup_len), 0, "restore");
    CHECK(list_count(&c) == 2 && seen("Gmail") && seen("GitLab"), "записи восстановлены");
    CHECK_RC(pmc_get(&c, 3, login, sizeof login, pw, sizeof pw), 0, "get");
    CHECK(!strcmp(pw, "gitlab#2026"), "пароль восстановлен");

    section("восстановление без бэкапа: пустое хранилище с теми же ключами");
    token_disconnect();
    hal_sim_erase();
    token_init();
    new_client(&c);
    pmc_pair(&c);
    pmc_connect(&c);
    CHECK_RC(pmc_restore(&c, g_words, PW, NULL, 0), 0, "restore без бэкапа");
    CHECK(list_count(&c) == 0, "пусто");

    section("полный сброс");
    CHECK_RC(pmc_factory_reset(&c), 0, "reset");
    pm_client n;
    new_client(&n);
    CHECK_RC(pmc_pair(&n), 0, "после сброса можно сопрячь заново");
    CHECK_RC(pmc_connect(&n), 0, "connect");
    pmc_info_t info;
    CHECK_RC(pmc_info(&n, &info), 0, "info");
    CHECK(!info.setup_done, "токен пуст");
    pmc_wipe(&c);
    pmc_wipe(&n);
}

static void test_real_argon_cost(void)
{
    section("стоимость Argon2id по умолчанию (64 МиБ, 3 прохода)");
    pm_client c;
    pmc_init(&c, direct_xfer, NULL);
    uint8_t salt[16] = {0}, out[32];
    void *work = malloc(65536u * 1024u);
    crypto_argon2_config cfg = {CRYPTO_ARGON2_ID, 65536, 3, 1};
    crypto_argon2_inputs in = {(const uint8_t *)PW, salt, (uint32_t)strlen(PW), 16};
    crypto_argon2(out, 32, work, cfg, in, crypto_argon2_no_extras);
    free(work);
    CHECK(1, "Argon2id выполнен");
    pmc_wipe(&c);
}

/* ------------------------------------------------------------------ */

static void hexs(const uint8_t *b, size_t n, char *out)
{
    for (size_t i = 0; i < n; i++) sprintf(out + 2 * i, "%02x", b[i]);
}

static size_t otp_blob(uint8_t *b, uint8_t type, uint8_t alg, uint8_t digits, uint8_t period, const char *secret)
{
    size_t l = strlen(secret);
    b[0] = type; b[1] = alg; b[2] = digits; b[3] = period;
    memcpy(b + 4, secret, l);
    return 4 + l;
}

static uint8_t g_list_otp[8];
static void otp_cb(void *ctx, uint32_t id, const char *cat, const char *name, uint8_t otp)
{
    (void)ctx; (void)cat; (void)name;
    if (id < 8) g_list_otp[id] = otp;
}

static void test_hashes_and_otp_vectors(void)
{
    section("SHA-1, HMAC, TOTP (RFC 6238), Steam Guard");
    uint8_t h[32], mac[32];
    char hx[65];
    pm_sha1((const uint8_t *)"abc", 3, h);
    hexs(h, 20, hx);
    CHECK(!strcmp(hx, "a9993e364706816aba3e25717850c26c9cd0d89d"), "SHA-1(abc)");
    pm_hmac(PM_SHA256, (const uint8_t *)"Jefe", 4, (const uint8_t *)"what do ya want for nothing?", 28, mac);
    hexs(mac, 32, hx);
    CHECK(!strcmp(hx, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"), "HMAC-SHA256 RFC 4231 #2");
    uint8_t longkey[131];
    memset(longkey, 0xaa, sizeof longkey);
    const char *lm = "Test Using Larger Than Block-Size Key - Hash Key First";
    pm_hmac(PM_SHA1, longkey, sizeof longkey, (const uint8_t *)lm, strlen(lm), mac);
    hexs(mac, 20, hx);
    CHECK(!strcmp(hx, "90d0dace1c1bdc957339307803160335bde6df2b"), "HMAC-SHA1 с ключом длиннее блока");

    uint8_t b1[80], b2[80], bs[80];
    size_t l1 = otp_blob(b1, OTP_TOTP, PM_SHA1, 8, 30, "12345678901234567890");
    size_t l2 = otp_blob(b2, OTP_TOTP, PM_SHA256, 8, 30, "12345678901234567890123456789012");
    size_t ls = otp_blob(bs, OTP_STEAM, PM_SHA1, 5, 30, "steam-test-secret-1234");
    static const struct { uint64_t t; const char *sha1, *sha256; } rfc[] = {
        {59, "94287082", "46119246"},
        {1111111109, "07081804", "68084774"},
        {2000000000, "69279037", "90698825"},
        {20000000000ull, "65353130", "77737706"},
    };
    char code[OTP_CODE_MAX + 1];
    int all = 1;
    for (size_t i = 0; i < sizeof rfc / sizeof rfc[0]; i++) {
        all &= pm_otp_code(b1, l1, rfc[i].t, code) == 8 && !strcmp(code, rfc[i].sha1);
        all &= pm_otp_code(b2, l2, rfc[i].t, code) == 8 && !strcmp(code, rfc[i].sha256);
    }
    CHECK(all, "все векторы RFC 6238 (SHA1, SHA256)");
    uint8_t b6[80];
    size_t l6 = otp_blob(b6, OTP_TOTP, PM_SHA1, 6, 30, "12345678901234567890");
    CHECK(pm_otp_code(b6, l6, 59, code) == 6 && !strcmp(code, "287082"), "6 цифр");
    CHECK(pm_otp_code(bs, ls, 1700000000, code) == 5 && !strcmp(code, "T7WDC"), "Steam Guard");
    CHECK(pm_otp_code(bs, ls, 1700000030, code) == 5 && !strcmp(code, "G4F35"), "Steam Guard, следующий период");

    uint8_t bad[80];
    CHECK(pm_otp_validate(bad, otp_blob(bad, OTP_TOTP, PM_SHA1, 9, 30, "12345678901234567890")) != 0, "9 цифр отвергнуты");
    CHECK(pm_otp_validate(bad, otp_blob(bad, OTP_TOTP, 7, 6, 30, "12345678901234567890")) != 0, "неизвестный алгоритм");
    CHECK(pm_otp_validate(bad, otp_blob(bad, OTP_TOTP, PM_SHA1, 6, 5, "12345678901234567890")) != 0, "период 5 с");
    CHECK(pm_otp_validate(bad, otp_blob(bad, OTP_TOTP, PM_SHA1, 6, 30, "short")) != 0, "короткий секрет");
    CHECK(pm_otp_validate(bad, otp_blob(bad, OTP_STEAM, PM_SHA1, 6, 30, "steam-test-secret-1234")) != 0,
          "Steam только 5 символов");
}

/* Новый токен с настроенным хранилищем; k_vault — для подкладывания старых форматов. */
static void fresh_vault(pm_client *c, uint8_t k_vault[32])
{
    hal_sim_open(NULL);
    token_init();
    new_client(c);
    pmc_pair(c);
    pmc_connect(c);
    char words[512];
    uint8_t seed[32], k_token[32], k_pc[32], salt[16], pw_hash[32];
    pmc_setup_begin(c, words, sizeof words);
    bip39_decode(words, seed);
    pm_keys_from_seed(seed, k_token, k_pc);
    pmc_setup_commit(c, PW);
    pm_salt_from_kpc(k_pc, salt);
    void *work = malloc((size_t)c->argon_blocks * 1024u);
    crypto_argon2_config cfg = {CRYPTO_ARGON2_ID, c->argon_blocks, c->argon_passes, 1};
    crypto_argon2_inputs in = {(const uint8_t *)PW, salt, (uint32_t)strlen(PW), 16};
    crypto_argon2(pw_hash, 32, work, cfg, in, crypto_argon2_no_extras);
    free(work);
    pm_vault_key(k_vault, k_token, k_pc, pw_hash);
}

static void test_otp_protocol(void)
{
    pm_client c;
    uint8_t kv[32];
    char code[16], login[256], pw[PM_MAX_PASSWORD + 1];
    uint8_t type = 0, period = 0;
    fresh_vault(&c, kv);

    section("OTP: запись, список, код считает токен");
    uint8_t b1[80], bs[80];
    size_t l1 = otp_blob(b1, OTP_TOTP, PM_SHA1, 8, 30, "12345678901234567890");
    size_t ls = otp_blob(bs, OTP_STEAM, PM_SHA1, 5, 30, "steam-test-secret-1234");
    uint32_t plain, totp, steam;
    CHECK_RC(pmc_add(&c, "", "Без кода", "u", "p", &plain), 0, "запись без OTP");
    CHECK_RC(pmc_add_otp(&c, "Работа", "GitHub", "ivan", "gh-pass", b1, l1, &totp), 0, "запись с TOTP");
    CHECK_RC(pmc_add_otp(&c, "Игры", "Steam", "ivan_gamer", "st-pass", bs, ls, &steam), 0, "запись со Steam Guard");
    memset(g_list_otp, 0xEE, sizeof g_list_otp);
    CHECK_RC(pmc_list(&c, otp_cb, NULL), 0, "list");
    CHECK(g_list_otp[plain] == OTP_NONE && g_list_otp[totp] == OTP_TOTP && g_list_otp[steam] == OTP_STEAM,
          "список сообщает тип OTP");
    CHECK_RC(pmc_get(&c, totp, login, sizeof login, pw, sizeof pw), 0, "get записи с OTP");
    CHECK(!strcmp(login, "ivan") && !strcmp(pw, "gh-pass"), "get отдаёт только логин и пароль");
    CHECK_RC(pmc_otp(&c, steam, 1700000000, code, sizeof code, &type, &period), 0, "код Steam");
    CHECK(!strcmp(code, "T7WDC") && type == OTP_STEAM && period == 30, "Steam: T7WDC");
    CHECK_RC(pmc_otp(&c, totp, 1700000000, code, sizeof code, &type, &period), 0, "код TOTP");
    CHECK(!strcmp(code, "81921300") && type == OTP_TOTP, "TOTP совпадает с эталоном");
    CHECK_RC(pmc_otp(&c, plain, 1700000000, code, sizeof code, NULL, NULL), ST_NO_OTP, "у записи без OTP кода нет");
    CHECK_RC(pmc_otp(&c, 99, 1700000000, code, sizeof code, NULL, NULL), ST_NOT_FOUND, "нет записи");

    section("OTP: коды «из будущего» не выдаются");
    CHECK_RC(pmc_otp(&c, totp, 1700000000 + 400, code, sizeof code, NULL, NULL), ST_BAD_TIME,
             "время на 400 с впереди часов токена — отказ");
    CHECK_RC(pmc_otp(&c, totp, 1700000000 + 30, code, sizeof code, NULL, NULL), 0, "соседний период — можно");
    CHECK_RC(pmc_otp(&c, totp, 1000, code, sizeof code, NULL, NULL), ST_BAD_TIME, "заведомо неверное время");
    hal_sim_advance_ms(400 * 1000);
    CHECK_RC(pmc_otp(&c, totp, 1700000000 + 400, code, sizeof code, NULL, NULL), 0, "часы токена догнали — можно");
    CHECK(!strcmp(code, "90695910"), "код верный");

    section("OTP: секрет не виден в flash, бэкапе и ответах");
    const uint8_t *fl = hal_sim_flash();
    CHECK(!memfind(fl, hal_flash_size(), "steam-test-secret", 17), "секрет Steam не виден в flash");
    CHECK(!memfind(fl, hal_flash_size(), "12345678901234567890", 20), "секрет TOTP не виден в flash");
    static uint8_t bk[PM_MAX_BACKUP];
    size_t bkl;
    CHECK_RC(pmc_backup(&c, bk, sizeof bk, &bkl), 0, "backup");
    CHECK(!memfind(bk, bkl, "steam-test-secret", 17), "бэкап зашифрован");

    section("OTP: ограничение частоты кодов");
    hal_sim_advance_ms(TOKEN_RATE_WINDOW_MS + 10);
    int ok = 1;
    uint64_t now = 1700000000 + 400 + 60;
    for (unsigned i = 0; i < TOKEN_OTP_RATE_N; i++) ok &= pmc_otp(&c, totp, now, code, sizeof code, NULL, NULL) == 0;
    CHECK(ok, "первые N кодов");
    CHECK_RC(pmc_otp(&c, totp, now, code, sizeof code, NULL, NULL), ST_RATE_LIMIT, "N+1 — отказ");

    section("правка на месте (UPDATE)");
    CHECK_RC(pmc_update(&c, totp, "Работа", "GitHub (новый)", "ivan2", "gh-pass-2", PMC_OTP_KEEP, NULL, 0), 0,
             "переименовать, OTP оставить");
    CHECK_RC(pmc_get(&c, totp, login, sizeof login, pw, sizeof pw), 0, "get");
    CHECK(!strcmp(login, "ivan2") && !strcmp(pw, "gh-pass-2"), "id прежний, данные новые");
    hal_sim_advance_ms(TOKEN_RATE_WINDOW_MS + 10);
    CHECK_RC(pmc_otp(&c, totp, now, code, sizeof code, NULL, NULL), 0, "OTP пережил правку");
    CHECK_RC(pmc_update(&c, totp, "Работа", "GitHub", "ivan", "p", PMC_OTP_SET, bs, ls), 0, "заменить OTP на Steam");
    CHECK_RC(pmc_otp(&c, totp, now, code, sizeof code, &type, NULL), 0, "код");
    CHECK(type == OTP_STEAM && strlen(code) == 5, "теперь Steam");
    CHECK_RC(pmc_update(&c, totp, "Работа", "GitHub", "ivan", "p", PMC_OTP_REMOVE, NULL, 0), 0, "убрать OTP");
    CHECK_RC(pmc_otp(&c, totp, now, code, sizeof code, NULL, NULL), ST_NO_OTP, "кода больше нет");
    CHECK_RC(pmc_update(&c, 77, "", "x", "", "", PMC_OTP_KEEP, NULL, 0), ST_NOT_FOUND, "правка несуществующей");
    uint8_t bad[80];
    size_t bl = otp_blob(bad, OTP_TOTP, PM_SHA1, 9, 30, "12345678901234567890");
    CHECK_RC(pmc_update(&c, totp, "", "x", "", "", PMC_OTP_SET, bad, bl), ST_BAD_ARGS, "неверные параметры OTP");
    reboot_token();
    pmc_connect(&c);
    CHECK_RC(pmc_unlock(&c, PW), 0, "после перезагрузки");
    memset(g_list_otp, 0xEE, sizeof g_list_otp);
    CHECK_RC(pmc_list(&c, otp_cb, NULL), 0, "list");
    CHECK(g_list_otp[totp] == OTP_NONE && g_list_otp[steam] == OTP_STEAM && g_list_otp[plain] == OTP_NONE,
          "правки сохранены на flash");
    hal_sim_advance_ms(TOKEN_RATE_WINDOW_MS + 10);
    CHECK_RC(pmc_get(&c, steam, login, sizeof login, pw, sizeof pw), 0, "соседняя запись");
    CHECK(!strcmp(pw, "st-pass"), "не задета правкой");
    pmc_wipe(&c);
}

/* STEAM_MOBILE: [3][1][5][30][n][shared][m][identity][u64 steamid][r][revocation] */
static size_t steam_blob(uint8_t *b, const char *shared, const char *identity, uint64_t sid, const char *rev)
{
    size_t n = 0, l;
    b[n++] = OTP_STEAM_MOBILE; b[n++] = PM_SHA1; b[n++] = 5; b[n++] = 30;
    l = strlen(shared);   b[n++] = (uint8_t)l; memcpy(b + n, shared, l); n += l;
    l = strlen(identity); b[n++] = (uint8_t)l; memcpy(b + n, identity, l); n += l;
    for (int i = 0; i < 8; i++) b[n++] = (uint8_t)(sid >> (8 * i));
    l = strlen(rev);      b[n++] = (uint8_t)l; memcpy(b + n, rev, l); n += l;
    return n;
}

static int hex_eq(const uint8_t *b, const char *hex)
{
    for (size_t i = 0; hex[2 * i]; i++) {
        unsigned v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1 || b[i] != v) return 0;
    }
    return 1;
}

static void test_steam_confirmations(void)
{
    pm_client c;
    uint8_t kv[32], key[20];
    char code[16], rev[32];
    fresh_vault(&c, kv);

    section("Steam: разбор параметров");
    uint8_t b[OTP_BLOB_MAX];
    size_t bl = steam_blob(b, "steam-test-secret-1234", "steam-identity-secret-01", 76561197960287930ull, "R12345");
    CHECK(pm_otp_validate(b, bl) == 0, "валидный блок");
    CHECK(bl <= OTP_BLOB_MAX, "влезает в OTP_BLOB_MAX");
    b[bl - 1] = ' ';
    CHECK(pm_otp_validate(b, bl) != 0, "непечатный код восстановления — отказ");
    bl = steam_blob(b, "steam-test-secret-1234", "short", 1, "");
    CHECK(pm_otp_validate(b, bl) != 0, "короткий identity_secret — отказ");
    CHECK(pm_otp_validate(b, bl - 1) != 0, "обрезанный блок — отказ");
    CHECK(pm_steam_tag_ok((const uint8_t *)"details123", 10) && !pm_steam_tag_ok((const uint8_t *)"Conf", 4) &&
          !pm_steam_tag_ok((const uint8_t *)"", 0), "теги: [a-z0-9], 1..32");

    section("Steam: ключи подтверждений считает токен");
    bl = steam_blob(b, "steam-test-secret-1234", "steam-identity-secret-01", 76561197960287930ull, "R12345");
    uint32_t id, totp;
    CHECK_RC(pmc_add_otp(&c, "Игры", "Steam", "gamer", "pw", b, bl, &id), 0, "запись с подтверждениями");
    uint8_t tb[40];
    size_t tl = otp_blob(tb, OTP_TOTP, PM_SHA1, 6, 30, "12345678901234567890");
    CHECK_RC(pmc_add_otp(&c, "", "Обычный TOTP", "", "", tb, tl, &totp), 0, "запись с TOTP");
    memset(g_list_otp, 0xEE, sizeof g_list_otp);
    pmc_list(&c, otp_cb, NULL);
    CHECK(g_list_otp[id] == OTP_STEAM_MOBILE, "список: тип 3");
    CHECK_RC(pmc_otp(&c, id, 1700000000, code, sizeof code, NULL, NULL), 0, "код входа");
    CHECK(!strcmp(code, "T7WDC"), "код входа из shared_secret");
    CHECK_RC(pmc_steam_conf(&c, id, 1700000000, "conf", key), 0, "ключ списка");
    CHECK(hex_eq(key, "18d97b0ee4409ea0b28919293b68beac46afb3b6"), "conf: совпал с эталоном");
    CHECK_RC(pmc_steam_conf(&c, id, 1700000000, "allow", key), 0, "ключ одобрения");
    CHECK(hex_eq(key, "3a8d79b3d6a5bd02aa3db74bc3603e0c4c21a6ab"), "allow: совпал с эталоном");
    CHECK_RC(pmc_steam_conf(&c, id, 1700000030, "details12345", key), 0, "ключ деталей");
    CHECK(hex_eq(key, "d4d392d35e37e7de21aeb76aed7a49e58b023e84"), "details: совпал с эталоном");
    CHECK_RC(pmc_steam_conf(&c, id, 1710000000, "allow", key), ST_BAD_TIME, "ключи «из будущего» — нет");
    CHECK_RC(pmc_steam_conf(&c, totp, 1700000000, "conf", key), ST_NO_OTP, "у TOTP нет identity_secret");
    CHECK_RC(pmc_steam_conf(&c, id, 1700000000, "Allow!", key), ST_BAD_ARGS, "тег с чужими символами");

    section("Steam: SteamID и код восстановления");
    uint64_t sid = 0;
    CHECK_RC(pmc_steam_info(&c, id, &sid, NULL, 0), 0, "SteamID");
    CHECK(sid == 76561197960287930ull, "SteamID верный");
    CHECK_RC(pmc_steam_info(&c, id, &sid, rev, sizeof rev), 0, "код восстановления");
    CHECK(!strcmp(rev, "R12345"), "код восстановления верный");
    CHECK_RC(pmc_steam_info(&c, totp, &sid, NULL, 0), ST_NO_OTP, "у TOTP нет Steam");

    section("Steam: журнал, лимит, секреты не видны");
    int acts = 0;
    g_log_n = 0;
    pmc_log(&c, log_cb, NULL);
    for (int i = 0; i < g_log_n; i++) acts += g_log_cmd[i] == CMD_STEAM_CONF;
    CHECK(acts == 2, "в журнале одобрение и отклонённая попытка, без списка и деталей");
    hal_sim_advance_ms(TOKEN_RATE_WINDOW_MS + 10);
    int limited = 0;
    for (unsigned i = 0; i <= TOKEN_STEAM_RATE_N; i++)
        if (pmc_steam_conf(&c, id, 1700000000, "conf", key) == ST_RATE_LIMIT) limited = 1;
    CHECK(limited, "не больше 30 ключей в минуту");
    const uint8_t *fl = hal_sim_flash();
    CHECK(!memfind(fl, hal_flash_size(), "steam-identity", 14), "identity_secret не виден в flash");
    uint32_t id2;
    uint8_t up[OTP_BLOB_MAX];
    size_t ul = steam_blob(up, "steam-test-secret-1234", "steam-identity-secret-02", 7, "R99999");
    CHECK_RC(pmc_update(&c, id, "Игры", "Steam", "gamer", "pw", PMC_OTP_SET, up, ul), 0, "замена секретов");
    CHECK_RC(pmc_steam_info(&c, id, &sid, NULL, 0), 0, "после замены");
    CHECK(sid == 7, "новый SteamID");
    CHECK_RC(pmc_add_otp(&c, "", "x", "", "", up, ul, &id2), 0, "вторая запись");
    pmc_wipe(&c);
}

static void test_storage_info(void)
{
    pm_client c;
    uint8_t kv[32];
    pmc_info_t info;
    fresh_vault(&c, kv);

    section("INFO: занятое и свободное место");
    CHECK_RC(pmc_info(&c, &info), 0, "info");
    CHECK(info.capacity == store_capacity() && info.capacity > 150000, "ёмкость — по буферу и flash (сотни КБ)");
    uint32_t empty = info.used;
    uint32_t id;
    CHECK_RC(pmc_add(&c, "Кат", "Имя", "логин", "пароль-123", &id), 0, "add");
    CHECK_RC(pmc_info(&c, &info), 0, "info");
    /* id 4 + строки с длиной + пароль с u16 + пустой OTP */
    size_t entry = 4 + 1 + strlen("Кат") + 1 + strlen("Имя") + 1 + strlen("логин") + 2 + strlen("пароль-123") + 1;
    CHECK(info.used == empty + entry, "used вырос ровно на размер записи");
    CHECK_RC(pmc_delete(&c, id), 0, "delete");
    pmc_info(&c, &info);
    CHECK(info.used == empty, "после удаления — как было");
    CHECK_RC(pmc_lock(&c), 0, "lock");
    pmc_info(&c, &info);
    CHECK(info.used == 0 && info.capacity == store_capacity(), "закрыто: used не раскрывается");
    pmc_wipe(&c);
}

/* Записать в flash симулятора старую разметку (последние 80 КБ): конфигурация v2
 * в секторе 0, копия хранилища (как бэкап) в слоте A. Остальное стёрто. */
static void write_legacy_layout(const pm_config *cfg, const uint8_t *blob, size_t blob_len, const char *file)
{
    static uint8_t img[256 * 1024];
    memset(img, 0xFF, sizeof img);
    uint8_t *b = img;                              /* старый файл: разметка с нуля */
    wire_put32(b, 0x46434D50u);                    /* "PMCF" */
    b[4] = 2;
    wire_put32(b + 5, cfg->seq);
    b[9] = (uint8_t)(cfg->flags | (cfg->pc_count ? 0x01 : 0));   /* старый флаг «сопряжён» */
    memcpy(b + 10, cfg->token_sk, 32);
    memcpy(b + 42, cfg->pcs[0].pub, 32);
    memcpy(b + 74, cfg->k_token, 32);
    wire_put32(b + 106, cfg->fails);
    crypto_blake2b(b + 110, 32, b, 110);
    memcpy(img + 2 * 4096, blob, blob_len);        /* слот A старой разметки */
    FILE *f = fopen(file, "wb");
    fwrite(img, 1, sizeof img, f);
    fclose(f);
}

static void test_big_vault_and_migration(void)
{
    pm_client c;
    char words[512];
    static uint8_t bk[PM_MAX_BACKUP];
    size_t bl = 0;
    static char pw[PM_MAX_PASSWORD + 1];
    char name[32], login[300], got[PM_MAX_PASSWORD + 1];

    section("ёмкость: по RAM и flash, а не 32 КБ");
    hal_sim_open(NULL);
    token_init();
    new_client(&c);
    pmc_pair(&c);
    pmc_connect(&c);
    pmc_setup_begin(&c, words, sizeof words);
    CHECK_RC(pmc_setup_commit(&c, PW), 0, "setup");
    pmc_info_t info;
    pmc_info(&c, &info);
    CHECK(info.capacity >= 190000, "ёмкость ~192 КБ (буфер симулятора как у RP2040)");
    memset(pw, 'k', 1000);
    pw[1000] = 0;
    int ok = 1;
    for (int i = 0; i < 150 && ok; i++) {
        snprintf(name, sizeof name, "Запись %03d", i);
        uint32_t id;
        pw[0] = (char)('A' + i % 26);
        ok = pmc_add(&c, "Много", name, "user", pw, &id) == 0;
    }
    CHECK(ok, "150 записей по 1 КБ (больше старого лимита)");
    pmc_info(&c, &info);
    CHECK(info.used > 150000, "занято > 150 КБ");
    CHECK(list_count(&c) == 150, "список — несколькими страницами, все 150");

    section("бэкап частями и восстановление на чистый токен");
    CHECK_RC(pmc_backup(&c, bk, sizeof bk, &bl), 0, "backup");
    CHECK(bl > 150000 && bl > PM_MAX_FRAME, "бэкап больше кадра");
    CHECK(!memfind(bk, bl, "kkkkkkkk", 8), "бэкап зашифрован");
    reboot_token();
    pmc_connect(&c);
    pmc_unlock(&c, PW);
    CHECK_RC(pmc_factory_reset(&c), 0, "стёрли токен");
    hal_sim_open(NULL);                            /* «новая плата» */
    token_init();
    pm_client n;
    new_client(&n);
    pmc_pair(&n);
    pmc_connect(&n);
    CHECK_RC(pmc_restore(&n, words, PW, bk, bl), 0, "restore 150 КБ");
    CHECK(list_count(&n) == 150, "все записи на месте");
    uint32_t first_id = 0;
    for (uint32_t id = 1; id < 300 && !first_id; id++)
        if (pmc_get(&n, id, login, sizeof login, got, sizeof got) == 0) first_id = id;
    CHECK(first_id && strlen(got) == 1000 && got[0] == 'A', "данные целы");

    section("заполнение до отказа");
    int full = 0;
    for (int i = 0; i < 400 && !full; i++) {
        uint32_t id;
        snprintf(name, sizeof name, "Ещё %03d", i);
        int rc = pmc_add(&n, "", name, "u", pw, &id);
        if (rc == ST_FULL) full = 1;
        else if (rc != 0) break;
    }
    pmc_info(&n, &info);
    CHECK(full && info.used <= info.capacity && info.capacity - info.used < 1100, "ST_FULL у самого края ёмкости");
    pmc_wipe(&n);

    section("перенос старой разметки (последние 80 КБ)");
    hal_sim_open(NULL);
    token_init();
    new_client(&c);
    pmc_pair(&c);
    pmc_connect(&c);
    pmc_setup_begin(&c, words, sizeof words);
    pmc_setup_commit(&c, PW);
    uint32_t idx;
    pmc_add(&c, "Старое", "До обновления", "old-user", "old-pass", &idx);
    bl = 0;
    pmc_backup(&c, bk, sizeof bk, &bl);           /* копия слота = формат старого слота */
    pm_config cfg;
    store_config_load(&cfg);
    write_legacy_layout(&cfg, bk, bl, "legacy_flash.bin");
    crypto_wipe(&cfg, sizeof cfg);
    hal_sim_open("legacy_flash.bin");              /* файл прежней версии, 256 КБ */
    token_init();                                  /* перенос */
    CHECK_RC(pmc_connect(&c), 0, "сопряжение пережило перенос");
    CHECK_RC(pmc_unlock(&c, PW), 0, "хранилище открывается");
    CHECK_RC(pmc_get(&c, idx, login, sizeof login, got, sizeof got), 0, "запись");
    CHECK(!strcmp(login, "old-user") && !strcmp(got, "old-pass"), "данные целы после переноса");
    pmc_info(&c, &info);
    CHECK(info.capacity >= 190000, "и ёмкость уже новая");
    uint32_t id2;
    CHECK_RC(pmc_add(&c, "", "После", "u", "p", &id2), 0, "запись после переноса");
    hal_sim_open("legacy_flash.bin");              /* перезапуск: новый файл 1 МБ */
    token_init();
    pmc_connect(&c);
    CHECK_RC(pmc_unlock(&c, PW), 0, "после перезапуска");
    CHECK(list_count(&c) == 2, "обе записи");
    remove("legacy_flash.bin");
    pmc_wipe(&c);
    hal_sim_open(NULL);
}

static int g_pcs_n, g_pcs_me;
static char g_pcs_label[4][64];
static void pcs_cb(void *ctx, int slot, int me, const uint8_t id[8], const char *label)
{
    (void)ctx; (void)id;
    if (slot < 4) snprintf(g_pcs_label[slot], sizeof g_pcs_label[slot], "%s", label);
    if (me) g_pcs_me = slot;
    g_pcs_n++;
}
static int pcs(pm_client *c)
{
    g_pcs_n = 0;
    g_pcs_me = -1;
    int rc = pmc_pc_list(c, pcs_cb, NULL);
    return rc == 0 ? g_pcs_n : -1;
}

static void test_multi_pc(void)
{
    pm_client a, b, x;
    char words[512], other[512];
    uint32_t id;

    section("до 4 ПК на токен: привязка по 24 словам");
    hal_sim_open(NULL);
    token_init();
    new_client(&a);
    pmc_pair(&a);
    pmc_connect(&a);
    pmc_setup_begin(&a, words, sizeof words);
    CHECK_RC(pmc_setup_commit(&a, PW), 0, "настроен на ПК A");
    pmc_add(&a, "", "Общая", "user", "shared-pass", &id);
    CHECK_RC(pmc_pc_label(&a, "Домашний ПК"), 0, "имя ПК A");

    new_client(&b);
    CHECK_RC(pmc_pair(&b), PMC_E_TOKEN - FE_ALREADY_PAIRED, "без слов второй ПК не привязать");
    /* другая, но корректная фраза */
    uint8_t rnd[32], seed2[32];
    hal_rng(rnd, 32);
    pm_seed_from_rand(seed2, rnd, rnd);
    bip39_to_string(seed2, other, sizeof other);
    CHECK_RC(pmc_pair_words(&b, other), PMC_E_TOKEN - FE_BAD_PROOF, "чужая фраза — отказ");
    CHECK_RC(pmc_pair_words(&b, words), PMC_E_TOKEN - FE_BAD_PROOF, "сразу после ошибки — пауза");
    hal_sim_advance_ms(1100);
    CHECK_RC(pmc_pair_words(&b, words), 0, "своя фраза — ПК B привязан");
    CHECK(b.have_kpc, "K_pc получен из слов");
    CHECK_RC(pmc_connect(&b), 0, "B: сессия");
    CHECK_RC(pmc_unlock(&b, PW), 0, "B: тот же мастер-пароль открывает хранилище");
    char login[64], pw[64];
    CHECK_RC(pmc_get(&b, id, login, sizeof login, pw, sizeof pw), 0, "B видит записи");
    CHECK(!strcmp(pw, "shared-pass"), "те же данные");
    CHECK_RC(pmc_pc_label(&b, "Рабочий ноутбук"), 0, "имя ПК B");
    CHECK(pcs(&b) == 2 && g_pcs_me == 1, "в списке 2 ПК, B — второй");
    CHECK(!strcmp(g_pcs_label[0], "Домашний ПК") && !strcmp(g_pcs_label[1], "Рабочий ноутбук"), "имена видны");
    CHECK_RC(pmc_connect(&a), 0, "A по-прежнему работает");

    section("не больше 4, отвязка");
    for (int i = 0; i < 2; i++) {
        new_client(&x);
        CHECK_RC(pmc_pair_words(&x, words), 0, "ещё ПК");
    }
    new_client(&x);
    CHECK_RC(pmc_pair_words(&x, words), PMC_E_TOKEN - FE_PAIR_FULL, "пятый — отказ");
    pmc_connect(&a);
    pmc_unlock(&a, PW);
    CHECK(pcs(&a) == 4, "4 ПК");
    CHECK_RC(pmc_pc_remove(&a, 1), 0, "A отвязывает B");
    CHECK_RC(pmc_connect(&b), PMC_E_TOKEN - FE_NOT_PAIRED, "B больше не подключается: токен его не знает");
    CHECK(pcs(&a) == 3 && g_pcs_me == 0, "осталось 3");
    reboot_token();
    pmc_connect(&a);
    pmc_unlock(&a, PW);
    CHECK(pcs(&a) == 3, "список пережил перезагрузку");
    CHECK_RC(pmc_pair_words(&b, words), 0, "B снова привязывается по словам");
    CHECK_RC(pmc_connect(&a), 0, "A");
    pmc_unlock(&a, PW);
    CHECK_RC(pmc_pc_remove(&a, 0), 0, "A отвязывает себя");
    pmc_info_t inf;
    CHECK_RC(pmc_info(&a, &inf), PMC_E_TOKEN - FE_NO_SESSION, "сессия A закрыта");
    CHECK_RC(pmc_connect(&a), PMC_E_TOKEN - FE_NOT_PAIRED, "A больше не привязан");
    CHECK_RC(pmc_pair(&a), PMC_E_TOKEN - FE_ALREADY_PAIRED, "и TOFU больше не работает");
    pmc_wipe(&a); pmc_wipe(&b); pmc_wipe(&x);
}

static void test_multi_token(void)
{
    static uint8_t img_a[1024 * 1024];
    pm_client c;
    char words[512];
    uint32_t ida, idb;
    char login[64], pw[64];

    section("до 4 токенов на ПК: выбор сам");
    new_client(&c);
    hal_sim_open(NULL);                                       /* токен A */
    token_init();
    pmc_pair(&c);
    pmc_connect(&c);
    pmc_setup_begin(&c, words, sizeof words);
    pmc_setup_commit(&c, "pw-A");
    pmc_add(&c, "", "На токене A", "a", "pa", &ida);
    uint8_t pk_a[32];
    memcpy(pk_a, c.token_pk, 32);
    memcpy(img_a, hal_sim_flash(), sizeof img_a);

    hal_sim_open(NULL);                                       /* токен B: другая плата */
    token_init();
    CHECK_RC(pmc_connect(&c), PMC_E_NOT_PAIRED, "незнакомый токен — не ошибка связи, а «не привязан»");
    uint8_t who[32];
    int setup = -1, n = -1;
    CHECK_RC(pmc_who(&c, who, &setup, &n), 0, "who");
    CHECK(!setup && n == 0 && memcmp(who, pk_a, 32) != 0, "чистый токен, другой ключ");
    CHECK_RC(pmc_pair(&c), 0, "привязали B");
    pmc_connect(&c);
    pmc_setup_begin(&c, words, sizeof words);
    pmc_setup_commit(&c, "pw-B");
    pmc_add(&c, "", "На токене B", "b", "pb", &idb);
    CHECK(c.known_n == 2, "ПК знает оба токена");
    CHECK_RC(pmc_identity_save(&c, "multi.id"), 0, "save");

    memcpy(hal_sim_flash(), img_a, sizeof img_a);            /* снова A */
    token_init();
    pm_client c2;
    new_client(&c2);
    CHECK_RC(pmc_identity_load(&c2, "multi.id"), 0, "load (v2)");
    CHECK_RC(pmc_connect(&c2), 0, "подключён A — выбран A");
    CHECK(!memcmp(c2.token_pk, pk_a, 32), "ключ A");
    CHECK_RC(pmc_unlock(&c2, "pw-A"), 0, "открыт своим паролем");
    CHECK_RC(pmc_get(&c2, ida, login, sizeof login, pw, sizeof pw), 0, "get");
    CHECK(!strcmp(pw, "pa"), "данные A");
    CHECK(list_count(&c2) == 1 && seen("На токене A"), "только записи A");

    section("файл ключа ПК: старый формат (один токен)");
    {
        uint8_t v1[102] = {'P', 'M', 'I', 'D', 1, 3};
        memcpy(v1 + 6, c2.sk, 32);
        memcpy(v1 + 38, pk_a, 32);
        memcpy(v1 + 70, c2.known[0].k_pc, 32);
        int ia = memcmp(c2.known[0].token_pk, pk_a, 32) == 0 ? 0 : 1;
        memcpy(v1 + 70, c2.known[ia].k_pc, 32);
        FILE *f = fopen("v1.id", "wb");
        fwrite(v1, 1, sizeof v1, f);
        fclose(f);
        pm_client old;
        new_client(&old);
        CHECK_RC(pmc_identity_load(&old, "v1.id"), 0, "загружен v1");
        CHECK(old.known_n == 1 && old.have_kpc, "один токен с ключом");
        CHECK_RC(pmc_connect(&old), 0, "подключается");
        CHECK_RC(pmc_unlock(&old, "pw-A"), 0, "и открывается");
        CHECK_RC(pmc_identity_save(&old, "v1.id"), 0, "сохранён уже как v2");
        pmc_wipe(&old);
        remove("v1.id");
    }

    section("не больше 4 токенов на ПК");
    for (int i = 0; i < 2; i++) {
        hal_sim_open(NULL);
        token_init();
        CHECK_RC(pmc_pair(&c2), 0, "ещё токен");
    }
    hal_sim_open(NULL);
    token_init();
    CHECK(c2.known_n == 4, "4 токена");
    CHECK_RC(pmc_pair(&c2), PMC_E_TOO_MANY, "пятый — отказ (сначала забыть ненужный)");
    CHECK_RC(pmc_forget_token(&c2, 3), 0, "забыли один");
    CHECK_RC(pmc_pair(&c2), 0, "теперь можно");
    remove("multi.id");
    pmc_wipe(&c); pmc_wipe(&c2);
    hal_sim_open(NULL);
}

static void test_framer(void)
{
    section("сборка кадров из потока (USB CDC)");
    uint8_t stream[64], buf[16];
    size_t n = 0;
    pm_framer_header(stream, 5);  memcpy(stream + 4, "hello", 5);  n = 9;
    pm_framer_header(stream + n, 3); memcpy(stream + n + 4, "abc", 3); n += 7;
    pm_framer f;
    pm_framer_reset(&f);
    /* по одному байту */
    int got = 0;
    for (size_t i = 0; i < n; i++) {
        size_t used;
        long r = pm_framer_feed(&f, buf, sizeof buf, stream + i, 1, &used);
        if (r == 5 && !memcmp(buf, "hello", 5)) got |= 1;
        if (r == 3 && !memcmp(buf, "abc", 3)) got |= 2;
        CHECK(used == 1 || r != 0, "байт потреблён");
    }
    CHECK(got == 3 && !pm_framer_busy(&f), "по одному байту: оба кадра");
    /* оба кадра одним куском: второй — в остатке */
    size_t used;
    long r = pm_framer_feed(&f, buf, sizeof buf, stream, n, &used);
    CHECK(r == 5 && used == 9, "первый кадр, остаток не тронут");
    r = pm_framer_feed(&f, buf, sizeof buf, stream + used, n - used, &used);
    CHECK(r == 3 && !memcmp(buf, "abc", 3), "второй кадр из остатка");
    /* длина больше буфера и нулевая — отказ со сбросом */
    uint8_t bad[4];
    pm_framer_header(bad, sizeof buf + 1);
    CHECK(pm_framer_feed(&f, buf, sizeof buf, bad, 4, &used) == -1 && !pm_framer_busy(&f), "слишком длинный кадр");
    pm_framer_header(bad, 0);
    CHECK(pm_framer_feed(&f, buf, sizeof buf, bad, 4, &used) == -1, "пустой кадр");
    /* обрыв посреди кадра: busy, сброс по таймауту делает транспорт */
    pm_framer_feed(&f, buf, sizeof buf, stream, 6, &used);
    CHECK(pm_framer_busy(&f), "незаконченный кадр виден");
    pm_framer_reset(&f);
    r = pm_framer_feed(&f, buf, sizeof buf, stream + 9, 7, &used);
    CHECK(r == 3, "после сброса — снова синхронно");

    section("USB: токен узнаётся по имени, чужой 1209:0001 — нет");
    CHECK(pm_serial_name_ok("pmtoken") && pm_serial_name_ok("pmtoken\n") && pm_serial_name_ok(" PMToken "), "pmtoken");
    CHECK(!pm_serial_name_ok("pmtoken2") && !pm_serial_name_ok("Pico") && !pm_serial_name_ok("") &&
          !pm_serial_name_ok("USB Serial Device"), "чужие имена");

#ifndef _WIN32
    section("USB: поиск в sysfs — VID/PID и имя");
    {
        /* <root>/devs/{tok,pico}: устройства; <root>/tty/ttyACM{0,1}/device -> интерфейс */
        char root[] = "/tmp/pmsysfs-XXXXXX", p[600], found[64];
        CHECK(mkdtemp(root) != NULL, "временный каталог");
        const char *dev[2][3] = {{"pico", "Pico", "ttyACM0"}, {"tok", "pmtoken", "ttyACM1"}};
        snprintf(p, sizeof p, "%s/devs", root); mkdir(p, 0700);
        snprintf(p, sizeof p, "%s/tty", root); mkdir(p, 0700);
        for (int i = 0; i < 2; i++) {
            const char *files[3][2] = {{"idVendor", "1209\n"}, {"idProduct", "0001\n"}, {"product", dev[i][1]}};
            snprintf(p, sizeof p, "%s/devs/%s", root, dev[i][0]); mkdir(p, 0700);
            snprintf(p, sizeof p, "%s/devs/%s/if0", root, dev[i][0]); mkdir(p, 0700);
            for (int k = 0; k < 3; k++) {
                snprintf(p, sizeof p, "%s/devs/%s/%s", root, dev[i][0], files[k][0]);
                FILE *f = fopen(p, "w"); fputs(files[k][1], f); fclose(f);
            }
            snprintf(p, sizeof p, "%s/tty/%s", root, dev[i][2]); mkdir(p, 0700);
            char target[300];
            snprintf(target, sizeof target, "%s/devs/%s/if0", root, dev[i][0]);
            snprintf(p, sizeof p, "%s/tty/%s/device", root, dev[i][2]);
            if (symlink(target, p) != 0) perror("symlink");
        }
        snprintf(p, sizeof p, "%s/tty", root);
        CHECK(pm_serial_find_in(p, found, sizeof found) == 1 && !strcmp(found, "/dev/ttyACM1"),
              "из двух 1209:0001 выбран pmtoken, не Pico");
        snprintf(p, sizeof p, "%s/devs/tok/product", root);
        FILE *f = fopen(p, "w"); fputs("Other", f); fclose(f);
        snprintf(p, sizeof p, "%s/tty", root);
        CHECK(pm_serial_find_in(p, found, sizeof found) == 0, "оба чужие — не найден");
        char cmd[700];
        snprintf(cmd, sizeof cmd, "rm -rf '%s'", root);
        if (system(cmd) != 0) puts("  (не удалось убрать временный каталог)");
    }
#endif

    section("token_handle: вход и выход в одном буфере");
    hal_sim_erase();
    token_init();
    static uint8_t io[PM_MAX_FRAME + 64];
    io[0] = FR_PAIR;
    memset(io + 1, 0x42, 32);
    size_t out = token_handle(io, 33, io, sizeof io);
    uint8_t pub[32];
    token_public_key(pub);
    CHECK(out == 33 && io[0] == FR_PAIR && !memcmp(io + 1, pub, 32), "PAIR на месте");
}

static void test_security_hardening(void)
{
    pm_client c;
    uint8_t kv[32];
    char login[256], pw[PM_MAX_PASSWORD + 1];
    fresh_vault(&c, kv);

    section("журнал только при открытом хранилище");
    CHECK_RC(pmc_lock(&c), 0, "lock");
    CHECK_RC(pmc_log(&c, log_cb, NULL), ST_LOCKED, "журнал закрыт");

    section("счётчик неверных паролей переживает перезагрузку");
    for (int i = 0; i < 3; i++) CHECK_RC(pmc_unlock(&c, "wrong"), ST_WRONG_KEY, "неверный пароль");
    CHECK_RC(pmc_unlock(&c, PW), ST_BACKOFF, "задержка");
    reboot_token();                                   /* выдернули токен, чтобы сбросить задержку */
    CHECK_RC(pmc_connect(&c), 0, "connect");
    CHECK_RC(pmc_unlock(&c, PW), ST_BACKOFF, "после перезагрузки задержка осталась");
    hal_sim_advance_ms(1100);
    CHECK_RC(pmc_unlock(&c, PW), 0, "после задержки открывается");
    pmc_lock(&c);
    reboot_token();
    pmc_connect(&c);
    CHECK_RC(pmc_unlock(&c, "wrong"), ST_WRONG_KEY, "после успеха счётчик обнулён: снова 3 бесплатные попытки");
    CHECK_RC(pmc_unlock(&c, PW), 0, "unlock");

    section("предел задержки — час");
    pmc_lock(&c);
    uint64_t total = 0;
    for (int i = 0; i < 30; i++) {
        int rc = pmc_unlock(&c, "wrong");
        if (rc == ST_BACKOFF) { hal_sim_advance_ms(TOKEN_BACKOFF_MAX_MS); total += TOKEN_BACKOFF_MAX_MS; i--; continue; }
        CHECK(rc == ST_WRONG_KEY, "неверный пароль");
    }
    hal_sim_advance_ms(TOKEN_BACKOFF_MAX_MS - 1000);
    CHECK_RC(pmc_unlock(&c, PW), ST_BACKOFF, "через 59 мин ещё ждём");
    hal_sim_advance_ms(2000);
    CHECK_RC(pmc_unlock(&c, PW), 0, "через час можно");
    (void)total;

    section("миграция хранилища v1 -> v2");
    static uint8_t v1[256];
    size_t n = 0;
    v1[n++] = 2; v1[n++] = 0;                 /* count */
    wire_put32(v1 + n, 6); n += 4;            /* next_id, версия 0 = v1 */
    wire_put32(v1 + n, 5); n += 4;            /* id */
    const char *f[] = {"Старое", "Legacy", "olduser"};
    for (int i = 0; i < 3; i++) { size_t l = strlen(f[i]); v1[n++] = (uint8_t)l; memcpy(v1 + n, f[i], l); n += l; }
    v1[n++] = 6; v1[n++] = 0; memcpy(v1 + n, "old-pw", 6); n += 6;
    wire_put32(v1 + n, 4); n += 4;            /* вторая запись: миграция сдвигает хвост */
    const char *g[] = {"", "Second", "u2"};
    for (int i = 0; i < 3; i++) { size_t l = strlen(g[i]); v1[n++] = (uint8_t)l; memcpy(v1 + n, g[i], l); n += l; }
    v1[n++] = 3; v1[n++] = 0; memcpy(v1 + n, "pw2", 3); n += 3;
    CHECK(store_vault_save(kv, v1, n) == 0, "подложили хранилище старого формата");
    reboot_token();
    pmc_connect(&c);
    CHECK_RC(pmc_unlock(&c, PW), 0, "открывается");
    memset(g_list_otp, 0xEE, sizeof g_list_otp);
    CHECK(list_count(&c) == 2 && seen("Legacy") && seen("Second"), "записи на месте");
    CHECK_RC(pmc_list(&c, otp_cb, NULL), 0, "list");
    CHECK(g_list_otp[5] == OTP_NONE && g_list_otp[4] == OTP_NONE, "OTP нет");
    CHECK_RC(pmc_get(&c, 5, login, sizeof login, pw, sizeof pw), 0, "get");
    CHECK(!strcmp(login, "olduser") && !strcmp(pw, "old-pw"), "данные целы");
    CHECK_RC(pmc_get(&c, 4, login, sizeof login, pw, sizeof pw), 0, "get второй");
    CHECK(!strcmp(login, "u2") && !strcmp(pw, "pw2"), "вторая цела");
    uint32_t id;
    CHECK_RC(pmc_add(&c, "", "Новая", "n", "np", &id), 0, "add после миграции");
    CHECK(id == 6, "нумерация продолжилась");
    reboot_token();
    pmc_connect(&c);
    CHECK_RC(pmc_unlock(&c, PW), 0, "после перезагрузки (уже v2)");
    CHECK(list_count(&c) == 3, "все записи");
    pmc_wipe(&c);
}

int main(int argc, char **argv)
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    hal_sim_quiet(1);
    test_vectors();
    test_session();
    test_full_flow();
    test_restore();
    test_hashes_and_otp_vectors();
    test_otp_protocol();
    test_security_hardening();
    test_framer();
    test_steam_confirmations();
    test_storage_info();
    test_big_vault_and_migration();
    test_multi_pc();
    test_multi_token();
    if (argc > 1 && !strcmp(argv[1], "--argon")) test_real_argon_cost();
    printf("\nИтого: %d пройдено, %d провалено\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
