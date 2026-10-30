/*
 * Тесты: клиент и токен в одном процессе, транспорт — прямой вызов token_handle().
 */
#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#endif

#include "bip39.h"
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
static void log_cb(void *ctx, uint32_t t, uint8_t cmd, uint8_t st, uint32_t id)
{
    (void)ctx; (void)t; (void)id;
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
static uint8_t g_backup[PM_MAX_FRAME];
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
    CHECK(!memfind(fl, STORE_TOTAL_BYTES, "S3cr3t-Gmail!", 13), "пароль не виден в flash");
    CHECK(!memfind(fl, STORE_TOTAL_BYTES, "Gmail", 5), "название не видно в flash");
    CHECK(!memfind(fl, STORE_TOTAL_BYTES, c.k_pc, 32), "K_pc не хранится на токене");

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
    CHECK_RC(pmc_connect(&imp), PMC_E_TOKEN - FE_DECRYPT, "ПК с чужим ключом не получает сессию");
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
    uint32_t offA = 2 * 4096, offB = (2 + STORE_SLOT_SECTORS) * 4096;
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
    CHECK(!memfind(fl, STORE_TOTAL_BYTES, "steam-test-secret", 17), "секрет Steam не виден в flash");
    CHECK(!memfind(fl, STORE_TOTAL_BYTES, "12345678901234567890", 20), "секрет TOTP не виден в flash");
    uint8_t bk[PM_MAX_FRAME];
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
    if (argc > 1 && !strcmp(argv[1], "--argon")) test_real_argon_cost();
    printf("\nИтого: %d пройдено, %d провалено\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
