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
static void count_cb(void *ctx, uint32_t id, const char *cat, const char *name)
{
    (void)ctx; (void)id; (void)cat;
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
    if (argc > 1 && !strcmp(argv[1], "--argon")) test_real_argon_cost();
    printf("\nИтого: %d пройдено, %d провалено\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
