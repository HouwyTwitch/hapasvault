/*
 * Проверка настоящего токена: весь протокол по USB с замером времени.
 *
 *   pmhwtest              найти токен по USB (VID/PID)
 *   pmhwtest COM5         явный порт (Linux: /dev/ttyACM0)
 *   pmhwtest tcp:47123    симулятор или эмулятор прошивки (firmware/emu)
 *
 * Нужен ЧИСТЫЙ токен (не сопряжённый): тест сопрягает его со временным ключом,
 * создаёт хранилище, гоняет все команды и в конце стирает токен обратно.
 * Сопряжённый токен тест не трогает.
 */
#include "framer.h"
#include "otp.h"
#include "pmclient.h"
#include "pmnet.h"
#include "pmserial.h"
#include "proto.h"
#include "sha.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define TIMEOUT_MS 60000            /* эмулятор в десятки раз медленнее платы */

static pm_client g_c;
static int g_fail;

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
static double wall_ms(void) { return (double)GetTickCount64(); }
#else
static double wall_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000.0 + t.tv_nsec / 1e6;
}
#endif

/* printf("%-44s") считает байты, а не буквы */
static void label(const char *s)
{
    int n = 0;
    for (const char *p = s; *p; p++) n += ((unsigned char)*p & 0xC0) != 0x80;
    printf("  %s%*s", s, n < 44 ? 44 - n : 0, "");
}

static double g_t0;
static void start(void) { g_t0 = wall_ms(); }

static void step(const char *what, int rc, int want)
{
    double ms = wall_ms() - g_t0;
    int ok = rc == want;
    if (!ok) g_fail++;
    label(what);
    printf(" %8.0f мс  %s", ms, ok ? "ок" : "ОШИБКА");
    if (!ok) printf(" (%d: %s, ждали %d)", rc, pmc_strerror(rc), want);
    printf("\n");
}

static void check(const char *what, int cond)
{
    if (!cond) g_fail++;
    label(what);
    printf(" %8s     %s\n", "", cond ? "ок" : "ОШИБКА");
}

static int g_items;
static void count_cb(void *ctx, uint32_t id, const char *cat, const char *name, uint8_t otp)
{
    (void)ctx; (void)id; (void)cat; (void)name; (void)otp;
    g_items++;
}

/* транспорт */
static int      g_tcp;
static pm_sock  g_sock = PM_BAD_SOCK;
static pm_serial g_ser = PM_BAD_SERIAL;
static char     g_path[128];

static long xfer(void *ctx, const uint8_t *req, size_t n, uint8_t *resp, size_t cap)
{
    (void)ctx;
    return g_tcp ? pm_net_xfer(&g_sock, req, n, resp, cap) : pm_serial_xfer(&g_ser, req, n, resp, cap);
}

static int open_transport(void)
{
    if (g_tcp) {
        g_sock = pm_net_connect("127.0.0.1", (uint16_t)atoi(g_path + 4));
        if (g_sock == PM_BAD_SOCK) return -1;
        pm_net_set_timeout(g_sock, TIMEOUT_MS);
        return 0;
    }
    int busy = 0;
    g_ser = pm_serial_open(g_path, TIMEOUT_MS, &busy);
    if (g_ser == PM_BAD_SERIAL) fprintf(stderr, busy ? "порт %s занят другой программой\n" : "не открыть %s\n", g_path);
    return g_ser == PM_BAD_SERIAL ? -1 : 0;
}

static void close_transport(void)
{
    pm_net_close(g_sock);
    pm_serial_close(g_ser);
    g_sock = PM_BAD_SOCK;
    g_ser = PM_BAD_SERIAL;
}

int main(int argc, char **argv)
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    setvbuf(stdout, NULL, _IONBF, 0);
    if (pm_net_init() != 0) return 1;
    if (argc > 1) snprintf(g_path, sizeof g_path, "%s", argv[1]);
    else if (!pm_serial_find(g_path, sizeof g_path)) {
        fprintf(stderr, "токен не найден по USB (%04X:%04X). Подключите или укажите порт.\n", PM_USB_VID, PM_USB_PID);
        return 2;
    }
    g_tcp = !strncmp(g_path, "tcp:", 4);
    printf("pmhwtest: %s\n", g_path);
    if (open_transport() != 0) return 2;

    pmc_init(&g_c, xfer, NULL);
    g_c.argon_blocks = 1024;     /* Argon2 считается на ПК; здесь проверяем токен */
    g_c.argon_passes = 1;

    /* чистый ли токен: PAIR вернёт «уже сопряжён» */
    start();
    int rc = pmc_pair(&g_c);
    if (rc == PMC_E_TOKEN - FE_ALREADY_PAIRED) {
        fprintf(stderr, "Токен уже сопряжён. Тест нужен на чистом токене — данные не тронуты.\n"
                        "Стереть: HapasVault → Настройки → «Стереть токен».\n");
        return 3;
    }
    step("сопряжение (X25519)", rc, 0);
    start(); step("сессия Noise KK (4 DH на токене)", rc = pmc_connect(&g_c), 0);
    if (rc != 0) return 1;

    pmc_info_t info;
    start(); step("INFO", pmc_info(&g_c, &info), 0);
    check("версия протокола", info.proto == PM_PROTO_VERSION);

    char words[512];
    start(); step("SETUP_BEGIN (seed из RNG токена)", pmc_setup_begin(&g_c, words, sizeof words), 0);
    start(); step("SETUP_COMMIT (запись конфигурации и слота)", pmc_setup_commit(&g_c, "hw-test-pw"), 0);

    static char big[PM_MAX_PASSWORD + 1];
    memset(big, 'p', PM_MAX_PASSWORD);
    uint32_t id = 0, id_totp = 0, id_steam = 0;
    start(); step("ADD (пароль 1024 байта)", pmc_add(&g_c, "Тест", "Большая", "user", big, &id), 0);

    static const uint8_t totp[] = {OTP_TOTP, PM_SHA1, 8, 30, '1','2','3','4','5','6','7','8','9','0',
                                   '1','2','3','4','5','6','7','8','9','0'};
    static const uint8_t steam[] = {OTP_STEAM, PM_SHA1, 5, 30, 's','t','e','a','m','-','t','e','s','t',
                                    '-','s','e','c','r','e','t','-','1','2','3','4'};
    start(); step("ADD + TOTP", pmc_add_otp(&g_c, "", "TOTP", "", "x", totp, sizeof totp, &id_totp), 0);
    start(); step("ADD + Steam Guard", pmc_add_otp(&g_c, "", "Steam", "", "x", steam, sizeof steam, &id_steam), 0);

    char code[16], ref[16];
    start(); step("OTP TOTP (HMAC-SHA1 на токене)", pmc_otp(&g_c, id_totp, 1700000000, code, sizeof code, NULL, NULL), 0);
    pm_otp_code(totp, sizeof totp, 1700000000, ref);
    check("код TOTP совпал с эталоном", !strcmp(code, ref));
    start(); step("OTP Steam", pmc_otp(&g_c, id_steam, 1700000000, code, sizeof code, NULL, NULL), 0);
    check("код Steam = T7WDC", !strcmp(code, "T7WDC"));

    char login[300], pw[PM_MAX_PASSWORD + 1];
    start(); step("GET (расшифровка на токене)", pmc_get(&g_c, id, login, sizeof login, pw, sizeof pw), 0);
    check("пароль цел", !strcmp(pw, big) && !strcmp(login, "user"));
    start(); step("UPDATE", pmc_update(&g_c, id, "Тест", "Большая", "user2", "short", PMC_OTP_KEEP, NULL, 0), 0);
    pmc_get(&g_c, id, login, sizeof login, pw, sizeof pw);
    check("изменение на месте", !strcmp(login, "user2") && !strcmp(pw, "short"));
    g_items = 0;
    start(); step("LIST", pmc_list(&g_c, count_cb, NULL), 0);
    check("3 записи", g_items == 3);
    start(); step("DELETE", pmc_delete(&g_c, id_totp), 0);

    static uint8_t backup[PM_MAX_FRAME];
    size_t blen = 0;
    start(); step("BACKUP", pmc_backup(&g_c, backup, sizeof backup, &blen), 0);
    check("копия не пустая", blen > 100);

    start(); step("LOCK", pmc_lock(&g_c), 0);
    start(); step("UNLOCK с неверным паролем", pmc_unlock(&g_c, "wrong"), ST_WRONG_KEY);
    start(); step("UNLOCK", pmc_unlock(&g_c, "hw-test-pw"), 0);

    /* закрыли порт = сброс DTR: токен обязан заблокироваться */
    close_transport();
    if (open_transport() != 0) return 1;
    start(); step("переподключение: новая сессия", pmc_connect(&g_c), 0);
    pmc_info(&g_c, &info);
    check("после отключения хранилище закрыто", info.setup_done && !info.unlocked);
    start(); step("UNLOCK после переподключения", pmc_unlock(&g_c, "hw-test-pw"), 0);
    pmc_info(&g_c, &info);
    check("записи на месте (flash)", info.count == 2);

    start(); step("FACTORY_RESET (токен снова чистый)", pmc_factory_reset(&g_c), 0);
    close_transport();
    pmc_wipe(&g_c);

    printf(g_fail ? "\nНЕ ПРОЙДЕНО: %d\n" : "\nВсё в порядке.\n", g_fail);
    return g_fail ? 1 : 0;
}
