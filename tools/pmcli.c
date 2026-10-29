/*
 * Консольный клиент для проверки протокола (замена GUI на время разработки).
 *
 *   pmcli [файл_идентичности] [порт]
 *
 * Работает с виртуальным токеном (pmtoken_sim). Одна сессия на запуск:
 * выход из программы = отключение = блокировка хранилища.
 */
#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <conio.h>
#else
#  define _POSIX_C_SOURCE 200809L
#  include <termios.h>
#  include <unistd.h>
#endif

#include "pmclient.h"
#include "pmnet.h"
#include "monocypher.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static pm_client g_c;
static const char *g_idfile;

static void read_line(const char *prompt, char *buf, size_t cap)
{
    printf("%s", prompt);
    fflush(stdout);
    if (!fgets(buf, (int)cap, stdin)) { buf[0] = 0; return; }
    buf[strcspn(buf, "\r\n")] = 0;
}

static void read_secret(const char *prompt, char *buf, size_t cap)
{
    printf("%s", prompt);
    fflush(stdout);
#ifdef _WIN32
    size_t n = 0;
    for (;;) {
        int ch = _getch();
        if (ch == '\r' || ch == '\n') break;
        if (ch == 8) { if (n) n--; continue; }
        if (n + 1 < cap) buf[n++] = (char)ch;
    }
    buf[n] = 0;
    printf("\n");
#else
    struct termios old, quiet;
    int tty = tcgetattr(STDIN_FILENO, &old) == 0;
    if (tty) { quiet = old; quiet.c_lflag &= (tcflag_t)~ECHO; tcsetattr(STDIN_FILENO, TCSANOW, &quiet); }
    if (!fgets(buf, (int)cap, stdin)) buf[0] = 0;
    buf[strcspn(buf, "\r\n")] = 0;
    if (tty) { tcsetattr(STDIN_FILENO, TCSANOW, &old); printf("\n"); }
#endif
}

static int report(int rc)
{
    if (rc != 0) printf("  ошибка: %s (%d)\n", pmc_strerror(rc), rc);
    return rc;
}

static void save_id(void)
{
    if (report(pmc_identity_save(&g_c, g_idfile)) == 0)
        printf("  данные ПК сохранены в %s\n", g_idfile);
}

static void on_item(void *ctx, uint32_t id, const char *cat, const char *name)
{
    (void)ctx;
    printf("  %4u  [%s] %s\n", id, cat, name);
}

static const char *cmd_name(uint8_t c)
{
    switch (c) {
    case CMD_SETUP_COMMIT: return "setup";
    case CMD_RESTORE: return "restore";
    case CMD_UNLOCK: return "unlock";
    case CMD_GET: return "get";
    case CMD_ADD: return "add";
    case CMD_DELETE: return "delete";
    case CMD_BACKUP: return "backup";
    default: return "?";
    }
}

static void on_log(void *ctx, uint32_t t, uint8_t cmd, uint8_t st, uint32_t id)
{
    (void)ctx;
    printf("  +%6us  %-8s id=%-4u %s\n", t, cmd_name(cmd), id, st ? pmc_strerror(st) : "ok");
}

static int confirm_words(const char *words)
{
    /* Проверяем 3 случайных слова из 24, чтобы убедиться, что фразу записали */
    char copy[512], *w[24];
    int n = 0;
    strncpy(copy, words, sizeof copy - 1);
    copy[sizeof copy - 1] = 0;
    for (char *t = strtok(copy, " "); t && n < 24; t = strtok(NULL, " ")) w[n++] = t;
    srand((unsigned)time(NULL));   /* выбор слов для проверки — не секрет */
    int idx[3] = {rand() % 8, 8 + rand() % 8, 16 + rand() % 8};
    for (int i = 0; i < 3; i++) {
        char prompt[64], ans[64];
        snprintf(prompt, sizeof prompt, "  слово №%d: ", idx[i] + 1);
        read_line(prompt, ans, sizeof ans);
        if (strcmp(ans, w[idx[i]]) != 0) return 0;
    }
    return 1;
}

static void help(void)
{
    printf(
        "Команды:\n"
        "  pair            сопрячь этот ПК с новым токеном\n"
        "  setup           первичная настройка: 24 слова + мастер-пароль\n"
        "  restore [файл]  восстановить из 24 слов (+ файл бэкапа)\n"
        "  unlock / lock   открыть / закрыть хранилище\n"
        "  list            список записей (без паролей)\n"
        "  get <id>        логин и пароль одной записи\n"
        "  add             добавить запись\n"
        "  del <id>        удалить запись\n"
        "  backup <файл>   сохранить зашифрованную копию хранилища\n"
        "  log             журнал операций токена\n"
        "  info            состояние токена\n"
        "  reset           полный сброс токена\n"
        "  quit\n");
}

int main(int argc, char **argv)
{
    g_idfile = argc > 1 ? argv[1] : "pmclient.id";
    uint16_t port = (uint16_t)(argc > 2 ? atoi(argv[2]) : PM_SIM_PORT);
    setvbuf(stdout, NULL, _IONBF, 0);
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif

    if (pm_net_init() != 0) return 1;
    pm_sock s = pm_net_connect("127.0.0.1", port);
    if (s == PM_BAD_SOCK) {
        printf("Токен не найден на 127.0.0.1:%u — запустите pmtoken_sim\n", port);
        return 1;
    }
    pmc_init(&g_c, pm_net_xfer, &s);
    if (getenv("PM_ARGON_KIB")) g_c.argon_blocks = (uint32_t)atoi(getenv("PM_ARGON_KIB"));

    if (pmc_identity_load(&g_c, g_idfile) == 0 && g_c.paired) {
        printf("Найдены данные ПК (%s), устанавливаю сессию...\n", g_idfile);
        if (report(pmc_connect(&g_c)) == 0) printf("Сессия установлена.\n");
    } else {
        printf("Этот ПК ещё не сопряжён. Команда: pair\n");
    }
    help();

    char line[512];
    for (;;) {
        read_line("> ", line, sizeof line);
        if (feof(stdin)) break;
        char *cmd = strtok(line, " ");
        char *arg = strtok(NULL, " ");
        if (!cmd) continue;

        if (!strcmp(cmd, "quit") || !strcmp(cmd, "exit")) break;
        else if (!strcmp(cmd, "help")) help();
        else if (!strcmp(cmd, "pair")) {
            if (report(pmc_pair(&g_c)) == 0) {
                printf("  Сопряжено.\n");
                save_id();
                report(pmc_connect(&g_c));
            }
        }
        else if (!strcmp(cmd, "info")) {
            pmc_info_t i;
            if (report(pmc_info(&g_c, &i)) == 0)
                printf("  настроен: %s, открыт: %s, записей: %u, протокол v%u, аптайм %us\n",
                       i.setup_done ? "да" : "нет", i.unlocked ? "да" : "нет", i.count,
                       i.proto, i.uptime_s);
        }
        else if (!strcmp(cmd, "setup")) {
            char words[512], p1[256], p2[256];
            if (report(pmc_setup_begin(&g_c, words, sizeof words)) != 0) continue;
            printf("\n  ЗАПИШИТЕ фразу восстановления (24 слова) на бумагу:\n\n");
            int n = 1;
            for (char *t = strtok(strcpy(p1, words), " "); t; t = strtok(NULL, " "), n++)
                printf("  %2d. %-10s%s", n, t, n % 4 == 0 ? "\n" : "");
            printf("\n  Проверка записи:\n");
            if (!confirm_words(words)) { printf("  неверно, настройка отменена\n"); continue; }
            crypto_wipe(words, sizeof words);
            for (;;) {
                read_secret("  мастер-пароль: ", p1, sizeof p1);
                read_secret("  ещё раз: ", p2, sizeof p2);
                if (strcmp(p1, p2) == 0 && strlen(p1) >= 8) break;
                printf("  не совпадает или короче 8 символов\n");
            }
            printf("  Argon2id...\n");
            if (report(pmc_setup_commit(&g_c, p1)) == 0) {
                printf("  Готово, хранилище создано и открыто.\n");
                save_id();
            }
            crypto_wipe(p1, sizeof p1); crypto_wipe(p2, sizeof p2);
        }
        else if (!strcmp(cmd, "restore")) {
            static uint8_t blob[PM_MAX_FRAME];
            size_t blen = 0;
            if (arg) {
                FILE *f = fopen(arg, "rb");
                if (!f) { printf("  нет файла %s\n", arg); continue; }
                blen = fread(blob, 1, sizeof blob, f);
                fclose(f);
            }
            char words[512], pw[256];
            read_line("  24 слова через пробел: ", words, sizeof words);
            read_secret("  мастер-пароль: ", pw, sizeof pw);
            if (report(pmc_restore(&g_c, words, pw, blob, blen)) == 0) {
                printf("  Восстановлено.\n");
                save_id();
            }
            crypto_wipe(words, sizeof words); crypto_wipe(pw, sizeof pw);
        }
        else if (!strcmp(cmd, "unlock")) {
            char pw[256];
            read_secret("  мастер-пароль: ", pw, sizeof pw);
            if (report(pmc_unlock(&g_c, pw)) == 0) printf("  Открыто.\n");
            crypto_wipe(pw, sizeof pw);
        }
        else if (!strcmp(cmd, "lock")) { if (report(pmc_lock(&g_c)) == 0) printf("  Закрыто.\n"); }
        else if (!strcmp(cmd, "list")) report(pmc_list(&g_c, on_item, NULL));
        else if (!strcmp(cmd, "get") && arg) {
            char login[256], pw[PM_MAX_PASSWORD + 1];
            if (report(pmc_get(&g_c, (uint32_t)atoi(arg), login, sizeof login, pw, sizeof pw)) == 0)
                printf("  логин:  %s\n  пароль: %s\n", login, pw);
            crypto_wipe(pw, sizeof pw);
        }
        else if (!strcmp(cmd, "add")) {
            char cat[256], name[256], login[256], pw[PM_MAX_PASSWORD + 1];
            uint32_t id;
            read_line("  категория: ", cat, sizeof cat);
            read_line("  название: ", name, sizeof name);
            read_line("  логин: ", login, sizeof login);
            read_secret("  пароль: ", pw, sizeof pw);
            if (report(pmc_add(&g_c, cat, name, login, pw, &id)) == 0) printf("  добавлено, id=%u\n", id);
            crypto_wipe(pw, sizeof pw);
        }
        else if (!strcmp(cmd, "del") && arg) { if (report(pmc_delete(&g_c, (uint32_t)atoi(arg))) == 0) printf("  удалено\n"); }
        else if (!strcmp(cmd, "log")) report(pmc_log(&g_c, on_log, NULL));
        else if (!strcmp(cmd, "backup") && arg) {
            static uint8_t blob[PM_MAX_FRAME];
            size_t n;
            if (report(pmc_backup(&g_c, blob, sizeof blob, &n)) == 0) {
                FILE *f = fopen(arg, "wb");
                if (f && fwrite(blob, 1, n, f) == n) printf("  %zu байт записано в %s (зашифровано)\n", n, arg);
                else printf("  не удалось записать %s\n", arg);
                if (f) fclose(f);
            }
        }
        else if (!strcmp(cmd, "reset")) {
            char yes[16];
            read_line("  Стереть ВСЁ на токене? Введите YES: ", yes, sizeof yes);
            if (!strcmp(yes, "YES") && report(pmc_factory_reset(&g_c)) == 0) {
                printf("  Токен сброшен. Сопряжение удалено.\n");
                save_id();
            }
        }
        else printf("  ? (help — список команд)\n");
    }
    pm_net_close(s);
    pmc_wipe(&g_c);
    return 0;
}
