/*
 * Виртуальный токен: то же ядро, что будет в прошивке RP2040,
 * но вместо USB — TCP на 127.0.0.1, вместо flash — файл.
 *
 *   pmtoken_sim [файл_flash] [порт]
 */
#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#endif

#include "hal_sim.h"
#include "pmnet.h"
#include "proto.h"
#include "token.h"
#include <stdio.h>
#include <stdlib.h>

static uint8_t g_in[PM_MAX_FRAME + 64];
static uint8_t g_out[PM_MAX_FRAME + 64];

int main(int argc, char **argv)
{
    const char *flash = argc > 1 ? argv[1] : "token_flash.bin";
    uint16_t port = (uint16_t)(argc > 2 ? atoi(argv[2]) : PM_SIM_PORT);

    setvbuf(stdout, NULL, _IONBF, 0);
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    if (pm_net_init() != 0) { fprintf(stderr, "сеть не инициализирована\n"); return 1; }
    hal_sim_open(flash);
    token_init();

    pm_sock ls = pm_net_listen(port);
    if (ls == PM_BAD_SOCK) { fprintf(stderr, "не удалось открыть порт %u\n", port); return 1; }
    printf("Виртуальный токен: flash = %s, 127.0.0.1:%u\n", flash, port);
    printf("Ctrl+C — выход. Отключение клиента = «выдернуть токен».\n");

    for (;;) {
        int r = pm_net_wait(ls, 1000);
        token_tick();
        if (r <= 0) continue;
        pm_sock s = pm_net_accept(ls);
        if (s == PM_BAD_SOCK) continue;
        printf("[usb] подключён\n");
        for (;;) {
            int w = pm_net_wait(s, 1000);
            token_tick();
            if (w < 0) break;
            if (w == 0) continue;
            long n = pm_net_recv_frame(s, g_in, sizeof g_in);
            if (n <= 0) break;
            size_t out = token_handle(g_in, (size_t)n, g_out, sizeof g_out);
            if (pm_net_send_frame(s, g_out, out) != 0) break;
        }
        pm_net_close(s);
        token_disconnect();
        printf("[usb] отключён, хранилище заблокировано\n");
    }
}
