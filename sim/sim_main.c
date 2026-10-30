/*
 * Виртуальный токен: то же ядро, что в прошивке RP2040,
 * но вместо USB — TCP на 127.0.0.1, вместо flash — файл.
 *
 *   pmtoken_sim [файл_flash] [порт]
 *   pmtoken_sim [файл_flash] --pty    (Linux/macOS: псевдотерминал вместо TCP —
 *                                      тот же путь, что у USB CDC прошивки)
 */
#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#else
#  define _XOPEN_SOURCE 600
#  define _DEFAULT_SOURCE
#  include <errno.h>
#  include <fcntl.h>
#  include <poll.h>
#  include <unistd.h>
#endif

#include "framer.h"
#include "hal.h"
#include "hal_sim.h"
#include "pmnet.h"
#include "proto.h"
#include "token.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Один буфер на запрос и ответ — как в прошивке (token_handle это допускает). */
static uint8_t g_buf[PM_MAX_FRAME + 64];

#ifndef _WIN32
/* Поток байт с псевдотерминала: сборка кадров как в firmware/main.c. */
static int run_pty(void)
{
    int m = posix_openpt(O_RDWR | O_NOCTTY);
    if (m < 0 || grantpt(m) != 0 || unlockpt(m) != 0) { perror("pty"); return 1; }
    printf("PTY %s\n", ptsname(m));
    printf("Виртуальный токен на псевдотерминале. Ctrl+C — выход.\n");

    pm_framer f;
    pm_framer_reset(&f);
    int connected = 0;
    uint64_t last_rx = 0;
    for (;;) {
        struct pollfd p = {m, POLLIN, 0};
        int r = poll(&p, 1, 200);
        token_tick();
        if (pm_framer_busy(&f) && hal_millis() - last_rx > PM_FRAMER_STALE_MS) pm_framer_reset(&f);
        if (r <= 0) continue;
        uint8_t chunk[512];
        ssize_t n = (p.revents & POLLIN) ? read(m, chunk, sizeof chunk) : -1;
        if (n <= 0) {
            /* клиент закрыл порт (= сброс DTR у USB): блокировка */
            if (connected) {
                token_disconnect();
                pm_framer_reset(&f);
                printf("[pty] отключён, хранилище заблокировано\n");
                connected = 0;
            }
            usleep(50000);
            continue;
        }
        if (!connected) { printf("[pty] подключён\n"); connected = 1; }
        last_rx = hal_millis();
        size_t off = 0;
        while (off < (size_t)n) {
            size_t used = 0;
            long len = pm_framer_feed(&f, g_buf, PM_MAX_FRAME, chunk + off, (size_t)n - off, &used);
            off += used;
            if (len <= 0) continue;
            size_t out = token_handle(g_buf, (size_t)len, g_buf, sizeof g_buf);
            uint8_t h[4];
            pm_framer_header(h, out);
            if (write(m, h, 4) != 4) break;
            for (size_t w = 0; w < out;) {
                ssize_t k = write(m, g_buf + w, out - w);
                if (k < 0 && errno == EINTR) continue;
                if (k <= 0) break;
                w += (size_t)k;
            }
        }
    }
}
#endif

int main(int argc, char **argv)
{
    const char *flash = argc > 1 ? argv[1] : "token_flash.bin";
    int pty = argc > 2 && !strcmp(argv[2], "--pty");
    uint16_t port = (uint16_t)(argc > 2 && !pty ? atoi(argv[2]) : PM_SIM_PORT);

    setvbuf(stdout, NULL, _IONBF, 0);
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    hal_sim_open(flash);
    token_init();
    if (pty) {
#ifdef _WIN32
        fprintf(stderr, "--pty есть только на Linux/macOS\n");
        return 1;
#else
        return run_pty();
#endif
    }
    if (pm_net_init() != 0) { fprintf(stderr, "сеть не инициализирована\n"); return 1; }

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
            long n = pm_net_recv_frame(s, g_buf, PM_MAX_FRAME);
            if (n <= 0) break;
            size_t out = token_handle(g_buf, (size_t)n, g_buf, sizeof g_buf);
            if (pm_net_send_frame(s, g_buf, out) != 0) break;
        }
        pm_net_close(s);
        token_disconnect();
        printf("[usb] отключён, хранилище заблокировано\n");
    }
}
