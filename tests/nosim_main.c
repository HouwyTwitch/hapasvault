/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Проверка сборки pmapi без симулятора (-DPM_SIMULATOR=OFF): на порту симулятора
 * слушает «поддельный токен», а pmapi_attach к нему не подключается.
 */
#ifdef _WIN32
#  include <windows.h>
#endif
#include "pmapi.h"
#include "pmclient.h"
#include "pmnet.h"
#include <stdio.h>

int main(void)
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    int fail = 0;
    if (pm_net_init() != 0) { puts("FAIL: сеть"); return 1; }
    uint16_t port = 0;
    pm_sock ls = PM_BAD_SOCK;
    for (uint16_t p = PM_SIM_PORT; p < PM_SIM_PORT + 50 && ls == PM_BAD_SOCK; p++) {
        ls = pm_net_listen(p);
        port = p;
    }
    if (ls == PM_BAD_SOCK) { puts("FAIL: не удалось слушать порт"); return 1; }

    if (pmapi_has_simulator() != 0) { puts("FAIL: pmapi_has_simulator() != 0"); fail++; }
    pmapi *h = pmapi_create(NULL);
    if (!h) { puts("FAIL: pmapi_create"); return 1; }
    int rc = pmapi_attach(h, port);
    if (rc != PMC_E_NO_DEVICE) { printf("FAIL: pmapi_attach = %d, ожидалось %d\n", rc, PMC_E_NO_DEVICE); fail++; }
    if (pmapi_is_attached(h)) { puts("FAIL: транспорт подключён"); fail++; }
    /* к слушателю никто не подключался */
    if (pm_net_wait(ls, 200) != 0) { puts("FAIL: pmapi открыл соединение с портом симулятора"); fail++; }
    pmapi_destroy(h);
    pm_net_close(ls);
    printf("pmnosim: %s\n", fail ? "провал" : "симулятора нет, сокет не открывается");
    return fail ? 1 : 0;
}
