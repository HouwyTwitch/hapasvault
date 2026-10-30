/* HAL для ПК: flash = файл, RNG = ОС, время = монотонные часы. */
#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <bcrypt.h>
#else
#  define _POSIX_C_SOURCE 200809L
#  include <time.h>
#endif

#include "hal.h"
#include "hal_sim.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SIM_FLASH_SIZE (256u * 1024u)

static uint8_t     g_flash[SIM_FLASH_SIZE];
static const char *g_path;
static uint64_t    g_offset_ms;
static int         g_quiet;

static void persist(uint32_t off, uint32_t len)
{
    if (!g_path) return;
    FILE *f = fopen(g_path, "r+b");
    if (!f) f = fopen(g_path, "w+b");
    if (!f) { perror("flash file"); return; }
    if (fseek(f, (long)off, SEEK_SET) == 0) fwrite(g_flash + off, 1, len, f);
    fclose(f);
}

int hal_sim_open(const char *path)
{
    memset(g_flash, 0xFF, sizeof g_flash);
    g_path = path;
    if (!path) return 0;
    FILE *f = fopen(path, "rb");
    if (f) {
        size_t n = fread(g_flash, 1, sizeof g_flash, f);
        (void)n;
        fclose(f);
    } else {
        persist(0, SIM_FLASH_SIZE);
    }
    return 0;
}

uint8_t *hal_sim_flash(void) { return g_flash; }
void hal_sim_erase(void) { memset(g_flash, 0xFF, sizeof g_flash); persist(0, SIM_FLASH_SIZE); }
void hal_sim_advance_ms(uint64_t ms) { g_offset_ms += ms; }
void hal_sim_quiet(int q) { g_quiet = q; }

uint32_t hal_flash_size(void) { return SIM_FLASH_SIZE; }

int hal_flash_read(uint32_t off, void *buf, uint32_t len)
{
    if (off > SIM_FLASH_SIZE || len > SIM_FLASH_SIZE - off) return -1;
    memcpy(buf, g_flash + off, len);
    return 0;
}

int hal_flash_write_sectors(uint32_t off, const void *buf, uint32_t len)
{
    if (off % HAL_FLASH_SECTOR || len % HAL_FLASH_SECTOR) return -1;
    if (off > SIM_FLASH_SIZE || len > SIM_FLASH_SIZE - off) return -1;
    memcpy(g_flash + off, buf, len);
    persist(off, len);
    return 0;
}

void hal_rng(void *buf, size_t len)
{
#ifdef _WIN32
    if (BCryptGenRandom(NULL, (PUCHAR)buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) abort();
#else
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f || fread(buf, 1, len, f) != len) abort();
    fclose(f);
#endif
}

static uint64_t os_millis(void)
{
#ifdef _WIN32
    return (uint64_t)GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
#endif
}

/* как на плате: отсчёт от «включения» (первого вызова), а не от загрузки ОС */
uint64_t hal_millis(void)
{
    static uint64_t base;
    if (!base) base = os_millis() - 1;
    return os_millis() - base + g_offset_ms;
}

void hal_led(hal_led_t s)
{
    static const char *names[] = {"ожидание", "сессия", "открыто", "ОШИБКА"};
    static int last = -1;
    if (g_quiet || (int)s == last) return;
    last = (int)s;
    printf("[светодиод] %s\n", names[s]);
    fflush(stdout);
}
