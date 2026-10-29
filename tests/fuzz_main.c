/*
 * Фаззинг токена: мутированные команды внутри действующей сессии (доходят до
 * разбора в do_command) и мусорные кадры снаружи. Запускается под ASan/UBSan:
 * любое чтение/запись за границу или UB роняет процесс.
 *
 *   pmfuzz [итераций] [seed]
 */
#include "hal_sim.h"
#include "kdf.h"
#include "monocypher.h"
#include "otp.h"
#include "pmclient.h"
#include "proto.h"
#include "session.h"
#include "token.h"
#include "wire.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint64_t g_rng = 0x9E3779B97F4A7C15ull;
static uint32_t rnd(void)
{
    g_rng ^= g_rng << 13; g_rng ^= g_rng >> 7; g_rng ^= g_rng << 17;
    return (uint32_t)(g_rng >> 11);
}

static uint8_t g_out[PM_MAX_FRAME + 64];
static long xfer(void *ctx, const uint8_t *req, size_t len, uint8_t *resp, size_t cap)
{
    (void)ctx;
    size_t n = token_handle(req, len, g_out, sizeof g_out);
    if (n > cap) return -1;
    memcpy(resp, g_out, n);
    return (long)n;
}

/* Шаблоны правильных запросов, из которых делаются мутанты. */
static size_t seed_request(uint8_t *b, size_t cap)
{
    wire_w w = {b, cap, 0, 0};
    uint8_t otp[4 + 20] = {OTP_TOTP, 1, 6, 30, '1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
                           '1', '2', '3', '4', '5', '6', '7', '8', '9', '0'};
    switch (rnd() % 10) {
    case 0: wire_put_u8(&w, CMD_INFO); break;
    case 1: wire_put_u8(&w, CMD_LIST); break;
    case 2: wire_put_u8(&w, CMD_GET); wire_put_u32(&w, rnd() % 8); break;
    case 3:
        wire_put_u8(&w, CMD_ADD);
        wire_put_str(&w, "cat"); wire_put_str(&w, "name"); wire_put_str(&w, "login");
        wire_put_u16(&w, 4); wire_put_bytes(&w, "pass", 4);
        if (rnd() & 1) { wire_put_u8(&w, sizeof otp); wire_put_bytes(&w, otp, sizeof otp); }
        break;
    case 4:
        wire_put_u8(&w, CMD_UPDATE); wire_put_u32(&w, rnd() % 8);
        wire_put_str(&w, "c"); wire_put_str(&w, "n"); wire_put_str(&w, "l");
        wire_put_u16(&w, 1); wire_put_u8(&w, 'p');
        wire_put_u8(&w, (uint8_t)(rnd() % 3));
        wire_put_u8(&w, sizeof otp); wire_put_bytes(&w, otp, sizeof otp);
        break;
    case 5: wire_put_u8(&w, CMD_OTP); wire_put_u32(&w, rnd() % 8); wire_put_u32(&w, 1700000000u + rnd() % 1000); wire_put_u32(&w, 0); break;
    case 6: wire_put_u8(&w, CMD_DELETE); wire_put_u32(&w, rnd() % 8); break;
    case 7: wire_put_u8(&w, CMD_LOG); break;
    case 8: wire_put_u8(&w, CMD_BACKUP); break;
    default: wire_put_u8(&w, (uint8_t)rnd()); break;
    }
    return w.n;
}

static size_t mutate(uint8_t *b, size_t n, size_t cap)
{
    int k = 1 + (int)(rnd() % 4);
    while (k--) {
        switch (rnd() % 6) {
        case 0: if (n) b[rnd() % n] ^= (uint8_t)(1u << (rnd() % 8)); break;   /* бит */
        case 1: if (n) b[rnd() % n] = (uint8_t)rnd(); break;                  /* байт */
        case 2: if (n > 1) n = 1 + rnd() % (n - 1); break;                    /* обрезать */
        case 3: { size_t add = rnd() % 64; if (n + add < cap) { for (size_t i = 0; i < add; i++) b[n + i] = (uint8_t)rnd(); n += add; } break; }
        case 4: if (n > 2) { size_t i = 1 + rnd() % (n - 1); b[i] = 0xFF; } break;   /* «длина» 255 */
        default: if (n > 3) { size_t i = 1 + rnd() % (n - 2); b[i] = 0xFF; b[i + 1] = 0xFF; } break;
        }
    }
    return n;
}

int main(int argc, char **argv)
{
    long iters = argc > 1 ? atol(argv[1]) : 20000;
    if (argc > 2) g_rng ^= (uint64_t)atoll(argv[2]) * 0x2545F4914F6CDD1Dull;
    hal_sim_quiet(1);
    hal_sim_open(NULL);
    token_init();

    pm_client c;
    pmc_init(&c, xfer, NULL);
    c.argon_blocks = 8;
    c.argon_passes = 1;
    if (pmc_pair(&c) || pmc_connect(&c)) { puts("setup failed"); return 1; }
    char words[512];
    pmc_setup_begin(&c, words, sizeof words);
    if (pmc_setup_commit(&c, "fuzz-password")) { puts("commit failed"); return 1; }
    uint32_t id;
    pmc_add(&c, "a", "b", "c", "d", &id);

    static uint8_t req[PM_MAX_FRAME], frame[PM_MAX_FRAME + 64], resp[PM_MAX_FRAME + 64];
    long inner = 0, outer = 0;
    for (long i = 0; i < iters; i++) {
        if (rnd() % 5 == 0) {
            /* мусор на внешнем уровне: любые типы кадров и длины */
            size_t n = rnd() % 300;
            for (size_t k = 0; k < n; k++) frame[k] = (uint8_t)rnd();
            if (n && rnd() % 2) frame[0] = (uint8_t)(1 + rnd() % 3);
            token_handle(frame, n, resp, sizeof resp);
            outer++;
        } else {
            size_t n = seed_request(req, sizeof req);
            n = mutate(req, n, sizeof req);
            if (!n) continue;
            /* зашифровать действующей сессией: мутант доходит до do_command */
            frame[0] = FR_DATA;
            size_t fl = 1 + pm_session_seal(&c.sess, frame + 1, req, n);
            size_t rl = token_handle(frame, fl, resp, sizeof resp);
            if (rl > 0 && resp[0] == FR_DATA) pm_session_open(&c.sess, resp, resp + 1, rl - 1);
            inner++;
        }
        /* держим сессию и хранилище открытыми, иначе мутанты упрутся в ST_LOCKED */
        if (!c.sess.active || i % 500 == 0) {
            if (pmc_connect(&c) != 0) { pmc_pair(&c); pmc_connect(&c); }
            pmc_unlock(&c, "fuzz-password");
        }
        if (i % 4000 == 0) hal_sim_advance_ms(61000);   /* сбросить лимиты частоты */
    }
    printf("fuzz: %ld команд в сессии, %ld внешних кадров — без падений\n", inner, outer);
    pmc_wipe(&c);
    return 0;
}
