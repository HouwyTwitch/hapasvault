#include "store.h"
#include "hal.h"
#include "monocypher.h"
#include <string.h>

#define CFG_MAGIC   0x46434D50u   /* "PMCF" */
#define VLT_MAGIC   0x54564D50u   /* "PMVT" */
#define CFG_VERSION 2   /* 2: + счётчик неверных паролей */

/* Заголовок слота хранилища:
 *   0  magic   u32
 *   4  seq     u32
 *   8  ct_len  u32
 *   12 nonce   24
 *   36 mac     16
 *   52 check   32  BLAKE2b(байты 0..51 || ciphertext) — целостность без ключа
 *   84 ciphertext
 */
#define H_SEQ   4
#define H_LEN   8
#define H_NONCE 12
#define H_MAC   36
#define H_CHECK 52

static uint8_t g_buf[STORE_SLOT_BYTES];   /* общий буфер сектора/слота */

static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static uint32_t get32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static uint32_t slot_off(int slot)
{
    return (STORE_CFG_SECTORS + (uint32_t)slot * STORE_SLOT_SECTORS) * 4096u;
}

/* ---------------- конфигурация ---------------- */

#define CFG_BODY_V1 106   /* 4 magic + 1 ver + 4 seq + 1 flags + 32*3 */
#define CFG_BODY    110   /* + u32 fails */

static void cfg_serialize(const pm_config *c, uint8_t *b)
{
    memset(b, 0xFF, 4096);
    put32(b, CFG_MAGIC);
    b[4] = CFG_VERSION;
    put32(b + 5, c->seq);
    b[9] = c->flags;
    memcpy(b + 10, c->token_sk, 32);
    memcpy(b + 42, c->pc_pub, 32);
    memcpy(b + 74, c->k_token, 32);
    put32(b + 106, c->fails);
    crypto_blake2b(b + CFG_BODY, 32, b, CFG_BODY);
}

static int cfg_parse(const uint8_t *b, pm_config *c)
{
    uint8_t chk[32];
    if (get32(b) != CFG_MAGIC || (b[4] != 1 && b[4] != CFG_VERSION)) return -1;
    size_t body = b[4] == 1 ? CFG_BODY_V1 : CFG_BODY;
    crypto_blake2b(chk, 32, b, body);
    if (crypto_verify32(chk, b + body) != 0) return -1;
    c->fails = b[4] == 1 ? 0 : get32(b + 106);
    c->seq = get32(b + 5);
    c->flags = b[9];
    memcpy(c->token_sk, b + 10, 32);
    memcpy(c->pc_pub, b + 42, 32);
    memcpy(c->k_token, b + 74, 32);
    return 0;
}

static int cfg_latest(pm_config *out, int *which)
{
    pm_config c;
    int found = -1;
    for (int i = 0; i < 2; i++) {
        if (hal_flash_read((uint32_t)i * 4096u, g_buf, 4096) != 0) continue;
        if (cfg_parse(g_buf, &c) != 0) continue;
        if (found < 0 || c.seq > out->seq) { *out = c; found = i; }
    }
    crypto_wipe(&c, sizeof c);
    crypto_wipe(g_buf, 4096);
    if (which) *which = found;
    return found < 0 ? -1 : 0;
}

int store_config_load(pm_config *cfg) { return cfg_latest(cfg, NULL); }

int store_config_save(pm_config *cfg)
{
    pm_config cur;
    int which = -1;
    if (cfg_latest(&cur, &which) == 0) cfg->seq = cur.seq + 1;
    else if (cfg->seq == 0) cfg->seq = 1;
    crypto_wipe(&cur, sizeof cur);
    int target = which == 0 ? 1 : 0;
    cfg_serialize(cfg, g_buf);
    int r = hal_flash_write_sectors((uint32_t)target * 4096u, g_buf, 4096);
    crypto_wipe(g_buf, 4096);
    return r;
}

/* ---------------- хранилище ---------------- */

/* Прочитать слот в g_buf и проверить целостность. */
static int slot_read_valid(int slot, uint32_t *seq)
{
    if (hal_flash_read(slot_off(slot), g_buf, STORE_SLOT_BYTES) != 0) return -1;
    if (get32(g_buf) != VLT_MAGIC) return -1;
    uint32_t len = get32(g_buf + H_LEN);
    if (len > STORE_CT_MAX) return -1;
    uint8_t chk[32];
    crypto_blake2b_ctx ctx;
    crypto_blake2b_init(&ctx, 32);
    crypto_blake2b_update(&ctx, g_buf, H_CHECK);
    crypto_blake2b_update(&ctx, g_buf + STORE_VAULT_HDR, len);
    crypto_blake2b_final(&ctx, chk);
    if (crypto_verify32(chk, g_buf + H_CHECK) != 0) return -1;
    if (seq) *seq = get32(g_buf + H_SEQ);
    return 0;
}

/* Номер свежего целого слота (или -1), его seq. g_buf после вызова не определён. */
static int vault_latest(uint32_t *seq_out)
{
    int best = -1;
    uint32_t best_seq = 0, s;
    for (int i = 0; i < 2; i++)
        if (slot_read_valid(i, &s) == 0 && (best < 0 || s > best_seq)) { best = i; best_seq = s; }
    if (seq_out) *seq_out = best_seq;
    return best;
}

int store_vault_exists(void) { return vault_latest(NULL) >= 0; }

static int write_slot_from_gbuf(int target)
{
    /* дополняем хвост 0xFF, как у стёртой flash */
    uint32_t len = get32(g_buf + H_LEN);
    memset(g_buf + STORE_VAULT_HDR + len, 0xFF, STORE_CT_MAX - len);
    return hal_flash_write_sectors(slot_off(target), g_buf, STORE_SLOT_BYTES);
}

static void finish_header(uint8_t *b, uint32_t len)
{
    crypto_blake2b_ctx ctx;
    crypto_blake2b_init(&ctx, 32);
    crypto_blake2b_update(&ctx, b, H_CHECK);
    crypto_blake2b_update(&ctx, b + STORE_VAULT_HDR, len);
    crypto_blake2b_final(&ctx, b + H_CHECK);
}

int store_vault_save(const uint8_t k_vault[32], const uint8_t *plain, size_t len)
{
    if (len > STORE_PLAIN_MAX) return -1;
    uint32_t seq = 0;
    int cur = vault_latest(&seq);
    int target = cur == 0 ? 1 : 0;

    uint8_t *b = g_buf;
    put32(b, VLT_MAGIC);
    put32(b + H_SEQ, cur < 0 ? 1 : seq + 1);
    put32(b + H_LEN, (uint32_t)len);
    hal_rng(b + H_NONCE, 24);
    /* AD = magic + seq + len: подмена заголовка ломает расшифровку */
    crypto_aead_lock(b + STORE_VAULT_HDR, b + H_MAC, k_vault, b + H_NONCE,
                     b, H_NONCE, plain, len);
    finish_header(b, (uint32_t)len);
    return write_slot_from_gbuf(target);
}

int store_vault_load(const uint8_t k_vault[32], uint8_t *plain, size_t *len)
{
    int cur = vault_latest(NULL);
    if (cur < 0) return -1;
    if (slot_read_valid(cur, NULL) != 0) return -1;
    uint32_t l = get32(g_buf + H_LEN);
    if (l > STORE_PLAIN_MAX) return -1;
    if (crypto_aead_unlock(plain, g_buf + H_MAC, k_vault, g_buf + H_NONCE, g_buf, H_NONCE,
                           g_buf + STORE_VAULT_HDR, l) != 0)
        return -2;
    *len = l;
    return 0;
}

long store_vault_raw(uint8_t *out, size_t cap)
{
    int cur = vault_latest(NULL);
    if (cur < 0 || slot_read_valid(cur, NULL) != 0) return -1;
    size_t total = STORE_VAULT_HDR + get32(g_buf + H_LEN);
    if (total > cap) return -1;
    memcpy(out, g_buf, total);
    return (long)total;
}

int store_vault_put_raw(const uint8_t *blob, size_t len)
{
    if (len < STORE_VAULT_HDR || len > STORE_SLOT_BYTES) return -1;
    uint32_t ct = get32(blob + H_LEN);
    if (get32(blob) != VLT_MAGIC || ct > STORE_PLAIN_MAX || STORE_VAULT_HDR + ct != len) return -1;
    uint32_t seq = 0;
    int cur = vault_latest(&seq);
    memcpy(g_buf, blob, len);
    /* seq входит в AD, поэтому его не меняем; но слот должен оказаться
       «свежее» существующих — стираем второй слот */
    uint8_t chk[32];
    memcpy(chk, g_buf + H_CHECK, 32);
    finish_header(g_buf, ct);
    if (crypto_verify32(chk, g_buf + H_CHECK) != 0) return -1;
    if (write_slot_from_gbuf(0) != 0) return -1;
    memset(g_buf, 0xFF, STORE_SLOT_BYTES);
    (void)cur; (void)seq;
    return hal_flash_write_sectors(slot_off(1), g_buf, STORE_SLOT_BYTES);
}

int store_wipe(void)
{
    memset(g_buf, 0xFF, sizeof g_buf);
    int r = 0;
    for (uint32_t off = 0; off < STORE_TOTAL_BYTES; off += STORE_SLOT_BYTES) {
        uint32_t n = STORE_TOTAL_BYTES - off < STORE_SLOT_BYTES ? STORE_TOTAL_BYTES - off
                                                                : STORE_SLOT_BYTES;
        r |= hal_flash_write_sectors(off, g_buf, n);
    }
    return r;
}
