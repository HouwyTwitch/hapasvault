/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "store.h"
#include "hal.h"
#include "monocypher.h"
#include <string.h>

#define CFG_MAGIC   0x46434D50u   /* "PMCF" */
#define VLT_MAGIC   0x54564D50u   /* "PMVT" */
#define CFG_VERSION 4   /* 4: до 4 привязанных ПК с именами; 3: размер слота; 2: счётчик неверных паролей */

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

/* Старая разметка внутри последних 80 КБ: конфигурация 0..1, слоты 2..10 и 11..19 */
#define LEGACY_SLOT_BYTES (9u * STORE_SECTOR)

static uint8_t  g_sec[STORE_SECTOR];   /* буфер одного сектора: всё остальное — в буфере токена */
static uint32_t g_slot;                /* размер слота S, байт (кратно сектору) */
static size_t   g_cap;                 /* ёмкость: байт открытого текста */
static int      g_cur = -1;            /* свежий целый слот (кэш; -1 — пересчитать) */
static uint32_t g_cur_seq, g_cur_len;

static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static uint32_t get32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static uint32_t region(void) { return hal_flash_size(); }
static uint32_t cfg_off(int i) { return region() - STORE_CFG_BYTES + (uint32_t)i * STORE_SECTOR; }
static uint32_t slot_off(int slot) { return region() - STORE_CFG_BYTES - (2u - (uint32_t)slot) * g_slot; }
static uint32_t legacy_base(void) { return region() - STORE_LEGACY_BYTES; }

size_t store_capacity(void) { return g_cap; }
uint32_t store_slot_offset(int slot) { return slot_off(slot); }

/* ---------------- конфигурация ---------------- */

/* v1..v3: [magic][ver][seq][flags][token_sk 32][pc_pub 32][k_token 32][fails][slot]
 * v4:     [magic][ver][seq][flags][token_sk 32][k_token 32][fails][slot][n][4 × (pub 32, label 32)] */
#define CFG_BODY_V1 106   /* 4 magic + 1 ver + 4 seq + 1 flags + 32*3 */
#define CFG_BODY_V2 110   /* + u32 fails */
#define CFG_BODY_V3 114   /* + u32 размер слота */
#define CFG_PC_AT   83
#define CFG_BODY    (CFG_PC_AT + STORE_MAX_PCS * (32 + STORE_PC_LABEL))

static void cfg_serialize(const pm_config *c, uint8_t *b)
{
    memset(b, 0xFF, STORE_SECTOR);
    put32(b, CFG_MAGIC);
    b[4] = CFG_VERSION;
    put32(b + 5, c->seq);
    b[9] = c->flags & (uint8_t)~CFG_PAIRED;
    memcpy(b + 10, c->token_sk, 32);
    memcpy(b + 42, c->k_token, 32);
    put32(b + 74, c->fails);
    put32(b + 78, g_slot);
    b[82] = c->pc_count;
    for (int i = 0; i < STORE_MAX_PCS; i++) {
        uint8_t *e = b + CFG_PC_AT + i * (32 + STORE_PC_LABEL);
        memset(e, 0, 32 + STORE_PC_LABEL);
        if (i < c->pc_count) {
            memcpy(e, c->pcs[i].pub, 32);
            memcpy(e + 32, c->pcs[i].label, STORE_PC_LABEL);
            e[32 + STORE_PC_LABEL - 1] = 0;
        }
    }
    crypto_blake2b(b + CFG_BODY, 32, b, CFG_BODY);
}

/* legacy: 1 — разобрать старые версии (1, 2) из старой разметки; 0 — новую (3 — прошлый
 * выпуск, 4 — текущий). Единственный ПК старых версий становится pcs[0]. */
static int cfg_parse(const uint8_t *b, pm_config *c, int legacy, uint32_t *slot)
{
    uint8_t chk[32];
    uint8_t v = b[4];
    if (get32(b) != CFG_MAGIC) return -1;
    if (legacy ? (v != 1 && v != 2) : (v != 3 && v != CFG_VERSION)) return -1;
    size_t body = v == 1 ? CFG_BODY_V1 : v == 2 ? CFG_BODY_V2 : v == 3 ? CFG_BODY_V3 : CFG_BODY;
    crypto_blake2b(chk, 32, b, body);
    if (crypto_verify32(chk, b + body) != 0) return -1;
    memset(c, 0, sizeof *c);
    c->seq = get32(b + 5);
    c->flags = b[9];
    memcpy(c->token_sk, b + 10, 32);
    if (v < 4) {
        c->fails = v == 1 ? 0 : get32(b + 106);
        memcpy(c->k_token, b + 74, 32);
        if (c->flags & CFG_PAIRED) {
            memcpy(c->pcs[0].pub, b + 42, 32);
            c->pc_count = 1;
        }
        c->flags &= (uint8_t)~CFG_PAIRED;
        if (slot) *slot = v == 3 ? get32(b + 110) : 0;
        return 0;
    }
    memcpy(c->k_token, b + 42, 32);
    c->fails = get32(b + 74);
    if (slot) *slot = get32(b + 78);
    c->pc_count = b[82] <= STORE_MAX_PCS ? b[82] : 0;
    for (int i = 0; i < c->pc_count; i++) {
        const uint8_t *e = b + CFG_PC_AT + i * (32 + STORE_PC_LABEL);
        memcpy(c->pcs[i].pub, e, 32);
        memcpy(c->pcs[i].label, e + 32, STORE_PC_LABEL);
        c->pcs[i].label[STORE_PC_LABEL - 1] = 0;
    }
    return 0;
}

static int cfg_latest_at(uint32_t base_a, uint32_t base_b, int legacy, pm_config *out, int *which, uint32_t *slot)
{
    pm_config c;
    uint32_t s = 0;
    int found = -1;
    for (int i = 0; i < 2; i++) {
        if (hal_flash_read(i ? base_b : base_a, g_sec, STORE_SECTOR) != 0) continue;
        if (cfg_parse(g_sec, &c, legacy, &s) != 0) continue;
        if (found < 0 || c.seq > out->seq) {
            *out = c;
            found = i;
            if (slot) *slot = s;
        }
    }
    crypto_wipe(&c, sizeof c);
    crypto_wipe(g_sec, sizeof g_sec);
    if (which) *which = found;
    return found < 0 ? -1 : 0;
}

static int cfg_latest(pm_config *out, int *which, uint32_t *slot)
{
    return cfg_latest_at(cfg_off(0), cfg_off(1), 0, out, which, slot);
}

int store_config_load(pm_config *cfg) { return cfg_latest(cfg, NULL, NULL); }

static int cfg_write(int target, const pm_config *cfg)
{
    cfg_serialize(cfg, g_sec);
    int r = hal_flash_write_sectors(cfg_off(target), g_sec, STORE_SECTOR);
    crypto_wipe(g_sec, sizeof g_sec);
    return r;
}

int store_config_save(pm_config *cfg)
{
    pm_config cur;
    int which = -1;
    if (cfg_latest(&cur, &which, NULL) == 0) cfg->seq = cur.seq + 1;
    else if (cfg->seq == 0) cfg->seq = 1;
    crypto_wipe(&cur, sizeof cur);
    return cfg_write(which == 0 ? 1 : 0, cfg);
}

/* ---------------- проверка целостности слота (без ключа, посекторно) ---------------- */

/* Проверить копию по смещению off с размером слота slot_bytes. 0 = целая. */
static int blob_check(uint32_t off, uint32_t slot_bytes, uint32_t *seq, uint32_t *len_out)
{
    uint8_t hdr[STORE_VAULT_HDR];
    if (hal_flash_read(off, hdr, sizeof hdr) != 0 || get32(hdr) != VLT_MAGIC) return -1;
    uint32_t len = get32(hdr + H_LEN);
    if (len > slot_bytes - STORE_VAULT_HDR) return -1;
    crypto_blake2b_ctx ctx;
    crypto_blake2b_init(&ctx, 32);
    crypto_blake2b_update(&ctx, hdr, H_CHECK);
    for (uint32_t done = 0; done < len;) {
        uint32_t n = len - done < STORE_SECTOR ? len - done : STORE_SECTOR;
        if (hal_flash_read(off + STORE_VAULT_HDR + done, g_sec, n) != 0) return -1;
        crypto_blake2b_update(&ctx, g_sec, n);
        done += n;
    }
    uint8_t chk[32];
    crypto_blake2b_final(&ctx, chk);
    if (crypto_verify32(chk, hdr + H_CHECK) != 0) return -1;
    if (seq) *seq = get32(hdr + H_SEQ);
    if (len_out) *len_out = len;
    return 0;
}

/* Свежий целый слот (или -1). */
static int vault_latest(void)
{
    if (g_cur >= 0) return g_cur;
    if (!g_slot) return -1;
    uint32_t s, l, best_seq = 0, best_len = 0;
    int best = -1;
    for (int i = 0; i < 2; i++)
        if (blob_check(slot_off(i), g_slot, &s, &l) == 0 && (best < 0 || s > best_seq)) {
            best = i;
            best_seq = s;
            best_len = l;
        }
    g_cur = best;
    g_cur_seq = best_seq;
    g_cur_len = best_len;
    return best;
}

int store_vault_exists(void) { return vault_latest() >= 0; }

/* Записать [hdr][ct len] в слот посекторно через g_sec; хвост слота не трогаем
 * (там старый шифротекст, его отрезает длина в заголовке). */
static int write_blob(uint32_t off, const uint8_t *hdr, const uint8_t *ct, uint32_t len)
{
    uint32_t total = STORE_VAULT_HDR + len, done = 0;
    int r = 0;
    while (done < total && r == 0) {
        memset(g_sec, 0xFF, sizeof g_sec);
        for (uint32_t i = 0; i < STORE_SECTOR && done + i < total; i++) {
            uint32_t p = done + i;
            g_sec[i] = p < STORE_VAULT_HDR ? hdr[p] : ct[p - STORE_VAULT_HDR];
        }
        r = hal_flash_write_sectors(off + done, g_sec, STORE_SECTOR);
        done += STORE_SECTOR;
    }
    crypto_wipe(g_sec, sizeof g_sec);
    return r;
}

static void finish_header(uint8_t *hdr, const uint8_t *ct, uint32_t len)
{
    crypto_blake2b_ctx ctx;
    crypto_blake2b_init(&ctx, 32);
    crypto_blake2b_update(&ctx, hdr, H_CHECK);
    crypto_blake2b_update(&ctx, ct, len);
    crypto_blake2b_final(&ctx, hdr + H_CHECK);
}

int store_vault_save(const uint8_t k_vault[32], uint8_t *plain, size_t len)
{
    if (len > g_cap) return -1;
    int cur = vault_latest();
    int target = cur == 0 ? 1 : 0;
    uint32_t seq = cur < 0 ? 1 : g_cur_seq + 1;

    uint8_t hdr[STORE_VAULT_HDR];
    put32(hdr, VLT_MAGIC);
    put32(hdr + H_SEQ, seq);
    put32(hdr + H_LEN, (uint32_t)len);
    hal_rng(hdr + H_NONCE, 24);
    /* шифруем на месте: RAM токена — один буфер на хранилище.
       AD = magic + seq + len: подмена заголовка ломает расшифровку */
    crypto_aead_lock(plain, hdr + H_MAC, k_vault, hdr + H_NONCE, hdr, H_NONCE, plain, len);
    finish_header(hdr, plain, (uint32_t)len);
    int r = write_blob(slot_off(target), hdr, plain, (uint32_t)len);
    /* и обратно: открытый текст нужен дальше, MAC только что посчитан нами */
    int back = crypto_aead_unlock(plain, hdr + H_MAC, k_vault, hdr + H_NONCE, hdr, H_NONCE, plain, len);
    if (r == 0 && back == 0) {
        g_cur = target;
        g_cur_seq = seq;
        g_cur_len = (uint32_t)len;
    } else {
        g_cur = -1;
    }
    return r == 0 && back == 0 ? 0 : -1;
}

int store_vault_load(const uint8_t k_vault[32], uint8_t *plain, size_t cap, size_t *len)
{
    int cur = vault_latest();
    if (cur < 0) return -1;
    uint8_t hdr[STORE_VAULT_HDR];
    uint32_t off = slot_off(cur);
    if (hal_flash_read(off, hdr, sizeof hdr) != 0) return -1;
    uint32_t l = get32(hdr + H_LEN);
    if (l > cap || l > g_cap) return -1;
    if (hal_flash_read(off + STORE_VAULT_HDR, plain, l) != 0) return -1;
    /* целостность проверена в vault_latest, но flash могли подменить между чтениями */
    uint8_t chk[32];
    memcpy(chk, hdr + H_CHECK, 32);
    finish_header(hdr, plain, l);
    if (crypto_verify32(chk, hdr + H_CHECK) != 0) { g_cur = -1; crypto_wipe(plain, l); return -1; }
    if (crypto_aead_unlock(plain, hdr + H_MAC, k_vault, hdr + H_NONCE, hdr, H_NONCE, plain, l) != 0) {
        crypto_wipe(plain, l);
        return -2;
    }
    *len = l;
    return 0;
}

long store_vault_raw(size_t off, uint8_t *out, size_t cap, size_t *total)
{
    int cur = vault_latest();
    if (cur < 0) return -1;
    size_t all = STORE_VAULT_HDR + g_cur_len;
    *total = all;
    if (off > all) return -1;
    size_t n = all - off < cap ? all - off : cap;
    if (hal_flash_read(slot_off(cur) + (uint32_t)off, out, (uint32_t)n) != 0) return -1;
    return (long)n;
}

int store_vault_put_raw(const uint8_t *blob, size_t len)
{
    if (len < STORE_VAULT_HDR || len - STORE_VAULT_HDR > g_cap) return -1;
    uint32_t ct = get32(blob + H_LEN);
    if (get32(blob) != VLT_MAGIC || STORE_VAULT_HDR + ct != len) return -1;
    uint8_t hdr[STORE_VAULT_HDR];
    memcpy(hdr, blob, sizeof hdr);
    finish_header(hdr, blob + STORE_VAULT_HDR, ct);
    if (crypto_verify32(hdr + H_CHECK, blob + H_CHECK) != 0) return -1;
    /* seq входит в AD, поэтому его не меняем: копия кладётся в слот A, слот B гасится */
    if (write_blob(slot_off(0), blob, blob + STORE_VAULT_HDR, ct) != 0) return -1;
    memset(g_sec, 0xFF, sizeof g_sec);
    int r = hal_flash_write_sectors(slot_off(1), g_sec, STORE_SECTOR);
    g_cur = -1;
    return r;
}

int store_wipe(void)
{
    /* конфигурация (с K_token) и заголовки слотов — обеих разметок. Шифротекст
       без K_token не расшифровать даже с паролем и K_pc, а стирать сотни КБ —
       секунды: стираем только то, что делает токен чистым */
    memset(g_sec, 0xFF, sizeof g_sec);
    int r = 0;
    r |= hal_flash_write_sectors(cfg_off(0), g_sec, STORE_SECTOR);
    r |= hal_flash_write_sectors(cfg_off(1), g_sec, STORE_SECTOR);
    if (g_slot) {
        r |= hal_flash_write_sectors(slot_off(0), g_sec, STORE_SECTOR);
        r |= hal_flash_write_sectors(slot_off(1), g_sec, STORE_SECTOR);
    }
    uint32_t base = legacy_base();
    r |= hal_flash_write_sectors(base, g_sec, STORE_SECTOR);
    r |= hal_flash_write_sectors(base + STORE_SECTOR, g_sec, STORE_SECTOR);
    r |= hal_flash_write_sectors(base + STORE_CFG_BYTES, g_sec, STORE_SECTOR);
    r |= hal_flash_write_sectors(base + STORE_CFG_BYTES + LEGACY_SLOT_BYTES, g_sec, STORE_SECTOR);
    g_cur = -1;
    return r;
}

/* ---------------- разметка: выбор и перенос старой ---------------- */

static uint32_t choose_slot(size_t buf_cap)
{
    /* слот вмещает заголовок и весь буфер (восстановление кладёт туда бэкап целиком) */
    uint32_t want = (uint32_t)((buf_cap + STORE_SECTOR - 1) / STORE_SECTOR * STORE_SECTOR);
    uint32_t avail = region() > STORE_CFG_BYTES ? (region() - STORE_CFG_BYTES) / 2u / STORE_SECTOR * STORE_SECTOR : 0;
    return want < avail ? want : avail;
}

/* Перенос из последних 80 КБ: копия хранилища — как есть (seq и шифротекст не
 * меняются), затем конфигурация на новое место. Выдернули посередине — старая
 * разметка цела до записи новой конфигурации, перенос повторится. */
static int migrate_legacy(const pm_config *old, uint8_t *buf, size_t buf_cap)
{
    uint32_t base = legacy_base();
    uint32_t s, l, best_seq = 0, best_len = 0;
    int best = -1;
    for (int i = 0; i < 2; i++) {
        uint32_t off = base + STORE_CFG_BYTES + (uint32_t)i * LEGACY_SLOT_BYTES;
        if (blob_check(off, LEGACY_SLOT_BYTES, &s, &l) == 0 && (best < 0 || s > best_seq)) {
            best = i; best_seq = s; best_len = l;
        }
    }
    /* новый слот A не должен задевать старую область: иначе только конфигурация */
    if (best >= 0 && slot_off(0) + g_slot <= base) {
        uint32_t total = STORE_VAULT_HDR + best_len;
        if (total > buf_cap) return -1;
        if (hal_flash_read(base + STORE_CFG_BYTES + (uint32_t)best * LEGACY_SLOT_BYTES, buf, total) != 0) return -1;
        if (write_blob(slot_off(0), buf, buf + STORE_VAULT_HDR, best_len) != 0) return -1;
        memset(g_sec, 0xFF, sizeof g_sec);
        if (hal_flash_write_sectors(slot_off(1), g_sec, STORE_SECTOR) != 0) return -1;
        crypto_wipe(buf, total);
    } else if (best >= 0) {
        return -1;   /* flash слишком мала для новой разметки: оставляем как было */
    }
    pm_config c = *old;
    c.seq += 1;
    int r = cfg_write(0, &c) | cfg_write(1, &c);
    crypto_wipe(&c, sizeof c);
    return r;
}

size_t store_init(uint8_t *buf, size_t buf_cap)
{
    pm_config c;
    uint32_t slot = 0;
    g_cur = -1;
    if (cfg_latest(&c, NULL, &slot) == 0 && slot >= STORE_SECTOR && slot % STORE_SECTOR == 0 &&
        2u * slot + STORE_CFG_BYTES <= region()) {
        g_slot = slot;                                      /* разметка уже выбрана */
    } else {
        g_slot = choose_slot(buf_cap);
        if (cfg_latest_at(legacy_base(), legacy_base() + STORE_SECTOR, 1, &c, NULL, NULL) == 0)
            migrate_legacy(&c, buf, buf_cap);
    }
    crypto_wipe(&c, sizeof c);
    size_t by_slot = g_slot > STORE_VAULT_HDR ? g_slot - STORE_VAULT_HDR : 0;
    size_t by_ram = buf_cap > STORE_VAULT_HDR ? buf_cap - STORE_VAULT_HDR : 0;
    g_cap = by_slot < by_ram ? by_slot : by_ram;
    return g_cap;
}
