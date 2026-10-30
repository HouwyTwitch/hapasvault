/*
 * SHA-1, SHA-256 и HMAC — для TOTP/Steam Guard (RFC 2104, 6238) и BIP39.
 * SHA-1 здесь только внутри HMAC для кодов OTP: так требуют сервисы,
 * для HMAC слабость SHA-1 к коллизиям не важна.
 */
#ifndef PM_SHA_H
#define PM_SHA_H

#include <stddef.h>
#include <stdint.h>

typedef enum { PM_SHA1 = 1, PM_SHA256 = 2 } pm_hash_alg;

typedef struct {
    pm_hash_alg alg;
    uint32_t h[8];
    uint8_t  buf[64];
    size_t   used;
    uint64_t total;
} pm_hash_ctx;

/* Длина дайджеста алгоритма (0 — неизвестный). */
size_t pm_hash_len(pm_hash_alg alg);

void pm_hash_init(pm_hash_ctx *c, pm_hash_alg alg);
void pm_hash_update(pm_hash_ctx *c, const uint8_t *data, size_t len);
void pm_hash_final(pm_hash_ctx *c, uint8_t *out);   /* out >= pm_hash_len */

void pm_sha256(const uint8_t *msg, size_t len, uint8_t out[32]);
void pm_sha1(const uint8_t *msg, size_t len, uint8_t out[20]);

/* HMAC. Возвращает длину дайджеста (0 — неизвестный алгоритм). */
size_t pm_hmac(pm_hash_alg alg, const uint8_t *key, size_t key_len,
               const uint8_t *msg, size_t msg_len, uint8_t *out);

#endif
