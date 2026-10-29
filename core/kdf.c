#include "kdf.h"
#include "monocypher.h"
#include <string.h>

static void derive(uint8_t out[32], const uint8_t key[32], const char *label)
{
    crypto_blake2b_keyed(out, 32, key, 32, (const uint8_t *)label, strlen(label));
}

void pm_seed_from_rand(uint8_t seed[32], const uint8_t rand_token[32],
                       const uint8_t rand_pc[32])
{
    static const char label[] = "pmtok/seed/v1";
    crypto_blake2b_ctx ctx;
    crypto_blake2b_init(&ctx, 32);
    crypto_blake2b_update(&ctx, (const uint8_t *)label, sizeof label - 1);
    crypto_blake2b_update(&ctx, rand_token, 32);
    crypto_blake2b_update(&ctx, rand_pc, 32);
    crypto_blake2b_final(&ctx, seed);
}

void pm_keys_from_seed(const uint8_t seed[32], uint8_t k_token[32], uint8_t k_pc[32])
{
    derive(k_token, seed, "pmtok/k_token/v1");
    derive(k_pc, seed, "pmtok/k_pc/v1");
}

void pm_salt_from_kpc(const uint8_t k_pc[32], uint8_t salt[16])
{
    uint8_t tmp[32];
    derive(tmp, k_pc, "pmtok/salt/v1");
    memcpy(salt, tmp, 16);
    crypto_wipe(tmp, sizeof tmp);
}

void pm_vault_key(uint8_t k_vault[32], const uint8_t k_token[32],
                  const uint8_t k_pc[32], const uint8_t pw_hash[32])
{
    static const char label[] = "pmtok/vault/v1";
    crypto_blake2b_ctx ctx;
    crypto_blake2b_keyed_init(&ctx, 32, k_token, 32);
    crypto_blake2b_update(&ctx, (const uint8_t *)label, sizeof label - 1);
    crypto_blake2b_update(&ctx, k_pc, 32);
    crypto_blake2b_update(&ctx, pw_hash, 32);
    crypto_blake2b_final(&ctx, k_vault);
}

uint32_t pm_pairing_code(const uint8_t token_pub[32], const uint8_t pc_pub[32])
{
    uint8_t buf[64], h[8];
    memcpy(buf, token_pub, 32);
    memcpy(buf + 32, pc_pub, 32);
    crypto_blake2b(h, sizeof h, buf, sizeof buf);
    uint32_t v = (uint32_t)h[0] | (uint32_t)h[1] << 8 | (uint32_t)h[2] << 16 |
                 (uint32_t)h[3] << 24;
    return v % 1000000u;
}
