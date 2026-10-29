/*
 * Вывод ключей. Общий код для токена и ПК (одинаковые метки с обеих сторон).
 *
 *   seed     = BLAKE2b("pmtok/seed/v1" || rand_token || rand_pc)     256 бит -> 24 слова
 *   K_token  = BLAKE2b_keyed(seed, "pmtok/k_token/v1")
 *   K_pc     = BLAKE2b_keyed(seed, "pmtok/k_pc/v1")
 *   salt     = BLAKE2b_keyed(K_pc, "pmtok/salt/v1")[0..16]           соль Argon2id
 *   pw_hash  = Argon2id(мастер-пароль, salt)                          считается на ПК
 *   K_vault  = BLAKE2b_keyed(K_token, "pmtok/vault/v1" || K_pc || pw_hash)
 */
#ifndef PM_KDF_H
#define PM_KDF_H

#include <stdint.h>

void pm_seed_from_rand(uint8_t seed[32], const uint8_t rand_token[32],
                       const uint8_t rand_pc[32]);
void pm_keys_from_seed(const uint8_t seed[32], uint8_t k_token[32], uint8_t k_pc[32]);
void pm_salt_from_kpc(const uint8_t k_pc[32], uint8_t salt[16]);
void pm_vault_key(uint8_t k_vault[32], const uint8_t k_token[32],
                  const uint8_t k_pc[32], const uint8_t pw_hash[32]);

/* Короткий код сверки при сопряжении (6 цифр), одинаков на обеих сторонах. */
uint32_t pm_pairing_code(const uint8_t token_pub[32], const uint8_t pc_pub[32]);

#endif
