/*
 * BIP39: 256 бит энтропии + 8 бит контрольной суммы (SHA-256) = 24 слова по 11 бит.
 * Используется только кодирование энтропии в слова и обратно
 * (PBKDF2-шаг BIP39 не нужен: совместимость с кошельками не требуется).
 */
#ifndef PM_BIP39_H
#define PM_BIP39_H

#include <stddef.h>
#include <stdint.h>

#define BIP39_WORDS 24

extern const char *const bip39_english[2048];

/* Энтропия -> 24 индекса слов. */
void bip39_encode(const uint8_t entropy[32], uint16_t idx[BIP39_WORDS]);

/* Строка из 24 слов (через пробелы, регистр не важен; допускаются первые
 * 4+ буквы слова) -> энтропия.
 * Возврат: 0 = ок, -1 = неизвестное слово, -2 = не 24 слова, -3 = контрольная сумма. */
int bip39_decode(const char *phrase, uint8_t entropy[32]);

/* Удобство: энтропия -> строка "word1 word2 ..." (буфер >= 24*9). */
void bip39_to_string(const uint8_t entropy[32], char *out, size_t cap);

void pm_sha256(const uint8_t *msg, size_t len, uint8_t out[32]);

#endif
