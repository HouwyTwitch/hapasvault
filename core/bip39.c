#include "bip39.h"
#include <ctype.h>
#include <string.h>

/* ---------- SHA-256 (нужен только для контрольной суммы BIP39) ---------- */

static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_block(uint32_t h[8], const uint8_t b[64])
{
    uint32_t w[64], a, bb, c, d, e, f, g, hh;
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)b[4 * i] << 24 | (uint32_t)b[4 * i + 1] << 16 |
               (uint32_t)b[4 * i + 2] << 8 | b[4 * i + 3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    a = h[0]; bb = h[1]; c = h[2]; d = h[3]; e = h[4]; f = h[5]; g = h[6]; hh = h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = hh + (ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25)) + ((e & f) ^ (~e & g)) + K256[i] + w[i];
        uint32_t t2 = (ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22)) + ((a & bb) ^ (a & c) ^ (bb & c));
        hh = g; g = f; f = e; e = d + t1; d = c; c = bb; bb = a; a = t1 + t2;
    }
    h[0] += a; h[1] += bb; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

void pm_sha256(const uint8_t *msg, size_t len, uint8_t out[32])
{
    uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    uint8_t blk[64];
    size_t i = 0;
    for (; i + 64 <= len; i += 64) sha256_block(h, msg + i);
    size_t rem = len - i;
    memset(blk, 0, 64);
    memcpy(blk, msg + i, rem);
    blk[rem] = 0x80;
    if (rem >= 56) { sha256_block(h, blk); memset(blk, 0, 64); }
    uint64_t bits = (uint64_t)len * 8;
    for (int k = 0; k < 8; k++) blk[63 - k] = (uint8_t)(bits >> (8 * k));
    sha256_block(h, blk);
    for (int k = 0; k < 8; k++) {
        out[4 * k] = (uint8_t)(h[k] >> 24); out[4 * k + 1] = (uint8_t)(h[k] >> 16);
        out[4 * k + 2] = (uint8_t)(h[k] >> 8); out[4 * k + 3] = (uint8_t)h[k];
    }
}

/* ---------- BIP39 ---------- */

static int get_bit(const uint8_t *buf, int i) { return (buf[i >> 3] >> (7 - (i & 7))) & 1; }
static void set_bit(uint8_t *buf, int i) { buf[i >> 3] |= (uint8_t)(0x80 >> (i & 7)); }

void bip39_encode(const uint8_t entropy[32], uint16_t idx[BIP39_WORDS])
{
    uint8_t buf[33], hash[32];
    memcpy(buf, entropy, 32);
    pm_sha256(entropy, 32, hash);
    buf[32] = hash[0];
    for (int w = 0; w < BIP39_WORDS; w++) {
        uint16_t v = 0;
        for (int b = 0; b < 11; b++) v = (uint16_t)(v << 1 | get_bit(buf, w * 11 + b));
        idx[w] = v;
    }
}

static int find_word(const char *w, size_t len)
{
    int cand = -1;
    for (int i = 0; i < 2048; i++) {
        const char *ref = bip39_english[i];
        size_t rl = strlen(ref);
        if (rl == len && memcmp(ref, w, len) == 0) return i;
        /* в английском списке первые 4 буквы уникальны */
        if (len >= 4 && len < rl && memcmp(ref, w, len) == 0) cand = i;
    }
    return cand;
}

int bip39_decode(const char *phrase, uint8_t entropy[32])
{
    uint8_t buf[33];
    memset(buf, 0, sizeof buf);
    int nwords = 0;
    const char *p = phrase;
    while (*p) {
        while (*p && !isalpha((unsigned char)*p)) p++;
        if (!*p) break;
        char word[16];
        size_t len = 0;
        while (*p && isalpha((unsigned char)*p)) {
            if (len < sizeof word - 1) word[len] = (char)tolower((unsigned char)*p);
            len++; p++;
        }
        if (len >= sizeof word) return -1;
        if (nwords >= BIP39_WORDS) return -2;
        int idx = find_word(word, len);
        if (idx < 0) return -1;
        for (int b = 0; b < 11; b++)
            if (idx & (1 << (10 - b))) set_bit(buf, nwords * 11 + b);
        nwords++;
    }
    if (nwords != BIP39_WORDS) return -2;
    uint8_t hash[32];
    pm_sha256(buf, 32, hash);
    if (hash[0] != buf[32]) return -3;
    memcpy(entropy, buf, 32);
    return 0;
}

void bip39_to_string(const uint8_t entropy[32], char *out, size_t cap)
{
    uint16_t idx[BIP39_WORDS];
    bip39_encode(entropy, idx);
    size_t pos = 0;
    if (cap) out[0] = 0;
    for (int i = 0; i < BIP39_WORDS; i++) {
        const char *w = bip39_english[idx[i]];
        size_t l = strlen(w);
        if (pos + l + 2 > cap) break;
        if (i) out[pos++] = ' ';
        memcpy(out + pos, w, l);
        pos += l;
        out[pos] = 0;
    }
}
