#include "bip39.h"
#include "sha.h"
#include <ctype.h>
#include <string.h>

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
