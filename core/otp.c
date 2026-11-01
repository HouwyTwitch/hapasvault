#include "otp.h"
#include "sha.h"
#include "monocypher.h"
#include <string.h>

int pm_steam_parts(const uint8_t *blob, size_t len,
                   const uint8_t **shared, size_t *shared_len,
                   const uint8_t **identity, size_t *identity_len,
                   uint64_t *steamid, const uint8_t **revocation, size_t *revocation_len)
{
    if (len < OTP_PARAMS || len > OTP_BLOB_MAX || blob[0] != OTP_STEAM_MOBILE) return -1;
    if (blob[1] != PM_SHA1 || blob[2] != 5 || blob[3] != 30) return -1;
    size_t p = OTP_PARAMS;
    /* общий и личный секреты: [u8 n][n байт], 10..64 */
    const uint8_t *part[2];
    size_t plen[2];
    for (int i = 0; i < 2; i++) {
        if (p >= len) return -1;
        size_t n = blob[p++];
        if (n < OTP_SECRET_MIN || n > OTP_SECRET_MAX || n > len - p) return -1;
        part[i] = blob + p;
        plen[i] = n;
        p += n;
    }
    if (len - p < 9) return -1;
    uint64_t sid = 0;
    for (int i = 7; i >= 0; i--) sid = sid << 8 | blob[p + (size_t)i];
    p += 8;
    size_t r = blob[p++];
    if (r > STEAM_REVOCATION_MAX || r != len - p) return -1;
    for (size_t i = 0; i < r; i++)
        if (blob[p + i] < 0x21 || blob[p + i] > 0x7E) return -1;
    if (shared) *shared = part[0];
    if (shared_len) *shared_len = plen[0];
    if (identity) *identity = part[1];
    if (identity_len) *identity_len = plen[1];
    if (steamid) *steamid = sid;
    if (revocation) *revocation = blob + p;
    if (revocation_len) *revocation_len = r;
    return 0;
}

int pm_steam_tag_ok(const uint8_t *tag, size_t len)
{
    if (len < 1 || len > STEAM_TAG_MAX) return 0;
    for (size_t i = 0; i < len; i++)
        if (!((tag[i] >= 'a' && tag[i] <= 'z') || (tag[i] >= '0' && tag[i] <= '9'))) return 0;
    return 1;
}

static int tag_eq(const uint8_t *tag, size_t len, const char *s)
{
    return strlen(s) == len && memcmp(tag, s, len) == 0;
}

int pm_steam_tag_is_action(const uint8_t *tag, size_t len)
{
    return tag_eq(tag, len, "allow") || tag_eq(tag, len, "accept") ||
           tag_eq(tag, len, "cancel") || tag_eq(tag, len, "reject");
}

int pm_steam_conf_key(const uint8_t *blob, size_t len, uint64_t unix_time,
                      const uint8_t *tag, size_t tag_len, uint8_t key[STEAM_CONF_KEY])
{
    const uint8_t *id;
    size_t id_len;
    if (pm_steam_parts(blob, len, NULL, NULL, &id, &id_len, NULL, NULL, NULL) != 0) return -1;
    if (!pm_steam_tag_ok(tag, tag_len)) return -1;
    uint8_t msg[8 + STEAM_TAG_MAX];
    for (int i = 0; i < 8; i++) msg[i] = (uint8_t)(unix_time >> (56 - 8 * i));
    memcpy(msg + 8, tag, tag_len);
    uint8_t mac[32];
    size_t n = pm_hmac(PM_SHA1, id, id_len, msg, 8 + tag_len, mac);
    if (n != STEAM_CONF_KEY) return -1;
    memcpy(key, mac, STEAM_CONF_KEY);
    crypto_wipe(mac, sizeof mac);
    return 0;
}

int pm_otp_validate(const uint8_t *blob, size_t len)
{
    if (len >= 1 && blob[0] == OTP_STEAM_MOBILE)
        return pm_steam_parts(blob, len, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    if (len < OTP_PARAMS + OTP_SECRET_MIN || len > OTP_PARAMS + OTP_SECRET_MAX) return -1;
    uint8_t type = blob[0], alg = blob[1], digits = blob[2], period = blob[3];
    switch (type) {
    case OTP_TOTP:
        if (alg != PM_SHA1 && alg != PM_SHA256) return -1;
        if (digits < 6 || digits > 8) return -1;
        if (period < 15 || period > 120) return -1;
        return 0;
    case OTP_STEAM:
        return alg == PM_SHA1 && digits == 5 && period == 30 ? 0 : -1;
    default:
        return -1;
    }
}

int pm_otp_code(const uint8_t *blob, size_t len, uint64_t unix_time, char code[OTP_CODE_MAX + 1])
{
    if (pm_otp_validate(blob, len) != 0) return -1;
    uint8_t type = blob[0], digits = blob[2], period = blob[3];
    const uint8_t *secret = blob + OTP_PARAMS;
    size_t secret_len = len - OTP_PARAMS;
    if (type == OTP_STEAM_MOBILE) {
        pm_steam_parts(blob, len, &secret, &secret_len, NULL, NULL, NULL, NULL, NULL);
        type = OTP_STEAM;
    }
    uint64_t counter = unix_time / period;
    uint8_t msg[8], mac[32];
    for (int i = 0; i < 8; i++) msg[i] = (uint8_t)(counter >> (56 - 8 * i));
    size_t ml = pm_hmac((pm_hash_alg)blob[1], secret, secret_len, msg, sizeof msg, mac);
    if (!ml) return -1;
    /* динамическое усечение (RFC 4226, 5.3) */
    unsigned off = mac[ml - 1] & 0x0F;
    uint32_t bin = (uint32_t)(mac[off] & 0x7F) << 24 | (uint32_t)mac[off + 1] << 16 |
                   (uint32_t)mac[off + 2] << 8 | mac[off + 3];
    crypto_wipe(mac, sizeof mac);

    if (type == OTP_STEAM) {
        static const char alphabet[] = "23456789BCDFGHJKMNPQRTVWXY";
        for (int i = 0; i < 5; i++) {
            code[i] = alphabet[bin % 26];
            bin /= 26;
        }
        code[5] = 0;
        return 5;
    }
    uint32_t mod = 1;
    for (int i = 0; i < digits; i++) mod *= 10;
    bin %= mod;
    for (int i = digits - 1; i >= 0; i--) {
        code[i] = (char)('0' + bin % 10);
        bin /= 10;
    }
    code[digits] = 0;
    return digits;
}
