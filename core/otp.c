#include "otp.h"
#include "sha.h"
#include "monocypher.h"
#include <string.h>

int pm_otp_validate(const uint8_t *blob, size_t len)
{
    if (len < OTP_PARAMS + OTP_SECRET_MIN || len > OTP_BLOB_MAX) return -1;
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
    uint64_t counter = unix_time / period;
    uint8_t msg[8], mac[32];
    for (int i = 0; i < 8; i++) msg[i] = (uint8_t)(counter >> (56 - 8 * i));
    size_t ml = pm_hmac((pm_hash_alg)blob[1], blob + OTP_PARAMS, len - OTP_PARAMS, msg, sizeof msg, mac);
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
