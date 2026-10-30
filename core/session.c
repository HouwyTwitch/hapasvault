#include "session.h"
#include "proto.h"
#include "monocypher.h"
#include <string.h>

static int is_zero32(const uint8_t x[32])
{
    static const uint8_t z[32] = {0};
    return crypto_verify32(x, z) == 0;
}

int pm_session_establish(pm_session *s, pm_role role,
                         const uint8_t my_s_sk[32], const uint8_t my_s_pk[32],
                         const uint8_t my_e_sk[32], const uint8_t my_e_pk[32],
                         const uint8_t peer_s_pk[32], const uint8_t peer_e_pk[32])
{
    static const char label[] = "pmtok/session/KK/v1";
    const uint8_t *i_s = role == PM_INITIATOR ? my_s_pk : peer_s_pk;
    const uint8_t *r_s = role == PM_INITIATOR ? peer_s_pk : my_s_pk;
    const uint8_t *i_e = role == PM_INITIATOR ? my_e_pk : peer_e_pk;
    const uint8_t *r_e = role == PM_INITIATOR ? peer_e_pk : my_e_pk;

    /* dh[0]=ee, dh[1]=es (эфемерный ПК x статический токена),
       dh[2]=se (статический ПК x эфемерный токена), dh[3]=ss */
    uint8_t dh[4][32];
    crypto_x25519(dh[0], my_e_sk, peer_e_pk);
    if (role == PM_INITIATOR) {
        crypto_x25519(dh[1], my_e_sk, peer_s_pk);
        crypto_x25519(dh[2], my_s_sk, peer_e_pk);
    } else {
        crypto_x25519(dh[1], my_s_sk, peer_e_pk);
        crypto_x25519(dh[2], my_e_sk, peer_s_pk);
    }
    crypto_x25519(dh[3], my_s_sk, peer_s_pk);

    int bad = 0;
    for (int i = 0; i < 4; i++) bad |= is_zero32(dh[i]);   /* точки малого порядка */

    uint8_t h[32];
    crypto_blake2b_ctx ctx;
    crypto_blake2b_init(&ctx, 32);
    crypto_blake2b_update(&ctx, (const uint8_t *)label, sizeof label - 1);
    crypto_blake2b_update(&ctx, i_s, 32);
    crypto_blake2b_update(&ctx, r_s, 32);
    crypto_blake2b_update(&ctx, i_e, 32);
    crypto_blake2b_update(&ctx, r_e, 32);
    crypto_blake2b_final(&ctx, h);

    uint8_t okm[64];
    crypto_blake2b_keyed(okm, 64, h, 32, &dh[0][0], sizeof dh);

    memset(s, 0, sizeof *s);
    if (role == PM_INITIATOR) {
        memcpy(s->k_send, okm, 32);
        memcpy(s->k_recv, okm + 32, 32);
    } else {
        memcpy(s->k_recv, okm, 32);
        memcpy(s->k_send, okm + 32, 32);
    }
    s->active = !bad;

    crypto_wipe(dh, sizeof dh);
    crypto_wipe(okm, sizeof okm);
    crypto_wipe(h, sizeof h);
    if (bad) { pm_session_clear(s); return -1; }
    return 0;
}

static void make_nonce(uint8_t nonce[24], uint64_t n)
{
    memset(nonce, 0, 24);
    for (int i = 0; i < 8; i++) nonce[i] = (uint8_t)(n >> (8 * i));
}

size_t pm_session_seal(pm_session *s, uint8_t *out, const uint8_t *in, size_t len)
{
    uint8_t nonce[24], ad = FR_DATA;
    make_nonce(nonce, s->n_send++);
    crypto_aead_lock(out + PM_MAC_LEN, out, s->k_send, nonce, &ad, 1, in, len);
    return len + PM_MAC_LEN;
}

long pm_session_open(pm_session *s, uint8_t *out, const uint8_t *in, size_t len)
{
    if (!s->active || len < PM_MAC_LEN) return -1;
    uint8_t nonce[24], ad = FR_DATA;
    make_nonce(nonce, s->n_recv);
    if (crypto_aead_unlock(out, in, s->k_recv, nonce, &ad, 1, in + PM_MAC_LEN,
                           len - PM_MAC_LEN) != 0)
        return -1;
    s->n_recv++;
    return (long)(len - PM_MAC_LEN);
}

void pm_session_clear(pm_session *s) { crypto_wipe(s, sizeof *s); }
