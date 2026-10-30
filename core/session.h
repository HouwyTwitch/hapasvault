/*
 * Зашифрованный канал ПК <-> токен.
 *
 * Рукопожатие в духе Noise KK: обе стороны заранее знают статические
 * ключи X25519 друг друга (обменялись при сопряжении), на каждую сессию
 * генерируют эфемерные. Ключи сессии выводятся из четырёх DH (ee, es, se, ss):
 *   - ee даёт forward secrecy (утечка статических ключей не раскрывает
 *     прошлые сессии);
 *   - es/se/ss дают взаимную аутентификацию: чужой ПК или чужой токен
 *     получат другие ключи, и первый же кадр не расшифруется.
 *
 * Шифрование: XChaCha20-Poly1305, отдельный ключ и счётчик на каждое
 * направление. Повтор, перестановка или подмена кадра -> ошибка.
 */
#ifndef PM_SESSION_H
#define PM_SESSION_H

#include <stddef.h>
#include <stdint.h>

#define PM_MAC_LEN 16

typedef struct {
    uint8_t  k_send[32];
    uint8_t  k_recv[32];
    uint64_t n_send;
    uint64_t n_recv;
    int      active;
} pm_session;

typedef enum { PM_INITIATOR = 0 /* ПК */, PM_RESPONDER = 1 /* токен */ } pm_role;

/* Вывести ключи сессии. 0 = ок, -1 = недопустимый ключ собеседника. */
int pm_session_establish(pm_session *s, pm_role role,
                         const uint8_t my_static_sk[32], const uint8_t my_static_pk[32],
                         const uint8_t my_eph_sk[32],    const uint8_t my_eph_pk[32],
                         const uint8_t peer_static_pk[32], const uint8_t peer_eph_pk[32]);

/* out = [mac 16][ciphertext len]. Возвращает длину out (len + 16). */
size_t pm_session_seal(pm_session *s, uint8_t *out, const uint8_t *in, size_t len);

/* in = [mac][ciphertext]. Возвращает длину открытого текста или -1. */
long pm_session_open(pm_session *s, uint8_t *out, const uint8_t *in, size_t len);

void pm_session_clear(pm_session *s);

#endif
