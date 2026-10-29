/* Чтение/запись полей протокола (little-endian) с проверкой границ. */
#ifndef PM_WIRE_H
#define PM_WIRE_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef struct { const uint8_t *p; size_t n; int err; } wire_r;
typedef struct { uint8_t *p; size_t cap; size_t n; int err; } wire_w;

static inline uint32_t wire_get32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static inline void wire_put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static inline const uint8_t *wire_bytes(wire_r *r, size_t len)
{
    if (r->err || r->n < len) { r->err = 1; return NULL; }
    const uint8_t *q = r->p;
    r->p += len; r->n -= len;
    return q;
}
static inline uint8_t wire_u8(wire_r *r)
{
    const uint8_t *q = wire_bytes(r, 1);
    return q ? q[0] : 0;
}
static inline uint16_t wire_u16(wire_r *r)
{
    const uint8_t *q = wire_bytes(r, 2);
    return q ? (uint16_t)(q[0] | q[1] << 8) : 0;
}
static inline uint32_t wire_u32(wire_r *r)
{
    const uint8_t *q = wire_bytes(r, 4);
    return q ? wire_get32(q) : 0;
}

static inline void wire_put_bytes(wire_w *w, const void *src, size_t len)
{
    if (w->err || w->cap - w->n < len) { w->err = 1; return; }
    memcpy(w->p + w->n, src, len);
    w->n += len;
}
static inline void wire_put_u8(wire_w *w, uint8_t v) { wire_put_bytes(w, &v, 1); }
static inline void wire_put_u16(wire_w *w, uint16_t v)
{
    uint8_t b[2] = {(uint8_t)v, (uint8_t)(v >> 8)};
    wire_put_bytes(w, b, 2);
}
static inline void wire_put_u32(wire_w *w, uint32_t v)
{
    uint8_t b[4];
    wire_put32(b, v);
    wire_put_bytes(w, b, 4);
}
/* Строка [u8 len][bytes] */
static inline void wire_put_str(wire_w *w, const char *s)
{
    size_t l = strlen(s);
    if (l > 255) { w->err = 1; return; }
    wire_put_u8(w, (uint8_t)l);
    wire_put_bytes(w, s, l);
}

#endif
