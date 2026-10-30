#include "framer.h"
#include <string.h>

void pm_framer_reset(pm_framer *f) { memset(f, 0, sizeof *f); }

int pm_framer_busy(const pm_framer *f) { return f->hdr_n != 0; }

long pm_framer_feed(pm_framer *f, uint8_t *buf, size_t cap,
                    const uint8_t *data, size_t n, size_t *used)
{
    size_t i = 0;
    while (f->hdr_n < 4 && i < n) {
        f->hdr[f->hdr_n++] = data[i++];
        if (f->hdr_n == 4) {
            f->need = (uint32_t)f->hdr[0] | (uint32_t)f->hdr[1] << 8 |
                      (uint32_t)f->hdr[2] << 16 | (uint32_t)f->hdr[3] << 24;
            f->have = 0;
            if (f->need == 0 || f->need > cap) {
                pm_framer_reset(f);
                *used = i;
                return -1;
            }
        }
    }
    if (f->hdr_n < 4) { *used = i; return 0; }

    size_t take = n - i;
    if (take > f->need - f->have) take = f->need - f->have;
    memcpy(buf + f->have, data + i, take);
    f->have += (uint32_t)take;
    *used = i + take;
    if (f->have < f->need) return 0;
    long len = (long)f->need;
    pm_framer_reset(f);
    return len;
}

void pm_framer_header(uint8_t hdr[4], size_t len)
{
    hdr[0] = (uint8_t)len;
    hdr[1] = (uint8_t)(len >> 8);
    hdr[2] = (uint8_t)(len >> 16);
    hdr[3] = (uint8_t)(len >> 24);
}
