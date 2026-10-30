"""Иконка приложения: «печенье» M3 Expressive (9 волн) с замочной скважиной.

    python gen_icon.py <выход.ico> [превью.png]
"""
import math
import sys

from PIL import Image, ImageDraw

S = 1024                       # рисуем крупно, потом уменьшаем (сглаживание)
BG = (103, 80, 164, 255)       # M3 baseline primary #6750A4
BG2 = (79, 55, 139, 255)
FG = (255, 255, 255, 255)


def cookie(cx, cy, r, waves=9, depth=0.085, rot=-math.pi / 2, n=720):
    pts = []
    for i in range(n):
        t = 2 * math.pi * i / n
        rr = r * (1 - depth + depth * math.cos(waves * (t - rot)))
        pts.append((cx + rr * math.cos(t), cy + rr * math.sin(t)))
    return pts


def main(out, preview=None):
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    c = S / 2
    d.polygon(cookie(c, c + 10, S * 0.48), fill=BG2)       # «тень»
    d.polygon(cookie(c, c, S * 0.48), fill=BG)
    # замочная скважина
    hr = S * 0.105
    hy = c - S * 0.07
    d.ellipse((c - hr, hy - hr, c + hr, hy + hr), fill=FG)
    top, bot = hy + hr * 0.4, c + S * 0.21
    d.rounded_rectangle((c - S * 0.05, top, c + S * 0.05, bot), radius=S * 0.05, fill=FG)
    sizes = [256, 128, 64, 48, 32, 24, 16]
    img.resize((256, 256), Image.LANCZOS).save(out, sizes=[(s, s) for s in sizes])
    if preview:
        img.resize((256, 256), Image.LANCZOS).save(preview)


if __name__ == "__main__":
    main(*sys.argv[1:])
