"""Generuje ikonę aplikacji (ui/assets/keystead.ico + keystead.png): tarcza z dziurką od klucza."""

import os

from PIL import Image, ImageDraw

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "ui", "assets")


def draw(size: int = 1024) -> Image.Image:
    s = size
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    # Tło: zaokrąglony kwadrat z pionowym gradientem indygo
    grad = Image.new("RGBA", (s, s))
    top, bottom = (99, 102, 241), (67, 56, 202)
    gd = ImageDraw.Draw(grad)
    for y in range(s):
        t = y / (s - 1)
        gd.line([(0, y), (s, y)], fill=tuple(int(a + (b - a) * t) for a, b in zip(top, bottom)) + (255,))
    mask = Image.new("L", (s, s), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, s - 1, s - 1], radius=int(s * 0.22), fill=255)
    img.paste(grad, (0, 0), mask)

    d = ImageDraw.Draw(img)
    # Tarcza
    cx = s / 2
    half, top_y, shoulder, mid_y, bot_y = s * 0.29, s * 0.16, s * 0.23, s * 0.50, s * 0.86

    def quad(p0, p1, p2, n=40):
        return [((1 - t) ** 2 * p0[0] + 2 * (1 - t) * t * p1[0] + t * t * p2[0],
                 (1 - t) ** 2 * p0[1] + 2 * (1 - t) * t * p1[1] + t * t * p2[1]) for t in (i / n for i in range(n + 1))]

    right = (quad((cx, top_y), (cx + half * 0.55, shoulder - s * 0.01), (cx + half, shoulder))
             + quad((cx + half, mid_y), (cx + half, bot_y - s * 0.12), (cx, bot_y)))
    left = [(2 * cx - x, y) for x, y in reversed(right)]
    d.polygon(right + left, fill=(255, 255, 255, 255))
    # Dziurka od klucza
    hole = (67, 56, 202, 255)
    r = s * 0.075
    ky = s * 0.44
    d.ellipse([cx - r, ky - r, cx + r, ky + r], fill=hole)
    d.polygon([(cx - r * 0.55, ky + r * 0.5), (cx + r * 0.55, ky + r * 0.5), (cx + r * 0.9, s * 0.66),
               (cx - r * 0.9, s * 0.66)], fill=hole)
    return img


def main():
    os.makedirs(OUT, exist_ok=True)
    img = draw()
    img.resize((256, 256), Image.LANCZOS).save(os.path.join(OUT, "keystead.png"))
    img.save(os.path.join(OUT, "keystead.ico"), sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    print("Zapisano", OUT)


if __name__ == "__main__":
    main()
