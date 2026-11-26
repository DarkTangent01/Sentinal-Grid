"""Sentinel brand assets from one geometry (docs/design-system.md → Logo). Writes public/brand/*.svg, public/favicon.svg,
public/favicon.ico, public/apple-touch-icon.png and public/brand/sentinel-icon-512.png.

    ../.venv/bin/python scripts/generate-brand.py        (from frontend/; needs Pillow)

The mark: a hexagonal frame — the protective structure — split into two interlocking halves that meet in a central
node, so the frame also reads as an "S" and as a small network (two open ends = nodes, the centre = the sentinel's
eye / core). The same symbol is used by Sentinel NMS and Sentinel Grid; only the accent colour changes. The geometry
is duplicated in src/components/Brand.tsx (MARK_PATHS) — change both together.
"""
from __future__ import annotations

import math
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "public"
BRAND = OUT / "brand"

# ---- geometry on a 32 × 32 grid --------------------------------------------------------------------------------
PATH_A = "M26.4 10 L16 4 L5.6 10 L16 16"
PATH_B = "M5.6 22 L16 28 L26.4 22 L16 16"
NODES = [(26.4, 10, 2.25), (5.6, 22, 2.25), (16, 16, 3.1)]
STROKE = 2.6
POLY_A = [(26.4, 10), (16, 4), (5.6, 10), (16, 16)]
POLY_B = [(5.6, 22), (16, 28), (26.4, 22), (16, 16)]

# Solid colours only (no gradients): neutral platform mark, restrained product accents. Mirrors Brand.tsx MARK_COLOR.
COLORS = {"sentinel": "#F5F5F5", "nms": "#38BDF8", "grid": "#A78BFA"}
LIGHT = {"sentinel": "#09090B", "nms": "#0284C7", "grid": "#7C3AED"}
TILE, TILE_LINE, INK, PAPER, SUB_DARK, SUB_LIGHT = "#0A0A0A", "#292929", "#F5F5F5", "#09090B", "#A1A1AA", "#52525B"
FONT = "Inter Variable, Inter, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif"


def mark(paint: str, x: float = 0, y: float = 0, scale: float = 1.0) -> str:
    """The mark as an SVG group in one solid colour (or currentColor)."""
    body = (f'<g fill="none" stroke="{paint}" stroke-width="{STROKE}" stroke-linecap="round" stroke-linejoin="round">'
            f'<path d="{PATH_A}"/><path d="{PATH_B}"/></g>'
            + "".join(f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="{paint}"/>' for cx, cy, r in NODES))
    return f'<g transform="translate({x} {y}) scale({scale})">{body}</g>'


def svg(w: float, h: float, inner: str, title: str) -> str:
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w:g} {h:g}" width="{w:g}" height="{h:g}" role="img" aria-label="{title}">'
            f"<title>{title}</title>{inner}</svg>\n")


def wordmark(x: float, baseline: float, size: float, color: str, product: str | None, accent: str | None, sub: str | None, subcolor: str) -> str:
    t = (f'<text x="{x}" y="{baseline}" font-family="{FONT}" font-size="{size}" font-weight="600" letter-spacing="-0.02em" fill="{color}">Sentinel'
         + (f'<tspan dx="{size * 0.28:.1f}" fill="{accent}" font-weight="600">{product}</tspan>' if product else "") + "</text>")
    if sub:
        t += (f'<text x="{x}" y="{baseline + size * 0.95:.1f}" font-family="{FONT}" font-size="{size * 0.42:.1f}" font-weight="500" '
              f'letter-spacing="0.02em" fill="{subcolor}">{sub}</text>')
    return t


def write_svgs() -> None:
    BRAND.mkdir(parents=True, exist_ok=True)
    files = {
        # 1 / 5 primary, dark background (white wordmark)
        "sentinel-logo-dark.svg": svg(200, 40, mark(COLORS["sentinel"], 0, 2, 1.125) + wordmark(46, 28, 22, INK, None, None, None, ""), "Sentinel"),
        # 6 light background
        "sentinel-logo-light.svg": svg(200, 40, mark(LIGHT["sentinel"], 0, 2, 1.125) + wordmark(46, 28, 22, PAPER, None, None, None, ""), "Sentinel"),
        # 7 monochrome (currentColor: inherits the surrounding text colour)
        "sentinel-logo-mono.svg": svg(200, 40, mark("currentColor", 0, 2, 1.125) + wordmark(46, 28, 22, "currentColor", None, None, None, ""), "Sentinel"),
        # 2 icon only
        "sentinel-mark.svg": svg(32, 32, mark(COLORS["sentinel"]), "Sentinel"),
        "sentinel-mark-mono.svg": svg(32, 32, mark("currentColor"), "Sentinel"),
        # 3 / 4 product logos (dark and light)
        "sentinel-nms-dark.svg": svg(320, 48, mark(COLORS["nms"], 0, 4, 1.25)
                                     + wordmark(52, 24, 22, INK, "NMS", "#38BDF8", "NETWORK MONITORING &amp; INTELLIGENCE", SUB_DARK), "Sentinel NMS"),
        "sentinel-nms-light.svg": svg(320, 48, mark(LIGHT["nms"], 0, 4, 1.25)
                                      + wordmark(52, 24, 22, PAPER, "NMS", "#0369A1", "NETWORK MONITORING &amp; INTELLIGENCE", SUB_LIGHT), "Sentinel NMS"),
        "sentinel-grid-dark.svg": svg(320, 48, mark(COLORS["grid"], 0, 4, 1.25)
                                      + wordmark(52, 24, 22, INK, "Grid", "#A78BFA", "SECURITY INTELLIGENCE PLATFORM", SUB_DARK), "Sentinel Grid"),
        "sentinel-grid-light.svg": svg(320, 48, mark(LIGHT["grid"], 0, 4, 1.25)
                                       + wordmark(52, 24, 22, PAPER, "Grid", "#6D28D9", "SECURITY INTELLIGENCE PLATFORM", SUB_LIGHT), "Sentinel Grid"),
        # 9 app tile (launcher, sidebar compact, loading screen)
        "sentinel-tile.svg": svg(64, 64, f'<rect width="64" height="64" rx="15" fill="{TILE}"/><rect x="0.75" y="0.75" width="62.5" height="62.5" rx="14.25" '
                                         f'fill="none" stroke="{TILE_LINE}" stroke-width="1.5"/>' + mark(COLORS["sentinel"], 10, 10, 1.375), "Sentinel"),
    }
    for name, body in files.items():
        (BRAND / name).write_text(body)
    # 8 favicon: the tile (dark square keeps the mark visible on light and dark browser chrome)
    (OUT / "favicon.svg").write_text(files["sentinel-tile.svg"])


# ---- raster (favicon.ico, touch icon) ---------------------------------------------------------------------------
def _hex(c: str) -> tuple[int, int, int]:
    c = c.lstrip("#")
    return tuple(int(c[i:i + 2], 16) for i in (0, 2, 4))


def raster(size: int, color: str, tile: bool = True):
    from PIL import Image, ImageDraw
    ss = 8
    S = size * ss
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    if tile:
        d.rounded_rectangle([0, 0, S - 1, S - 1], radius=int(S * 15 / 64), fill=_hex(TILE) + (255,), outline=_hex(TILE_LINE) + (255,), width=max(1, int(S * 1.5 / 64)))
        off, sc = S * 10 / 64, S * 44 / 64 / 32
    else:
        off, sc = S * 0.04, S * 0.92 / 32
    mask = Image.new("L", (S, S), 0)
    m = ImageDraw.Draw(mask)
    w = int(STROKE * sc)
    for poly in (POLY_A, POLY_B):
        pts = [(off + x * sc, off + y * sc) for x, y in poly]
        m.line(pts, fill=255, width=w, joint="curve")
        for px, py in (pts[0], pts[-1]):
            m.ellipse([px - w / 2, py - w / 2, px + w / 2, py + w / 2], fill=255)
    for cx, cy, r in NODES:
        x, y, rr = off + cx * sc, off + cy * sc, r * sc
        m.ellipse([x - rr, y - rr, x + rr, y + rr], fill=255)
    g = Image.new("RGBA", (S, S), _hex(color) + (255,))
    img.paste(g, (0, 0), mask)
    return img.resize((size, size), Image.LANCZOS)


def write_rasters() -> None:
    raster(180, COLORS["sentinel"]).save(OUT / "apple-touch-icon.png")
    raster(512, COLORS["sentinel"]).save(BRAND / "sentinel-icon-512.png")
    ico = raster(256, COLORS["sentinel"])
    ico.save(OUT / "favicon.ico", sizes=[(16, 16), (32, 32), (48, 48), (64, 64)])


if __name__ == "__main__":
    write_svgs()
    write_rasters()
    print("written:", sorted(p.name for p in BRAND.iterdir()), "+ favicon.svg, favicon.ico, apple-touch-icon.png")
