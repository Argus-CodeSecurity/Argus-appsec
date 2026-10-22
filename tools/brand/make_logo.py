"""Generate the Nephilex logo set as hand-built SVG geometry.

The mark is an orb web: a frame thread the radials anchor to, a capture spiral
drawn as straight segments between radials (as a real orb-weaver builds it),
and a hub set slightly above centre. One radial is picked out in the signal
colour, with a node on it and a pulse ring at the hub: the thread that carries
a vibration back to the spider.

Run from the repository root:
    python tools/brand/make_logo.py

Outputs go to docs/assets/brand/. Re-running is deterministic.
"""

from __future__ import annotations

import math
from pathlib import Path

OUT = Path(__file__).resolve().parents[2] / "docs" / "assets" / "brand"

GOLD = "#E3A63B"
# Deeper gold for thin threads on white, where the bright gold loses contrast.
GOLD_ON_LIGHT = "#B07513"
SIGNAL = "#3CC8C0"
NAVY = "#0E1726"
INK = "#0E1726"
PAPER = "#FFFFFF"
FONT = "Inter, 'Segoe UI', 'Helvetica Neue', Helvetica, Arial, sans-serif"
LINES = 'stroke-linecap="round" stroke-linejoin="round"'


def _web(
    cx: float,
    cy: float,
    radius: float,
    spokes: int,
    rings: list[float],
    thread: float,
    frame: float,
    hub: float,
    signal_spoke: int | None,
    gold: str = "",
) -> str:
    """Return SVG elements for an orb web centred on (cx, cy)."""
    gold = gold or GOLD
    angles = [-math.pi / 2 + (i + 0.5) * 2 * math.pi / spokes for i in range(spokes)]

    def point(i: int, frac: float) -> tuple[float, float]:
        a = angles[i % spokes]
        return cx + radius * frac * math.cos(a), cy + radius * frac * math.sin(a)

    def polygon(frac: float) -> str:
        return " ".join(f"{x:.2f},{y:.2f}" for x, y in (point(i, frac) for i in range(spokes)))

    parts: list[str] = []
    for frac in rings:
        parts.append(
            f'<polygon points="{polygon(frac)}" fill="none" stroke="{gold}" '
            f'stroke-opacity="0.85" stroke-width="{thread:.2f}" {LINES}/>'
        )
    parts.append(
        f'<polygon points="{polygon(1.0)}" fill="none" stroke="{gold}" '
        f'stroke-width="{frame:.2f}" {LINES}/>'
    )
    for i in range(spokes):
        if i == signal_spoke:
            continue
        x, y = point(i, 1.0)
        parts.append(
            f'<line x1="{cx:.2f}" y1="{cy:.2f}" x2="{x:.2f}" y2="{y:.2f}" '
            f'stroke="{gold}" stroke-width="{thread:.2f}" {LINES}/>'
        )
    if signal_spoke is not None:
        x, y = point(signal_spoke, 1.0)
        nx, ny = point(signal_spoke, rings[-1] if rings else 0.7)
        parts.append(
            f'<line x1="{cx:.2f}" y1="{cy:.2f}" x2="{x:.2f}" y2="{y:.2f}" '
            f'stroke="{SIGNAL}" stroke-width="{thread * 1.6:.2f}" {LINES}/>'
        )
        parts.append(
            f'<circle cx="{cx:.2f}" cy="{cy:.2f}" r="{hub * 1.9:.2f}" fill="none" '
            f'stroke="{SIGNAL}" stroke-width="{thread * 1.2:.2f}"/>'
        )
        parts.append(f'<circle cx="{nx:.2f}" cy="{ny:.2f}" r="{hub * 0.62:.2f}" fill="{SIGNAL}"/>')
    parts.append(f'<circle cx="{cx:.2f}" cy="{cy:.2f}" r="{hub:.2f}" fill="{gold}"/>')
    return "\n  ".join(parts)


def _svg(width: int, height: int, body: str) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        f'width="{width}" height="{height}" role="img" aria-label="Nephilex">\n'
        f"  <title>Nephilex</title>\n  {body}\n</svg>\n"
    )


def mark(size: int = 512, *, background: bool = True, simple: bool = False) -> str:
    """The square mark. ``simple`` drops detail for favicon sizes."""
    s = size
    gold = GOLD if background else GOLD_ON_LIGHT
    cx, cy = s / 2, s * 0.485  # the hub sits a little above centre, as in a real orb web
    if simple:
        web = _web(cx, cy, s * 0.38, 8, [0.5], s * 0.05, s * 0.06, s * 0.085, 1, gold)
    else:
        web = _web(cx, cy, s * 0.37, 12, [0.34, 0.6, 0.82], s * 0.014, s * 0.02, s * 0.04, 1, gold)
    bg = (
        f'<rect width="{s}" height="{s}" rx="{s * 0.22:.1f}" fill="{NAVY}"/>\n  '
        if background
        else ""
    )
    return _svg(s, s, bg + web)


def wordmark(*, dark: bool) -> str:
    """Mark plus the name, for README headers and the docs site."""
    w, h = 1200, 300
    text = PAPER if dark else INK
    sub = "#9AA7BD" if dark else "#5B6678"
    bg = f'<rect width="{w}" height="{h}" rx="28" fill="{NAVY}"/>\n  ' if dark else ""
    web = _web(
        150, 150, 104, 12, [0.34, 0.6, 0.82], 3.0, 4.4, 9.5, 1, GOLD if dark else GOLD_ON_LIGHT
    )
    words = (
        f'<text x="300" y="168" font-family="{FONT}" font-size="124" font-weight="700" '
        f'letter-spacing="-2" fill="{text}">nephilex</text>\n'
        f'  <text x="304" y="226" font-family="{FONT}" font-size="34" font-weight="500" '
        f'letter-spacing="1" fill="{sub}">Application security that feels every thread</text>'
    )
    return _svg(w, h, bg + web + "\n  " + words)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    files = {
        "nephilex-mark.svg": mark(512),
        "nephilex-mark-transparent.svg": mark(512, background=False),
        "nephilex-favicon.svg": mark(64, simple=True),
        "nephilex-wordmark-dark.svg": wordmark(dark=True),
        "nephilex-wordmark-light.svg": wordmark(dark=False),
    }
    for name, svg in files.items():
        (OUT / name).write_text(svg, encoding="utf-8", newline="\n")
        print("wrote", OUT / name)


if __name__ == "__main__":
    main()
