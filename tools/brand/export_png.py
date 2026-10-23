"""Render the PNG variants of the Nephilex logo from the generated SVGs.

Needs PyMuPDF (``pip install pymupdf``), used only by this maintainer tool.

Run from the repository root after ``make_logo.py``:
    python tools/brand/export_png.py
"""

from __future__ import annotations

from pathlib import Path

import pymupdf

BRAND = Path(__file__).resolve().parents[2] / "docs" / "assets" / "brand"
NAVY = (14 / 255, 23 / 255, 38 / 255)


def _svg_page(name: str) -> pymupdf.Document:
    return pymupdf.open("pdf", pymupdf.open(str(BRAND / name)).convert_to_pdf())


def render_square(svg: str, size: int, out: str) -> None:
    doc = pymupdf.open()
    page = doc.new_page(width=size, height=size)
    page.show_pdf_page(pymupdf.Rect(0, 0, size, size), _svg_page(svg), 0)
    page.get_pixmap(alpha=True).save(str(BRAND / out))


def render_social(out: str) -> None:
    """GitHub social preview: 1280x640, the wordmark centred on navy (offset for its right margin)."""
    doc = pymupdf.open()
    page = doc.new_page(width=1280, height=640)
    page.draw_rect(page.rect, color=None, fill=NAVY)
    page.show_pdf_page(
        pymupdf.Rect(200, 170, 1200, 420), _svg_page("nephilex-wordmark-dark.svg"), 0
    )
    page.get_pixmap(alpha=False).save(str(BRAND / out))


def main() -> None:
    for size in (16, 32, 64, 128, 256, 512):
        name = "nephilex-favicon.svg" if size <= 32 else "nephilex-mark.svg"
        render_square(name, size, f"nephilex-{size}.png")
    render_social("nephilex-social-preview.png")
    for path in sorted(BRAND.glob("*.png")):
        print("wrote", path)


if __name__ == "__main__":
    main()
