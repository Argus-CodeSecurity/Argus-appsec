"""Chart geometry, computed in Python, rendered as plain SVG in the templates.

No charting library: a security dashboard's visuals are a risk trend line and
severity bars, both of which are a few lines of SVG. Colors come from the
validated data-viz status palette (see ``SEVERITY``), each always shown with its
label so meaning is never carried by color alone.
"""

from __future__ import annotations

from typing import Any

# Severity -> (label, fill). Fills are the validated status palette; Low/Info use
# the categorical blue / muted ink so all five steps stay CVD-distinct.
SEVERITY: dict[int, dict[str, str]] = {
    4: {"label": "Critical", "fill": "#d03b3b"},
    3: {"label": "High", "fill": "#ec835a"},
    2: {"label": "Medium", "fill": "#fab219"},
    1: {"label": "Low", "fill": "#2a78d6"},
    0: {"label": "Info", "fill": "#898781"},
}
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
_LABEL_FILL = {v["label"]: v["fill"] for v in SEVERITY.values()}


def severity_fill(label_or_value: str | int) -> str:
    if isinstance(label_or_value, int):
        return SEVERITY.get(label_or_value, SEVERITY[0])["fill"]
    return _LABEL_FILL.get(label_or_value, "#898781")


def risk_band(score: float) -> str:
    """Coarse label for a 0-100 aggregate risk score."""
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    if score > 0:
        return "Low"
    return "None"


def trend_geometry(scans: list[Any], width: int = 720, height: int = 200, pad: int = 32) -> dict:
    """Points/paths for a risk-over-time line, plus per-point hover data."""
    plot_w = width - 2 * pad
    plot_h = height - 2 * pad
    n = len(scans)
    dots = []
    for i, s in enumerate(scans):
        x = pad + (plot_w * (i / (n - 1)) if n > 1 else plot_w / 2)
        y = pad + plot_h * (1 - min(max(s.risk_score, 0), 100) / 100)
        dots.append(
            {
                "x": round(x, 1),
                "y": round(y, 1),
                "risk": round(s.risk_score, 1),
                "when": s.created_at.strftime("%Y-%m-%d %H:%M"),
                "findings": s.total_findings,
            }
        )
    polyline = " ".join(f"{d['x']},{d['y']}" for d in dots)
    area = ""
    if dots:
        base = height - pad
        area = (
            f"M {dots[0]['x']},{base} "
            + " ".join(f"L {d['x']},{d['y']}" for d in dots)
            + f" L {dots[-1]['x']},{base} Z"
        )
    gridlines = []
    for t in (0, 25, 50, 75, 100):
        y = pad + plot_h * (1 - t / 100)
        gridlines.append({"y": round(y, 1), "label": str(t)})
    return {
        "width": width,
        "height": height,
        "pad": pad,
        "polyline": polyline,
        "area": area,
        "dots": dots,
        "gridlines": gridlines,
    }


def severity_bar(counts: dict[str, int], total: int) -> list[dict]:
    """Segments for a single stacked severity bar (percent widths)."""
    total = total or 1
    segments = []
    for label in SEVERITY_ORDER:
        n = counts.get(label, 0)
        if n:
            segments.append(
                {
                    "label": label,
                    "count": n,
                    "pct": round(100 * n / total, 2),
                    "fill": severity_fill(label),
                }
            )
    return segments
