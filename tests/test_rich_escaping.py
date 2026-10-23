"""`nephilex learn` and audience views must survive Rich markup in finding text."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from rich.console import Console

from nephilex.core.models import Finding, Location, Remediation, ScanResult, Severity
from nephilex.reporting.audience import AUDIENCES, render_for_audience
from nephilex.reporting.learn import render_lessons

NASTY = "[/bold] oops [link=https://evil.example]x[/link] [red]"


def _result() -> ScanResult:
    f = Finding(
        id="x",
        rule_id="r.[/]",
        scanner="patterns",
        title=NASTY,
        description="d",
        location=Location(path="dir\\[x]\\", start_line=1, snippet=NASTY),
        severity=Severity.HIGH,
        cwe=["CWE-[/dim]"],
        why_vulnerable=NASTY,
        attacker_perspective=NASTY,
        business_impact=NASTY,
        remediation=Remediation(summary=NASTY, guidance=NASTY),
    )
    return ScanResult(target="t[/]", started_at=datetime.now(timezone.utc), findings=[f])


def _print(markup: str) -> str:
    console = Console(record=True, width=400, color_system=None)
    console.print(markup)  # raises MarkupError on unbalanced/hostile tags
    return console.export_text()


def test_learn_renders_hostile_text_literally():
    text = _print(render_lessons(_result()))
    assert "[/bold] oops [link=https://evil.example]x[/link] [red]" in text


@pytest.mark.parametrize("audience", AUDIENCES)
def test_audience_views_render_hostile_text_literally(audience):
    text = _print(render_for_audience(_result(), audience))
    assert "[/bold] oops" in text or "r.[/]" in text
