"""Tests for `argus learn` (findings rendered as security lessons)."""

from __future__ import annotations

import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from argus.core.models import (
    ExploitScenario,
    Finding,
    Location,
    Remediation,
    ScanResult,
    Severity,
)
from argus.reporting.learn import render_lessons

_FIXTURE = Path(__file__).parent / "fixtures" / "golden_app"


def _result_with_finding() -> ScanResult:
    r = ScanResult(
        target="/proj", started_at=datetime(2026, 1, 1, tzinfo=timezone.utc), argus_version="0.7.0"
    )
    r.findings = [
        Finding(
            id="1",
            rule_id="patterns.python-shell-true",
            scanner="patterns",
            title="Command execution with shell=True",
            description="d",
            location=Location(
                path="app.py", start_line=6, snippet="subprocess.run(cmd, shell=True)"
            ),
            severity=Severity.HIGH,
            cwe=["CWE-78"],
            why_vulnerable="Shell metacharacters in input run extra commands.",
            attacker_perspective="Inject `; rm -rf /` through the argument.",
            exploit=ExploitScenario(exploit_walkthrough="Send host='a; id' to run `id`."),
            remediation=Remediation(summary="Pass an argument list without shell=True."),
        )
    ]
    return r


def test_render_lessons_has_structure():
    out = render_lessons(_result_with_finding())
    assert "Lesson 1:" in out
    assert "Where: app.py:6" in out
    assert "Why it matters:" in out
    assert "How it is exploited:" in out
    assert "Walkthrough:" in out
    assert "How to fix it:" in out
    assert "Learn more: https://" in out


def test_render_lessons_empty():
    r = ScanResult(
        target="/p", started_at=datetime(2026, 1, 1, tzinfo=timezone.utc), argus_version="0.7.0"
    )
    assert "No findings to learn from" in render_lessons(r)


def test_learn_cli_smoke():
    proc = subprocess.run(
        [sys.executable, "-m", "argus", "learn", str(_FIXTURE), "--quiet"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0
    assert "Lesson 1:" in proc.stdout
