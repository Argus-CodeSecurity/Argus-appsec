"""Tests for the shields.io security-badge reporter."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from nephilex.core.models import Finding, Location, ScanResult, Severity
from nephilex.core.plugin import registry


def _result(*severities: Severity) -> ScanResult:
    r = ScanResult(
        target="/proj",
        started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        nephilex_version="0.7.0",
    )
    r.findings = [
        Finding(
            id=str(i),
            rule_id="r",
            scanner="s",
            title="t",
            description="d",
            location=Location(path="a.py", start_line=1),
            severity=sev,
        )
        for i, sev in enumerate(severities)
    ]
    return r


def _badge(*severities):
    return json.loads(registry.get_reporter("badge")().render(_result(*severities)))


def test_clean_is_brightgreen():
    b = _badge()
    assert b == {
        "schemaVersion": 1,
        "label": "security",
        "message": "no findings",
        "color": "brightgreen",
    }


def test_critical_is_red():
    b = _badge(Severity.CRITICAL, Severity.HIGH)
    assert b["color"] == "red" and "critical" in b["message"]


def test_high_is_orange_when_no_critical():
    b = _badge(Severity.HIGH, Severity.MEDIUM)
    assert b["color"] == "orange" and "high" in b["message"]


def test_medium_is_yellow():
    b = _badge(Severity.MEDIUM)
    assert b["color"] == "yellow"


def test_low_only_is_yellowgreen():
    b = _badge(Severity.LOW, Severity.INFO)
    assert b["color"] == "yellowgreen"
