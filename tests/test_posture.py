"""Tests for security posture summary."""

from __future__ import annotations

from datetime import datetime, timezone

from argus.core.models import Finding, Location, ScanResult, Severity
from argus.reporting.posture import PostureStatus, evaluate_posture


def _finding(sev: Severity) -> Finding:
    return Finding(
        id="1",
        rule_id="test.rule",
        scanner="patterns",
        title="Test",
        description="Test finding",
        location=Location(path="a.py", start_line=1),
        severity=sev,
    )


def _result(*findings: Finding) -> ScanResult:
    return ScanResult(
        target="app",
        started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        findings=list(findings),
    )


def test_clean_scan():
    summary = evaluate_posture(_result(), Severity.HIGH)
    assert summary.status == PostureStatus.CLEAN
    assert summary.critical == 0


def test_fail_on_high_gate():
    summary = evaluate_posture(_result(_finding(Severity.HIGH)), Severity.HIGH)
    assert summary.status == PostureStatus.FAIL
    assert "Does not meet" in summary.headline


def test_pass_with_only_medium():
    summary = evaluate_posture(_result(_finding(Severity.MEDIUM)), Severity.HIGH)
    assert summary.status == PostureStatus.PASS
