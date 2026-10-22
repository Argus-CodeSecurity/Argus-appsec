"""Audience views: same findings, re-rendered for dev / exec / auditor."""

from __future__ import annotations

from datetime import datetime, timezone

from argus.core.models import Finding, Location, Remediation, ScanResult, Severity
from argus.reporting.audience import render_for_audience


def _result() -> ScanResult:
    r = ScanResult(
        target="/proj", started_at=datetime(2026, 1, 1, tzinfo=timezone.utc), argus_version="0.7.0"
    )
    r.findings = [
        Finding(
            id="1",
            rule_id="patterns.sqli",
            scanner="patterns",
            title="SQL injection",
            description="d",
            location=Location(path="a.py", start_line=5),
            severity=Severity.CRITICAL,
            cwe=["CWE-89"],
            owasp=["A03:2021-Injection"],
            why_vulnerable="Untrusted input reaches a database query.",
            business_impact="Full database compromise and data exfiltration.",
            remediation=Remediation(summary="Use parameterized queries."),
        ),
    ]
    return r


def test_exec_view_is_business_focused_without_code():
    out = render_for_audience(_result(), "exec")
    assert "Risk score" in out and "database compromise" in out
    assert "Fix:" not in out  # execs do not need the fix command


def test_auditor_view_shows_taxonomy():
    out = render_for_audience(_result(), "auditor")
    assert "By CWE" in out and "CWE-89" in out
    assert "A03:2021-Injection" in out
    assert "no runtime/DAST testing" in out  # honest coverage caveat


def test_dev_view_shows_fix_and_docs():
    out = render_for_audience(_result(), "dev")
    assert "Fix:" in out and "parameterized" in out
    assert "Docs:" in out and "https://" in out


def test_unknown_audience_defaults_to_dev():
    assert render_for_audience(_result(), "mystery") == render_for_audience(_result(), "dev")
