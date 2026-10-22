"""Identical lines in one file must stay distinct in drift and GitLab output."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from argus.analysis.drift import compare_scans
from argus.core.models import Finding, Location, ScanResult, Severity
from argus.reporting.gitlab import GitLabReporter


def _f(line: int) -> Finding:
    return Finding(
        id=f"r:{line}",
        rule_id="py.eval",
        scanner="patterns",
        title="eval",
        description="",
        severity=Severity.HIGH,
        location=Location(path="a.py", start_line=line, snippet="eval(x)"),
    )


def _result(*findings: Finding) -> ScanResult:
    return ScanResult(target="t", started_at=datetime.now(timezone.utc), findings=list(findings))


def test_gitlab_ids_are_unique_and_first_keeps_fingerprint():
    a, b = _f(3), _f(9)
    assert a.fingerprint() == b.fingerprint()
    doc = json.loads(GitLabReporter().render(_result(a, b)))
    ids = [v["id"] for v in doc["vulnerabilities"]]
    assert len(set(ids)) == 2
    assert a.fingerprint() in ids and f"{a.fingerprint()}#2" in ids


def test_drift_counts_a_second_identical_finding_as_added():
    report = compare_scans(_result(_f(3)), _result(_f(3), _f(9)))
    assert len(report.added) == 1
    assert report.added[0].fingerprint == _f(3).fingerprint()


def test_drift_counts_a_removed_duplicate():
    report = compare_scans(_result(_f(3), _f(9)), _result(_f(3)))
    assert len(report.removed) == 1 and not report.added
