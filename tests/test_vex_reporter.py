"""Tests for the OpenVEX reporter.

VEX statements describe exploitability of vulnerable dependencies. A reachable
CVE is 'affected'; one whose package is never imported is 'not_affected' with the
standard justification (the formal expression of the reachability analysis). SAST
findings, which are not about third-party components, are omitted.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from nephilex.analysis import reachability
from nephilex.core.models import Finding, Location, ScanResult, Severity
from nephilex.core.plugin import registry


def _result(findings: list[Finding]) -> ScanResult:
    r = ScanResult(
        target="/proj",
        started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        nephilex_version="0.7.0",
    )
    r.findings = findings
    return r


def _dep_finding(reach: str | None = None) -> Finding:
    meta = {"cve": "CVE-2024-0001", "fixed_version": "2.0.2", "installed_version": "2.0.1"}
    if reach is not None:
        meta["reachability"] = reach
    return Finding(
        id="d",
        rule_id="dependencies.OSV-1",
        scanner="dependencies",
        title="Vulnerable dependency: flask 2.0.1 (CVE-2024-0001)",
        description="d",
        location=Location(path="requirements.txt", snippet="flask==2.0.1"),
        severity=Severity.HIGH,
        tags=["dependency", "PyPI"],
        metadata=meta,
    )


def _render(findings):
    return json.loads(registry.get_reporter("vex")().render(_result(findings)))


def test_vex_document_shape():
    doc = _render([_dep_finding()])
    assert doc["@context"].startswith("https://openvex.dev/")
    assert doc["author"] and doc["version"] == 1 and doc["timestamp"]
    assert doc["@id"]  # stable, derived from target + timestamp


def test_reachable_cve_is_affected_with_action():
    st = _render([_dep_finding()])["statements"][0]
    assert st["vulnerability"]["name"] == "CVE-2024-0001"
    assert st["products"][0]["@id"] == "pkg:pypi/flask@2.0.1"
    assert st["status"] == "affected"
    assert "2.0.2" in st["action_statement"]


def test_unreachable_cve_is_not_affected_with_justification():
    st = _render([_dep_finding(reach=reachability.NOT_IMPORTED)])["statements"][0]
    assert st["status"] == "not_affected"
    assert st["justification"] == "vulnerable_code_not_in_execute_path"


def test_non_cve_findings_are_omitted():
    sast = Finding(
        id="s",
        rule_id="patterns.python-shell-true",
        scanner="patterns",
        title="shell=True",
        description="d",
        location=Location(path="a.py", start_line=1),
        severity=Severity.HIGH,
    )
    assert _render([sast])["statements"] == []


def test_duplicate_cve_product_pairs_collapse():
    doc = _render([_dep_finding(), _dep_finding()])
    assert len(doc["statements"]) == 1
