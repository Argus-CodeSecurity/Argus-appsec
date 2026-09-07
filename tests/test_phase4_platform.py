"""Phase 4 drift detection tests."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from argus.analysis.drift import compare_inventories, compare_scans, highest_added_severity
from argus.core.models import Finding, Location, ScanResult, Severity


def _scan(target: str, *findings: Finding) -> ScanResult:
    return ScanResult(
        target=target,
        started_at=datetime.now(timezone.utc),
        argus_version="0.8.0",
        findings=list(findings),
    )


def _f(rule: str, path: str = "a.py", line: int = 1, sev=Severity.HIGH) -> Finding:
    return Finding(
        id=f"x:{rule}", rule_id=rule, scanner="patterns", title=rule,
        description="", location=Location(path=path, start_line=line, snippet="bad()"),
        severity=sev,
    )


def test_compare_scans_detects_added_and_removed():
    before = _scan("v1", _f("r1", line=1))
    after = _scan("v2", _f("r2", line=2))
    report = compare_scans(before, after)
    assert len(report.added) == 1
    assert report.added[0].rule_id == "r2"
    assert len(report.removed) == 1
    assert report.removed[0].rule_id == "r1"


def test_compare_scans_severity_change():
    before = _scan("v1", _f("r1", sev=Severity.LOW))
    after = _scan("v2", _f("r1", sev=Severity.HIGH))
    report = compare_scans(before, after)
    assert not report.added
    assert len(report.severity_changed) == 1


def test_compare_inventories_dependency_change():
    before = {"target": "a", "dependencies": [{"ecosystem": "pypi", "name": "flask", "version": "2.0"}]}
    after = {"target": "b", "dependencies": [{"ecosystem": "pypi", "name": "flask", "version": "3.0"}]}
    drift = compare_inventories(before, after)
    assert drift["summary"]["deps_changed"] == 1


def test_highest_added_severity():
    before = _scan("v1")
    after = _scan("v2", _f("r1", sev=Severity.CRITICAL))
    report = compare_scans(before, after)
    assert highest_added_severity(report) == Severity.CRITICAL


def test_drift_cli_registered():
    import typer
    from argus.cli.main import app

    cmds = typer.main.get_command(app).commands
    assert "drift" in cmds
    assert "watch" in cmds


def test_enterprise_policy_pack_loads():
    from pathlib import Path
    import yaml
    from argus.policy.engine import load_policies

    path = Path(__file__).resolve().parents[1] / "examples" / "policies" / "enterprise.yml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    policies = load_policies(data)
    ids = {p["id"] for p in policies}
    assert "block-critical" in ids
    assert "block-secrets" in ids
    assert len(policies) >= 6
