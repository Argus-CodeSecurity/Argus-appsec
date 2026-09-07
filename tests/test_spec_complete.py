"""Tests for spec-completion modules."""

from __future__ import annotations

from pathlib import Path

from argus.analysis.risk_engine import enrich_contextual_risk
from argus.analysis.security_graph import build_security_graph
from argus.analysis.verification import assign_verification_state
from argus.core.models import Finding, Location, ScanResult, Severity
from argus.exceptions import FindingException, apply_exceptions
from argus.intel.reevaluation import reevaluate_intel
from argus.plugins.signing import plugin_allowed, verify_plugin_entry
from argus.profiles import apply_profile
from datetime import datetime, timezone


def _finding(scanner: str = "patterns") -> Finding:
    return Finding(
        id="t:1", rule_id="t", scanner=scanner, title="t", description="d",
        location=Location(path="a.py", snippet="bad()"), severity=Severity.HIGH,
    )


def test_security_graph_builds():
    r = ScanResult(target=".", started_at=datetime.now(timezone.utc), findings=[_finding()])
    r.project_summary = {"languages": ["python"], "frameworks": ["fastapi"]}
    g = build_security_graph(r)
    assert g["nodes"]
    assert "internet" in g["trust_boundaries"]


def test_contextual_risk_enrichment():
    r = ScanResult(target=".", started_at=datetime.now(timezone.utc), findings=[_finding()])
    r.project_summary = {"live_target": "https://example.com"}
    enrich_contextual_risk(r)
    assert r.findings[0].metadata.get("contextual_risk", 0) > 0


def test_verification_states():
    f = _finding("dast")
    f.metadata["finding_kind"] = "dynamic"
    assert assign_verification_state(f) == "verified"


def test_exceptions_suppress():
    f = _finding()
    fp = f.fingerprint()
    kept, n = apply_exceptions([f], [FindingException(fp, "suppress", "ok", "owner")])
    assert n == 1
    assert kept == []


def test_reevaluation_intel():
    hits = reevaluate_intel(
        known_packages=[{"name": "bad-pkg", "ecosystem": "pypi"}],
        malicious_intel={"pypi:bad-pkg"},
        targets_by_package={"pypi:bad-pkg": ["prod"]},
    )
    assert hits and hits[0].severity == "critical"


def test_plugin_allowlist(monkeypatch):
    monkeypatch.setenv("ARGUS_PLUGIN_ALLOWLIST", "trusted")
    assert plugin_allowed("trusted") is True
    assert plugin_allowed("other") is False


def test_business_logic_on_corpus():
    from argus.core.config import Config
    from argus.core.engine import ScanEngine
    from argus.core.project import Project

    root = Path(__file__).parent / "corpus"
    root.mkdir(exist_ok=True)
    (root / "logic.py").write_text(
        'price = request.args.get("price")\n', encoding="utf-8",
    )
    p = Project.from_path(root)
    cfg = Config.load(project_root=root)
    cfg.scanners = ["business-logic"]
    r = ScanEngine(cfg).scan(p)
    assert any("logic.price" in f.rule_id for f in r.findings)


def test_junit_reporter():
    from argus.reporting.junit import JUnitReporter

    r = ScanResult(target=".", started_at=datetime.now(timezone.utc), findings=[_finding()])
    xml = JUnitReporter().render(r)
    assert "<testsuite" in xml and "failure" in xml


def test_deep_profile_includes_new_scanners():
    scanners = apply_profile("deep")
    assert "business-logic" in scanners
    assert "git-security" in scanners
    assert "dast" in scanners
