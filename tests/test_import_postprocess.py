"""Imported findings get the same post-processing as Argus's own (ScanEngine.postprocess)."""

from __future__ import annotations

import inspect
import json
from datetime import datetime, timezone
from pathlib import Path

from argus.core.config import load_project_config
from argus.core.models import Finding, Location, ScanResult, Severity
from argus.core.project import Project
from argus.importers import import_result, merge_into, parse_sarif, pipeline
from argus.importers.sarif import SarifImport


def _doc(results: list) -> dict:
    return {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "T", "rules": []}}, "results": results}],
    }


def _result(uri: str, line: int, rule: str = "R1", **props) -> dict:
    loc = {"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": line}}}
    out: dict = {"ruleId": rule, "message": {"text": "m"}, "locations": [loc], "level": "error"}
    if props:
        out["properties"] = props
    return out


def _imported(root: Path, results: list) -> SarifImport:
    return parse_sarif(_doc(results), project_root=root)


def _records(root: Path) -> list[dict]:
    log = root / ".argus" / "audit.log"
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines() if line]


def _project(root: Path):
    project = Project.from_path(root)
    cfg = load_project_config(project)
    cfg.ai.enabled = False
    return project, cfg


def test_pipeline_uses_only_the_public_postprocess() -> None:
    source = inspect.getsource(pipeline)
    assert "postprocess(" in source
    assert "engine._" not in source and "._apply_" not in source and "._run_agents" not in source


def test_import_applies_context_and_records_suppressions(tmp_path: Path) -> None:
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "run.py").write_text(
        'os.system(a)\nos.system(b)  # argus-ignore reason="constant input"\nos.system(c)\n',
        encoding="utf-8",
    )
    (tmp_path / ".argus").mkdir()
    (tmp_path / ".argus" / "context.yml").write_text(
        "internal_paths: ['scripts/**']\n", encoding="utf-8"
    )
    (tmp_path / ".argus.yml").write_text(
        "allow:\n  - {rule: R3, reason: tool is wrong here}\n", encoding="utf-8"
    )
    project, cfg = _project(tmp_path)
    imported = _imported(
        tmp_path,
        [
            _result("scripts/run.py", 1, "R1"),
            _result("scripts/run.py", 2, "R2"),
            _result("scripts/run.py", 3, "R3"),
        ],
    )
    result = import_result(imported, project, cfg)

    assert [f.rule_id for f in result.findings] == ["t.R1"]
    kept = result.findings[0]
    # context: internal_paths lowers High to Medium and says why
    assert kept.severity is Severity.MEDIUM and "internal" in kept.tags
    assert kept.metadata["context"]["changes"][0]["setting"] == "internal_paths"
    assert result.project_summary["context"]["internal"] == 1
    # audit: the inline comment and the allowlist entry are both recorded
    matched = sorted(
        (r["kind"], r["rule"]) for r in _records(tmp_path) if r["action"] == "suppression.matched"
    )
    assert matched == [("allowlist", "t.R3"), ("inline", "t.R2")]
    assert result.project_summary["audit"]["recorded"] >= 2
    assert result.project_summary["origin"] == "sarif-import"


def test_import_drops_findings_under_exclude_paths(tmp_path: Path) -> None:
    (tmp_path / "vendor_x").mkdir()
    (tmp_path / "vendor_x" / "a.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / ".argus.yml").write_text("exclude_paths: ['vendor_x/**']\n", encoding="utf-8")
    project, cfg = _project(tmp_path)
    imported = _imported(tmp_path, [_result("vendor_x/a.py", 1), _result("app.py", 1)])
    result = import_result(imported, project, cfg)
    assert [f.location.path for f in result.findings] == ["app.py"]


def test_merge_into_folds_duplicates_and_keeps_scan_summary(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("os.system(cmd)\nx = 1\nos.system(y)\n", encoding="utf-8")
    project, cfg = _project(tmp_path)
    native = Finding(
        id="patterns:shell:1",
        rule_id="patterns.python-os-system",
        scanner="patterns",
        title="t",
        description="d",
        location=Location(path="app.py", start_line=1, snippet="os.system(cmd)"),
        severity=Severity.MEDIUM,
        cwe=["CWE-78"],
    )
    scan = ScanResult(target=str(tmp_path), started_at=datetime.now(timezone.utc))
    scan.findings = [native]
    scan.scanners_run = ["patterns"]
    scan.project_summary = {"audit": {"path": ".argus/audit.log", "recorded": 1}}
    imported = _imported(
        tmp_path,
        [
            _result("app.py", 1, "shell", cwe="CWE-78", **{"security-severity": "8.0"}),
            _result("app.py", 3, "other"),
        ],
    )
    merged = merge_into(scan, imported, project, cfg)

    assert merged == 1
    assert native.severity is Severity.HIGH  # raised by the duplicate it absorbed
    assert native.metadata["also_reported_by"][0]["scanner"] == "sarif:t"
    assert sorted(f.rule_id for f in scan.findings) == ["patterns.python-os-system", "t.other"]
    assert scan.scanners_run == ["patterns", "sarif:t"]
    assert scan.project_summary["audit"]["recorded"] == 1  # the scan's own entry is kept
    assert scan.project_summary["imported_sarif"]["merged"] == 1
