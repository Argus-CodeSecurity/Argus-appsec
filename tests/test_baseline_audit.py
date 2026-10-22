"""--baseline records the findings it hides in the audit log (trusted local projects)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from typer.testing import CliRunner

from argus.cli._common import apply_baseline
from argus.cli.main import app
from argus.core.config import Config
from argus.core.models import Finding, Location, ScanResult
from argus.core.project import Project

runner = CliRunner()
_CODE = "import yaml\n\n\ndef load(s):\n    return yaml.load(s)\n"


def _records(root: Path) -> list[dict]:
    log = root / ".argus" / "audit.log"
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines() if line]


def _baseline_kinds(root: Path) -> list[tuple[str, str]]:
    return [(r["action"], r["rule"] or "") for r in _records(root) if r["kind"] == "baseline"]


def _scan(root: Path, *extra: str):
    args = ["scan", str(root), "-s", "patterns", "--no-ai", "--no-cache", "-q", *extra]
    return runner.invoke(app, args)


def test_scan_baseline_is_recorded(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(_CODE, encoding="utf-8")
    report = tmp_path.parent / f"{tmp_path.name}-baseline.json"
    first = _scan(tmp_path, "-f", "json", "-o", str(report))
    assert first.exit_code == 0, first.output
    assert _baseline_kinds(tmp_path) == []

    second = _scan(tmp_path, "--baseline", str(report), "-f", "json")
    assert second.exit_code == 0, second.output
    assert _baseline_kinds(tmp_path) == [
        ("suppression.added", ""),
        ("suppression.matched", "patterns.python-yaml-load"),
    ]
    # Recorded once per content: the same baseline again adds nothing.
    _scan(tmp_path, "--baseline", str(report), "-f", "json")
    assert len(_baseline_kinds(tmp_path)) == 2


def test_audit_log_false_disables_baseline_records(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(_CODE, encoding="utf-8")
    (tmp_path / ".argus.yml").write_text("audit_log: false\n", encoding="utf-8")
    report = tmp_path.parent / f"{tmp_path.name}-baseline.json"
    _scan(tmp_path, "-f", "json", "-o", str(report))
    res = _scan(tmp_path, "--baseline", str(report), "-f", "json")
    assert res.exit_code == 0, res.output
    assert _records(tmp_path) == []


def _hidden_result(tmp_path: Path) -> tuple[ScanResult, Path]:
    f = Finding(
        id="x",
        rule_id="patterns.python-yaml-load",
        scanner="patterns",
        title="t",
        description="",
        location=Location(path="app.py", start_line=5, snippet="return yaml.load(s)"),
    )
    baseline = tmp_path.parent / f"{tmp_path.name}-b.json"
    known = ScanResult(target=str(tmp_path), started_at=datetime.now(timezone.utc), findings=[f])
    baseline.write_text(known.model_dump_json(), encoding="utf-8")
    result = ScanResult(target=str(tmp_path), started_at=datetime.now(timezone.utc))
    result.findings = [f.model_copy()]
    return result, baseline


def test_untrusted_or_remote_projects_are_not_recorded(tmp_path: Path) -> None:
    result, baseline = _hidden_result(tmp_path)
    untrusted = Config(trust_project_config=False)
    apply_baseline(result, baseline, quiet=True, project=Project.from_path(tmp_path), cfg=untrusted)
    assert result.findings == []
    assert _records(tmp_path) == []

    result, baseline = _hidden_result(tmp_path)
    remote = Project.from_path(tmp_path, origin="github")
    apply_baseline(
        result, baseline, quiet=True, project=remote, cfg=Config(trust_project_config=True)
    )
    assert result.findings == []
    assert _records(tmp_path) == []


def test_trusted_local_project_is_recorded(tmp_path: Path) -> None:
    result, baseline = _hidden_result(tmp_path)
    trusted = Config(trust_project_config=True)
    apply_baseline(result, baseline, quiet=True, project=Project.from_path(tmp_path), cfg=trusted)
    assert [r["action"] for r in _records(tmp_path)] == [
        "suppression.added",
        "suppression.matched",
    ]
