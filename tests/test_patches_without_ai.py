"""--patches attaches Argus's deterministic fixes even with --no-ai."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from argus.cli.main import app
from argus.core.config import Config
from argus.core.engine import ScanEngine
from argus.core.models import ScanResult
from argus.core.project import Project

runner = CliRunner()
CODE = "import hashlib\nimport yaml\n\n\ndef load(s):\n    return yaml.load(s)\n"


def _scan(root: Path, *, patches: bool, ai: bool) -> ScanResult:
    cfg = Config(scanners=["patterns"], cache=False, generate_patches=patches)
    cfg.ai.enabled = ai
    return ScanEngine(cfg).scan(Project.from_path(root))


def _yaml(result: ScanResult):
    return next(f for f in result.findings if f.rule_id == "patterns.python-yaml-load")


def test_no_ai_with_patches_attaches_a_verified_fix(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(CODE, encoding="utf-8")
    finding = _yaml(_scan(tmp_path, patches=True, ai=False))
    assert finding.remediation is not None
    assert finding.remediation.patch and "yaml.safe_load" in finding.remediation.patch
    assert finding.remediation.verified is True
    assert finding.metadata["patch_source"] == "deterministic"
    assert "patch_review" not in finding.metadata  # not a model-proposed draft


def test_no_ai_without_patches_attaches_nothing(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(CODE, encoding="utf-8")
    finding = _yaml(_scan(tmp_path, patches=False, ai=False))
    assert finding.remediation is None or not finding.remediation.patch


def test_findings_without_a_rewrite_are_left_alone(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(CODE, encoding="utf-8")
    without = {f.id: f for f in _scan(tmp_path, patches=False, ai=False).findings}
    with_patches = _scan(tmp_path, patches=True, ai=False).findings
    for f in with_patches:
        if f.rule_id == "patterns.python-yaml-load":
            continue
        assert f.remediation == without[f.id].remediation
        assert "patch_source" not in f.metadata


def test_cli_scan_no_ai_patches(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(CODE, encoding="utf-8")
    res = runner.invoke(
        app,
        ["scan", str(tmp_path), "-s", "patterns", "--no-ai", "--patches", "-f", "json", "-q"],
    )
    assert res.exit_code == 0, res.output
    result = ScanResult.model_validate_json(res.stdout)
    finding = _yaml(result)
    assert finding.remediation is not None and finding.remediation.verified is True
