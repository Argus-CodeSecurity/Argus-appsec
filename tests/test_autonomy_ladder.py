"""Tests for the autonomy ladder (Rung 3): auto-tier fix classification + gating."""

from __future__ import annotations

from pathlib import Path

from argus.core.config import Config
from argus.core.engine import ScanEngine
from argus.core.project import Project
from argus.remediation.applier import apply_fixes
from argus.remediation.pullrequest import FixOptions, run_fix_workflow
from argus.remediation.rewrites import AUTO_APPLY, auto_apply_rules


def test_default_auto_set_is_conservative():
    # The built-in auto set is small and excludes behavior-changing rewrites.
    assert "patterns.python-yaml-load" in AUTO_APPLY
    assert "patterns.flask-debug-true" in AUTO_APPLY
    for risky in (
        "patterns.weak-hash-md5-sha1",
        "patterns.python-shell-true",
        "patterns.tls-verify-disabled",
        "llm.torch-load-pickle",
    ):
        assert risky not in AUTO_APPLY


def test_auto_apply_rules_graduate_and_demote():
    assert auto_apply_rules(None) == set(AUTO_APPLY)

    cfg = Config.from_dict(
        {
            "autofix": {
                "graduate": ["patterns.weak-hash-md5-sha1"],
                "demote": ["patterns.flask-debug-true"],
            }
        }
    )
    rules = auto_apply_rules(cfg)
    assert "patterns.weak-hash-md5-sha1" in rules  # graduated in
    assert "patterns.flask-debug-true" not in rules  # demoted out
    assert "patterns.python-yaml-load" in rules  # still default


def _project_with_two_fixables(tmp_path: Path) -> Project:
    (tmp_path / "a.py").write_text(
        "import yaml, hashlib\n"
        "def load(s):\n"
        "    return yaml.load(s)\n"
        "def h(b):\n"
        "    return hashlib.md5(b).hexdigest()\n",
        encoding="utf-8",
    )
    return Project.from_path(tmp_path)


def test_apply_fixes_only_rules_applies_just_the_auto_tier(tmp_path: Path):
    project = _project_with_two_fixables(tmp_path)
    result = ScanEngine(Config()).scan(project)

    report = apply_fixes(project, result.findings, only_rules={"patterns.python-yaml-load"})

    text = (tmp_path / "a.py").read_text(encoding="utf-8")
    assert "safe_load" in text  # the auto-tier yaml fix was applied
    assert "hashlib.md5" in text  # the non-auto md5 fix was NOT applied
    assert report.fixes and all(f.rule_id == "patterns.python-yaml-load" for f in report.fixes)


def test_fix_workflow_auto_dry_run_scopes_to_auto_tier(tmp_path: Path):
    project = _project_with_two_fixables(tmp_path)
    result = ScanEngine(Config()).scan(project)

    outcome = run_fix_workflow(
        project,
        result.findings,
        FixOptions(dry_run=True, only_rules=auto_apply_rules(None)),
    )
    fixed_rules = {f.rule_id for f in outcome.applied.fixes}
    assert fixed_rules == {"patterns.python-yaml-load"}  # md5 excluded from auto
    assert any("Auto-tier" in m for m in outcome.messages)
    # Dry run must not touch the file.
    assert "safe_load" not in (tmp_path / "a.py").read_text(encoding="utf-8")
