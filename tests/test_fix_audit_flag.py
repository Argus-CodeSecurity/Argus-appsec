"""`audit_log: false` turns off the fix records of `nephilex fix`, not only the env switch."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from nephilex.audit import AUDIT_PATH
from nephilex.cli.main import app
from nephilex.core.models import Finding, Location, Severity
from nephilex.core.project import Project
from nephilex.remediation import git_ops
from nephilex.remediation.pullrequest import FixOptions, run_fix_workflow

pytestmark = pytest.mark.skipif(not git_ops.git_available(), reason="git not installed")
ID = ("-c", "user.name=Setup", "-c", "user.email=setup@example.com", "-c", "commit.gpgsign=false")


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args], check=True, capture_output=True, text=True
    ).stdout.strip()


def _repo(tmp_path: Path, monkeypatch, config: str | None = None) -> Path:
    empty = tmp_path / "empty.gitconfig"
    empty.write_text("", encoding="utf-8")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(empty))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for var in ("AUTHOR", "COMMITTER"):
        monkeypatch.setenv(f"GIT_{var}_NAME", "Dev")
        monkeypatch.setenv(f"GIT_{var}_EMAIL", "dev@example.com")
    monkeypatch.delenv("NEPHILEX_AUDIT_LOG", raising=False)
    root = tmp_path / "repo"
    root.mkdir()
    (root / "a.py").write_text("import yaml\nx = yaml.load(s)\n", encoding="utf-8")
    if config is not None:
        (root / ".nephilex.yml").write_text(config, encoding="utf-8")
    _git(root, "init", "-q", "-b", "main")
    _git(root, *ID, "add", "-A")
    _git(root, *ID, "commit", "-qm", "init")
    return root


def _actions(root: Path) -> list[str]:
    log = root / AUDIT_PATH
    if not log.exists():
        return []
    return [json.loads(line)["action"] for line in log.read_text(encoding="utf-8").splitlines()]


def _finding() -> Finding:
    return Finding(
        id="f1",
        rule_id="patterns.python-yaml-load",
        scanner="patterns",
        title="t",
        description="",
        location=Location(path="a.py", start_line=2),
        severity=Severity.HIGH,
    )


def test_fix_options_audit_false_writes_no_records(tmp_path: Path, monkeypatch) -> None:
    root = _repo(tmp_path, monkeypatch)
    outcome = run_fix_workflow(Project.from_path(root), [_finding()], FixOptions(audit=False))
    assert outcome.committed, outcome.error
    assert _actions(root) == []
    assert outcome.applied.audit_records == 0


def test_cli_fix_honours_audit_log_false(tmp_path: Path, monkeypatch) -> None:
    root = _repo(tmp_path, monkeypatch, config="audit_log: false\n")
    res = CliRunner().invoke(app, ["fix", str(root), "-s", "patterns", "-q"])
    assert res.exit_code == 0, res.output
    assert "yaml.safe_load" in (root / "a.py").read_text(encoding="utf-8")
    assert _actions(root) == []


def test_cli_fix_records_by_default(tmp_path: Path, monkeypatch) -> None:
    root = _repo(tmp_path, monkeypatch)
    res = CliRunner().invoke(app, ["fix", str(root), "-s", "patterns", "-q"])
    assert res.exit_code == 0, res.output
    assert _actions(root) == ["fix.applied"]
