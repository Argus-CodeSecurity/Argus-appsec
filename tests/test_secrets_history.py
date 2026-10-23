"""Git-history secret scanning: catch a credential committed and later deleted."""

from __future__ import annotations

import shutil
import subprocess

import pytest

from nephilex.core.config import Config
from nephilex.core.plugin import ScannerContext
from nephilex.core.project import Project
from nephilex.scanners.secrets import SecretsScanner


def _git(root, *args):
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, text=True)


def _repo_with_deleted_secret(tmp_path):
    if not shutil.which("git"):
        pytest.skip("git not available")
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "t@example.com")
    _git(tmp_path, "config", "user.name", "Test")
    # Commit a file that contains a secret.
    (tmp_path / "config.py").write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-q", "-m", "add config")
    # Remove the secret in a later commit, so the working tree is clean.
    (tmp_path / "config.py").write_text('AWS_KEY = os.environ["AWS_KEY"]\n', encoding="utf-8")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-q", "-m", "move secret to env")
    return tmp_path


def _run_secrets(project, *, history: bool):
    cfg = Config(scanner_options={"secrets": {"history": True} if history else {}})
    return list(SecretsScanner().scan(ScannerContext(project=project, config=cfg, ai=None)))


def test_working_tree_scan_misses_deleted_secret(tmp_path):
    project = Project.from_path(_repo_with_deleted_secret(tmp_path))
    findings = _run_secrets(project, history=False)
    assert not any("AKIA" in (f.location.snippet or "") for f in findings)
    assert not any("history" in f.rule_id for f in findings)


def test_history_scan_finds_deleted_secret(tmp_path):
    project = Project.from_path(_repo_with_deleted_secret(tmp_path))
    findings = _run_secrets(project, history=True)
    hist = [f for f in findings if f.rule_id == "secrets.history.aws-access-key-id"]
    assert hist, "the deleted AWS key should be found in git history"
    # It must guide the user to rotate, not just delete.
    assert "rotate" in hist[0].remediation.summary.lower()


def test_history_scan_is_noop_without_git(tmp_path):
    # A plain directory (not a git repo) yields no history findings and no crash.
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    findings = _run_secrets(Project.from_path(tmp_path), history=True)
    assert not any("history" in f.rule_id for f in findings)
