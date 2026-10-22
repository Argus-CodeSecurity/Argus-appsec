"""`argus fix` git workflow: branch base, rollback, identity, hooks, redaction."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from argus.core.models import Finding, Location, Severity
from argus.core.project import Project
from argus.remediation import git_ops
from argus.remediation.hosting import redact_credentials
from argus.remediation.pullrequest import FixOptions, run_fix_workflow

pytestmark = pytest.mark.skipif(not git_ops.git_available(), reason="git not installed")

ID = ("-c", "user.name=Setup", "-c", "user.email=setup@example.com",
      "-c", "commit.gpgsign=false")


def _git(root: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(root), *args], check=True,
                          capture_output=True, text=True).stdout.strip()


@pytest.fixture
def isolated_git(tmp_path, monkeypatch):
    """Hide the machine's global/system git config (identity, hooks path)."""
    empty = tmp_path / "empty.gitconfig"
    empty.write_text("", encoding="utf-8")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(empty))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for var in ("GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL",
                "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL"):
        monkeypatch.delenv(var, raising=False)


def _repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "a.py").write_text("import yaml\nx = yaml.load(s)\n", encoding="utf-8")
    _git(root, "init", "-q", "-b", "main")
    _git(root, "config", "commit.gpgsign", "false")
    _git(root, *ID, "add", "-A")
    _git(root, *ID, "commit", "-qm", "init")
    return root


def _finding() -> Finding:
    return Finding(
        id="f1", rule_id="patterns.python-yaml-load", scanner="patterns",
        title="yaml.load", description="",
        location=Location(path="a.py", start_line=2), severity=Severity.HIGH)


def test_refuses_when_head_is_not_base(tmp_path, isolated_git):
    root = _repo(tmp_path)
    _git(root, "checkout", "-q", "-b", "feature")
    (root / "b.py").write_text("y = 1\n", encoding="utf-8")
    _git(root, *ID, "add", "-A")
    _git(root, *ID, "commit", "-qm", "feature work")
    outcome = run_fix_workflow(Project.from_path(root), [_finding()],
                               FixOptions(base="main"))
    assert outcome.error and "--base feature" in outcome.error
    assert not outcome.committed
    assert _git(root, "rev-parse", "--abbrev-ref", "HEAD") == "feature"


def test_force_branch_resets_stale_branch_to_base(tmp_path, isolated_git):
    root = _repo(tmp_path)
    _git(root, "checkout", "-q", "-b", "argus/security-fixes")
    (root / "stale.py").write_text("old = 1\n", encoding="utf-8")
    _git(root, *ID, "add", "-A")
    _git(root, *ID, "commit", "-qm", "stale")
    _git(root, "checkout", "-q", "main")
    outcome = run_fix_workflow(Project.from_path(root), [_finding()],
                               FixOptions(force_branch=True))
    assert outcome.committed, outcome.error
    assert _git(root, "rev-parse", "HEAD~1") == _git(root, "rev-parse", "main")
    assert not (root / "stale.py").exists()


def test_failure_restores_tree_and_branch(tmp_path, isolated_git, monkeypatch):
    root = _repo(tmp_path)

    def boom(*args, **kwargs):
        raise git_ops.GitError("simulated commit failure")

    monkeypatch.setattr(git_ops, "commit", boom)
    f = _finding()
    outcome = run_fix_workflow(Project.from_path(root), [f], FixOptions())
    assert outcome.error and "simulated" in outcome.error
    assert _git(root, "status", "--porcelain") == ""
    assert _git(root, "rev-parse", "--abbrev-ref", "HEAD") == "main"
    assert not git_ops.branch_exists(root, "argus/security-fixes")
    assert "yaml.load(s)" in (root / "a.py").read_text(encoding="utf-8")
    assert "remediation_applied" not in f.metadata


def test_commit_keeps_configured_identity(tmp_path, isolated_git):
    root = _repo(tmp_path)
    _git(root, "config", "user.name", "Real Dev")
    _git(root, "config", "user.email", "dev@example.com")
    outcome = run_fix_workflow(Project.from_path(root), [_finding()], FixOptions())
    assert outcome.committed, outcome.error
    assert _git(root, "log", "-1", "--format=%an <%ae>") == "Real Dev <dev@example.com>"


def test_commit_falls_back_to_argus_identity(tmp_path, isolated_git):
    root = _repo(tmp_path)
    outcome = run_fix_workflow(Project.from_path(root), [_finding()], FixOptions())
    assert outcome.committed, outcome.error
    assert _git(root, "log", "-1", "--format=%an <%ae>") == "Argus <argus@localhost>"


def test_commit_hooks_run_unless_opted_out(tmp_path, isolated_git):
    root = _repo(tmp_path)
    hook = root / ".git" / "hooks" / "pre-commit"
    hook.write_text("#!/bin/sh\necho blocked by hook >&2\nexit 1\n", encoding="utf-8")
    hook.chmod(0o755)
    outcome = run_fix_workflow(Project.from_path(root), [_finding()], FixOptions())
    assert not outcome.committed
    assert outcome.error and "blocked by hook" in outcome.error
    assert _git(root, "status", "--porcelain") == ""

    outcome = run_fix_workflow(Project.from_path(root), [_finding()],
                               FixOptions(no_verify=True))
    assert outcome.committed, outcome.error


def test_redact_credentials_strips_userinfo():
    url = "https://x-access-token:ghp_secret123@github.com/o/r.git"
    assert redact_credentials(url) == "https://github.com/o/r.git"
    msg = "fatal: unable to access 'https://user:pw@gitlab.com/o/r/': 403"
    assert "pw" not in redact_credentials(msg)
    assert redact_credentials("git@github.com:o/r.git") == "git@github.com:o/r.git"
