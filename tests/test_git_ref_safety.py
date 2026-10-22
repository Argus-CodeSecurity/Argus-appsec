"""Git refs and working-tree manifests used by the dependency diff are untrusted."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

import argus.inventory as inventory
from argus.core.config import Config
from argus.core.plugin import ScannerContext
from argus.core.project import Project
from argus.inventory import collect_packages_at_ref, resolve_commit
from argus.scanners.dependency_diff import DependencyDiffScanner

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True, text=True
    ).stdout.strip()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "t@example.com")
    _git(tmp_path, "config", "user.name", "T")
    (tmp_path / "requirements.txt").write_text("django==4.2\n", encoding="utf-8")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-q", "-m", "one")
    (tmp_path / "requirements.txt").write_text("django==5.0\n", encoding="utf-8")
    _git(tmp_path, "commit", "-q", "-am", "two")
    return tmp_path


@pytest.mark.parametrize("ref", ["--output=pwned.txt", "-p", " --all", "", "a\nb"])
def test_option_like_refs_are_rejected(repo, ref):
    with pytest.raises(ValueError):
        resolve_commit(repo, ref)
    assert not (repo / "pwned.txt").exists()


def test_unknown_ref_is_an_error(repo):
    with pytest.raises(ValueError):
        resolve_commit(repo, "no-such-branch")


def test_ref_resolves_to_commit_sha(repo):
    sha = resolve_commit(repo, "HEAD~1")
    assert sha == _git(repo, "rev-parse", "HEAD~1")
    assert collect_packages_at_ref(repo, "HEAD~1") == [
        ("PyPI", "requirements.txt", "django", "4.2")
    ]


def test_scanner_refuses_injected_ref(repo):
    cfg = Config(
        scanner_options={"dependency-diff": {"ref": "--output=pwned.txt...HEAD", "behavior": False}}
    )
    ctx = ScannerContext(project=Project.from_path(repo), config=cfg)
    with pytest.raises(ValueError):
        list(DependencyDiffScanner().scan(ctx))
    assert not (repo / "pwned.txt").exists()


def test_oversized_worktree_manifest_is_skipped(repo, monkeypatch):
    monkeypatch.setattr(inventory, "MAX_TEXT_BYTES", 5)
    assert collect_packages_at_ref(repo, "WORKTREE") == []


def test_worktree_manifest_symlink_is_skipped(repo, tmp_path_factory):
    outside = tmp_path_factory.mktemp("outside") / "reqs.txt"
    outside.write_text("flask==2.0\n", encoding="utf-8")
    target = repo / "requirements.txt"
    target.unlink()
    try:
        os.symlink(outside, target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not available")
    assert collect_packages_at_ref(repo, "WORKTREE") == []


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFOs on this platform")
def test_worktree_manifest_fifo_is_skipped(repo):
    target = repo / "requirements.txt"
    target.unlink()
    os.mkfifo(target)
    assert collect_packages_at_ref(repo, "WORKTREE") == []
