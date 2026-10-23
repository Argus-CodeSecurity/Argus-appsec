"""Inline review comments use repository-relative paths for subdirectory scans."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from nephilex.core.models import Finding, Location, Severity
from nephilex.remediation import git_ops, pr_review

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is required")


def _git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=Test", "-c", "user.email=test@example.com", *args],
        cwd=root,
        check=True,
        capture_output=True,
    )


def _finding(path: str, line: int) -> Finding:
    return Finding(
        id=f"patterns.python-yaml-load:{path}:{line}",
        rule_id="patterns.python-yaml-load",
        scanner="patterns",
        title="Unsafe yaml.load",
        description="yaml.load on untrusted input can construct arbitrary objects.",
        severity=Severity.HIGH,
        location=Location(path=path, start_line=line),
    )


def test_subdirectory_scan_comments_on_repository_paths(tmp_path):
    service = tmp_path / "services" / "api"
    service.mkdir(parents=True)
    _git(tmp_path, "init", "-q", "-b", "main")
    (service / "app.py").write_text("x = 1\n", encoding="utf-8")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-q", "-m", "base")
    (service / "app.py").write_text("x = 1\ndata = yaml.load(body)\n", encoding="utf-8")
    _git(tmp_path, "commit", "-q", "-am", "change")

    prefix = git_ops.path_prefix(service)
    assert prefix == "services/api/"

    changed = pr_review.changed_lines(service, "HEAD~1")
    inline, leftover = pr_review.split_comments([_finding("app.py", 2)], changed, prefix)

    assert leftover == []
    assert [c["path"] for c in inline] == ["services/api/app.py"]


def test_repository_root_scan_has_no_prefix(tmp_path):
    _git(tmp_path, "init", "-q", "-b", "main")
    assert git_ops.path_prefix(tmp_path) == ""
