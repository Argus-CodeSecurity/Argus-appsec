"""Diff-aware scanning must never silently drop findings when git cannot answer."""

from __future__ import annotations

import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

from argus.analysis.diff_scan import DiffError, resolve_diff
from argus.core.models import Finding, Location, ScanResult, Severity
from argus.remediation import git_ops
from argus.remediation.pr_review import _unquote_path, changed_lines, parse_changed_lines

pytestmark = pytest.mark.skipif(not git_ops.git_available(), reason="git not installed")


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)


def _repo(root: Path) -> Path:
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "t@example.com")
    _git(root, "config", "user.name", "T")
    _git(root, "config", "commit.gpgsign", "false")
    return root


def _commit(root: Path, files: dict[str, str], msg: str) -> None:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", msg)


def _finding(path: str, line: int) -> Finding:
    return Finding(
        id=f"r:{path}:{line}", rule_id="r", scanner="patterns", title="t",
        description="", location=Location(path=path, start_line=line),
        severity=Severity.HIGH,
    )


def test_unknown_ref_raises_instead_of_empty_scope(tmp_path):
    root = _repo(tmp_path)
    _commit(root, {"app.py": "a = 1\n"}, "init")
    with pytest.raises(DiffError, match="cannot resolve"):
        resolve_diff(root, "origin/does-not-exist...HEAD")


def test_option_like_ref_is_rejected(tmp_path):
    root = _repo(tmp_path)
    _commit(root, {"app.py": "a = 1\n"}, "init")
    with pytest.raises(DiffError):
        resolve_diff(root, "--output=x")


def test_no_changes_is_an_empty_scope_not_an_error(tmp_path):
    root = _repo(tmp_path)
    _commit(root, {"app.py": "a = 1\n"}, "init")
    scope = resolve_diff(root, "HEAD")
    assert scope.empty


def test_subdirectory_paths_are_project_relative(tmp_path):
    root = _repo(tmp_path)
    _commit(root, {"svc/app.py": "a = 1\n", "other.py": "x = 1\n"}, "init")
    _commit(root, {"svc/app.py": "a = 1\nb = 2\n", "other.py": "x = 2\n"}, "change")
    scope = resolve_diff(root / "svc", "HEAD~1...HEAD")
    assert scope.changed_lines == {"app.py": {2}}


def test_non_ascii_paths_are_not_quoted(tmp_path):
    root = _repo(tmp_path)
    _commit(root, {"café.py": "a = 1\n"}, "init")
    _commit(root, {"café.py": "a = 1\nb = 2\n"}, "change")
    scope = resolve_diff(root, "HEAD~1")
    assert "café.py" in scope.changed_files


def test_unquote_git_c_style_path():
    assert _unquote_path('"b/caf\\303\\251 \\"x\\".py"') == 'b/café "x".py'
    assert _unquote_path("b/plain.py") == "b/plain.py"


def test_parse_ignores_unicode_line_separators_in_content():
    # A content line holding U+2028 must not be split into a fake hunk header.
    diff = (
        "+++ b/a.py\n"
        "@@ -0,0 +1 @@\n"
        "+x = ' @@ -1 +500,3 @@'\n"
    )
    assert parse_changed_lines(diff) == {"a.py": {1}}


def test_pr_review_changed_lines_tolerates_bad_ref(tmp_path):
    root = _repo(tmp_path)
    _commit(root, {"app.py": "a = 1\n"}, "init")
    assert changed_lines(root, "nope") == {}


def test_cli_keeps_all_findings_when_diff_fails(tmp_path):
    from argus.cli.main import _apply_diff

    root = _repo(tmp_path)
    _commit(root, {"app.py": "a = 1\n"}, "init")
    result = ScanResult(target=str(root), started_at=datetime.now(timezone.utc),
                        findings=[_finding("app.py", 1), _finding("lib.py", 3)])
    _apply_diff(result, root, "origin/missing...HEAD", quiet=True)
    assert len(result.findings) == 2


def test_non_utf8_content_in_diff_does_not_crash(tmp_path):
    root = _repo(tmp_path)
    (root / "latin.py").write_bytes(b"a = 1\n")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "init")
    (root / "latin.py").write_bytes(b"a = 1\nb = '\xe9\xff'\n")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "latin-1")
    scope = resolve_diff(root, "HEAD~1")
    assert scope.changed_lines == {"latin.py": {2}}


def test_refs_that_look_like_options_are_rejected(tmp_path):
    root = _repo(tmp_path)
    _commit(root, {"app.py": "a = 1\n"}, "init")
    assert git_ops.rev_parse(root, "--all") is None
    assert git_ops.show_file(root, "--output=pwned", "app.py") is None
    assert not (root / "pwned").exists()
    assert git_ops.show_file(root, "HEAD", "app.py") == "a = 1\n"


def test_git_timeout_raises_git_error(tmp_path, monkeypatch):
    def hang(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="git", timeout=1)

    monkeypatch.setattr(git_ops.subprocess, "run", hang)
    with pytest.raises(git_ops.GitError, match="timed out"):
        git_ops.diff(tmp_path, "HEAD")
