"""The file walk respects .gitignore for untracked files, never for tracked ones."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from argus.cli.main import app
from argus.core import gitexec
from argus.core.config import Config, ConfigError
from argus.core.engine import ScanEngine
from argus.core.project import Project, git_ignored_paths

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")

_SECRET = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, text=True)


def _write(root: Path, rel: str, text: str = "x = 1\n") -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _repo(root: Path) -> Path:
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "t@example.com")
    _git(root, "config", "user.name", "Test")
    _git(root, "config", "core.autocrlf", "false")
    return root


def _commit(root: Path, *paths: str) -> None:
    _git(root, "add", "-f", "--", *paths)
    _git(root, "commit", "-q", "-m", "commit")


def _names(project: Project) -> list[str]:
    return [f.rel_path for f in project.files()]


def test_untracked_ignored_files_are_skipped(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    _write(root, ".gitignore", "out/\n.claude/\n*.log\nlocal.env\n")
    _write(root, "src/app.py")
    _commit(root, ".gitignore", "src/app.py")
    _write(root, "src/new.py")  # untracked, not ignored: scanned
    _write(root, "out/bundle.js", "var a = 1;\n")
    _write(root, ".claude/settings.local.json", "{}\n")
    _write(root, "debug.log", "x\n")
    _write(root, "local.env", _SECRET)
    assert _names(Project.from_path(root)) == [".gitignore", "src/app.py", "src/new.py"]


def test_tracked_files_are_scanned_even_when_gitignore_matches(tmp_path: Path) -> None:
    # A hostile pull request commits code and an ignore pattern covering it.
    root = _repo(tmp_path)
    _write(root, "app.py", _SECRET)
    _write(root, "lib/util.py")
    _write(root, ".gitignore", "*\n")
    _commit(root, "app.py", "lib/util.py", ".gitignore")
    _write(root, "untracked.py")  # ignored by "*" and untracked: skipped
    assert _names(Project.from_path(root)) == [".gitignore", "app.py", "lib/util.py"]

    cfg = Config(scanners=["secrets"])
    cfg.ai.enabled = False
    cfg.cache = False
    result = ScanEngine(cfg).scan(Project.from_path(root))
    assert any(f.location.path == "app.py" for f in result.findings)


def test_ignored_directory_with_a_tracked_file_keeps_the_tracked_file(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    _write(root, ".gitignore", "out/\n")
    _write(root, "out/keep.py")
    _commit(root, ".gitignore", "out/keep.py")
    _write(root, "out/generated.py")
    assert _names(Project.from_path(root)) == [".gitignore", "out/keep.py"]


def test_include_ignored_restores_the_full_walk(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    _write(root, ".gitignore", "out/\nlocal.env\n")
    _commit(root, ".gitignore")
    _write(root, "out/bundle.js", "var a = 1;\n")
    _write(root, "local.env", _SECRET)
    project = Project.from_path(root, include_ignored=True)
    assert _names(project) == [".gitignore", "local.env", "out/bundle.js"]


def test_config_key_and_engine_copy(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    _write(root, ".gitignore", "local.env\n")
    _commit(root, ".gitignore")
    _write(root, "local.env", _SECRET)
    assert Config.from_dict({"include_ignored": True}).include_ignored is True
    assert Config().include_ignored is False
    with pytest.raises(ConfigError):
        Config.from_dict({"include_ignored": "yes"})

    project = Project.from_path(root)
    assert _names(project) == [".gitignore"]  # caches the git-aware walk
    for include, expected in ((False, False), (True, True)):
        cfg = Config(scanners=["secrets"], include_ignored=include, cache=False)
        cfg.ai.enabled = False
        result = ScanEngine(cfg).scan(project)
        found = any(f.location.path == "local.env" for f in result.findings)
        assert found is expected


def test_cli_include_ignored_flag(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    _write(root, ".gitignore", "local.env\n")
    _commit(root, ".gitignore")
    _write(root, "local.env", _SECRET)
    runner = CliRunner()
    args = ["scan", str(root), "-s", "secrets", "-f", "json", "-q", "--no-cache", "--no-ai"]
    default = runner.invoke(app, args)
    assert default.exit_code == 0, default.output
    assert "local.env" not in default.stdout
    included = runner.invoke(app, [*args, "--include-ignored"])
    assert included.exit_code == 0, included.output
    assert "local.env" in included.stdout


def test_not_a_repository_walks_everything(tmp_path: Path) -> None:
    _write(tmp_path, ".gitignore", "*.py\n")
    _write(tmp_path, "app.py")
    assert git_ignored_paths(tmp_path) is None
    assert _names(Project.from_path(tmp_path)) == [".gitignore", "app.py"]


def test_git_missing_falls_back_to_the_walk(tmp_path: Path, monkeypatch) -> None:
    root = _repo(tmp_path)
    _write(root, ".gitignore", "local.env\n")
    _write(root, "local.env", _SECRET)
    monkeypatch.setattr(gitexec, "git_available", lambda: False)
    assert git_ignored_paths(root) is None
    assert _names(Project.from_path(root)) == [".gitignore", "local.env"]


def test_ignored_project_root_is_walked(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    _write(root, ".gitignore", "scratch/\n")
    _commit(root, ".gitignore")
    _write(root, "scratch/a.py")
    _write(root, "scratch/b.py")
    # The operator named the ignored directory explicitly: scan it.
    assert _names(Project.from_path(root / "scratch")) == ["a.py", "b.py"]


def test_subdirectory_target_uses_paths_relative_to_it(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    _write(root, ".gitignore", "*.gen.py\n")
    _write(root, "pkg/mod.py")
    _commit(root, ".gitignore", "pkg/mod.py")
    _write(root, "pkg/mod.gen.py")
    assert _names(Project.from_path(root / "pkg")) == ["mod.py"]


def test_git_runs_with_the_untrusted_profile(tmp_path: Path, monkeypatch) -> None:
    root = _repo(tmp_path)
    seen: list[object] = []
    real = gitexec.run

    def spy(*args, **kwargs):
        seen.append(kwargs.get("profile"))
        return real(*args, **kwargs)

    monkeypatch.setattr(gitexec, "run", spy)
    git_ignored_paths(root)
    assert seen == [gitexec.UNTRUSTED]
