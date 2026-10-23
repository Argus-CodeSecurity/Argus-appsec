"""--config-from-ref: take settings from a trusted git ref, not the checked-out tree."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from nephilex.cli.main import app
from nephilex.core.config import ConfigError, load_config_from_ref, load_project_config
from nephilex.core.project import Project

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")

runner = CliRunner()
_SECRET = 'AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"\n'


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.com",
            "-c",
            "commit.gpgsign=false",
            *args,
        ],
        cwd=repo,
        check=True,
        capture_output=True,
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A repo whose `base` tag has a strict config and whose tree loosens it."""
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q")
    (root / ".nephilex.yml").write_text("fail_on: low\n", encoding="utf-8")
    (root / "ci").mkdir()
    (root / "ci" / "nephilex.yml").write_text("fail_on: high\n", encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "base")
    _git(root, "tag", "base")
    # The "pull request": loosen every in-tree setting and add a secret.
    (root / ".nephilex.yml").write_text(
        'exclude_paths: ["**"]\nexclude_scanners: ["secrets"]\n', encoding="utf-8"
    )
    (root / "ci" / "nephilex.yml").write_text('exclude_paths: ["**"]\n', encoding="utf-8")
    (root / "settings.py").write_text(
        _SECRET.rstrip("\n") + '  # nephilex-ignore reason="trust me"\n', encoding="utf-8"
    )
    return root


def test_reads_config_from_ref_not_tree(repo: Path) -> None:
    cfg = load_project_config(Project.from_path(repo), config_from_ref="base")
    assert cfg.fail_on is not None and cfg.fail_on.label == "Low"
    assert cfg.exclude_paths == []
    assert cfg.trust_project_config is False


def test_explicit_config_path_is_read_from_ref(repo: Path) -> None:
    cfg = load_config_from_ref(repo, "base", repo / "ci" / "nephilex.yml")
    assert cfg.fail_on is not None and cfg.fail_on.label == "High"
    assert cfg.exclude_paths == []


def test_explicit_config_missing_at_ref_is_error(repo: Path) -> None:
    (repo / "new.yml").write_text("fail_on: low\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="does not exist"):
        load_config_from_ref(repo, "base", repo / "new.yml")


def test_explicit_config_outside_repo_is_error(repo: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside.yml"
    outside.write_text("fail_on: low\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="outside the repository"):
        load_config_from_ref(repo, "base", outside)


def test_ref_without_config_gives_untrusted_defaults(repo: Path) -> None:
    _git(repo, "rm", "-q", "--cached", ".nephilex.yml", "ci/nephilex.yml")
    _git(repo, "commit", "-q", "-m", "drop config")
    _git(repo, "tag", "empty")
    cfg = load_config_from_ref(repo, "empty")
    assert cfg.fail_on is None
    assert cfg.trust_project_config is False


@pytest.mark.parametrize("ref", ["", "-c", "--output=/tmp/x", "base:evil.yml", "a b", "ba\nse"])
def test_rejects_unsafe_refs(repo: Path, ref: str) -> None:
    with pytest.raises(ConfigError):
        load_config_from_ref(repo, ref)


def test_unknown_ref_is_error(repo: Path) -> None:
    with pytest.raises(ConfigError, match="cannot resolve"):
        load_config_from_ref(repo, "origin/does-not-exist")


def test_cannot_combine_with_trust_remote(repo: Path) -> None:
    with pytest.raises(ConfigError):
        load_project_config(Project.from_path(repo), config_from_ref="base", trust_remote=True)


def test_scan_gates_with_ref_config_and_ignores_tree_suppressions(repo: Path) -> None:
    res = runner.invoke(
        app,
        [
            "scan",
            str(repo),
            "--config-from-ref",
            "base",
            "--quiet",
            "--no-ai",
            "--no-cache",
            "-f",
            "json",
        ],
    )
    assert res.exit_code == 1, res.output


def test_scan_with_unknown_ref_exits_2(repo: Path) -> None:
    res = runner.invoke(
        app,
        [
            "scan",
            str(repo),
            "--config-from-ref",
            "nope",
            "--quiet",
            "--no-ai",
            "--no-cache",
            "-f",
            "json",
        ],
    )
    assert res.exit_code == 2, res.output
