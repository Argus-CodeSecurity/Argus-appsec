"""A bad --diff ref is a usage error (exit 2 with a message), never a traceback."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from nephilex.cli.main import app

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")

runner = CliRunner()


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "t@example.com")
    _git(tmp_path, "config", "user.name", "T")
    _git(tmp_path, "config", "commit.gpgsign", "false")
    (tmp_path / "requirements.txt").write_text("django==4.2\n", encoding="utf-8")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-q", "-m", "one")
    return tmp_path


COMMANDS = [
    ["dependencies", "--no-behavior"],
    ["supply-chain", "--no-behavior", "--quiet"],
    ["sbom"],
]


@pytest.mark.parametrize("command", COMMANDS, ids=lambda c: c[0])
@pytest.mark.parametrize("ref", ["no-such-branch...HEAD", "--output=pwned.txt"])
def test_bad_diff_ref_exits_2_with_a_message(repo: Path, command: list[str], ref: str) -> None:
    res = runner.invoke(app, [command[0], str(repo), *command[1:], f"--diff={ref}"])
    assert res.exit_code == 2, res.output
    assert isinstance(res.exception, SystemExit)  # no uncaught exception
    assert "Error:" in res.output
    assert "Traceback" not in res.output
    assert not (repo / "pwned.txt").exists()


def test_good_diff_ref_still_works(repo: Path) -> None:
    (repo / "requirements.txt").write_text("django==5.0\n", encoding="utf-8")
    _git(repo, "commit", "-q", "-am", "two")
    res = runner.invoke(app, ["dependencies", str(repo), "--no-behavior", "--diff=HEAD~1"])
    assert res.exit_code == 0, res.output
    assert "django" in res.output
