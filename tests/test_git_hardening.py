"""Scanning an untrusted repo must not execute programs named in its .git/config.

A hostile repository controls its own ``.git/config``. Keys such as
``core.fsmonitor`` (run whenever the index is read) and ``gpg.program`` (run by
``log.showSignature``) turn ``git log`` / ``git ls-files`` into code execution on
the scanning host. These tests plant both and check that Argus's git-based
scanners never trigger them.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from argus.scanners import _git

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not available")


def _git_plain(root: Path, *args: str, stdin: str | None = None) -> str:
    # Bytes in/out so Windows text mode does not turn object bodies into CRLF.
    proc = subprocess.run(
        ["git", "-C", str(root), "-c", "commit.gpgsign=false", *args],
        check=True, capture_output=True,
        input=stdin.encode("utf-8") if stdin is not None else None,
    )
    return proc.stdout.decode("utf-8")


_FAKE_SIG = (
    "gpgsig -----BEGIN PGP SIGNATURE-----\n"
    " \n"
    " iQEzBAABCAAdFiEEAAAAAAAAAAAAAAAAAAAAAAAAAAAFAmAAAAAACgkQAAAAAAAAAAAA\n"
    " =AAAA\n"
    " -----END PGP SIGNATURE-----\n"
)


def _hostile_repo(tmp_path: Path) -> tuple[Path, Path]:
    """A repo whose config runs a marker-writing script via fsmonitor and gpg."""
    repo = tmp_path / "repo"
    repo.mkdir()
    marker = tmp_path / "pwned.txt"
    script = tmp_path / "payload.sh"
    script.write_text(f'#!/bin/sh\necho pwned >> "{marker.as_posix()}"\n', encoding="utf-8")
    script.chmod(0o755)

    _git_plain(repo, "init", "-q")
    _git_plain(repo, "config", "user.email", "t@example.com")
    _git_plain(repo, "config", "user.name", "Test")
    (repo / "requirements.txt").write_text("requests==2.0\n", encoding="utf-8")
    (repo / "server.key").write_text("not really a key\n", encoding="utf-8")
    _git_plain(repo, "add", "-A")
    _git_plain(repo, "commit", "-q", "-m", "init")

    # Re-write HEAD as a "signed" commit so log.showSignature has a reason to
    # call gpg.program.
    raw = _git_plain(repo, "cat-file", "commit", "HEAD")
    header, _, message = raw.partition("\n\n")
    signed = header + "\n" + _FAKE_SIG + "\n" + message
    sha = _git_plain(repo, "hash-object", "-t", "commit", "-w", "--stdin", stdin=signed).strip()
    _git_plain(repo, "update-ref", "HEAD", sha)

    payload = script.as_posix()
    _git_plain(repo, "config", "core.fsmonitor", payload)
    _git_plain(repo, "config", "gpg.program", payload)
    _git_plain(repo, "config", "log.showSignature", "true")
    _git_plain(repo, "config", "core.pager", payload)
    _git_plain(repo, "config", "diff.external", payload)
    return repo, marker


def test_payload_fires_without_hardening(tmp_path):
    """Sanity check: the planted config really is dangerous with plain git."""
    repo, marker = _hostile_repo(tmp_path)
    subprocess.run(["git", "-C", str(repo), "ls-files"], capture_output=True)
    subprocess.run(["git", "-C", str(repo), "log", "-1"], capture_output=True)
    if not marker.exists():
        pytest.skip("this git build did not run the planted helpers")
    assert marker.exists()


def test_hardened_runner_does_not_execute_repo_config(tmp_path):
    repo, marker = _hostile_repo(tmp_path)
    assert _git.is_git_repo(repo)
    for args in (("ls-files",), ("log", "-1"), ("log", "-p", "--all"),
                 ("log", "-5", "--name-only", "--", "requirements.txt")):
        res = _git.run_git(repo, *args)
        assert res is not None and res.returncode == 0, args
    assert not marker.exists(), marker.read_text()


def test_git_scanners_do_not_execute_repo_config(tmp_path):
    from argus.core.config import Config
    from argus.core.plugin import ScannerContext
    from argus.core.project import Project
    from argus.scanners.git_security import GitSecurityScanner
    from argus.scanners.secrets_history import find_history_secrets

    repo, marker = _hostile_repo(tmp_path)
    project = Project.from_path(repo)
    ctx = ScannerContext(project=project, config=Config())
    findings = list(GitSecurityScanner().scan(ctx))
    find_history_secrets(repo)

    assert not marker.exists(), marker.read_text()
    # The scanner still works: the tracked key and manifest change are reported.
    rules = {f.rule_id for f in findings}
    assert "git.dangerous-tracked-file" in rules
    assert "git.dependency-manifest-change" in rules


def test_run_git_bounds_output(tmp_path):
    repo, _ = _hostile_repo(tmp_path)
    res = _git.run_git(repo, "log", "-p", "--all", max_output=10)
    assert res is not None and res.truncated and len(res.stdout) == 10


def _plain_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "plain"
    repo.mkdir()
    _git_plain(repo, "init", "-q")
    _git_plain(repo, "config", "user.email", "t@example.com")
    _git_plain(repo, "config", "user.name", "Test")
    return repo


def test_history_keeps_distinct_secrets_with_same_prefix(tmp_path):
    from argus.scanners.secrets_history import find_history_secrets

    repo = _plain_repo(tmp_path)
    (repo / "a.py").write_text('K1 = "AKIAIOSFODNN7EXAMPLE"\nK2 = "AKIAJ2345678ABCDEFGH"\n',
                               encoding="utf-8")
    _git_plain(repo, "add", "-A")
    _git_plain(repo, "commit", "-q", "-m", "keys")
    found, truncated = find_history_secrets(repo)
    aws = [s for s in found if s.rule == "aws-access-key-id"]
    assert len(aws) == 2
    assert len({s.fingerprint for s in aws}) == 2
    assert not truncated


def test_history_survives_non_utf8_content(tmp_path):
    from argus.scanners.secrets_history import find_history_secrets

    repo = _plain_repo(tmp_path)
    (repo / "latin1.txt").write_bytes(b"caf\xe9 \xff\xfe\n")
    (repo / "a.py").write_text('K = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8")
    _git_plain(repo, "add", "-A")
    _git_plain(repo, "commit", "-q", "-m", "mixed encodings")
    found, _ = find_history_secrets(repo)
    assert any(s.rule == "aws-access-key-id" for s in found)


def test_history_reports_truncation(tmp_path, monkeypatch, caplog):
    from argus.scanners import secrets_history

    repo = _plain_repo(tmp_path)
    (repo / "a.py").write_text("x = 1\n" * 200, encoding="utf-8")
    _git_plain(repo, "add", "-A")
    _git_plain(repo, "commit", "-q", "-m", "big")
    monkeypatch.setattr(secrets_history, "_MAX_OUTPUT_BYTES", 100)
    with caplog.at_level("WARNING", logger="argus.scanners.secrets_history"):
        _, truncated = secrets_history.find_history_secrets(repo)
    assert truncated
    assert "only the newest commits" in caplog.text
