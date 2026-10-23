"""Cloning untrusted repos: hardened git flags, bounded size/time, no leaked temp dirs."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

import nephilex.targets as targets


class _FakeGit:
    """Stand-in for subprocess.Popen running `git clone`."""

    def __init__(self, behaviour: str) -> None:
        self.behaviour = behaviour
        self.cmd: list[str] = []
        self.env: dict[str, str] = {}
        self.killed = False
        self.returncode: int | None = None

    def __call__(self, cmd, **kwargs):
        self.cmd = list(cmd)
        self.env = kwargs["env"]
        dest = Path(cmd[-1])
        if self.behaviour == "ok":
            (dest / "app.py").write_text("x = 1\n", encoding="utf-8")
            self.returncode = 0
        elif self.behaviour == "fail":
            kwargs["stderr"].write(b"fatal: repository not found")
            self.returncode = 128
        elif self.behaviour == "huge":
            (dest / "blob.bin").write_bytes(b"\0" * 4096)  # keeps "downloading"
        # "hang": never finishes on its own
        return self

    def wait(self, timeout=None):
        if self.returncode is None:
            raise subprocess.TimeoutExpired(self.cmd, timeout)
        return self.returncode

    def poll(self):
        return self.returncode

    def kill(self):
        self.killed = True
        self.returncode = -9


@pytest.fixture
def fake_git(monkeypatch, tmp_path):
    made: list[str] = []
    real_mkdtemp = targets.tempfile.mkdtemp

    def mkdtemp(prefix=""):
        d = real_mkdtemp(prefix=prefix, dir=tmp_path)
        made.append(d)
        return d

    monkeypatch.setattr(targets.tempfile, "mkdtemp", mkdtemp)
    monkeypatch.setattr(targets.shutil, "which", lambda name: "/usr/bin/git")
    monkeypatch.setattr(targets, "_CLONE_POLL_SECONDS", 0.01)

    def install(behaviour: str) -> _FakeGit:
        fake = _FakeGit(behaviour)
        monkeypatch.setattr(targets.subprocess, "Popen", fake)
        return fake

    install.made = made  # type: ignore[attr-defined]
    return install


URL = "https://github.com/example/repo.git"


def test_clone_uses_hardened_flags(fake_git) -> None:
    fake = fake_git("ok")
    resolved = targets.resolve(URL, branch="main")
    try:
        cmd = fake.cmd
        assert cmd[0] == "git"
        for flag in ("--depth", "--single-branch", "--no-tags"):
            assert flag in cmd
        assert "protocol.file.allow=never" in cmd
        assert any(c.startswith("core.hooksPath=") for c in cmd)
        assert cmd[cmd.index("--branch") + 1] == "main"
        assert cmd[-3] == "--" and cmd[-2] == URL
        assert fake.env["GIT_LFS_SKIP_SMUDGE"] == "1"
        assert fake.env["GIT_TERMINAL_PROMPT"] == "0"
        assert resolved.project is not None
        assert resolved.project.origin == "github"
    finally:
        resolved.cleanup()


@pytest.mark.parametrize("behaviour", ["fail", "hang", "huge"])
def test_failed_clone_never_leaks_temp_dir(fake_git, monkeypatch, behaviour) -> None:
    fake = fake_git(behaviour)
    monkeypatch.setattr(targets, "_CLONE_TIMEOUT_SECONDS", 0.05)
    monkeypatch.setattr(targets, "_MAX_CLONE_BYTES", 1024)
    with pytest.raises(RuntimeError):
        targets.resolve(URL)
    assert fake_git.made and not any(Path(d).exists() for d in fake_git.made)
    if behaviour in ("hang", "huge"):
        assert fake.killed


def test_option_like_branch_rejected(fake_git) -> None:
    fake_git("ok")
    with pytest.raises(ValueError):
        targets.resolve(URL, branch="--upload-pack=evil")
