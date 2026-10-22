"""Target resolution: turn a user-supplied target into a local Project.

Argus accepts several kinds of target:

* a local path,
* a Git remote (GitHub / GitLab / Bitbucket / any ``git`` URL), which is shallow-
  cloned into a temporary directory,
* a deployed website URL, handled by :class:`WebTarget` for the (optional) dynamic
  layer rather than the filesystem scanners.

``resolve`` returns either a :class:`~argus.core.project.Project` (for anything on
disk) or a :class:`WebTarget`. Callers that only do static analysis can require a
Project. Cleanup of any temporary clone is the caller's responsibility via the
returned :class:`ResolvedTarget`.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from argus.core.project import Project

_GIT_URL = re.compile(r"^(https?://|git@)")
_HOST_ORIGIN = {
    "github.com": "github",
    "gitlab.com": "gitlab",
    "bitbucket.org": "bitbucket",
}

# Only these transports are ever handed to `git clone`. Git supports others,
# notably ``ext::`` and ``file://``, that can execute arbitrary commands during
# a clone. Because Argus is routinely pointed at untrusted repositories, we allow
# an explicit safe set and also constrain git itself via GIT_ALLOW_PROTOCOL.
_ALLOWED_GIT_PROTOCOLS = ("https", "http", "ssh", "git")
_SAFE_URL = re.compile(r"^(?:https?|ssh|git)://", re.IGNORECASE)
_SCP_LIKE = re.compile(r"^[A-Za-z0-9._-]+@[A-Za-z0-9._-]+:")  # git@host:owner/repo


@dataclass
class WebTarget:
    """A deployed application URL, input to the dynamic (DAST) layer."""

    url: str

    @property
    def name(self) -> str:
        return urlparse(self.url).netloc or self.url


@dataclass
class ResolvedTarget:
    project: Project | None = None
    web: WebTarget | None = None
    _tempdir: str | None = None

    def cleanup(self) -> None:
        if self._tempdir:
            shutil.rmtree(self._tempdir, ignore_errors=True)
            self._tempdir = None


def _looks_like_web_app(url: str) -> bool:
    """A plain http(s) URL that is not a git repo is treated as a web target."""
    if not url.startswith(("http://", "https://")):
        return False
    return not (url.endswith(".git") or "/tree/" in url or _is_repo_host(url))


def _is_repo_host(url: str) -> bool:
    host = urlparse(url).netloc.lower()
    return host in _HOST_ORIGIN


def _origin_for(url: str) -> str:
    host = urlparse(url).netloc.lower()
    return _HOST_ORIGIN.get(host, "git")


def resolve(target: str, *, branch: str | None = None) -> ResolvedTarget:
    """Resolve a target string into a Project or WebTarget."""
    # 1. Local path
    path = Path(target)
    if path.exists():
        return ResolvedTarget(project=Project.from_path(path))

    # 2. Deployed website
    if _looks_like_web_app(target):
        return ResolvedTarget(web=WebTarget(url=target))

    # 3. Git remote
    if _GIT_URL.match(target) or _is_repo_host(target):
        return _clone(target, branch=branch)

    raise ValueError(
        f"Could not resolve target {target!r}. Provide a local path, a git URL, or a website URL."
    )


def _is_safe_clone_url(url: str) -> bool:
    """Reject transports (ext::, file://, ...) that let a clone execute code."""
    return bool(_SAFE_URL.match(url) or _SCP_LIKE.match(url))


# Maximum cloned repository size (bytes) before the scan is aborted.
_MAX_CLONE_BYTES = 500 * 1024 * 1024  # 500 MiB
# Wall-clock limit for the clone, and how often its size is checked.
_CLONE_TIMEOUT_SECONDS = 300
_CLONE_POLL_SECONDS = 1.0


def _clone_dir_size(path: Path) -> int:
    total = 0
    for root, _dirs, files in os.walk(path):
        for name in files:
            try:
                total += (Path(root) / name).stat().st_size
            except OSError:
                continue
    return total


def _clone_command(url: str, branch: str | None, dest: str) -> list[str]:
    """The hardened ``git clone`` invocation for an untrusted repository."""
    cmd = [
        "git",
        # Never run hooks (a user/global template could install some), never
        # use local-file or ext:: transports (also for submodules), and keep
        # fsmonitor (a configurable command) off.
        "-c",
        f"core.hooksPath={os.devnull}",
        "-c",
        "protocol.file.allow=never",
        "-c",
        "protocol.ext.allow=never",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "submodule.recurse=false",
        "clone",
        "--depth",
        "1",
        "--single-branch",
        "--no-tags",
    ]
    if branch:
        cmd += ["--branch", branch]
    return [*cmd, "--", url, dest]


def _clone_env() -> dict[str, str]:
    # Defense in depth: constrain git to the safe transports even if a crafted URL
    # slips past the URL check, stop credential prompts from hanging a scan, and
    # do not download Git LFS objects (they can be arbitrarily large and are not
    # source code).
    return {
        **os.environ,
        "GIT_ALLOW_PROTOCOL": ":".join(_ALLOWED_GIT_PROTOCOLS),
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_LFS_SKIP_SMUDGE": "1",
    }


def _run_clone(cmd: list[str], dest: Path) -> None:
    """Run the clone, enforcing the timeout and size limit while it runs.

    Checking the size only after the clone finished meant the whole oversized
    repository had already been downloaded and written to disk. Polling the
    destination lets us stop the transfer once it crosses the limit.
    """
    with tempfile.TemporaryFile() as errf:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=errf,
            env=_clone_env(),
        )
        deadline = time.monotonic() + _CLONE_TIMEOUT_SECONDS
        try:
            while True:
                try:
                    returncode = proc.wait(timeout=_CLONE_POLL_SECONDS)
                    break
                except subprocess.TimeoutExpired:
                    pass
                if time.monotonic() > deadline:
                    raise RuntimeError(f"git clone timed out after {_CLONE_TIMEOUT_SECONDS}s")
                size = _clone_dir_size(dest)
                if size > _MAX_CLONE_BYTES:
                    raise RuntimeError(
                        f"cloned repository exceeds size limit (over {size} bytes > "
                        f"{_MAX_CLONE_BYTES} bytes); clone aborted"
                    )
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
        if returncode != 0:
            errf.seek(0)
            stderr = errf.read().decode("utf-8", errors="replace").strip()
            raise RuntimeError(f"git clone failed: {stderr}")


def _clone(url: str, *, branch: str | None) -> ResolvedTarget:
    if shutil.which("git") is None:
        raise RuntimeError("git is required to scan a remote repository but was not found on PATH.")
    if not _is_safe_clone_url(url):
        raise ValueError(
            f"Refusing to clone {url!r}: only https, http, ssh, and git transports are allowed."
        )
    if branch is not None and (not branch.strip() or branch.startswith("-")):
        raise ValueError(f"Refusing to clone: invalid branch name {branch!r}")
    tmp = tempfile.mkdtemp(prefix="argus-clone-")
    # Whatever goes wrong (timeout, size limit, git failure, Ctrl+C), never
    # leave a partial clone of an untrusted repository behind.
    try:
        _run_clone(_clone_command(url, branch, tmp), Path(tmp))
        clone_bytes = _clone_dir_size(Path(tmp))
        if clone_bytes > _MAX_CLONE_BYTES:
            raise RuntimeError(
                f"cloned repository exceeds size limit ({clone_bytes} bytes > "
                f"{_MAX_CLONE_BYTES} bytes)"
            )
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise

    origin = _origin_for(url)
    project = Project.from_path(tmp, origin=origin, origin_url=url, name=_repo_name(url))
    return ResolvedTarget(project=project, _tempdir=tmp)


def _repo_name(url: str) -> str:
    tail = url.rstrip("/").split("/")[-1]
    return tail[:-4] if tail.endswith(".git") else tail
