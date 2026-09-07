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
        f"Could not resolve target {target!r}. Provide a local path, a git URL, "
        "or a website URL."
    )


def _is_safe_clone_url(url: str) -> bool:
    """Reject transports (ext::, file://, ...) that let a clone execute code."""
    return bool(_SAFE_URL.match(url) or _SCP_LIKE.match(url))


# Maximum cloned repository size (bytes) before the scan is aborted.
_MAX_CLONE_BYTES = 500 * 1024 * 1024  # 500 MiB


def _clone_dir_size(path: Path) -> int:
    total = 0
    for root, _dirs, files in os.walk(path):
        for name in files:
            try:
                total += (Path(root) / name).stat().st_size
            except OSError:
                continue
    return total


def _clone(url: str, *, branch: str | None) -> ResolvedTarget:
    if shutil.which("git") is None:
        raise RuntimeError(
            "git is required to scan a remote repository but was not found on PATH."
        )
    if not _is_safe_clone_url(url):
        raise ValueError(
            f"Refusing to clone {url!r}: only https, http, ssh, and git transports "
            "are allowed."
        )
    tmp = tempfile.mkdtemp(prefix="argus-clone-")
    cmd = ["git", "clone", "--depth", "1"]
    if branch:
        cmd += ["--branch", branch]
    cmd += ["--", url, tmp]
    # Defense in depth: constrain git to the safe transports even if a crafted URL
    # slips past the check above, and stop credential prompts from hanging a scan.
    env = {
        **os.environ,
        "GIT_ALLOW_PROTOCOL": ":".join(_ALLOWED_GIT_PROTOCOLS),
        "GIT_TERMINAL_PROMPT": "0",
    }
    try:
        subprocess.run(
            cmd, check=True, capture_output=True, text=True, timeout=300, env=env
        )
    except subprocess.CalledProcessError as exc:
        shutil.rmtree(tmp, ignore_errors=True)
        raise RuntimeError(f"git clone failed: {exc.stderr.strip()}") from exc

    clone_bytes = _clone_dir_size(Path(tmp))
    if clone_bytes > _MAX_CLONE_BYTES:
        shutil.rmtree(tmp, ignore_errors=True)
        raise RuntimeError(
            f"cloned repository exceeds size limit ({clone_bytes} bytes > "
            f"{_MAX_CLONE_BYTES} bytes)"
        )

    origin = _origin_for(url)
    project = Project.from_path(tmp, origin=origin, origin_url=url,
                                name=_repo_name(url))
    return ResolvedTarget(project=project, _tempdir=tmp)


def _repo_name(url: str) -> str:
    tail = url.rstrip("/").split("/")[-1]
    return tail[:-4] if tail.endswith(".git") else tail
