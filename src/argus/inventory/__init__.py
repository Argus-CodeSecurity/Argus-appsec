"""Dependency inventory helpers shared by SBOM, SCA, and diff analysis."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

from argus.core.project import MAX_TEXT_BYTES
from argus.scanners.dependencies import _PARSERS, collect_packages, safe_parse

__all__ = [
    "collect_packages", "collect_packages_at_ref", "resolve_commit", "split_ref_spec",
]

# Seconds allowed for one git call while reading manifests at a ref.
_GIT_TIMEOUT = 60.0


def split_ref_spec(ref_spec: str, *, head: str = "HEAD") -> tuple[str, str]:
    """Split ``base...head`` or bare base ref into ``(base, head)``."""
    spec = ref_spec.strip()
    if "..." in spec:
        base, h = spec.split("...", 1)
        return base.strip(), (h.strip() or head)
    return spec, head


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[bytes] | None:
    """Run git with an argument list and a timeout; None if it cannot run."""
    if shutil.which("git") is None:
        return None
    try:
        return subprocess.run(
            ["git", "-C", str(root), *args],
            capture_output=True, timeout=_GIT_TIMEOUT, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None


def resolve_commit(root: Path, ref: str) -> str:
    """Resolve a user-supplied ref to a full commit SHA.

    ``ref`` comes from scanner options (and so from a CLI flag or a config file).
    A value such as ``--output=/tmp/x`` would otherwise be read by git as an
    option, so refs starting with ``-`` are rejected outright, and the ref is
    resolved with ``rev-parse --verify --end-of-options`` so it can only ever be
    a revision. Callers then use the returned SHA, never the raw string.

    Raises ValueError for a rejected or unknown ref.
    """
    ref = ref.strip()
    if not ref or ref.startswith("-") or any(c in ref for c in "\0\n\r"):
        raise ValueError(f"invalid git ref: {ref!r}")
    proc = _git(root, "rev-parse", "--verify", "--quiet", "--end-of-options",
                f"{ref}^{{commit}}")
    sha = proc.stdout.decode("ascii", "replace").strip() if proc is not None else ""
    if proc is None or proc.returncode != 0 or not _is_sha(sha):
        raise ValueError(f"unknown git ref: {ref!r}")
    return sha


def _is_sha(value: str) -> bool:
    return len(value) in (40, 64) and all(c in "0123456789abcdef" for c in value)


def _read_at_commit(root: Path, sha: str, rel_path: str) -> str | None:
    """Contents of ``rel_path`` at commit ``sha``, or None (absent or too large)."""
    spec = f"{sha}:{rel_path}"
    size = _git(root, "cat-file", "-s", spec)
    if size is None or size.returncode != 0:
        return None
    try:
        if int(size.stdout.strip() or b"0") > MAX_TEXT_BYTES:
            return None
    except ValueError:
        return None
    blob = _git(root, "cat-file", "blob", spec)
    if blob is None or blob.returncode != 0:
        return None
    return blob.stdout.decode("utf-8", errors="replace")


def _read_worktree_manifest(path: Path) -> str | None:
    """Read a manifest from the working tree, refusing anything but a small file.

    The scanned tree is untrusted: a manifest that is a symlink (to /dev/zero, a
    huge file, or something outside the repo) or a FIFO would otherwise make
    read_text() exhaust memory or block forever.
    """
    try:
        st = os.lstat(path)
    except OSError:
        return None
    if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_TEXT_BYTES:
        return None
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_TEXT_BYTES + 1)
    except OSError:
        return None
    if len(data) > MAX_TEXT_BYTES:
        return None
    return data.decode("utf-8", errors="replace")


def collect_packages_at_ref(root: Path, ref: str) -> list[tuple[str, str, str, str]]:
    """Collect ``(ecosystem, manifest_path, package, version)`` at a git ref.

    ``HEAD`` and ``WORKTREE`` read the root manifests from the working tree, so
    uncommitted edits are included. Any other ref is resolved to a commit SHA
    first (see :func:`resolve_commit`, which raises ValueError for a bad ref)
    and the manifests are read from that commit.
    """
    sha = None if ref in ("HEAD", "WORKTREE") else resolve_commit(root, ref)
    per_eco: dict[str, dict[tuple[str, str], tuple[str, str, str]]] = {}
    for manifest_name, (ecosystem, parser) in _PARSERS.items():
        if sha is None:
            text = _read_worktree_manifest(root / manifest_name)
        else:
            text = _read_at_commit(root, sha, manifest_name)
        if not text:
            continue
        for pkg, version in safe_parse(parser, text, f"{manifest_name}@{ref}"):
            bucket = per_eco.setdefault(ecosystem, {})
            bucket.setdefault((pkg, version), (manifest_name, pkg, version))
    out: list[tuple[str, str, str, str]] = []
    for ecosystem, bucket in per_eco.items():
        for path, pkg, version in bucket.values():
            out.append((ecosystem, path, pkg, version))
    out.sort(key=lambda t: (t[0], t[2], t[3], t[1]))
    return out
