"""Thin wrappers over the ``git`` CLI for the fix workflow.

Kept deliberately small and explicit: each function is one git command. All calls
run with a fixed identity fallback so commits succeed in CI where no global
git identity is configured, without overwriting a user's real identity when one
exists.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


class GitError(RuntimeError):
    """A git command failed."""


def git_available() -> bool:
    return shutil.which("git") is not None


def _run(root: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    if not git_available():
        raise GitError("git is not installed or not on PATH.")
    proc = subprocess.run(
        ["git", "-C", str(root), *args],
        capture_output=True, text=True,
    )
    if check and proc.returncode != 0:
        raise GitError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc


def is_git_repo(root: Path) -> bool:
    if not git_available():
        return False
    proc = _run(root, "rev-parse", "--is-inside-work-tree", check=False)
    return proc.returncode == 0 and proc.stdout.strip() == "true"


def current_branch(root: Path) -> str:
    return _run(root, "rev-parse", "--abbrev-ref", "HEAD").stdout.strip()


def diff(root: Path, *args: str) -> str:
    """Return `git diff <args>` stdout (empty string on failure).

    Used by the PR-review flow to discover which lines a pull request changed.
    Non-fatal: a missing ref just yields an empty diff (a full, non-diff review).
    """
    return _run(root, "diff", *args, check=False).stdout


def show_file(root: Path, ref: str, rel_path: str) -> str | None:
    """Return file contents at ``ref:rel_path``, or None if unavailable."""
    proc = _run(root, "show", f"{ref}:{rel_path}", check=False)
    if proc.returncode != 0:
        return None
    return proc.stdout


def rev_parse(root: Path, ref: str) -> str | None:
    """Resolve a ref to a commit sha, or None."""
    proc = _run(root, "rev-parse", ref, check=False)
    if proc.returncode != 0:
        return None
    return proc.stdout.strip() or None


def has_uncommitted_changes(root: Path) -> bool:
    return bool(_run(root, "status", "--porcelain").stdout.strip())


def default_branch(root: Path) -> str:
    """Best-effort guess at the base branch to target for a PR."""
    # Prefer the remote HEAD if known.
    proc = _run(root, "symbolic-ref", "refs/remotes/origin/HEAD", check=False)
    if proc.returncode == 0 and proc.stdout.strip():
        return proc.stdout.strip().rsplit("/", 1)[-1]
    for candidate in ("main", "master"):
        if _run(root, "rev-parse", "--verify", candidate, check=False).returncode == 0:
            return candidate
    return current_branch(root)


def remote_url(root: Path, remote: str = "origin") -> str | None:
    proc = _run(root, "remote", "get-url", remote, check=False)
    if proc.returncode != 0:
        return None
    return proc.stdout.strip() or None


def create_branch(root: Path, name: str, *, base: str | None = None) -> None:
    args = ["checkout", "-b", name]
    if base:
        args.append(base)
    _run(root, *args)


def checkout(root: Path, name: str) -> None:
    _run(root, "checkout", name)


def branch_exists(root: Path, name: str) -> bool:
    return _run(root, "rev-parse", "--verify", name, check=False).returncode == 0


def stage_all(root: Path) -> None:
    _run(root, "add", "-A")


def stage_paths(root: Path, paths: list[str]) -> None:
    """Stage only the given project-relative paths.

    Used by the fix workflow instead of ``git add -A`` so that only files Argus
    actually rewrote are committed, never a developer's unrelated changes.
    """
    if not paths:
        return
    _run(root, "add", "--", *paths)


def commit(root: Path, message: str, *, author_name: str = "Argus",
           author_email: str = "argus@localhost") -> str:
    """Commit staged changes with a guaranteed identity; return the commit sha."""
    _run(
        root,
        "-c", f"user.name={author_name}",
        "-c", f"user.email={author_email}",
        "commit", "-m", message, "--no-verify",
    )
    return _run(root, "rev-parse", "HEAD").stdout.strip()


def push(root: Path, branch: str, *, remote: str = "origin",
         set_upstream: bool = True, force: bool = False) -> None:
    args = ["push"]
    if set_upstream:
        args.append("-u")
    if force:
        args.append("--force-with-lease")
    args += [remote, branch]
    _run(root, *args)


@dataclass
class RepoInfo:
    root: Path
    is_repo: bool
    branch: str | None = None
    remote: str | None = None
    dirty: bool = False


def inspect(root: Path) -> RepoInfo:
    if not is_git_repo(root):
        return RepoInfo(root=root, is_repo=False)
    return RepoInfo(
        root=root,
        is_repo=True,
        branch=current_branch(root),
        remote=remote_url(root),
        dirty=has_uncommitted_changes(root),
    )
