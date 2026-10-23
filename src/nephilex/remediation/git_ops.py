"""Thin wrappers over the ``git`` CLI for the fix and review workflows.

Kept deliberately small and explicit: each function is one git command. Commits
fall back to a fixed identity only when none is configured (so they succeed in
bare CI containers) and never override a user's real identity.

Every call goes through :func:`nephilex.core.gitexec.run` with the
:data:`~nephilex.core.gitexec.WORKTREE` profile: these functions act on the
operator's own checkout (creating branches, committing with their hooks and
signing setup, pushing with their credentials), so only the git features the
workflow never needs are switched off. Reading an untrusted repository uses
:mod:`nephilex.scanners._git` instead.
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from nephilex.core import gitexec
from nephilex.core.gitexec import git_available

__all__ = [
    "GitError",
    "RepoInfo",
    "add_worktree",
    "branch_exists",
    "checkout",
    "clean_untracked",
    "commit",
    "create_branch",
    "current_branch",
    "default_branch",
    "delete_branch",
    "diff",
    "git_available",
    "has_uncommitted_changes",
    "inspect",
    "is_git_repo",
    "path_prefix",
    "prune_worktrees",
    "push",
    "remote_url",
    "remove_worktree",
    "reset_hard",
    "rev_parse",
    "show_file",
    "stage_all",
    "stage_paths",
    "verify_commit",
]

# Per-command timeout in seconds; a hung git (credential prompt, huge history,
# network filesystem) must not hang a CI job forever.
_DEFAULT_TIMEOUT = 300.0


class GitError(RuntimeError):
    """A git command failed."""


def _timeout() -> float:
    try:
        return float(os.environ.get("NEPHILEX_GIT_TIMEOUT", _DEFAULT_TIMEOUT))
    except ValueError:
        return _DEFAULT_TIMEOUT


def _run(
    root: Path,
    *args: str,
    check: bool = True,
    timeout: float | None = None,
    config: Sequence[str] = (),
) -> subprocess.CompletedProcess[str]:
    """Run one git command through the shared runner; raise GitError on failure.

    Output is decoded leniently (git output carries file content and paths in
    whatever encoding the repo uses) and capped. Output past the cap is never
    returned as if complete: with ``check`` it raises, otherwise the result
    carries a non-zero return code so callers treat it as unavailable.
    """
    try:
        res = gitexec.run(
            root,
            *args,
            profile=gitexec.WORKTREE,
            config=config,
            timeout=timeout or _timeout(),
            capture_stderr=True,
        )
    except gitexec.GitExecError as exc:
        raise GitError(str(exc)) from exc
    returncode, stderr = res.returncode, res.stderr
    if res.truncated:
        returncode = 1
        stderr = f"output exceeded {gitexec.DEFAULT_MAX_OUTPUT} bytes"
    proc = subprocess.CompletedProcess(["git", *args], returncode, res.stdout, stderr)
    if check and proc.returncode != 0:
        raise GitError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc


def _safe_ref(ref: str) -> bool:
    """Reject empty refs and anything git could parse as an option."""
    return gitexec.is_safe_ref(ref)


def is_git_repo(root: Path) -> bool:
    if not git_available():
        return False
    proc = _run(root, "rev-parse", "--is-inside-work-tree", check=False)
    return proc.returncode == 0 and proc.stdout.strip() == "true"


def current_branch(root: Path) -> str:
    return _run(root, "rev-parse", "--abbrev-ref", "HEAD").stdout.strip()


def path_prefix(root: Path) -> str:
    """``root``'s location inside its repository, e.g. ``"services/api/"``.

    Empty at the repository root or outside a repository. Finding paths are
    relative to the scanned directory; adding this prefix gives the
    repository-relative path that git diffs and hosting APIs use.
    """
    proc = _run(root, "rev-parse", "--show-prefix", check=False)
    if proc.returncode != 0:
        return ""
    return proc.stdout.strip()


def diff(root: Path, *args: str) -> str:
    """Return `git diff <args>` stdout; raise :class:`GitError` if git fails.

    An empty string means git ran and found no changes. A failure (unknown ref,
    shallow clone without a merge base, not a repository) raises instead of
    looking like an empty diff, so callers cannot mistake "could not compute the
    diff" for "nothing changed". Paths are printed unquoted (UTF-8) so non-ASCII
    file names match the scanner's paths. External diff drivers and textconv
    filters are disabled.
    """
    return _run(
        root, "diff", "--no-ext-diff", "--no-textconv", *args, config=("core.quotePath=false",)
    ).stdout


def rev_parse(root: Path, ref: str) -> str | None:
    """Resolve ``ref`` to a commit sha, or None if it is not a commit."""
    if not _safe_ref(ref):
        return None
    proc = _run(
        root,
        "rev-parse",
        "--verify",
        "--quiet",
        "--end-of-options",
        f"{ref}^{{commit}}",
        check=False,
    )
    if proc.returncode != 0:
        return None
    return proc.stdout.strip() or None


def verify_commit(root: Path, ref: str) -> bool:
    """True if ``ref`` resolves to a commit in this repository."""
    return rev_parse(root, ref) is not None


def show_file(root: Path, ref: str, rel_path: str) -> str | None:
    """Return file contents at ``ref:rel_path``, or None if unavailable."""
    sha = rev_parse(root, ref)
    if sha is None:
        return None
    proc = _run(root, "show", "--no-ext-diff", "--no-textconv", f"{sha}:{rel_path}", check=False)
    if proc.returncode != 0:
        return None
    return proc.stdout


def has_uncommitted_changes(root: Path) -> bool:
    return bool(_run(root, "status", "--porcelain").stdout.strip())


def default_branch(root: Path) -> str:
    """Best-effort guess at the base branch to target for a PR."""
    # Prefer the remote HEAD if known.
    proc = _run(root, "symbolic-ref", "refs/remotes/origin/HEAD", check=False)
    if proc.returncode == 0 and proc.stdout.strip():
        return proc.stdout.strip().rsplit("/", 1)[-1]
    for candidate in ("main", "master"):
        if verify_commit(root, candidate):
            return candidate
    return current_branch(root)


def remote_url(root: Path, remote: str = "origin") -> str | None:
    proc = _run(root, "remote", "get-url", remote, check=False)
    if proc.returncode != 0:
        return None
    return proc.stdout.strip() or None


def create_branch(root: Path, name: str, *, base: str | None = None, reset: bool = False) -> None:
    """Create branch ``name`` at ``base`` and check it out.

    With ``reset`` an existing branch is moved to ``base`` (``checkout -B``)
    instead of failing, so a stale branch never carries old commits forward.
    """
    if not _safe_ref(name) or (base is not None and not _safe_ref(base)):
        raise GitError(f"refusing unsafe branch/ref name: {name!r} / {base!r}")
    args = ["checkout", "-B" if reset else "-b", name]
    if base:
        args.append(base)
    _run(root, *args)


def checkout(root: Path, name: str) -> None:
    if not _safe_ref(name):
        raise GitError(f"refusing unsafe ref name: {name!r}")
    _run(root, "checkout", name)


def delete_branch(root: Path, name: str) -> None:
    if not _safe_ref(name):
        raise GitError(f"refusing unsafe branch name: {name!r}")
    _run(root, "branch", "-D", name)


def reset_hard(root: Path) -> None:
    """Discard staged and unstaged changes to tracked files."""
    _run(root, "reset", "--hard", "-q", "HEAD")


def clean_untracked(root: Path) -> None:
    """Delete untracked and ignored files under ``root``.

    Only for the temporary worktrees Nephilex creates to run a project's tests,
    where everything untracked is an artifact of an earlier test run. Never call
    this on the operator's own checkout.
    """
    _run(root, "clean", "-ffdxq")


def add_worktree(root: Path, path: Path, commit: str) -> None:
    """Check out ``commit`` into a new, detached worktree at ``path``.

    The repository's hooks are switched off for this call (``post-checkout``
    would otherwise run): creating a throwaway checkout is not an action the
    operator's hooks are meant to see.
    """
    if not _safe_ref(commit):
        raise GitError(f"refusing unsafe ref: {commit!r}")
    _run(
        root,
        "worktree",
        "add",
        "--detach",
        "--quiet",
        str(path),
        commit,
        config=(f"core.hooksPath={os.devnull}",),
    )


def remove_worktree(root: Path, path: Path) -> None:
    """Remove the worktree at ``path``, even if it has changes or is locked."""
    _run(root, "worktree", "remove", "--force", "--force", str(path))


def prune_worktrees(root: Path) -> None:
    """Forget worktrees whose directories no longer exist (best effort)."""
    _run(root, "worktree", "prune", check=False)


def branch_exists(root: Path, name: str) -> bool:
    if not _safe_ref(name):
        return False
    return (
        _run(
            root,
            "rev-parse",
            "--verify",
            "--quiet",
            "--end-of-options",
            f"refs/heads/{name}",
            check=False,
        ).returncode
        == 0
    )


def stage_all(root: Path) -> None:
    _run(root, "add", "-A")


def stage_paths(root: Path, paths: list[str]) -> None:
    """Stage only the given project-relative paths.

    Used by the fix workflow instead of ``git add -A`` so that only files Nephilex
    actually rewrote are committed, never a developer's unrelated changes.
    """
    if not paths:
        return
    _run(root, "add", "--", *paths)


def _config_value(root: Path, key: str) -> str:
    return _run(root, "config", "--get", key, check=False).stdout.strip()


def commit(
    root: Path,
    message: str,
    *,
    author_name: str = "Nephilex",
    author_email: str = "nephilex@localhost",
    no_verify: bool = False,
) -> str:
    """Commit staged changes; return the commit sha.

    The user's own identity is used whenever one is configured (git config or
    the GIT_AUTHOR_*/GIT_COMMITTER_* environment), so DCO/CLA checks and branch
    protection see the real author. The fallback identity is supplied only for
    the parts that are missing, e.g. in a bare CI container. Commit hooks run
    unless ``no_verify`` is explicitly requested.
    """
    identity: list[str] = []
    if not (
        _config_value(root, "user.name")
        or (os.environ.get("GIT_AUTHOR_NAME") and os.environ.get("GIT_COMMITTER_NAME"))
    ):
        identity.append(f"user.name={author_name}")
    if not (
        _config_value(root, "user.email")
        or (os.environ.get("GIT_AUTHOR_EMAIL") and os.environ.get("GIT_COMMITTER_EMAIL"))
    ):
        identity.append(f"user.email={author_email}")
    args = ["commit", "-m", message]
    if no_verify:
        args.append("--no-verify")
    _run(root, *args, config=identity)
    return _run(root, "rev-parse", "HEAD").stdout.strip()


def push(
    root: Path,
    branch: str,
    *,
    remote: str = "origin",
    set_upstream: bool = True,
    force: bool = False,
) -> None:
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
