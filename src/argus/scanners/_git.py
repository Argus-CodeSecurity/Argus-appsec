"""Read-only git access for scanners, on top of :mod:`argus.core.gitexec`.

Scanners read repositories Argus does not trust, so every call here uses the
:data:`~argus.core.gitexec.UNTRUSTED` profile: the repository's own
``.git/config`` cannot launch programs (fsmonitor, gpg, textconv, external
diff, pager, hooks), no transport can be used, and output is bounded. See
:mod:`argus.core.gitexec` for the full list.

Every read-only git call made while scanning a target should go through
:func:`run_git`.
"""

from __future__ import annotations

from pathlib import Path

from argus.core import gitexec
from argus.core.gitexec import DEFAULT_MAX_OUTPUT, DEFAULT_TIMEOUT, GitResult, git_available

__all__ = [
    "DEFAULT_MAX_OUTPUT",
    "DEFAULT_TIMEOUT",
    "GitResult",
    "git_available",
    "hardened_argv",
    "hardened_env",
    "is_git_repo",
    "run_git",
]


def hardened_env() -> dict[str, str]:
    """The environment git runs with: no system config, no prompts, no helpers."""
    return gitexec.git_env(gitexec.UNTRUSTED)


def hardened_argv(root: Path, *args: str) -> list[str]:
    """Build the argv for ``git <args>`` run against ``root`` with hardening."""
    return gitexec.git_argv(root, *args, profile=gitexec.UNTRUSTED)


def run_git(
    root: Path,
    *args: str,
    timeout: float = DEFAULT_TIMEOUT,
    max_output: int = DEFAULT_MAX_OUTPUT,
) -> GitResult | None:
    """Run a read-only git command in ``root`` with repo config neutralised.

    Returns ``None`` if git is missing, times out, or cannot be started.
    Output is streamed and at most ``max_output`` bytes are kept; past that the
    process is killed and the result is marked ``truncated``, so an enormous
    history cannot exhaust memory. Bytes are decoded as UTF-8 with invalid
    sequences replaced, since commit contents can be in any encoding.
    """
    try:
        return gitexec.run(
            root, *args, profile=gitexec.UNTRUSTED, timeout=timeout, max_output=max_output
        )
    except gitexec.GitExecError:
        return None


def is_git_repo(root: Path) -> bool:
    res = run_git(root, "rev-parse", "--is-inside-work-tree", timeout=15)
    return res is not None and res.returncode == 0 and res.stdout.strip() == "true"
