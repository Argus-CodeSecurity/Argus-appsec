"""The one place Argus runs ``git``.

Running git inside a repository means git honours that repository's own
``.git/config``, and a hostile repository can use it to run programs on the
host: ``core.fsmonitor`` runs whenever the index is read, ``gpg.program`` runs
on ``log.showSignature``, ``diff.external`` and textconv drivers run while
producing diffs, and ``core.pager`` runs when output is paged. Config given with
``-c`` on the command line takes precedence over every config file (including
``include.path`` chains), so dangerous keys are pinned there, the matching
command-line switches are added where a subcommand supports them, and the
environment is cleaned.

Two profiles exist because Argus uses git for two different jobs:

* :data:`UNTRUSTED` is for reading a repository Argus is scanning: a cloned
  remote or any checkout whose ``.git/config`` may have been written by someone
  else. Every key that can launch a program is pinned, hooks and credential
  helpers are off, no transport may be used (so no fetch, no lazy fetch of
  missing objects), and the system config and pager environment are ignored.
* :data:`WORKTREE` is for the operator's own checkout, where ``argus fix`` and
  ``argus review`` create branches, commit and push on the operator's behalf.
  Those steps need the operator's hooks, signing setup, credential helpers and
  SSH configuration, so only the keys the workflow never needs are pinned
  (fsmonitor, external diff, textconv, pager, signature display).

Both profiles share the rest: an argument list (never a shell), ``--no-pager``,
no terminal prompts, a wall-clock timeout, stdout capped at a byte limit and
decoded as UTF-8 with invalid bytes replaced, and :func:`is_safe_ref` for refs
that come from users or config.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import threading
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

#: Default wall-clock limit for one git invocation, in seconds.
DEFAULT_TIMEOUT = 60.0
#: Default cap on stdout kept from one git invocation, in bytes.
DEFAULT_MAX_OUTPUT = 50_000_000
#: Cap on stderr kept from one git invocation, in bytes.
_MAX_STDERR = 1_000_000

# Keys that make git launch a program while reading. Pinned in both profiles.
# An empty core.fsmonitor/diff.external disables them.
_READ_PATH_CONFIG: tuple[str, ...] = (
    "core.fsmonitor=",
    "core.pager=cat",
    "core.untrackedCache=false",
    "log.showSignature=false",
    "diff.external=",
    "pager.log=false",
    "pager.diff=false",
    "pager.show=false",
)

# Additionally pinned when the repository is untrusted. gpg programs point at
# the null device, which cannot be executed, rather than at a name looked up on
# PATH. protocol.allow=never forbids every transport, so nothing configured in
# the repository (a promisor remote, an ssh command, a proxy) can be reached.
_UNTRUSTED_EXTRA_CONFIG: tuple[str, ...] = (
    f"core.hooksPath={os.devnull}",
    "core.askPass=",
    "core.sshCommand=",
    "core.gitProxy=",
    f"gpg.program={os.devnull}",
    f"gpg.openpgp.program={os.devnull}",
    f"gpg.ssh.program={os.devnull}",
    f"gpg.x509.program={os.devnull}",
    "protocol.allow=never",
    "credential.helper=",
)

# Subcommands that render commits or diffs accept these switches; they stop
# external diff drivers, textconv filters and signature verification even if a
# config key is somehow bypassed (e.g. by a .gitattributes driver).
_DIFF_SAFETY_FLAGS: dict[str, tuple[str, ...]] = {
    "log": ("--no-textconv", "--no-ext-diff", "--no-show-signature"),
    "show": ("--no-textconv", "--no-ext-diff", "--no-show-signature"),
    "diff": ("--no-textconv", "--no-ext-diff"),
}

# Environment variables that would launch a helper program. Removed in both
# profiles.
_PROGRAM_ENV = ("GIT_EXTERNAL_DIFF", "GIT_PAGER", "PAGER")

# Removed as well for untrusted repositories: variables that redirect git to
# another repository, or that a parent process could use to inject config or
# helpers.
_UNTRUSTED_SCRUBBED_ENV = (
    *_PROGRAM_ENV,
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_NAMESPACE",
    "GIT_ASKPASS",
    "SSH_ASKPASS",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "GIT_EDITOR",
    "GIT_SEQUENCE_EDITOR",
    "GIT_PROXY_COMMAND",
    "GIT_CONFIG",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_PARAMETERS",
)


@dataclass(frozen=True)
class GitProfile:
    """How much of git's configurable behaviour to switch off for one call."""

    name: str
    config: tuple[str, ...]
    scrubbed_env: tuple[str, ...]
    extra_env: tuple[tuple[str, str], ...] = field(default=())


#: Reading a repository Argus is scanning (its config is attacker-controlled).
UNTRUSTED = GitProfile(
    name="untrusted",
    config=_READ_PATH_CONFIG + _UNTRUSTED_EXTRA_CONFIG,
    scrubbed_env=_UNTRUSTED_SCRUBBED_ENV,
    extra_env=(
        ("GIT_CONFIG_NOSYSTEM", "1"),
        ("GIT_OPTIONAL_LOCKS", "0"),
        ("GIT_ASKPASS", ""),
        ("SSH_ASKPASS", ""),
        # Never lazily fetch missing objects from a (repo-configured) promisor remote.
        ("GIT_NO_LAZY_FETCH", "1"),
    ),
)

#: The operator's own checkout, where Argus commits and pushes for them.
WORKTREE = GitProfile(
    name="worktree",
    config=_READ_PATH_CONFIG,
    scrubbed_env=_PROGRAM_ENV,
)


class GitExecError(RuntimeError):
    """git could not be run to completion."""


class GitNotFoundError(GitExecError):
    """git is not installed or not on PATH."""


class GitTimeoutError(GitExecError):
    """git ran longer than its timeout and was killed."""

    def __init__(self, message: str, timeout: float) -> None:
        super().__init__(message)
        self.timeout = timeout


@dataclass
class GitResult:
    returncode: int
    stdout: str
    #: True when stdout went past the byte cap and the process was stopped.
    truncated: bool = False
    stderr: str = ""


def git_available() -> bool:
    return shutil.which("git") is not None


def is_safe_ref(ref: str) -> bool:
    """Whether a user- or config-supplied ref may be passed to git.

    Rejects empty refs, anything git could parse as an option (a leading
    ``-``) and control characters that could split or truncate an argument.
    Callers should still place the ref after ``--end-of-options`` where the
    subcommand supports it.
    """
    return bool(ref) and not ref.startswith("-") and not any(c in ref for c in "\0\n\r")


def git_env(profile: GitProfile = UNTRUSTED) -> dict[str, str]:
    """The environment git runs with under ``profile``."""
    env = {k: v for k, v in os.environ.items() if k not in profile.scrubbed_env}
    env.update(
        {
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_PAGER": "cat",
            "PAGER": "cat",
        }
    )
    env.update(dict(profile.extra_env))
    return env


def git_argv(
    root: Path,
    *args: str,
    profile: GitProfile = UNTRUSTED,
    config: Sequence[str] = (),
) -> list[str]:
    """Build the argv for ``git <args>`` run against ``root`` under ``profile``.

    ``config`` adds caller-specific ``-c key=value`` settings (for example a
    commit identity). They come after the profile's pins, so a caller can
    tighten but should never use this to undo a pin.
    """
    argv = ["git", "--no-pager", "-C", str(root)]
    for item in (*profile.config, *config):
        argv += ["-c", item]
    if args:
        sub, rest = args[0], list(args[1:])
        argv.append(sub)
        argv += list(_DIFF_SAFETY_FLAGS.get(sub, ()))
        argv += rest
    return argv


def run(
    root: Path,
    *args: str,
    profile: GitProfile = UNTRUSTED,
    config: Sequence[str] = (),
    timeout: float = DEFAULT_TIMEOUT,
    max_output: int = DEFAULT_MAX_OUTPUT,
    capture_stderr: bool = False,
) -> GitResult:
    """Run ``git <args>`` in ``root`` under ``profile`` and return its result.

    Output is streamed and at most ``max_output`` bytes of stdout are kept; past
    that the process is killed and the result is marked ``truncated`` (with
    return code 0 and the partial output), so an enormous history or blob
    cannot exhaust memory. Bytes are decoded as UTF-8 with invalid sequences
    replaced, since repository content can be in any encoding. stderr is
    discarded unless ``capture_stderr`` is set.

    Raises :class:`GitNotFoundError` if git is missing, :class:`GitTimeoutError`
    if it runs past ``timeout`` seconds, and :class:`GitExecError` if it cannot
    be started.
    """
    if not git_available():
        raise GitNotFoundError("git is not installed or not on PATH.")
    try:
        proc = subprocess.Popen(
            git_argv(root, *args, profile=profile, config=config),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE if capture_stderr else subprocess.DEVNULL,
            env=git_env(profile),
        )
    except OSError as exc:
        raise GitExecError(f"could not start git: {exc}") from exc

    err_chunks: list[bytes] = []

    def _drain_stderr() -> None:
        # Read stderr concurrently so a chatty command cannot fill the pipe and
        # block while stdout is being read.
        assert proc.stderr is not None
        kept = 0
        while chunk := proc.stderr.read(65536):
            if kept < _MAX_STDERR:
                err_chunks.append(chunk[: _MAX_STDERR - kept])
                kept += len(err_chunks[-1])

    reader = threading.Thread(target=_drain_stderr, daemon=True) if capture_stderr else None
    if reader is not None:
        reader.start()

    chunks: list[bytes] = []
    size = 0
    truncated = False
    timed_out = threading.Event()

    def _expire() -> None:
        timed_out.set()
        proc.kill()

    timer = threading.Timer(timeout, _expire)
    timer.start()
    try:
        assert proc.stdout is not None
        while chunk := proc.stdout.read(65536):
            chunks.append(chunk)
            size += len(chunk)
            if size > max_output:
                truncated = True
                proc.kill()
                break
        proc.wait()
    finally:
        timer.cancel()
        if proc.stdout is not None:
            proc.stdout.close()
        if reader is not None:
            reader.join(timeout=5)
        if proc.stderr is not None:
            proc.stderr.close()
    if timed_out.is_set():
        raise GitTimeoutError(f"git {' '.join(args)} timed out after {timeout:g}s", timeout)
    text = b"".join(chunks)[:max_output].decode("utf-8", errors="replace")
    stderr = b"".join(err_chunks).decode("utf-8", errors="replace")
    if truncated:
        return GitResult(0, text, truncated=True, stderr=stderr)
    return GitResult(proc.returncode, text, stderr=stderr)
