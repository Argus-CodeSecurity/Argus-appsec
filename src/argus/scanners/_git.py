"""A hardened ``git`` runner for reading repositories Argus does not trust.

Scanning a repository means running ``git`` inside it, and git honours the
repository's own ``.git/config``. A hostile repo can use that to run arbitrary
commands on the scanning host: ``core.fsmonitor`` is executed whenever the
index is read, ``gpg.program`` runs on ``log.showSignature``, ``diff.external``
and textconv drivers run while producing diffs, and ``core.pager`` runs when
output is paged. Config given with ``-c`` on the command line takes precedence
over every config file (including ``include.path`` chains in the repo), so each
dangerous key is pinned to a harmless value here, the matching command-line
switches are passed where a subcommand supports them, and the system config
and pager environment are ignored.

Every read-only git call made while scanning a target should go through
:func:`run_git`.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path

#: Default wall-clock limit for one git invocation, in seconds.
DEFAULT_TIMEOUT = 60.0
#: Default cap on stdout kept from one git invocation, in bytes.
DEFAULT_MAX_OUTPUT = 50_000_000

# Pinned on the command line; these override anything in the repo's config.
# An empty core.fsmonitor/diff.external disables them. gpg programs point at the
# null device, which cannot be executed, rather than at a name looked up on PATH.
_HARDENING_CONFIG: tuple[str, ...] = (
    "core.fsmonitor=",
    f"core.hooksPath={os.devnull}",
    "core.pager=cat",
    "core.askPass=",
    "core.sshCommand=",
    "core.gitProxy=",
    "core.untrackedCache=false",
    "log.showSignature=false",
    f"gpg.program={os.devnull}",
    f"gpg.openpgp.program={os.devnull}",
    f"gpg.ssh.program={os.devnull}",
    f"gpg.x509.program={os.devnull}",
    "diff.external=",
    "pager.log=false",
    "pager.diff=false",
    "pager.show=false",
    "protocol.allow=never",
    "credential.helper=",
)

# Subcommands that render commits or diffs accept these switches; they stop
# external diff drivers, textconv filters and signature verification even if a
# config key above is somehow bypassed (e.g. by a .gitattributes driver).
_DIFF_SAFETY_FLAGS: dict[str, tuple[str, ...]] = {
    "log": ("--no-textconv", "--no-ext-diff", "--no-show-signature"),
    "show": ("--no-textconv", "--no-ext-diff", "--no-show-signature"),
    "diff": ("--no-textconv", "--no-ext-diff"),
}

# Environment variables that would let the caller's environment (or a parent
# git process) redirect git to another repository or launch a helper program.
_SCRUBBED_ENV = (
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_NAMESPACE",
    "GIT_EXTERNAL_DIFF",
    "GIT_PAGER",
    "PAGER",
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


@dataclass
class GitResult:
    returncode: int
    stdout: str
    truncated: bool = False


def git_available() -> bool:
    return shutil.which("git") is not None


def hardened_env() -> dict[str, str]:
    """The environment git runs with: no system config, no prompts, no helpers."""
    env = {k: v for k, v in os.environ.items() if k not in _SCRUBBED_ENV}
    env.update({
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PAGER": "cat",
        "PAGER": "cat",
        "GIT_ASKPASS": "",
        "SSH_ASKPASS": "",
        # Never lazily fetch missing objects from a (repo-configured) promisor remote.
        "GIT_NO_LAZY_FETCH": "1",
    })
    return env


def hardened_argv(root: Path, *args: str) -> list[str]:
    """Build the argv for ``git <args>`` run against ``root`` with hardening."""
    argv = ["git", "--no-pager", "-C", str(root)]
    for item in _HARDENING_CONFIG:
        argv += ["-c", item]
    if args:
        sub, rest = args[0], list(args[1:])
        argv.append(sub)
        argv += list(_DIFF_SAFETY_FLAGS.get(sub, ()))
        argv += rest
    return argv


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
    if not git_available():
        return None
    try:
        proc = subprocess.Popen(
            hardened_argv(root, *args),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=hardened_env(),
        )
    except OSError:
        return None

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
        while True:
            chunk = proc.stdout.read(65536)
            if not chunk:
                break
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
    if timed_out.is_set():
        return None
    text = b"".join(chunks)[:max_output].decode("utf-8", errors="replace")
    if truncated:
        return GitResult(0, text, truncated=True)
    return GitResult(proc.returncode, text)


def is_git_repo(root: Path) -> bool:
    res = run_git(root, "rev-parse", "--is-inside-work-tree", timeout=15)
    return res is not None and res.returncode == 0 and res.stdout.strip() == "true"
