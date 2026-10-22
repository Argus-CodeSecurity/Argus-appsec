"""Scan git history for secrets that were committed and later removed.

The working-tree secrets scan misses the most dangerous real-world case: a
credential that was committed, then deleted in a later commit. It is gone from the
current files but still trivially recoverable from history, so the correct
remediation is to *rotate* it, not just delete it.

This walks the diffs across all of history (bounded, so a huge repo cannot hang a
scan), runs the high-precision secret signatures on added lines, and reports each
unique secret with the commit that introduced it. Only signature matches are used
(not entropy) to keep history noise low. Every git call uses an argument array,
never a shell, and goes through the hardened runner in :mod:`argus.scanners._git`.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from pathlib import Path

from argus.scanners import _git

log = logging.getLogger("argus.scanners.secrets_history")

# Bound the diff we read so an enormous history cannot hang or OOM a scan.
_MAX_OUTPUT_BYTES = 20_000_000  # ~20 MB of unified diff text
_MAX_LINE = 1000  # skip minified/huge added lines, matching the working-tree scan
_TIMEOUT = 300.0  # seconds for the whole history walk


@dataclass
class HistorySecret:
    rule: str
    redacted: str
    path: str
    commit: str
    #: sha256 of the full matched value; distinguishes secrets whose redacted
    #: prefixes are identical (e.g. every AWS key starts with ``AKIA``).
    fingerprint: str = ""


def find_history_secrets(root: Path) -> tuple[list[HistorySecret], bool]:
    """Return (secrets, truncated). Empty list if not a git repo or git absent.

    ``truncated`` is True when the history was larger than the size cap (or the
    walk timed out) and older commits were not read; it is also logged as a
    warning so a capped scan with no findings is not silently "clean".
    """
    from argus.scanners.secrets import _SIGNATURES, SecretsScanner

    # The repo being scanned is untrusted; the hardened runner stops its
    # .git/config from launching programs (fsmonitor, gpg, textconv, pager).
    if not _git.is_git_repo(root):
        return [], False
    proc = _git.run_git(
        root, "log", "-p", "-U0", "--all", "--no-color", "--no-merges",
        timeout=_TIMEOUT, max_output=_MAX_OUTPUT_BYTES,
    )
    if proc is None:
        log.warning("git history scan of %s failed or timed out after %ss; "
                    "history was not checked for secrets", root, _TIMEOUT)
        return [], True
    if proc.returncode != 0:
        log.warning("git log failed in %s (exit %s); history was not checked "
                    "for secrets", root, proc.returncode)
        return [], False

    text = proc.stdout
    truncated = proc.truncated
    if truncated:
        log.warning("git history of %s exceeds %d bytes; only the newest commits "
                    "were checked for secrets", root, _MAX_OUTPUT_BYTES)

    seen: set[tuple[str, str]] = set()
    found: list[HistorySecret] = []
    commit = ""
    path = ""
    for line in text.splitlines():
        if line.startswith("commit "):
            commit = line[7:].strip()[:12]
        elif line.startswith("+++ b/"):
            path = line[6:].strip()
        elif line.startswith("+") and not line.startswith("+++"):
            added = line[1:]
            if len(added) > _MAX_LINE:
                continue
            for rule, pattern in _SIGNATURES.items():
                m = pattern.search(added)
                if not m:
                    continue
                digest = hashlib.sha256(m.group(0).encode("utf-8", "replace")).hexdigest()
                key = (rule, digest)
                if key not in seen:
                    seen.add(key)
                    found.append(HistorySecret(
                        rule=rule, redacted=SecretsScanner._redact(m.group(0)),
                        path=path, commit=commit, fingerprint=digest[:16],
                    ))
                break  # one secret per line is enough
    return found, truncated
