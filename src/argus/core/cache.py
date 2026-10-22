"""On-disk scan cache: unchanged files skip re-analysis between runs.

Findings from *file-local* scanners (those whose findings depend only on the
content of one file, secrets, SAST patterns, IaC, the AST taint tiers) are
cached per ``(scanner, options, file content hash)``. On the next scan, files
whose content is unchanged reuse their cached findings and only changed or new
files are re-analyzed, which is what makes warm scans fast in CI and on
pre-commit.

Correctness properties:

* Keyed by **content hash**, never by mtime, a file restored to a previous
  state hits the cache, an edited file never does.
* The Argus version and the scanner's options are part of the key, so a rule
  update or a config change invalidates cleanly.
* Cross-file analyses (dependency/OSV lookups have their own cache; future
  cross-file taint) are never cached here, only scanners that declare
  themselves ``file_local``.
* Zero-finding files are cached too ("scanned, clean"), that is most files,
  and most of the win.

The cache lives under ``~/.cache/argus/scan`` (override the base directory
with ``ARGUS_CACHE_DIR``) and can be disabled with ``--no-cache`` or
``cache: false`` in ``.argus.yml``.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import tempfile
from pathlib import Path

from argus.core.models import Finding

log = logging.getLogger("argus.core.cache")

_CACHE_FORMAT = 1


def _cache_dir() -> Path:
    override = os.environ.get("ARGUS_CACHE_DIR")
    base = Path(override) if override else Path.home() / ".cache" / "argus"
    return base / "scan"


def file_key(rel_path: str, text: str) -> str:
    digest = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:24]
    return f"{rel_path}@{digest}"


def scanner_key(name: str, options: dict) -> str:
    opts = hashlib.sha256(
        json.dumps(options, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()[:12]
    return f"{name}@{opts}"


class ScanCache:
    """Per-project findings cache for file-local scanners.

    Load-modify-save per scan: ``lookup`` during the scan, ``store`` fresh
    results, then one ``save`` at the end. A corrupt or unreadable cache file
    is treated as a miss, the cache can never break a scan.
    """

    def __init__(self, project_root: Path, argus_version: str) -> None:
        digest = hashlib.sha256(str(project_root).encode("utf-8")).hexdigest()[:24]
        self.path = _cache_dir() / f"{digest}.json"
        self.version = argus_version
        self._entries: dict[str, dict[str, list[dict]]] = {}
        self._dirty = False
        self._load()

    def _load(self) -> None:
        try:
            blob = json.loads(self.path.read_text(encoding="utf-8"))
            if blob.get("format") == _CACHE_FORMAT and blob.get("argus") == self.version:
                self._entries = blob.get("entries", {})
        except (OSError, ValueError):
            self._entries = {}

    def lookup(self, scanner: str, file: str) -> list[Finding] | None:
        """Cached findings for a (scanner key, file key), or None on miss."""
        raw = self._entries.get(scanner, {}).get(file)
        if raw is None:
            return None
        try:
            return [Finding.model_validate(f) for f in raw]
        except Exception:  # schema drift within a version, treat as a miss
            return None

    def store(self, scanner: str, file: str, findings: list[Finding]) -> None:
        self._entries.setdefault(scanner, {})[file] = [
            f.model_dump(mode="json") for f in findings
        ]
        self._dirty = True

    def prune(self, scanner: str, live_files: set[str]) -> None:
        """Drop entries for files that no longer exist (or whose content moved on)."""
        bucket = self._entries.get(scanner)
        if bucket is None:
            return
        stale = [k for k in bucket if k not in live_files]
        for k in stale:
            del bucket[k]
        if stale:
            self._dirty = True

    def save(self) -> None:
        if not self._dirty:
            return
        tmp: str | None = None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            # A unique temp file per writer: concurrent runs on the same project
            # each write their own file and atomically replace the cache, so
            # one run can never rename another's half-written file into place.
            fd, tmp = tempfile.mkstemp(prefix=self.path.stem + ".",
                                       suffix=".tmp", dir=self.path.parent)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump({"format": _CACHE_FORMAT, "argus": self.version,
                           "entries": self._entries}, fh)
            os.replace(tmp, self.path)
            tmp = None
        except OSError as exc:  # a read-only cache dir must never fail the scan
            log.debug("Could not persist scan cache to %s: %s", self.path, exc)
        finally:
            if tmp is not None:
                with contextlib.suppress(OSError):
                    os.unlink(tmp)
