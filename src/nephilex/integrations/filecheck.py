"""The fast, file-level check behind ``nephilex check`` and the MCP check tools.

An editor or an AI coding assistant runs this after every edit, so it must be
quick and quiet: it runs only the *file-local* scanners (those whose findings
depend on one file's content: secrets, patterns, the AST taint tiers, iac,
llm, malware and the other built-ins that declare ``file_local``) on just the
files it is given. It uses the per-file scan cache, makes no network calls
and, by default, does no AI enrichment.

Two details keep it from disturbing a full ``nephilex scan``:

* The cache is shared with ``nephilex scan`` (same project root, same keys), but a
  check sees only a few files, so it must not prune the entries of every
  other file. :class:`FileCheckEngine` opens the cache without pruning.
* Live secret verification and git-history scanning are repository-level,
  network-using options; a check forces both off whatever the config says.
"""

from __future__ import annotations

import copy
import stat
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from nephilex import __version__
from nephilex.core.cache import ScanCache
from nephilex.core.config import Config, ConfigError
from nephilex.core.engine import ScanEngine
from nephilex.core.models import ScanResult
from nephilex.core.plugin import registry
from nephilex.core.project import DEFAULT_IGNORES, FileRef, Project

#: Files or directories whose presence marks a project root, nearest first.
PROJECT_MARKERS = (".git", ".nephilex.yml", ".nephilex.yaml")

#: Options that make the secrets scanner leave the file (network, git history).
_SECRETS_NON_LOCAL = ("verify", "history")


@dataclass(frozen=True)
class Skipped:
    """A path that was given to the check but not checked, and why."""

    path: str
    reason: str
    #: True when the path cannot be checked at all (outside the project,
    #: missing, a directory); False when it is deliberately ignored.
    refused: bool = True

    def to_dict(self) -> dict[str, object]:
        return {"path": self.path, "reason": self.reason, "refused": self.refused}


def find_project_root(start: Path) -> Path:
    """The nearest directory at or above ``start`` holding a project marker.

    A git checkout (``.git`` directory or file) or a Nephilex config marks the
    project. Without either, ``start`` itself is the project.
    """
    start = start.resolve()
    for candidate in (start, *start.parents):
        if any((candidate / marker).exists() for marker in PROJECT_MARKERS):
            return candidate
    return start


def file_local_scanners() -> list[str]:
    """Names of every registered scanner that declares ``file_local``."""
    return sorted(name for name, cls in registry.scanners().items() if cls.file_local)


def select_files(
    root: Path, paths: Iterable[str | Path], *, exclude_paths: Iterable[str] = ()
) -> tuple[list[FileRef], list[Skipped]]:
    """Turn the given paths into project files, refusing anything unsafe.

    Relative paths resolve against the current directory. Symlinks and ``..``
    are resolved before the containment check, so neither can reach outside
    ``root``. Directories, missing files, non-regular files, files inside the
    directories every scan ignores (``node_modules``, ``.git``, ...) and files
    matching ``exclude_paths`` are skipped with a reason rather than checked.
    """
    root = root.resolve()
    probe = Project(root=root, name=root.name, extra_ignores=tuple(exclude_paths))
    files: list[FileRef] = []
    skipped: list[Skipped] = []
    seen: set[str] = set()
    for raw in paths:
        shown = str(raw)
        try:
            resolved = Path(raw).expanduser().resolve()
        except (OSError, RuntimeError):
            skipped.append(Skipped(shown, "path could not be resolved"))
            continue
        if not resolved.is_relative_to(root):
            skipped.append(Skipped(shown, f"outside the project root {root}"))
            continue
        try:
            st = resolved.stat()
        except OSError:
            skipped.append(Skipped(shown, "does not exist"))
            continue
        if stat.S_ISDIR(st.st_mode):
            skipped.append(Skipped(shown, "is a directory (use `nephilex scan` for directories)"))
            continue
        if not stat.S_ISREG(st.st_mode):
            skipped.append(Skipped(shown, "not a regular file"))
            continue
        rel = resolved.relative_to(root).as_posix()
        if any(part in DEFAULT_IGNORES for part in rel.split("/")[:-1]):
            skipped.append(Skipped(shown, "inside a directory Nephilex never scans", refused=False))
            continue
        if probe._excluded(rel):
            skipped.append(Skipped(shown, "matches exclude_paths in the config", refused=False))
            continue
        if rel in seen:
            continue
        seen.add(rel)
        files.append(FileRef(path=resolved, rel_path=rel, size=st.st_size))
    return files, skipped


def check_config(base: Config, *, ai: bool = False, cache: bool = True) -> Config:
    """A copy of ``base`` restricted to what a file-level check may do.

    The scanner selection is narrowed to file-local scanners (honouring
    ``scanners`` / ``exclude_scanners`` from the config), secret verification
    and history scanning are dropped, the AI agents run only when ``ai`` is
    set (and the config has not disabled them), and attack simulation, patch
    generation and live targets are off.
    """
    cfg = copy.deepcopy(base)
    available = file_local_scanners()
    wanted = [n for n in (cfg.scanners or available) if n in available]
    chosen = [n for n in wanted if n not in cfg.exclude_scanners]
    if not chosen:
        raise ConfigError(
            "no file-local scanners are selected for nephilex check (the config's "
            "scanners/exclude_scanners leave none of: " + ", ".join(available) + ")"
        )
    cfg.scanners = chosen
    cfg.exclude_scanners = []
    secrets = cfg.scanner_options.get("secrets")
    if secrets:
        cfg.scanner_options["secrets"] = {
            k: v for k, v in secrets.items() if k not in _SECRETS_NON_LOCAL
        }
    cfg.ai.enabled = bool(ai and cfg.ai.enabled)
    cfg.attack_simulation = False
    cfg.generate_patches = False
    cfg.dast_url = None
    if not cache:
        cfg.cache = False
    return cfg


class _SubsetCache(ScanCache):
    """The project's scan cache, opened for a run that sees only some files.

    ``ScanEngine`` prunes every cache entry whose file it did not see in this
    run. For a check of one file that would throw away the cached results of
    every other file in the project, so pruning is left to full scans.
    """

    def prune(self, scanner: str, live_files: set[str]) -> None:
        return None


class FileCheckEngine(ScanEngine):
    """A :class:`ScanEngine` whose cache keeps entries for files it did not see."""

    def _open_cache(self, project: Project) -> ScanCache | None:
        if not self.config.cache or project.origin != "local":
            return None
        try:
            return _SubsetCache(project.root, __version__)
        except Exception:  # cache trouble must never break a check
            return None


def run_check(
    root: Path,
    files: list[FileRef],
    cfg: Config,
    *,
    progress: Callable[[str], None] | None = None,
) -> ScanResult:
    """Scan exactly ``files`` (already confined to ``root``) with ``cfg``.

    ``cfg`` should come from :func:`check_config`. With no files the result is
    empty and no scanner runs.
    """
    root = root.resolve()
    if not files:
        now = datetime.now(timezone.utc)
        return ScanResult(
            target=str(root),
            started_at=now,
            finished_at=now,
            nephilex_version=__version__,
            project_summary={"name": root.name, "root": str(root), "file_count": 0},
        )
    project = Project(
        root=root,
        name=root.name,
        extra_ignores=tuple(cfg.exclude_paths),
        include_ignored=cfg.include_ignored,
    )
    # The engine keeps this file list because the project already carries the
    # config's ignore settings; it never walks the rest of the tree.
    project._files_cache = tuple(files)
    return FileCheckEngine(cfg, progress=progress).scan(project)
