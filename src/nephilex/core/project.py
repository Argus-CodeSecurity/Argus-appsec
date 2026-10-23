"""The project model: a normalized view of the target Nephilex is analyzing.

A ``Project`` is produced by loading a local directory (or a checked-out remote
repo) and is then enriched by the :mod:`nephilex.analysis.repository` analyzer with
detected languages, frameworks, and architecture facts. Scanners consume the
project rather than touching the filesystem directly, which keeps them testable.
"""

from __future__ import annotations

import fnmatch
import os
import stat
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Directories that are noise for security analysis. Skipped during file walks.
DEFAULT_IGNORES: tuple[str, ...] = (
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "vendor",
    "dist",
    "build",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".next",
    ".nuxt",
    "target",
    ".gradle",
    ".idea",
    ".nephilex",
    "coverage",
    "htmlcov",
    ".terraform",
)

# Files above this size are treated as assets/blobs and not read as source.
MAX_TEXT_BYTES = 2_000_000
# Leading bytes inspected for a NUL to decide whether a file is binary.
_SNIFF_BYTES = 2048
# Wall-clock limit for listing the files git ignores, in seconds.
_GIT_LIST_TIMEOUT = 30.0


@dataclass(frozen=True)
class GitIgnored:
    """Untracked paths git ignores under a project root (POSIX, root-relative)."""

    files: frozenset[str]
    #: Whole directories git ignores; nothing below them is tracked.
    dirs: frozenset[str]

    def covers_dir(self, rel_dir: str) -> bool:
        return rel_dir in self.dirs

    def covers_file(self, rel_path: str) -> bool:
        return rel_path in self.files


def _inside_git_work_tree(root: Path) -> bool:
    """Cheap pre-check: is there a ``.git`` entry at or above ``root``?

    Saves starting git for the common case of a directory that is not a
    repository at all.
    """
    return any((d / ".git").exists() for d in (root, *root.parents))


def git_ignored_paths(root: Path) -> GitIgnored | None:
    """The untracked files and directories git ignores under ``root``.

    Runs ``git ls-files --others --ignored --exclude-standard --directory``
    through :mod:`nephilex.core.gitexec` with the untrusted profile, because the
    repository being scanned may be hostile. The listing only ever names
    *untracked* paths, so a tracked file is never in it, whatever the
    repository's ``.gitignore`` says: a pull request cannot hide committed
    code by adding an ignore pattern. Anything git does not name (a path it
    spells differently, a nested repository) is still scanned.

    Returns None when ``root`` is not in a git work tree, git is missing or
    fails, or ``root`` itself is ignored (the caller named it explicitly);
    callers then walk every file as before.
    """
    if not _inside_git_work_tree(root):
        return None
    from nephilex.core import gitexec

    try:
        res = gitexec.run(
            root,
            "ls-files",
            "--others",
            "--ignored",
            "--exclude-standard",
            "--directory",
            "-z",
            profile=gitexec.UNTRUSTED,
            timeout=_GIT_LIST_TIMEOUT,
        )
    except gitexec.GitExecError:
        return None
    if res.returncode != 0 or res.truncated:
        return None
    files: set[str] = set()
    dirs: set[str] = set()
    for entry in res.stdout.split("\0"):
        if not entry:
            continue
        if entry in ("./", "."):
            return None  # the project root itself is ignored
        if entry.endswith("/"):
            dirs.add(entry.rstrip("/"))
        else:
            files.add(entry)
    return GitIgnored(frozenset(files), frozenset(dirs))


@dataclass
class FileRef:
    """A single project file. Content is read lazily and cached per instance."""

    path: Path  # absolute path on disk
    rel_path: str  # POSIX-style path relative to project root
    size: int
    language: str | None = None

    _text: str | None = field(default=None, repr=False, compare=False)
    _read_attempted: bool = field(default=False, repr=False, compare=False)
    # Guards the lazy read: the engine shares one FileRef across parallel scanner
    # threads, so text() must be atomic or a racing reader can observe an
    # in-progress read as empty content (silently missed findings).
    _lock: threading.Lock = field(
        default_factory=threading.Lock, init=False, repr=False, compare=False
    )

    @property
    def name(self) -> str:
        return self.path.name

    @property
    def suffix(self) -> str:
        return self.path.suffix.lower()

    def is_probably_binary(self) -> bool:
        if self.size > MAX_TEXT_BYTES:
            return True
        try:
            # Only the sniff window is read, not the whole file.
            with open(self.path, "rb") as fh:
                chunk = fh.read(_SNIFF_BYTES)
        except OSError:
            return True
        return b"\x00" in chunk

    def _read_text(self) -> str:
        """Read the file as text with a hard size bound, or "" if binary/too big.

        The size recorded during the walk can be stale (the file may have grown
        since), so the read itself is capped instead of trusting it.
        """
        if self.size > MAX_TEXT_BYTES:
            return ""
        try:
            with open(self.path, "rb") as fh:
                data = fh.read(MAX_TEXT_BYTES + 1)
        except OSError:
            return ""
        if len(data) > MAX_TEXT_BYTES or b"\x00" in data[:_SNIFF_BYTES]:
            return ""
        # Same newline handling as Path.read_text (universal newlines).
        text = data.decode("utf-8", errors="replace")
        return text.replace("\r\n", "\n").replace("\r", "\n")

    def text(self) -> str:
        """Return file contents as text, or "" if unreadable/binary. Cached.

        Thread-safe: parallel scanners share one FileRef, so the read happens
        under a lock and ``_text`` is published before ``_read_attempted`` is
        set. A reader that observes the flag is therefore guaranteed to see the
        fully-read content, never an empty in-progress value.
        """
        if self._read_attempted:
            return self._text or ""
        with self._lock:
            # Double-checked: another thread may have finished the read while we
            # were waiting for the lock.
            if self._read_attempted:
                return self._text or ""
            text = self._read_text()
            self._text = text  # publish content first...
            self._read_attempted = True  # ...then the flag readers gate on.
            return self._text or ""

    def lines(self) -> list[str]:
        return self.text().splitlines()


@dataclass
class Project:
    """A normalized, analyzable view of the scan target."""

    root: Path
    name: str
    origin: str = "local"  # local | github | gitlab | bitbucket | url
    origin_url: str | None = None

    # Populated by the repository analyzer.
    languages: dict[str, int] = field(default_factory=dict)  # language -> file count
    frameworks: list[str] = field(default_factory=list)
    architecture: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    extra_ignores: tuple[str, ...] = ()
    # Also scan untracked files that git ignores (build output, local virtual
    # environments). Off by default: in a git work tree only tracked files and
    # untracked files that are not ignored are scanned.
    include_ignored: bool = False

    # Materialized file list, computed on first access. Not part of equality.
    _files_cache: tuple[FileRef, ...] | None = field(default=None, repr=False, compare=False)

    @classmethod
    def from_path(cls, path: str | os.PathLike[str], **kwargs: Any) -> Project:
        root = Path(path).resolve()
        if not root.exists():
            raise FileNotFoundError(f"Project path does not exist: {root}")
        if root.is_file():
            root = root.parent
        return cls(root=root, name=kwargs.pop("name", None) or root.name, **kwargs)

    def _ignored(self) -> set[str]:
        return set(DEFAULT_IGNORES)

    def _excluded(self, rel_path: str) -> bool:
        """True if a relative path matches any configured exclude glob.

        ``extra_ignores`` (from ``exclude_paths`` in config) are treated as globs
        against the POSIX relative path, e.g. ``examples/**``, ``*.min.js``,
        ``src/nephilex/scanners/llm.py``, as well as the bare basename, so both a
        directory subtree and a single file can be excluded.
        """
        name = rel_path.rsplit("/", 1)[-1]
        for pat in self.extra_ignores:
            if fnmatch.fnmatch(rel_path, pat) or fnmatch.fnmatch(name, pat):
                return True
            # `dir/**` should also match the directory prefix `dir/...`.
            if pat.endswith("/**") and (rel_path == pat[:-3] or rel_path.startswith(pat[:-2])):
                return True
        return False

    def iter_files(self) -> Iterator[FileRef]:
        """Walk the project, skipping ignored directories and unreadable files.

        Directories and files are traversed in sorted order so that the file list,
        and therefore finding ids and report ordering, is deterministic and
        reproducible across machines and filesystems.

        In a git work tree, untracked files that git ignores are skipped
        (see :func:`git_ignored_paths`) unless ``include_ignored`` is set.
        Tracked files are always walked.
        """
        ignores = self._ignored()
        git_ignored = None if self.include_ignored else git_ignored_paths(self.root)
        for dirpath, dirnames, filenames in os.walk(self.root):
            base_rel = Path(dirpath).relative_to(self.root).as_posix()
            # Sorting dirnames in place also fixes os.walk's traversal order.
            # Prune by built-in basename ignores, by exclude-glob and by
            # directories git ignores (which lets us skip descending into an
            # excluded subtree entirely).
            kept_dirs = []
            for d in dirnames:
                rel_dir = f"{base_rel}/{d}".lstrip("/").removeprefix("./")
                if d in ignores or self._excluded(rel_dir):
                    continue
                if git_ignored is not None and git_ignored.covers_dir(rel_dir):
                    continue
                kept_dirs.append(d)
            dirnames[:] = sorted(kept_dirs)
            for filename in sorted(filenames):
                abs_path = Path(dirpath) / filename
                rel = abs_path.relative_to(self.root).as_posix()
                if self._excluded(rel):
                    continue
                if git_ignored is not None and git_ignored.covers_file(rel):
                    continue
                # Symlink escape guard: a hostile repository can point a symlink at
                # a file outside the scan root (e.g. /etc/passwd or an SSH key) to
                # get its contents read and then embedded in a shared report. Skip
                # any symlink whose real target leaves the project root. In-repo
                # symlinks are still allowed so legitimate layouts keep working.
                if abs_path.is_symlink():
                    try:
                        real = abs_path.resolve()
                    except OSError:
                        continue
                    if not real.is_relative_to(self.root):
                        continue
                try:
                    st = abs_path.stat()
                except OSError:
                    continue
                # Only regular files: opening a FIFO (which a repository can
                # contain) blocks forever, and device nodes are never source.
                if not stat.S_ISREG(st.st_mode):
                    continue
                yield FileRef(path=abs_path, rel_path=rel, size=st.st_size)

    def files(self) -> tuple[FileRef, ...]:
        """All project files, materialized and cached on first access."""
        if self._files_cache is None:
            self._files_cache = tuple(self.iter_files())
        return self._files_cache

    def files_matching(self, *patterns: str) -> list[FileRef]:
        """Return files whose relative path matches any glob pattern."""
        out: list[FileRef] = []
        for f in self.files():
            if any(fnmatch.fnmatch(f.rel_path, p) or fnmatch.fnmatch(f.name, p) for p in patterns):
                out.append(f)
        return out

    def find_file(self, name: str) -> FileRef | None:
        for f in self.files():
            if f.name == name or f.rel_path == name:
                return f
        return None

    def summary(self) -> dict[str, Any]:
        """A compact, serializable snapshot for reports and the dashboard."""
        return {
            "name": self.name,
            "root": str(self.root),
            "origin": self.origin,
            "origin_url": self.origin_url,
            "file_count": len(self.files()),
            "languages": dict(sorted(self.languages.items(), key=lambda kv: kv[1], reverse=True)),
            "frameworks": self.frameworks,
            "architecture": self.architecture,
        }
