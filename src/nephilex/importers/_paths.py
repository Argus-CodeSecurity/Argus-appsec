"""Resolve SARIF artifact URIs to project-relative paths, safely.

SARIF locates a result with an ``artifactLocation``: a URI that is either
absolute (``file:///home/ci/repo/src/app.py``) or relative to a named base
(``uriBaseId``) defined in ``run.originalUriBaseIds`` or implied by
convention (``%SRCROOT%``). The URI is untrusted input, so resolution is
purely lexical first and only then checked against the real project root:

* a relative path that climbs out of the root (``../../etc/passwd``) is
  rejected, never clamped;
* an absolute path is accepted only if it lies inside the project root;
* a base URI that points somewhere else (the checkout path on the CI machine
  that produced the file) is treated as the project root, so the relative
  part is re-anchored here rather than followed elsewhere;
* nothing outside the root is ever opened: :meth:`PathResolver.read_lines`
  resolves symlinks and re-checks containment before reading.
"""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any
from urllib.parse import unquote, urlsplit

from nephilex.core.project import MAX_TEXT_BYTES

_SCHEME = re.compile(r"^(?P<scheme>[A-Za-z][A-Za-z0-9+.\-]+):")
_WIN_DRIVE = re.compile(r"^[A-Za-z]:(?:[\\/]|$)")
# "C:" or a drive-relative "C:name": on Windows either one leaves the root.
_DRIVE_SEGMENT = re.compile(r"^[A-Za-z]:")
# Bases are rarely chained more than once or twice; stop a cycle early.
_MAX_BASE_CHAIN = 8
_SNIFF_BYTES = 2048


class UnsafePathError(ValueError):
    """A SARIF location would resolve outside the project root."""


@dataclass(frozen=True)
class ResolvedPath:
    """Where an artifact location points.

    ``kind`` is ``"file"`` for a path inside the project (``path`` is POSIX and
    relative to the root) and ``"external"`` for something that is not a
    local file, such as an ``https`` URL (``path`` is the URL).
    """

    kind: str
    path: str
    rebased: bool = False


def _clean_relative(raw: str) -> str:
    """Normalize a relative path lexically, refusing to leave the root."""
    parts: list[str] = []
    for seg in raw.replace("\\", "/").split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if not parts:
                raise UnsafePathError("path escapes the project root")
            parts.pop()
            continue
        if _DRIVE_SEGMENT.match(seg):
            raise UnsafePathError("path contains a drive letter")
        parts.append(seg)
    if not parts:
        raise UnsafePathError("path is empty")
    return "/".join(parts)


@dataclass
class _Uri:
    """A parsed artifact URI: absolute local path, relative path or external URL."""

    kind: str  # "absolute" | "relative" | "external"
    value: str


def _parse_uri(uri: str) -> _Uri:
    if "\x00" in uri:
        raise UnsafePathError("path contains a NUL byte")
    uri = uri.strip()
    if not uri:
        raise UnsafePathError("path is empty")
    if uri.startswith(("\\\\", "//")):
        raise UnsafePathError("network (UNC) paths are not supported")
    if _WIN_DRIVE.match(uri):
        return _Uri("absolute", uri.replace("\\", "/"))
    m = _SCHEME.match(uri)
    if m:
        scheme = m.group("scheme").lower()
        if scheme == "file":
            parts = urlsplit(uri)
            if parts.netloc not in ("", "localhost"):
                raise UnsafePathError("file URIs on another host are not supported")
            path = unquote(parts.path)
            if re.match(r"^/[A-Za-z]:(?:/|$)", path):
                path = path[1:]  # file:///C:/repo -> C:/repo
            return _Uri("absolute", path)
        if scheme in ("http", "https"):
            return _Uri("external", uri)
        raise UnsafePathError(f"unsupported URI scheme {scheme!r}")
    path = unquote(uri.split("?", 1)[0].split("#", 1)[0]).replace("\\", "/")
    if path.startswith("/"):
        return _Uri("absolute", path)
    return _Uri("relative", path)


def _is_filesystem_root(path: str) -> bool:
    stripped = path.rstrip("/")
    return stripped == "" or bool(re.fullmatch(r"[A-Za-z]:", stripped))


@dataclass
class PathResolver:
    """Resolve artifact locations for one SARIF run against a project root."""

    root: Path
    base_ids: dict[str, Any] = field(default_factory=dict)
    _lines: dict[str, list[str] | None] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        self.root = self.root.resolve()

    # --- bases ---------------------------------------------------------------
    def _base(self, base_id: str | None, depth: int = 0) -> _Uri | None:
        """The resolved value of ``base_id``; None means "the project root"."""
        if not base_id or depth > _MAX_BASE_CHAIN:
            return None
        entry = self.base_ids.get(base_id)
        if not isinstance(entry, dict):
            # %SRCROOT% and friends are often used without a definition.
            return None
        uri = entry.get("uri")
        if not isinstance(uri, str) or not uri.strip():
            return None
        parsed = _parse_uri(uri)
        if parsed.kind == "external":
            raise UnsafePathError(f"base {base_id!r} is not a local path")
        if parsed.kind == "absolute":
            return None if _is_filesystem_root(parsed.value) else parsed
        parent_id = entry.get("uriBaseId")
        parent = self._base(parent_id if isinstance(parent_id, str) else None, depth + 1)
        if parent is None:
            return _Uri("relative", parsed.value)
        joined = parent.value.rstrip("/") + "/" + parsed.value
        return _Uri(parent.kind, joined)

    # --- resolution ----------------------------------------------------------
    def _inside_root(self, absolute: str) -> str | None:
        """The root-relative path of ``absolute``, or None if it is outside."""
        windows = bool(_WIN_DRIVE.match(absolute))
        pure: PurePosixPath | PureWindowsPath = (
            PureWindowsPath(absolute) if windows else PurePosixPath(absolute)
        )
        if ".." in pure.parts:
            # Normalize lexically before comparing; ".." in an absolute path
            # is either harmless noise or an attempt to sneak out.
            anchor, rest = pure.anchor, pure.relative_to(pure.anchor).as_posix()
            try:
                cleaned = _clean_relative(rest)
            except UnsafePathError:
                return None
            pure = type(pure)(anchor + cleaned)
        candidate = Path(str(pure))
        if not candidate.is_absolute():
            # A Windows path on a POSIX host (or vice versa) cannot be ours.
            return None
        try:
            rel = candidate.resolve(strict=False).relative_to(self.root)
        except (ValueError, OSError):
            return None
        posix = rel.as_posix()
        return None if posix in ("", ".") else posix

    def resolve(self, uri: str, base_id: str | None = None) -> ResolvedPath:
        """Resolve one artifact location, raising :class:`UnsafePathError`."""
        parsed = _parse_uri(uri)
        if parsed.kind == "external":
            return ResolvedPath("external", parsed.value)
        if parsed.kind == "absolute":
            rel = self._inside_root(parsed.value)
            if rel is None:
                raise UnsafePathError("absolute path is outside the project root")
            return ResolvedPath("file", rel)
        relative = _clean_relative(parsed.value)
        base = self._base(base_id)
        if base is None:
            return ResolvedPath("file", relative)
        if base.kind == "relative":
            return ResolvedPath("file", _clean_relative(base.value + "/" + relative))
        inside = self._inside_root(base.value.rstrip("/") + "/" + relative)
        if inside is not None:
            return ResolvedPath("file", inside)
        # The base names the checkout on the machine that produced the file.
        # Re-anchor the (already validated) relative part on our root.
        return ResolvedPath("file", relative, rebased=True)

    # --- reading -------------------------------------------------------------
    def read_lines(self, rel_path: str) -> list[str] | None:
        """The lines of a project file, or None if it cannot be read safely.

        Follows the same rules as the project walk: the real path (after
        symlinks) must stay inside the root, only regular text files up to the
        project size limit are read, and binary files are skipped.
        """
        if rel_path in self._lines:
            return self._lines[rel_path]
        self._lines[rel_path] = lines = self._read(rel_path)
        return lines

    def _read(self, rel_path: str) -> list[str] | None:
        if os.name == "nt" and ":" in rel_path:
            return None  # alternate data streams, device names
        try:
            real = self.root.joinpath(*rel_path.split("/")).resolve(strict=True)
            if not real.is_relative_to(self.root):
                return None
            st = real.stat()
            if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_TEXT_BYTES:
                return None
            with real.open("rb") as fh:
                data = fh.read(MAX_TEXT_BYTES + 1)
        except OSError:
            return None
        if len(data) > MAX_TEXT_BYTES or b"\x00" in data[:_SNIFF_BYTES]:
            return None
        return data.decode("utf-8", errors="replace").splitlines()
