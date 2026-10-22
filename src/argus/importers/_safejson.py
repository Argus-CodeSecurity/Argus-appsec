"""Bounded JSON loading for untrusted import files.

A file handed to ``argus import`` comes from another tool, a CI artifact or a
pull request, so it is treated like any other untrusted input: the size is
capped before anything is read into memory, non-standard constants (``NaN``,
``Infinity``) are rejected, and nesting depth is bounded both by the decoder's
own recursion guard and by an explicit, iterative check afterwards.
"""

from __future__ import annotations

import json
import stat
from pathlib import Path
from typing import Any

#: Largest import file read, in bytes. Real SARIF from a large CodeQL or
#: Semgrep run is a few megabytes; anything near this is almost certainly not
#: a report anyone meant to import.
DEFAULT_MAX_BYTES = 50 * 1024 * 1024

#: Deepest JSON nesting accepted. SARIF itself needs about a dozen levels
#: (code flows are the deepest part); the rest is headroom for ``properties``.
MAX_DEPTH = 64


class ImportFormatError(ValueError):
    """An import file could not be read or is not acceptable input."""


def read_bounded(path: Path, max_bytes: int = DEFAULT_MAX_BYTES) -> bytes:
    """Read a regular file of at most ``max_bytes`` bytes.

    The size is checked before reading and again on the bytes actually read,
    so a file that grows between the two cannot slip past the cap. Only
    regular files are read: a FIFO would block forever.
    """
    try:
        st = path.stat()
    except OSError as exc:
        raise ImportFormatError(f"cannot read {path}: {exc.strerror or exc}") from exc
    if not stat.S_ISREG(st.st_mode):
        raise ImportFormatError(f"{path} is not a regular file")
    if st.st_size > max_bytes:
        raise ImportFormatError(f"{path} is {st.st_size} bytes; the import limit is {max_bytes}")
    try:
        with path.open("rb") as fh:
            data = fh.read(max_bytes + 1)
    except OSError as exc:
        raise ImportFormatError(f"cannot read {path}: {exc.strerror or exc}") from exc
    if len(data) > max_bytes:
        raise ImportFormatError(f"{path} exceeds the import limit of {max_bytes} bytes")
    return data


def _reject_constant(name: str) -> Any:
    raise ImportFormatError(f"non-standard JSON constant {name!r}")


def _depth_exceeds(value: Any, limit: int) -> bool:
    """True if ``value`` nests containers deeper than ``limit`` (iterative)."""
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, dict):
            children: Any = node.values()
        elif isinstance(node, list):
            children = node
        else:
            continue
        if depth > limit:
            return True
        stack.extend((child, depth + 1) for child in children)
    return False


def loads_untrusted(data: bytes, *, source: str, max_depth: int = MAX_DEPTH) -> Any:
    """Decode UTF-8 JSON from an untrusted source with a depth bound."""
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ImportFormatError(f"{source} is not UTF-8 encoded: {exc.reason}") from exc
    try:
        value = json.loads(text, parse_constant=_reject_constant)
    except RecursionError as exc:
        raise ImportFormatError(f"{source} is nested too deeply to import") from exc
    except json.JSONDecodeError as exc:
        raise ImportFormatError(
            f"{source} is not valid JSON (line {exc.lineno}, column {exc.colno}): {exc.msg}"
        ) from exc
    if _depth_exceeds(value, max_depth):
        raise ImportFormatError(f"{source} nests deeper than {max_depth} levels")
    return value
