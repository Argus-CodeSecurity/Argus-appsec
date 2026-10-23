"""Download the vulnerable and patched version of every manifest case.

Files come from ``raw.githubusercontent.com`` at the exact commit SHAs in the
manifest and are written under ``benchmarks/.corpora/heldout/files`` (git
ignored). They are third-party code: they are scanned as data and never
imported or executed. The SHA-256 and size of each version are recorded in the
manifest the first time they are fetched; later fetches verify against them.
"""

from __future__ import annotations

import hashlib
from pathlib import Path, PurePosixPath
from typing import Any

from benchmarks.heldout.github import Client, GitHubError
from benchmarks.heldout.selection import MAX_FILE_BYTES

VERSIONS = ("vulnerable", "patched")

# Directory names that at least one of the three tools skips by default
# (Nephilex DEFAULT_IGNORES, Semgrep's default .semgrepignore, Bandit's default
# excludes). The selection rule already drops test, vendored and build paths;
# any remaining component with one of these names is renamed with a trailing
# underscore so that no tool silently skips a case because of where the file
# sat in its repository.
SKIPPED_DIR_NAMES = frozenset(
    {
        ".git", ".hg", ".svn", ".bzr", "cvs", "node_modules", "vendor", "dist", "build",
        ".venv", "venv", "env", ".env", "__pycache__", ".mypy_cache", ".pytest_cache",
        ".ruff_cache", ".tox", ".eggs", ".next", ".nuxt", "target", ".gradle", ".idea",
        ".nephilex", "coverage", "htmlcov", ".terraform", "test", "tests",
    }
)  # fmt: skip
# Path components kept below the case directory (parent dirs plus file name).
# The full repository path can exceed Windows path limits; the last three
# components keep the framework hints (``views.py``, ``routes/``) that matter.
KEEP_COMPONENTS = 3


def local_relpath(repo_path: str) -> str:
    """Where a repository file is stored inside its case/version directory."""
    parts = [p for p in PurePosixPath(repo_path).parts if p not in ("", ".", "..", "/")]
    parts = parts[-KEEP_COMPONENTS:]
    dirs = [f"{p}_" if p.lower() in SKIPPED_DIR_NAMES else p for p in parts[:-1]]
    return "/".join([*dirs, parts[-1]])


def case_file(files_root: Path, case: dict[str, Any], version: str) -> Path:
    key = "path_vulnerable" if version == "vulnerable" else "path_patched"
    return files_root / case["case_id"] / version / local_relpath(case[key])


def fetch_case(client: Client, files_root: Path, case: dict[str, Any]) -> str | None:
    """Fetch both versions; record hashes; return an exclusion reason or None."""
    recorded = case.setdefault("content", {})
    for version in VERSIONS:
        sha = case["parent_sha"] if version == "vulnerable" else case["fix_sha"]
        path = case["path_vulnerable"] if version == "vulnerable" else case["path_patched"]
        dest = case_file(files_root, case, version)
        expected = recorded.get(version)
        if dest.is_file() and expected and _sha256(dest.read_bytes()) == expected["sha256"]:
            continue
        try:
            data = client.raw(case["repo"], sha, path)
        except GitHubError as exc:
            return f"download failed ({version}): {exc}"
        digest = _sha256(data)
        if expected and expected["sha256"] != digest:
            return f"content changed since the manifest was frozen ({version})"
        if len(data) > MAX_FILE_BYTES:
            recorded[version] = {"sha256": digest, "bytes": len(data)}
            return f"file larger than {MAX_FILE_BYTES} bytes ({version})"
        if b"\x00" in data[:4096]:
            return f"binary content ({version})"
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        recorded[version] = {"sha256": digest, "bytes": len(data)}
    return None


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
