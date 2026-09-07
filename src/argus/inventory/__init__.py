"""Dependency inventory helpers shared by SBOM, SCA, and diff analysis."""

from __future__ import annotations

from pathlib import Path

from argus.remediation import git_ops
from argus.scanners.dependencies import _PARSERS, collect_packages

__all__ = ["collect_packages", "collect_packages_at_ref", "split_ref_spec"]


def split_ref_spec(ref_spec: str, *, head: str = "HEAD") -> tuple[str, str]:
    """Split ``base...head`` or bare base ref into ``(base, head)``."""
    spec = ref_spec.strip()
    if "..." in spec:
        base, h = spec.split("...", 1)
        return base.strip(), (h.strip() or head)
    return spec, head


def collect_packages_at_ref(root: Path, ref: str) -> list[tuple[str, str, str, str]]:
    """Collect ``(ecosystem, manifest_path, package, version)`` at a git ref.

    Reads manifest/lock file contents via ``git show ref:path``. Falls back to
    the working tree when ``ref`` is ``HEAD`` and a file is modified but present.
    """
    per_eco: dict[str, dict[tuple[str, str], tuple[str, str, str]]] = {}
    for manifest_name, (ecosystem, parser) in _PARSERS.items():
        text: str | None = None
        if ref in ("HEAD", "WORKTREE"):
            candidate = root / manifest_name
            if candidate.is_file():
                text = candidate.read_text(encoding="utf-8", errors="replace")
        else:
            text = git_ops.show_file(root, ref, manifest_name)
        if not text:
            continue
        for pkg, version in parser(text):
            bucket = per_eco.setdefault(ecosystem, {})
            bucket.setdefault((pkg, version), (manifest_name, pkg, version))
    out: list[tuple[str, str, str, str]] = []
    for ecosystem, bucket in per_eco.items():
        for path, pkg, version in bucket.values():
            out.append((ecosystem, path, pkg, version))
    out.sort(key=lambda t: (t[0], t[2], t[3], t[1]))
    return out
