"""Static asset inventory from repository analysis."""

from __future__ import annotations

from typing import Any

from argus.analysis.repository import RepositoryAnalyzer
from argus.core.project import Project
from argus.scanners.dependencies import collect_packages


def build_inventory(project: Project) -> dict[str, Any]:
    """Build a JSON-serializable inventory of what Argus discovered in a repo."""
    RepositoryAnalyzer().analyze(project)
    arch = project.architecture or {}
    packages = [
        {
            "ecosystem": eco,
            "name": name,
            "version": version,
            "manifest": manifest,
        }
        for eco, name, version, manifest in collect_packages(project)
    ]
    summary = project.summary()
    return {
        "target": str(project.root),
        "languages": project.languages,
        "frameworks": project.frameworks,
        "architecture": arch,
        "dependencies": packages,
        "counts": {
            "files": summary.get("file_count", 0),
            "dependencies": len(packages),
            "ci_cd_files": len(arch.get("ci_cd") or []),
            "container_files": len(arch.get("containers") or []),
            "iac_files": len(arch.get("iac") or []),
        },
    }
