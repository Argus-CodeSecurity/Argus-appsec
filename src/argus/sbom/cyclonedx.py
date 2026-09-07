"""CycloneDX SBOM generation from dependency manifests and lock files."""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any

from argus import __version__
from argus.core.project import Project
from argus.scanners.dependencies import collect_packages

_PURL_TYPE = {
    "PyPI": "pypi",
    "npm": "npm",
    "Go": "golang",
    "crates.io": "cargo",
    "RubyGems": "gem",
    "Packagist": "composer",
}


def _purl(ecosystem: str, name: str, version: str) -> str:
    ptype = _PURL_TYPE.get(ecosystem, "generic")
    return f"pkg:{ptype}/{name}@{version}"


def _bom_ref(ecosystem: str, name: str, version: str) -> str:
    raw = f"{ecosystem}:{name}@{version}".encode()
    return hashlib.sha256(raw).hexdigest()[:32]


def build_cyclonedx(
    project: Project,
    *,
    name: str | None = None,
    version: str = "0.0.0",
) -> dict[str, Any]:
    """Build a CycloneDX 1.5 JSON document for ``project``."""
    components: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    for ecosystem, path, pkg, ver in collect_packages(project):
        key = (ecosystem, pkg, ver)
        if key in seen:
            continue
        seen.add(key)
        ref = _bom_ref(ecosystem, pkg, ver)
        components.append({
            "type": "library",
            "bom-ref": ref,
            "name": pkg,
            "version": ver,
            "purl": _purl(ecosystem, pkg, ver),
            "properties": [
                {"name": "argus:ecosystem", "value": ecosystem},
                {"name": "argus:manifest", "value": path},
            ],
        })

    components.sort(key=lambda c: (c["name"], c["version"]))
    serial = uuid.uuid5(uuid.NAMESPACE_URL, str(project.root))

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": [{"vendor": "Argus", "name": "argus-appsec", "version": __version__}],
            "component": {
                "type": "application",
                "name": name or project.root.name or "application",
                "version": version,
            },
        },
        "components": components,
    }
