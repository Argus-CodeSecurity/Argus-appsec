"""SPDX 2.3 SBOM generation."""

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


def _spdx_id(ecosystem: str, name: str, version: str) -> str:
    digest = hashlib.sha256(f"{ecosystem}:{name}@{version}".encode()).hexdigest()[:16]
    return f"SPDXRef-Package-{digest}"


def build_spdx(
    project: Project,
    *,
    name: str | None = None,
    version: str = "0.0.0",
) -> dict[str, Any]:
    """Build an SPDX 2.3 JSON document for ``project``."""
    app_name = name or project.root.name or "application"
    doc_id = f"SPDXRef-DOCUMENT-{uuid.uuid5(uuid.NAMESPACE_URL, str(project.root))}"
    root_id = "SPDXRef-RootPackage"

    packages: list[dict[str, Any]] = [{
        "SPDXID": root_id,
        "name": app_name,
        "versionInfo": version,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "supplier": "NOASSERTION",
        "primaryPackagePurpose": "APPLICATION",
    }]

    relationships: list[dict[str, str]] = [{
        "spdxElementId": doc_id,
        "relationshipType": "DESCRIBES",
        "relatedSpdxElement": root_id,
    }]

    seen: set[tuple[str, str, str]] = set()
    for ecosystem, path, pkg, ver in collect_packages(project):
        key = (ecosystem, pkg, ver)
        if key in seen:
            continue
        seen.add(key)
        spdx_id = _spdx_id(ecosystem, pkg, ver)
        packages.append({
            "SPDXID": spdx_id,
            "name": pkg,
            "versionInfo": ver,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "supplier": "NOASSERTION",
            "externalRefs": [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": _purl(ecosystem, pkg, ver),
            }],
            "comment": f"ecosystem={ecosystem}; manifest={path}",
        })
        relationships.append({
            "spdxElementId": root_id,
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": spdx_id,
        })

    packages.sort(key=lambda p: (p.get("name", ""), p.get("versionInfo", "")))

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": doc_id,
        "name": f"{app_name}-sbom",
        "documentNamespace": f"https://argus.local/sbom/{uuid.uuid4()}",
        "creationInfo": {
            "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "creators": [f"Tool: argus-appsec-{__version__}"],
        },
        "packages": packages,
        "relationships": relationships,
    }
