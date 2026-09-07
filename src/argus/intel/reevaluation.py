"""Post-deploy intelligence re-evaluation (spec §58)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ReevaluationHit:
    package: str
    ecosystem: str
    reason: str
    affected_targets: list[str] = field(default_factory=list)
    severity: str = "high"


def reevaluate_intel(
    *,
    known_packages: list[dict[str, Any]],
    malicious_intel: set[str] | None = None,
    targets_by_package: dict[str, list[str]] | None = None,
) -> list[ReevaluationHit]:
    """Match new intelligence against known deployed packages."""
    intel = malicious_intel or set()
    by_pkg = targets_by_package or {}
    hits: list[ReevaluationHit] = []
    for pkg in known_packages:
        name = pkg.get("name") or pkg.get("package")
        eco = pkg.get("ecosystem", "unknown")
        if not name:
            continue
        key = f"{eco}:{name}"
        if key in intel or name in intel:
            hits.append(ReevaluationHit(
                package=str(name),
                ecosystem=str(eco),
                reason="Package now flagged in threat intelligence",
                affected_targets=by_pkg.get(key, []),
                severity="critical",
            ))
    return hits
