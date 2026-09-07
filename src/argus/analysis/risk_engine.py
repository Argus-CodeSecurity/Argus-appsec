"""Contextual risk scoring (spec §30)."""

from __future__ import annotations

from argus.core.models import ScanResult, Severity


def enrich_contextual_risk(result: ScanResult) -> None:
    """Augment each finding with contextual risk metadata."""
    summary = result.project_summary or {}
    internet_exposed = bool(summary.get("live_target") or summary.get("has_api"))
    production = "production" in str(summary.get("environment", "")).lower()

    for f in result.findings:
        base = f.risk_score()
        boost = 0.0
        if f.severity >= Severity.HIGH:
            boost += 10
        if "reachable" in f.tags or f.metadata.get("reachability") == "REACHABLE":
            boost += 15
        if "attack-chain" in f.tags or f.scanner == "chains":
            boost += 20
        if internet_exposed and f.severity >= Severity.MEDIUM:
            boost += 10
        if production:
            boost += 5
        if "kev" in f.tags or "epss-high" in f.tags:
            boost += 12
        if f.metadata.get("verification") == "verified":
            boost += 8

        contextual = min(100.0, round(base + boost, 1))
        f.metadata["contextual_risk"] = contextual
        f.metadata["risk_factors"] = {
            "base": base,
            "internet_exposed": internet_exposed,
            "production": production,
            "boost": boost,
        }
