"""Finding verification state assignment (spec §31)."""

from __future__ import annotations

from argus.core.models import Confidence, Finding


def assign_verification_state(finding: Finding) -> str:
    """Return verification state: detected|likely|confirmed|verified|fixed|accepted|false_positive."""
    existing = finding.metadata.get("verification")
    if existing in {
        "verified", "confirmed", "fixed", "accepted", "false_positive", "likely", "detected",
    }:
        return str(existing)

    if finding.remediation and finding.remediation.verified:
        return "fixed"
    if finding.metadata.get("finding_kind") == "dynamic":
        return "verified"
    if finding.scanner in ("secret_verify", "dast", "host", "fim", "container-image"):
        return "confirmed"
    if finding.confidence >= Confidence.HIGH and finding.metadata.get("evidence"):
        return "confirmed"
    if finding.confidence >= Confidence.MEDIUM:
        return "likely"
    return "detected"


def apply_verification_states(findings: list[Finding]) -> None:
    for f in findings:
        f.metadata["verification"] = assign_verification_state(f)
