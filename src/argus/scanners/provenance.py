"""Read SLSA / in-toto provenance attestations (static, no execution)."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from pathlib import PurePosixPath

from argus.core.models import (
    Confidence,
    Finding,
    Likelihood,
    Location,
    Remediation,
    Severity,
)
from argus.core.plugin import Scanner, ScannerContext, scanner

_ATTESTATION_NAMES = re.compile(
    r"(?i)(provenance|attestation|\.intoto\.jsonl|slsa\.provenance)",
)


def _loads(text: str) -> dict | list | None:
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None


def _check_provenance(path: str, data: dict, counter: int) -> Iterable[Finding]:
    """Validate minimal SLSA provenance fields when present."""
    # SLSA v1 predicate
    predicate = data.get("predicate") or data
    if isinstance(predicate, dict) and predicate.get("buildType"):
        builder = (predicate.get("builder") or {}).get("id", "")
        if not builder:
            counter += 1
            yield Finding(
                id=f"provenance:missing-builder:{counter}",
                rule_id="provenance.missing-builder-id",
                scanner="provenance",
                title="Provenance attestation missing builder identity",
                description="The attestation has no builder.id — provenance is incomplete.",
                location=Location(path=path),
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                likelihood=Likelihood.UNLIKELY,
                cwe=["CWE-345"],
                owasp=["A08:2021-Software and Data Integrity Failures"],
                why_vulnerable="Without builder identity, provenance cannot be verified.",
                remediation=Remediation(
                    summary="Regenerate attestation with a identified builder.",
                    guidance="Use SLSA-compliant CI with signed provenance (GitHub attestations, Sigstore).",
                ),
                tags=["provenance", "slsa"],
            )
        return

    # Unsigned / minimal stub
    if data.get("_type") == "https://in-toto.io/Statement/v1":
        subj = data.get("subject") or []
        if subj and not data.get("verification"):
            counter += 1
            yield Finding(
                id=f"provenance:unsigned:{counter}",
                rule_id="provenance.unsigned",
                scanner="provenance",
                title="Provenance attestation is not signed",
                description=(
                    "An in-toto statement was found without verification material. "
                    "Treat as informational until signature is validated."
                ),
                location=Location(path=path),
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                likelihood=Likelihood.UNLIKELY,
                cwe=["CWE-345"],
                owasp=["A08:2021-Software and Data Integrity Failures"],
                why_vulnerable="Unsigned provenance can be forged.",
                remediation=Remediation(
                    summary="Verify attestation signatures against trusted roots.",
                ),
                tags=["provenance", "unsigned"],
            )


@scanner
class ProvenanceScanner(Scanner):
    name = "provenance"
    category = "supply-chain"
    description = "Reads SLSA/in-toto provenance files and flags integrity gaps."

    def applies_to(self, project) -> bool:
        return any(
            _ATTESTATION_NAMES.search(f.rel_path)
            for f in project.files()
        )

    def scan(self, ctx: ScannerContext) -> Iterable[Finding]:
        counter = 0
        for f in ctx.project.files():
            if not _ATTESTATION_NAMES.search(f.rel_path):
                continue
            if f.suffix not in (".json", ".jsonl", "") and ".json" not in f.rel_path:
                continue
            text = f.text()
            if f.rel_path.endswith(".jsonl"):
                for line in text.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    data = _loads(line)
                    if isinstance(data, dict):
                        yield from _check_provenance(f.rel_path, data, counter)
                        counter += 1
            else:
                data = _loads(text)
                if isinstance(data, dict):
                    yield from _check_provenance(f.rel_path, data, counter)
                    counter += 1

        # Flag release directories with no provenance at all (optional, info).
        opts = ctx.config.options_for(self.name)
        if opts.get("require_for_releases"):
            for f in ctx.project.files_matching("package.json"):
                rel = PurePosixPath(f.rel_path)
                if rel.parent.name != "dist" and rel.parent.name != "build":
                    continue
                counter += 1
                yield Finding(
                    id=f"provenance:missing:{counter}",
                    rule_id="provenance.missing",
                    scanner="provenance",
                    title="Release artifact directory has no provenance attestation",
                    description=f"No provenance file found near `{f.rel_path}`.",
                    location=Location(path=f.rel_path),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.LOW,
                    likelihood=Likelihood.UNLIKELY,
                    cwe=["CWE-345"],
                    owasp=["A08:2021-Software and Data Integrity Failures"],
                    why_vulnerable="Artifacts without provenance cannot be traced to source.",
                    remediation=Remediation(
                        summary="Attach SLSA provenance to release artifacts.",
                    ),
                    tags=["provenance"],
                )
