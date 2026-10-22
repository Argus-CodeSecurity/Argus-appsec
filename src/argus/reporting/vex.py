"""OpenVEX reporter.

Emits an OpenVEX (https://openvex.dev) document describing the exploitability of
each known-vulnerable dependency Argus found. VEX is the machine-readable standard
for "this CVE is present but not exploitable here", and it is the formal
expression of Argus's reachability analysis: a dependency whose vulnerable code is
never imported is reported as ``not_affected`` with the standard justification,
while a reachable one is ``affected`` with the fix. Pairing this with an SBOM is
increasingly requested by enterprise buyers.

Only findings that carry a CVE (the dependency scanner's output) are VEX-relevant;
SAST, secret, and IaC findings are not about third-party components and are
omitted.
"""

from __future__ import annotations

import hashlib
import json

from argus.analysis import reachability
from argus.core.models import ScanResult
from argus.core.plugin import Reporter, reporter

_OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"
_AUTHOR = "Argus AppSec"

# Dependency ecosystem -> Package URL (purl) type.
_PURL_TYPE = {
    "PyPI": "pypi",
    "npm": "npm",
    "Go": "golang",
    "crates.io": "cargo",
    "RubyGems": "gem",
    "Packagist": "composer",
}


def _purl(finding) -> str:
    """Best-effort Package URL for a dependency finding (generic fallback)."""
    name, _, version = (finding.location.snippet or "").partition("==")
    name = name.strip() or "unknown"
    version = version.strip()
    ptype = _PURL_TYPE.get(next((t for t in finding.tags if t in _PURL_TYPE), ""), "generic")
    return f"pkg:{ptype}/{name}" + (f"@{version}" if version else "")


@reporter
class VexReporter(Reporter):
    name = "vex"
    extension = "json"
    description = "OpenVEX document: exploitability status of vulnerable dependencies."

    def render(self, result: ScanResult) -> str:
        statements = []
        seen: set[tuple[str, str]] = set()
        for f in result.sorted_findings():
            cve = f.metadata.get("cve")
            if not cve:
                continue  # VEX is about known-CVE components, not SAST findings
            product = _purl(f)
            if (cve, product) in seen:
                continue
            seen.add((cve, product))

            not_reachable = f.metadata.get("reachability") == reachability.NOT_IMPORTED
            stmt: dict = {
                "vulnerability": {"name": cve},
                "products": [{"@id": product}],
                "status": "not_affected" if not_reachable else "affected",
            }
            if not_reachable:
                stmt["justification"] = "vulnerable_code_not_in_execute_path"
                stmt["impact_statement"] = (
                    "The vulnerable package is present but its code is never imported "
                    "by this project, so the vulnerability is not reachable."
                )
            else:
                fixed = f.metadata.get("fixed_version")
                stmt["action_statement"] = (
                    f"Upgrade to {fixed} or later." if fixed else "Upgrade to a patched version."
                )
            statements.append(stmt)

        timestamp = result.started_at.isoformat()
        digest = hashlib.sha256(f"{result.target}{timestamp}".encode()).hexdigest()[:16]
        doc = {
            "@context": _OPENVEX_CONTEXT,
            "@id": f"https://openvex.dev/docs/argus/{digest}",
            "author": _AUTHOR,
            "role": "Automated security scanner",
            "timestamp": timestamp,
            "version": 1,
            "tooling": f"Argus AppSec {result.argus_version}",
            "statements": statements,
        }
        return json.dumps(doc, indent=2)
