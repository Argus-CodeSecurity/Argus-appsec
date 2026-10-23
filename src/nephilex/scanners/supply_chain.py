"""Supply-chain risk scanner: malicious packages, typosquats, suspicious scripts.

This is the foundation of Nephilex's supply-chain engine. It does not replace CVE
lookup (see :mod:`nephilex.scanners.dependencies`); it adds intelligence about
*malicious* and *suspicious* packages independent of published advisories.

Checks:

* **Known malicious packages** - bundled seed list (OSV/GitHub advisory sourced).
* **Typosquatting** - edit distance <= 1 from a popular package in the same ecosystem.
* **Suspicious npm lifecycle scripts**: ``preinstall`` / ``postinstall`` with shell
  or network patterns in ``package.json``.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from functools import lru_cache
from importlib import resources

from nephilex.core.models import (
    Confidence,
    Finding,
    Likelihood,
    Location,
    Remediation,
    Severity,
)
from nephilex.core.plugin import Scanner, ScannerContext, scanner
from nephilex.scanners._text import iter_scan_windows, match_columns
from nephilex.scanners.dependencies import _PARSERS, _loads, collect_packages
from nephilex.supply_chain.intel import (
    is_malicious,
    levenshtein,
    load_malicious_packages,
    normalize_name,
)
from nephilex.supply_chain.scripts import LIFECYCLE_HOOKS, SUSPICIOUS_INSTALL_SCRIPT


@lru_cache(maxsize=1)
def _load_popular() -> dict:
    with (
        resources.files("nephilex.scanners.data")
        .joinpath("supply_chain.json")
        .open(encoding="utf-8") as fh
    ):
        return json.load(fh).get("popular", {})


def _typosquat_candidates(name: str, ecosystem: str) -> list[str]:
    popular = _load_popular().get(ecosystem, [])
    hits: list[str] = []
    # Compare normalized names, so a PyPI spelling variant of a popular package
    # (python_dateutil for python-dateutil) is not mistaken for a typosquat.
    _, norm = normalize_name(ecosystem, name)
    for pkg in popular:
        _, other = normalize_name(ecosystem, pkg)
        if norm == other:
            continue
        if levenshtein(norm, other) <= 1:
            hits.append(pkg)
    return hits


def _known_malicious(ecosystem: str, name: str, *, online: bool = True) -> bool:
    return is_malicious(ecosystem, name, online=online)


def _hook_position(f, hook: str) -> tuple[int, int, int] | None:
    """``(line, start_column, end_column)`` of the ``"hook":`` key in a package.json."""
    key = re.compile(rf'"{re.escape(hook)}"\s*:')
    for lineno, offset, seg in iter_scan_windows(f.lines()):
        m = key.search(seg)
        if m:
            return (lineno, *match_columns(m, offset))
    return None


def _scan_npm_scripts(project, counter: int) -> Iterable[Finding]:
    for f in project.files_matching("package.json"):
        data = _loads(f.text())
        if not isinstance(data, dict):
            continue
        scripts = data.get("scripts") or {}
        if not isinstance(scripts, dict):
            continue
        for hook in LIFECYCLE_HOOKS:
            body = scripts.get(hook)
            if not isinstance(body, str) or not SUSPICIOUS_INSTALL_SCRIPT.search(body):
                continue
            counter += 1
            pos = _hook_position(f, hook)
            yield Finding(
                id=f"supply-chain:npm-script:{counter}",
                rule_id="supply-chain.npm-lifecycle-script",
                scanner="supply-chain",
                title=f"Suspicious npm {hook} script",
                description=(
                    f"The `{hook}` script in package.json contains patterns associated "
                    f"with shell execution, downloads, or credential access."
                ),
                # The line number lets the engine merge this with the malware
                # scanner's finding for the same script (same file, line, CWE).
                location=Location(
                    path=f.rel_path,
                    start_line=pos[0] if pos else None,
                    end_line=pos[0] if pos else None,
                    start_column=pos[1] if pos else None,
                    end_column=pos[2] if pos else None,
                    snippet=body[:200],
                ),
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                likelihood=Likelihood.POSSIBLE,
                cwe=["CWE-506"],
                owasp=["A06:2021-Vulnerable and Outdated Components"],
                why_vulnerable=(
                    "Lifecycle scripts run automatically on install without user "
                    "confirmation, a common supply-chain attack vector."
                ),
                attacker_perspective=(
                    "A compromised or malicious package can execute arbitrary commands "
                    "during `npm install` via lifecycle hooks."
                ),
                business_impact=(
                    "Install-time script execution can exfiltrate credentials, plant "
                    "backdoors, or compromise developer machines and CI runners."
                ),
                remediation=Remediation(
                    summary=f"Review the `{hook}` script; remove or pin trusted sources.",
                    guidance=(
                        "Prefer lockfiles, verify package provenance, and use "
                        "`npm ci --ignore-scripts` in CI until scripts are audited."
                    ),
                ),
                tags=["supply-chain", "npm", hook],
                metadata={"hook": hook},
            )


@scanner
class SupplyChainScanner(Scanner):
    name = "supply-chain"
    category = "supply-chain"
    description = "Flags known malicious packages, typosquats, and suspicious install scripts."

    def applies_to(self, project) -> bool:
        # File presence only: parsing every manifest here ran untrusted input
        # through the parsers before the scan (and outside its error handling).
        return bool(project.files_matching(*_PARSERS))

    def scan(self, ctx: ScannerContext) -> Iterable[Finding]:
        opts = ctx.config.options_for(self.name)
        online_intel = bool(opts.get("online_intel", True))
        # Warm intel cache once per scan (bundled + optional remote).
        load_malicious_packages(online=online_intel)

        counter = 0
        seen: set[tuple[str, str, str]] = set()

        for ecosystem, path, pkg, version in collect_packages(ctx.project):
            key = (ecosystem, pkg.lower(), path)
            if key in seen:
                continue
            seen.add(key)

            if _known_malicious(ecosystem, pkg, online=online_intel):
                counter += 1
                yield Finding(
                    id=f"supply-chain:malicious:{counter}",
                    rule_id="supply-chain.known-malicious",
                    scanner="supply-chain",
                    title=f"Known malicious package: {pkg}",
                    description=(
                        f"`{pkg}` ({ecosystem}) appears on Nephilex's malicious-package "
                        f"intelligence list."
                    ),
                    location=Location(path=path, snippet=f"{pkg}=={version}"),
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    likelihood=Likelihood.ALMOST_CERTAIN,
                    cwe=["CWE-506"],
                    owasp=["A06:2021-Vulnerable and Outdated Components"],
                    why_vulnerable=(
                        "This package has been reported as malicious in public "
                        "supply-chain advisories."
                    ),
                    attacker_perspective=(
                        "Malicious packages can steal credentials, backdoor builds, "
                        "or run arbitrary code during install or import."
                    ),
                    business_impact=(
                        "Critical supply-chain compromise; remove immediately and "
                        "rotate any credentials that may have been exposed."
                    ),
                    remediation=Remediation(
                        summary=f"Remove `{pkg}` and audit systems that installed it.",
                        guidance=(
                            "Rotate secrets, review CI logs, and scan for persistence. "
                            "Pin dependencies and enable lockfile-only installs."
                        ),
                    ),
                    tags=["supply-chain", "malicious", ecosystem.lower()],
                    metadata={"ecosystem": ecosystem, "package": pkg, "version": version},
                )
                continue

            typos = _typosquat_candidates(pkg, ecosystem)
            if typos:
                counter += 1
                yield Finding(
                    id=f"supply-chain:typosquat:{counter}",
                    rule_id="supply-chain.typosquat",
                    scanner="supply-chain",
                    title=f"Possible typosquat: {pkg}",
                    description=(
                        f"`{pkg}` is one edit away from popular package(s): {', '.join(typos)}."
                    ),
                    location=Location(path=path, snippet=f"{pkg}=={version}"),
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    likelihood=Likelihood.POSSIBLE,
                    cwe=["CWE-506"],
                    owasp=["A06:2021-Vulnerable and Outdated Components"],
                    why_vulnerable=(
                        "Typosquatting packages mimic trusted names to trick "
                        "installers into pulling the wrong dependency."
                    ),
                    attacker_perspective=(
                        "Developers mistyping a package name may install an attacker-"
                        "controlled package with the same install privileges."
                    ),
                    business_impact="Supply-chain compromise via mistaken dependency.",
                    remediation=Remediation(
                        summary=f"Verify `{pkg}` is intentional; prefer `{typos[0]}` if not.",
                        guidance=(
                            "Check package provenance, publisher identity, and download "
                            "counts before accepting unfamiliar names."
                        ),
                    ),
                    tags=["supply-chain", "typosquat", ecosystem.lower()],
                    metadata={
                        "ecosystem": ecosystem,
                        "package": pkg,
                        "similar_to": typos,
                    },
                )

        yield from _scan_npm_scripts(ctx.project, counter)
