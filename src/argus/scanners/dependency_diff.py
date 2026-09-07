"""Dependency version differential scanner for pull requests."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from argus.core.models import (
    Confidence,
    Finding,
    Likelihood,
    Location,
    Remediation,
    Severity,
)
from argus.core.plugin import Scanner, ScannerContext, scanner
from argus.inventory.dependency_diff import PackageChange, diff_packages
from argus.remediation import git_ops
from argus.supply_chain.behavior import compare_fingerprints, npm_fingerprint


def _change_finding(change: PackageChange, counter: int) -> Finding:
    if change.change == "added":
        title = f"Dependency added: {change.package}@{change.new_version}"
        severity = Severity.MEDIUM
        why = "A new dependency expands the supply-chain attack surface."
    elif change.change == "removed":
        title = f"Dependency removed: {change.package}"
        severity = Severity.INFO
        why = "Dependency removed; verify nothing required it at runtime."
    else:
        title = (
            f"Dependency version changed: {change.package} "
            f"{change.old_version} → {change.new_version}"
        )
        severity = Severity.MEDIUM
        why = "Version changes can introduce new vulnerabilities or malicious behavior."

    return Finding(
        id=f"dependency-diff:{change.change}:{counter}",
        rule_id=f"dependency-diff.{change.change}",
        scanner="dependency-diff",
        title=title,
        description=(
            f"{change.package} ({change.ecosystem}) in `{change.manifest}`: "
            f"{change.old_version or 'n/a'} -> {change.new_version or 'n/a'}."
        ),
        location=Location(
            path=change.manifest,
            snippet=f"{change.package}=={change.new_version or change.old_version}",
        ),
        severity=severity,
        confidence=Confidence.HIGH,
        likelihood=Likelihood.POSSIBLE if change.change != "removed" else Likelihood.RARE,
        cwe=["CWE-1104"] if change.change != "removed" else [],
        owasp=["A06:2021-Vulnerable and Outdated Components"],
        why_vulnerable=why,
        attacker_perspective=(
            "Supply-chain attacks often land through new or updated dependencies "
            "in lockfile changes merged without review."
        ),
        business_impact="Unreviewed dependency changes can introduce CVEs or malware.",
        remediation=Remediation(
            summary="Review the dependency diff before merge.",
            guidance=(
                "Run `argus scan --diff` and inspect SBOM delta; pin trusted versions."
            ),
        ),
        tags=["supply-chain", "dependency-diff", change.change],
        metadata={
            "ecosystem": change.ecosystem,
            "package": change.package,
            "old_version": change.old_version,
            "new_version": change.new_version,
            "change": change.change,
        },
    )


def _behavior_findings(change: PackageChange, counter: int, *, timeout: float) -> Iterable[Finding]:
    if change.ecosystem != "npm" or change.change != "changed":
        return
    if not change.old_version or not change.new_version:
        return
    old_fp = npm_fingerprint(change.package, change.old_version, timeout=timeout)
    new_fp = npm_fingerprint(change.package, change.new_version, timeout=timeout)
    for anomaly in compare_fingerprints(old_fp, new_fp):
        counter += 1
        yield Finding(
            id=f"dependency-diff:behavior:{counter}",
            rule_id="dependency-diff.behavior-anomaly",
            scanner="dependency-diff",
            title=f"Behavioral anomaly in {change.package} version update",
            description=(
                f"{change.package} {change.old_version} → {change.new_version}: {anomaly}."
            ),
            location=Location(path=change.manifest, snippet=anomaly),
            severity=Severity.CRITICAL,
            confidence=Confidence.MEDIUM,
            likelihood=Likelihood.LIKELY,
            cwe=["CWE-506"],
            owasp=["A06:2021-Vulnerable and Outdated Components"],
            why_vulnerable=(
                "The new version adds install-time capabilities not present before, "
                "a common sign of supply-chain compromise."
            ),
            attacker_perspective=(
                "Malicious maintainers add install scripts in patch releases to "
                "execute during CI `npm ci`."
            ),
            business_impact="Potential credential theft or backdoor during install.",
            remediation=Remediation(
                summary="Block merge until the version change is verified with the publisher.",
                guidance=(
                    "Compare registry metadata, review publisher identity, and test "
                    "in an isolated environment before adopting the new version."
                ),
            ),
            tags=["supply-chain", "behavior-anomaly"],
            metadata={
                "package": change.package,
                "old_version": change.old_version,
                "new_version": change.new_version,
                "anomaly": anomaly,
            },
        )


@scanner
class DependencyDiffScanner(Scanner):
    name = "dependency-diff"
    category = "supply-chain"
    description = "Reports dependency additions, removals, and version changes in a git diff."

    file_local = False

    def applies_to(self, project) -> bool:
        return git_ops.is_git_repo(Path(project.root))

    def scan(self, ctx: ScannerContext) -> Iterable[Finding]:
        opts = ctx.config.options_for(self.name)
        ref = opts.get("ref") or opts.get("diff_ref")
        if not ref:
            return
        timeout = float(opts.get("timeout", 10.0))
        behavior = bool(opts.get("behavior", True))
        for counter, change in enumerate(diff_packages(Path(ctx.project.root), str(ref)), start=1):
            yield _change_finding(change, counter)
            if behavior:
                yield from _behavior_findings(change, counter, timeout=timeout)
