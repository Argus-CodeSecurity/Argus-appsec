"""Configuration drift: compare scans and inventories over time."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from argus.core.models import Finding, ScanResult, Severity


@dataclass
class FindingDrift:
    fingerprint: str
    rule_id: str
    title: str
    location: str
    severity: str
    scanner: str


@dataclass
class ScanDriftReport:
    before_target: str
    after_target: str
    added: list[FindingDrift] = field(default_factory=list)
    removed: list[FindingDrift] = field(default_factory=list)
    severity_changed: list[dict[str, Any]] = field(default_factory=list)

    @property
    def has_regressions(self) -> bool:
        return bool(self.added or self.severity_changed)

    def summary(self) -> dict[str, int]:
        return {
            "added": len(self.added),
            "removed": len(self.removed),
            "severity_changed": len(self.severity_changed),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": "scan_drift",
            "before_target": self.before_target,
            "after_target": self.after_target,
            "summary": self.summary(),
            "added": [f.__dict__ for f in self.added],
            "removed": [f.__dict__ for f in self.removed],
            "severity_changed": self.severity_changed,
        }


def _finding_drift(f: Finding) -> FindingDrift:
    return FindingDrift(
        fingerprint=f.fingerprint(),
        rule_id=f.rule_id,
        title=f.title,
        location=f.location.as_ref(),
        severity=f.severity.label,
        scanner=f.scanner,
    )


def compare_scans(before: ScanResult, after: ScanResult) -> ScanDriftReport:
    """Diff two scan reports by stable finding fingerprint."""
    before_map = {f.fingerprint(): f for f in before.findings}
    after_map = {f.fingerprint(): f for f in after.findings}
    report = ScanDriftReport(
        before_target=before.target,
        after_target=after.target,
    )
    for fp, f in after_map.items():
        if fp not in before_map:
            report.added.append(_finding_drift(f))
        else:
            old = before_map[fp]
            if old.severity != f.severity:
                report.severity_changed.append({
                    "fingerprint": fp,
                    "rule_id": f.rule_id,
                    "location": f.location.as_ref(),
                    "before_severity": old.severity.label,
                    "after_severity": f.severity.label,
                })
    for fp, f in before_map.items():
        if fp not in after_map:
            report.removed.append(_finding_drift(f))
    return report


def _dep_key(d: dict[str, Any]) -> tuple[str, str]:
    return (d.get("ecosystem", ""), d.get("name", ""))


def compare_inventories(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """Diff two ``build_inventory()`` payloads."""
    b_deps = {_dep_key(d): d for d in before.get("dependencies") or []}
    a_deps = {_dep_key(d): d for d in after.get("dependencies") or []}
    dep_added, dep_removed, dep_changed = [], [], []
    for k, d in a_deps.items():
        if k not in b_deps:
            dep_added.append(d)
        elif b_deps[k].get("version") != d.get("version"):
            dep_changed.append({
                "ecosystem": d.get("ecosystem"),
                "name": d.get("name"),
                "before_version": b_deps[k].get("version"),
                "after_version": d.get("version"),
                "manifest": d.get("manifest"),
            })
    for k, d in b_deps.items():
        if k not in a_deps:
            dep_removed.append(d)

    b_arch = before.get("architecture") or {}
    a_arch = after.get("architecture") or {}
    arch_keys = ("ci_cd", "containers", "iac", "dependency_manifests")
    arch_changes: dict[str, dict[str, list[str]]] = {}
    for key in arch_keys:
        b_set = set(b_arch.get(key) or [])
        a_set = set(a_arch.get(key) or [])
        added = sorted(a_set - b_set)
        removed = sorted(b_set - a_set)
        if added or removed:
            arch_changes[key] = {"added": added, "removed": removed}

    return {
        "kind": "inventory_drift",
        "before_target": before.get("target"),
        "after_target": after.get("target"),
        "dependencies": {
            "added": dep_added,
            "removed": dep_removed,
            "changed": dep_changed,
        },
        "architecture": arch_changes,
        "summary": {
            "deps_added": len(dep_added),
            "deps_removed": len(dep_removed),
            "deps_changed": len(dep_changed),
            "arch_areas_changed": len(arch_changes),
        },
    }


def highest_added_severity(report: ScanDriftReport) -> Severity:
    best = Severity.INFO
    for item in report.added:
        sev = Severity.parse(item.severity)
        if sev > best:
            best = sev
    for ch in report.severity_changed:
        sev = Severity.parse(ch["after_severity"])
        if sev > best:
            best = sev
    return best
