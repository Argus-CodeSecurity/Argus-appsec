"""SBOM diff: new, removed, and changed components between git refs."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from argus.inventory import collect_packages_at_ref, split_ref_spec

ComponentKey = tuple[str, str, str]  # ecosystem, name, version


@dataclass(frozen=True)
class SbomComponentChange:
    ecosystem: str
    name: str
    old_version: str | None
    new_version: str | None

    @property
    def change(self) -> str:
        if self.old_version is None:
            return "added"
        if self.new_version is None:
            return "removed"
        if self.old_version != self.new_version:
            return "changed"
        return "unchanged"


def _index(packages: list[tuple[str, str, str, str]]) -> dict[tuple[str, str], str]:
    """Map (ecosystem, package) -> highest-seen version (last wins, sorted input)."""
    out: dict[tuple[str, str], str] = {}
    for ecosystem, _path, pkg, version in packages:
        out[(ecosystem, pkg)] = version
    return out


def diff_components(root: Path, ref_spec: str, *, head: str = "HEAD") -> list[SbomComponentChange]:
    """Compare dependency inventories at ``base...head``."""
    base_ref, head_ref = split_ref_spec(ref_spec, head=head)
    old = _index(collect_packages_at_ref(root, base_ref))
    new = _index(collect_packages_at_ref(root, head_ref))
    changes: list[SbomComponentChange] = []
    for key in sorted(set(old) | set(new)):
        ecosystem, name = key
        ov, nv = old.get(key), new.get(key)
        if ov == nv:
            continue
        pc = SbomComponentChange(ecosystem, name, ov, nv)
        if pc.change != "unchanged":
            changes.append(pc)
    return changes


def diff_to_dict(changes: list[SbomComponentChange], *, ref_spec: str) -> dict[str, Any]:
    return {
        "diff": ref_spec,
        "summary": {
            "added": sum(1 for c in changes if c.change == "added"),
            "removed": sum(1 for c in changes if c.change == "removed"),
            "changed": sum(1 for c in changes if c.change == "changed"),
        },
        "components": [
            {
                "ecosystem": c.ecosystem,
                "name": c.name,
                "change": c.change,
                "old_version": c.old_version,
                "new_version": c.new_version,
            }
            for c in changes
        ],
    }
