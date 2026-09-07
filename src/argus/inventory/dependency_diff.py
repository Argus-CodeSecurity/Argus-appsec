"""Dependency version differential analysis between git refs."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from argus.inventory import collect_packages_at_ref, split_ref_spec


@dataclass(frozen=True)
class PackageChange:
    """A dependency added, removed, or version-changed between two refs."""

    ecosystem: str
    package: str
    manifest: str
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


def diff_packages(root: Path, ref_spec: str, *, head: str = "HEAD") -> list[PackageChange]:
    """Compare dependency inventories at ``base...head`` (or ``base`` vs HEAD)."""
    base_ref, head_ref = split_ref_spec(ref_spec, head=head)
    old_index = _index(collect_packages_at_ref(root, base_ref))
    new_index = _index(collect_packages_at_ref(root, head_ref))

    changes: list[PackageChange] = []
    keys = set(old_index) | set(new_index)
    for key in sorted(keys):
        ecosystem, pkg = key
        old_entries = old_index.get(key, {})
        new_entries = new_index.get(key, {})
        manifests = set(old_entries) | set(new_entries)
        for manifest in sorted(manifests):
            old_ver = old_entries.get(manifest)
            new_ver = new_entries.get(manifest)
            if old_ver == new_ver:
                continue
            pc = PackageChange(
                ecosystem=ecosystem,
                package=pkg,
                manifest=manifest,
                old_version=old_ver,
                new_version=new_ver,
            )
            if pc.change != "unchanged":
                changes.append(pc)
    return changes


def _index(
    packages: list[tuple[str, str, str, str]],
) -> dict[tuple[str, str], dict[str, str]]:
    """Map (ecosystem, package) -> {manifest_path: version}."""
    out: dict[tuple[str, str], dict[str, str]] = {}
    for ecosystem, path, pkg, version in packages:
        out.setdefault((ecosystem, pkg), {})[path] = version
    return out
