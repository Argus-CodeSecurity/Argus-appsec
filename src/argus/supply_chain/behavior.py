"""Static behavioral fingerprints from package registry metadata (no execution).

Fetches npm package manifests from the public registry only. Never runs install
scripts or downloads package tarballs. Used to detect suspicious capability
changes between dependency versions in a PR diff.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

import httpx

log = logging.getLogger("argus.supply_chain.behavior")

_REGISTRY = "https://registry.npmjs.org"
_SUSPICIOUS = re.compile(
    r"(curl|wget|bash|powershell|eval\(|child_process|http://|https://|"
    r"chmod\s|/etc/passwd|~/.ssh|process\.env)",
    re.IGNORECASE,
)


@dataclass
class BehaviorFingerprint:
    ecosystem: str
    package: str
    version: str
    install_scripts: list[str] = field(default_factory=list)
    bins: list[str] = field(default_factory=list)
    dependency_count: int = 0
    suspicious_script: bool = False

    def capability_tags(self) -> set[str]:
        tags: set[str] = set()
        if self.install_scripts:
            tags.add("install-script")
        if self.bins:
            tags.add("executable-bin")
        if self.suspicious_script:
            tags.add("suspicious-script")
        if self.dependency_count > 50:
            tags.add("large-dependency-tree")
        return tags


def npm_fingerprint(name: str, version: str, *, timeout: float = 10.0) -> BehaviorFingerprint | None:
    """Fetch npm registry metadata for one exact version (read-only)."""
    url = f"{_REGISTRY}/{name}/{version}"
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            resp = client.get(url)
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        log.debug("npm fingerprint failed for %s@%s: %s", name, version, exc)
        return None

    scripts = data.get("scripts") or {}
    install_hooks = [
        h for h in ("preinstall", "install", "postinstall", "prepare")
        if isinstance(scripts.get(h), str)
    ]
    script_bodies = " ".join(str(scripts.get(h, "")) for h in install_hooks)
    bins_raw = data.get("bin") or {}
    bins = sorted(bins_raw.keys()) if isinstance(bins_raw, dict) else []
    deps = data.get("dependencies") or {}
    return BehaviorFingerprint(
        ecosystem="npm",
        package=name,
        version=version,
        install_scripts=install_hooks,
        bins=bins,
        dependency_count=len(deps) if isinstance(deps, dict) else 0,
        suspicious_script=bool(_SUSPICIOUS.search(script_bodies)),
    )


def compare_fingerprints(
    old: BehaviorFingerprint | None,
    new: BehaviorFingerprint | None,
) -> list[str]:
    """Return human-readable anomalies when ``new`` adds capabilities vs ``old``."""
    if new is None:
        return []
    if old is None:
        if new.suspicious_script:
            return ["new package version includes suspicious install script patterns"]
        return []

    anomalies: list[str] = []
    old_tags = old.capability_tags()
    new_tags = new.capability_tags()
    added = new_tags - old_tags
    if "install-script" in added:
        hooks = ", ".join(new.install_scripts) or "install"
        anomalies.append(f"install lifecycle script(s) added: {hooks}")
    if "suspicious-script" in added or (
        new.suspicious_script and not old.suspicious_script
    ):
        anomalies.append("suspicious patterns in install scripts (network/shell/env access)")
    if "executable-bin" in added:
        anomalies.append(f"new executable bin entries: {', '.join(new.bins)}")
    if new.dependency_count > old.dependency_count + 20:
        anomalies.append(
            f"dependency count jumped from {old.dependency_count} to {new.dependency_count}"
        )
    return anomalies
