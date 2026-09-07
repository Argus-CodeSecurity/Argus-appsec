"""Plugin trust and optional signature verification (spec §56)."""

from __future__ import annotations

import hashlib
import os
from importlib import metadata


def plugin_allowed(name: str) -> bool:
    """Check allowlist / blocklist for plugin entry points."""
    allow = os.environ.get("ARGUS_PLUGIN_ALLOWLIST", "").strip()
    if allow:
        return name in {x.strip() for x in allow.split(",") if x.strip()}
    block = os.environ.get("ARGUS_PLUGIN_BLOCKLIST", "").strip()
    return not (block and name in {x.strip() for x in block.split(",") if x.strip()})


def plugin_fingerprint(name: str, module_path: str) -> str:
    return hashlib.sha256(f"{name}:{module_path}".encode()).hexdigest()[:16]


def load_trusted_plugins() -> set[str]:
    """Load trusted plugin fingerprints from ARGUS_TRUSTED_PLUGINS (comma-separated)."""
    raw = os.environ.get("ARGUS_TRUSTED_PLUGINS", "")
    return {x.strip() for x in raw.split(",") if x.strip()}


def verify_plugin_entry(ep: metadata.EntryPoint) -> bool:
    if not plugin_allowed(ep.name):
        return False
    trusted = load_trusted_plugins()
    if not trusted:
        return True
    fp = plugin_fingerprint(ep.name, ep.value)
    return fp in trusted or ep.name in trusted
