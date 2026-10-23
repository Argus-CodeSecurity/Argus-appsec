"""Plugin trust controls: entry-point allowlist, blocklist and pinning (spec section 56).

Despite the module name, this is not cryptographic signature verification.
Nephilex loads third-party code from two entry-point groups, ``nephilex.plugins``
(scanners, reporters, AI providers) and ``nephilex.commands`` (CLI commands),
and both are filtered the same way:

* ``NEPHILEX_PLUGIN_ALLOWLIST``: comma-separated entry-point names. When set,
  only these names load.
* ``NEPHILEX_PLUGIN_BLOCKLIST``: comma-separated names that never load (used
  when no allowlist is set).
* ``NEPHILEX_TRUSTED_PLUGINS``: optional pins. When set, an entry point must
  also match one pin, either its name or :func:`plugin_fingerprint` of its
  name and import target, so a different package reusing an allowed name
  with a different target is refused.

These are policy controls over what gets imported, not proof of who wrote
the code: anything installed in the environment can already run code.
Nephilex's own built-in plugins are always allowed so an allowlist cannot
disable core scanning.
"""

from __future__ import annotations

import hashlib
import os
from importlib import metadata

#: Import target of Nephilex's own built-in plugin registration.
BUILTIN_ENTRY_POINT = "nephilex.plugins:register_builtins"


def _names(var: str) -> set[str]:
    return {x.strip() for x in os.environ.get(var, "").split(",") if x.strip()}


def plugin_allowed(name: str) -> bool:
    """Check an entry-point name against the allowlist / blocklist."""
    allow = _names("NEPHILEX_PLUGIN_ALLOWLIST")
    if allow:
        return name in allow
    return name not in _names("NEPHILEX_PLUGIN_BLOCKLIST")


def plugin_fingerprint(name: str, module_path: str) -> str:
    """A pin for an entry point: a hash of its name and import target."""
    return hashlib.sha256(f"{name}:{module_path}".encode()).hexdigest()[:16]


def load_trusted_plugins() -> set[str]:
    """Pins from NEPHILEX_TRUSTED_PLUGINS (names or fingerprints, comma-separated)."""
    return _names("NEPHILEX_TRUSTED_PLUGINS")


def is_builtin_entry(ep: metadata.EntryPoint) -> bool:
    """True for the entry point that registers Nephilex's own plugins."""
    return ep.value.replace(" ", "") == BUILTIN_ENTRY_POINT


def verify_plugin_entry(ep: metadata.EntryPoint) -> bool:
    """Whether an entry point (from any Nephilex group) may be loaded.

    Applies the allowlist/blocklist and, if configured, the pins. The name
    is historical: this checks policy, it does not verify a signature.
    """
    if is_builtin_entry(ep):
        return True
    if not plugin_allowed(ep.name):
        return False
    trusted = load_trusted_plugins()
    if not trusted:
        return True
    return plugin_fingerprint(ep.name, ep.value) in trusted or ep.name in trusted


#: Clearer alias for new code.
entry_point_allowed = verify_plugin_entry
