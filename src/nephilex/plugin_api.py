"""The stable, versioned API for Nephilex plugins.

Third-party scanners, reporters and AI providers should import from this module
only. Every name in ``__all__`` is covered by the compatibility policy (see
``COMPATIBILITY.md`` and ``docs/plugins.md``): it is not removed or changed
incompatibly without raising :data:`PLUGIN_API_VERSION`. Anything else in the
``nephilex`` package is internal and may change in any release.

Plugin classes inherit ``api_version = PLUGIN_API_VERSION`` from their base
class. When a later Nephilex raises the version, the registry skips plugins built
for the old one and logs which plugin was skipped, instead of running code
written against a contract that no longer holds.

Example::

    from nephilex.plugin_api import Finding, Location, Scanner, ScannerContext, scanner

    @scanner
    class TodoScanner(Scanner):
        name = "todo"
        description = "Flags TODO markers."

        def scan(self, ctx: ScannerContext):
            ...
"""

from __future__ import annotations

from nephilex.ai.base import AIProvider, ChatMessage
from nephilex.core.config import Config
from nephilex.core.models import (
    Confidence,
    Finding,
    Likelihood,
    Location,
    Remediation,
    ScanResult,
    Severity,
)
from nephilex.core.plugin import (
    PLUGIN_API_VERSION,
    PluginVersionError,
    Reporter,
    Scanner,
    ScannerContext,
    ai_provider,
    reporter,
    scanner,
)
from nephilex.core.project import FileRef, Project

__all__ = [
    "PLUGIN_API_VERSION",
    "AIProvider",
    "ChatMessage",
    "Confidence",
    "Config",
    "FileRef",
    "Finding",
    "Likelihood",
    "Location",
    "PluginVersionError",
    "Project",
    "Remediation",
    "Reporter",
    "ScanResult",
    "Scanner",
    "ScannerContext",
    "Severity",
    "ai_provider",
    "reporter",
    "scanner",
]
