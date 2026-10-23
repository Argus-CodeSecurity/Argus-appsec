"""Built-in plugin registration and plugin trust (allowlist) helpers."""

from __future__ import annotations

from nephilex.plugins.signing import entry_point_allowed, plugin_allowed, verify_plugin_entry

_registered = False


def _load_reporters() -> None:
    from nephilex.reporting import (  # noqa: F401
        badge,
        gitlab,
        html,
        json_reporter,
        markdown,
        sarif,
        vex,
    )


def _load_ai_providers() -> None:
    from nephilex.ai import (  # noqa: F401
        anthropic_provider,
        heuristic,
        ollama_provider,
        openai_provider,
    )


def register_builtins() -> None:
    """Register Nephilex's built-in scanners, reporters and AI providers.

    Scanners are imported here, as always: every scan and check needs them,
    and importing ``nephilex.scanners`` first also keeps the package import
    order the scanner modules rely on. Reporters and AI providers are not:
    each group is imported on the first registry lookup of its kind
    (``registry.reporters()``, ``registry.get_ai_provider("heuristic")``,
    ...), so a command that never needs them, such as ``nephilex check``, does
    not import the report formats or the model clients and their HTTP
    library. Calling this more than once (the CLI and the ``nephilex.plugins``
    entry point both do) is harmless.
    """
    from nephilex import scanners  # noqa: F401

    global _registered
    if _registered:
        return
    _registered = True
    from nephilex.core.plugin import registry

    registry.add_loader("Reporter", _load_reporters)
    registry.add_loader("AIProvider", _load_ai_providers)


__all__ = ["register_builtins", "entry_point_allowed", "plugin_allowed", "verify_plugin_entry"]
