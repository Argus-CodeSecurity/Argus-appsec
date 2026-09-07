"""Built-in plugin registration and signing helpers."""

from __future__ import annotations

from argus.plugins.signing import plugin_allowed, verify_plugin_entry


def register_builtins() -> None:
    from argus import scanners  # noqa: F401
    from argus.ai import (  # noqa: F401
        anthropic_provider,
        heuristic,
        ollama_provider,
        openai_provider,
    )
    from argus.reporting import (  # noqa: F401
        badge,
        gitlab,
        html,
        json_reporter,
        markdown,
        sarif,
        vex,
    )


__all__ = ["register_builtins", "plugin_allowed", "verify_plugin_entry"]
