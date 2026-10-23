"""Provider selection with graceful fallback.

``build_provider`` honors the requested provider but never hard-fails a scan just
because a model backend is missing: if the requested cloud/local provider is
unavailable (no SDK, no key, no server), it warns and falls back to the offline
heuristic provider so ``nephilex scan`` still produces a report.
"""

from __future__ import annotations

import warnings

# Importing the provider modules is what registers them in the registry.
from nephilex.ai import (  # noqa: F401
    anthropic_provider,
    heuristic,
    ollama_provider,
    openai_provider,
)
from nephilex.ai.base import AIProvider
from nephilex.core.config import AIConfig
from nephilex.core.plugin import registry


def build_provider(cfg: AIConfig) -> AIProvider:
    providers = registry.ai_providers()
    requested = cfg.provider

    if requested not in providers:
        warnings.warn(
            f"Unknown AI provider {requested!r}; using 'heuristic'. Available: {sorted(providers)}",
            stacklevel=2,
        )
        requested = "heuristic"

    cls = providers[requested]
    if not cls.is_available():
        if requested != "heuristic":
            warnings.warn(
                f"AI provider {requested!r} is not available "
                f"(missing SDK, credentials, or server). Falling back to 'heuristic'.",
                stacklevel=2,
            )
        cls = providers["heuristic"]

    return cls(model=cfg.model, temperature=cfg.temperature, max_tokens=cfg.max_tokens)
