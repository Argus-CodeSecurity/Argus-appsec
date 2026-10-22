"""Anthropic (Claude) provider.

Uses the official ``anthropic`` SDK if installed and ``ANTHROPIC_API_KEY`` is set.
Import of the SDK is deferred to :meth:`complete` so the module loads even when
the optional dependency is absent, availability is reported by ``is_available``.
"""

from __future__ import annotations

import os
import re
from typing import Any

from argus.ai.base import AIProvider, max_retries, request_timeout
from argus.core.plugin import ai_provider

# Model families that only accept the default temperature.
_FIXED_SAMPLING = re.compile(
    r"^claude-(?:(?:opus|sonnet|haiku|fable|mythos)-5|opus-4-[78])(?![0-9])"
)


@ai_provider
class AnthropicProvider(AIProvider):
    name = "anthropic"
    is_remote = True
    # A current, capable default; override via config `ai.model`, --ai-model or
    # the ARGUS_AI_MODEL environment variable.
    default_model = "claude-sonnet-5-5"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._client: Any | None = None

    @classmethod
    def is_available(cls) -> bool:
        if not os.environ.get("ANTHROPIC_API_KEY"):
            return False
        try:
            import anthropic  # noqa: F401
        except ImportError:
            return False
        return True

    def _get_client(self) -> Any:
        if self._client is None:
            import anthropic

            self._client = anthropic.Anthropic(
                api_key=os.environ["ANTHROPIC_API_KEY"],
                timeout=request_timeout(),
                max_retries=max_retries(),
            )
        return self._client

    def complete(self, system: str, user: str) -> str:
        client = self._get_client()
        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
        # Newer models reject non-default sampling parameters with a 400.
        if not _FIXED_SAMPLING.match(self.model):
            kwargs["temperature"] = self.temperature
        resp = client.messages.create(**kwargs)
        # Concatenate text blocks from the response content.
        return "".join(
            block.text for block in resp.content if getattr(block, "type", "") == "text"
        ).strip()
