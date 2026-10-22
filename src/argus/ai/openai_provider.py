"""OpenAI provider.

Uses the official ``openai`` SDK if installed and ``OPENAI_API_KEY`` is set.
"""

from __future__ import annotations

import os
from typing import Any

from argus.ai.base import AIProvider, max_retries, request_timeout
from argus.core.plugin import ai_provider


@ai_provider
class OpenAIProvider(AIProvider):
    name = "openai"
    is_remote = True
    default_model = "gpt-4o"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._client: Any | None = None

    @classmethod
    def is_available(cls) -> bool:
        if not os.environ.get("OPENAI_API_KEY"):
            return False
        try:
            import openai  # noqa: F401
        except ImportError:
            return False
        return True

    def _get_client(self) -> Any:
        if self._client is None:
            from openai import OpenAI

            self._client = OpenAI(
                api_key=os.environ["OPENAI_API_KEY"],
                timeout=request_timeout(),
                max_retries=max_retries(),
            )
        return self._client

    def complete(self, system: str, user: str) -> str:
        client = self._get_client()
        resp = client.chat.completions.create(
            model=self.model,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        return (resp.choices[0].message.content or "").strip()
