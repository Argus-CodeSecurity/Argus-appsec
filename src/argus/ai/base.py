"""The AIProvider contract and shared helpers.

An AI provider is a thin, uniform wrapper around a chat-style model. Agents call
:meth:`AIProvider.complete` with a system prompt and a user prompt and get back
text. Everything provider-specific (auth, endpoints, request shape) lives in the
concrete subclasses.
"""

from __future__ import annotations

import abc
import os
from dataclasses import dataclass
from typing import ClassVar

from argus.core.plugin import PLUGIN_API_VERSION

# Network defaults for model calls. SDK defaults (a 10 minute timeout) would let
# one stalled request hold a CI job for a very long time.
DEFAULT_TIMEOUT = 60.0
DEFAULT_MAX_RETRIES = 2


def request_timeout(default: float = DEFAULT_TIMEOUT) -> float:
    """Per-request timeout in seconds (``ARGUS_AI_TIMEOUT`` overrides)."""
    try:
        value = float(os.environ.get("ARGUS_AI_TIMEOUT", default))
    except ValueError:
        return default
    return value if value > 0 else default


def max_retries(default: int = DEFAULT_MAX_RETRIES) -> int:
    """Retries on transient errors (``ARGUS_AI_MAX_RETRIES`` overrides)."""
    try:
        value = int(os.environ.get("ARGUS_AI_MAX_RETRIES", default))
    except ValueError:
        return default
    return max(value, 0)


@dataclass
class ChatMessage:
    role: str  # "system" | "user" | "assistant"
    content: str


class AIProvider(abc.ABC):
    """Base class for all model backends."""

    #: Plugin API version this class was written against (see ``Scanner``).
    api_version: ClassVar[int] = PLUGIN_API_VERSION
    #: Unique provider id used in config and the `--ai-provider` flag.
    name: ClassVar[str] = ""
    #: Whether this provider sends data off the local machine. Surfaced to users
    #: so they can make an informed choice about source-code confidentiality.
    is_remote: ClassVar[bool] = True
    #: Default model id when the user doesn't specify one.
    default_model: ClassVar[str] = ""

    def __init__(self, model: str | None = None, *, temperature: float = 0.0,
                 max_tokens: int = 4096) -> None:
        # Precedence: explicit (config `ai.model` / --ai-model), then the
        # ARGUS_AI_MODEL environment variable, then the provider default.
        self.model = model or os.environ.get("ARGUS_AI_MODEL") or self.default_model
        self.temperature = temperature
        self.max_tokens = max_tokens

    @classmethod
    def is_available(cls) -> bool:
        """Return True if this provider can actually be used (SDK + creds present).

        The heuristic provider is always available; cloud/local providers check
        for their SDK and credentials. Used to fall back gracefully.
        """
        return True

    @abc.abstractmethod
    def complete(self, system: str, user: str) -> str:
        """Return the model's completion for a system + user prompt."""
        raise NotImplementedError

    def chat(self, messages: list[ChatMessage]) -> str:
        """Multi-turn convenience wrapper. Providers may override for efficiency.

        The default flattens the conversation into a single system+user call,
        which is enough for Argus's mostly single-shot agent prompts.
        """
        system = "\n\n".join(m.content for m in messages if m.role == "system")
        convo = "\n\n".join(f"{m.role.upper()}: {m.content}"
                            for m in messages if m.role != "system")
        return self.complete(system, convo)
