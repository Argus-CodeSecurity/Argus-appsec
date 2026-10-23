"""Ollama provider, local models over HTTP.

Keeps source code inside your own environment: no SDK, no API key, just a running
Ollama server (default ``http://localhost:11434``). Uses ``httpx`` directly so it
has no extra install beyond Nephilex's base dependencies.

``OLLAMA_HOST`` may point at another machine; in that case source code does
leave this host, and the provider reports itself as remote.
"""

from __future__ import annotations

import ipaddress
import os
from typing import Any
from urllib.parse import urlsplit

import httpx

from nephilex.ai.base import AIProvider, max_retries, request_timeout
from nephilex.core.plugin import ai_provider

# Local models are slower than hosted APIs; allow longer generations by default.
_DEFAULT_TIMEOUT = 120.0


def _host() -> str:
    host = os.environ.get("OLLAMA_HOST", "http://localhost:11434").strip().rstrip("/")
    if "://" not in host:  # Ollama accepts a bare "host:port"
        host = f"http://{host}"
    return host


def _is_loopback(url: str) -> bool:
    hostname = (urlsplit(url).hostname or "").lower()
    if hostname in ("localhost", "") or hostname.endswith(".localhost"):
        return True
    try:
        addr = ipaddress.ip_address(hostname)
    except ValueError:
        return False
    return addr.is_loopback or addr.is_unspecified  # 0.0.0.0 / :: connect locally


class _RemoteFromHost:
    """``is_remote`` computed from ``OLLAMA_HOST`` on class or instance access."""

    def __get__(self, obj: Any, owner: Any = None) -> bool:
        return not _is_loopback(_host())


@ai_provider
class OllamaProvider(AIProvider):
    name = "ollama"
    # Local only when OLLAMA_HOST points at this machine.
    is_remote = _RemoteFromHost()
    default_model = "llama3.1"

    @classmethod
    def is_available(cls) -> bool:
        try:
            resp = httpx.get(f"{_host()}/api/tags", timeout=1.5)
            return resp.status_code == 200
        except Exception:
            return False

    def complete(self, system: str, user: str) -> str:
        payload = {
            "model": self.model,
            "stream": False,
            "options": {"temperature": self.temperature},
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        attempts = max_retries() + 1
        for attempt in range(attempts):
            try:
                resp = httpx.post(
                    f"{_host()}/api/chat", json=payload, timeout=request_timeout(_DEFAULT_TIMEOUT)
                )
                resp.raise_for_status()
                break
            except httpx.TransportError:
                # Connection problems and timeouts are worth a retry; HTTP
                # errors (bad model name, 4xx) are not.
                if attempt == attempts - 1:
                    raise
        return resp.json().get("message", {}).get("content", "").strip()
