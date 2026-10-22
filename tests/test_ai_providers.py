"""AI providers: timeouts, retries, default model and locality."""

from __future__ import annotations

import sys
import types

import httpx
import pytest

from argus.ai.anthropic_provider import AnthropicProvider
from argus.ai.ollama_provider import OllamaProvider
from argus.ai.openai_provider import OpenAIProvider


class _Recorder:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.calls: list[dict] = []


def _fake_anthropic(monkeypatch) -> list[_Recorder]:
    made: list[_Recorder] = []

    class Messages:
        def __init__(self, rec):
            self.rec = rec

        def create(self, **kwargs):
            self.rec.calls.append(kwargs)
            block = types.SimpleNamespace(type="text", text="ok")
            return types.SimpleNamespace(content=[block])

    def factory(**kwargs):
        rec = _Recorder(**kwargs)
        rec.messages = Messages(rec)
        made.append(rec)
        return rec

    monkeypatch.setitem(sys.modules, "anthropic", types.SimpleNamespace(Anthropic=factory))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    return made


def test_anthropic_default_model_is_current(monkeypatch):
    monkeypatch.delenv("ARGUS_AI_MODEL", raising=False)
    assert AnthropicProvider().model == "claude-sonnet-5-5"


def test_model_overridable_by_env_and_config(monkeypatch):
    monkeypatch.setenv("ARGUS_AI_MODEL", "claude-opus-5-5")
    assert AnthropicProvider().model == "claude-opus-5-5"
    assert AnthropicProvider(model="claude-haiku-5-5").model == "claude-haiku-5-5"


def test_anthropic_client_has_timeout_and_retries(monkeypatch):
    made = _fake_anthropic(monkeypatch)
    monkeypatch.delenv("ARGUS_AI_MODEL", raising=False)
    monkeypatch.setenv("ARGUS_AI_TIMEOUT", "30")
    monkeypatch.setenv("ARGUS_AI_MAX_RETRIES", "4")
    assert AnthropicProvider().complete("s", "u") == "ok"
    assert made[0].kwargs["timeout"] == 30.0
    assert made[0].kwargs["max_retries"] == 4


def test_anthropic_defaults_without_env(monkeypatch):
    made = _fake_anthropic(monkeypatch)
    monkeypatch.delenv("ARGUS_AI_TIMEOUT", raising=False)
    monkeypatch.delenv("ARGUS_AI_MAX_RETRIES", raising=False)
    AnthropicProvider().complete("s", "u")
    assert made[0].kwargs["timeout"] == 60.0
    assert made[0].kwargs["max_retries"] == 2


def test_anthropic_skips_temperature_for_fixed_sampling_models(monkeypatch):
    made = _fake_anthropic(monkeypatch)
    AnthropicProvider(model="claude-sonnet-5-5").complete("s", "u")
    assert "temperature" not in made[0].calls[0]
    AnthropicProvider(model="claude-sonnet-4-6").complete("s", "u")
    assert made[1].calls[0]["temperature"] == 0.0


def test_openai_client_has_timeout_and_retries(monkeypatch):
    seen: dict = {}

    def factory(**kwargs):
        seen.update(kwargs)
        return object()

    monkeypatch.setitem(sys.modules, "openai", types.SimpleNamespace(OpenAI=factory))
    monkeypatch.setenv("OPENAI_API_KEY", "k")
    monkeypatch.delenv("ARGUS_AI_TIMEOUT", raising=False)
    OpenAIProvider()._get_client()
    assert seen["timeout"] == 60.0 and seen["max_retries"] == 2


@pytest.mark.parametrize(("host", "remote"), [
    (None, False),
    ("http://127.0.0.1:11434", False),
    ("0.0.0.0:11434", False),
    ("http://[::1]:11434", False),
    ("http://gpu-box.internal:11434", True),
    ("https://10.1.2.3", True),
])
def test_ollama_locality_follows_ollama_host(monkeypatch, host, remote):
    if host is None:
        monkeypatch.delenv("OLLAMA_HOST", raising=False)
    else:
        monkeypatch.setenv("OLLAMA_HOST", host)
    assert OllamaProvider.is_remote is remote
    assert OllamaProvider().is_remote is remote


def test_ollama_retries_transport_errors(monkeypatch):
    calls = {"n": 0}

    def flaky(url, **kwargs):
        calls["n"] += 1
        assert kwargs["timeout"] == 120.0
        if calls["n"] < 3:
            raise httpx.ConnectError("down")
        return httpx.Response(200, json={"message": {"content": " hi "}},
                              request=httpx.Request("POST", url))

    monkeypatch.delenv("ARGUS_AI_TIMEOUT", raising=False)
    monkeypatch.delenv("ARGUS_AI_MAX_RETRIES", raising=False)
    monkeypatch.setattr(httpx, "post", flaky)
    assert OllamaProvider().complete("s", "u") == "hi"
    assert calls["n"] == 3
