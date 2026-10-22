"""Plugin allowlist/blocklist applies to every entry-point group."""

from __future__ import annotations

from importlib import metadata

import pytest

import argus.cli.main as cli_main
from argus.plugins.signing import (
    BUILTIN_ENTRY_POINT,
    plugin_fingerprint,
    verify_plugin_entry,
)

CALLS: list[str] = []


def _register_command(app) -> None:  # target of the fake entry point below
    CALLS.append("loaded")


def _ep(name: str, value: str, group: str = "argus.plugins") -> metadata.EntryPoint:
    return metadata.EntryPoint(name=name, value=value, group=group)


def test_builtins_allowed_even_with_allowlist(monkeypatch) -> None:
    monkeypatch.setenv("ARGUS_PLUGIN_ALLOWLIST", "something-else")
    monkeypatch.setenv("ARGUS_TRUSTED_PLUGINS", "something-else")
    assert verify_plugin_entry(_ep("builtin", BUILTIN_ENTRY_POINT)) is True


def test_allowlist_and_blocklist(monkeypatch) -> None:
    monkeypatch.setenv("ARGUS_PLUGIN_BLOCKLIST", "bad")
    assert verify_plugin_entry(_ep("bad", "pkg:reg")) is False
    assert verify_plugin_entry(_ep("good", "pkg:reg")) is True
    monkeypatch.setenv("ARGUS_PLUGIN_ALLOWLIST", "good")
    assert verify_plugin_entry(_ep("other", "pkg:reg")) is False


def test_pins_bind_name_to_target(monkeypatch) -> None:
    monkeypatch.setenv("ARGUS_TRUSTED_PLUGINS", plugin_fingerprint("k8s", "argus_k8s:reg"))
    assert verify_plugin_entry(_ep("k8s", "argus_k8s:reg")) is True
    assert verify_plugin_entry(_ep("k8s", "evil_pkg:reg")) is False


def test_command_entry_points_respect_allowlist(monkeypatch) -> None:
    target = f"{__name__}:_register_command"
    eps = [_ep("cmd", target, group="argus.commands")]
    monkeypatch.setattr(metadata, "entry_points", lambda group=None: eps)
    CALLS.clear()

    monkeypatch.setenv("ARGUS_PLUGIN_ALLOWLIST", "someone-else")
    with pytest.warns(UserWarning, match="Blocked"):
        cli_main._load_plugin_commands()
    assert CALLS == []

    monkeypatch.setenv("ARGUS_PLUGIN_ALLOWLIST", "cmd")
    cli_main._load_plugin_commands()
    assert CALLS == ["loaded"]
