"""The public plugin API: exported names, api_version checks, ScannerContext."""

from __future__ import annotations

import dataclasses
import logging
from collections.abc import Iterable
from pathlib import Path

import pytest

import nephilex.plugin_api as plugin_api
from nephilex.ai.base import AIProvider
from nephilex.core.plugin import (
    PLUGIN_API_VERSION,
    Registry,
    Reporter,
    Scanner,
    ScannerContext,
    registry,
)

DOCUMENTED = {
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
}


def _fresh_registry() -> Registry:
    reg = Registry()
    reg._loaded_entrypoints = True  # keep the test independent of installed plugins
    return reg


def _scanner_cls(name: str, version: object) -> type[Scanner]:
    class _S(Scanner):
        def scan(self, ctx: ScannerContext) -> Iterable:
            return []

    _S.name = name
    _S.api_version = version  # type: ignore[assignment]
    return _S


def test_plugin_api_exports_documented_names() -> None:
    assert set(plugin_api.__all__) == DOCUMENTED
    for name in DOCUMENTED:
        assert getattr(plugin_api, name) is not None
    assert plugin_api.PLUGIN_API_VERSION == PLUGIN_API_VERSION == 1
    assert plugin_api.Scanner is Scanner
    assert plugin_api.AIProvider is AIProvider


def test_plugins_doc_lists_every_exported_name() -> None:
    doc = (Path(__file__).resolve().parents[1] / "docs" / "plugins.md").read_text(encoding="utf-8")
    section = doc.split("## Stability and versioning", 1)[1]
    missing = sorted(n for n in DOCUMENTED if f"`{n}`" not in section)
    assert not missing


def test_base_classes_carry_the_current_api_version() -> None:
    assert Scanner.api_version == PLUGIN_API_VERSION
    assert Reporter.api_version == PLUGIN_API_VERSION
    assert AIProvider.api_version == PLUGIN_API_VERSION


def test_matching_version_is_registered() -> None:
    reg = _fresh_registry()
    cls = _scanner_cls("compatible", PLUGIN_API_VERSION)
    assert reg.register_scanner(cls) is cls
    assert reg.get_scanner("compatible") is cls
    assert reg.rejected() == {}


@pytest.mark.parametrize("version", ["1", "1.4"])
def test_same_major_in_string_form_is_accepted(version: str) -> None:
    reg = _fresh_registry()
    reg.register_scanner(_scanner_cls("stringy", version))
    assert "stringy" in reg.scanners()


@pytest.mark.parametrize("version", [2, 0, "2.0", None, "one", True])
def test_mismatched_version_is_skipped_and_logged(version: object, caplog) -> None:
    reg = _fresh_registry()
    cls = _scanner_cls("future", version)
    with caplog.at_level(logging.WARNING, logger="nephilex.plugins"):
        assert reg.register_scanner(cls) is cls  # no exception
    assert "future" not in reg.scanners()
    assert ("Scanner", "future") in reg.rejected()
    assert "future" in caplog.text and "plugin API version" in caplog.text
    with pytest.raises(KeyError, match="skipped"):
        reg.get_scanner("future")


def test_mismatched_reporter_and_provider_are_skipped(caplog) -> None:
    class FutureReporter(Reporter):
        name = "future-fmt"
        api_version = 2

        def render(self, result) -> str:
            return ""

    class FutureProvider(AIProvider):
        name = "future-ai"
        api_version = 2

        def complete(self, system: str, user: str) -> str:
            return ""

    reg = _fresh_registry()
    with caplog.at_level(logging.WARNING, logger="nephilex.plugins"):
        reg.register_reporter(FutureReporter)
        reg.register_ai_provider(FutureProvider)
    assert reg.reporters() == {} and reg.ai_providers() == {}
    assert set(reg.rejected()) == {("Reporter", "future-fmt"), ("AIProvider", "future-ai")}
    assert "future-fmt" in caplog.text and "future-ai" in caplog.text


def test_scan_runs_when_a_plugin_is_skipped(tmp_path: Path, monkeypatch) -> None:
    from nephilex.core.config import Config
    from nephilex.core.engine import ScanEngine
    from nephilex.core.project import Project

    monkeypatch.setattr(registry, "_rejected", {})
    registry.register_scanner(_scanner_cls("from-the-future", 99))
    (tmp_path / "app.py").write_text("import os\n", encoding="utf-8")

    cfg = Config()
    cfg.ai.enabled = False
    cfg.cache = False
    cfg.scanners = ["patterns"]
    result = ScanEngine(cfg).scan(Project.from_path(tmp_path))
    assert result.errors == []
    assert "from-the-future" not in registry.scanners()


def test_scanner_context_is_a_dataclass_with_the_old_call_shapes(tmp_path: Path) -> None:
    from nephilex.core.config import Config
    from nephilex.core.project import Project

    assert dataclasses.is_dataclass(ScannerContext)
    project, config = Project.from_path(tmp_path), Config()
    positional = ScannerContext(project, config)
    keyword = ScannerContext(project=project, config=config, ai=None)
    assert positional.ai is None and keyword.project is project
    # Identity semantics are kept, so contexts stay hashable and distinct.
    assert positional != keyword
    assert len({positional, keyword}) == 2
