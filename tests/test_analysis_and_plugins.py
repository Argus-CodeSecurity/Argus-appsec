"""Tests for repository analysis and the plugin registry."""

from __future__ import annotations

import pytest

from argus.analysis.repository import RepositoryAnalyzer
from argus.core.models import Finding, Location, Severity
from argus.core.plugin import Registry, Scanner, ScannerContext


def test_analyzer_detects_language_and_framework(vulnerable_project):
    RepositoryAnalyzer().analyze(vulnerable_project)
    assert "Python" in vulnerable_project.languages
    assert "Flask" in vulnerable_project.frameworks
    assert "Docker" in vulnerable_project.languages


def test_analyzer_maps_architecture(vulnerable_project):
    RepositoryAnalyzer().analyze(vulnerable_project)
    arch = vulnerable_project.architecture
    assert "REST/HTTP" in arch["apis"]
    assert any("Dockerfile" in c for c in arch["containers"])
    assert "requirements.txt" in arch["dependency_manifests"]


def test_registry_registration_and_lookup():
    reg = Registry()

    @reg.register_scanner
    class Dummy(Scanner):
        name = "dummy"
        category = "test"

        def scan(self, ctx: ScannerContext):
            yield Finding(
                id="dummy:1",
                rule_id="dummy.r",
                scanner="dummy",
                title="t",
                description="d",
                location=Location(path="x", start_line=1),
                severity=Severity.LOW,
            )

    assert "dummy" in reg.scanners()
    assert reg.get_scanner("dummy") is Dummy


def test_registry_rejects_nameless_scanner():
    reg = Registry()
    with pytest.raises(ValueError):

        @reg.register_scanner
        class NoName(Scanner):
            def scan(self, ctx):
                return []


def test_registry_unknown_lookup_raises():
    reg = Registry()
    with pytest.raises(KeyError):
        reg.get_scanner("nope")


def test_registry_rejects_duplicate_name_different_class():
    reg = Registry()

    @reg.register_scanner
    class First(Scanner):
        name = "dup"
        category = "test"

        def scan(self, ctx: ScannerContext):
            return []

    with pytest.raises(ValueError, match="already registered"):

        @reg.register_scanner
        class Second(Scanner):
            name = "dup"
            category = "test"

            def scan(self, ctx: ScannerContext):
                return []


def test_registry_allows_idempotent_reregistration():
    reg = Registry()

    class Once(Scanner):
        name = "once"
        category = "test"

        def scan(self, ctx: ScannerContext):
            return []

    assert reg.register_scanner(Once) is Once
    assert reg.register_scanner(Once) is Once  # same class is fine


def test_analyzer_caps_aggregate_source_blob(tmp_path, monkeypatch):
    """A monorepo of many small files must not build an unbounded source blob."""
    from argus.analysis import repository as repo_mod
    from argus.core.project import Project

    budget = 120
    monkeypatch.setattr(repo_mod, "_SOURCE_BLOB_BUDGET", budget)
    monkeypatch.setattr(repo_mod, "_PER_FILE_SOURCE_CAP", 50)
    root = tmp_path / "mono"
    root.mkdir()
    for i in range(30):
        (root / f"mod{i}.py").write_text("x" * 40 + "\n", encoding="utf-8")

    seen: dict[str, int] = {}
    orig = RepositoryAnalyzer._detect_frameworks

    def capture(deps, blob):
        seen["len"] = len(blob)
        return orig(deps, blob)

    monkeypatch.setattr(RepositoryAnalyzer, "_detect_frameworks", staticmethod(capture))
    project = Project.from_path(root)
    RepositoryAnalyzer().analyze(project)

    assert "Python" in project.languages
    assert seen["len"] <= budget + 30  # content budget + newline separators
    assert seen["len"] < 30 * 40  # far below the unbounded total
