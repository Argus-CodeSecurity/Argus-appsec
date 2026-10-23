"""Tests for import-level reachability analysis (experimental tier 1)."""

from __future__ import annotations

from pathlib import Path

from nephilex.analysis.reachability import (
    IMPORTED,
    NOT_IMPORTED,
    UNKNOWN,
    collect_python_imports,
    python_import_verdict,
)
from nephilex.core.config import Config
from nephilex.core.models import Likelihood
from nephilex.core.plugin import ScannerContext, registry
from nephilex.core.project import Project


def _reachability_config() -> Config:
    return Config(scanner_options={"dependencies": {"online": False, "reachability": True}})


def _scan_deps(tmp_path: Path, config: Config) -> list:
    project = Project.from_path(tmp_path)
    cls = registry.get_scanner("dependencies")
    ctx = ScannerContext(project=project, config=config, ai=None)
    return list(cls().scan(ctx))


# --- import collection -------------------------------------------------------
def test_collect_imports_plain_from_and_aliased(tmp_path):
    (tmp_path / "app.py").write_text(
        "import yaml\n"
        "import os, json\n"
        "from flask import Flask\n"
        "from dateutil.parser import parse\n"
        "import numpy as np\n",
        encoding="utf-8",
    )
    imports = collect_python_imports(Project.from_path(tmp_path))
    assert {"yaml", "os", "json", "flask", "dateutil", "numpy"} <= imports


def test_collect_imports_indented_and_case(tmp_path):
    (tmp_path / "lazy.py").write_text(
        "def f():\n    import requests\n    from PIL import Image\n",
        encoding="utf-8",
    )
    imports = collect_python_imports(Project.from_path(tmp_path))
    assert "requests" in imports
    assert "pil" in imports  # stored lowercase


def test_collect_imports_ignores_non_python(tmp_path):
    (tmp_path / "notes.md").write_text("import fakepkg\n", encoding="utf-8")
    assert collect_python_imports(Project.from_path(tmp_path)) == set()


# --- verdicts ----------------------------------------------------------------
def test_verdict_alias_table_maps_distribution_to_import_name():
    assert python_import_verdict("pyyaml", {"yaml"}) == IMPORTED
    assert python_import_verdict("Pillow", {"pil"}) == IMPORTED
    assert python_import_verdict("beautifulsoup4", {"bs4"}) == IMPORTED


def test_verdict_normalizes_dashes_and_dots():
    assert python_import_verdict("typing-extensions", {"typing_extensions"}) == IMPORTED
    assert python_import_verdict("ruamel.yaml", {"ruamel"}) == IMPORTED


def test_verdict_not_imported_and_unknown():
    assert python_import_verdict("flask", {"yaml", "os"}) == NOT_IMPORTED
    # No Python source at all -> no meaningful verdict.
    assert python_import_verdict("flask", set()) == UNKNOWN


# --- scanner integration -------------------------------------------------------
def test_dependency_findings_annotated_with_reachability(tmp_path):
    (tmp_path / "requirements.txt").write_text("pyyaml==5.3\nflask==2.0.0\n", encoding="utf-8")
    (tmp_path / "main.py").write_text("import yaml\nprint(yaml)\n", encoding="utf-8")

    findings = {
        f.metadata["installed_version"]: f for f in _scan_deps(tmp_path, _reachability_config())
    }
    yaml_finding = next(f for f in findings.values() if "pyyaml" in f.title)
    flask_finding = next(f for f in findings.values() if "flask" in f.title)

    assert yaml_finding.metadata["reachability"] == IMPORTED
    assert "IS imported" in yaml_finding.description

    assert flask_finding.metadata["reachability"] == NOT_IMPORTED
    assert flask_finding.likelihood == Likelihood.UNLIKELY
    assert "deprioritized rather than suppressed" in flask_finding.description


def test_reachability_off_by_default_leaves_findings_untouched(tmp_path):
    (tmp_path / "requirements.txt").write_text("pyyaml==5.3\n", encoding="utf-8")
    (tmp_path / "main.py").write_text("import yaml\n", encoding="utf-8")

    offline = Config(scanner_options={"dependencies": {"online": False}})
    for finding in _scan_deps(tmp_path, offline):
        assert "reachability" not in finding.metadata
        assert "Reachability" not in finding.description
