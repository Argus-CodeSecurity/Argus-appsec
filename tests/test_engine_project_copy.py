"""ScanEngine.scan must not modify the Project the caller passed in."""

from __future__ import annotations

from pathlib import Path

from argus.core.config import Config
from argus.core.engine import ScanEngine
from argus.core.project import Project


def _config(**kwargs) -> Config:
    cfg = Config(**kwargs)
    cfg.ai.enabled = False
    cfg.cache = False
    cfg.scanners = ["secrets"]
    return cfg


def _project(tmp_path: Path) -> Project:
    (tmp_path / "legacy").mkdir()
    (tmp_path / "legacy" / "keys.py").write_text('K = "AKIAJ2345678ABCDEFGH"\n', encoding="utf-8")
    (tmp_path / "app.py").write_text("import os\n", encoding="utf-8")
    return Project.from_path(tmp_path)


def test_scan_leaves_the_callers_project_untouched(tmp_path: Path) -> None:
    project = _project(tmp_path)
    project.metadata["owner"] = "caller"

    ScanEngine(_config(exclude_paths=["legacy/**"])).scan(project)

    assert project.extra_ignores == ()
    assert project.languages == {} and project.frameworks == []
    assert project.architecture == {}
    assert project.metadata == {"owner": "caller"}


def test_exclude_paths_do_not_leak_into_the_next_scan(tmp_path: Path) -> None:
    project = _project(tmp_path)

    first = ScanEngine(_config(exclude_paths=["legacy/**"])).scan(project)
    second = ScanEngine(_config()).scan(project)

    assert not any(f.location.path.startswith("legacy/") for f in first.findings)
    assert any(f.location.path.startswith("legacy/") for f in second.findings)
