"""A missing [ast] extra is reported as such, not as "not applicable".

Without tree-sitter the taint tiers are skipped. The skip message must say why,
so a scan that silently runs without data-flow analysis is not mistaken for a
project with nothing to analyse (the GitHub Action used to do exactly that).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from nephilex.core.config import Config
from nephilex.core.engine import ScanEngine
from nephilex.core.project import Project
from nephilex.scanners import ast_js, ast_python, ast_python_interproc


def _messages(root: Path, scanners: list[str]) -> list[str]:
    seen: list[str] = []
    cfg = Config(scanners=scanners, cache=False)
    cfg.ai.enabled = False
    ScanEngine(cfg, progress=seen.append).scan(Project.from_path(root))
    return seen


def test_missing_extra_names_the_fix(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "app.py").write_text("import os\nos.system(input())\n", encoding="utf-8")
    (tmp_path / "web.js").write_text("eval(location.hash)\n", encoding="utf-8")
    for module in (ast_python, ast_python_interproc, ast_js):
        monkeypatch.setattr(module, "is_available", lambda: False)

    messages = _messages(tmp_path, ["ast-python", "ast-python-xfile", "ast-js"])
    for name in ("ast-python", "ast-python-xfile", "ast-js"):
        line = next(m for m in messages if f"'{name}'" in m)
        assert 'pip install "nephilex[ast]"' in line, line


def test_nothing_to_scan_is_still_not_applicable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "README.md").write_text("no code here\n", encoding="utf-8")
    monkeypatch.setattr(ast_python, "is_available", lambda: False)

    line = next(m for m in _messages(tmp_path, ["ast-python"]) if "'ast-python'" in m)
    assert "not applicable" in line
