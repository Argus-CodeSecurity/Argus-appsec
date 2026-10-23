"""Regression tests for two accuracy bugs that benchmarks/accuracy.py surfaced.

1. False negative: ``subprocess(..., shell=True)`` was dropped by the engine's
   prefer-AST step whenever the AST tier ran over the file, even though the AST
   taint tier does not model that taint-independent smell.
2. False positive: a properly parameterized query
   ``execute("... %s", (uid,))`` was flagged as SQL injection because a tainted
   value in the bound-parameters argument counted as reaching the sink.

These pin the fixes so the numbers cannot silently regress.
"""

from __future__ import annotations

import pytest

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_python")

from nephilex.analysis.repository import RepositoryAnalyzer  # noqa: E402
from nephilex.core.config import Config  # noqa: E402
from nephilex.core.engine import ScanEngine  # noqa: E402
from nephilex.core.plugin import ScannerContext, registry  # noqa: E402
from nephilex.core.project import Project  # noqa: E402


def _run_ast(tmp_path, code: str):
    (tmp_path / "app.py").write_text(code, encoding="utf-8")
    project = Project.from_path(tmp_path)
    RepositoryAnalyzer().analyze(project)
    ctx = ScannerContext(project=project, config=Config(), ai=None)
    return list(registry.get_scanner("ast-python")().scan(ctx))


def _engine_scan(tmp_path, code: str):
    (tmp_path / "app.py").write_text(code, encoding="utf-8")
    cfg = Config(scanner_options={"dependencies": {"online": False}})
    return ScanEngine(cfg).scan(Project.from_path(tmp_path))


def test_shell_true_survives_prefer_ast(tmp_path):
    """shell=True must be reported through the full engine, not swallowed."""
    result = _engine_scan(
        tmp_path,
        "import subprocess\ndef run(host):\n    subprocess.run('ping ' + host, shell=True)\n",
    )
    cwes = {c for f in result.sorted_findings() for c in f.cwe}
    assert "CWE-78" in cwes


def test_parameterized_sql_not_flagged(tmp_path):
    """A bound-parameter query is the safe form and must not be flagged."""
    findings = _run_ast(
        tmp_path,
        "from flask import request\n"
        "def q(cursor):\n"
        "    uid = request.args.get('id')\n"
        "    cursor.execute('SELECT * FROM users WHERE id = %s', (uid,))\n",
    )
    assert not any(f.rule_id.endswith("ast-sql-injection") for f in findings)


def test_concatenated_sql_still_flagged(tmp_path):
    """The genuinely unsafe, concatenated query must still be caught."""
    findings = _run_ast(
        tmp_path,
        "from flask import request\n"
        "def q(cursor):\n"
        "    uid = request.args.get('id')\n"
        "    cursor.execute('SELECT * FROM users WHERE id = ' + uid)\n",
    )
    assert any(f.rule_id.endswith("ast-sql-injection") for f in findings)
