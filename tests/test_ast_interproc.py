"""Tests for cross-file / inter-procedural Python taint (depth-1)."""

from __future__ import annotations

import pytest

from nephilex.core.config import Config
from nephilex.core.plugin import ScannerContext, registry
from nephilex.core.project import Project
from nephilex.scanners.ast_python import is_available

pytestmark = pytest.mark.skipif(
    not is_available(), reason="tree-sitter (the [ast] extra) is not installed"
)


def _scan(tmp_path) -> list:
    from nephilex.analysis.repository import RepositoryAnalyzer

    project = Project.from_path(tmp_path)
    RepositoryAnalyzer().analyze(project)
    cls = registry.get_scanner("ast-python-xfile")
    return list(cls().scan(ScannerContext(project=project, config=Config(), ai=None)))


def _rules(findings) -> set[str]:
    return {f.rule_id for f in findings}


def test_cross_file_sql_injection(tmp_path):
    (tmp_path / "db.py").write_text(
        "def run_query(uid):\n    cursor.execute('SELECT * FROM users WHERE id = ' + uid)\n",
        encoding="utf-8",
    )
    (tmp_path / "routes.py").write_text(
        "from db import run_query\ndef handler():\n    run_query(request.args.get('id'))\n",
        encoding="utf-8",
    )
    findings = _scan(tmp_path)
    assert "ast-python-xfile.ast-sql-injection" in _rules(findings)
    f = next(f for f in findings if f.scanner == "ast-python-xfile")
    assert "db.py" in f.metadata["sink_location"]
    assert f.location.path == "routes.py"  # reported at the call site


def test_same_file_interprocedural(tmp_path):
    (tmp_path / "app.py").write_text(
        "def sink(cmd):\n    os.system(cmd)\ndef view():\n    sink(request.args.get('c'))\n",
        encoding="utf-8",
    )
    assert "ast-python-xfile.ast-command-injection" in _rules(_scan(tmp_path))


def test_clean_argument_does_not_fire(tmp_path):
    # run_query IS dangerous, but the call passes a constant, not a source.
    (tmp_path / "db.py").write_text(
        "def run_query(uid):\n    cursor.execute('SELECT * FROM t WHERE id = ' + uid)\n",
        encoding="utf-8",
    )
    (tmp_path / "routes.py").write_text(
        "from db import run_query\ndef handler():\n    run_query('42')\n",
        encoding="utf-8",
    )
    assert _scan(tmp_path) == []


def test_non_source_variable_does_not_fire(tmp_path):
    # Requires a *direct* source at the call site; a plain variable is not enough.
    (tmp_path / "db.py").write_text(
        "def run_query(uid):\n    cursor.execute('SELECT * FROM t WHERE id = ' + uid)\n",
        encoding="utf-8",
    )
    (tmp_path / "routes.py").write_text(
        "from db import run_query\ndef handler():\n    x = 5\n    run_query(x)\n",
        encoding="utf-8",
    )
    assert _scan(tmp_path) == []


def test_safe_function_not_flagged(tmp_path):
    # The parameter never reaches a sink, so passing a source is fine.
    (tmp_path / "u.py").write_text(
        "def greet(name):\n    return 'hello ' + name\n",
        encoding="utf-8",
    )
    (tmp_path / "routes.py").write_text(
        "from u import greet\ndef handler():\n    greet(request.args.get('n'))\n",
        encoding="utf-8",
    )
    assert _scan(tmp_path) == []


def test_keyword_argument_mapping(tmp_path):
    (tmp_path / "db.py").write_text(
        "def run_query(uid):\n    cursor.execute('SELECT * FROM t WHERE id = ' + uid)\n",
        encoding="utf-8",
    )
    (tmp_path / "routes.py").write_text(
        "from db import run_query\ndef handler():\n    run_query(uid=request.args.get('id'))\n",
        encoding="utf-8",
    )
    assert "ast-python-xfile.ast-sql-injection" in _rules(_scan(tmp_path))
