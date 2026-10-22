"""Tests for the AST (tree-sitter) taint scanner and cross-tier dedup.

These require the optional [ast] extra; they skip cleanly if it is absent so the
suite still passes without tree-sitter installed.
"""

from __future__ import annotations

import pytest

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_python")

from argus.core.config import Config  # noqa: E402
from argus.core.engine import ScanEngine  # noqa: E402
from argus.core.plugin import ScannerContext, registry  # noqa: E402
from argus.scanners import ast_python  # noqa: E402


def _run_ast(tmp_path, code: str):
    from argus.analysis.repository import RepositoryAnalyzer
    from argus.core.project import Project

    (tmp_path / "app.py").write_text(code, encoding="utf-8")
    project = Project.from_path(tmp_path)
    RepositoryAnalyzer().analyze(project)
    ctx = ScannerContext(project=project, config=Config(), ai=None)
    return list(registry.get_scanner("ast-python")().scan(ctx))


def test_available_and_registered():
    assert ast_python.is_available() is True
    assert "ast-python" in registry.scanners()


def test_multi_hop_sql_injection(tmp_path):
    """Source -> two intermediate variables -> execute(): the regex tier can't."""
    findings = _run_ast(
        tmp_path,
        "from flask import request\n"
        "def h():\n"
        "    name = request.args.get('user')\n"
        "    a = name\n"
        "    b = a\n"
        "    cursor.execute('SELECT * FROM u WHERE n = ' + b)\n",
    )
    sqli = [f for f in findings if "CWE-89" in f.cwe]
    assert len(sqli) == 1
    assert sqli[0].rule_id == "ast-python.ast-sql-injection"
    assert sqli[0].confidence.label == "High"


def test_command_injection(tmp_path):
    findings = _run_ast(
        tmp_path,
        "from flask import request\n"
        "def h():\n"
        "    host = request.args.get('host')\n"
        "    os.system('ping ' + host)\n",
    )
    assert [f for f in findings if "CWE-78" in f.cwe]


def test_path_traversal(tmp_path):
    findings = _run_ast(
        tmp_path,
        "from flask import request\n"
        "def h():\n"
        "    p = request.args.get('file')\n"
        "    q = p\n"
        "    open(q).read()\n",
    )
    assert [f for f in findings if "CWE-22" in f.cwe]


def test_code_injection(tmp_path):
    findings = _run_ast(
        tmp_path,
        "from flask import request\ndef h():\n    expr = request.args.get('e')\n    eval(expr)\n",
    )
    assert [f for f in findings if "CWE-95" in f.cwe]


def test_sanitized_input_not_flagged(tmp_path):
    """int() coercion removes the taint -> no SQL injection."""
    findings = _run_ast(
        tmp_path,
        "from flask import request\n"
        "def h():\n"
        "    uid = int(request.args.get('id'))\n"
        "    cursor.execute('SELECT * FROM u WHERE id = ' + str(uid))\n",
    )
    assert not [f for f in findings if "CWE-89" in f.cwe]


def test_constant_not_flagged(tmp_path):
    findings = _run_ast(
        tmp_path,
        "def h():\n    name = 'admin'\n    cursor.execute('SELECT * FROM u WHERE n = ' + name)\n",
    )
    assert not [f for f in findings if "CWE-89" in f.cwe]


def test_taint_does_not_leak_across_functions(tmp_path):
    """A tainted var in one function must not taint a same-named var in another."""
    findings = _run_ast(
        tmp_path,
        "from flask import request\n"
        "def a():\n"
        "    x = request.args.get('q')\n"
        "def b():\n"
        "    x = 'constant'\n"
        "    cursor.execute('SELECT ' + x)\n",
    )
    assert not [f for f in findings if "CWE-89" in f.cwe]


def test_engine_dedupes_regex_and_ast(tmp_path):
    """The same SQLi caught by both tiers is reported once (AST, higher confidence)."""
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "def h():\n"
        "    name = request.args.get('user')\n"
        "    query = f\"SELECT * FROM u WHERE n = '{name}'\"\n"
        "    cursor.execute(query)\n",
        encoding="utf-8",
    )
    from argus.core.project import Project

    result = ScanEngine(Config(scanners=["patterns", "ast-python"])).scan(
        Project.from_path(tmp_path)
    )
    sqli = [f for f in result.findings if "CWE-89" in f.cwe]
    assert len(sqli) == 1
    assert sqli[0].scanner == "ast-python"  # the higher-confidence tier won
