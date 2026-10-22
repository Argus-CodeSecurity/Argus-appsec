"""One hostile file must not zero out a whole scanner.

The AST scanners used to walk trees recursively, so a file with a few
thousand levels of nesting raised RecursionError, and only the parse call was
guarded, so that one file discarded every finding from every other file. The
secrets scanner ran its git-history pass inside the same generator as the
working-tree pass, so a history failure dropped the working-tree findings.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from argus.core.config import Config
from argus.core.plugin import ScannerContext, registry
from argus.core.project import Project
from argus.scanners import ast_python
from argus.scanners.ast_python import is_available

DEPTH = 3000  # well past the default recursion limit of 1000

needs_ast = pytest.mark.skipif(
    not is_available(), reason="tree-sitter (the [ast] extra) is not installed")


def _scan(tmp_path: Path, scanner: str, files: dict[str, str], options=None) -> list:
    for name, body in files.items():
        (tmp_path / name).write_text(body, encoding="utf-8")
    from argus.analysis.repository import RepositoryAnalyzer

    project = Project.from_path(tmp_path)
    RepositoryAnalyzer().analyze(project)
    cfg = Config(scanner_options=options or {})
    cls = registry.get_scanner(scanner)
    return list(cls().scan(ScannerContext(project=project, config=cfg, ai=None)))


PY_VULN = (
    "def handler():\n"
    "    name = request.args.get('u')\n"
    "    value = name\n"
    "    cursor.execute('SELECT * FROM t WHERE n = ' + value)\n"
)
PY_DEEP = "x = " + "(" * DEPTH + "1" + ")" * DEPTH + "\n" + "y = " + "f(" * DEPTH + ")" * DEPTH + "\n"


@needs_ast
def test_ast_python_survives_deep_nesting(tmp_path):
    findings = _scan(tmp_path, "ast-python", {"deep.py": PY_DEEP, "app.py": PY_VULN})
    assert any(f.rule_id == "ast-python.ast-sql-injection" and f.location.path == "app.py"
               for f in findings)


@needs_ast
def test_ast_python_deep_tainted_expression_is_still_analyzed(tmp_path):
    deep_arg = "(" * DEPTH + "request.args['q']" + ")" * DEPTH
    body = f"def h():\n    eval({deep_arg})\n"
    findings = _scan(tmp_path, "ast-python", {"deep.py": body})
    assert any(f.rule_id == "ast-python.ast-code-injection" for f in findings)


@needs_ast
def test_ast_python_isolates_a_failing_file(tmp_path, monkeypatch):
    real_run = ast_python._Analyzer.run

    def run(self, root):
        if self._path == "bad.py":
            raise RecursionError("boom")
        return real_run(self, root)

    monkeypatch.setattr(ast_python._Analyzer, "run", run)
    findings = _scan(tmp_path, "ast-python", {"bad.py": "x = 1\n", "app.py": PY_VULN})
    rules = {(f.rule_id, f.location.path) for f in findings}
    assert ("ast-python.ast-sql-injection", "app.py") in rules
    assert ("ast-python.analysis-skipped", "bad.py") in rules
    note = next(f for f in findings if f.rule_id == "ast-python.analysis-skipped")
    assert note.severity.label.lower() == "info"


@needs_ast
def test_ast_python_xfile_survives_deep_nesting(tmp_path):
    files = {
        "deep.py": PY_DEEP,
        "db.py": ("def run_query(uid):\n"
                  "    cursor.execute('SELECT * FROM users WHERE id = ' + uid)\n"),
        "routes.py": ("from db import run_query\n"
                      "def handler():\n"
                      "    run_query(request.args.get('id'))\n"),
    }
    findings = _scan(tmp_path, "ast-python-xfile", files)
    assert any(f.rule_id == "ast-python-xfile.ast-sql-injection" for f in findings)


def _js_available() -> bool:
    from argus.scanners.ast_js import is_available as js_ok
    return js_ok()


@pytest.mark.skipif(not _js_available(), reason="tree-sitter JS grammar not installed")
def test_ast_js_survives_deep_nesting(tmp_path):
    deep = "const x = " + "[" * DEPTH + "]" * DEPTH + ";\nconst y = " + "f(" * DEPTH + ")" * DEPTH + ";\n"
    vuln = ("app.get('/u', (req, res) => {\n"
            "  const id = req.query.id;\n"
            "  db.query('SELECT * FROM users WHERE id = ' + id);\n"
            "});\n")
    findings = _scan(tmp_path, "ast-js", {"deep.js": deep, "app.js": vuln})
    assert any(f.rule_id == "ast-js.ast-sql-injection" and f.location.path == "app.js"
               for f in findings)


def test_secrets_history_failure_keeps_working_tree_findings(tmp_path, monkeypatch):
    from argus.scanners import secrets_history

    def explode(root):
        raise OSError("git exploded")

    monkeypatch.setattr(secrets_history, "find_history_secrets", explode)
    key = "AKIA" + "Q7RT2LMX9PZK4HNB"
    findings = _scan(tmp_path, "secrets", {"config.py": f'KEY = "{key}"\n'},
                     options={"secrets": {"history": True}})
    rules = {f.rule_id for f in findings}
    assert "secrets.aws-access-key-id" in rules
    assert "secrets.history-scan-failed" in rules


def test_make_parser_supports_pre_022_bindings(monkeypatch):
    import tree_sitter

    class OldParser:
        """Bindings before 0.22: no constructor argument, set_language()."""

        def __init__(self):
            self.lang = None

        def set_language(self, lang):
            self.lang = lang

    class PropertyParser:
        """Bindings with a `language` property but no constructor argument."""

        def __init__(self):
            self.language = None

    monkeypatch.setattr(tree_sitter, "Parser", OldParser)
    assert ast_python.make_parser("L").lang == "L"
    monkeypatch.setattr(tree_sitter, "Parser", PropertyParser)
    assert ast_python.make_parser("L").language == "L"
