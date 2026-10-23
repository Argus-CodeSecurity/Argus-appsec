"""Tests for the Go SAST pattern rules."""

from __future__ import annotations

from nephilex.analysis.repository import RepositoryAnalyzer
from nephilex.core.config import Config
from nephilex.core.plugin import ScannerContext, registry
from nephilex.core.project import Project


def _scan_go(tmp_path, content: str, name: str = "main.go") -> set[str]:
    (tmp_path / name).write_text(content, encoding="utf-8")
    (tmp_path / "go.mod").write_text("module example.com/app\n\ngo 1.21\n", encoding="utf-8")
    project = Project.from_path(tmp_path)
    RepositoryAnalyzer().analyze(project)
    cls = registry.get_scanner("patterns")
    findings = cls().scan(ScannerContext(project=project, config=Config(), ai=None))
    return {f.rule_id for f in findings}


def test_go_sql_injection_sprintf(tmp_path):
    rules = _scan_go(
        tmp_path,
        "package main\n"
        "func q(db *sql.DB, id string) {\n"
        '    db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))\n'
        "}\n",
    )
    assert "patterns.go-sql-sprintf" in rules


def test_go_sql_parameterized_is_clean(tmp_path):
    rules = _scan_go(
        tmp_path,
        "package main\n"
        "func q(db *sql.DB, id string) {\n"
        '    db.Query("SELECT * FROM users WHERE id = $1", id)\n'
        "}\n",
    )
    assert "patterns.go-sql-sprintf" not in rules


def test_go_command_injection_shell(tmp_path):
    rules = _scan_go(
        tmp_path,
        "package main\n"
        "func run(userInput string) {\n"
        '    exec.Command("sh", "-c", "echo "+userInput)\n'
        "}\n",
    )
    assert "patterns.go-command-injection" in rules


def test_go_direct_exec_is_clean(tmp_path):
    rules = _scan_go(
        tmp_path, 'package main\nfunc run(name string) {\n    exec.Command("ls", "-l", name)\n}\n'
    )
    assert "patterns.go-command-injection" not in rules


def test_go_weak_hash(tmp_path):
    rules = _scan_go(tmp_path, "package main\nfunc h(b []byte) { md5.Sum(b) }\n")
    assert "patterns.go-weak-hash" in rules


def test_go_ssrf(tmp_path):
    rules = _scan_go(
        tmp_path,
        "package main\n"
        "func fetch(r *http.Request) {\n"
        '    http.Get(r.URL.Query().Get("target"))\n'
        "}\n",
    )
    assert "patterns.go-ssrf-request" in rules
