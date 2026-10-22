"""Tests for YAML-defined custom SAST rules."""

from __future__ import annotations

from argus.analysis.repository import RepositoryAnalyzer
from argus.core.config import Config
from argus.core.plugin import ScannerContext, registry
from argus.core.project import Project
from argus.scanners.custom_rules import load_custom_rules


def _scan(tmp_path, config) -> list:
    project = Project.from_path(tmp_path)
    RepositoryAnalyzer().analyze(project)
    cls = registry.get_scanner("patterns")
    return list(cls().scan(ScannerContext(project=project, config=config, ai=None)))


_RULE_YAML = """
rules:
  - id: no-eval-marker
    title: Custom banned marker
    pattern: 'BANNED_TOKEN'
    severity: high
    cwe: [CWE-1]
    why: A banned token appears in source.
    fix: Remove it.
"""


def test_load_custom_rules_from_convention_dir(tmp_path):
    rules_dir = tmp_path / ".argus" / "rules"
    rules_dir.mkdir(parents=True)
    (rules_dir / "team.yml").write_text(_RULE_YAML, encoding="utf-8")
    rules = load_custom_rules(tmp_path)
    assert [r.id for r in rules] == ["no-eval-marker"]


def test_custom_rule_produces_finding(tmp_path):
    rules_dir = tmp_path / ".argus" / "rules"
    rules_dir.mkdir(parents=True)
    (rules_dir / "team.yml").write_text(_RULE_YAML, encoding="utf-8")
    (tmp_path / "app.py").write_text("x = 'BANNED_TOKEN'\n", encoding="utf-8")

    findings = _scan(tmp_path, Config(trust_project_config=True))
    hits = [f for f in findings if f.rule_id == "patterns.no-eval-marker"]
    assert hits
    assert hits[0].severity.label == "High"


def test_rules_option_path(tmp_path):
    (tmp_path / "myrules.yml").write_text(_RULE_YAML, encoding="utf-8")
    (tmp_path / "app.py").write_text("y = BANNED_TOKEN\n", encoding="utf-8")
    # A trusted (local) project may point at a rules file inside itself.
    cfg = Config(scanner_options={"patterns": {"rules": "myrules.yml"}}, trust_project_config=True)
    findings = _scan(tmp_path, cfg)
    assert any(f.rule_id == "patterns.no-eval-marker" for f in findings)


def test_rules_option_path_inside_untrusted_tree_is_ignored(tmp_path):
    (tmp_path / "myrules.yml").write_text(_RULE_YAML, encoding="utf-8")
    (tmp_path / "app.py").write_text("y = BANNED_TOKEN\n", encoding="utf-8")
    cfg = Config(scanner_options={"patterns": {"rules": "myrules.yml"}})
    findings = _scan(tmp_path, cfg)
    assert not any(f.rule_id == "patterns.no-eval-marker" for f in findings)


def test_invalid_rule_is_skipped_not_fatal(tmp_path):
    rules_dir = tmp_path / ".argus" / "rules"
    rules_dir.mkdir(parents=True)
    # One valid rule, one missing 'pattern', one bad regex.
    (rules_dir / "mixed.yml").write_text(
        "rules:\n"
        "  - id: ok\n    pattern: 'FOO'\n    severity: low\n"
        "  - id: no-pattern\n    severity: low\n"
        "  - id: bad-regex\n    pattern: '('\n    severity: low\n",
        encoding="utf-8",
    )
    rules = load_custom_rules(tmp_path)
    assert [r.id for r in rules] == ["ok"]


def test_custom_rules_disable_cache(tmp_path):
    scanner = registry.get_scanner("patterns")()

    # No custom rules -> normal cacheable behavior.
    plain = tmp_path / "plain"
    plain.mkdir()
    ctx_plain = ScannerContext(project=Project.from_path(plain), config=Config(), ai=None)
    assert scanner.cacheable(ctx_plain) is True

    # Custom rules present -> not cacheable (they can change without a file change).
    withrules = tmp_path / "withrules"
    (withrules / ".argus" / "rules").mkdir(parents=True)
    (withrules / ".argus" / "rules" / "team.yml").write_text(_RULE_YAML, encoding="utf-8")
    ctx_rules = ScannerContext(
        project=Project.from_path(withrules), config=Config(trust_project_config=True), ai=None
    )
    assert scanner.cacheable(ctx_rules) is False
