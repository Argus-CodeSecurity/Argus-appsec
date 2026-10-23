"""Custom rule loading: ReDoS lint, malformed rules, and untrusted rule paths."""

from __future__ import annotations

from pathlib import Path

import pytest

from nephilex.scanners.custom_rules import _coerce_rule, _is_catastrophic, load_custom_rules


@pytest.mark.parametrize(
    "pattern",
    [
        "(a+)+$",
        "([a-z]*)+",
        "(a|aa)+$",
        "(.*a){25}",
        r"(\w|\d\d)+$",
        "(?:x|x?y)*z",
        "(a|)+b",
        r"(?:\s*,)+$",
    ],
)
def test_catastrophic_shapes_are_rejected(pattern):
    assert _is_catastrophic(pattern)


@pytest.mark.parametrize(
    "pattern",
    [
        r"\bAKIA[0-9A-Z]{16}\b",
        r"password\s*=\s*['\"].+['\"]",
        r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
        r"(\d{1,3}\.){3}\d{1,3}",
        "(foo|bar)+baz",
        "(?:a|b)*c",
        r"eval\s*\(",
        r"(?i)(md5|sha1)\(",
        # CPython's parser folds single-character branches into one character
        # class, so this is a plain linear repeat, not an ambiguous alternation.
        r"(\w|\d)+$",
    ],
)
def test_ordinary_patterns_are_accepted(pattern):
    assert not _is_catastrophic(pattern)


def test_invalid_severity_skips_the_rule():
    assert _coerce_rule({"id": "x", "pattern": "foo", "severity": "bogus"}, "t") is None


@pytest.mark.parametrize(
    "raw",
    [
        {"id": "x", "pattern": "foo", "suppress": "("},
        {"id": "x", "pattern": "foo", "cwe": 5},
        {"id": "x", "pattern": "("},
        {"pattern": "foo"},
    ],
)
def test_malformed_rule_is_skipped_not_raised(raw):
    assert _coerce_rule(raw, "t") is None


def test_valid_rule_loads():
    rule = _coerce_rule(
        {"id": "x", "pattern": "foo", "severity": "high", "cwe": "CWE-1", "languages": ["Python"]},
        "t",
    )
    assert rule is not None and rule.cwe == ["CWE-1"] and rule.languages == {"Python"}


RULES_YAML = "rules:\n  - id: injected\n    pattern: 'foo'\n    severity: low\n"


def test_untrusted_target_ignores_relative_rules_inside_it(tmp_path: Path):
    target = tmp_path / "repo"
    (target / "cfg").mkdir(parents=True)
    (target / "cfg" / "rules.yml").write_text(RULES_YAML, encoding="utf-8")
    assert load_custom_rules(target, "cfg/*.yml", include_convention_dir=False) == []
    loaded = load_custom_rules(target, "cfg/*.yml", include_convention_dir=True)
    assert [r.id for r in loaded] == ["injected"]


def test_untrusted_target_keeps_rules_outside_it(tmp_path: Path):
    target = tmp_path / "repo"
    target.mkdir()
    (tmp_path / "ops-rules.yml").write_text(RULES_YAML, encoding="utf-8")
    relative = load_custom_rules(target, "../ops-rules.yml", include_convention_dir=False)
    absolute = load_custom_rules(
        target, str(tmp_path / "ops-rules.yml"), include_convention_dir=False
    )
    assert [r.id for r in relative] == ["injected"]
    assert [r.id for r in absolute] == ["injected"]
