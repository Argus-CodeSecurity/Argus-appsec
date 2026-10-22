"""Tests for the reporters."""

from __future__ import annotations

import json

from argus.core.config import Config
from argus.core.engine import ScanEngine
from argus.core.plugin import registry


def _result(project):
    return ScanEngine(Config(attack_simulation=True, generate_patches=True)).scan(project)


def test_json_reporter_roundtrips(vulnerable_project):
    result = _result(vulnerable_project)
    rendered = registry.get_reporter("json")().render(result)
    data = json.loads(rendered)  # must be valid JSON
    assert data["findings"]
    assert data["argus_version"]


def test_sarif_is_valid_and_maps_levels(vulnerable_project):
    result = _result(vulnerable_project)
    rendered = registry.get_reporter("sarif")().render(result)
    doc = json.loads(rendered)
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "Argus"
    assert run["results"]
    # Every result references a declared rule.
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    for res in run["results"]:
        assert res["ruleId"] in rule_ids
        assert res["level"] in {"note", "warning", "error"}
    # GitHub security-severity present on rules.
    assert all("security-severity" in r["properties"] for r in run["tool"]["driver"]["rules"])


def test_markdown_contains_sections(vulnerable_project):
    result = _result(vulnerable_project)
    md = registry.get_reporter("markdown")().render(result)
    assert "# Argus Security Report" in md
    assert "## Findings" in md
    assert "Attack simulation" in md


def test_html_is_self_contained(vulnerable_project):
    result = _result(vulnerable_project)
    html = registry.get_reporter("html")().render(result)
    assert html.startswith("<!doctype html>")
    assert "<style>" in html  # CSS inlined
    assert "http-equiv" not in html  # no external refresh
    # No external resource references.
    assert 'src="http' not in html and 'href="http' not in html


def test_csv_has_header_and_rows(vulnerable_project):
    result = _result(vulnerable_project)
    csv_text = registry.get_reporter("csv")().render(result)
    lines = csv_text.strip().splitlines()
    assert lines[0].startswith("id,scanner,rule_id")
    assert len(lines) > 1


def test_gitlab_sast_report_shape(vulnerable_project):
    result = _result(vulnerable_project)
    doc = json.loads(registry.get_reporter("gitlab")().render(result))
    assert doc["version"].startswith("15.")
    assert doc["scan"]["type"] == "sast"
    assert doc["scan"]["scanner"]["id"] == "argus"
    assert doc["vulnerabilities"]
    for v in doc["vulnerabilities"]:
        assert v["severity"] in {"Info", "Low", "Medium", "High", "Critical"}
        assert v["category"] == "sast"
        assert v["location"]["file"]
        # Every vulnerability must carry at least one identifier (GitLab requires it).
        assert v["identifiers"]
