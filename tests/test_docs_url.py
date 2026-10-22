"""Every finding carries a docs URL, and reporters surface it."""

from __future__ import annotations

import json

from argus.core.config import Config
from argus.core.engine import ScanEngine
from argus.core.models import Finding, Location, docs_url_for
from argus.core.plugin import registry


def _finding(scanner: str) -> Finding:
    return Finding(
        id="x",
        rule_id=f"{scanner}.r",
        scanner=scanner,
        title="t",
        description="d",
        location=Location(path="a.py", start_line=1),
    )


def test_docs_url_maps_scanner_to_page():
    assert _finding("secrets").docs_url.endswith("/scanners/#secrets")
    assert docs_url_for("llm").endswith("#llm-ai-application-security")
    assert docs_url_for("ast-python").endswith("#taint-data-flow-ast")
    # Unknown scanner still links to the scanners page (no anchor).
    assert docs_url_for("mystery").endswith("/scanners/")


def test_docs_url_serialized_in_json(vulnerable_project):
    result = ScanEngine(Config()).scan(vulnerable_project)
    data = json.loads(registry.get_reporter("json")().render(result))
    assert data["findings"]
    assert all(f["docs_url"].startswith("https://") for f in data["findings"])


def test_docs_url_in_sarif_help_uri(vulnerable_project):
    result = ScanEngine(Config()).scan(vulnerable_project)
    doc = json.loads(registry.get_reporter("sarif")().render(result))
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert rules and all("helpUri" in r for r in rules)


def test_docs_url_in_csv(vulnerable_project):
    result = ScanEngine(Config()).scan(vulnerable_project)
    csv_text = registry.get_reporter("csv")().render(result)
    assert "docs_url" in csv_text.splitlines()[0]
