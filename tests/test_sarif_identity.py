"""Imported findings: tool fingerprints decide identity, and docs link to the import guide."""

from __future__ import annotations

from pathlib import Path

from argus.core.models import Finding, Location, docs_url_for
from argus.importers import parse_sarif


def _doc(result: dict) -> dict:
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "T"}}, "results": [result]}]}


def _result(line: int, **extra) -> dict:
    loc = {
        "physicalLocation": {"artifactLocation": {"uri": "app.py"}, "region": {"startLine": line}}
    }
    return {"ruleId": "R1", "message": {"text": "m"}, "locations": [loc], **extra}


def _finding(tmp_path: Path, line: int, **extra) -> Finding:
    return parse_sarif(_doc(_result(line, **extra)), project_root=tmp_path).findings[0]


def test_tool_fingerprints_survive_an_unreadable_file_and_a_moved_line(tmp_path: Path) -> None:
    fp = {"primaryLocationLineHash": "4f1b2c:1"}
    # No project file to read and no snippet: only the tool's fingerprint is stable.
    before = _finding(tmp_path, 3, partialFingerprints=fp)
    after = _finding(tmp_path, 9, partialFingerprints=fp)
    assert before.fingerprint() == after.fingerprint()
    digest = before.metadata["sarif"]["fingerprint"]
    assert before.fingerprint() == f"{before.rule_id}|app.py|{digest}"


def test_different_tool_fingerprints_are_different_findings(tmp_path: Path) -> None:
    a = _finding(tmp_path, 3, fingerprints={"matchBasedId/v1": "aaa"})
    b = _finding(tmp_path, 3, fingerprints={"matchBasedId/v1": "bbb"})
    assert a.fingerprint() != b.fingerprint()


def test_without_tool_fingerprints_the_content_fingerprint_is_kept(tmp_path: Path) -> None:
    src = tmp_path / "app.py"
    src.write_text("import os\nos.system(cmd)\n", encoding="utf-8")
    before = _finding(tmp_path, 2)
    src.write_text("import os\n\n\nos.system(cmd)\n", encoding="utf-8")
    after = _finding(tmp_path, 4)
    assert "fingerprints" not in before.metadata["sarif"]
    # The importer's digest includes the line here, so it is not used.
    assert before.metadata["sarif"]["fingerprint"] != after.metadata["sarif"]["fingerprint"]
    assert before.fingerprint() == after.fingerprint()


def test_a_malformed_sarif_digest_is_ignored() -> None:
    f = Finding(
        id="x",
        rule_id="t.R1",
        scanner="sarif:t",
        title="t",
        description="d",
        location=Location(path="app.py", start_line=1, snippet="x = 1"),
        metadata={"sarif": {"fingerprint": "not|a digest", "fingerprints": {"k": "v"}}},
    )
    assert f.fingerprint().startswith("t.R1|app.py|")
    assert "not|a digest" not in f.fingerprint()


def test_imported_findings_link_to_the_import_guide(tmp_path: Path) -> None:
    assert docs_url_for("sarif:codeql").endswith("/importing/")
    assert _finding(tmp_path, 1).docs_url.endswith("/importing/")
    assert docs_url_for("secrets").endswith("/scanners/#secrets")
