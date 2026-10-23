"""Tests for enterprise/CI features: determinism, baseline, trust boundary,
report-injection hardening, and cross-language fix validation."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from nephilex.baseline import filter_new, load_fingerprints
from nephilex.core.config import Config
from nephilex.core.models import Finding, Location, ScanResult, Severity
from nephilex.core.project import Project
from nephilex.remediation.applier import _syntax_error


def _finding(rule_id="patterns.x", path="a.py", line=1, snippet="danger()") -> Finding:
    return Finding(
        id=f"{rule_id}:{line}",
        rule_id=rule_id,
        scanner="patterns",
        title="t",
        description="d",
        location=Location(path=path, start_line=line, snippet=snippet),
        severity=Severity.HIGH,
    )


# --- determinism -----------------------------------------------------------
def test_file_walk_is_deterministic_and_sorted(tmp_path: Path):
    for name in ["z.py", "a.py", "m.py"]:
        (tmp_path / name).write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "b.py").write_text("y = 2\n", encoding="utf-8")

    # Files within a directory are visited in sorted order, and the overall walk
    # is reproducible across independent Project instances.
    rels1 = [f.rel_path for f in Project.from_path(tmp_path).files()]
    rels2 = [f.rel_path for f in Project.from_path(tmp_path).files()]
    assert rels1 == rels2
    assert rels1[:3] == ["a.py", "m.py", "z.py"]  # top-level files sorted


# --- fingerprint is shift-resistant ----------------------------------------
def test_fingerprint_survives_line_shift():
    a = _finding(line=10, snippet="do_dangerous(x)")
    b = _finding(line=42, snippet="  do_dangerous(x)  ")  # moved + reindented
    assert a.fingerprint() == b.fingerprint()

    c = _finding(line=10, snippet="do_other(x)")
    assert a.fingerprint() != c.fingerprint()


# --- baseline / diff-aware scanning ----------------------------------------
def test_baseline_suppresses_known_findings(tmp_path: Path):
    result = ScanResult(target="t", started_at=datetime.now(timezone.utc))
    known = _finding(snippet="old_bug()")
    result.add(known)
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(result.model_dump_json(indent=2), encoding="utf-8")

    fps = load_fingerprints(baseline_path)
    current = [known, _finding(rule_id="patterns.y", snippet="new_bug()")]
    new, suppressed = filter_new(current, fps)

    assert suppressed == 1
    assert len(new) == 1
    assert new[0].rule_id == "patterns.y"


# --- trust boundary: config discovery only when a root is given ------------
def test_config_not_discovered_without_project_root(tmp_path: Path):
    (tmp_path / ".nephilex.yml").write_text("scanners: [secrets]\n", encoding="utf-8")
    # Simulates the untrusted-remote path: no project_root -> repo config ignored.
    assert Config.load(project_root=None).scanners == []
    # With a trusted root it is honored.
    assert Config.load(project_root=tmp_path).scanners == ["secrets"]


# --- markdown report-injection hardening -----------------------------------
def test_markdown_fences_untrusted_snippet():
    from nephilex.core.plugin import registry

    result = ScanResult(target="t", started_at=datetime.now(timezone.utc))
    # A snippet that tries to break out of a ``` fence and inject content.
    result.add(_finding(snippet="```\n## Injected heading\nmalicious"))
    md = registry.get_reporter("markdown")().render(result)
    # The fence must be longer than the backtick run inside the snippet.
    assert "````" in md


# --- cross-language fix validation -----------------------------------------
def test_syntax_gate_validates_python_json_yaml():
    assert _syntax_error("m.py", "x = 1\n") is None
    assert _syntax_error("m.py", "def (:\n") is not None
    assert _syntax_error("c.json", '{"a": 1}') is None
    assert _syntax_error("c.json", '{"a": }') is not None
    assert _syntax_error("k.yaml", "a: 1\n") is None
    assert _syntax_error("k.yaml", "a: [1, 2\n") is not None
