"""Fix applier: encodings, line endings and the applied/verified distinction."""

from __future__ import annotations

from pathlib import Path

from argus.analysis.verification import assign_verification_state
from argus.core.models import Finding, Location, Remediation, Severity
from argus.core.project import Project
from argus.remediation.applier import APPLIED_KEY, apply_fixes

RULE = "patterns.python-yaml-load"


def _finding(path: str, line: int) -> Finding:
    return Finding(
        id=f"{RULE}:{path}:{line}", rule_id=RULE, scanner="patterns", title="t",
        description="d", location=Location(path=path, start_line=line),
        severity=Severity.HIGH,
    )


def test_latin1_file_is_skipped_not_fatal(tmp_path: Path):
    (tmp_path / "latin.py").write_bytes(b"# caf\xe9\nimport yaml\nx = yaml.load(s)\n")
    (tmp_path / "ok.py").write_text("import yaml\nx = yaml.load(s)\n", encoding="utf-8")
    report = apply_fixes(Project.from_path(tmp_path),
                         [_finding("latin.py", 3), _finding("ok.py", 2)])
    assert any("latin.py" in s and "not UTF-8" in s for s in report.skipped)
    assert report.changed_files == ["ok.py"]
    assert (tmp_path / "latin.py").read_bytes().startswith(b"# caf\xe9")


def test_unusual_line_separators_are_preserved(tmp_path: Path):
    # \x0c and   are not line breaks for git or the scanner; splitlines()
    # treated them as such, shifting line numbers and rewriting the bytes.
    src = "import yaml\r\nform = '\x0c'\r\ns = ' '\nx = yaml.load(s)\r\nend = 1"
    (tmp_path / "m.py").write_bytes(src.encode("utf-8"))
    report = apply_fixes(Project.from_path(tmp_path), [_finding("m.py", 4)])
    assert report.changed_files == ["m.py"]
    out = (tmp_path / "m.py").read_bytes().decode("utf-8")
    assert out == src.replace("yaml.load(s)", "yaml.safe_load(s)")


def test_applied_flag_drives_fixed_state(tmp_path: Path):
    (tmp_path / "a.py").write_text("import yaml\nx = yaml.load(s)\n", encoding="utf-8")
    f = _finding("a.py", 2)
    apply_fixes(Project.from_path(tmp_path), [f], dry_run=True)
    assert APPLIED_KEY not in f.metadata
    apply_fixes(Project.from_path(tmp_path), [f])
    assert f.metadata[APPLIED_KEY] is True
    assert assign_verification_state(f) == "fixed"


def test_proposed_verified_patch_is_not_fixed():
    f = _finding("a.py", 2)
    f.remediation = Remediation(summary="s", patch="--- a\n+++ b\n", verified=True)
    assert assign_verification_state(f) != "fixed"
