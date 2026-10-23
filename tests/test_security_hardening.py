"""Self-defense tests: Nephilex must not be exploitable by a hostile repository.

These cover the scanner-as-attack-surface cases where a malicious target tries to
make Nephilex read or write files outside the scan root via symlinks or path
traversal. See THREAT_MODEL.md.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from nephilex.core.models import Finding, Location, Severity
from nephilex.core.project import Project
from nephilex.remediation.applier import apply_fixes


def _symlink_or_skip(link: Path, target: Path) -> None:
    """Create a symlink, or skip the test where the OS forbids it (Windows)."""
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):  # pragma: no cover - platform dependent
        pytest.skip("symlink creation not permitted on this platform")


def _yaml_load_finding(path: str, line: int) -> Finding:
    # A rule with a known deterministic fix (yaml.load -> yaml.safe_load).
    return Finding(
        id=f"x:{line}",
        rule_id="patterns.python-yaml-load",
        scanner="patterns",
        title="t",
        description="d",
        location=Location(path=path, start_line=line),
        severity=Severity.HIGH,
    )


def test_symlink_escaping_root_is_not_read(tmp_path: Path):
    """A symlink pointing outside the project must not be scanned."""
    secret = tmp_path / "host_secret.txt"
    secret.write_text("TOP SECRET, do not exfiltrate", encoding="utf-8")
    root = tmp_path / "proj"
    root.mkdir()
    (root / "app.py").write_text("x = 1\n", encoding="utf-8")
    _symlink_or_skip(root / "leak.txt", secret)

    rels = {f.rel_path for f in Project.from_path(root).files()}
    assert "app.py" in rels
    assert "leak.txt" not in rels  # escape blocked


def test_internal_symlink_is_still_scanned(tmp_path: Path):
    """A symlink that stays inside the project is legitimate and kept."""
    root = tmp_path / "proj"
    root.mkdir()
    (root / "real.py").write_text("y = 2\n", encoding="utf-8")
    _symlink_or_skip(root / "alias.py", root / "real.py")

    rels = {f.rel_path for f in Project.from_path(root).files()}
    assert "real.py" in rels
    assert "alias.py" in rels


def test_fix_engine_refuses_path_traversal(tmp_path: Path):
    """A finding whose path escapes the root must not be written to."""
    root = tmp_path / "proj"
    root.mkdir()
    outside = tmp_path / "escape.py"
    outside.write_text("yaml.load(x)\n", encoding="utf-8")

    project = Project.from_path(root)
    report = apply_fixes(project, [_yaml_load_finding("../escape.py", 1)])

    assert outside.read_text(encoding="utf-8") == "yaml.load(x)\n"  # untouched
    assert not report.any_changes
    assert any("refusing to write" in s for s in report.skipped)


def test_fix_engine_refuses_symlinked_target(tmp_path: Path):
    """A fix must not be written through a symlink that leaves the root."""
    root = tmp_path / "proj"
    root.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("yaml.load(x)\n", encoding="utf-8")
    _symlink_or_skip(root / "m.py", outside)

    project = Project.from_path(root)
    report = apply_fixes(project, [_yaml_load_finding("m.py", 1)])

    assert outside.read_text(encoding="utf-8") == "yaml.load(x)\n"  # untouched
    assert any("refusing to write" in s for s in report.skipped)
