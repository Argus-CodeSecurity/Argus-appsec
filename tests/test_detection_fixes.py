"""Regression tests for detection-accuracy fixes.

Each test pins a specific false-positive or under-rating bug that was fixed:

* os.system rule no longer fires on constant commands containing 'f' (df, find).
* --config with a non-existent path errors instead of silently using defaults.
* JS eval/Function sink no longer matches names merely ending in the word.
* toString is not treated as a JS taint sanitizer.
* CVSS vector strings are parsed into a real base score (not defaulted to MEDIUM).
* secret verification maps 403 to UNKNOWN, not INVALID.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from argus.core.config import Config
from argus.core.models import Severity
from argus.core.plugin import ScannerContext, registry
from argus.plugins import register_builtins

register_builtins()


def _run_patterns(tmp_path: Path, rel_path: str, content: str):
    from argus.analysis.repository import RepositoryAnalyzer
    from argus.core.project import Project

    target = tmp_path / rel_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    project = Project.from_path(tmp_path)
    RepositoryAnalyzer().analyze(project)
    cls = registry.get_scanner("patterns")
    return list(cls().scan(ScannerContext(project=project, config=Config(), ai=None)))


def test_os_system_constant_command_not_flagged(tmp_path):
    findings = _run_patterns(tmp_path, "a.py", 'os.system("df -h")\nos.system("find . -name x")\n')
    assert not [f for f in findings if f.rule_id == "patterns.python-os-system"]


def test_os_system_dynamic_command_still_flagged(tmp_path):
    findings = _run_patterns(
        tmp_path,
        "a.py",
        'os.system("ls " + user)\nos.system(f"rm {path}")\nos.system("cmd %s" % arg)\n',
    )
    lines = sorted(
        f.location.start_line for f in findings if f.rule_id == "patterns.python-os-system"
    )
    assert lines == [1, 2, 3]


def test_missing_explicit_config_path_errors():
    with pytest.raises(FileNotFoundError):
        Config.load(path="/tmp/argus-nonexistent-config-xyz.yml")


def test_missing_config_without_explicit_path_uses_defaults():
    # Discovery mode (no explicit path) must still fall back silently.
    assert isinstance(Config.load(), Config)


def test_js_eval_sink_does_not_match_lookalikes():
    from argus.scanners.ast_js import CALL_SINKS

    sink = next(s for s in CALL_SINKS if s.id == "ast-code-injection")
    assert sink.fn.search("eval")
    assert sink.fn.search("window.Function")
    assert not sink.fn.search("retrieval")
    assert not sink.fn.search("myFunction")
    assert not sink.fn.search("medieval")


def test_tostring_is_not_a_js_sanitizer():
    from argus.scanners.ast_js import _SANITIZERS

    assert "toString" not in _SANITIZERS
    assert "encodeURIComponent" in _SANITIZERS  # real ones still present


def test_cvss_vector_string_bands_correctly():
    from argus.scanners.osv import _cvss_band

    # A vector-only 9.8 advisory must band CRITICAL, not default to MEDIUM.
    assert _cvss_band("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == Severity.CRITICAL
    assert _cvss_band("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") == Severity.CRITICAL
    assert _cvss_band("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N") == Severity.LOW
    assert _cvss_band("9.8") == Severity.CRITICAL  # bare number still supported
    assert _cvss_band("not-a-vector") is None


def test_secret_verify_403_is_unknown_not_invalid():
    from argus.scanners import secret_verify as sv

    assert sv._status_verdict(401) == sv.INVALID
    assert sv._status_verdict(403) == sv.UNKNOWN
    assert sv._status_verdict(200) == sv.LIVE
