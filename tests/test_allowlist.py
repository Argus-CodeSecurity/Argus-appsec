"""Committed allowlist (config ``allow:``): accept findings outside the source."""

from __future__ import annotations

from argus.core.config import Config
from argus.core.engine import ScanEngine
from argus.core.project import Project

_CODE = 'import subprocess\nsubprocess.run("x", shell=True)\n'


def _scan(tmp_path, allow):
    (tmp_path / "deploy.py").write_text(_CODE, encoding="utf-8")
    cfg = Config(scanner_options={"dependencies": {"online": False}}, allow=allow)
    return ScanEngine(cfg).scan(Project.from_path(tmp_path))


def _has_shell(result) -> bool:
    return any("shell-true" in f.rule_id for f in result.findings)


def test_config_loads_allow_from_dict():
    cfg = Config.from_dict({"allow": [{"rule": "x", "reason": "y"}]})
    assert cfg.allow == [{"rule": "x", "reason": "y"}]


def test_no_allowlist_reports(tmp_path):
    assert _has_shell(_scan(tmp_path, []))


def test_allow_by_rule_and_path(tmp_path):
    assert not _has_shell(
        _scan(tmp_path, [{"rule": "python-shell-true", "path": "deploy.py", "reason": "trusted"}])
    )


def test_allow_requires_reason(tmp_path):
    assert _has_shell(_scan(tmp_path, [{"rule": "python-shell-true", "path": "deploy.py"}]))


def test_allow_wrong_path_does_not_match(tmp_path):
    assert _has_shell(
        _scan(tmp_path, [{"rule": "python-shell-true", "path": "other.py", "reason": "x"}])
    )


def test_allow_path_glob(tmp_path):
    assert not _has_shell(
        _scan(tmp_path, [{"rule": "python-shell-true", "path": "*.py", "reason": "x"}])
    )


def test_allow_expired_resurfaces(tmp_path):
    assert _has_shell(
        _scan(
            tmp_path,
            [
                {
                    "rule": "python-shell-true",
                    "path": "deploy.py",
                    "reason": "x",
                    "until": "2000-01-01",
                }
            ],
        )
    )


def test_allow_future_until_suppresses(tmp_path):
    assert not _has_shell(
        _scan(
            tmp_path,
            [
                {
                    "rule": "python-shell-true",
                    "path": "deploy.py",
                    "reason": "x",
                    "until": "2099-01-01",
                }
            ],
        )
    )


def test_allow_entry_matching_everything_is_rejected(tmp_path):
    # No rule and no path would suppress the whole scan; such an entry is ignored.
    assert _has_shell(_scan(tmp_path, [{"reason": "x"}]))
