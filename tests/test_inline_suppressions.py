"""Inline suppression comments: `# argus-ignore: <rule> reason="..."`.

A team must be able to accept a specific finding on a specific line, with a
documented reason, and optionally have that acceptance expire. These pin the
semantics: reason is required, the rule id scopes it, and `until=` resurfaces the
finding once it passes.
"""

from __future__ import annotations

from argus.core.config import Config
from argus.core.engine import ScanEngine
from argus.core.project import Project

_SHELL = 'import subprocess\nsubprocess.run("x", shell=True)  {comment}\n'


def _scan(tmp_path, comment: str):
    (tmp_path / "app.py").write_text(_SHELL.format(comment=comment), encoding="utf-8")
    cfg = Config(scanner_options={"dependencies": {"online": False}},
                 trust_project_config=True)
    return ScanEngine(cfg).scan(Project.from_path(tmp_path))


def _has_shell_finding(result) -> bool:
    return any("shell-true" in f.rule_id for f in result.findings)


def test_baseline_without_comment_reports_it(tmp_path):
    assert _has_shell_finding(_scan(tmp_path, ""))


def test_suppress_by_rule_id(tmp_path):
    assert not _has_shell_finding(
        _scan(tmp_path, '# argus-ignore: python-shell-true reason="trusted internal input"'))


def test_reason_is_required(tmp_path):
    # No reason string -> the comment is not a valid suppression.
    assert _has_shell_finding(_scan(tmp_path, "# argus-ignore: python-shell-true"))


def test_wildcard_suppresses_whole_line(tmp_path):
    assert not _has_shell_finding(_scan(tmp_path, '# argus-ignore reason="reviewed by security"'))


def test_wrong_rule_does_not_suppress(tmp_path):
    assert _has_shell_finding(
        _scan(tmp_path, '# argus-ignore: some-other-rule reason="unrelated"'))


def test_future_until_suppresses(tmp_path):
    assert not _has_shell_finding(
        _scan(tmp_path, '# argus-ignore: python-shell-true reason="temp" until=2099-01-01'))


def test_expired_until_resurfaces(tmp_path):
    assert _has_shell_finding(
        _scan(tmp_path, '# argus-ignore: python-shell-true reason="temp" until=2000-01-01'))
