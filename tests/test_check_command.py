"""``nephilex check``: the fast, file-level check editors and AI hooks run."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from nephilex.cli.main import app
from nephilex.core.config import Config
from nephilex.core.plugin import registry
from nephilex.integrations import filecheck
from nephilex.integrations.hookfmt import HOOK_LINE_REGEXP

runner = CliRunner()

VULN = "import yaml\n\n\ndef load(raw):\n    return yaml.load(raw)\n"
SECRET = 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n'
CLEAN = "def add(a, b):\n    return a + b\n"


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "proj"
    (root / ".git").mkdir(parents=True)
    (root / "app.py").write_text(VULN, encoding="utf-8")
    (root / "clean.py").write_text(CLEAN, encoding="utf-8")
    (root / "src").mkdir()
    (root / "src" / "keys.py").write_text(SECRET, encoding="utf-8")
    monkeypatch.chdir(root)
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    return root


def test_text_output_reports_and_gates(project: Path) -> None:
    res = runner.invoke(app, ["check", "app.py"])
    assert res.exit_code == 1, res.output
    assert "patterns.python-yaml-load" in res.stdout
    assert "Fix:" in res.stdout


def test_clean_file_passes(project: Path) -> None:
    res = runner.invoke(app, ["check", "clean.py"])
    assert res.exit_code == 0, res.output
    assert "No findings in 1 file." in res.stdout


def test_fail_on_threshold(project: Path) -> None:
    # yaml.load is high; a critical threshold lets it through.
    assert runner.invoke(app, ["check", "app.py", "--fail-on", "critical"]).exit_code == 0
    assert runner.invoke(app, ["check", "src/keys.py", "--fail-on", "critical"]).exit_code == 1


def test_json_output_is_the_scan_schema(project: Path) -> None:
    res = runner.invoke(app, ["check", "app.py", "src/keys.py", "-f", "json"])
    assert res.exit_code == 1, res.output
    doc = json.loads(res.stdout)
    assert {"target", "findings", "scanners_run", "project_summary", "errors"} <= set(doc)
    rules = {f["rule_id"] for f in doc["findings"]}
    assert {"patterns.python-yaml-load", "secrets.aws-access-key-id"} <= rules
    assert doc["project_summary"]["check"]["files"] == ["app.py", "src/keys.py"]
    assert set(doc["scanners_run"]) <= set(filecheck.file_local_scanners())


def test_hook_format_matches_the_problem_matcher_regexp(project: Path) -> None:
    res = runner.invoke(app, ["check", "app.py", "-f", "hook"])
    assert res.exit_code == 1
    pattern = re.compile(HOOK_LINE_REGEXP)
    lines = res.stdout.strip().splitlines()
    assert lines
    for line in lines:
        m = pattern.match(line)
        assert m, line
        assert m.group(1) == "app.py"
        assert m.group(4) in {"error", "warning", "info"}
    assert any(
        "patterns.python-yaml-load" in line and ":5:" in line and "Fix: " in line for line in lines
    )
    assert all(line.isascii() for line in lines)


def test_hook_format_is_silent_when_clean(project: Path) -> None:
    res = runner.invoke(app, ["check", "clean.py", "-f", "hook"])
    assert res.exit_code == 0
    assert res.stdout == ""


@pytest.mark.parametrize(
    "path",
    [
        lambda root: str(root.parent / "outside.py"),
        lambda root: "../outside.py",
        lambda root: "missing.py",
        lambda root: "src",
    ],
)
def test_unusable_paths_are_usage_errors(project: Path, path) -> None:
    (project.parent / "outside.py").write_text(VULN, encoding="utf-8")
    res = runner.invoke(app, ["check", path(project)])
    assert res.exit_code == 2, res.output
    assert "Error:" in res.stderr


def test_symlink_out_of_the_project_is_refused(project: Path) -> None:
    (project.parent / "outside.py").write_text(VULN, encoding="utf-8")
    link = project / "link.py"
    try:
        link.symlink_to(project.parent / "outside.py")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not available")
    assert runner.invoke(app, ["check", "link.py"]).exit_code == 2


def test_usage_errors(project: Path) -> None:
    assert runner.invoke(app, ["check"]).exit_code == 2
    assert runner.invoke(app, ["check", "app.py", "-f", "sarif"]).exit_code == 2
    assert runner.invoke(app, ["check", "app.py", "--fail-on", "hgih"]).exit_code == 2
    assert runner.invoke(app, ["check", "app.py", "--root", "nope"]).exit_code == 2


def test_ignored_directories_are_skipped_not_errors(project: Path) -> None:
    (project / "node_modules").mkdir()
    (project / "node_modules" / "x.py").write_text(VULN, encoding="utf-8")
    res = runner.invoke(app, ["check", "node_modules/x.py"])
    assert res.exit_code == 0, res.output
    assert "Skipping" in res.stderr


def test_exclude_paths_from_config_are_honoured(project: Path) -> None:
    (project / ".nephilex.yml").write_text('exclude_paths: ["app.py"]\n', encoding="utf-8")
    assert runner.invoke(app, ["check", "app.py"]).exit_code == 0


def test_root_option_and_subdirectory_cwd(project: Path, monkeypatch) -> None:
    monkeypatch.chdir(project / "src")
    # The project root is found by walking up to .git, so ../app.py is inside.
    assert runner.invoke(app, ["check", "../app.py"]).exit_code == 1
    # An explicit --root narrows the project: app.py is then outside it.
    res = runner.invoke(app, ["check", "--root", ".", "../app.py"])
    assert res.exit_code == 2


def test_only_file_local_scanners_run() -> None:
    cfg = filecheck.check_config(Config())
    assert cfg.scanners == filecheck.file_local_scanners()
    for name in cfg.scanners:
        assert registry.scanners()[name].file_local
    for expected in ("secrets", "patterns", "ast-python", "ast-js", "iac", "llm", "malware"):
        assert expected in cfg.scanners
    assert "dependencies" not in cfg.scanners
    assert cfg.ai.enabled is False


def test_check_config_honours_selection_and_drops_network_options() -> None:
    base = Config(scanners=["secrets", "dependencies", "patterns"], exclude_scanners=["patterns"])
    base.scanner_options = {"secrets": {"verify": True, "history": True, "entropy": False}}
    cfg = filecheck.check_config(base)
    assert cfg.scanners == ["secrets"]
    assert cfg.scanner_options["secrets"] == {"entropy": False}
    # The caller's config is not modified.
    assert base.scanner_options["secrets"]["verify"] is True


def test_check_config_with_nothing_left_is_a_config_error() -> None:
    from nephilex.core.config import ConfigError

    with pytest.raises(ConfigError):
        filecheck.check_config(Config(scanners=["dependencies"]))


def test_check_keeps_cache_entries_of_other_files(project: Path) -> None:
    from nephilex import __version__
    from nephilex.core.cache import ScanCache
    from nephilex.core.engine import ScanEngine
    from nephilex.core.project import Project

    ScanEngine(Config()).scan(Project.from_path(project))
    before = ScanCache(project.resolve(), __version__)._entries["secrets@" + _opts_key()]
    assert any(k.startswith("src/keys.py@") for k in before)

    assert runner.invoke(app, ["check", "app.py"]).exit_code == 1
    after = ScanCache(project.resolve(), __version__)._entries["secrets@" + _opts_key()]
    assert any(k.startswith("src/keys.py@") for k in after)
    assert any(k.startswith("app.py@") for k in after)


def _opts_key() -> str:
    from nephilex.core.cache import scanner_key

    return scanner_key("secrets", {}).split("@", 1)[1]


# --- editor hook protocols -----------------------------------------------------
def _claude_event(path: str) -> str:
    return json.dumps(
        {
            "session_id": "abc123",
            "hook_event_name": "PostToolUse",
            "tool_name": "Write",
            "tool_input": {"file_path": path, "content": "..."},
            "tool_response": {"filePath": path, "type": "create"},
        }
    )


def test_claude_hook_blocks_with_reason(project: Path, monkeypatch) -> None:
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(project))
    res = runner.invoke(
        app, ["check", "--hook", "claude"], input=_claude_event(str(project / "app.py"))
    )
    assert res.exit_code == 0, res.output
    answer = json.loads(res.stdout)
    assert answer["decision"] == "block"
    assert "patterns.python-yaml-load" in answer["reason"]
    assert "app.py:5:" in answer["reason"]


def test_claude_hook_lower_severity_is_context_only(project: Path, monkeypatch) -> None:
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(project))
    res = runner.invoke(
        app,
        ["check", "--hook", "claude", "--fail-on", "critical"],
        input=_claude_event(str(project / "app.py")),
    )
    assert res.exit_code == 0
    answer = json.loads(res.stdout)
    assert "decision" not in answer
    ctx = answer["hookSpecificOutput"]
    assert ctx["hookEventName"] == "PostToolUse"
    assert "patterns.python-yaml-load" in ctx["additionalContext"]


@pytest.mark.parametrize("name", ["clean.py", "../outside.py", "gone.py"])
def test_claude_hook_is_silent_for_clean_outside_or_missing(project: Path, name: str) -> None:
    (project.parent / "outside.py").write_text(VULN, encoding="utf-8")
    res = runner.invoke(
        app, ["check", "--hook", "claude"], input=_claude_event(str(project / name))
    )
    assert res.exit_code == 0, res.output
    assert res.stdout == ""


def test_claude_hook_bad_event_is_a_non_blocking_error(project: Path) -> None:
    res = runner.invoke(app, ["check", "--hook", "claude"], input="not json")
    assert res.exit_code == 1
    res = runner.invoke(app, ["check", "--hook", "claude"], input="[1, 2]")
    assert res.exit_code == 1
    # An event without a file path (another tool) is simply ignored.
    res = runner.invoke(app, ["check", "--hook", "claude"], input='{"tool_name": "Bash"}')
    assert res.exit_code == 0
    assert res.stdout == ""


def test_claude_hook_config_error_is_exit_1_not_2(project: Path, monkeypatch) -> None:
    (project / ".nephilex.yml").write_text("scanners: [dependencies]\n", encoding="utf-8")
    res = runner.invoke(
        app, ["check", "--hook", "claude"], input=_claude_event(str(project / "app.py"))
    )
    assert res.exit_code == 1


def test_cursor_hook_reports_on_stderr(project: Path) -> None:
    event = {
        "hook_event_name": "afterFileEdit",
        "file_path": str(project / "app.py"),
        "edits": [{"old_string": "a", "new_string": "b"}],
        "workspace_roots": [str(project)],
    }
    res = runner.invoke(app, ["check", "--hook", "cursor"], input=json.dumps(event))
    assert res.exit_code == 0, res.output
    assert res.stdout.strip() == "{}"
    assert "patterns.python-yaml-load" in res.stderr


def test_unknown_hook_editor_is_a_usage_error(project: Path) -> None:
    assert runner.invoke(app, ["check", "--hook", "vim"], input="{}").exit_code == 2


# --- strict mode: --no-inline-ignores ------------------------------------------------
SILENCED = (
    "import yaml\n\n\ndef load(raw):\n"
    '    return yaml.load(raw)  # nephilex-ignore: python-yaml-load reason="trust me"\n'
)


def test_inline_ignore_hides_a_finding_by_default(project: Path) -> None:
    (project / "app.py").write_text(SILENCED, encoding="utf-8")
    res = runner.invoke(app, ["check", "app.py"])
    assert res.exit_code == 0, res.output
    assert "No findings" in res.stdout


def test_no_inline_ignores_reports_silenced_findings(project: Path) -> None:
    (project / "app.py").write_text(SILENCED, encoding="utf-8")
    res = runner.invoke(app, ["check", "app.py", "--no-inline-ignores", "-f", "hook"])
    assert res.exit_code == 1, res.output
    assert "patterns.python-yaml-load" in res.stdout
    # Nothing was suppressed, so nothing is recorded as suppressed either.
    assert not (project / ".nephilex" / "audit.log").exists()


def test_claude_hook_with_no_inline_ignores_still_blocks(project: Path, monkeypatch) -> None:
    (project / "app.py").write_text(SILENCED, encoding="utf-8")
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(project))
    event = _claude_event(str(project / "app.py"))
    quiet = runner.invoke(app, ["check", "--hook", "claude"], input=event)
    assert quiet.exit_code == 0 and quiet.stdout == ""
    strict = runner.invoke(app, ["check", "--hook", "claude", "--no-inline-ignores"], input=event)
    assert strict.exit_code == 0, strict.output
    assert json.loads(strict.stdout)["decision"] == "block"


def test_inline_ignores_is_not_a_config_file_key() -> None:
    # A config file in the tree must not be able to switch strict mode off or on.
    assert Config.from_dict({"inline_ignores": False}).inline_ignores is True
