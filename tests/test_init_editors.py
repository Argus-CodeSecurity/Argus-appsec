"""``argus init --editor``: editor MCP and hook config files."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from argus.cli.main import app
from argus.integrations import editors

runner = CliRunner()

EXPECTED = {
    "claude": [".mcp.json", ".claude/settings.json"],
    "cursor": [".cursor/mcp.json", ".cursor/hooks.json", ".cursor/rules/argus.mdc"],
    "vscode": [".vscode/mcp.json", ".vscode/tasks.json"],
}


def _init(tmp_path: Path, *args: str):
    return runner.invoke(app, ["init", "--project-dir", str(tmp_path), *args])


def _load(tmp_path: Path, rel: str) -> dict:
    return json.loads((tmp_path / rel).read_text(encoding="utf-8"))


@pytest.mark.parametrize("editor", sorted(EXPECTED))
def test_writes_the_editor_files(tmp_path: Path, editor: str) -> None:
    res = _init(tmp_path, "--editor", editor)
    assert res.exit_code == 0, res.output
    for rel in EXPECTED[editor]:
        text = (tmp_path / rel).read_text(encoding="utf-8")
        assert text.isascii(), rel  # no dashes or other decorative Unicode
        if rel.endswith(".json"):
            json.loads(text)
    assert not (tmp_path / ".argus.yml").exists()


def test_claude_files(tmp_path: Path) -> None:
    assert _init(tmp_path, "--editor", "claude").exit_code == 0
    server = _load(tmp_path, ".mcp.json")["mcpServers"]["argus"]
    assert server == {"type": "stdio", "command": "argus", "args": ["mcp"], "env": {}}
    groups = _load(tmp_path, ".claude/settings.json")["hooks"]["PostToolUse"]
    assert groups == [
        {
            "matcher": "Edit|Write",
            "hooks": [
                {
                    "type": "command",
                    "command": "argus check --hook claude --no-inline-ignores",
                    "timeout": 30,
                }
            ],
        }
    ]


def test_cursor_files(tmp_path: Path) -> None:
    assert _init(tmp_path, "--editor", "cursor").exit_code == 0
    server = _load(tmp_path, ".cursor/mcp.json")["mcpServers"]["argus"]
    assert server["type"] == "stdio"
    assert server["args"] == ["mcp"]
    assert server["env"] == {"ARGUS_MCP_ROOTS": "${workspaceFolder}"}
    hooks = _load(tmp_path, ".cursor/hooks.json")
    assert hooks["version"] == 1
    assert hooks["hooks"]["afterFileEdit"] == [
        {"command": "argus check --hook cursor --no-inline-ignores", "timeout": 30}
    ]
    rule = (tmp_path / ".cursor/rules/argus.mdc").read_text(encoding="utf-8")
    assert rule.startswith("---\ndescription: ")
    assert "alwaysApply: true\n---\n" in rule
    for tool in ("argus_check_files", "argus_check_snippet", "argus_check_package", "argus_fix"):
        assert tool in rule


def test_vscode_files(tmp_path: Path) -> None:
    assert _init(tmp_path, "--editor", "vscode").exit_code == 0
    mcp = _load(tmp_path, ".vscode/mcp.json")
    assert "mcpServers" not in mcp
    assert mcp["servers"]["argus"]["type"] == "stdio"
    tasks = _load(tmp_path, ".vscode/tasks.json")
    assert tasks["version"] == "2.0.0"
    (task,) = tasks["tasks"]
    assert task["label"] == editors.VSCODE_TASK_LABEL
    assert task["args"][-1] == "${file}"
    assert "hook" in task["args"]
    assert task["problemMatcher"]["fileLocation"] == ["relative", "${workspaceFolder}"]
    from argus.integrations.hookfmt import HOOK_LINE_REGEXP

    assert task["problemMatcher"]["pattern"]["regexp"] == HOOK_LINE_REGEXP


def test_several_editors_at_once(tmp_path: Path) -> None:
    res = _init(tmp_path, "--editor", "claude", "--editor", "vscode")
    assert res.exit_code == 0, res.output
    for rel in EXPECTED["claude"] + EXPECTED["vscode"]:
        assert (tmp_path / rel).exists()


def test_refuses_to_overwrite_and_writes_nothing(tmp_path: Path) -> None:
    (tmp_path / ".claude").mkdir()
    settings = tmp_path / ".claude" / "settings.json"
    settings.write_text('{"model": "x"}\n', encoding="utf-8")
    res = _init(tmp_path, "--editor", "claude")
    assert res.exit_code == 1
    assert "already exists" in res.stderr
    assert settings.read_text(encoding="utf-8") == '{"model": "x"}\n'
    assert not (tmp_path / ".mcp.json").exists()  # all or nothing


def test_force_merges_and_keeps_other_settings(tmp_path: Path) -> None:
    (tmp_path / ".claude").mkdir()
    other_hook = {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo hi"}]}
    (tmp_path / ".claude" / "settings.json").write_text(
        json.dumps({"model": "x", "hooks": {"PostToolUse": [other_hook]}}), encoding="utf-8"
    )
    (tmp_path / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"other": {"command": "o"}}}), encoding="utf-8"
    )
    for _ in range(2):  # re-running replaces the Argus entries instead of adding more
        res = _init(tmp_path, "--editor", "claude", "--force")
        assert res.exit_code == 0, res.output
    settings = _load(tmp_path, ".claude/settings.json")
    assert settings["model"] == "x"
    assert settings["hooks"]["PostToolUse"] == [other_hook, editors.CLAUDE_HOOK_GROUP]
    servers = _load(tmp_path, ".mcp.json")["mcpServers"]
    assert set(servers) == {"other", "argus"}


def test_force_merges_vscode_tasks_and_cursor_hooks(tmp_path: Path) -> None:
    (tmp_path / ".vscode").mkdir()
    (tmp_path / ".vscode" / "tasks.json").write_text(
        json.dumps({"version": "2.0.0", "tasks": [{"label": "build"}]}), encoding="utf-8"
    )
    (tmp_path / ".cursor").mkdir()
    (tmp_path / ".cursor" / "hooks.json").write_text(
        json.dumps({"version": 1, "hooks": {"afterFileEdit": [{"command": "fmt"}]}}),
        encoding="utf-8",
    )
    for _ in range(2):
        res = _init(tmp_path, "--editor", "vscode", "--editor", "cursor", "--force")
        assert res.exit_code == 0, res.output
    labels = [t["label"] for t in _load(tmp_path, ".vscode/tasks.json")["tasks"]]
    assert labels == ["build", editors.VSCODE_TASK_LABEL]
    entries = _load(tmp_path, ".cursor/hooks.json")["hooks"]["afterFileEdit"]
    assert entries == [{"command": "fmt"}, editors.CURSOR_HOOK]


def test_force_refuses_jsonc_it_cannot_merge(tmp_path: Path) -> None:
    (tmp_path / ".vscode").mkdir()
    jsonc = '{\n  // build tasks\n  "version": "2.0.0", "tasks": []\n}\n'
    (tmp_path / ".vscode" / "tasks.json").write_text(jsonc, encoding="utf-8")
    res = _init(tmp_path, "--editor", "vscode", "--force")
    assert res.exit_code == 1
    assert "not plain JSON" in res.stderr
    assert (tmp_path / ".vscode" / "tasks.json").read_text(encoding="utf-8") == jsonc
    assert not (tmp_path / ".vscode" / "mcp.json").exists()


def test_unknown_editor_is_a_usage_error(tmp_path: Path) -> None:
    assert _init(tmp_path, "--editor", "emacs").exit_code == 2


def test_plain_init_still_writes_argus_yml(tmp_path: Path) -> None:
    target = tmp_path / ".argus.yml"
    assert runner.invoke(app, ["init", str(target)]).exit_code == 0
    assert runner.invoke(app, ["init", str(target)]).exit_code == 1
    target.write_text("# mine\n", encoding="utf-8")
    assert runner.invoke(app, ["init", str(target), "--force"]).exit_code == 0
    assert target.read_text(encoding="utf-8") != "# mine\n"
