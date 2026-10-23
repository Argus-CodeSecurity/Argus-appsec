"""Project config templates that ``nephilex init --editor`` writes.

Each editor gets the files that register ``nephilex mcp`` as an MCP server and
run ``nephilex check`` after the agent edits a file. Editor config formats
change, so every template below names the documentation page it was checked
against and the date. Re-check those pages before changing a template.

JSON files are merged rather than replaced when ``--force`` is given: only
Nephilex's own entries (the ``nephilex`` server, the Nephilex hook, the Nephilex task) are
added or replaced, so other settings in the same file survive.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from nephilex.integrations.hookfmt import HOOK_LINE_REGEXP

EDITORS = ("claude", "cursor", "vscode")

#: Every Nephilex hook command starts with this, which is how a re-run finds and
#: replaces the hook it wrote before instead of adding a second one.
_HOOK_PREFIX = "nephilex check"

JSONDict = dict[str, Any]


@dataclass(frozen=True)
class EditorFile:
    """One file ``nephilex init --editor`` writes."""

    path: str  # project-relative, POSIX separators
    content: str  # the file as written when it does not exist yet
    #: For a JSON file: merges Nephilex's entries into existing parsed content.
    merge: Callable[[JSONDict], JSONDict] | None = None


def _json(data: JSONDict) -> str:
    return json.dumps(data, indent=2) + "\n"


# --- shared pieces -----------------------------------------------------------
_SERVER_NAME = "nephilex"


def _merge_server(key: str, server: JSONDict) -> Callable[[JSONDict], JSONDict]:
    def merge(existing: JSONDict) -> JSONDict:
        servers = existing.get(key)
        if not isinstance(servers, dict):
            servers = {}
        servers[_SERVER_NAME] = copy.deepcopy(server)
        existing[key] = servers
        return existing

    return merge


def _is_nephilex_hook(entry: object, command_key: str = "command") -> bool:
    if not isinstance(entry, dict):
        return False
    command = entry.get(command_key)
    return isinstance(command, str) and command.strip().startswith(_HOOK_PREFIX)


# --- Claude Code ---------------------------------------------------------------
# .mcp.json, checked against https://code.claude.com/docs/en/mcp on 2026-10-22:
# project-scoped servers live under "mcpServers" in .mcp.json at the project
# root; a stdio server is {"type": "stdio", "command", "args", "env"}. Claude
# Code asks the user to approve a project-scoped server before first use.
CLAUDE_MCP_SERVER: JSONDict = {"type": "stdio", "command": "nephilex", "args": ["mcp"], "env": {}}

# .claude/settings.json, checked against https://code.claude.com/docs/en/hooks
# on 2026-10-22: hooks.PostToolUse is a list of {"matcher", "hooks"} groups;
# the matcher "Edit|Write" matches either tool exactly; a handler is
# {"type": "command", "command", "timeout"} with the timeout in seconds. With
# no "args" the command runs in shell form (sh, Git Bash or PowerShell). The
# hook gets the event JSON (tool_input.file_path) on stdin; on exit 0 a JSON
# {"decision": "block", "reason"} or hookSpecificOutput.additionalContext is
# shown to Claude next to the tool result. `nephilex check --hook claude` speaks
# exactly that protocol. --no-inline-ignores keeps the agent from silencing a
# finding by adding a nephilex-ignore comment.
CLAUDE_HOOK_COMMAND = "nephilex check --hook claude --no-inline-ignores"
CLAUDE_HOOK_GROUP: JSONDict = {
    "matcher": "Edit|Write",
    "hooks": [{"type": "command", "command": CLAUDE_HOOK_COMMAND, "timeout": 30}],
}


def _merge_claude_settings(existing: JSONDict) -> JSONDict:
    hooks = existing.get("hooks")
    if not isinstance(hooks, dict):
        hooks = {}
    groups = hooks.get("PostToolUse")
    if not isinstance(groups, list):
        groups = []
    kept = []
    for group in groups:
        handlers = group.get("hooks") if isinstance(group, dict) else None
        if isinstance(handlers, list) and any(_is_nephilex_hook(h) for h in handlers):
            continue  # a Nephilex hook from an earlier init: replaced below
        kept.append(group)
    hooks["PostToolUse"] = [*kept, copy.deepcopy(CLAUDE_HOOK_GROUP)]
    existing["hooks"] = hooks
    return existing


# --- Cursor ------------------------------------------------------------------
# .cursor/mcp.json, checked against https://cursor.com/docs/context/mcp on
# 2026-10-22: "mcpServers" with {"type": "stdio", "command", "args", "env"};
# ${workspaceFolder} (the folder holding .cursor/mcp.json) is resolved in
# command, args and env. The docs do not state the server's working
# directory, so NEPHILEX_MCP_ROOTS pins the project root explicitly.
CURSOR_MCP_SERVER: JSONDict = {
    "type": "stdio",
    "command": "nephilex",
    "args": ["mcp"],
    "env": {"NEPHILEX_MCP_ROOTS": "${workspaceFolder}"},
}

# .cursor/hooks.json, checked against https://cursor.com/docs/agent/hooks on
# 2026-10-22: {"version": 1, "hooks": {"afterFileEdit": [{"command", "timeout"}]}};
# project hooks run from the project root and receive {"file_path", "edits",
# "workspace_roots", ...} on stdin. afterFileEdit has no output the agent
# reads, so the rule file below tells the agent to call the MCP tools; the
# hook's findings appear in Cursor's hook output.
CURSOR_HOOK: JSONDict = {
    "command": "nephilex check --hook cursor --no-inline-ignores",
    "timeout": 30,
}


def _merge_cursor_hooks(existing: JSONDict) -> JSONDict:
    existing.setdefault("version", 1)
    hooks = existing.get("hooks")
    if not isinstance(hooks, dict):
        hooks = {}
    entries = hooks.get("afterFileEdit")
    if not isinstance(entries, list):
        entries = []
    hooks["afterFileEdit"] = [
        *(e for e in entries if not _is_nephilex_hook(e)),
        copy.deepcopy(CURSOR_HOOK),
    ]
    existing["hooks"] = hooks
    return existing


# .cursor/rules/nephilex.mdc, checked against https://cursor.com/docs/context/rules
# on 2026-10-22: project rules are .mdc files in .cursor/rules with
# description / globs / alwaysApply front matter; alwaysApply: true is the
# "Always Apply" type.
CURSOR_RULE = """\
---
description: Check new and edited code with the Nephilex security tools
alwaysApply: true
---

# Security checks with Nephilex

This project uses Nephilex (the `nephilex` MCP server) to catch security problems in
code while it is written.

- After you create or edit files, call `nephilex_check_files` with the paths you
  changed. Fix every high or critical finding before you finish, and tell the
  user about any medium finding you leave in place.
- To check code before it is written to disk, call `nephilex_check_snippet` with
  the code and a filename hint.
- Before you add a dependency, call `nephilex_check_package` with its ecosystem,
  name and version. Do not add a package whose verdict is `malicious` or
  `possibly_hallucinated`; explain a `suspicious` or `vulnerable` verdict to
  the user first.
- When a finding has `fix_available: true`, call `nephilex_fix` with its `id` to
  get a verified diff, review it, and apply it yourself.
- Do not silence findings with `nephilex-ignore` comments, `.nephilex.yml` changes
  or baselines unless the user asks you to.
"""


# --- VS Code -------------------------------------------------------------------
# .vscode/mcp.json, checked against
# https://code.visualstudio.com/docs/agents/reference/mcp-configuration (page
# dated 2026-10-21) on 2026-10-22: a top-level "servers" object; a stdio
# server is {"type": "stdio", "command", "args", "env", "envFile", "cwd"},
# cwd defaults to the workspace folder; ${workspaceFolder} is supported.
VSCODE_MCP_SERVER: JSONDict = {
    "type": "stdio",
    "command": "nephilex",
    "args": ["mcp"],
    "cwd": "${workspaceFolder}",
}

# .vscode/tasks.json, checked against https://code.visualstudio.com/docs/debugtest/tasks
# (page dated 2026-10-21) on 2026-10-22: "version": "2.0.0", tasks with label,
# type "process", command, args and a problemMatcher {owner, source,
# fileLocation ["relative", "${workspaceFolder}"], pattern {regexp, file, line,
# column, severity, code, message}}; severity must capture error, warning or
# info, which is the level field of `nephilex check --format hook`.
VSCODE_TASK_LABEL = "Nephilex: check current file"
VSCODE_TASK: JSONDict = {
    "label": VSCODE_TASK_LABEL,
    "type": "process",
    "command": "nephilex",
    "args": ["check", "--root", "${workspaceFolder}", "--format", "hook", "${file}"],
    "problemMatcher": {
        "owner": "nephilex",
        "source": "nephilex",
        "fileLocation": ["relative", "${workspaceFolder}"],
        "pattern": {
            "regexp": HOOK_LINE_REGEXP,
            "file": 1,
            "line": 2,
            "column": 3,
            "severity": 4,
            "code": 6,
            "message": 7,
        },
    },
}


def _merge_vscode_tasks(existing: JSONDict) -> JSONDict:
    existing.setdefault("version", "2.0.0")
    tasks = existing.get("tasks")
    if not isinstance(tasks, list):
        tasks = []
    kept = [t for t in tasks if not (isinstance(t, dict) and t.get("label") == VSCODE_TASK_LABEL)]
    existing["tasks"] = [*kept, copy.deepcopy(VSCODE_TASK)]
    return existing


def files_for(editor: str) -> list[EditorFile]:
    """The files ``nephilex init --editor <editor>`` writes."""
    if editor == "claude":
        return [
            EditorFile(
                ".mcp.json",
                _json({"mcpServers": {_SERVER_NAME: CLAUDE_MCP_SERVER}}),
                _merge_server("mcpServers", CLAUDE_MCP_SERVER),
            ),
            EditorFile(
                ".claude/settings.json",
                _json({"hooks": {"PostToolUse": [CLAUDE_HOOK_GROUP]}}),
                _merge_claude_settings,
            ),
        ]
    if editor == "cursor":
        return [
            EditorFile(
                ".cursor/mcp.json",
                _json({"mcpServers": {_SERVER_NAME: CURSOR_MCP_SERVER}}),
                _merge_server("mcpServers", CURSOR_MCP_SERVER),
            ),
            EditorFile(
                ".cursor/hooks.json",
                _json({"version": 1, "hooks": {"afterFileEdit": [CURSOR_HOOK]}}),
                _merge_cursor_hooks,
            ),
            EditorFile(".cursor/rules/nephilex.mdc", CURSOR_RULE),
        ]
    if editor == "vscode":
        return [
            EditorFile(
                ".vscode/mcp.json",
                _json({"servers": {_SERVER_NAME: VSCODE_MCP_SERVER}}),
                _merge_server("servers", VSCODE_MCP_SERVER),
            ),
            EditorFile(
                ".vscode/tasks.json",
                _json({"version": "2.0.0", "tasks": [VSCODE_TASK]}),
                _merge_vscode_tasks,
            ),
        ]
    raise ValueError(f"unknown editor {editor!r} (choose from: {', '.join(EDITORS)})")


@dataclass(frozen=True)
class Planned:
    """What ``nephilex init --editor`` will do with one file."""

    file: EditorFile
    target: Path
    action: str  # "create", "merge", "overwrite", "exists" or "error"
    text: str = ""  # content to write, for create / merge / overwrite
    problem: str = ""


def plan(project_dir: Path, editors: list[str], *, force: bool) -> list[Planned]:
    """Decide, without writing anything, what each editor file needs."""
    out: list[Planned] = []
    for editor in editors:
        for f in files_for(editor):
            target = project_dir / f.path
            if not target.exists():
                out.append(Planned(f, target, "create", f.content))
            elif not force:
                out.append(Planned(f, target, "exists", problem="already exists"))
            elif target.is_symlink() or not target.is_file():
                out.append(Planned(f, target, "error", problem="is not a regular file"))
            elif f.merge is None:
                out.append(Planned(f, target, "overwrite", f.content))
            else:
                try:
                    existing = json.loads(target.read_text(encoding="utf-8"))
                except (OSError, UnicodeDecodeError, ValueError):
                    out.append(
                        Planned(
                            f,
                            target,
                            "error",
                            problem="is not plain JSON (comments or a syntax error?); "
                            "add the Nephilex entries by hand, see docs/editors.md",
                        )
                    )
                    continue
                if not isinstance(existing, dict):
                    out.append(Planned(f, target, "error", problem="is not a JSON object"))
                    continue
                out.append(Planned(f, target, "merge", _json(f.merge(existing))))
    return out


def write(planned: list[Planned]) -> None:
    """Write every planned create / merge / overwrite."""
    for p in planned:
        if p.action in ("create", "merge", "overwrite"):
            p.target.parent.mkdir(parents=True, exist_ok=True)
            p.target.write_text(p.text, encoding="utf-8", newline="\n")
