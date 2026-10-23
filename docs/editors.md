# Editors and AI assistants

Nephilex can check code while it is being written, by you or by an AI coding
assistant. There are two pieces, and most setups use both:

- **A hook or task** runs `nephilex check` on a file right after it is edited.
  It is fast, offline and needs no cooperation from the model.
- **The MCP server** (`nephilex mcp`) gives the assistant tools it can call
  itself: check files or a snippet, check a dependency before adding it, and
  get a verified fix as a diff. See [MCP server](mcp.md) for the tool
  reference.

`nephilex init --editor claude|cursor|vscode` writes the project config for
both. It never overwrites an existing file unless you pass `--force`, and
with `--force` it merges the Nephilex entries into existing JSON files, keeping
your other settings.

## `nephilex check`

```bash
nephilex check src/app.py                 # human-readable
nephilex check src/app.py -f json         # same schema as `nephilex scan -f json`
nephilex check src/app.py -f hook         # one line per finding
nephilex check a.py b.ts --fail-on critical
```

`nephilex check` scans only the files you name, with only the file-local
scanners: secrets, the SAST patterns, the AST taint tiers (Python,
JavaScript/TypeScript), IaC, LLM/AI usage, malware, and the other built-in
scanners whose findings depend on a single file (CI workflows, Dockerfiles,
cloud config, language rules). Dependency, OSV and cross-file analyses are
left to `nephilex scan`.

- It reuses the scan cache, so an unchanged file costs almost nothing. It
  does not prune cache entries for other files, so it never slows down the
  next full scan.
- It makes no network calls: secret verification and git-history scanning
  are always off for a check, whatever `.nephilex.yml` says.
- It does no AI enrichment unless you pass `--ai`.
- It reads `.nephilex.yml` from the project root like `nephilex scan`, including
  `exclude_paths`, `scanners`, `exclude_scanners` and `allow` entries.

The project root is the nearest directory at or above the current one that
holds `.git` or `.nephilex.yml` (or `--root`). A path outside it, a missing
file or a directory is refused with exit status 2. Files inside directories
Nephilex never scans (`node_modules`, `.git`, `dist`, ...) and files matching
`exclude_paths` are skipped with a note on stderr.

Exit status: 0 when nothing is at or above `--fail-on` (default `high`), 1
when something is or a scanner crashed (set `fail_on_error: false` to ignore
crashes), 2 for usage errors.

### Strict mode for AI assistants

An inline `nephilex-ignore` comment hides a finding on its line, which is what
a developer wants after reviewing it. An AI assistant that is told about a
finding can add the same comment to make the hook go quiet instead of fixing
the code. `--no-inline-ignores` ignores those comments for the run, so every
finding in the file is reported whatever comments it carries:

```bash
nephilex check src/app.py --no-inline-ignores
```

The hooks that `nephilex init --editor claude` and `nephilex init --editor cursor`
write use it. Suppressions kept outside the source (`allow:` entries in
`.nephilex.yml` and `.nephilex/exceptions.yml`) still apply, and a full
`nephilex scan` still honours inline comments, so a comment a reviewer accepted
keeps working in CI. Put those files under `CODEOWNERS` if an assistant
must not change them either.

### The hook format

```text
src/app.py:12:5: error high patterns.python-yaml-load: Unsafe yaml.load without SafeLoader. Fix: Use yaml.safe_load, or yaml.load(..., Loader=yaml.SafeLoader).
```

That is `path:line:column: level severity rule-id: title. Fix: hint`. The
path is relative to the project root. `level` is `error` for critical and
high, `warning` for medium and `info` for low and info, so an editor problem
matcher can use it. Clean files print nothing.

### Editor hook mode

`nephilex check --hook claude` and `nephilex check --hook cursor` read the hook
event the editor writes to stdin, check the edited file, and answer in that
editor's hook protocol. Writes outside the project and deleted files are
ignored silently (exit 0). Problems with Nephilex itself, such as an invalid
config, exit 1, which both editors treat as a non-blocking hook error.

### Speed

Measured on Windows 11 with Python 3.11, checking one 300-line Python file:
the check itself takes about 75 ms with a warm cache and about 220 ms
without one. The whole `nephilex check` process takes about 0.7 to 0.9 s,
most of it Python startup and importing Nephilex; under heavy load it is
slower. `nephilex check` does not import the report formats, the AI provider
clients or their HTTP library unless it needs them (`-f json` loads the JSON
reporter, `--ai` the provider).

## Claude Code

```bash
nephilex init --editor claude
```

This writes two files.

`.mcp.json` registers the MCP server for the project:

```json
{
  "mcpServers": {
    "nephilex": {
      "type": "stdio",
      "command": "nephilex",
      "args": ["mcp"],
      "env": {}
    }
  }
}
```

`.claude/settings.json` adds a PostToolUse hook that runs after the Edit and
Write tools:

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Edit|Write",
        "hooks": [
          {
            "type": "command",
            "command": "nephilex check --hook claude --no-inline-ignores",
            "timeout": 30
          }
        ]
      }
    ]
  }
}
```

The hook reads `tool_input.file_path` from the event. When the file has
findings at or above `--fail-on` (default high), it answers with
`{"decision": "block", "reason": "..."}`: the edit has already happened,
and Claude Code shows the reason, one hook-format line per finding, to
Claude next to the tool result so it fixes the code. Lower findings are
passed as `additionalContext` instead. A clean file produces no output.
`--no-inline-ignores` makes the hook report findings even where Claude added
a `nephilex-ignore` comment (see [Strict mode](#strict-mode-for-ai-assistants)).

To gate on a different severity, edit the command, for example
`nephilex check --hook claude --no-inline-ignores --fail-on medium`.

Claude Code asks you to approve a project MCP server from `.mcp.json` the
first time; approve `nephilex`.

### Verify in 5 minutes

1. Run `nephilex --version` in the project directory. If it fails, the hook and
   server cannot start either; see [Troubleshooting](#troubleshooting).
2. Start Claude Code in the project and approve the `nephilex` server. Run
   `/mcp` and check that `nephilex` is connected with five tools.
3. Run `/hooks` and check that a PostToolUse hook with matcher `Edit|Write`
   runs `nephilex check --hook claude --no-inline-ignores`.
4. Ask: "Create demo_nephilex.py with a function that loads YAML using
   yaml.load". After the write, Claude should mention the Nephilex finding
   (`patterns.python-yaml-load`) and switch to `yaml.safe_load` on its own.
5. Ask: "Call nephilex_check_files on demo_nephilex.py, then nephilex_fix on the
   finding". It should get a diff back and say it was not applied.
6. Ask: "Use nephilex_check_package to check the npm package lodahs". The
   verdict should be `suspicious` (it resembles `lodash`).
7. Delete `demo_nephilex.py`.

## Cursor

```bash
nephilex init --editor cursor
```

This writes three files.

`.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "nephilex": {
      "type": "stdio",
      "command": "nephilex",
      "args": ["mcp"],
      "env": {"NEPHILEX_MCP_ROOTS": "${workspaceFolder}"}
    }
  }
}
```

`NEPHILEX_MCP_ROOTS` pins the project root, because Cursor's documentation does
not say which directory it starts the server in.

`.cursor/hooks.json`:

```json
{
  "version": 1,
  "hooks": {
    "afterFileEdit": [
      {"command": "nephilex check --hook cursor --no-inline-ignores", "timeout": 30}
    ]
  }
}
```

Cursor's `afterFileEdit` hook has no output the agent reads, so the hook
writes its findings to stderr (Cursor's Hooks output channel is the
documented place to debug hooks; its documentation does not say whether hook
stderr is shown there), and the agent is told to use the MCP tools by a
project rule:

`.cursor/rules/nephilex.mdc` is an Always Apply rule that tells the agent to call
`nephilex_check_files` after it writes code, `nephilex_check_package` before adding
a dependency, `nephilex_fix` for verified fixes, and not to silence findings
with `nephilex-ignore` comments. Edit it to suit your team.

### Verify in 5 minutes

1. Run `nephilex --version` in the project directory.
2. Open the project in Cursor. In Cursor Settings, under MCP, check that the
   `nephilex` server is enabled and lists five tools.
3. In Cursor Settings, under Rules, check that `nephilex` is listed as a project
   rule that always applies.
4. In the Agent, ask: "Create demo_nephilex.py with a function that loads YAML
   using yaml.load". The agent should call `nephilex_check_files` afterwards
   (shown as a tool call) and fix the finding.
5. Open the Output panel, choose the Hooks channel, and check that the
   `afterFileEdit` hook ran without errors. If your Cursor version shows hook
   stderr there, the `patterns.python-yaml-load` line appears too.
6. Ask the agent to check the npm package `lodahs` with Nephilex; the verdict
   should be `suspicious`.
7. Delete `demo_nephilex.py`.

## VS Code

```bash
nephilex init --editor vscode
```

This writes two files.

`.vscode/mcp.json` (VS Code uses a top-level `servers` key):

```json
{
  "servers": {
    "nephilex": {
      "type": "stdio",
      "command": "nephilex",
      "args": ["mcp"],
      "cwd": "${workspaceFolder}"
    }
  }
}
```

`.vscode/tasks.json` adds a "Nephilex: check current file" task that runs
`nephilex check --format hook` on the active file. Its problem matcher turns
each finding into an entry in the Problems panel:

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "Nephilex: check current file",
      "type": "process",
      "command": "nephilex",
      "args": ["check", "--root", "${workspaceFolder}", "--format", "hook", "${file}"],
      "problemMatcher": {
        "owner": "nephilex",
        "source": "nephilex",
        "fileLocation": ["relative", "${workspaceFolder}"],
        "pattern": {
          "regexp": "^(.+?):(\\d+):(\\d+): (error|warning|info) (\\S+) (\\S+): (.*)$",
          "file": 1,
          "line": 2,
          "column": 3,
          "severity": 4,
          "code": 6,
          "message": 7
        }
      }
    }
  ]
}
```

The task exits 1 when it finds something at or above `high`, so VS Code
reports the task as failed; the findings are in the Problems panel either
way.

`nephilex init` cannot merge into a `tasks.json` that contains comments (VS Code
allows them). In that case it stops without writing anything; copy the task
above into your file by hand.

### Verify in 5 minutes

1. Run `nephilex --version` in the integrated terminal.
2. Open `.vscode/mcp.json`; VS Code shows a Start action above the `nephilex`
   server. Start it and check that it reports five tools.
3. In the Chat view, switch to Agent mode, open the tools picker and check
   that the `nephilex` tools are listed.
4. Create `demo_nephilex.py` containing `import yaml` and
   `data = yaml.load(open("x"))`. Run Terminal, Run Task, "Nephilex: check
   current file". The Problems panel should show an error on line 2 with
   code `patterns.python-yaml-load`.
5. In Agent mode, ask: "Call nephilex_check_files on demo_nephilex.py, then
   nephilex_fix on the finding". Approve the tool calls; the reply should
   include a diff that was not applied.
6. Delete `demo_nephilex.py`.

## Other MCP clients

Windsurf, Cline, Continue, Zed, Gemini CLI, Codex CLI and other MCP clients
can run Nephilex as a stdio server. Their config file formats differ and Nephilex
has not verified them, so register it through the client's own MCP settings
with:

- command: `nephilex`
- arguments: `mcp`
- transport: stdio
- optional environment: `NEPHILEX_MCP_ROOTS=<your project directory>` if the
  client does not start servers in the project directory.

Many clients accept the common `mcpServers` shape:

```json
{"mcpServers": {"nephilex": {"command": "nephilex", "args": ["mcp"]}}}
```

### Verify in 5 minutes

1. Run `nephilex --version` in the project directory.
2. Register the server as above and restart the client.
3. Check that the client lists the five `nephilex_*` tools.
4. Ask the assistant to call `nephilex_check_snippet` with
   `import yaml\nyaml.load(s)` and language `python`. It should report
   `patterns.python-yaml-load` on line 2.
5. Ask it to call `nephilex_fix` with that finding's `id`; it should return a
   diff using `yaml.safe_load` and say it was not applied.

## Troubleshooting

- **`nephilex` is not found by the editor.** Editors started from a desktop
  launcher may not see the shell `PATH` of a virtual environment. Use the
  absolute path to the `nephilex` executable (for example
  `/path/to/venv/bin/nephilex` or `C:\path\to\venv\Scripts\nephilex.exe`) as the
  command in the generated files.
- **The MCP tools refuse a path as outside the allowed roots.** The server
  only reads files under the directory it was started in, or under
  `NEPHILEX_MCP_ROOTS`. Set `NEPHILEX_MCP_ROOTS` to the project directory in the
  server's `env`.
- **No network.** Set `NEPHILEX_MCP_OFFLINE=1` in the server's `env` to keep
  `nephilex_check_package` offline. The other tools never use the network.

## Formats verified

Editor config formats change. Each generated file was checked against the
official documentation on 2026-10-22; the template source in
`src/nephilex/integrations/editors.py` records the same pages.

| File | Documentation |
| --- | --- |
| `.mcp.json` | <https://code.claude.com/docs/en/mcp> |
| `.claude/settings.json` hooks | <https://code.claude.com/docs/en/hooks> |
| `.cursor/mcp.json` | <https://cursor.com/docs/context/mcp> |
| `.cursor/hooks.json` | <https://cursor.com/docs/agent/hooks> |
| `.cursor/rules/nephilex.mdc` | <https://cursor.com/docs/context/rules> |
| `.vscode/mcp.json` | <https://code.visualstudio.com/docs/agents/reference/mcp-configuration> |
| `.vscode/tasks.json` | <https://code.visualstudio.com/docs/debugtest/tasks> |
