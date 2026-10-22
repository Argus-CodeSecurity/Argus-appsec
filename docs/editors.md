# Editors and AI assistants

Argus can check code while it is being written, by you or by an AI coding
assistant. There are two pieces, and most setups use both:

- **A hook or task** runs `argus check` on a file right after it is edited.
  It is fast, offline and needs no cooperation from the model.
- **The MCP server** (`argus mcp`) gives the assistant tools it can call
  itself: check files or a snippet, check a dependency before adding it, and
  get a verified fix as a diff. See [MCP server](mcp.md) for the tool
  reference.

`argus init --editor claude|cursor|vscode` writes the project config for
both. It never overwrites an existing file unless you pass `--force`, and
with `--force` it merges the Argus entries into existing JSON files, keeping
your other settings.

## `argus check`

```bash
argus check src/app.py                 # human-readable
argus check src/app.py -f json         # same schema as `argus scan -f json`
argus check src/app.py -f hook         # one line per finding
argus check a.py b.ts --fail-on critical
```

`argus check` scans only the files you name, with only the file-local
scanners: secrets, the SAST patterns, the AST taint tiers (Python,
JavaScript/TypeScript), IaC, LLM/AI usage, malware, and the other built-in
scanners whose findings depend on a single file (CI workflows, Dockerfiles,
cloud config, language rules). Dependency, OSV and cross-file analyses are
left to `argus scan`.

- It reuses the scan cache, so an unchanged file costs almost nothing. It
  does not prune cache entries for other files, so it never slows down the
  next full scan.
- It makes no network calls: secret verification and git-history scanning
  are always off for a check, whatever `.argus.yml` says.
- It does no AI enrichment unless you pass `--ai`.
- It reads `.argus.yml` from the project root like `argus scan`, including
  `exclude_paths`, `scanners`, `exclude_scanners` and `allow` entries.

The project root is the nearest directory at or above the current one that
holds `.git` or `.argus.yml` (or `--root`). A path outside it, a missing
file or a directory is refused with exit status 2. Files inside directories
Argus never scans (`node_modules`, `.git`, `dist`, ...) and files matching
`exclude_paths` are skipped with a note on stderr.

Exit status: 0 when nothing is at or above `--fail-on` (default `high`), 1
when something is or a scanner crashed (set `fail_on_error: false` to ignore
crashes), 2 for usage errors.

### Strict mode for AI assistants

An inline `argus-ignore` comment hides a finding on its line, which is what
a developer wants after reviewing it. An AI assistant that is told about a
finding can add the same comment to make the hook go quiet instead of fixing
the code. `--no-inline-ignores` ignores those comments for the run, so every
finding in the file is reported whatever comments it carries:

```bash
argus check src/app.py --no-inline-ignores
```

The hooks that `argus init --editor claude` and `argus init --editor cursor`
write use it. Suppressions kept outside the source (`allow:` entries in
`.argus.yml` and `.argus/exceptions.yml`) still apply, and a full
`argus scan` still honours inline comments, so a comment a reviewer accepted
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

`argus check --hook claude` and `argus check --hook cursor` read the hook
event the editor writes to stdin, check the edited file, and answer in that
editor's hook protocol. Writes outside the project and deleted files are
ignored silently (exit 0). Problems with Argus itself, such as an invalid
config, exit 1, which both editors treat as a non-blocking hook error.

### Speed

Measured on Windows 11 with Python 3.11, checking one 300-line Python file:
the check itself takes about 75 ms with a warm cache and about 220 ms
without one. The whole `argus check` process takes about 1.2 to 1.4 s on an
idle machine, most of it Python startup and importing Argus (about 1.0 to
1.5 s); under heavy load it was 2 to 2.5 s.

## Claude Code

```bash
argus init --editor claude
```

This writes two files.

`.mcp.json` registers the MCP server for the project:

```json
{
  "mcpServers": {
    "argus": {
      "type": "stdio",
      "command": "argus",
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
            "command": "argus check --hook claude --no-inline-ignores",
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
an `argus-ignore` comment (see [Strict mode](#strict-mode-for-ai-assistants)).

To gate on a different severity, edit the command, for example
`argus check --hook claude --no-inline-ignores --fail-on medium`.

Claude Code asks you to approve a project MCP server from `.mcp.json` the
first time; approve `argus`.

### Verify in 5 minutes

1. Run `argus --version` in the project directory. If it fails, the hook and
   server cannot start either; see [Troubleshooting](#troubleshooting).
2. Start Claude Code in the project and approve the `argus` server. Run
   `/mcp` and check that `argus` is connected with five tools.
3. Run `/hooks` and check that a PostToolUse hook with matcher `Edit|Write`
   runs `argus check --hook claude --no-inline-ignores`.
4. Ask: "Create demo_argus.py with a function that loads YAML using
   yaml.load". After the write, Claude should mention the Argus finding
   (`patterns.python-yaml-load`) and switch to `yaml.safe_load` on its own.
5. Ask: "Call argus_check_files on demo_argus.py, then argus_fix on the
   finding". It should get a diff back and say it was not applied.
6. Ask: "Use argus_check_package to check the npm package lodahs". The
   verdict should be `suspicious` (it resembles `lodash`).
7. Delete `demo_argus.py`.

## Cursor

```bash
argus init --editor cursor
```

This writes three files.

`.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "argus": {
      "type": "stdio",
      "command": "argus",
      "args": ["mcp"],
      "env": {"ARGUS_MCP_ROOTS": "${workspaceFolder}"}
    }
  }
}
```

`ARGUS_MCP_ROOTS` pins the project root, because Cursor's documentation does
not say which directory it starts the server in.

`.cursor/hooks.json`:

```json
{
  "version": 1,
  "hooks": {
    "afterFileEdit": [
      {"command": "argus check --hook cursor --no-inline-ignores", "timeout": 30}
    ]
  }
}
```

Cursor's `afterFileEdit` hook has no output the agent reads, so the hook
writes its findings to stderr (Cursor's Hooks output channel is the
documented place to debug hooks; its documentation does not say whether hook
stderr is shown there), and the agent is told to use the MCP tools by a
project rule:

`.cursor/rules/argus.mdc` is an Always Apply rule that tells the agent to call
`argus_check_files` after it writes code, `argus_check_package` before adding
a dependency, `argus_fix` for verified fixes, and not to silence findings
with `argus-ignore` comments. Edit it to suit your team.

### Verify in 5 minutes

1. Run `argus --version` in the project directory.
2. Open the project in Cursor. In Cursor Settings, under MCP, check that the
   `argus` server is enabled and lists five tools.
3. In Cursor Settings, under Rules, check that `argus` is listed as a project
   rule that always applies.
4. In the Agent, ask: "Create demo_argus.py with a function that loads YAML
   using yaml.load". The agent should call `argus_check_files` afterwards
   (shown as a tool call) and fix the finding.
5. Open the Output panel, choose the Hooks channel, and check that the
   `afterFileEdit` hook ran without errors. If your Cursor version shows hook
   stderr there, the `patterns.python-yaml-load` line appears too.
6. Ask the agent to check the npm package `lodahs` with Argus; the verdict
   should be `suspicious`.
7. Delete `demo_argus.py`.

## VS Code

```bash
argus init --editor vscode
```

This writes two files.

`.vscode/mcp.json` (VS Code uses a top-level `servers` key):

```json
{
  "servers": {
    "argus": {
      "type": "stdio",
      "command": "argus",
      "args": ["mcp"],
      "cwd": "${workspaceFolder}"
    }
  }
}
```

`.vscode/tasks.json` adds an "Argus: check current file" task that runs
`argus check --format hook` on the active file. Its problem matcher turns
each finding into an entry in the Problems panel:

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "Argus: check current file",
      "type": "process",
      "command": "argus",
      "args": ["check", "--root", "${workspaceFolder}", "--format", "hook", "${file}"],
      "problemMatcher": {
        "owner": "argus",
        "source": "argus",
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

`argus init` cannot merge into a `tasks.json` that contains comments (VS Code
allows them). In that case it stops without writing anything; copy the task
above into your file by hand.

### Verify in 5 minutes

1. Run `argus --version` in the integrated terminal.
2. Open `.vscode/mcp.json`; VS Code shows a Start action above the `argus`
   server. Start it and check that it reports five tools.
3. In the Chat view, switch to Agent mode, open the tools picker and check
   that the `argus` tools are listed.
4. Create `demo_argus.py` containing `import yaml` and
   `data = yaml.load(open("x"))`. Run Terminal, Run Task, "Argus: check
   current file". The Problems panel should show an error on line 2 with
   code `patterns.python-yaml-load`.
5. In Agent mode, ask: "Call argus_check_files on demo_argus.py, then
   argus_fix on the finding". Approve the tool calls; the reply should
   include a diff that was not applied.
6. Delete `demo_argus.py`.

## Other MCP clients

Windsurf, Cline, Continue, Zed, Gemini CLI, Codex CLI and other MCP clients
can run Argus as a stdio server. Their config file formats differ and Argus
has not verified them, so register it through the client's own MCP settings
with:

- command: `argus`
- arguments: `mcp`
- transport: stdio
- optional environment: `ARGUS_MCP_ROOTS=<your project directory>` if the
  client does not start servers in the project directory.

Many clients accept the common `mcpServers` shape:

```json
{"mcpServers": {"argus": {"command": "argus", "args": ["mcp"]}}}
```

### Verify in 5 minutes

1. Run `argus --version` in the project directory.
2. Register the server as above and restart the client.
3. Check that the client lists the five `argus_*` tools.
4. Ask the assistant to call `argus_check_snippet` with
   `import yaml\nyaml.load(s)` and language `python`. It should report
   `patterns.python-yaml-load` on line 2.
5. Ask it to call `argus_fix` with that finding's `id`; it should return a
   diff using `yaml.safe_load` and say it was not applied.

## Troubleshooting

- **`argus` is not found by the editor.** Editors started from a desktop
  launcher may not see the shell `PATH` of a virtual environment. Use the
  absolute path to the `argus` executable (for example
  `/path/to/venv/bin/argus` or `C:\path\to\venv\Scripts\argus.exe`) as the
  command in the generated files.
- **The MCP tools refuse a path as outside the allowed roots.** The server
  only reads files under the directory it was started in, or under
  `ARGUS_MCP_ROOTS`. Set `ARGUS_MCP_ROOTS` to the project directory in the
  server's `env`.
- **No network.** Set `ARGUS_MCP_OFFLINE=1` in the server's `env` to keep
  `argus_check_package` offline. The other tools never use the network.

## Formats verified

Editor config formats change. Each generated file was checked against the
official documentation on 2026-10-22; the template source in
`src/argus/integrations/editors.py` records the same pages.

| File | Documentation |
| --- | --- |
| `.mcp.json` | <https://code.claude.com/docs/en/mcp> |
| `.claude/settings.json` hooks | <https://code.claude.com/docs/en/hooks> |
| `.cursor/mcp.json` | <https://cursor.com/docs/context/mcp> |
| `.cursor/hooks.json` | <https://cursor.com/docs/agent/hooks> |
| `.cursor/rules/argus.mdc` | <https://cursor.com/docs/context/rules> |
| `.vscode/mcp.json` | <https://code.visualstudio.com/docs/agents/reference/mcp-configuration> |
| `.vscode/tasks.json` | <https://code.visualstudio.com/docs/debugtest/tasks> |
