# MCP server (for AI agents)

A fast-growing share of code is written with AI coding agents. If the agent runs a
security scan right after it generates code, the vulnerability is caught before it
is ever committed. Argus ships a built-in [Model Context
Protocol](https://modelcontextprotocol.io) server so any MCP-capable agent can
call it as a tool.

It is self-contained (no extra dependency), speaks JSON-RPC over stdio, and is
read-only: the scan never modifies your files.

## Run it

```bash
argus mcp
```

That starts the server on stdin/stdout. You normally do not run it by hand; you
point an MCP client at it.

## Connect an agent

Most MCP clients take a small JSON config. Register Argus as a server:

```json
{
  "mcpServers": {
    "argus": {
      "command": "argus",
      "args": ["mcp"]
    }
  }
}
```

Once connected, the agent sees one tool:

| Tool | Arguments | Returns |
| --- | --- | --- |
| `argus_scan` | `path` (required), `min_severity` (optional: info/low/medium/high/critical) | A structured summary plus a list of findings, each with rule id, severity, CWE/OWASP, location, and remediation. |

A typical agent instruction is simply: *"After you write code, call `argus_scan`
on the project directory and fix anything critical or high before finishing."*

## What comes back

The tool returns JSON so the agent can act on it programmatically:

```json
{
  "target": "/path/to/project",
  "summary": {
    "total_findings": 7,
    "returned": 7,
    "truncated": false,
    "by_severity": {"critical": 1, "high": 2, "medium": 3, "low": 1},
    "risk_score": 68
  },
  "findings": [
    {
      "rule_id": "llm.insecure-output-handling",
      "scanner": "llm",
      "severity": "high",
      "title": "Insecure handling of LLM output",
      "location": "agent.py:42",
      "cwe": ["CWE-95"],
      "owasp": ["LLM02:2025-Insecure Output Handling"],
      "remediation": "Validate, parse, or escape model output before a sensitive sink."
    }
  ]
}
```

Findings are capped per call (the `summary` always reports the true `total_findings`
and whether the list was `truncated`, so coverage is never silently hidden).

## Notes

- **Read-only.** The `argus_scan` tool only reads the path you give it.
- **Confined to your project.** Paths must be inside the directory the server
  was started in, or inside one of the directories listed in `ARGUS_MCP_ROOTS`
  (separated by `;` on Windows and `:` elsewhere). This stops a
  prompt-injected agent from scanning your home directory.
- **Untrusted by default.** Rules and suppressions shipped inside the scanned
  directory (`.argus/rules`, `argus-ignore` comments) are not honoured, since
  the agent may have just cloned it.
- **Bounded.** A scan stops after `ARGUS_MCP_SCAN_TIMEOUT` seconds (default
  600).
- **Local paths only.** It does not clone remote repositories from an agent call.
- **Offline by default**, like the rest of Argus, so an agent can scan without a
  network round-trip (dependency CVE lookups still use the network when enabled).
