# LLM / AI-application security

Codebases now embed LLM calls, agent frameworks, MCP servers and model loading,
and that surface has its own vulnerability classes that generic SAST does not
cover. Nephilex ships two scanners for it, with every finding mapped to an id in
the [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/)
and to a CWE:

| Scanner | Reads | Needs |
|---------|-------|-------|
| `llm` | Python and JS/TS files that touch an LLM or agent stack (OpenAI, Anthropic, LangChain, LlamaIndex, LiteLLM, Ollama, Google GenAI, CrewAI, AutoGen, MCP SDKs, transformers) | The data-flow rules need the `[ast]` extra (`pip install "nephilex[ast]"`); the line rules always run |
| `agent-config` | MCP and agent configuration files (`.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `claude_desktop_config.json`, `.claude/settings.json`, Windsurf `mcp_config.json`, Cline, Roo Code, Gemini CLI) | Nothing extra |

Every finding carries `owasp` and `metadata.owasp_llm` (for example
`LLM05:2025-Improper Output Handling`) and the tags `ai-security` plus `llm`,
`agent` and/or `mcp`, so the JSON and SARIF output can be filtered or routed by
category.

```bash
nephilex scan ./my-ai-app --scanners llm,agent-config
```

## Rules

| Rule | OWASP LLM | CWE | What it flags |
|------|-----------|-----|---------------|
| `llm.insecure-output-handling` | LLM05 | 78, 95, 89, 73/22, 918, 79, 1336, 502 | A model response reaching a shell, `eval`/`exec`, SQL, a file write/delete path, an outbound URL, unescaped HTML, a template compiler or an unsafe deserializer |
| `llm.tool-handler-exec` | LLM06 | 78, 95 | An agent tool whose handler passes its (model-chosen) argument to a shell or `eval` |
| `llm.agent-shell-tool` | LLM06 | 78, 250 | `ShellTool`, `PythonREPLTool`, `PythonAstREPLTool`, `load_tools(["terminal"])` given to an agent |
| `llm.agent-file-write-tool` | LLM06 | 732, 73 | `FileManagementToolkit` (or `WriteFileTool` and friends) exposing write/delete/move |
| `llm.agent-requests-tool` | LLM06 | 918 | `RequestsToolkit` / `Requests*Tool` enabled with `allow_dangerous_requests=True` |
| `llm.agent-sql-write-tool` | LLM06 | 89, 250 | `SQLDatabaseToolkit` / `create_sql_agent` with no read-only scoping in the file |
| `llm.agent-code-execution` | LLM06 | 94, 250 | AutoGen `use_docker: False` or `LocalCommandLineCodeExecutor`; CrewAI `code_execution_mode="unsafe"` |
| `llm.untrusted-input-in-system-prompt` | LLM01 | 77, 74 | Request input, file contents, retrieved documents or HTTP responses flowing into a system prompt |
| `llm.secret-in-system-prompt` | LLM07 | 798, 200 | A credential in system-prompt text |
| `llm.internal-url-in-system-prompt` | LLM07 | 200 | A private IP, `localhost` or `*.internal`-style host in system-prompt text |
| `llm.prompt-injection` | LLM01 | 74 | Request input concatenated into a prompt string (line rule) |
| `llm.secret-in-prompt` | LLM02 | 522, 200 | A credential in prompt text (line rule) |
| `llm.unrestricted-tool-registration` | LLM06 | 732 | `allow_dangerous_*=True` / `dangerous_tools=True` opt-in flags (line rule) |
| `llm.trust-remote-code` | LLM03 | 494, 829 | `trust_remote_code=True` |
| `llm.torch-load-pickle` | LLM03 | 502 | `torch.load` without `weights_only=True` |
| `llm.model-download-http` | LLM03 | 319, 494 | Model weights fetched over plaintext HTTP |
| `agent-config.mcp-hardcoded-secret` | LLM02 | 798 | A literal credential in an MCP server's `env`, `headers` or `args` |
| `agent-config.mcp-unpinned-package` | LLM03 | 1357, 829 | A server started with `npx`/`bunx`/`pnpm dlx`/`uvx`/`pipx run`/`docker run` on an unpinned package or image |
| `agent-config.mcp-plaintext-http` | LLM03 | 319 | A remote MCP server over `http://` (loopback excluded) |
| `agent-config.mcp-broad-filesystem-root` | LLM06 | 732, 552 | A filesystem server (or Claude Code `additionalDirectories`) granted `/`, a drive root or a home directory |
| `agent-config.agent-auto-approve` | LLM06 | 862 | Tools that run without confirmation: Cline `autoApprove`, Roo Code `alwaysAllow`, Gemini CLI `trust: true`, Claude Code `enableAllProjectMcpServers`, a bare `Bash` allow rule, `bypassPermissions` |

### `llm.insecure-output-handling` (LLM05 Improper Output Handling)

Model output is attacker-influenceable: anyone who can put text in front of the
model (a chat message, a web page, a retrieved document) can steer what it
returns. A prompt injection upstream becomes command execution, SQL injection,
SSRF or XSS at the sink.

```python
llm = ChatOpenAI()
sql = llm.invoke(f"Write SQL for: {question}").content
conn.execute(sql)  # flagged: CWE-89
```

**Fix.** Have the model choose parameters, not code: bind them into fixed,
parameterized queries, map choices onto fixed argv lists, pin URL hosts in code,
escape before HTML. If text-to-SQL is the product, run it on a read-only,
row-scoped role.

Sources are recognized only when the receiver really is an LLM object, resolved
through the file's imports (`client = OpenAI()`, `llm = ChatOpenAI()`,
`chain = prompt | llm`, `index.as_query_engine()`, `litellm.completion`,
`ollama.chat`, `genai.Client().models.generate_content`, Vercel AI SDK
`generateText`), so `model.predict(X)` on a scikit-learn model or a Twilio
`client.messages.create` is not a source. Provider metadata (`.id`, `.usage`,
`.finish_reason`) is not model text.

What clears a value, and only for the sink it protects:

* numeric or boolean coercion (`int()`, `float()`, `len()`, `Number()`);
* `shlex.quote` for shells, `html.escape` / `bleach.clean` / `DOMPurify.sanitize`
  for HTML, `os.path.basename` / `secure_filename` for paths;
* a URL whose scheme and host are literal (`f"https://api.example.com/{slug}"`);
* Pydantic validation that pins the field (`Literal`, an `Enum`, `int`, a
  `pattern=`). A plain `str` field stays tainted: the schema did not constrain
  it. A schema defined outside the file cannot be inspected and is trusted;
* an allowlist check (`if cmd not in ALLOWED: raise`, `if host in HOSTS:`,
  `re.fullmatch`, `is_relative_to`, `ALLOWED.includes(x)`). A blocklist
  (`if "rm" in cmd`) does not clear anything, and checking one property
  (`block.type == "tool_use"`) does not clear the rest of the object.

`json.loads` does not clear anything: the parsed dict is still model text.

### `llm.tool-handler-exec` (LLM06 Excessive Agency)

Tool-call arguments are model output. A tool (LangChain `@tool`, MCP
`@mcp.tool()`, OpenAI Agents `@function_tool`, `Tool(func=...)`,
`StructuredTool.from_function`, a dispatch dict of handlers) that shells out or
evals its argument gives the agent unbounded capability.

```python
@mcp.tool()
def calculate(expression: str) -> str:
    return str(eval(expression))  # flagged: CWE-95
```

**Fix.** Give the tool a narrow, typed interface (`Literal` or `Enum`
parameters, which this rule treats as safe), never pass arguments through a
shell or `eval`, and require confirmation for side effects.

### Agent tools: `agent-shell-tool`, `agent-file-write-tool`, `agent-requests-tool`, `agent-sql-write-tool`, `agent-code-execution` (LLM06)

Each finding names the tool, the agent it is wired into (or says no wiring was
found in the file), and what makes it excessive.

```python
tools = FileManagementToolkit().get_tools()  # flagged: all write/delete tools, no root_dir
agent = create_react_agent(llm, tools, prompt)

runner = autogen.UserProxyAgent(
    "runner", code_execution_config={"use_docker": False}
)  # flagged: host execution
```

Not flagged: `FileManagementToolkit(selected_tools=["read_file"])`,
`RequestsToolkit` without `allow_dangerous_requests` (LangChain refuses to build
it), AutoGen with `use_docker: True` or `code_execution_config=False`, CrewAI's
default safe (Docker) mode, and a SQL connection with visible read-only scoping
(`mode=ro`, `postgresql_readonly`). A human-approval guard in the same file
(`HumanApprovalCallbackHandler`, LangGraph `interrupt_before` / `interrupt_on`,
`HumanInTheLoopMiddleware`) suppresses the tool rules.

**Fix.** Replace broad tools with narrow ones that each do one operation, confine
file tools with `root_dir` and `selected_tools`, run generated code in a sandbox
(Docker executor, E2B, Modal), connect SQL agents with a read-only role, and
keep destructive tools behind human approval. `agent-sql-write-tool` is reported
with LOW confidence because privileges cannot be seen in code.

### `llm.untrusted-input-in-system-prompt` (LLM01 Prompt Injection)

```python
docs = store.similarity_search(q)
context = "\n".join(d.page_content for d in docs)
messages = [{"role": "system", "content": "Answer using: " + context}]  # flagged
```

System prompts are `{"role": "system" | "developer"}` messages, LangChain
`SystemMessage` and `("system", ...)` tuples, Anthropic `system=`, OpenAI
`instructions=`, `system_prompt=` / `system_message=` / `system_instruction=`
arguments, and variables named like `SYSTEM_PROMPT`. Sources are request
parameters (including FastAPI/Flask route parameters), file reads, vector-store
retrieval, document loaders and HTTP responses.

**Fix.** Keep the system prompt static; pass untrusted data in a delimited
user-role message and constrain what the model may do with it.

### `llm.secret-in-system-prompt` and `llm.internal-url-in-system-prompt` (LLM07 System Prompt Leakage)

```python
SYSTEM_PROMPT = (
    "You are support. Admin password: Sup3rS3cret99. Billing: http://billing.internal/api"
)
```

System prompts are routinely extracted, so anything in them is effectively
public. Secrets are matched with the secrets scanner's signatures plus provider
key formats and `password: <value>` prose; the snippet is always redacted.

**Fix.** Keep credentials and internal endpoints in server-side code or tools,
never in text the model can repeat; rotate any exposed credential.

### Line rules (`prompt-injection`, `secret-in-prompt`, `unrestricted-tool-registration`, `trust-remote-code`, `torch-load-pickle`, `model-download-http`)

Well-known signatures that need no data flow. `trust_remote_code=True`,
`torch.load` without `weights_only=True` and plaintext model downloads are
**LLM03 Supply Chain**. Where a data-flow rule reports the same line, the line
rule is dropped. Without tree-sitter, a regex pass stands in for
`insecure-output-handling` and the `agent-shell-tool` line rule for the agent
analysis.

### `agent-config.mcp-hardcoded-secret` (LLM02 Sensitive Information Disclosure)

```json
{"mcpServers": {"brave": {"command": "node", "args": ["index.js"],
  "env": {"BRAVE_API_KEY": "BSAq8Zx3LmN7pQ2rT5vW9yK1"}}}}
```

Literal values in `env`, `headers` and `--flag value` arguments are checked with
the secrets scanner's signatures and, for secret-named keys, an entropy test;
`${VAR}`, `${env:VAR}`, `${input:id}` and placeholders are not secrets. The
value is redacted in every snippet. When the secrets scanner also matches the
line, the engine reports it once.

**Fix.** Rotate, then reference the value: `${VAR}` in `.mcp.json`,
`${env:VAR}` in Cursor and Windsurf, `${input:id}` with `password: true` in VS
Code, or an `envFile` kept out of version control.

### `agent-config.mcp-unpinned-package` (LLM03 Supply Chain)

```json
{"mcpServers": {"github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"]}}}
```

An unpinned spec is resolved at every start, so a compromised or typosquatted
release runs with the developer's privileges and feeds tool descriptions to the
model. `npx -y` additionally skips the install prompt. Exact versions
(`pkg@1.2.3`, `uvx pkg==1.2.3`, `uvx --from 'pkg==1.2.3' cmd`), local paths, git
specs and image digests are not flagged; `@latest`, ranges and bare names are.

**Fix.** Pin exact versions (or an image digest), or install the server as a
locked dependency.

### `agent-config.mcp-plaintext-http` (LLM03 Supply Chain)

A remote server over `http://` exposes auth headers and lets anyone on the path
rewrite tool descriptions and results, which is prompt injection by another
route. Loopback addresses are not flagged. **Fix.** Use `https://`.

### `agent-config.mcp-broad-filesystem-root` (LLM06 Excessive Agency)

```json
{"mcpServers": {"fs": {"command": "npx",
  "args": ["-y", "@modelcontextprotocol/server-filesystem@2025.8.21", "/"]}}}
```

Also checks docker `--mount` / `-v` sources for the filesystem image and Claude
Code `permissions.additionalDirectories`. Root and drive roots are HIGH, home
directories MEDIUM. **Fix.** Grant only the project or a dedicated workspace.

### `agent-config.agent-auto-approve` (LLM06 Excessive Agency)

```json
{"permissions": {"allow": ["Bash"]}}
```

Confirmation prompts are the last check between a prompt injection and a side
effect. Flagged: non-empty Cline `autoApprove` and Roo Code `alwaysAllow`,
Gemini CLI `trust: true`, Claude Code `enableAllProjectMcpServers: true`, a bare
`Bash`/`Bash(*)`/`PowerShell` allow rule, and `defaultMode: "bypassPermissions"`
(LOW: Claude Code v2.1.257 and later ignore it in project files). Scoped rules
such as `Bash(npm run test *)` are not flagged. **Fix.** Remove auto-approval or
limit it to read-only tools.

## Scope and honesty

The data-flow tier is intra-file and per function (nested JS functions see their
enclosing scope). A value that crosses a module boundary, or a prompt built in
one file and sent from another, is not traced. Pydantic models defined in other
files are trusted rather than guessed at, which favors precision over recall.
The configuration rules read only the files listed above, by their documented
key names. Treat findings as high-value leads and a clean result as "no known
LLM or agent anti-patterns found", not a proof of safety.

The labeled corpus in `benchmarks/accuracy.py` has a vulnerable and a safe case
for each data-flow and configuration rule, and CI fails if any is misclassified.
