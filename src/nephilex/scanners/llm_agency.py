"""Agent tool permissions (OWASP LLM06 Excessive Agency), Python.

Finds agents handed tools whose capability is far wider than any task needs,
with no human-approval guard in the file, and says which tool, which agent it
is wired into, and what makes it excessive:

* ``agent-shell-tool``: LangChain ``ShellTool`` / ``PythonREPLTool`` /
  ``PythonAstREPLTool`` (or ``load_tools(["terminal"])``): arbitrary command or
  code execution.
* ``agent-file-write-tool``: ``FileManagementToolkit`` exposing
  ``write_file`` / ``file_delete`` / ``move_file`` / ``copy_file`` (all of them
  unless ``selected_tools`` narrows it), or those tools directly.
* ``agent-requests-tool``: ``RequestsToolkit`` / ``Requests*Tool`` /
  ``load_tools(["requests_*"])`` enabled with ``allow_dangerous_requests`` or
  ``allow_dangerous_tools``: model-chosen URLs (SSRF) and, for the toolkit,
  POST/PUT/PATCH/DELETE.
* ``agent-sql-write-tool``: ``SQLDatabaseToolkit`` / ``create_sql_agent`` /
  ``QuerySQLDatabaseTool`` over a connection with no read-only scoping visible
  in the file: the model writes and runs arbitrary SQL.
* ``agent-code-execution``: AutoGen ``code_execution_config`` with
  ``"use_docker": False`` or a ``LocalCommandLineCodeExecutor``, and CrewAI
  ``allow_code_execution=True`` with ``code_execution_mode="unsafe"``: model
  code runs on the host instead of a sandbox.

Tool handlers that pass their own arguments to a shell or ``eval`` are found
by the data-flow pass (rule ``tool-handler-exec`` in
:mod:`nephilex.scanners.llm_taint`).

A human-approval guard in the same file (LangChain
``HumanApprovalCallbackHandler``, LangGraph ``interrupt_before`` /
``interrupt_on`` / ``HumanInTheLoopMiddleware``) suppresses the tool rules:
every call is then confirmed by a person, which is the documented mitigation.
"""

from __future__ import annotations

import re
from typing import Any

from nephilex.core.models import Confidence, Finding, Severity
from nephilex.scanners.llm_ast import (
    LLM06,
    Src,
    call_args,
    end_line_of,
    import_aliases,
    is_false,
    is_llm_qualname,
    is_true,
    line_of,
    make_finding,
    qualify,
    string_value,
    walk,
)

_SHELL_TOOLS = {"ShellTool", "PythonREPLTool", "PythonAstREPLTool", "BashProcess"}
_FILE_WRITE_TOOLS = {"WriteFileTool", "DeleteFileTool", "MoveFileTool", "CopyFileTool"}
# Tool names exposed by FileManagementToolkit (langchain_community
# agent_toolkits/file_management/toolkit.py); the write-capable ones.
_FILE_WRITE_NAMES = {"write_file", "file_delete", "move_file", "copy_file"}
_REQUESTS_TOOLS = {
    "RequestsToolkit",
    "RequestsGetTool",
    "RequestsPostTool",
    "RequestsPatchTool",
    "RequestsPutTool",
    "RequestsDeleteTool",
}
_SQL_TOOLS = {
    "SQLDatabaseToolkit",
    "create_sql_agent",
    "QuerySQLDataBaseTool",
    "QuerySQLDatabaseTool",
}
_AGENT_CALLEE = re.compile(
    r"(?:^|\.)(?:initialize_agent|create_\w*agent|AgentExecutor|Agent|AssistantAgent|"
    r"ConversableAgent|UserProxyAgent|CodeExecutorAgent|Crew|ToolNode|bind_tools|"
    r"ReActAgent|FunctionAgent|CodeAgent|ToolCallingAgent|from_tools)$"
)
_HUMAN_GUARD = re.compile(
    r"\bHumanApprovalCallbackHandler\b|\binterrupt_before\s*=|\binterrupt_on\s*=|"
    r"\bHumanInTheLoopMiddleware\b"
)
_READONLY_HINT = re.compile(
    r"(?i)mode=ro\b|\breadonly\b|read_only|default_transaction_read_only|"
    r"postgresql_readonly|ApplicationIntent=ReadOnly|\?immutable=1"
)


class _Agency:
    def __init__(self, data: bytes, root, path: str, in_test: bool) -> None:
        self.src = Src(data)
        self.root = root
        self.path = path
        self.in_test = in_test
        self.aliases = import_aliases(root, self.src)
        self.text = data.decode("utf-8", "ignore")
        self.findings: list[Finding] = []
        self.calls = [n for n in walk(root) if n.type == "call"]

    # --- helpers ---------------------------------------------------------------
    def _q(self, call) -> str:
        fn = call.child_by_field_name("function")
        return qualify(self.src.text(fn), self.aliases) if fn is not None else ""

    def _from_stack(self, q: str) -> bool:
        return is_llm_qualname(q)

    def _binding(self, call) -> str | None:
        """Name a call's value is assigned to, if any.

        Climbs through method chains, so ``files = Toolkit().get_tools()``
        binds the toolkit's tools to ``files``.
        """
        parent = call.parent
        while parent is not None and parent.type in (
            "parenthesized_expression",
            "attribute",
            "call",
            "await",
        ):
            parent = parent.parent
        if parent is not None and parent.type == "assignment":
            left = parent.child_by_field_name("left")
            if left is not None and left.type in ("identifier", "attribute"):
                return self.src.text(left)
        return None

    def _agent_for(self, call) -> str | None:
        """The agent this tool (call or the name it is bound to) is wired into."""
        names = {self._binding(call)} - {None}
        # One level of list indirection: tools = [ShellTool()]; Agent(tools=tools).
        holder = call.parent
        while holder is not None and holder.type in ("list", "tuple", "parenthesized_expression"):
            holder = holder.parent
        if holder is not None and holder.type == "assignment":
            left = holder.child_by_field_name("left")
            if left is not None:
                names.add(self.src.text(left))
        for other in self.calls:
            if other is call:
                continue
            q = self._q(other)
            if not _AGENT_CALLEE.search(q):
                continue
            args = other.child_by_field_name("arguments")
            if args is None:
                continue
            inside = args.start_byte <= call.start_byte and call.end_byte <= args.end_byte
            mentions = any(
                n.type in ("identifier", "attribute") and self.src.text(n) in names
                for n in walk(args)
            )
            if inside or mentions:
                bound = self._binding(other)
                label = q.rsplit(".", 1)[-1]
                return f"'{bound}' ({label})" if bound else label
        return None

    def _report(
        self,
        call,
        rule: str,
        tool: str,
        title: str,
        excessive: str,
        severity: Severity,
        confidence: Confidence,
        cwe: list[str],
        fix: str,
        attack: str,
        *,
        is_agent: bool = False,
    ) -> None:
        line = line_of(call)
        if is_agent:
            bound = self._binding(call)
            agent: str | None = f"'{bound}'" if bound else tool.split("(", 1)[0]
            description = f"Agent {agent} is configured with {tool}. {excessive}"
        else:
            agent = self._agent_for(call)
            where = (
                f"wired into agent {agent}"
                if agent
                else "created in this file (no agent wiring found)"
            )
            description = f"Tool {tool} is {where}. {excessive}"
        self.findings.append(
            make_finding(
                rule=rule,
                key=tool,
                title=title,
                description=description,
                path=self.path,
                line=line,
                end_line=end_line_of(call),
                columns=self.src.columns(call),
                snippet=self.src.line_text(line),
                severity=severity,
                confidence=confidence,
                cwe=cwe,
                owasp_llm=LLM06,
                why="An agent can do whatever its tools allow, and what it decides to do is "
                "steerable by any text it reads. " + excessive,
                attack=attack,
                impact="A single prompt injection (a crafted web page, document, email or "
                "chat message) turns into the full capability of this tool.",
                fix=fix,
                tags=["llm", "agent"],
                metadata={
                    "tool": tool,
                    "agent": agent,
                    "excessive": excessive,
                    "end_line": int(call.end_point[0]) + 1,
                },
                in_test=self.in_test,
            )
        )

    # --- rules -----------------------------------------------------------------
    def run(self) -> list[Finding]:
        guarded = bool(_HUMAN_GUARD.search(self.text))
        for call in self.calls:
            q = self._q(call)
            last = q.rsplit(".", 1)[-1]
            pos, kw = call_args(call)
            if not guarded and self._from_stack(q):
                if last in _SHELL_TOOLS:
                    self._shell(call, last)
                elif last == "load_tools":
                    self._load_tools(call, pos, kw)
                elif last == "FileManagementToolkit":
                    self._file_toolkit(call, kw)
                elif last in _FILE_WRITE_TOOLS:
                    self._file_tool(call, last, kw)
                elif last in _REQUESTS_TOOLS:
                    self._requests(call, last, kw)
                elif last in _SQL_TOOLS:
                    self._sql(call, last, pos, kw)
            if self._from_stack(q) or last == "LocalCommandLineCodeExecutor":
                self._code_execution(call, q, last, pos, kw)
        return self.findings

    def _shell(self, call, tool: str) -> None:
        what = (
            "executes arbitrary Python in the agent's process"
            if "Python" in tool
            else "runs arbitrary shell commands"
        )
        self._report(
            call,
            "agent-shell-tool",
            tool,
            f"Agent given {tool}, which {what}",
            f"{tool} {what}, with the agent's OS privileges and no allowlist or confirmation step.",
            Severity.HIGH,
            Confidence.HIGH,
            ["CWE-78", "CWE-250"],
            "Replace the shell / REPL tool with narrow tools that each do one fixed "
            "operation. If code execution is the product, run it in an isolated sandbox "
            "(container or microVM with no credentials) and require human approval "
            "(HumanApprovalCallbackHandler or a LangGraph interrupt) per call.",
            "Plant an instruction to download and run a script in content the agent reads; the agent "
            "calls the tool and the host runs it.",
        )

    def _load_tools(self, call, pos: list[Any], kw: dict[str, Any]) -> None:
        names_node = kw.get("tool_names") or (pos[0] if pos else None)
        if names_node is None or names_node.type not in ("list", "tuple"):
            return
        names = {string_value(n, self.src) for n in names_node.named_children} - {None}
        if "terminal" in names:
            self._shell(call, 'load_tools(["terminal"])')
        req = sorted(n for n in names if n and n.startswith("requests"))
        if req and is_true(kw.get("allow_dangerous_tools"), self.src):
            self._report_requests(
                call, f"load_tools({req})", writes=any(n != "requests_get" for n in req)
            )

    def _file_toolkit(self, call, kw: dict[str, Any]) -> None:
        selected = kw.get("selected_tools")
        if selected is not None:
            if selected.type not in ("list", "tuple"):
                return  # computed selection: cannot tell, do not guess
            names = {string_value(n, self.src) for n in selected.named_children} - {None}
            writes = sorted(n for n in names if n in _FILE_WRITE_NAMES)
            if not writes:
                return
            exposed = ", ".join(writes)
        else:
            exposed = "all of copy_file, file_delete, move_file, write_file"
        root = kw.get("root_dir")
        scope = (
            "with no root_dir, so paths are not confined to a directory"
            if root is None
            else "inside root_dir"
        )
        self._report(
            call,
            "agent-file-write-tool",
            "FileManagementToolkit",
            "Agent given file write/delete tools",
            f"It exposes {exposed} {scope}; the model can overwrite or delete files.",
            Severity.HIGH if root is None else Severity.MEDIUM,
            Confidence.HIGH,
            ["CWE-732", "CWE-73"],
            "Pass selected_tools with only the read operations the task needs, set "
            "root_dir to a dedicated scratch directory, and run the agent under an OS "
            "user that cannot write elsewhere.",
            "Inject 'delete the project files' or 'overwrite ~/.bashrc' into content the "
            "agent reads.",
        )

    def _file_tool(self, call, tool: str, kw: dict[str, Any]) -> None:
        root = kw.get("root_dir")
        self._report(
            call,
            "agent-file-write-tool",
            tool,
            f"Agent given {tool}",
            f"{tool} lets the model write, move or delete files"
            + (" anywhere the process can reach (no root_dir)." if root is None else "."),
            Severity.HIGH if root is None else Severity.MEDIUM,
            Confidence.HIGH,
            ["CWE-732", "CWE-73"],
            "Drop write/delete tools unless the task needs them; confine them with "
            "root_dir and require approval for destructive operations.",
            "Inject an instruction to overwrite configuration or delete data.",
        )

    def _requests(self, call, tool: str, kw: dict[str, Any]) -> None:
        if not is_true(kw.get("allow_dangerous_requests"), self.src):
            return  # LangChain refuses to build these tools without the opt-in
        self._report_requests(call, tool, writes=tool != "RequestsGetTool")

    def _report_requests(self, call, tool: str, *, writes: bool) -> None:
        excessive = "The model chooses any URL, including internal and cloud-metadata addresses" + (
            ", and can send POST/PUT/PATCH/DELETE requests." if writes else "."
        )
        self._report(
            call,
            "agent-requests-tool",
            tool,
            "Agent given arbitrary-URL HTTP request tools",
            excessive,
            Severity.HIGH if writes else Severity.MEDIUM,
            Confidence.HIGH,
            ["CWE-918"],
            "Wrap the one API the agent needs in a dedicated tool with the base URL fixed "
            "in code, allowlist hosts, block private and link-local ranges at the network "
            "layer, and expose GET only unless writes are essential.",
            "Have the agent fetch http://169.254.169.254/latest/meta-data/ or POST to an "
            "internal admin API.",
        )

    def _sql(self, call, tool: str, pos: list[Any], kw: dict[str, Any]) -> None:
        if _READONLY_HINT.search(self.text):
            return
        self._report(
            call,
            "agent-sql-write-tool",
            tool,
            "SQL agent tool over a connection with no read-only scoping",
            "The model writes and executes arbitrary SQL, and nothing in this file "
            "restricts the connection to read-only, so INSERT/UPDATE/DELETE/DROP run "
            "with the connection's full privileges.",
            Severity.MEDIUM,
            Confidence.LOW,
            ["CWE-89", "CWE-250"],
            "Connect the agent with a read-only database role limited to the tables it "
            "needs (or a read-only replica / SQLite mode=ro), and keep write operations "
            "behind dedicated, parameterized tools.",
            "Inject 'run DROP TABLE users' or a data-exfiltrating SELECT into the conversation.",
        )

    def _code_execution(self, call, q: str, last: str, pos: list[Any], kw: dict[str, Any]) -> None:
        # AutoGen: LocalCommandLineCodeExecutor runs generated code on the host.
        if last == "LocalCommandLineCodeExecutor" and ("autogen" in q or "autogen" in self.text):
            self._report_code(
                call,
                "LocalCommandLineCodeExecutor",
                "It runs model-written code directly on the host (AutoGen's docs: "
                "'The local version will run code on your local system').",
            )
            return
        cfg = kw.get("code_execution_config")
        if cfg is not None and cfg.type == "dictionary" and "autogen" in q:
            if self._human_always(kw):
                return
            for pair in cfg.named_children:
                if pair.type != "pair":
                    continue
                key = string_value(pair.child_by_field_name("key"), self.src)
                value = pair.child_by_field_name("value")
                if key == "use_docker" and is_false(value, self.src):
                    self._report_code(
                        call,
                        f"{last}(code_execution_config={{'use_docker': False}})",
                        "use_docker=False runs model-written code on the host instead "
                        "of in a Docker container.",
                    )
                    return
        # CrewAI: allow_code_execution=True with the "unsafe" (no Docker) mode.
        if (
            last == "Agent"
            and q.startswith("crewai")
            and is_true(kw.get("allow_code_execution"), self.src)
        ):
            mode = string_value(kw.get("code_execution_mode"), self.src)
            if mode == "unsafe":
                self._report_code(
                    call,
                    "Agent(allow_code_execution=True, code_execution_mode='unsafe')",
                    "code_execution_mode='unsafe' runs model-written code directly on "
                    "the host; the default 'safe' mode uses Docker.",
                )
        if last == "CodeInterpreterTool" and is_true(kw.get("unsafe_mode"), self.src):
            self._report_code(
                call,
                "CodeInterpreterTool(unsafe_mode=True)",
                "unsafe_mode=True executes model-written code on the host without a container.",
            )

    def _human_always(self, kw: dict[str, Any]) -> bool:
        mode = string_value(kw.get("human_input_mode"), self.src)
        return mode == "ALWAYS"

    def _report_code(self, call, tool: str, excessive: str) -> None:
        # An AutoGen / CrewAI agent constructor is itself the agent; an executor
        # or tool object is wired into one.
        is_agent = not tool.startswith(("LocalCommandLineCodeExecutor", "CodeInterpreterTool"))
        self._report(
            call,
            "agent-code-execution",
            tool,
            "Agent executes model-written code without a sandbox",
            excessive,
            Severity.HIGH,
            Confidence.HIGH,
            ["CWE-94", "CWE-250"],
            "Execute generated code only in an isolated sandbox: AutoGen "
            "DockerCommandLineCodeExecutor (or use_docker=True), CrewAI safe mode, or a "
            "remote sandbox (E2B, Modal) with no credentials or network access to "
            "internal systems.",
            "Get the model to write code that reads credentials or opens a reverse shell; "
            "the executor runs it on the host.",
            is_agent=is_agent,
        )


def analyze_agency(data: bytes, root, path: str, in_test: bool) -> list[Finding]:
    return _Agency(data, root, path, in_test).run()
