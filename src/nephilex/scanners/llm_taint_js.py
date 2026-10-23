"""LLM and agent data-flow rules for JavaScript and TypeScript (tree-sitter).

The JS/TS counterpart of :mod:`nephilex.scanners.llm_taint`. One statement-ordered
walk per file tracks four kinds of value:

* ``llm``: a response from the OpenAI, Anthropic, LangChain.js, Vercel AI SDK
  (``generateText``, ``streamText``), Ollama, Google Generative AI / GenAI or
  LlamaIndex.TS clients, resolved through the file's ``import`` / ``require``
  bindings. Reaching ``eval`` / ``new Function`` / ``vm``, ``child_process``,
  SQL (``query``, ``prepare``, ``$queryRawUnsafe``), ``fs`` writes, ``fetch`` /
  ``axios`` / ``got`` URLs, or HTML (``innerHTML``, ``document.write``,
  ``dangerouslySetInnerHTML``, an Express ``res.send`` of markup) is
  ``insecure-output-handling`` (LLM05).
* ``tool-arg``: a parameter of an agent tool handler (Vercel AI SDK / OpenAI
  Agents ``tool({execute})``, MCP ``server.tool`` / ``server.registerTool``,
  LangChain.js ``tool()`` / ``DynamicStructuredTool``). A zod ``z.enum`` /
  ``z.number`` / ``z.boolean`` / ``z.literal`` field is constrained and not
  tracked. Reaching a shell or ``eval`` is ``tool-handler-exec``; a file path,
  URL, SQL text or email recipient is ``tool-argument-to-sink`` (LLM06).
* ``untrusted``: request input (``req.body``, ``req.query``, ``await
  req.json()``) and external content (``fetch`` responses, files read at run
  time). In a system prompt it is ``untrusted-input-in-system-prompt``; as a
  message role or a whole message list it is ``untrusted-message-role``
  (LLM01); external content in the prompt of a model that can act is
  ``indirect-prompt-injection`` (LLM01).
* ``secret``: ``process.env`` values with credential names, which must not be
  placed in a prompt (``secret-sent-to-model``, LLM02).

Sanitizers clear only what they protect against: ``DOMPurify.sanitize`` and
friends for HTML, ``encodeURIComponent`` for URLs and shells, numeric coercion
for everything; schema validation (``schema.parse`` from zod and similar, and
``generateObject``) yields a structured value that is not reported. An
allowlist check (``if (!ALLOWED.includes(cmd)) return``, ``HOSTS.has(u.hostname)``,
``Object.hasOwn(MAP, key)``, ``p.startsWith(BASE + path.sep)``) clears the
checked value. Nested functions see the enclosing scope (closures are the norm
in JS), and calls to functions defined once in the file are followed with the
caller's argument taint.
"""

from __future__ import annotations

import re
from dataclasses import replace
from typing import Any

from nephilex.core.models import Confidence, Finding
from nephilex.scanners import llm_agent
from nephilex.scanners.llm_agent import ModelCall
from nephilex.scanners.llm_ast import (
    LLM01,
    LLM05,
    Src,
    end_line_of,
    line_of,
    make_finding,
    walk,
)
from nephilex.scanners.llm_taint import (
    ALL_KINDS,
    SINK_SPECS,
    Taint,
    TaintSet,
    _merge,
    _strip,
    system_prompt_finding,
    tool_exec_finding,
)

_LLM_PACKAGES = re.compile(
    r"^(?:openai|@anthropic-ai/sdk|@langchain/[\w.-]+|langchain(?:/[\w./-]+)?|ai|"
    r"@ai-sdk/[\w.-]+|ollama(?:/browser)?|@google/generative-ai|@google/genai|"
    r"llamaindex|@llamaindex/[\w.-]+|@mistralai/mistralai|groq-sdk|cohere-ai|@openai/agents)$"
)
# Classes whose instances call a model (prompt templates, messages, parsers,
# splitters and stores from the same packages are not).
_JS_LLM_CTOR = re.compile(
    r"^(?:OpenAI|AzureOpenAI|Anthropic|AnthropicBedrock|AnthropicVertex|GoogleGenerativeAI|"
    r"GoogleGenAI|Ollama|Groq|Mistral|CohereClient|CohereClientV2|LLMChain|ConversationChain|"
    r"RetrievalQAChain|AgentExecutor|\w*LLM|\w*Agent)$"
    r"|^(?:Azure)?Chat(?!Prompt|Message|Result|Generation|History|Session)[A-Z]\w*$"
)
_AI_SDK_TEXT = {"generateText", "streamText"}
_AI_SDK_OBJECT = {"generateObject", "streamObject"}
_SOURCE_METHODS = {
    "create",
    "parse",
    "stream",
    "invoke",
    "call",
    "predict",
    "generateContent",
    "generateContentStream",
    "sendMessage",
    "sendMessageStream",
    "chat",
    "complete",
    "run",
    "query",
    "generate",
}
_CREATE_PARENTS = {"completions", "responses", "messages"}
_DERIVE_METHODS = {
    "getGenerativeModel",
    "bindTools",
    "bind",
    "withStructuredOutput",
    "withRetry",
    "withConfig",
    "startChat",
    "asQueryEngine",
    "asChatEngine",
}
_CLEAN_FUNCS = {"Number", "parseInt", "parseFloat", "Boolean", "isNaN"}
_CLEAN_METHODS = {"startsWith", "endsWith", "includes", "indexOf", "test", "length", "has"}
_SANITIZERS: dict[str, frozenset[str]] = {
    "sanitize": frozenset({"html"}),
    "sanitizeHtml": frozenset({"html"}),
    "escapeHtml": frozenset({"html"}),
    "escape": frozenset({"html"}),
    "encodeURIComponent": frozenset({"ssrf", "shell", "html"}),
    "quote": frozenset({"shell"}),
    "basename": frozenset({"file"}),
}
_SCHEMA_METHODS = {"parse", "parseAsync", "validateSync", "assert"}
_HTTP_FUNCS = {"fetch", "axios", "got", "ky", "request"}
_HTTP_VERBS = {"get", "post", "put", "patch", "delete", "head", "request"}
_FS_MODULES = ("fs", "node:fs", "fs/promises", "node:fs/promises", "fs-extra")
_FS_WRITE = {
    "writeFile",
    "writeFileSync",
    "appendFile",
    "appendFileSync",
    "unlink",
    "unlinkSync",
    "rm",
    "rmSync",
    "rmdir",
    "rmdirSync",
    "rename",
    "renameSync",
    "createWriteStream",
}
_FS_READ = {"readFile", "readFileSync"}
_CP_MODULES = ("child_process", "node:child_process")
_CP_EXEC = {"exec", "execSync"}
_CP_SPAWN = {"spawn", "spawnSync", "execFile", "execFileSync", "fork"}
_HOST_PINNED = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://[^/{}$\s]+/")
_WEAK_PREFIXES = {"http", "https", "http://", "https://", "/", "", "ftp://", "file://"}
_REQUEST_MEMBER = re.compile(r"^(?:req|request|ctx\.request)\.(?:body|query|params|cookies)\b")
_REQUEST_CALL = re.compile(r"^(?:req|request)\.(?:json|formData|text)$")
_SECRET_ENV = re.compile(r"(?i)secret|token|passw|api_?key|private_?key|credential|_key$")
_SQL_RECEIVER = re.compile(r"(?i)db|sql|database|conn|pool|client|knex|stmt")
#: Keys of a model call's options object that are configuration, not prompt text.
_NON_PROMPT_KEYS = {
    "model",
    "tools",
    "tool_choice",
    "toolChoice",
    "max_tokens",
    "maxTokens",
    "max_output_tokens",
    "maxOutputTokens",
    "temperature",
    "top_p",
    "topP",
    "stream",
    "response_format",
    "maxSteps",
    "stopWhen",
    "seed",
    "metadata",
    "store",
    "parallel_tool_calls",
    "reasoning",
    "thinking",
    "providerOptions",
    "abortSignal",
    "headers",
    "maxRetries",
    "schema",
    "output",
}
_CONSTRAINED_ZOD = re.compile(
    r"^z\.(?:enum|nativeEnum|number|boolean|literal|int|bigint|coerce\.number|date)\("
)
_FUNCTION_TYPES = ("arrow_function", "function_expression", "function", "generator_function")
_MUTATORS = {"push", "unshift", "add", "set"}


class JsTaint:
    def __init__(self, data: bytes, root, path: str, in_test: bool) -> None:
        self.src = Src(data)
        self.root = root
        self.path = path
        self.in_test = in_test
        self.imports: dict[str, str] = {}  # local name -> "module" or "module#export"
        self.objects: set[str] = set()  # LLM objects
        self.mcp_servers: set[str] = set()
        self.local_funcs: dict[str, Any] = {}  # name -> function node (defined once)
        self.tool_vars: dict[str, str] = {}  # variable holding a tool -> tool name
        self.tool_caps: dict[str, set[str]] = {}
        self.tool_returns: dict[str, tuple[str, int]] = {}
        self.calls: dict[int, ModelCall] = {}
        self.findings: list[Finding] = []
        self._seen: set[tuple[str, int]] = set()
        self._done: set[tuple[int, int]] = set()  # (start, end) of tool handlers walked
        self._ret_stack: list[TaintSet] = []
        self._inline_stack: list[str] = []
        self._inline_memo: dict[tuple[Any, ...], TaintSet] = {}
        self._loop_depth = 0

    def run(self) -> list[Finding]:
        self._collect_imports()
        self._collect_objects()
        self._collect_functions()
        self._block(self.root, {})
        for call in sorted(self.calls.values(), key=lambda c: c.line):
            for name, caps in call.tools.items():
                caps |= self.tool_caps.get(name, set())
                if name in self.tool_returns:
                    origin, line = self.tool_returns[name]
                    call.add_source(f"the result of tool '{name}' ({origin})", line)
            finding = llm_agent.indirect_injection_finding(call, self.path, self.in_test)
            if finding is not None:
                self.findings.append(finding)
        return self.findings

    # --- imports and objects ---------------------------------------------------
    def _string(self, node) -> str | None:
        if node is None or node.type != "string":
            return None
        return "".join(self.src.text(c) for c in node.named_children if c.type == "string_fragment")

    def _collect_imports(self) -> None:
        for node in walk(self.root):
            if node.type == "import_statement":
                module = self._string(node.child_by_field_name("source"))
                if module is None:
                    continue
                for n in walk(node):
                    if n.type == "import_specifier":
                        name = n.child_by_field_name("name")
                        alias = n.child_by_field_name("alias") or name
                        if name is not None and alias is not None:
                            self.imports[self.src.text(alias)] = f"{module}#{self.src.text(name)}"
                    elif n.type == "namespace_import":
                        ident = next((c for c in n.named_children if c.type == "identifier"), None)
                        if ident is not None:
                            self.imports[self.src.text(ident)] = module
                    elif n.type == "import_clause":
                        for c in n.named_children:
                            if c.type == "identifier":
                                self.imports[self.src.text(c)] = module
            elif node.type == "variable_declarator":
                value = node.child_by_field_name("value")
                name = node.child_by_field_name("name")
                if value is None or name is None:
                    continue
                if value.type == "await_expression" and value.named_children:
                    value = value.named_children[0]
                if value.type != "call_expression":
                    continue
                fn = value.child_by_field_name("function")
                args = value.child_by_field_name("arguments")
                first = args.named_children[0] if args is not None and args.named_children else None
                fn_text = self.src.text(fn) if fn is not None else ""
                if fn_text in ("promisify", "util.promisify") and first is not None:
                    # const run = promisify(exec): run is exec.
                    if name.type == "identifier" and self.src.text(first) in self.imports:
                        self.imports[self.src.text(name)] = self.imports[self.src.text(first)]
                    continue
                if fn_text not in ("require", "import"):
                    continue
                module = self._string(first)
                if module is None:
                    continue
                if name.type == "identifier":
                    self.imports[self.src.text(name)] = module
                elif name.type == "object_pattern":
                    for c in name.named_children:
                        if c.type == "shorthand_property_identifier_pattern":
                            self.imports[self.src.text(c)] = f"{module}#{self.src.text(c)}"
                        elif c.type == "pair_pattern":
                            key = c.child_by_field_name("key")
                            val = c.child_by_field_name("value")
                            if key is not None and val is not None:
                                self.imports[self.src.text(val)] = f"{module}#{self.src.text(key)}"

    def _module_of(self, name: str) -> str:
        return self.imports.get(name, "").split("#", 1)[0]

    def _export_of(self, name: str) -> str:
        return self.imports.get(name, "#").split("#", 1)[-1]

    def _is_llm_import(self, name: str) -> bool:
        return bool(_LLM_PACKAGES.match(self._module_of(name)))

    def _collect_objects(self) -> None:
        decls: list[tuple[str, Any]] = []
        for node in walk(self.root):
            if node.type == "variable_declarator":
                name = node.child_by_field_name("name")
                value = node.child_by_field_name("value")
                if name is not None and value is not None and name.type == "identifier":
                    decls.append((self.src.text(name), value))
            elif node.type == "assignment_expression":
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                if left is not None and right is not None:
                    decls.append((self.src.text(left), right))
        for _ in range(3):
            changed = False
            for name, value in decls:
                if name not in self.objects and self._is_llm_value(value):
                    self.objects.add(name)
                    changed = True
            if not changed:
                break
        for name, value in decls:
            if value.type == "await_expression" and value.named_children:
                value = value.named_children[0]
            if value.type == "new_expression":
                ctor = value.child_by_field_name("constructor")
                text = self.src.text(ctor) if ctor is not None else ""
                head = text.split(".", 1)[0]
                if text.rsplit(".", 1)[-1] == "McpServer" or (
                    self._module_of(head).startswith("@modelcontextprotocol/sdk")
                    and text.endswith("Server")
                ):
                    self.mcp_servers.add(name)

    def _collect_functions(self) -> None:
        counts: dict[str, int] = {}
        for node in walk(self.root):
            name = None
            fn = None
            if node.type in ("function_declaration", "generator_function_declaration"):
                name_node = node.child_by_field_name("name")
                name, fn = (self.src.text(name_node) if name_node else None), node
            elif node.type == "variable_declarator":
                value = node.child_by_field_name("value")
                name_node = node.child_by_field_name("name")
                if (
                    value is not None
                    and value.type in _FUNCTION_TYPES
                    and name_node is not None
                    and name_node.type == "identifier"
                ):
                    name, fn = self.src.text(name_node), value
            if name and fn is not None:
                counts[name] = counts.get(name, 0) + 1
                self.local_funcs[name] = fn
        for name, count in counts.items():
            if count > 1:
                del self.local_funcs[name]

    def _is_llm_value(self, value) -> bool:
        if value.type == "await_expression" and value.named_children:
            value = value.named_children[0]
        if value.type == "new_expression":
            ctor = value.child_by_field_name("constructor")
            if ctor is None:
                return False
            text = self.src.text(ctor)
            head, last = text.split(".", 1)[0], text.rsplit(".", 1)[-1]
            return self._is_llm_import(head) and bool(_JS_LLM_CTOR.match(last))
        if value.type == "call_expression":
            fn = value.child_by_field_name("function")
            if fn is None:
                return False
            if fn.type == "identifier" and self._is_llm_import(self.src.text(fn)):
                # Factory helpers such as openai("gpt-4o") from @ai-sdk/openai.
                return self._export_of(self.src.text(fn)) not in (
                    _AI_SDK_TEXT | _AI_SDK_OBJECT | {"tool", "jsonSchema", "zodSchema"}
                )
            if fn.type == "member_expression":
                prop = fn.child_by_field_name("property")
                obj = fn.child_by_field_name("object")
                pname = self.src.text(prop) if prop is not None else ""
                if obj is not None and self._root_is_llm(obj) and pname in _DERIVE_METHODS:
                    return True
                if pname == "pipe" and obj is not None:
                    args = value.child_by_field_name("arguments")
                    return bool(
                        args is not None and any(self._root_is_llm(a) for a in args.named_children)
                    ) or self._root_is_llm(obj)
        return False

    def _root_is_llm(self, node) -> bool:
        cur = node
        while cur is not None:
            if cur.type in ("identifier", "this"):
                return self.src.text(cur) in self.objects
            if cur.type == "member_expression":
                if self.src.text(cur) in self.objects:
                    return True
                cur = cur.child_by_field_name("object")
                continue
            if cur.type in ("new_expression", "call_expression"):
                return self._is_llm_value(cur)
            if cur.type in ("parenthesized_expression", "await_expression"):
                cur = cur.named_children[0] if cur.named_children else None
                continue
            return False
        return False

    def _root_name(self, node) -> str | None:
        cur = node
        while cur is not None:
            if cur.type == "identifier":
                return self.src.text(cur)
            if cur.type == "member_expression":
                cur = cur.child_by_field_name("object")
                continue
            if cur.type == "call_expression":
                fn = cur.child_by_field_name("function")
                cur = fn.child_by_field_name("object") if fn is not None else None
                continue
            return None
        return None

    # --- statements ------------------------------------------------------------
    def _block(self, node, scope: dict[str, TaintSet]) -> None:
        for stmt in node.named_children:
            self._stmt(stmt, scope)

    def _stmt(self, node, scope: dict[str, TaintSet]) -> None:
        t = node.type
        if t in ("lexical_declaration", "variable_declaration"):
            for decl in node.named_children:
                if decl.type != "variable_declarator":
                    continue
                value = decl.child_by_field_name("value")
                name = decl.child_by_field_name("name")
                if value is None or name is None:
                    continue
                self._expr(value, scope)
                self._bind(name, self._eval(value, scope), scope)
            return
        if t == "expression_statement":
            for child in node.named_children:
                self._expr(child, scope)
                if child.type in ("assignment_expression", "augmented_assignment_expression"):
                    left = child.child_by_field_name("left")
                    right = child.child_by_field_name("right")
                    if left is not None and right is not None:
                        taint = self._eval(right, scope)
                        if child.type == "augmented_assignment_expression":
                            taint = _merge(self._eval(left, scope), taint)
                        self._bind(left, taint, scope)
                elif child.type == "call_expression":
                    self._mutation(child, scope)
            return
        if t == "return_statement":
            for child in node.named_children:
                self._expr(child, scope)
            if node.named_children and self._ret_stack:
                value = self._eval(node.named_children[0], scope)
                self._ret_stack[-1] = _merge(self._ret_stack[-1], value)
            return
        if t == "if_statement":
            cond = node.child_by_field_name("condition")
            cons = node.child_by_field_name("consequence")
            if cond is not None:
                self._expr(cond, scope)
            guarded = self._guarded(cond, scope) if cond is not None else set()
            exits = cons is not None and self._exits(cons)
            if cons is not None:
                if guarded and not exits:
                    inner = {k: v for k, v in scope.items() if k not in guarded}
                    self._stmt_or_block(cons, inner)
                else:
                    self._stmt_or_block(cons, scope)
            alt = node.child_by_field_name("alternative")
            if alt is not None:
                self._generic(alt, scope)
            if guarded and exits:
                for n in guarded:
                    scope.pop(n, None)
            return
        if t == "for_in_statement":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if right is not None:
                self._expr(right, scope)
                if left is not None:
                    self._bind(left, self._eval(right, scope), scope)
            body = node.child_by_field_name("body")
            # Twice, so a value pushed at the end of one iteration (a tool result
            # added to the message list) is seen by the next.
            self._loop_depth += 1
            for _ in range(self._passes()):
                if body is not None:
                    self._stmt_or_block(body, scope)
            self._loop_depth -= 1
            return
        if t in ("for_statement", "while_statement", "do_statement"):
            init = node.child_by_field_name("initializer")
            if init is not None:
                self._stmt(init, scope) if init.type.endswith("declaration") else self._expr(
                    init, scope
                )
            self._loop_depth += 1
            for _ in range(self._passes()):
                for field_name in ("condition", "increment"):
                    child = node.child_by_field_name(field_name)
                    if child is not None:
                        self._expr(child, scope)
                body = node.child_by_field_name("body")
                if body is not None:
                    self._stmt_or_block(body, scope)
            self._loop_depth -= 1
            return
        if t in ("function_declaration", "generator_function_declaration", "method_definition"):
            self._function(node, scope)
            return
        self._generic(node, scope)

    def _passes(self) -> int:
        """Loop bodies run twice, but only the outer two levels (nesting stays linear)."""
        return 2 if self._loop_depth <= 2 else 1

    def _stmt_or_block(self, node, scope: dict[str, TaintSet]) -> None:
        if node.type == "statement_block":
            self._block(node, scope)
        else:
            self._stmt(node, scope)

    def _generic(self, node, scope: dict[str, TaintSet]) -> None:
        for child in node.named_children:
            if child.type == "statement_block":
                self._block(child, scope)
            elif child.type.endswith(("_statement", "_declaration")) or child.type in (
                "else_clause",
                "catch_clause",
                "finally_clause",
                "switch_body",
                "switch_case",
                "switch_default",
                "class_body",
                "method_definition",
            ):
                self._stmt(child, scope)
            else:
                self._expr(child, scope)

    def _exits(self, node) -> bool:
        if node.type in (
            "return_statement",
            "throw_statement",
            "continue_statement",
            "break_statement",
        ):
            return True
        if node.type == "statement_block":
            stmts = [c for c in node.named_children if c.type != "comment"]
            return bool(stmts) and self._exits(stmts[-1])
        return False

    def _bind(self, target, taint: TaintSet, scope: dict[str, TaintSet]) -> None:
        if target.type in (
            "identifier",
            "member_expression",
            "shorthand_property_identifier_pattern",
        ):
            key = self.src.text(target)
            if taint:
                scope[key] = taint
            else:
                scope.pop(key, None)
            return
        if target.type == "subscript_expression":
            obj = target.child_by_field_name("object")
            if obj is not None and taint:
                scope[self.src.text(obj)] = _merge(scope.get(self.src.text(obj), {}), taint)
            return
        if target.type == "assignment_pattern":
            left = target.child_by_field_name("left")
            if left is not None:
                self._bind(left, taint, scope)
            return
        for child in target.named_children:
            if child.type == "pair_pattern":
                value = child.child_by_field_name("value")
                if value is not None:
                    self._bind(value, taint, scope)
            else:
                self._bind(child, taint, scope)

    def _mutation(self, call, scope: dict[str, TaintSet]) -> None:
        """``messages.push(x)`` puts ``x``'s taint into ``messages``."""
        fn = call.child_by_field_name("function")
        if fn is None or fn.type != "member_expression":
            return
        prop = fn.child_by_field_name("property")
        obj = fn.child_by_field_name("object")
        if prop is None or obj is None or self.src.text(prop) not in _MUTATORS:
            return
        if obj.type not in ("identifier", "member_expression"):
            return
        args = call.child_by_field_name("arguments")
        taint: TaintSet = {}
        for a in args.named_children if args is not None else []:
            taint = _merge(taint, self._eval(a, scope))
        if taint:
            key = self.src.text(obj)
            scope[key] = _merge(scope.get(key, {}), taint)

    def _guarded(self, cond, scope: dict[str, TaintSet]) -> set[str]:
        out: set[str] = set()
        for n in walk(cond):
            if n.type == "call_expression":
                fn = n.child_by_field_name("function")
                args = n.child_by_field_name("arguments")
                if fn is None or args is None or fn.type != "member_expression":
                    continue
                prop = fn.child_by_field_name("property")
                obj = fn.child_by_field_name("object")
                pname = self.src.text(prop) if prop is not None else ""
                argv = args.named_children
                if pname in ("includes", "has") and obj is not None and not self._eval(obj, scope):
                    if obj.type == "string":
                        continue  # "abc".includes(x) is a substring test
                    for a in argv:
                        out |= self._checked(a, scope)
                elif pname == "hasOwn" and self.src.text(obj) == "Object" and len(argv) > 1:
                    out |= self._checked(argv[1], scope)
                elif pname == "test" and obj is not None and obj.type == "regex":
                    for a in argv:
                        out |= self._checked(a, scope)
                elif pname == "startsWith" and obj is not None and argv:
                    lit = self._string(argv[0])
                    if lit is not None and lit.lower() in _WEAK_PREFIXES:
                        continue
                    if self.src.text(obj) in scope:
                        out.add(self.src.text(obj))
            elif n.type == "binary_expression":
                op = n.child_by_field_name("operator")
                left = n.child_by_field_name("left")
                right = n.child_by_field_name("right")
                if op is None or left is None or right is None:
                    continue
                if self.src.text(op) in ("===", "==", "!==", "!="):
                    for a, b in ((left, right), (right, left)):
                        if b.type in ("string", "number") and self.src.text(a) in scope:
                            out.add(self.src.text(a))
                elif self.src.text(op) == "in" and not self._eval(right, scope):
                    out |= self._checked(left, scope)
        return out

    def _checked(self, node, scope: dict[str, TaintSet]) -> set[str]:
        """Tainted names an allowlist test on ``node`` vouches for (``u.hostname`` -> ``u``)."""
        text = self.src.text(node)
        if text in scope:
            return {text}
        if node.type == "member_expression":
            prop = node.child_by_field_name("property")
            obj = node.child_by_field_name("object")
            if (
                prop is not None
                and obj is not None
                and self.src.text(prop) in ("hostname", "host", "origin")
                and self.src.text(obj) in scope
            ):
                return {self.src.text(obj)}
        return set()

    # --- functions -----------------------------------------------------------------
    def _params(self, fn) -> list[Any]:
        params = fn.child_by_field_name("parameters")
        if params is None:
            single = fn.child_by_field_name("parameter")
            return [single] if single is not None else []
        out = []
        for p in params.named_children:
            if p.type in ("required_parameter", "optional_parameter"):
                pattern = p.child_by_field_name("pattern")
                if pattern is not None:
                    out.append(pattern)
            elif p.type != "comment":
                out.append(p)
        return out

    def _param_names(self, pattern) -> list[str]:
        if pattern.type == "identifier":
            return [self.src.text(pattern)]
        names: list[str] = []
        for n in walk(pattern):
            if n.type in ("shorthand_property_identifier_pattern",):
                names.append(self.src.text(n))
            elif n.type == "pair_pattern":
                value = n.child_by_field_name("value")
                if value is not None and value.type == "identifier":
                    names.append(self.src.text(value))
            elif (
                n.type == "identifier"
                and n.parent is not None
                and n.parent.type
                in (
                    "assignment_pattern",
                    "rest_pattern",
                    "array_pattern",
                )
            ):
                names.append(self.src.text(n))
        return names

    def _function(
        self,
        fn,
        scope: dict[str, TaintSet],
        tainted: dict[str, TaintSet] | None = None,
    ) -> TaintSet:
        """Walk a nested function with the enclosing scope; its return taint."""
        inner = dict(scope)
        for p in self._params(fn):
            for name in self._param_names(p):
                inner.pop(name, None)
        if tainted:
            inner.update(tainted)
        body = fn.child_by_field_name("body")
        if body is None:
            return {}
        self._ret_stack.append({})
        if body.type == "statement_block":
            self._block(body, inner)
        else:
            self._expr(body, inner)
            self._ret_stack[-1] = _merge(self._ret_stack[-1], self._eval(body, inner))
        return self._ret_stack.pop()

    def _inline(self, name: str, args: list[Any], scope: dict[str, TaintSet]) -> TaintSet:
        """Follow a call to a function defined once in the file; its return taint."""
        fn = self.local_funcs.get(name)
        if fn is None or name in self._inline_stack or len(self._inline_stack) >= 3:
            return {}
        callee: dict[str, TaintSet] = {}
        for p, a in zip(self._params(fn), args, strict=False):
            ts = self._eval(a, scope)
            if ts:
                for pname in self._param_names(p):
                    callee[pname] = ts
        key = (
            name,
            tuple(
                sorted(
                    (p, f, t.line, frozenset(t.kinds), t.validated, t.external)
                    for p, ts in callee.items()
                    for f, t in ts.items()
                )
            ),
        )
        if key in self._inline_memo:
            return self._inline_memo[key]
        self._inline_memo[key] = {}
        self._inline_stack.append(name)
        try:
            ret = self._function(fn, {}, callee)
        finally:
            self._inline_stack.pop()
        self._inline_memo[key] = ret
        return ret

    # --- agent tools -----------------------------------------------------------------
    def _object_pairs(self, obj) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if obj is None or obj.type != "object":
            return out
        for c in obj.named_children:
            if c.type == "pair":
                key = c.child_by_field_name("key")
                value = c.child_by_field_name("value")
                if key is not None and value is not None:
                    k = self._string(key) if key.type == "string" else self.src.text(key)
                    out[k or ""] = value
            elif c.type == "shorthand_property_identifier":
                out[self.src.text(c)] = c
            elif c.type == "method_definition":
                name = c.child_by_field_name("name")
                if name is not None:
                    out[self.src.text(name)] = c
        return out

    def _constrained_keys(self, schema) -> set[str]:
        """Fields of a zod schema (``z.object({...})`` or a raw shape) that are closed sets."""
        if schema is None:
            return set()
        if schema.type == "call_expression":
            args = schema.child_by_field_name("arguments")
            schema = args.named_children[0] if args is not None and args.named_children else None
        return {
            k
            for k, v in self._object_pairs(schema).items()
            if _CONSTRAINED_ZOD.match(self.src.text(v))
        }

    def _tool_name_from_parent(self, call) -> str:
        parent = call.parent
        if parent is not None and parent.type == "pair":
            key = parent.child_by_field_name("key")
            if key is not None:
                return self._string(key) or self.src.text(key)
        if parent is not None and parent.type == "variable_declarator":
            name = parent.child_by_field_name("name")
            if name is not None:
                return self.src.text(name)
        return "tool"

    def _tool_handler(self, call) -> tuple[Any, str, set[str]] | None:
        """(handler function, tool name, constrained argument names) for a tool definition."""
        fn = call.child_by_field_name("function") or call.child_by_field_name("constructor")
        args_node = call.child_by_field_name("arguments")
        args = args_node.named_children if args_node is not None else []
        if fn is None:
            return None
        fn_text = self.src.text(fn)
        if fn.type == "identifier" and self._export_of(fn_text) == "tool":
            module = self._module_of(fn_text)
            if module in ("ai", "@openai/agents") and args and args[0].type == "object":
                pairs = self._object_pairs(args[0])
                handler = pairs.get("execute")
                schema = pairs.get("parameters") or pairs.get("inputSchema")
                name = self._string(pairs.get("name")) or self._tool_name_from_parent(call)
                if handler is not None and handler.type in _FUNCTION_TYPES:
                    return handler, name, self._constrained_keys(schema)
            if (
                module.startswith(("@langchain/", "langchain"))
                and args
                and args[0].type in _FUNCTION_TYPES
            ):
                opts = self._object_pairs(args[1]) if len(args) > 1 else {}
                name = self._string(opts.get("name")) or self._tool_name_from_parent(call)
                return args[0], name, self._constrained_keys(opts.get("schema"))
        if call.type == "new_expression" and fn_text.rsplit(".", 1)[-1] in (
            "DynamicStructuredTool",
            "DynamicTool",
        ):
            pairs = self._object_pairs(args[0]) if args else {}
            handler = pairs.get("func")
            name = self._string(pairs.get("name")) or self._tool_name_from_parent(call)
            if handler is not None and handler.type in _FUNCTION_TYPES:
                return handler, name, self._constrained_keys(pairs.get("schema"))
        if fn.type == "member_expression":
            prop = fn.child_by_field_name("property")
            obj = fn.child_by_field_name("object")
            pname = self.src.text(prop) if prop is not None else ""
            if (
                pname in ("tool", "registerTool")
                and obj is not None
                and self._root_name(obj) in self.mcp_servers
                and args
                and args[-1].type in _FUNCTION_TYPES
            ):
                name = self._string(args[0]) or "tool"
                schema = None
                if pname == "registerTool" and len(args) > 2:
                    schema = self._object_pairs(args[1]).get("inputSchema")
                else:
                    schema = next((a for a in args[1:-1] if a.type == "object"), None)
                return args[-1], name, self._constrained_keys(schema)
        return None

    def _walk_tool(self, call, scope: dict[str, TaintSet]) -> None:
        found = self._tool_handler(call)
        if found is None:
            return
        handler, name, constrained = found
        if (handler.start_byte, handler.end_byte) in self._done:
            return
        self._done.add((handler.start_byte, handler.end_byte))
        parent = call.parent
        if parent is not None and parent.type == "variable_declarator":
            var = parent.child_by_field_name("name")
            if var is not None:
                self.tool_vars[self.src.text(var)] = name
        tainted: dict[str, TaintSet] = {}
        params = self._params(handler)
        if params:
            for pname in self._param_names(params[0]):
                if pname in constrained:
                    continue
                tainted[pname] = {
                    "tool-arg": Taint(
                        "tool-arg",
                        ALL_KINDS,
                        f"argument '{pname}' of agent tool '{name}'",
                        line_of(handler),
                        tool=name,
                    )
                }
        ret = self._function(handler, scope, tainted)
        ext = ret.get("untrusted")
        if ext is not None and ext.external and name not in self.tool_returns:
            self.tool_returns[name] = (ext.origin, ext.line)

    def _resolve_tools(self, node) -> dict[str, set[str]]:
        found: dict[str, set[str]] = {}
        if node is None:
            return found
        if node.type == "object":
            for key, value in self._object_pairs(node).items():
                if value.type in ("call_expression", "new_expression") and self._tool_handler(
                    value
                ):
                    found.setdefault(self._tool_handler(value)[1], set())  # type: ignore[index]
                elif self.src.text(value) in self.tool_vars:
                    found.setdefault(self.tool_vars[self.src.text(value)], set())
                else:
                    found.setdefault(key, set())
            return found
        for n in walk(node):
            if n.type == "identifier" and self.src.text(n) in self.tool_vars:
                found.setdefault(self.tool_vars[self.src.text(n)], set())
        return found

    # --- expressions -------------------------------------------------------------
    def _expr(self, node, scope: dict[str, TaintSet]) -> None:
        """Check sinks, prompts and nested functions inside one expression."""
        stack = [node]
        while stack:
            n = stack.pop()
            if n.type in _FUNCTION_TYPES:
                if (n.start_byte, n.end_byte) not in self._done:
                    self._function(n, scope)
                continue
            if n.type in ("call_expression", "new_expression"):
                self._walk_tool(n, scope)
                self._check_call(n, scope)
                self._check_model_call(n, scope)
                fn = n.child_by_field_name("function")
                if (
                    fn is not None
                    and fn.type == "identifier"
                    and self.src.text(fn) in self.local_funcs
                ):
                    self._eval_call(n, scope)  # follow the call with these arguments
            elif n.type == "object":
                self._check_message_object(n, scope)
            elif n.type == "assignment_expression":
                left = n.child_by_field_name("left")
                if left is not None and left.type == "member_expression":
                    prop = left.child_by_field_name("property")
                    if prop is not None and self.src.text(prop) in ("innerHTML", "outerHTML"):
                        self._sink(
                            n, "html", n.child_by_field_name("right"), self.src.text(prop), scope
                        )
            elif n.type == "jsx_attribute":
                kids = n.named_children
                if kids and self.src.text(kids[0]) == "dangerouslySetInnerHTML":
                    for pair in walk(n):
                        if pair.type == "pair":
                            key = pair.child_by_field_name("key")
                            if key is not None and self.src.text(key) == "__html":
                                self._sink(
                                    n,
                                    "html",
                                    pair.child_by_field_name("value"),
                                    "dangerouslySetInnerHTML",
                                    scope,
                                )
            stack.extend(reversed(n.children))

    @staticmethod
    def _content_only(ts: TaintSet) -> TaintSet:
        t = ts.get("untrusted")
        if t is None or not t.structural:
            return ts
        return {**ts, "untrusted": replace(t, structural=False)}

    def _env_secret(self, node) -> TaintSet:
        text = self.src.text(node)
        m = re.match(r"^process\.env(?:\.(\w+)|\[\s*['\"](\w+)['\"]\s*\])$", text)
        if m is None:
            return {}
        name = m.group(1) or m.group(2)
        if not _SECRET_ENV.search(name):
            return {}
        return {"secret": Taint("secret", ALL_KINDS, f"environment variable {name}", line_of(node))}

    def _untrusted(self, origin: str, line: int, *, external: bool) -> TaintSet:
        return {"untrusted": Taint("untrusted", ALL_KINDS, origin, line, external=external)}

    def _eval(self, node, scope: dict[str, TaintSet]) -> TaintSet:
        if node is None:
            return {}
        t = node.type
        if t in (
            "number",
            "true",
            "false",
            "null",
            "undefined",
            "regex",
            "string",
            *_FUNCTION_TYPES,
        ):
            return {}
        if t in ("identifier", "shorthand_property_identifier"):
            return scope.get(self.src.text(node), {})
        if t == "member_expression":
            key = self.src.text(node)
            if key in scope:
                return scope[key]
            secret = self._env_secret(node)
            if secret:
                return secret
            if _REQUEST_MEMBER.match(key):
                return self._untrusted("request input", line_of(node), external=False)
            prop = node.child_by_field_name("property")
            if prop is not None and self.src.text(prop) == "length":
                return {}
            return self._eval(node.child_by_field_name("object"), scope)
        if t == "subscript_expression":
            secret = self._env_secret(node)
            if secret:
                return secret
            return self._eval(node.child_by_field_name("object"), scope)
        if t in ("call_expression", "new_expression"):
            return self._eval_call(node, scope)
        if t == "template_string":
            out: TaintSet = {}
            for child in node.named_children:
                out = _merge(out, self._eval(child, scope))
            return self._content_only(out)
        if t == "ternary_expression":
            return _merge(
                self._eval(node.child_by_field_name("consequence"), scope),
                self._eval(node.child_by_field_name("alternative"), scope),
            )
        if t == "object":
            out = {}
            role_fixed = False
            for key, value in self._object_pairs(node).items():
                if key == "role" and value.type == "string":
                    role_fixed = True
                out = _merge(out, self._eval(value, scope))
            for c in node.named_children:
                if c.type == "spread_element":
                    out = _merge(out, self._eval(c, scope))
            return self._content_only(out) if role_fixed else out
        if t == "binary_expression":
            op = node.child_by_field_name("operator")
            if op is not None and self.src.text(op) in (
                "===",
                "==",
                "!==",
                "!=",
                "<",
                ">",
                "<=",
                ">=",
                "instanceof",
                "in",
            ):
                return {}
        if t == "unary_expression":
            return {}
        out = {}
        for child in node.named_children:
            out = _merge(out, self._eval(child, scope))
        return out

    def _eval_call(self, node, scope: dict[str, TaintSet]) -> TaintSet:
        fn = node.child_by_field_name("function") or node.child_by_field_name("constructor")
        if fn is None:
            return {}
        fn_text = self.src.text(fn)
        args_node = node.child_by_field_name("arguments")
        args = args_node.named_children if args_node is not None else []
        last = fn_text.rsplit(".", 1)[-1]
        src = self._source(node, fn, fn_text, last)
        if src is not None:
            return src
        external = self._external_source(node, fn, fn_text, last, args)
        if external:
            return external
        if fn.type == "identifier" and last in _CLEAN_FUNCS:
            return {}
        out: TaintSet = {}
        for a in args:
            out = _merge(out, self._eval(a, scope))
        if fn.type == "identifier" and fn_text == "String":
            return self._content_only(out)
        if fn.type == "identifier" and fn_text in self.local_funcs:
            out = _merge(out, self._inline(fn_text, args, scope))
        if fn.type == "member_expression":
            obj = fn.child_by_field_name("object")
            recv = self._eval(obj, scope)
            if recv and last in _CLEAN_METHODS:
                return {}
            if last in _SCHEMA_METHODS and obj is not None and self.src.text(obj) != "JSON":
                return {f: replace(t, validated=True) for f, t in out.items()}
            # MAP.get(key): the value comes from MAP, not from the key.
            out = recv if last == "get" else _merge(recv, out)
        kinds = _SANITIZERS.get(last)
        if kinds:
            out = _strip(out, kinds)
        return out

    def _external_source(self, node, fn, fn_text: str, last: str, args) -> TaintSet:
        """Request input and content fetched from outside the application."""
        line = line_of(node)
        if fn.type == "member_expression" and _REQUEST_CALL.match(fn_text):
            return self._untrusted("request input", line, external=False)
        head = fn_text.split(".", 1)[0]
        mod = self._module_of(head)
        if fn.type == "identifier" and (
            fn_text in ("fetch", "axios", "got", "ky")
            or self._module_of(fn_text) in ("axios", "got", "node-fetch", "undici")
        ):
            return self._untrusted("an HTTP response", line, external=True)
        if (
            fn.type == "member_expression"
            and (head in ("axios", "got", "ky") or mod in ("axios", "got", "undici"))
            and last in _HTTP_VERBS
        ):
            return self._untrusted("an HTTP response", line, external=True)
        is_read = (fn.type == "member_expression" and mod in _FS_MODULES and last in _FS_READ) or (
            fn.type == "identifier"
            and self._module_of(fn_text) in _FS_MODULES
            and self._export_of(fn_text) in _FS_READ
        )
        if is_read and args and args[0].type not in ("string", "template_string"):
            return self._untrusted("file contents", line, external=True)
        return {}

    def _source(self, node, fn, fn_text: str, last: str) -> TaintSet | None:
        line = line_of(node)

        def taint(validated: bool = False) -> TaintSet:
            return {
                "llm": Taint(
                    "llm", ALL_KINDS, f"model output from {fn_text}()", line, validated=validated
                )
            }

        if fn.type == "identifier" and self._module_of(fn_text) in ("ai",):
            export = self._export_of(fn_text)
            if export in _AI_SDK_TEXT:
                return taint()
            if export in _AI_SDK_OBJECT:
                return taint(validated=True)
        if fn.type == "member_expression":
            obj = fn.child_by_field_name("object")
            if obj is None:
                return None
            head = fn_text.split(".", 1)[0]
            if self._module_of(head).startswith("ollama") and last in ("chat", "generate"):
                return taint()
            if self._root_is_llm(obj) and last in _SOURCE_METHODS:
                parent = self.src.text(obj).rsplit(".", 1)[-1]
                if last not in ("create", "parse", "stream") or parent in _CREATE_PARENTS:
                    return taint()
        return None

    # --- model calls and prompts -------------------------------------------------------
    def _check_model_call(self, node, scope: dict[str, TaintSet]) -> None:
        fn = node.child_by_field_name("function")
        if fn is None or node.type != "call_expression":
            return
        fn_text = self.src.text(fn)
        if self._source(node, fn, fn_text, fn_text.rsplit(".", 1)[-1]) is None:
            return
        args_node = node.child_by_field_name("arguments")
        args = args_node.named_children if args_node is not None else []
        label = f"{fn_text}()"
        opts = self._object_pairs(args[0]) if args and args[0].type == "object" else None
        if opts is not None:
            prompt = [v for k, v in opts.items() if k not in _NON_PROMPT_KEYS]
        else:
            prompt = list(args)
        line = line_of(node)
        info = self.calls.get(line)
        if info is None:
            info = ModelCall(
                line=line,
                end_line=end_line_of(node),
                columns=self.src.columns(node),
                snippet=self.src.line_text(line),
                label=label,
            )
            self.calls[line] = info
        for value in prompt:
            ts = self._eval(value, scope)
            ext = ts.get("untrusted")
            if ext is not None and ext.external:
                info.add_source(ext.origin, ext.line)
            secret = ts.get("secret")
            if secret is not None and ("secret-sent-to-model", secret.line) not in self._seen:
                self._seen.add(("secret-sent-to-model", secret.line))
                self.findings.append(
                    llm_agent.secret_to_model_finding(
                        origin=secret.origin,
                        source_line=secret.line,
                        label=label,
                        **self._where(node),
                    )
                )
        if opts is not None:
            for name, caps in self._resolve_tools(opts.get("tools")).items():
                info.tools.setdefault(name, set()).update(caps)
            for key, ctx in (
                ("system", "system= option"),
                ("instructions", "instructions= option"),
            ):
                if key in opts:
                    self._system_prompt(opts[key], f"{ctx} of {label}", scope)
            messages = opts.get("messages") or opts.get("input")
            if messages is not None and messages.type not in ("array", "string", "template_string"):
                bad = self._eval(messages, scope).get("untrusted")
                if bad is not None and bad.structural and not bad.external:
                    self._report_role(node, bad, label)

    def _check_message_object(self, node, scope: dict[str, TaintSet]) -> None:
        """``{role: "system", content: X}`` and ``{role: <request input>, ...}``."""
        pairs = self._object_pairs(node)
        role = pairs.get("role")
        if role is None or "content" not in pairs:
            return
        role_value = self._string(role)
        if role_value in ("system", "developer"):
            self._system_prompt(pairs["content"], f'"{role_value}" role message', scope)
        elif role_value is None:
            bad = self._eval(role, scope).get("untrusted")
            if bad is not None:
                self._report_role(node, bad, "a chat message")

    def _report_role(self, node, bad: Taint, label: str) -> None:
        if ("untrusted-message-role", bad.line) in self._seen:
            return
        self._seen.add(("untrusted-message-role", bad.line))
        self.findings.append(
            llm_agent.message_role_finding(
                origin=bad.origin, source_line=bad.line, label=label, **self._where(node)
            )
        )

    def _system_prompt(self, expr, label: str, scope: dict[str, TaintSet]) -> None:
        taint = self._eval(expr, scope).get("untrusted")
        if taint is None or ("untrusted-input-in-system-prompt", taint.line) in self._seen:
            return
        self._seen.add(("untrusted-input-in-system-prompt", taint.line))
        self.findings.append(
            system_prompt_finding(
                origin=taint.origin, source_line=taint.line, label=label, **self._where(expr)
            )
        )

    def _where(self, node) -> dict[str, Any]:
        line = line_of(node)
        return {
            "path": self.path,
            "line": line,
            "end_line": end_line_of(node),
            "columns": self.src.columns(node),
            "snippet": self.src.line_text(line),
            "in_test": self.in_test,
        }

    # --- sinks -------------------------------------------------------------------
    def _check_call(self, node, scope: dict[str, TaintSet]) -> None:
        fn = node.child_by_field_name("function") or node.child_by_field_name("constructor")
        if fn is None:
            return
        fn_text = self.src.text(fn)
        args_node = node.child_by_field_name("arguments")
        args = args_node.named_children if args_node is not None else []
        first = args[0] if args else None
        last = fn_text.rsplit(".", 1)[-1]
        head = fn_text.split(".", 1)[0]
        head_mod = self._module_of(head)
        if node.type == "new_expression" and fn_text == "Function":
            for a in args:
                self._sink(node, "code", a, "new Function()", scope)
            return
        if fn_text == "eval":
            self._sink(node, "code", first, "eval", scope)
            return
        if head_mod in ("vm", "node:vm") and last.startswith("run"):
            self._sink(node, "code", first, fn_text, scope)
            return
        cp = head_mod in _CP_MODULES
        if fn.type == "identifier" and self._module_of(fn_text) in _CP_MODULES:
            cp, last = True, self._export_of(fn_text)
        if cp and last in _CP_EXEC | _CP_SPAWN:
            self._sink(node, "shell", first, f"child_process.{last}", scope)
            return
        if (
            last == "sendMail"
            or fn_text.endswith(".emails.send")
            or (head_mod == "@sendgrid/mail" and last in ("send", "sendMultiple"))
        ):
            pairs = self._object_pairs(first)
            for key in ("to", "cc", "bcc"):
                if key in pairs:
                    self._sink(node, "recipient", pairs[key], f"{fn_text}() recipients", scope)
            return
        if fn.type == "member_expression":
            obj = fn.child_by_field_name("object")
            if last in (
                "query",
                "execute",
                "raw",
                "$queryRawUnsafe",
                "$executeRawUnsafe",
                "unsafe",
            ) or (
                last == "prepare" and obj is not None and _SQL_RECEIVER.search(self.src.text(obj))
            ):
                if obj is not None and not self._root_is_llm(obj):
                    self._sink(node, "sql", first, fn_text, scope)
                return
            if head_mod in _FS_MODULES and last in _FS_WRITE:
                self._sink(node, "file", first, fn_text, scope)
                if last in ("rename", "renameSync") and len(args) > 1:
                    self._sink(node, "file", args[1], fn_text, scope)
                return
            if head in ("axios", "got", "ky", "superagent") or head_mod in (
                "axios",
                "got",
                "undici",
                "http",
                "https",
                "node:http",
                "node:https",
            ):
                if last in _HTTP_VERBS:
                    self._sink(node, "ssrf", first, fn_text, scope)
                return
            if fn_text in ("document.write", "document.writeln"):
                self._sink(node, "html", first, fn_text, scope)
                return
            if last == "insertAdjacentHTML" and len(args) > 1:
                self._sink(node, "html", args[1], "insertAdjacentHTML", scope)
                return
            if (
                last in ("send", "write", "end")
                and head in ("res", "response", "reply")
                and first is not None
                and self._has_markup(first)
            ):
                # Express sends a string body as text/html.
                self._sink(node, "html", first, f"{fn_text}() HTML response", scope)
                return
        if fn.type == "identifier":
            if self._module_of(fn_text) in _FS_MODULES and self._export_of(fn_text) in _FS_WRITE:
                self._sink(node, "file", first, fn_text, scope)
            elif fn_text in _HTTP_FUNCS or self._module_of(fn_text) in (
                "axios",
                "got",
                "undici",
                "node-fetch",
            ):
                self._sink(node, "ssrf", first, fn_text, scope)

    def _has_markup(self, node) -> bool:
        return any(
            n.type in ("string_fragment", "string") and "<" in self.src.text(n) for n in walk(node)
        )

    def _host_pinned(self, node) -> bool:
        if node.type == "template_string":
            for c in node.named_children:
                if c.type == "string_fragment":
                    return bool(_HOST_PINNED.match(self.src.text(c)))
                return False
            return False
        if node.type == "binary_expression":
            left = node.child_by_field_name("left")
            while left is not None and left.type == "binary_expression":
                left = left.child_by_field_name("left")
            lit = self._string(left) if left is not None else None
            return bool(lit and _HOST_PINNED.match(lit))
        return False

    def _sink(self, node, kind: str, arg, label: str, scope: dict[str, TaintSet]) -> None:
        if arg is None:
            return
        if kind == "ssrf" and self._host_pinned(arg):
            return
        for flavor, t in self._eval(arg, scope).items():
            if t.validated or kind not in t.kinds:
                continue
            line = line_of(node)
            if flavor == "llm":
                if t.line in self.calls:
                    self.calls[t.line].add_sink(kind, label, line)
                if kind in SINK_SPECS:
                    self._report_output(node, kind, label, t)
                elif kind == "recipient":
                    self._report_tool_arg(node, kind, label, t)
            elif flavor == "tool-arg":
                if t.tool is not None:
                    self.tool_caps.setdefault(t.tool, set()).add(kind)
                if kind in ("shell", "code"):
                    if (f"tool-handler-exec:{kind}", line) not in self._seen:
                        self._seen.add((f"tool-handler-exec:{kind}", line))
                        self.findings.append(
                            tool_exec_finding(
                                kind=kind, label=label, origin=t.origin, **self._where(node)
                            )
                        )
                elif kind in llm_agent.TOOL_ARG_SINKS:
                    self._report_tool_arg(node, kind, label, t)

    def _report_tool_arg(self, node, kind: str, label: str, t: Taint) -> None:
        line = line_of(node)
        if (f"tool-argument-to-sink:{kind}", line) in self._seen:
            return
        self._seen.add((f"tool-argument-to-sink:{kind}", line))
        origin = t.origin if t.flavor == "tool-arg" else f"tool-call argument ({t.origin})"
        self.findings.append(
            llm_agent.tool_argument_finding(
                kind=kind, label=label, origin=origin, **self._where(node)
            )
        )

    def _report_output(self, node, kind: str, label: str, t: Taint) -> None:
        line = line_of(node)
        if (kind, line) in self._seen:
            return
        self._seen.add((kind, line))
        spec = SINK_SPECS[kind]
        self.findings.append(
            make_finding(
                rule="insecure-output-handling",
                key=kind,
                title=f"Model output {spec.phrase} ({label})",
                description=(
                    f"{t.origin[:1].upper()}{t.origin[1:]} (line {t.line}) reaches "
                    f"{label} without validation, so the response is {spec.phrase}."
                ),
                path=self.path,
                line=line,
                end_line=end_line_of(node),
                columns=self.src.columns(node),
                snippet=self.src.line_text(line),
                severity=spec.severity,
                confidence=Confidence.HIGH,
                cwe=list(spec.cwe),
                owasp_llm=LLM05,
                why="Model output is attacker-influenceable through prompt injection, and "
                f"here it is {spec.phrase}.",
                attack=spec.attack,
                impact="Prompt injection upgraded to a classic injection in this sink.",
                fix=spec.fix,
                tags=["llm", "taint"],
                metadata={
                    "analysis": "taint-dataflow",
                    "sink": kind,
                    "sink_call": label,
                    "source": t.origin,
                    "source_line": t.line,
                    "owasp_llm_related": [LLM01],
                },
                in_test=self.in_test,
            )
        )


def analyze_js(data: bytes, root, path: str, in_test: bool) -> list[Finding]:
    return JsTaint(data, root, path, in_test).run()
