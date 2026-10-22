"""Model output to dangerous sinks in JavaScript and TypeScript (tree-sitter).

The JS/TS counterpart of the ``insecure-output-handling`` rule in
:mod:`argus.scanners.llm_taint` (OWASP LLM05). Sources are responses from the
OpenAI, Anthropic, LangChain.js, Vercel AI SDK (``generateText``,
``streamText``), Ollama, Google Generative AI / GenAI and LlamaIndex.TS
clients, resolved through the file's ``import`` / ``require`` bindings. Sinks
are ``eval`` / ``new Function`` / ``vm``, ``child_process``, SQL ``query`` /
``$queryRawUnsafe``, ``fs`` writes and deletes, ``fetch`` / ``axios`` / ``got``
URLs (SSRF), and ``innerHTML`` / ``document.write`` /
``dangerouslySetInnerHTML``.

Sanitizers clear only what they protect against: ``DOMPurify.sanitize`` and
friends for HTML, ``encodeURIComponent`` for URLs and shells, numeric coercion
for everything; schema validation (``schema.parse`` from zod and similar, and
``generateObject``) yields a structured value that is not reported. An
allowlist check (``if (!ALLOWED.includes(cmd)) return``) clears the checked
value. Nested functions see the enclosing scope (closures are the norm in JS).
"""

from __future__ import annotations

import re
from typing import Any

from argus.core.models import Confidence, Finding
from argus.scanners.llm_ast import LLM01, LLM05, Src, line_of, make_finding, walk
from argus.scanners.llm_taint import ALL_KINDS, SINK_SPECS

_LLM_PACKAGES = re.compile(
    r"^(?:openai|@anthropic-ai/sdk|@langchain/[\w.-]+|langchain(?:/[\w./-]+)?|ai|"
    r"@ai-sdk/[\w.-]+|ollama(?:/browser)?|@google/generative-ai|@google/genai|"
    r"llamaindex|@llamaindex/[\w.-]+|@mistralai/mistralai|groq-sdk|cohere-ai)$"
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
_CLEAN_METHODS = {"startsWith", "endsWith", "includes", "indexOf", "test", "length"}
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
_CP_EXEC = {"exec", "execSync"}
_CP_SPAWN = {"spawn", "spawnSync", "execFile", "execFileSync", "fork"}
_HOST_PINNED = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://[^/{}$\s]+/")

Taint = dict[str, Any]  # {"kinds": frozenset, "origin": str, "line": int, "validated": bool}


def _merge(a: Taint | None, b: Taint | None) -> Taint | None:
    if a is None:
        return b
    if b is None:
        return a
    if a["validated"] and not b["validated"]:
        return b
    if b["validated"] and not a["validated"]:
        return a
    return {**a, "kinds": a["kinds"] | b["kinds"]}


class JsTaint:
    def __init__(self, data: bytes, root, path: str, in_test: bool) -> None:
        self.src = Src(data)
        self.root = root
        self.path = path
        self.in_test = in_test
        self.imports: dict[str, str] = {}  # local name -> "module" or "module#export"
        self.objects: set[str] = set()  # LLM objects
        self.findings: list[Finding] = []
        self._seen: set[tuple[str, int]] = set()

    def run(self) -> list[Finding]:
        self._collect_imports()
        self._collect_objects()
        self._block(self.root, {})
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
                if fn is None or self.src.text(fn) not in ("require", "import"):
                    continue
                args = value.child_by_field_name("arguments")
                module = (
                    self._string(args.named_children[0]) if args and args.named_children else None
                )
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
                return self._export_of(self.src.text(fn)) not in _AI_SDK_TEXT | _AI_SDK_OBJECT
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

    # --- statements ------------------------------------------------------------
    def _block(self, node, scope: dict[str, Taint]) -> None:
        for stmt in node.named_children:
            self._stmt(stmt, scope)

    def _stmt(self, node, scope: dict[str, Taint]) -> None:
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
            if body is not None:
                self._stmt_or_block(body, scope)
            return
        if t in ("function_declaration", "generator_function_declaration", "method_definition"):
            body = node.child_by_field_name("body")
            if body is not None:
                self._block(body, dict(scope))
            return
        self._generic(node, scope)

    def _stmt_or_block(self, node, scope: dict[str, Taint]) -> None:
        if node.type == "statement_block":
            self._block(node, scope)
        else:
            self._stmt(node, scope)

    def _generic(self, node, scope: dict[str, Taint]) -> None:
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

    def _bind(self, target, taint: Taint | None, scope: dict[str, Taint]) -> None:
        if target.type in (
            "identifier",
            "member_expression",
            "shorthand_property_identifier_pattern",
        ):
            key = self.src.text(target)
            if taint is not None:
                scope[key] = taint
            else:
                scope.pop(key, None)
            return
        if target.type == "subscript_expression":
            obj = target.child_by_field_name("object")
            if obj is not None and taint is not None:
                scope[self.src.text(obj)] = _merge(scope.get(self.src.text(obj)), taint)  # type: ignore[assignment]
            return
        for child in target.named_children:
            if child.type == "pair_pattern":
                value = child.child_by_field_name("value")
                if value is not None:
                    self._bind(value, taint, scope)
            else:
                self._bind(child, taint, scope)

    def _guarded(self, cond, scope: dict[str, Taint]) -> set[str]:
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
                if (
                    pname in ("includes", "has")
                    and obj is not None
                    and self._eval(obj, scope) is None
                ):
                    if obj.type == "string":
                        continue  # "abc".includes(x) is a substring test
                    for a in args.named_children:
                        if self.src.text(a) in scope:
                            out.add(self.src.text(a))
                elif pname == "test" and obj is not None and obj.type == "regex":
                    for a in args.named_children:
                        if self.src.text(a) in scope:
                            out.add(self.src.text(a))
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
        return out

    # --- expressions -------------------------------------------------------------
    def _eval(self, node, scope: dict[str, Taint]) -> Taint | None:
        if node is None:
            return None
        t = node.type
        if t in (
            "number",
            "true",
            "false",
            "null",
            "undefined",
            "regex",
            "string",
            "arrow_function",
            "function_expression",
        ):
            return None
        if t in ("identifier", "shorthand_property_identifier"):
            return scope.get(self.src.text(node))
        if t == "member_expression":
            key = self.src.text(node)
            if key in scope:
                return scope[key]
            prop = node.child_by_field_name("property")
            if prop is not None and self.src.text(prop) == "length":
                return None
            return self._eval(node.child_by_field_name("object"), scope)
        if t == "subscript_expression":
            return self._eval(node.child_by_field_name("object"), scope)
        if t in ("call_expression", "new_expression"):
            return self._eval_call(node, scope)
        if t in ("binary_expression",):
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
                return None
        if t == "unary_expression":
            return None
        out: Taint | None = None
        for child in node.named_children:
            out = _merge(out, self._eval(child, scope))
        return out

    def _eval_call(self, node, scope: dict[str, Taint]) -> Taint | None:
        fn = node.child_by_field_name("function") or node.child_by_field_name("constructor")
        if fn is None:
            return None
        fn_text = self.src.text(fn)
        args_node = node.child_by_field_name("arguments")
        args = args_node.named_children if args_node is not None else []
        last = fn_text.rsplit(".", 1)[-1]
        src = self._source(node, fn, fn_text, last)
        if src is not None:
            return src
        if fn.type == "identifier" and last in _CLEAN_FUNCS:
            return None
        out: Taint | None = None
        for a in args:
            out = _merge(out, self._eval(a, scope))
        if fn.type == "member_expression":
            obj = fn.child_by_field_name("object")
            recv = self._eval(obj, scope)
            if recv is not None and last in _CLEAN_METHODS:
                return None
            if last in _SCHEMA_METHODS and obj is not None and self.src.text(obj) != "JSON":
                return {**out, "validated": True} if out is not None else None
            out = _merge(recv, out)
        kinds = _SANITIZERS.get(last)
        if kinds and out is not None:
            left = out["kinds"] - kinds
            return {**out, "kinds": left} if left else None
        return out

    def _source(self, node, fn, fn_text: str, last: str) -> Taint | None:
        line = line_of(node)

        def taint(validated: bool = False) -> Taint:
            return {
                "kinds": ALL_KINDS,
                "origin": f"model output from {fn_text}()",
                "line": line,
                "validated": validated,
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

    # --- sinks -------------------------------------------------------------------
    def _expr(self, node, scope: dict[str, Taint]) -> None:
        for n in walk(node):
            if n.type in ("call_expression", "new_expression"):
                self._check_call(n, scope)
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

    def _check_call(self, node, scope: dict[str, Taint]) -> None:
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
        cp = head_mod in ("child_process", "node:child_process")
        if fn.type == "identifier" and self._module_of(fn_text) in (
            "child_process",
            "node:child_process",
        ):
            cp, last = True, self._export_of(fn_text)
        if cp and last in _CP_EXEC:
            self._sink(node, "shell", first, f"child_process.{last}", scope)
            return
        if cp and last in _CP_SPAWN:
            self._sink(node, "shell", first, f"child_process.{last}", scope)
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
            ):
                if obj is not None and not self._root_is_llm(obj):
                    self._sink(node, "sql", first, fn_text, scope)
                return
            if (
                head_mod in ("fs", "node:fs", "fs/promises", "node:fs/promises", "fs-extra")
                and last in _FS_WRITE
            ):
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
        if fn.type == "identifier":
            if (
                self._module_of(fn_text) in ("fs", "node:fs", "fs/promises", "node:fs/promises")
                and self._export_of(fn_text) in _FS_WRITE
            ):
                self._sink(node, "file", first, fn_text, scope)
            elif fn_text in _HTTP_FUNCS or self._module_of(fn_text) in (
                "axios",
                "got",
                "undici",
                "node-fetch",
            ):
                self._sink(node, "ssrf", first, fn_text, scope)

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

    def _sink(self, node, kind: str, arg, label: str, scope: dict[str, Taint]) -> None:
        if arg is None:
            return
        if kind == "ssrf" and self._host_pinned(arg):
            return
        t = self._eval(arg, scope)
        if t is None or t["validated"] or kind not in t["kinds"]:
            return
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
                    f"{t['origin'][:1].upper()}{t['origin'][1:]} (line {t['line']}) reaches "
                    f"{label} without validation, so the response is {spec.phrase}."
                ),
                path=self.path,
                line=line,
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
                    "source": t["origin"],
                    "source_line": t["line"],
                    "owasp_llm_related": [LLM01],
                },
                in_test=self.in_test,
            )
        )


def analyze_js(data: bytes, root, path: str, in_test: bool) -> list[Finding]:
    return JsTaint(data, root, path, in_test).run()
