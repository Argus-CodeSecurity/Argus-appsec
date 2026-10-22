"""AST-based taint analysis for JavaScript and TypeScript.

The regex tier's JS rules (``.innerHTML =``, SQL-ish concatenation) fire on the
*shape* of the code and can't tell tainted input from safe values, the classic
source of false positives on real Node/TS apps. This scanner parses JS/TS/TSX
with tree-sitter and tracks untrusted input through variable assignments into
sinks, so it flags an issue only when tainted data actually reaches it.

Precision decisions that matter on real code:

* **Parameterized queries are safe.** For SQL sinks only the *first* argument (the
  query text) is checked. ``db.query('... WHERE id = ?', [userId])`` is NOT
  flagged, the taint is in the bound-parameters array, not the query string.
* **Sanitizers clear taint**, ``DOMPurify.sanitize``, ``encodeURIComponent``,
  ``Number()``/``parseInt`` (numeric coercion), ``escape``, ``validator.*``.
* **Per-function scope** so a tainted variable in one handler doesn't leak into
  another.

Optional via ``pip install "argus-appsec[ast]"``. Without tree-sitter the scanner
reports not-applicable and Argus falls back to the regex tier.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from functools import lru_cache
from typing import TYPE_CHECKING, Any

from argus.core.models import (
    Confidence,
    Finding,
    Likelihood,
    Location,
    Remediation,
    Severity,
)
from argus.core.plugin import Scanner, ScannerContext, scanner
from argus.scanners.ast_python import (
    analysis_skipped_finding,
    language_context,
    make_parser,
    marker,
    node_location,
    run_with_context,
)
from argus.scanners.patterns import _is_test_file  # shared test-path helper

if TYPE_CHECKING:
    from argus.context import LanguageContext

# File extension -> tree-sitter language module + factory attribute.
_LANGS = {
    "javascript": ("tree_sitter_javascript", "language", {".js", ".jsx", ".mjs", ".cjs"}),
    "typescript": ("tree_sitter_typescript", "language_typescript", {".ts", ".mts", ".cts"}),
    "tsx": ("tree_sitter_typescript", "language_tsx", {".tsx"}),
}


@lru_cache(maxsize=1)
def _load_parsers():
    """Return {lang_name: Parser} for JS/TS/TSX, or None if tree-sitter is absent."""
    try:
        import importlib

        from tree_sitter import Language
    except ImportError:
        return None
    parsers = {}
    for name, (module, factory, _exts) in _LANGS.items():
        try:
            mod = importlib.import_module(module)
            lang = Language(getattr(mod, factory)())
            parsers[name] = make_parser(lang)
        except Exception:  # a missing grammar shouldn't disable the others
            continue
    return parsers or None


def is_available() -> bool:
    return _load_parsers() is not None


def _lang_for(suffix: str) -> str | None:
    for name, (_m, _f, exts) in _LANGS.items():
        if suffix in exts:
            return name
    return None


# Untrusted-input sources (Express/Koa/browser). A member expression or call
# mentioning one of these taints the value.
_SOURCE_RE = re.compile(
    r"\breq(uest)?\.(query|body|params|headers|cookies|get)\b"
    r"|\bctx\.(query|request|params|headers)\b"
    r"|\blocation\.(search|hash|href|pathname)\b"
    r"|\bdocument\.(URL|documentURI|referrer|cookie)\b"
    r"|\bwindow\.name\b"
    r"|\bprocess\.(argv|env)\b"
)
# Function-name last components that neutralize taint. NB: toString() is *not*
# a sanitizer -- `userInput.toString()` still yields attacker-controlled text and
# does nothing against XSS/injection, so listing it here would clear taint that
# is still live.
_SANITIZERS = {
    "parseInt",
    "parseFloat",
    "Number",
    "encodeURIComponent",
    "encodeURI",
    "escape",
    "sanitize",
    "escapeHtml",
    "sanitizeHtml",
    "quote",
}


@dataclass
class Sink:
    id: str
    #: matches the call's function text (identifier or member expression)
    fn: re.Pattern[str]
    cwe: list[str]
    owasp: list[str]
    title: str
    severity: Severity
    why: str
    attack: str
    impact: str
    fix: str
    #: which arguments to treat as the payload: "first" or "rest" (all but first)
    args: str = "first"
    references: list[str] = field(default_factory=list)


CALL_SINKS: list[Sink] = [
    Sink(
        id="ast-sql-injection",
        fn=re.compile(r"(^|\.)(query|execute|executeQuery|raw|unsafe)$"),
        cwe=["CWE-89"],
        owasp=["A03:2021-Injection"],
        severity=Severity.HIGH,
        title="SQL injection (tainted value concatenated into a query)",
        why="Untrusted input is built into the SQL query string, so it can change "
        "the query's structure. (Parameterized queries with bound values are "
        "not flagged.)",
        attack="Supply `' OR '1'='1` or a stacked query in the tainted parameter.",
        impact="Unauthorized data access or modification, up to full DB compromise.",
        fix="Use parameterized queries / bound placeholders (e.g. "
        "query('... WHERE id = ?', [id])) instead of string concatenation.",
        args="first",  # only the query text; params array is the safe path
    ),
    Sink(
        id="ast-command-injection",
        fn=re.compile(r"(^|\.)(execSync|spawnSync)$"),
        cwe=["CWE-78"],
        owasp=["A03:2021-Injection"],
        severity=Severity.HIGH,
        title="OS command injection (tainted value reaches a shell command)",
        why="Untrusted input reaches child_process exec, which runs it via the shell.",
        attack="Inject `; rm -rf` or `$(...)` through the tainted parameter.",
        impact="Remote code execution on the host.",
        fix="Use execFile/spawn with an argument array (no shell) and validate input.",
    ),
    Sink(
        id="ast-path-traversal",
        fn=re.compile(
            r"(^|\.)(readFile|readFileSync|createReadStream|sendFile|"
            r"writeFile|writeFileSync)$"
        ),
        cwe=["CWE-22"],
        owasp=["A01:2021-Broken Access Control"],
        severity=Severity.MEDIUM,
        title="Path traversal (tainted value reaches a file operation)",
        why="A filesystem path built from untrusted input reaches a file API without "
        "normalization, so `../` can escape the intended directory.",
        attack="Request a path such as `../../etc/passwd`.",
        impact="Disclosure of sensitive files, or writing outside the intended area.",
        fix="Resolve the path and confirm it stays within an allowed base directory "
        "(path.resolve + prefix check), or use a vetted sanitizer.",
    ),
    Sink(
        id="ast-code-injection",
        # Prefix is required (not optional): eval/Function must be the whole name
        # or a real member access (.eval). The old optional `(^|\.)?` also matched
        # names merely ending in the word -- retrieval, myFunction, medieval.
        fn=re.compile(r"(^|\.)(eval|Function)$"),
        cwe=["CWE-95"],
        owasp=["A03:2021-Injection"],
        severity=Severity.HIGH,
        title="Code injection (tainted value reaches eval/Function)",
        why="Untrusted input flows into eval or the Function constructor, which "
        "execute it as code.",
        attack="Provide a JavaScript expression in the tainted value.",
        impact="Remote code execution in the JS runtime.",
        fix="Never eval untrusted input; use JSON.parse or an explicit dispatch.",
    ),
    Sink(
        id="ast-xss",
        fn=re.compile(r"(^|\.)(write|insertAdjacentHTML)$"),
        cwe=["CWE-79"],
        owasp=["A03:2021-Injection"],
        severity=Severity.MEDIUM,
        title="Cross-site scripting (tainted value written as HTML)",
        why="Untrusted input is written to the document as HTML, so an attacker's "
        "markup/script executes in the victim's browser.",
        attack="Get the app to render an attacker-controlled string containing "
        "`<script>` or an event handler.",
        impact="Session theft and actions performed as the victim.",
        fix="Use textContent, a framework-escaped binding, or sanitize with a vetted "
        "library (DOMPurify) before inserting HTML.",
        args="rest",  # insertAdjacentHTML(position, html): the payload is not first
    ),
]

# XSS via assignment to a DOM HTML property (el.innerHTML = tainted).
_HTML_SINK_PROPS = {"innerHTML", "outerHTML"}
_XSS_CWES = frozenset(("CWE-79",))


@scanner
class ASTJsScanner(Scanner):
    name = "ast-js"
    category = "sast"
    file_local = True
    description = (
        "Data-flow (taint) analysis for JavaScript/TypeScript via "
        "tree-sitter; multi-hop injection/XSS the regex tier misses. "
        "Needs the [ast] extra."
    )

    def applies_to(self, project) -> bool:
        return is_available() and bool(
            project.files_matching(
                "*.js", "*.jsx", "*.mjs", "*.cjs", "*.ts", "*.tsx", "*.mts", "*.cts"
            )
        )

    def scan(self, ctx: ScannerContext) -> Iterable[Finding]:
        parsers = _load_parsers()
        if not parsers:
            return
        context = language_context(ctx, "javascript")
        source = getattr(getattr(ctx.config, "context", None), "source", "") or ""
        for f in ctx.project.files():
            lang = _lang_for(f.suffix)
            if lang is None or lang not in parsers or f.is_probably_binary():
                continue
            src = f.text().encode("utf-8", "replace")
            if not src.strip():
                continue
            # Per-file isolation: one hostile file is skipped and noted, it does
            # not take the findings for every other file down with it.
            in_test = _is_test_file(f.rel_path)
            try:
                tree = parsers[lang].parse(src)
                findings = run_with_context(
                    lambda c, src=src, path=f.rel_path, in_test=in_test: _JsAnalyzer(
                        src, path, in_test, context=c
                    ),
                    tree.root_node,
                    f.text(),
                    context,
                    scanner_name=self.name,
                    source=source,
                )
            except Exception as exc:
                yield analysis_skipped_finding(self.name, f.rel_path, exc)
                continue
            yield from findings


_FUNCTION_NODES = {
    "function_declaration",
    "function_expression",
    "arrow_function",
    "method_definition",
    "generator_function",
    "generator_function_declaration",
}


class _JsAnalyzer:
    def __init__(
        self,
        src: bytes,
        path: str,
        in_test: bool,
        *,
        context: LanguageContext | None = None,
    ) -> None:
        self._src = src
        self._path = path
        self._in_test = in_test
        self._seen: set[tuple[str, int]] = set()
        self._lines: list[bytes] | None = None
        # Project context (trusted config only); see ast_python._Analyzer.
        self._ctx = context
        self._ctx_cwes: tuple[str, ...] = tuple(sorted(context.cwes)) if context else ()

    def run(self, root) -> Iterable[Finding]:
        yield from self._walk(root, set())

    def _walk(self, root, tainted: set[str]) -> Iterable[Finding]:
        # Explicit stack instead of recursion (deeply nested input would raise
        # RecursionError); children are pushed in reverse to keep the pre-order
        # the taint updates depend on.
        stack: list[tuple[Any, set[str]]] = [(root, tainted)]
        while stack:
            node, scope = stack.pop()
            t = node.type
            if t in _FUNCTION_NODES:
                body = node.child_by_field_name("body")
                if body is not None:
                    stack.append((body, set()))  # fresh per-function scope
                continue
            if t == "variable_declarator":
                self._handle_decl(node, scope)
                value = node.child_by_field_name("value")
                if value is not None:
                    stack.append((value, scope))
                continue
            if t == "assignment_expression":
                finding = self._handle_assignment(node, scope)
                if finding is not None:
                    yield finding
                right = node.child_by_field_name("right")
                if right is not None:
                    stack.append((right, scope))
                continue
            if t == "call_expression":
                finding = self._check_call_sink(node, scope)
                if finding is not None:
                    yield finding
            stack.extend((child, scope) for child in reversed(node.children))

    # --- taint propagation --------------------------------------------------
    def _handle_decl(self, node, tainted: set[str]) -> None:
        name = node.child_by_field_name("name")
        value = node.child_by_field_name("value")
        if name is None or value is None or name.type != "identifier":
            return
        self._assign(self._text(name), value, tainted)

    def _handle_assignment(self, node, tainted: set[str]) -> Finding | None:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None:
            return None
        # XSS: el.innerHTML = <tainted>
        if left.type == "member_expression":
            prop = left.child_by_field_name("property")
            if (
                prop is not None
                and self._text(prop) in _HTML_SINK_PROPS
                and self._tainted(right, tainted, _XSS_CWES)
            ):
                return self._html_assignment_finding(node)
        # Taint update for a plain identifier target.
        if left.type == "identifier":
            self._assign(self._text(left), right, tainted)
        return None

    def _assign(self, ident: str, value, tainted: set[str]) -> None:
        """Update ``ident``'s taint (and per-CWE sanitized markers) from ``value``."""
        if self._tainted(value, tainted):
            # Computed before the scope changes: `x = x + y` reads x's markers.
            clean_for = [
                c for c in self._ctx_cwes if not self._tainted(value, tainted, frozenset((c,)))
            ]
            tainted.difference_update(marker(ident, c) for c in self._ctx_cwes)
            tainted.add(ident)
            tainted.update(marker(ident, c) for c in clean_for)
        else:
            tainted.discard(ident)
            tainted.difference_update(marker(ident, c) for c in self._ctx_cwes)

    def _ident_tainted(self, name: str, tainted: set[str], cwes: frozenset[str] | None) -> bool:
        if name not in tainted:
            return False
        return not (cwes and any(marker(name, c) in tainted for c in cwes))

    def _source(self, text: str) -> bool:
        if self._ctx is not None:
            text = self._ctx.mask_trusted(text)
        return bool(_SOURCE_RE.search(text))

    def _tainted(self, node, tainted: set[str], cwes: frozenset[str] | None = None) -> bool:
        """Whether ``node`` carries taint into a sink of ``cwes`` (None: any sink)."""
        if node.type == "call_expression" and self._is_sanitizer(node, cwes):
            return False
        text = self._text(node)
        if self._source(text):
            return True
        if node.type == "identifier":
            return self._ident_tainted(text, tainted, cwes)
        # Below the root only tainted identifiers can still match (a
        # descendant's text is a token-aligned slice of the text just checked),
        # so walk for those alone; see ast_python._Analyzer._tainted.
        stack = list(node.children)
        while stack:
            child = stack.pop()
            if child.type == "call_expression" and self._is_sanitizer(child, cwes):
                continue
            if child.type == "identifier" and self._ident_tainted(self._text(child), tainted, cwes):
                return True
            stack.extend(child.children)
        return False

    # --- sinks --------------------------------------------------------------
    def _check_call_sink(self, call, tainted: set[str]) -> Finding | None:
        fn = call.child_by_field_name("function")
        if fn is None:
            return None
        fn_text = self._text(fn)
        sink = next((s for s in CALL_SINKS if s.fn.search(fn_text)), None)
        if sink is None:
            # child_process.exec, not RegExp.prototype.exec
            if fn.type == "member_expression" and self._text(fn).endswith(".exec"):
                obj = fn.child_by_field_name("object")
                obj_text = self._text(obj) if obj else ""
                if obj is not None and obj.type == "regex":
                    return None
                if "child_process" not in obj_text and obj_text not in ("cp", "childProcess"):
                    return None
                sink = next(s for s in CALL_SINKS if s.id == "ast-command-injection")
            else:
                return None
        args = call.child_by_field_name("arguments")
        if args is None:
            return None
        payload = list(args.named_children)
        if sink.args == "first":
            payload = payload[:1]
        elif sink.args == "rest":
            payload = payload[1:]
        cwes = frozenset(sink.cwe)
        if not any(self._tainted(a, tainted, cwes) for a in payload):
            return None
        return self._finding(sink, call.start_point[0] + 1, call)

    def _html_assignment_finding(self, node) -> Finding | None:
        line = node.start_point[0] + 1
        sink = Sink(
            id="ast-xss",
            fn=re.compile(""),
            cwe=["CWE-79"],
            owasp=["A03:2021-Injection"],
            severity=Severity.MEDIUM,
            title="Cross-site scripting (tainted value assigned to innerHTML)",
            why="Untrusted input is assigned to an element's HTML, so attacker "
            "markup/script executes in the victim's browser.",
            attack="Render an attacker-controlled string containing `<script>` or an "
            "event-handler attribute.",
            impact="Session theft and actions performed as the victim.",
            fix="Use textContent or sanitize with a vetted library (DOMPurify) before "
            "assigning HTML.",
        )
        return self._finding(sink, line, node)

    # --- helpers ------------------------------------------------------------
    def _is_sanitizer(self, call, cwes: frozenset[str] | None = None) -> bool:
        fn = call.child_by_field_name("function")
        if fn is None:
            return False
        fn_text = self._text(fn)
        if fn_text.rsplit(".", 1)[-1] in _SANITIZERS:
            return True
        return self._ctx is not None and self._ctx.clears(fn_text, cwes)

    def _text(self, node) -> str:
        return self._src[node.start_byte : node.end_byte].decode("utf-8", "ignore")

    def _location(self, node) -> Location:
        if self._lines is None:  # split once per file, not once per finding
            self._lines = self._src.splitlines()
        return node_location(self._path, self._src, node, self._lines)

    def _finding(self, sink: Sink, line: int, node) -> Finding | None:
        key = (sink.id, line)
        if key in self._seen:
            return None
        self._seen.add(key)
        severity = sink.severity
        confidence = Confidence.HIGH
        tags = ["sast", "ast", "taint"]
        if self._in_test:
            severity = Severity(max(Severity.INFO, sink.severity - 1))
            confidence = Confidence.LOW
            tags.append("test-context")
        return Finding(
            id=f"{ASTJsScanner.name}:{sink.id}:{self._path}:{line}",
            rule_id=f"{ASTJsScanner.name}.{sink.id}",
            scanner=ASTJsScanner.name,
            title=sink.title,
            description=sink.why,
            location=self._location(node),
            severity=severity,
            confidence=confidence,
            likelihood=Likelihood.LIKELY,
            cwe=sink.cwe,
            owasp=sink.owasp,
            why_vulnerable=sink.why,
            attacker_perspective=sink.attack,
            business_impact=sink.impact,
            remediation=Remediation(
                summary=sink.fix,
                guidance=sink.fix,
                references=sink.references
                or [f"https://cwe.mitre.org/data/definitions/{sink.cwe[0].split('-')[1]}.html"],
            ),
            tags=tags,
            metadata={"analysis": "taint-dataflow"},
        )
