"""AST-based taint analysis for Python (the precise SAST tier).

The regex ``patterns`` scanner is fast but line-anchored: it can follow a value
one hop from an input source into a sink, but not through a chain of assignments.
This scanner parses Python with tree-sitter and tracks tainted values through
multiple hops, so it catches injection that the regex tier misses:

    name  = request.args.get("user")   # source
    safe  = name                       # hop 1
    value = safe                       # hop 2
    cursor.execute("SELECT ... " + value)   # sink  -> reported here

It is **optional**: tree-sitter is an extra (``pip install "argus-appsec[ast]"``).
Without it the scanner reports as not-applicable and Argus falls back to the
regex tier, nothing breaks. Analysis here is intra-file and per-function-scope,
which keeps it fast and low-noise; a companion depth-1 cross-file/inter-procedural
tier lives in :mod:`argus.scanners.ast_python_interproc`, and deeper multi-hop
whole-program flow remains future work.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

from argus.core.models import (
    Confidence,
    Finding,
    Likelihood,
    Location,
    Remediation,
    Severity,
)
from argus.core.plugin import Scanner, ScannerContext, scanner

log = logging.getLogger("argus.scanners.ast")


def new_parser():
    """Build a fresh tree-sitter Python parser, or None if unavailable.

    A tree-sitter ``Parser`` is not safe to call from two threads at once, and
    scanners now run concurrently. Anything that parses on its own thread (e.g.
    the cross-file scanner) must take its **own** parser via this function rather
    than sharing the cached one below.
    """
    try:
        import tree_sitter_python as tspython
        from tree_sitter import Language
    except ImportError:
        return None
    return make_parser(Language(tspython.language()))


def make_parser(lang):
    """A tree-sitter ``Parser`` for ``lang`` on any supported binding version.

    tree-sitter >= 0.22 takes the language in the constructor. Older bindings
    construct an empty parser and set the language afterwards, through
    ``set_language()`` (removed in 0.22) or the ``language`` property.
    """
    from tree_sitter import Parser

    try:
        return Parser(lang)
    except TypeError:  # pragma: no cover - bindings older than 0.22
        parser = Parser()
        setter = getattr(parser, "set_language", None)
        if setter is not None:
            setter(lang)
        else:
            parser.language = lang
        return parser


def analysis_skipped_finding(scanner_name: str, path: str, exc: BaseException) -> Finding:
    """An INFO note that one file could not be analyzed.

    A file that breaks the parser or the analysis (e.g. pathologically deep
    nesting) is skipped on its own instead of failing the whole scanner, and
    this note keeps the gap visible in the report rather than silent.
    """
    log.warning("%s: skipped %s (%s)", scanner_name, path, type(exc).__name__)
    return Finding(
        id=f"{scanner_name}:analysis-skipped:{path}",
        rule_id=f"{scanner_name}.analysis-skipped",
        scanner=scanner_name,
        title="File skipped by AST analysis",
        description=(
            f"{scanner_name} could not analyze this file ({type(exc).__name__}), so "
            "data-flow issues in it are not covered by this scan. The regex tier "
            "still ran on it. Unusually deep nesting is a common cause."
        ),
        location=Location(path=path),
        severity=Severity.INFO,
        confidence=Confidence.LOW,
        likelihood=Likelihood.UNLIKELY,
        remediation=Remediation(
            summary="Review this file manually or simplify its structure.",
        ),
        tags=["sast", "ast", "analysis-gap"],
        metadata={"error": type(exc).__name__},
    )


@lru_cache(maxsize=1)
def _load_parser():
    """Shared, cached parser for the single-threaded intra-file scanner.

    Only the ``ast-python`` scanner uses this, and its ``scan`` walks files
    sequentially on one worker thread, so a single shared instance is safe here.
    """
    return new_parser()


def is_available() -> bool:
    return _load_parser() is not None


# Untrusted-input sources: an expression mentioning one of these is tainted.
_SOURCE_RE = re.compile(
    r"\brequest\.(args|form|values|json|data|files|cookies|headers|query_params|GET|POST)\b"
    r"|\binput\s*\("
    r"|\bsys\.argv\b"
    r"|\bflask\.request\b"
    r"|\bos\.environ\b"
)
# Function-name last components that neutralize taint (numeric coercion, quoting,
# path basename, HTML escaping). Keyed on the final identifier of the call target.
_SANITIZERS = {
    "int", "float", "bool", "secure_filename", "basename", "quote", "escape",
    "safe_join", "quote_plus", "shlex",
}


@dataclass
class Sink:
    id: str
    fn: re.Pattern[str]     # matches the call's function text (e.g. "cursor.execute")
    cwe: list[str]
    owasp: list[str]
    title: str
    severity: Severity
    why: str
    attack: str
    impact: str
    fix: str
    references: list[str] = field(default_factory=list)


SINKS: list[Sink] = [
    Sink(
        id="ast-sql-injection",
        fn=re.compile(r"(^|\.)(execute|executemany|executescript)$"),
        cwe=["CWE-89"], owasp=["A03:2021-Injection"], severity=Severity.HIGH,
        title="SQL injection (tainted value reaches a database query)",
        why="A value derived from untrusted input flows into a database query "
            "without parameterization, so input can change the query's structure.",
        attack="Supply `' OR '1'='1` (or a UNION/stacked query) in the tainted "
               "parameter to read or modify unintended rows.",
        impact="Unauthorized data access or modification, up to full database "
               "compromise.",
        fix="Use parameterized queries / bound parameters and never build SQL from "
            "input, even across intermediate variables.",
    ),
    Sink(
        id="ast-command-injection",
        fn=re.compile(r"(^|\.)system$|(^|\.)popen$|^subprocess\.\w+$"),
        cwe=["CWE-78"], owasp=["A03:2021-Injection"], severity=Severity.HIGH,
        title="OS command injection (tainted value reaches a shell command)",
        why="A value derived from untrusted input flows into a command executed by "
            "the OS/shell, so shell metacharacters can inject additional commands.",
        attack="Inject `; rm -rf` or `$(...)` through the tainted parameter to run "
               "arbitrary commands.",
        impact="Remote code execution on the host.",
        fix="Pass arguments as a list without a shell, and validate/quote input.",
    ),
    Sink(
        id="ast-path-traversal",
        fn=re.compile(r"(^|\.)open$|send_file$|send_from_directory$"),
        cwe=["CWE-22"], owasp=["A01:2021-Broken Access Control"], severity=Severity.MEDIUM,
        title="Path traversal (tainted value reaches a file operation)",
        why="A filesystem path derived from untrusted input reaches a file operation "
            "without normalization, so `../` can escape the intended directory.",
        attack="Request a path such as `../../etc/passwd` to read or write files "
               "outside the intended location.",
        impact="Disclosure of sensitive files, or writing outside the intended area.",
        fix="Resolve the path and confirm it stays within an allowed base directory "
            "(e.g. os.path.realpath + prefix check, or secure_filename).",
    ),
    Sink(
        id="ast-code-injection",
        fn=re.compile(r"^(eval|exec)$"),
        cwe=["CWE-95"], owasp=["A03:2021-Injection"], severity=Severity.HIGH,
        title="Code injection (tainted value reaches eval/exec)",
        why="Untrusted input flows into eval/exec, which executes it as code.",
        attack="Provide a Python expression/statement in the tainted value.",
        impact="Remote code execution within the interpreter.",
        fix="Never eval/exec untrusted input; use a safe parser or explicit dispatch.",
    ),
]

# Test/fixture paths, findings there are downgraded, matching the regex scanner.
from argus.scanners.patterns import _is_test_file  # noqa: E402  (shared helper)


@scanner
class ASTPythonScanner(Scanner):
    name = "ast-python"
    category = "sast"
    file_local = True
    description = ("Data-flow (taint) analysis for Python via tree-sitter; catches "
                   "multi-hop injection the regex tier misses. Needs the [ast] extra.")

    def applies_to(self, project) -> bool:
        return is_available() and bool(project.files_matching("*.py"))

    def scan(self, ctx: ScannerContext) -> Iterable[Finding]:
        parser = _load_parser()
        if parser is None:
            return
        for f in ctx.project.files():
            if f.language != "Python" or f.is_probably_binary():
                continue
            src = f.text().encode("utf-8", "replace")
            if not src.strip():
                continue
            # One hostile or unparseable file must never sink the whole scanner:
            # analyze each file in isolation and note the ones that fail.
            try:
                tree = parser.parse(src)
                analyzer = _Analyzer(src, f.rel_path, _is_test_file(f.rel_path))
                findings = list(analyzer.run(tree.root_node))
            except Exception as exc:
                yield analysis_skipped_finding(self.name, f.rel_path, exc)
                continue
            yield from findings


class _Analyzer:
    """Intra-file, per-function-scope taint walk over a Python AST."""

    def __init__(self, src: bytes, path: str, in_test: bool) -> None:
        self._src = src
        self._path = path
        self._in_test = in_test
        self._seen: set[tuple[str, int]] = set()  # (sink_id, line) de-dup within file
        self._lines: list[str] | None = None

    def run(self, root) -> Iterable[Finding]:
        yield from self._walk(root, set())

    def seeded_sinks(self, body, seed_names: set[str]) -> list[tuple[str, int]]:
        """Sinks reachable in ``body`` when ``seed_names`` start tainted.

        Used by the inter-procedural pass to decide which *parameters* of a
        function flow into a sink (seed each parameter, see what fires). Returns
        (sink_id, line) pairs. Does not mutate this analyzer's dedup state.
        """
        saved = self._seen
        self._seen = set()
        try:
            found = [(f.rule_id.split(".", 1)[-1], f.location.start_line or 0)
                     for f in self._walk(body, set(seed_names))]
        finally:
            self._seen = saved
        return found

    # --- traversal ----------------------------------------------------------
    # All walks use an explicit stack, not recursion: a file with a few thousand
    # levels of nesting would otherwise raise RecursionError. Children are pushed
    # in reverse so nodes are visited in the same pre-order as a recursive walk,
    # which matters because assignments update the shared taint set as they go.
    def _walk(self, root, tainted: set[str]) -> Iterable[Finding]:
        stack: list[tuple[Any, set[str]]] = [(root, tainted)]
        while stack:
            node, scope = stack.pop()
            t = node.type
            if t == "function_definition":
                body = node.child_by_field_name("body")
                if body is not None:
                    stack.append((body, set()))   # fresh scope per function
                continue
            if t in ("assignment", "augmented_assignment"):
                self._apply_assignment(node, scope, augmented=(t == "augmented_assignment"))
                right = node.child_by_field_name("right")
                if right is not None:
                    stack.append((right, scope))  # catch sinks on the RHS too
                continue
            if t == "call":
                finding = self._check_sink(node, scope)
                if finding is not None:
                    yield finding
            stack.extend((child, scope) for child in reversed(node.children))

    # --- taint rules --------------------------------------------------------
    def _apply_assignment(self, node, tainted: set[str], *, augmented: bool) -> None:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None:
            return
        names = self._target_names(left)
        if self._tainted(right, tainted):
            tainted.update(names)
        elif not augmented:
            tainted.difference_update(names)  # reassigned to a clean value

    def _tainted(self, node, tainted: set[str]) -> bool:
        if node.type == "call" and self._is_sanitizer(node):
            return False
        text = self._text(node)
        if _SOURCE_RE.search(text):
            return True
        if node.type == "identifier":
            return text in tainted
        # The source pattern was just checked against the whole subtree's text,
        # and a descendant's text is a token-aligned slice of it, so below this
        # point only tainted identifiers can still match. Checking just those
        # keeps this linear in the subtree; re-running the regex on every
        # descendant was quadratic in the nesting depth.
        stack = list(node.children)
        while stack:
            child = stack.pop()
            if child.type == "call" and self._is_sanitizer(child):
                continue
            if child.type == "identifier" and self._text(child) in tainted:
                return True
            stack.extend(child.children)
        return False

    def _check_sink(self, call, tainted: set[str]) -> Finding | None:
        fn_node = call.child_by_field_name("function")
        if fn_node is None:
            return None
        fn_text = self._text(fn_node)
        sink = next((s for s in SINKS if s.fn.search(fn_text)), None)
        if sink is None:
            return None
        args = call.child_by_field_name("arguments")
        if args is None:
            return None
        named = args.named_children
        # For SQL sinks, only the first argument (the query string) is dangerous.
        # A tainted value in a later argument is a bound parameter, i.e. the safe,
        # parameterized form `execute("... %s", (uid,))`, and must NOT be flagged.
        to_check = named[:1] if sink.id == "ast-sql-injection" else named
        if not any(self._tainted(a, tainted) for a in to_check):
            return None
        line = call.start_point[0] + 1
        key = (sink.id, line)
        if key in self._seen:
            return None
        self._seen.add(key)
        return self._finding(sink, line, call)

    # --- helpers ------------------------------------------------------------
    def _is_sanitizer(self, call) -> bool:
        fn = call.child_by_field_name("function")
        if fn is None:
            return False
        last = self._text(fn).rsplit(".", 1)[-1]
        return last in _SANITIZERS

    def _target_names(self, left) -> set[str]:
        """Identifier names assigned by an LHS (handles simple and tuple targets)."""
        names: set[str] = set()
        stack = [left]
        while stack:
            node = stack.pop()
            if node.type == "identifier":
                names.add(self._text(node))
            else:
                stack.extend(node.children)
        return names

    def _text(self, node) -> str:
        return self._src[node.start_byte:node.end_byte].decode("utf-8", "ignore")

    def _line_text(self, line: int) -> str:
        if self._lines is None:  # split once per file, not once per finding
            self._lines = self._src.decode("utf-8", "ignore").splitlines()
        try:
            return self._lines[line - 1].strip()
        except IndexError:  # pragma: no cover
            return ""

    def _finding(self, sink: Sink, line: int, call) -> Finding:
        severity = sink.severity
        confidence = Confidence.HIGH  # backed by real data flow, not a pattern
        tags = ["sast", "ast", "taint"]
        if self._in_test:
            severity = Severity(max(Severity.INFO, sink.severity - 1))
            confidence = Confidence.LOW
            tags.append("test-context")
        return Finding(
            id=f"{ASTPythonScanner.name}:{sink.id}:{self._path}:{line}",
            rule_id=f"{ASTPythonScanner.name}.{sink.id}",
            scanner=ASTPythonScanner.name,
            title=sink.title,
            description=sink.why,
            location=Location(path=self._path, start_line=line,
                              snippet=self._line_text(line)[:240]),
            severity=severity, confidence=confidence, likelihood=Likelihood.LIKELY,
            cwe=sink.cwe, owasp=sink.owasp,
            why_vulnerable=sink.why,
            attacker_perspective=sink.attack,
            business_impact=sink.impact,
            remediation=Remediation(
                summary=sink.fix, guidance=sink.fix,
                references=sink.references or [
                    f"https://cwe.mitre.org/data/definitions/{sink.cwe[0].split('-')[1]}.html"
                ],
            ),
            tags=tags,
            metadata={"analysis": "taint-dataflow"},
        )
