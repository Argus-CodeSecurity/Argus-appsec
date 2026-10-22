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
from argus.scanners._pyflow import (
    CMD_FN,
    CODE_FN,
    DESER_FN,
    NON_TAINT_SINKS,
    PATH_FN,
    SINK_CWES,
    SOURCE_RE,
    SQL_FN,
    UNIVERSAL_SANITIZERS,
    Flow,
    source_callables,
)

if TYPE_CHECKING:
    from argus.context import LanguageContext

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


#: Finding.metadata key on a placeholder finding for a flow that the project
#: context (a declared sanitizer or trusted source) cleared. The engine removes
#: these from the findings and lists them in the scan summary, so what the
#: context file suppressed stays reviewable.
CONTEXT_CLEARED_KEY = "context_cleared"


def language_context(ctx: ScannerContext, language: str) -> LanguageContext | None:
    """The trusted project context for ``language``, if the config carries one."""
    project_context = getattr(ctx.config, "context", None)
    if project_context is None:
        return None
    lc: LanguageContext | None = project_context.for_language(language)
    return lc


def marker(name: str, cwe: str) -> str:
    """Scope-set entry meaning "``name`` is sanitized for ``cwe``".

    The NUL byte cannot occur in an identifier, so markers never collide with
    the variable names stored in the same set.
    """
    return f"{name}\0{cwe}"


def run_with_context(
    make: Any,
    root: Any,
    text: str,
    context: LanguageContext | None,
    *,
    scanner_name: str,
    source: str,
) -> list[Finding]:
    """Run an analyzer with ``context`` and report what the context cleared.

    ``make(context)`` builds a fresh analyzer. Without a context (or when no
    configured name occurs in the file) this is a single plain run. Otherwise
    the file is analyzed twice, without and with the context, and each finding
    that only the plain run produced comes back as an INFO placeholder carrying
    :data:`CONTEXT_CLEARED_KEY`, naming the context entries seen in the file.
    """
    if context is None or not context.relevant(text):
        return list(make(None).run(root))
    with_ctx = list(make(context).run(root))
    kept = {(f.rule_id, f.location.start_line) for f in with_ctx}
    names = context.matched_names(text)
    for f in make(None).run(root):
        if (f.rule_id, f.location.start_line) in kept:
            continue
        f.severity = Severity.INFO
        f.tags.append("context-cleared")
        f.metadata[CONTEXT_CLEARED_KEY] = {
            "source": source,
            "scanner": scanner_name,
            "rule": f.rule_id,
            "path": f.location.path,
            "line": f.location.start_line,
            "why": "a sanitizer or trusted source declared in the project context "
            "removes the taint on this flow",
            "entries": names,
        }
        with_ctx.append(f)
    return with_ctx


# Untrusted-input sources, shared with the cross-file tier (see _pyflow).
_SOURCE_RE = SOURCE_RE
#: Kept for callers that used the old name; the flow engine owns the list now.
_SANITIZERS = set(UNIVERSAL_SANITIZERS)


@dataclass
class Sink:
    id: str
    fn: re.Pattern[str]  # matches the call's function text (e.g. "cursor.execute")
    cwe: list[str]
    owasp: list[str]
    title: str
    severity: Severity
    why: str
    attack: str
    impact: str
    fix: str
    references: list[str] = field(default_factory=list)
    confidence: Confidence = Confidence.HIGH


_INJECTION = ["A03:2021-Injection"]

SINKS: list[Sink] = [
    Sink(
        id="ast-sql-injection",
        fn=SQL_FN,
        cwe=["CWE-89"],
        owasp=_INJECTION,
        severity=Severity.HIGH,
        title="SQL injection (tainted value reaches a database query)",
        why="A value derived from untrusted input flows into a database query "
        "without parameterization, so input can change the query's structure.",
        attack="Supply `' OR '1'='1` (or a UNION/stacked query) in the tainted "
        "parameter to read or modify unintended rows.",
        impact="Unauthorized data access or modification, up to full database compromise.",
        fix="Use parameterized queries / bound parameters and never build SQL from "
        "input, even across intermediate variables.",
    ),
    Sink(
        id="ast-sql-string-building",
        fn=SQL_FN,
        cwe=["CWE-89"],
        owasp=_INJECTION,
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        title="SQL query built by string formatting from a non-constant value",
        why="The query passed to execute() is assembled with %, + , .format() or an "
        "f-string from a value that is not a constant. No untrusted source was traced "
        "to it in this file, but if the value can be influenced by a caller (a "
        "function parameter, a request elsewhere), the query structure can change.",
        attack="If any caller passes attacker-controlled text, inject SQL through it.",
        impact="Unauthorized data access or modification if the value is attacker-controlled.",
        fix="Pass values as bound parameters (execute(sql, params)) instead of "
        "formatting them into the SQL text.",
    ),
    Sink(
        id="ast-command-injection",
        fn=CMD_FN,
        cwe=["CWE-78"],
        owasp=_INJECTION,
        severity=Severity.HIGH,
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
        fn=PATH_FN,
        cwe=["CWE-22"],
        owasp=["A01:2021-Broken Access Control"],
        severity=Severity.MEDIUM,
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
        fn=CODE_FN,
        cwe=["CWE-95"],
        owasp=_INJECTION,
        severity=Severity.HIGH,
        title="Code injection (tainted value reaches eval/exec)",
        why="Untrusted input flows into eval/exec, which executes it as code.",
        attack="Provide a Python expression/statement in the tainted value.",
        impact="Remote code execution within the interpreter.",
        fix="Never eval/exec untrusted input; use a safe parser or explicit dispatch.",
    ),
    Sink(
        id="ast-unsafe-deserialization",
        fn=DESER_FN,
        cwe=["CWE-502"],
        owasp=["A08:2021-Software and Data Integrity Failures"],
        severity=Severity.HIGH,
        title="Unsafe deserialization of untrusted data",
        why="Untrusted input reaches pickle/marshal or yaml.load with an unsafe "
        "loader, which can construct arbitrary objects and run code while loading.",
        attack="Send a crafted pickle stream (a __reduce__ payload) or a YAML document "
        "with `!!python/object/apply` tags.",
        impact="Remote code execution.",
        fix="Never unpickle untrusted bytes; use JSON or yaml.safe_load with a schema.",
    ),
    Sink(
        id="ast-xss",
        fn=re.compile(r"(?:^|\.)(?:Markup|mark_safe|SafeString|SafeText|HttpResponse)$"),
        cwe=["CWE-79"],
        owasp=_INJECTION,
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        title="Cross-site scripting (tainted value returned as HTML)",
        why="A value derived from untrusted input is returned from a web view (or "
        "wrapped in Markup/mark_safe) without HTML escaping, so markup in the input "
        "is rendered by the browser.",
        attack="Send `<script>...</script>` (or an event-handler attribute) in the "
        "parameter and get a victim to open the link.",
        impact="Script execution in the victim's session: account takeover, data theft.",
        fix="Escape output (markupsafe.escape / html.escape), render through an "
        "autoescaping template, or return JSON.",
    ),
    Sink(
        id="ast-open-redirect",
        fn=re.compile(r"(?:^|\.)(?:redirect|HttpResponseRedirect|RedirectResponse)$"),
        cwe=["CWE-601"],
        owasp=["A01:2021-Broken Access Control"],
        severity=Severity.MEDIUM,
        title="Open redirect (tainted value used as a redirect target)",
        why="The redirect target comes from untrusted input without an allowlist "
        "check of the host, so the app can send users to any site.",
        attack="Craft a link to this app that redirects to a phishing page.",
        impact="Credible phishing and token leakage through the trusted domain.",
        fix="Redirect only to relative paths or to hosts on an allowlist "
        "(urlparse(target).netloc in ALLOWED), or use url_for().",
    ),
    Sink(
        id="ast-xxe",
        fn=re.compile(r"(?:^|\.)(?:parseString|parse|fromstring|XML|iterparse)$"),
        cwe=["CWE-611"],
        owasp=["A05:2021-Security Misconfiguration"],
        severity=Severity.HIGH,
        title="XML external entity injection (untrusted XML, entities enabled)",
        why="Untrusted XML is parsed by a parser that has external entity resolution "
        "turned on (feature_external_ges or resolve_entities=True).",
        attack='Submit a document with `<!ENTITY x SYSTEM "file:///etc/passwd">`.',
        impact="Local file disclosure, SSRF, or denial of service.",
        fix="Leave external entities disabled (the Python default) or parse with defusedxml.",
    ),
    Sink(
        id="ast-ldap-injection",
        fn=re.compile(r"(?:^|\.)search(?:_s|_st|_ext|_ext_s)?$"),
        cwe=["CWE-90"],
        owasp=_INJECTION,
        severity=Severity.HIGH,
        title="LDAP injection (tainted value in an LDAP search filter or base)",
        why="Untrusted input is placed into an LDAP filter or DN without escaping, so "
        "filter metacharacters can change the query.",
        attack="Send `*)(uid=*))(|(uid=*` to widen the filter and enumerate entries.",
        impact="Authentication bypass or disclosure of directory data.",
        fix="Escape values with ldap3.utils.conv.escape_filter_chars (or "
        "ldap.filter.escape_filter_chars) before building the filter.",
    ),
    Sink(
        id="ast-xpath-injection",
        fn=re.compile(r"(?:^|\.)(?:xpath|XPath|select|find|findall|iterfind|findtext)$"),
        cwe=["CWE-643"],
        owasp=_INJECTION,
        severity=Severity.HIGH,
        title="XPath injection (tainted value in an XPath expression)",
        why="Untrusted input is concatenated into an XPath expression, so quotes and "
        "operators in it can change what the query selects.",
        attack="Send `' or '1'='1` to select every node.",
        impact="Disclosure of XML data or authentication bypass.",
        fix="Use XPath variables (root.xpath(query, name=value)) instead of "
        "formatting values into the expression.",
    ),
    Sink(
        id="ast-trust-boundary",
        fn=re.compile(r"(?:^|\.)session$"),
        cwe=["CWE-501"],
        owasp=["A04:2021-Insecure Design"],
        severity=Severity.LOW,
        confidence=Confidence.MEDIUM,
        title="Trust boundary violation (untrusted value stored in the session)",
        why="Request data is written into the server-side session, where later code "
        "is likely to treat it as trusted, validated state.",
        attack="Plant a crafted value in the session through this request and have a "
        "later request act on it.",
        impact="Authorization or logic flaws in code that trusts session contents.",
        fix="Validate the value before storing it, and keep untrusted input apart "
        "from trusted session state.",
    ),
    Sink(
        id="ast-weak-random",
        fn=re.compile(r"^random\.\w+$"),
        cwe=["CWE-330", "CWE-338"],
        owasp=["A02:2021-Cryptographic Failures"],
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        title="Weak random number generator used for a security value",
        why="A value from the `random` module (a predictable Mersenne Twister) is "
        "used as a token, password, session or cookie value.",
        attack="Observe a few outputs, recover the generator state and predict the next tokens.",
        impact="Session hijacking, password-reset or token forgery.",
        fix="Use the secrets module (secrets.token_urlsafe, secrets.token_hex) or "
        "random.SystemRandom.",
    ),
]
_SINK_BY_ID = {s.id: s for s in SINKS}
if set(_SINK_BY_ID) != set(SINK_CWES):  # pragma: no cover - a coding error
    raise RuntimeError("every flow sink needs a catalog entry")

# Test/fixture paths, findings there are downgraded, matching the regex scanner.
from argus.scanners.patterns import _is_test_file  # noqa: E402  (shared helper)


@scanner
class ASTPythonScanner(Scanner):
    name = "ast-python"
    category = "sast"
    file_local = True
    description = (
        "Data-flow (taint) analysis for Python via tree-sitter; catches "
        "multi-hop injection the regex tier misses. Needs the [ast] extra."
    )

    def applies_to(self, project) -> bool:
        return is_available() and bool(project.files_matching("*.py"))

    def scan(self, ctx: ScannerContext) -> Iterable[Finding]:
        parser = _load_parser()
        if parser is None:
            return
        context = language_context(ctx, "python")
        source = getattr(getattr(ctx.config, "context", None), "source", "") or ""
        for f in ctx.project.files():
            if f.language != "Python" or f.is_probably_binary():
                continue
            src = f.text().encode("utf-8", "replace")
            if not src.strip():
                continue
            # One hostile or unparseable file must never sink the whole scanner:
            # analyze each file in isolation and note the ones that fail.
            in_test = _is_test_file(f.rel_path)
            try:
                tree = parser.parse(src)
                findings = run_with_context(
                    lambda c, src=src, path=f.rel_path, in_test=in_test: _Analyzer(
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


def node_location(path: str, src: bytes, node, lines: list[bytes] | None = None) -> Location:
    """A Location for a tree-sitter node: 1-based lines, 1-based columns.

    Columns follow the SARIF convention (``end_column`` is the column just past
    the last character) and count characters, not bytes. The snippet is the
    node's first source line with its indentation kept and only the line ending
    removed.
    """
    if lines is None:
        lines = src.splitlines()
    srow, scol = node.start_point
    erow, ecol = node.end_point
    first = lines[srow] if srow < len(lines) else b""
    last = lines[erow] if erow < len(lines) else b""
    start_col = len(first[:scol].decode("utf-8", "ignore")) + 1
    end_col = len(last[:ecol].decode("utf-8", "ignore")) + 1
    snippet = first.decode("utf-8", "ignore").rstrip("\r\n")[:240]
    return Location(
        path=path,
        start_line=srow + 1,
        end_line=erow + 1,
        start_column=start_col,
        end_column=end_col,
        snippet=snippet,
    )


class _Analyzer:
    """Runs the flow engine over one file and turns its reports into findings."""

    def __init__(
        self,
        src: bytes,
        path: str,
        in_test: bool,
        *,
        context: LanguageContext | None = None,
        source_methods: frozenset[str] = frozenset(),
        source_functions: frozenset[str] = frozenset(),
    ) -> None:
        self._src = src
        self._path = path
        self._in_test = in_test
        self._seen: set[tuple[str, int]] = set()  # (sink_id, line) de-dup within file
        self._lines: list[bytes] | None = None
        # Project context (trusted config only): extra sanitizers, some valid
        # only for particular CWEs, and sources that are not attacker-controlled.
        self._ctx = context
        self._extra_methods = source_methods
        self._extra_functions = source_functions
        self._findings: list[Finding] = []

    def run(self, root) -> list[Finding]:
        methods, functions = source_callables(self._src, root, self._ctx)
        flow = Flow(
            self._src,
            self._emit,
            context=self._ctx,
            source_methods=self._extra_methods | frozenset(methods),
            source_functions=self._extra_functions | frozenset(functions),
        )
        self._findings = []
        flow.run(root)
        return list(self._findings)

    def seeded_sinks(self, body, seed_names: set[str]) -> list[tuple[str, int]]:
        """Taint sinks reachable in ``body`` when ``seed_names`` start tainted.

        Used by the inter-procedural pass to decide which *parameters* of a
        function flow into a sink (seed each parameter, see what fires). Returns
        (sink_id, line) pairs. Does not touch this analyzer's findings.
        """
        found: list[tuple[str, int]] = []
        seen: set[tuple[str, int]] = set()

        def collect(sink_id: str, node) -> None:
            key = (sink_id, node.start_point[0] + 1)
            if sink_id not in NON_TAINT_SINKS and key not in seen:
                seen.add(key)
                found.append(key)

        Flow(self._src, collect, context=self._ctx).run_body(body, seed_names)
        return found

    def _emit(self, sink_id: str, node) -> None:
        line = node.start_point[0] + 1
        key = (sink_id, line)
        if key in self._seen:
            return
        self._seen.add(key)
        sink = _SINK_BY_ID[sink_id]
        self._findings.append(self._finding(sink, line, node))

    def _finding(self, sink: Sink, line: int, node) -> Finding:
        severity = sink.severity
        confidence = sink.confidence  # backed by real data flow, not a pattern
        tags = ["sast", "ast", "taint"]
        if self._in_test:
            severity = Severity(max(Severity.INFO, sink.severity - 1))
            confidence = Confidence.LOW
            tags.append("test-context")
        if self._lines is None:  # split once per file, not once per finding
            self._lines = self._src.splitlines()
        return Finding(
            id=f"{ASTPythonScanner.name}:{sink.id}:{self._path}:{line}",
            rule_id=f"{ASTPythonScanner.name}.{sink.id}",
            scanner=ASTPythonScanner.name,
            title=sink.title,
            description=sink.why,
            location=node_location(self._path, self._src, node, self._lines),
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


def line_verdicts(src: bytes, parser) -> dict[tuple[str, int], str]:
    """Per-line data-flow verdicts the regex tier uses to grade its findings.

    Keys are ``("deser", line)`` for pickle/marshal/unsafe yaml.load calls and
    ``("shell", line)`` for shell=True subprocess calls and os.system/os.popen;
    values say whether the payload argument is ``"tainted"``, built only from
    ``"literal"`` values, or of ``"unknown"`` origin.
    """
    root = parser.parse(src).root_node
    methods, functions = source_callables(src, root)
    flow = Flow(src, None, source_methods=frozenset(methods), source_functions=frozenset(functions))
    flow.run(root)
    return flow.verdicts
