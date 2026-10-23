"""Shared tree-sitter plumbing for the LLM / agent security rules.

The ``llm`` scanner's precise rules (model output into a sink, excessive agent
tools, system-prompt construction) all parse Python with tree-sitter and need
the same few things: a parser owned by this scanner, the file's import aliases
so a call can be resolved to the package it really comes from, the in-file
Pydantic models (to tell a schema that constrains a value from one that does
not), and one way to build a finding. They live here so each rule module stays
about its rule.

Parsers are per thread. A tree-sitter ``Parser`` must not be used from two
threads at once, and the engine runs scanners concurrently, so this module never
shares the parser cached by :mod:`nephilex.scanners.ast_python` or
:mod:`nephilex.scanners.ast_js`.
"""

from __future__ import annotations

import re
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from nephilex.core.models import (
    Confidence,
    Finding,
    Likelihood,
    Location,
    Remediation,
    Severity,
)

SCANNER_NAME = "llm"

# OWASP Top 10 for LLM Applications 2025 ids, as listed on
# https://genai.owasp.org/llm-top-10/ (verified 2026-10).
LLM01 = "LLM01:2025-Prompt Injection"
LLM02 = "LLM02:2025-Sensitive Information Disclosure"
LLM03 = "LLM03:2025-Supply Chain"
LLM05 = "LLM05:2025-Improper Output Handling"
LLM06 = "LLM06:2025-Excessive Agency"
LLM07 = "LLM07:2025-System Prompt Leakage"

OWASP_URLS = {
    LLM01: "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
    LLM02: "https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/",
    LLM03: "https://genai.owasp.org/llmrisk/llm032025-supply-chain/",
    LLM05: "https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/",
    LLM06: "https://genai.owasp.org/llmrisk/llm062025-excessive-agency/",
    LLM07: "https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/",
}

_local = threading.local()


def python_parser():
    """This thread's tree-sitter Python parser, or None without the [ast] extra."""
    if not hasattr(_local, "py"):
        from nephilex.scanners.ast_python import new_parser

        _local.py = new_parser()
    return _local.py


_JS_GRAMMARS = {
    ".js": ("tree_sitter_javascript", "language"),
    ".jsx": ("tree_sitter_javascript", "language"),
    ".mjs": ("tree_sitter_javascript", "language"),
    ".cjs": ("tree_sitter_javascript", "language"),
    ".ts": ("tree_sitter_typescript", "language_typescript"),
    ".mts": ("tree_sitter_typescript", "language_typescript"),
    ".cts": ("tree_sitter_typescript", "language_typescript"),
    ".tsx": ("tree_sitter_typescript", "language_tsx"),
}


def js_parser(suffix: str):
    """This thread's tree-sitter parser for a JS/TS file suffix, or None."""
    spec = _JS_GRAMMARS.get(suffix)
    if spec is None:
        return None
    cache: dict[tuple[str, str], Any] = getattr(_local, "js", None) or {}
    _local.js = cache
    if spec not in cache:
        try:
            import importlib

            from tree_sitter import Language

            from nephilex.scanners.ast_python import make_parser

            mod = importlib.import_module(spec[0])
            cache[spec] = make_parser(Language(getattr(mod, spec[1])()))
        except Exception:  # missing grammar or binding: this language is skipped
            cache[spec] = None
    return cache[spec]


def ast_available() -> bool:
    return python_parser() is not None


# --- node helpers ----------------------------------------------------------


class Src:
    """Source bytes plus cheap node-text and line accessors."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self._lines: list[bytes] | None = None

    def text(self, node) -> str:
        return self.data[node.start_byte : node.end_byte].decode("utf-8", "ignore")

    def _byte_lines(self) -> list[bytes]:
        # Split on "\n" only, the way tree-sitter counts rows, so line numbers
        # and columns agree with node positions.
        if self._lines is None:
            self._lines = self.data.split(b"\n")
        return self._lines

    def line_text(self, line: int) -> str:
        """Source line ``line`` (1-based) with its indentation, line ending dropped."""
        lines = self._byte_lines()
        if 1 <= line <= len(lines):
            return lines[line - 1].decode("utf-8", "ignore").rstrip("\r\n")
        return ""

    def columns(self, node) -> tuple[int, int]:
        """1-based ``(start_column, end_column)`` of ``node`` in characters.

        ``start_column`` is on the node's first line and ``end_column`` on its
        last line (``end_line_of``), just past the last character (SARIF).
        """
        lines = self._byte_lines()
        srow, scol = node.start_point
        erow, ecol = node.end_point
        first = lines[srow] if srow < len(lines) else b""
        last = lines[erow] if erow < len(lines) else b""
        start = len(first[:scol].decode("utf-8", "ignore")) + 1
        end = len(last[:ecol].decode("utf-8", "ignore")) + 1
        if erow == srow:
            end = max(end, start + 1)
        return start, end


def line_of(node) -> int:
    return int(node.start_point[0]) + 1


def end_line_of(node) -> int:
    return int(node.end_point[0]) + 1


def walk(root) -> Iterator[Any]:
    """Pre-order walk with an explicit stack (deep nesting must not recurse)."""
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(node.children))


def call_args(call) -> tuple[list[Any], dict[str, Any]]:
    """Positional argument nodes and keyword-argument value nodes of a call."""
    positional: list[Any] = []
    keywords: dict[str, Any] = {}
    args = call.child_by_field_name("arguments")
    if args is None:
        return positional, keywords
    for child in args.named_children:
        if child.type == "keyword_argument":
            name = child.child_by_field_name("name")
            value = child.child_by_field_name("value")
            if name is not None and value is not None:
                keywords[name.text.decode("utf-8", "ignore")] = value
        elif child.type in ("list_splat", "dictionary_splat", "comment"):
            continue
        else:
            positional.append(child)
    return positional, keywords


def string_value(node, src: Src) -> str | None:
    """The literal value of a plain (non-interpolated) Python string, else None."""
    if node is None or node.type != "string":
        return None
    if any(c.type == "interpolation" for c in node.children):
        return None
    parts = [src.text(c) for c in node.children if c.type == "string_content"]
    return "".join(parts)


def is_true(node, src: Src) -> bool:
    return node is not None and src.text(node) == "True"


def is_false(node, src: Src) -> bool:
    return node is not None and src.text(node) == "False"


# --- import resolution -----------------------------------------------------

#: Top-level packages that make up an LLM / agent stack. A name imported from
#: one of these is treated as part of that stack when resolving calls.
_LLM_PACKAGE_RE = re.compile(
    r"^(openai|anthropic|langchain(_[a-z0-9_]+)?|langgraph|llama_index|litellm|ollama|"
    r"google\.genai|google\.generativeai|vertexai|mistralai|cohere|groq|together|"
    r"crewai|crewai_tools|autogen|autogen_agentchat|autogen_ext|pyautogen|"
    r"transformers|huggingface_hub|mcp|fastmcp|agents|smolagents)(\.|$)"
)


def is_llm_qualname(qualname: str) -> bool:
    return bool(_LLM_PACKAGE_RE.match(qualname))


def import_aliases(root, src: Src) -> dict[str, str]:
    """Map each locally bound import name to its fully qualified name.

    ``from langchain_openai import ChatOpenAI as Chat`` maps ``Chat`` to
    ``langchain_openai.ChatOpenAI``; ``import google.genai as genai`` maps
    ``genai`` to ``google.genai``. Only top-level and function-level import
    statements are read, which is where imports live in practice.
    """
    aliases: dict[str, str] = {}
    for node in walk(root):
        if node.type == "import_statement":
            for child in node.named_children:
                if child.type == "dotted_name":
                    full = src.text(child)
                    aliases.setdefault(full.split(".", 1)[0], full.split(".", 1)[0])
                elif child.type == "aliased_import":
                    name = child.child_by_field_name("name")
                    alias = child.child_by_field_name("alias")
                    if name is not None and alias is not None:
                        aliases[src.text(alias)] = src.text(name)
        elif node.type == "import_from_statement":
            module = node.child_by_field_name("module_name")
            if module is None:
                continue
            mod = src.text(module).lstrip(".")
            for child in node.children_by_field_name("name"):
                if child.type == "dotted_name":
                    aliases[src.text(child)] = f"{mod}.{src.text(child)}"
                elif child.type == "aliased_import":
                    name = child.child_by_field_name("name")
                    alias = child.child_by_field_name("alias")
                    if name is not None and alias is not None:
                        aliases[src.text(alias)] = f"{mod}.{src.text(name)}"
    return aliases


def qualify(dotted: str, aliases: dict[str, str]) -> str:
    """Resolve the first component of a dotted call target through the imports."""
    head, sep, rest = dotted.partition(".")
    resolved = aliases.get(head)
    if resolved is None:
        return dotted
    return resolved + sep + rest


# --- in-file Pydantic models -----------------------------------------------

# Field annotations that pin a value to a closed or non-textual set. A plain
# ``str`` (or anything not listed) leaves the model's output free-form.
_CONSTRAINED_ANNOTATION = re.compile(
    r"^(?:typing\.)?(?:Literal\[|int\b|float\b|bool\b|Decimal\b|UUID\b|uuid\.UUID\b|"
    r"datetime\b|date\b|conint\(|confloat\(|PositiveInt\b|NonNegativeInt\b|"
    r"NegativeInt\b|StrictInt\b|StrictBool\b|StrictFloat\b)"
)
_PATTERN_CONSTRAINT = re.compile(r"\b(?:pattern|regex)\s*=")


@dataclass
class ModelIndex:
    """Pydantic models and Enums defined in the file, with per-field verdicts."""

    #: model name -> {field name -> True if the field's value is constrained}
    models: dict[str, dict[str, bool]] = field(default_factory=dict)
    enums: set[str] = field(default_factory=set)

    def field_constrained(self, model: str | None, attr: str) -> bool | None:
        """True/False for a known model's field, None when it cannot be told."""
        if model is None or model not in self.models:
            return None
        return self.models[model].get(attr)


def model_index(root, src: Src) -> ModelIndex:
    index = ModelIndex()
    classes: list[tuple[str, list[str], Any]] = []
    for node in walk(root):
        if node.type != "class_definition":
            continue
        name = node.child_by_field_name("name")
        body = node.child_by_field_name("body")
        supers = node.child_by_field_name("superclasses")
        if name is None or body is None:
            continue
        bases = (
            [src.text(b).rsplit(".", 1)[-1] for b in supers.named_children]
            if supers is not None
            else []
        )
        classes.append((src.text(name), bases, body))
    for name, bases, _body in classes:
        if any(b in ("Enum", "StrEnum", "IntEnum", "Flag", "IntFlag") for b in bases):
            index.enums.add(name)
    model_names = {"BaseModel", "RootModel"}
    # Resolve subclass chains of in-file models (bounded by the class count).
    for _ in range(len(classes)):
        grew = False
        for name, bases, _body in classes:
            if name not in model_names and any(b in model_names for b in bases):
                model_names.add(name)
                grew = True
        if not grew:
            break
    for name, _bases, body in classes:
        if name not in model_names or name in ("BaseModel", "RootModel"):
            continue
        fields: dict[str, bool] = {}
        for stmt in body.named_children:
            node = stmt.named_children[0] if stmt.type == "expression_statement" else stmt
            if node is None or node.type != "assignment":
                continue
            left = node.child_by_field_name("left")
            ann = node.child_by_field_name("type")
            if left is None or ann is None or left.type != "identifier":
                continue
            ann_text = src.text(ann).strip()
            if ann_text.startswith("Annotated["):
                inner = ann_text[len("Annotated[") :]
                constrained = bool(
                    _CONSTRAINED_ANNOTATION.match(inner) or _PATTERN_CONSTRAINT.search(inner)
                )
            else:
                constrained = bool(_CONSTRAINED_ANNOTATION.match(ann_text))
            base_name = ann_text.split("[", 1)[0].rsplit(".", 1)[-1]
            if base_name in index.enums:
                constrained = True
            right = node.child_by_field_name("right")
            if right is not None and _PATTERN_CONSTRAINT.search(src.text(right)):
                constrained = True
            if ann_text.startswith("constr(") and _PATTERN_CONSTRAINT.search(ann_text):
                constrained = True
            fields[src.text(left)] = constrained
        index.models[name] = fields
    return index


# --- findings --------------------------------------------------------------


def downgrade_for_tests(severity: Severity, in_test: bool) -> tuple[Severity, Confidence | None]:
    """Test and fixture code: one severity step down and LOW confidence."""
    if not in_test:
        return severity, None
    return Severity(max(Severity.INFO, severity - 1)), Confidence.LOW


def make_finding(
    *,
    rule: str,
    key: str,
    title: str,
    description: str,
    path: str,
    line: int | None,
    snippet: str,
    severity: Severity,
    confidence: Confidence,
    cwe: list[str],
    owasp_llm: str,
    why: str,
    attack: str,
    impact: str,
    fix: str,
    tags: list[str],
    metadata: dict[str, Any] | None = None,
    in_test: bool = False,
    likelihood: Likelihood = Likelihood.LIKELY,
    scanner_name: str = SCANNER_NAME,
    references: list[str] | None = None,
    columns: tuple[int, int] | None = None,
    end_line: int | None = None,
) -> Finding:
    """One finding for an LLM/agent rule, with the OWASP LLM id attached.

    ``columns`` is ``(start_column, end_column)`` as from :meth:`Src.columns`;
    ``end_line`` is the line ``end_column`` is on and defaults to ``line``.
    """
    severity, low_conf = downgrade_for_tests(severity, in_test)
    all_tags = list(dict.fromkeys(["ai-security", *tags, owasp_llm.split(":", 1)[0]]))
    if low_conf is not None:
        confidence = low_conf
        all_tags.append("test-context")
    meta = {"owasp_llm": owasp_llm, **(metadata or {})}
    refs = [OWASP_URLS.get(owasp_llm, "https://genai.owasp.org/llm-top-10/")]
    refs += [f"https://cwe.mitre.org/data/definitions/{c.split('-', 1)[1]}.html" for c in cwe[:1]]
    refs += references or []
    return Finding(
        id=f"{scanner_name}:{rule}:{path}:{line or 0}:{key}",
        rule_id=f"{scanner_name}.{rule}",
        scanner=scanner_name,
        title=title,
        description=description,
        location=Location(
            path=path,
            start_line=line,
            end_line=(end_line or line) if columns else None,
            start_column=columns[0] if columns else None,
            end_column=columns[1] if columns else None,
            snippet=snippet[:240],
        ),
        severity=severity,
        confidence=confidence,
        likelihood=likelihood,
        cwe=cwe,
        owasp=[owasp_llm],
        why_vulnerable=why,
        attacker_perspective=attack,
        business_impact=impact,
        remediation=Remediation(summary=fix, guidance=fix, references=refs),
        tags=all_tags,
        metadata=meta,
    )
