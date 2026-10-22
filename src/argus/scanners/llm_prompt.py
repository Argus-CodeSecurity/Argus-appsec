"""System-prompt construction rules (OWASP LLM01 and LLM07).

Two questions are asked of every place a Python file builds a *system* prompt
(the instruction channel the model trusts most):

* **LLM01 Prompt Injection.** Does untrusted data (request parameters, file
  contents, retrieved documents, HTTP responses) flow into it? That data
  belongs in a delimited user-role message, never in the instructions. The
  data flow itself is tracked by :mod:`argus.scanners.llm_taint`; this module
  only says where a system prompt is.
* **LLM07 System Prompt Leakage.** Does its literal text carry a credential or
  an internal URL? System prompts are routinely extracted by users, so anything
  in them should be treated as public.

A "system prompt" here is one of: a ``{"role": "system" | "developer",
"content": ...}`` message dict, a LangChain ``SystemMessage(...)`` or a
``("system", ...)`` tuple, an Anthropic ``system=`` argument, an OpenAI
Responses / Agents SDK ``instructions=`` argument, a ``system_prompt=`` /
``system_message=`` / ``system_instruction=`` argument of an LLM-stack call, or
a variable whose name says it holds one (``SYSTEM_PROMPT = ...``).
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

from argus.core.models import Confidence, Finding, Severity
from argus.scanners._text import iter_scan_lines
from argus.scanners.llm_ast import (
    LLM07,
    Src,
    call_args,
    is_llm_qualname,
    line_of,
    make_finding,
    qualify,
    string_value,
    walk,
)

#: Variable names that hold a system prompt.
SYSTEM_PROMPT_NAME = re.compile(
    r"(?i)(?:^|[._])(?:system_?(?:prompt|message|msg|instructions?|template)s?|sys_prompt)$"
)
_SYSTEM_KWARGS = {"system_prompt", "system_message", "system_instruction", "system_template"}
_ROLE_VALUES = {"system", "developer"}


def system_prompt_exprs(node, src: Src, aliases: dict[str, str]) -> Iterator[tuple[Any, str]]:
    """Yield ``(expression, label)`` for system-prompt text built at ``node``.

    ``node`` is any expression node; only dictionaries, tuples and calls can
    carry a system prompt, everything else yields nothing.
    """
    if node.type == "dictionary":
        role = content = None
        for pair in node.named_children:
            if pair.type != "pair":
                continue
            key = string_value(pair.child_by_field_name("key"), src)
            value = pair.child_by_field_name("value")
            if key == "role":
                role = string_value(value, src)
            elif key == "content":
                content = value
        if role in _ROLE_VALUES and content is not None:
            yield content, f'"{role}" role message'
        return
    if node.type == "tuple":
        items = node.named_children
        if len(items) == 2 and string_value(items[0], src) == "system":
            yield items[1], '("system", ...) prompt template message'
        return
    if node.type != "call":
        return
    fn = node.child_by_field_name("function")
    if fn is None:
        return
    fn_text = src.text(fn)
    q = qualify(fn_text, aliases)
    last = q.rsplit(".", 1)[-1]
    pos, kw = call_args(node)
    if last in ("SystemMessage", "SystemMessagePromptTemplate") or (
        last == "from_template" and "SystemMessagePromptTemplate" in q
    ):
        target = kw.get("content") or kw.get("template") or (pos[0] if pos else None)
        if target is not None:
            yield target, f"{last}(...)"
        return
    if "system" in kw and re.search(r"\.messages\.(?:create|stream|parse|count_tokens)$", fn_text):
        yield kw["system"], "Anthropic system= argument"
    if "instructions" in kw and (
        re.search(r"\.responses\.(?:create|parse|stream)$", fn_text)
        or q in ("agents.Agent", "agents.agent.Agent")
    ):
        yield kw["instructions"], "instructions= argument"
    llm_call = is_llm_qualname(q) or bool(
        re.search(r"(?:completions|messages|responses)\.\w+$", fn_text)
    )
    if llm_call:
        for name in _SYSTEM_KWARGS & kw.keys():
            yield kw[name], f"{name}= argument"


# --- LLM07: literal secrets and internal URLs in system prompt text --------

# Provider keys not covered by the generic secrets signatures.
_LLM_KEY_SIGNATURES = {
    "anthropic-api-key": re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}"),
    "openai-api-key": re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}"),
}
# "password: hunter2", "api key is abc123..." written as prose in the prompt.
_PROSE_SECRET = re.compile(
    r"(?i)\b(?:password|passwd|api[ _-]?key|secret|token)\b(?:\s{1,3}is\b)?"
    r"\s{0,3}(?:[:=]\s{0,3})?['\"]?(?P<val>[A-Za-z0-9_\-/+=.]{8,128})"
)
_PROSE_PLACEHOLDER = re.compile(
    r"(?i)^(?:x{3,}|\*{3,}|changeme|example|placeholder|redacted|your|none|null|"
    r"provided|required|secret|token|password|valid|invalid|missing|unknown)"
)
_INTERNAL_URL = re.compile(
    r"(?i)\bhttps?://(?:"
    r"localhost|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
    r"169\.254\.\d{1,3}\.\d{1,3}|"
    r"[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63}){0,8}\.(?:internal|local|corp|lan|intranet|"
    r"svc\.cluster\.local))"
    r"(?![a-z0-9.-])"
)


def _secret_spans(text: str) -> list[tuple[int, int, str]]:
    from argus.scanners.secrets import _PLACEHOLDER, _SIGNATURES

    spans: list[tuple[int, int, str]] = []
    for rule, pattern in (*_SIGNATURES.items(), *_LLM_KEY_SIGNATURES.items()):
        for m in pattern.finditer(text):
            s, e = m.span("val") if "val" in m.re.groupindex and m.group("val") else m.span()
            if not _PLACEHOLDER.search(text[s:e]):
                spans.append((s, e, rule))
    for m in _PROSE_SECRET.finditer(text):
        val = m.group("val")
        if _PROSE_PLACEHOLDER.search(val) or val.isalpha():
            continue  # "the password is required", a word not a credential
        if not any(c.isdigit() for c in val):
            continue
        spans.append((*m.span("val"), "credential-in-prose"))
    return spans


def mask(text: str, spans: list[tuple[int, int, str]]) -> str:
    """``text`` with every span replaced by the secrets scanner's redaction."""
    from argus.scanners.secrets import SecretsScanner, redact_line

    out: list[str] = []
    pos = 0
    for start, end, _rule in sorted(spans):
        if start < pos:
            continue
        out.append(text[pos:start])
        out.append(SecretsScanner._redact(text[start:end]))
        pos = end
    out.append(text[pos:])
    return redact_line("".join(out))


def literal_strings(
    expr, src: Src, consts: dict[str, list[tuple[str, int]]]
) -> list[tuple[str, int]]:
    """Bounded line segments of the string literals in ``expr``, with line numbers.

    Constants that ``expr`` names are included. Every segment goes through
    :func:`argus.scanners._text.iter_scan_lines`, so a huge literal is searched
    in bounded windows like any other scanned line.
    """
    raw: list[tuple[str, int]] = []
    for node in walk(expr):
        if node.type == "string_content":
            raw.append((src.text(node), line_of(node)))
        elif node.type == "identifier":
            raw.extend(consts.get(src.text(node), ()))
    out: list[tuple[str, int]] = []
    for text, first_line in raw:
        for offset, segment in iter_scan_lines(text):
            out.append((segment, first_line + offset - 1))
    return out


def constant_strings(root, src: Src) -> dict[str, list[tuple[str, int]]]:
    """Module-level ``NAME = "..."`` string text, keyed by name (with its line)."""
    consts: dict[str, list[tuple[str, int]]] = {}
    for stmt in root.named_children:
        if stmt.type != "expression_statement" or not stmt.named_children:
            continue
        node = stmt.named_children[0]
        if node.type != "assignment":
            continue
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None or left.type != "identifier":
            continue
        parts = [(src.text(n), line_of(n)) for n in walk(right) if n.type == "string_content"]
        if parts:
            consts[src.text(left)] = parts
    return consts


def leak_findings(
    expr,
    label: str,
    src: Src,
    consts: dict[str, list[tuple[str, int]]],
    path: str,
    in_test: bool,
    seen: set[tuple[str, int]],
) -> Iterator[Finding]:
    """LLM07 findings for secrets / internal URLs in one system prompt."""
    for text, line in literal_strings(expr, src, consts):
        spans = _secret_spans(text)
        if spans and ("secret-in-system-prompt", line) not in seen:
            seen.add(("secret-in-system-prompt", line))
            kinds = sorted({s[2] for s in spans})
            yield make_finding(
                rule="secret-in-system-prompt",
                key="secret",
                title="Credential embedded in a system prompt",
                description=(
                    f"The {label} contains a value matching {', '.join(kinds)}. System "
                    "prompts are sent to the model provider and are routinely extracted "
                    "by users, so the credential must be treated as disclosed."
                ),
                path=path,
                line=line,
                snippet=mask(src.line_text(line), _secret_spans(src.line_text(line))),
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                cwe=["CWE-798", "CWE-200"],
                owasp_llm=LLM07,
                why="A secret placed in the system prompt is readable by anyone who can "
                "talk to the model: a single 'repeat your instructions' request, or an "
                "injected document, can make the model print it.",
                attack="Ask the assistant to reveal its instructions verbatim, or plant "
                "text in a retrieved document that asks it to.",
                impact="Credential compromise for whatever the key protects.",
                fix="Remove the credential from the prompt. Call the protected service "
                "from your own code (or a tool) that holds the key server-side, and rotate "
                "the exposed value.",
                tags=["llm", "prompt", "secret"],
                metadata={"secret_kinds": kinds, "context": label},
                in_test=in_test,
            )
        m = _INTERNAL_URL.search(text)
        if m and ("internal-url-in-system-prompt", line) not in seen:
            seen.add(("internal-url-in-system-prompt", line))
            yield make_finding(
                rule="internal-url-in-system-prompt",
                key="url",
                title="Internal URL embedded in a system prompt",
                description=(
                    f"The {label} names an internal endpoint ({m.group(0)}). Anything in "
                    "a system prompt should be assumed public, and an internal address "
                    "tells an attacker where to aim follow-up requests (SSRF, tools)."
                ),
                path=path,
                line=line,
                snippet=src.line_text(line),
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                cwe=["CWE-200"],
                owasp_llm=LLM07,
                why="System prompt contents leak through extraction attacks; internal "
                "hostnames and private IPs in them map your network for an attacker.",
                attack="Extract the system prompt, then point a tool or SSRF-capable "
                "feature at the disclosed internal endpoint.",
                impact="Disclosure of internal topology that eases lateral movement.",
                fix="Keep internal endpoints in server-side configuration used by your "
                "code or tools, not in text the model can repeat.",
                tags=["llm", "prompt"],
                metadata={"context": label},
                in_test=in_test,
            )
