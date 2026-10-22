"""Escaping helpers for putting untrusted text into Markdown.

Finding titles, file paths, rule ids, snippets and model-written prose all come
from (or are influenced by) the scanned repository. When that Markdown is posted
to a pull request with a bot token, unescaped text can inject links, images,
raw HTML, fake headings or ``@mentions`` that ping arbitrary users and teams.
Every reporter that emits Markdown goes through these helpers.
"""

from __future__ import annotations

import re

# Zero-width joiner: keeps "@user" readable while stopping the mention.
_ZWJ = "‍"

# ASCII punctuation that carries Markdown/GFM meaning anywhere in a line
# ("#" included: "#123" autolinks and cross-references issues).
_MD_META = re.compile(r"([\\`*_{}\[\]()#!|~&])")
# Characters that only matter at the start of a line (lists, quotes, setext
# headings, ordered lists); escaping them everywhere would just add noise.
_LINE_START = re.compile(r"^(\s*)([-+>=]|\d+(?=[.)]))")


def _escape_line_start(m: re.Match[str]) -> str:
    lead, mark = m.group(1), m.group(2)
    if mark.isdigit():  # "1." -> "1\." keeps the number, drops the list
        return f"{lead}{mark}\\"
    return f"{lead}\\{mark}"


def md_text(text: object, *, multiline: bool = False) -> str:
    """Escape ``text`` so it renders literally as Markdown prose.

    Backslash-escapes Markdown metacharacters, turns ``<`` into ``&lt;`` so no
    raw HTML survives, and breaks ``@mentions`` with a zero-width joiner. By
    default newlines collapse to spaces so the value stays on one line (a list
    item or table cell). With ``multiline=True`` line breaks are kept as hard
    breaks, each line escaped on its own.
    """
    s = "" if text is None else str(text)
    if multiline:
        lines = s.replace("\r\n", "\n").replace("\r", "\n").split("\n")
        return "  \n".join(md_text(line) for line in lines).strip()
    s = s.replace("\r", " ").replace("\n", " ")
    s = _MD_META.sub(r"\\\1", s)
    s = _LINE_START.sub(_escape_line_start, s)
    s = s.replace("<", "&lt;")
    return s.replace("@", "@" + _ZWJ)


def _longest_backtick_run(content: str) -> int:
    longest = run = 0
    for ch in content:
        run = run + 1 if ch == "`" else 0
        longest = max(longest, run)
    return longest


def md_code(text: object, *, in_table: bool = False) -> str:
    """Wrap ``text`` in an inline code span it cannot break out of.

    The delimiter is one backtick longer than the longest run inside. Code spans
    render their content literally, so links, HTML and mentions inside are inert.
    In a GFM table cell, ``|`` still splits the cell even inside a code span,
    so pass ``in_table=True`` there to escape it.
    """
    s = "" if text is None else str(text)
    s = s.replace("\r", " ").replace("\n", " ")
    if in_table:
        s = s.replace("|", "\\|")
    ticks = "`" * (_longest_backtick_run(s) + 1)
    # A leading/trailing backtick (or space) must be padded or it merges with
    # the delimiter / gets stripped.
    if s.startswith(("`", " ")) or s.endswith(("`", " ")):
        s = f" {s} "
    return f"{ticks}{s}{ticks}"


def md_fence(content: str, lang: str = "") -> list[str]:
    """Wrap untrusted content in a fenced code block it cannot break out of.

    Scanned source (snippets, diffs) can itself contain backtick runs; the fence
    is longer than the longest run inside so the block stays intact when the
    Markdown is rendered (e.g. as a PR comment).
    """
    ticks = "`" * max(3, _longest_backtick_run(content) + 1)
    return [f"{ticks}{lang}", content, ticks]
