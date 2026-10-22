"""Post scan findings as a pull-request review (the Argus PR bot).

Given a scan's findings and a checked-out pull request, this posts the findings
that land on lines the PR changed as **inline** GitHub review comments, and lists
any remaining new findings in the review summary. Paired with ``--baseline``
(diff-aware scanning), this yields the "comment only on what this PR introduces"
behavior that lets teams adopt a scanner without drowning in pre-existing debt.

The parsing and comment-building are pure and unit-tested; the network calls live
in :mod:`argus.remediation.hosting`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from argus.core.models import Finding
from argus.remediation import git_ops
from argus.remediation.hosting import RepoRef, post_issue_comment, post_pr_review
from argus.reporting.md_escape import md_code, md_text

# `@@ -old,+new @@` hunk header; we only need the new-side start and length.
_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")

_C_ESCAPES = {"a": 7, "b": 8, "t": 9, "n": 10, "v": 11, "f": 12, "r": 13,
              '"': 34, "\\": 92}


def _unquote_path(path: str) -> str:
    r"""Undo git's C-style quoting (``"caf\303\251.py"``) of a diff path.

    ``core.quotePath=false`` keeps non-ASCII names raw, but git still quotes
    paths containing control characters, quotes or backslashes.
    """
    if len(path) < 2 or not (path.startswith('"') and path.endswith('"')):
        return path
    body = path[1:-1]
    out = bytearray()
    i = 0
    while i < len(body):
        ch = body[i]
        if ch == "\\" and i + 1 < len(body):
            nxt = body[i + 1]
            octal = body[i + 1:i + 4]
            if len(octal) == 3 and all(c in "01234567" for c in octal):
                out.append(int(octal, 8))
                i += 4
                continue
            if nxt in _C_ESCAPES:
                out.append(_C_ESCAPES[nxt])
                i += 2
                continue
        out += ch.encode("utf-8")
        i += 1
    return out.decode("utf-8", errors="replace")


def parse_changed_lines(diff_text: str) -> dict[str, set[int]]:
    """Map each file to the set of line numbers a unified diff *adds*.

    Expects the output of ``git diff --unified=0``. Only added/modified lines on
    the new side are collected, since those are the lines a PR can be commented
    on. Pure and testable, no git required.
    """
    changed: dict[str, set[int]] = {}
    current: set[int] | None = None
    # Split on "\n" only: str.splitlines() also breaks on \x0c,   and
    # friends, which would let file content masquerade as hunk headers.
    for line in diff_text.split("\n"):
        line = line.rstrip("\r")
        if line.startswith("+++ "):
            # git appends a tab after names that contain spaces.
            path = _unquote_path(line[4:].rstrip("\t"))
            if path == "/dev/null":
                current = None
                continue
            # Strip the "b/" prefix git adds.
            if path.startswith("b/"):
                path = path[2:]
            current = changed.setdefault(path, set())
            continue
        m = _HUNK.match(line)
        if m and current is not None:
            start = int(m.group(1))
            length = int(m.group(2)) if m.group(2) is not None else 1
            for n in range(start, start + max(length, 1)):
                current.add(n)
    # Drop files that ended up with no added lines (pure deletions).
    return {p: lines for p, lines in changed.items() if lines}


def changed_lines(root: str | Path, base: str, head: str = "HEAD") -> dict[str, set[int]]:
    """Line numbers changed between ``base`` and ``head`` (per file).

    Uses a three-dot diff (``base...head``) so it matches what the PR shows,
    the changes on the head branch since it diverged from base. Returns an empty
    map if git or the refs are unavailable (caller then falls back to a
    summary-only review, which still lists every finding).
    """
    try:
        text = git_ops.diff(Path(root), "--unified=0", "--no-color", "--no-ext-diff",
                            f"{base}...{head}")
    except git_ops.GitError:
        return {}
    return parse_changed_lines(text)


def finding_comment(f: Finding) -> dict:
    """Build one inline GitHub review-comment payload for a finding.

    Everything interpolated comes from the scanned (possibly hostile) PR, so it
    is escaped: no links, HTML or @mentions can ride along on the bot's token.
    """
    parts = [f"**Argus | {f.severity.label} · {md_text(f.title)}**", md_code(f.rule_id)]
    if f.why_vulnerable:
        parts.append("\n" + md_text(f.why_vulnerable, multiline=True))
    if f.remediation and f.remediation.summary:
        parts.append(f"\n**Fix:** {md_text(f.remediation.summary)}")
    mapping = ", ".join(f.cwe + f.owasp)
    if mapping:
        parts.append(f"\n_{md_text(mapping)}_")
    return {
        "path": f.location.path,
        "line": f.location.start_line,
        "side": "RIGHT",
        "body": "  \n".join(parts),
    }


def split_comments(
    findings: list[Finding], changed: dict[str, set[int]]
) -> tuple[list[dict], list[Finding]]:
    """Split findings into (inline comments on changed lines, everything else).

    GitHub rejects a whole review if any comment targets a line outside the diff,
    so only findings whose line is in ``changed`` become inline comments; the
    rest are returned to be summarized in the review body.
    """
    inline: list[dict] = []
    leftover: list[Finding] = []
    for f in findings:
        line = f.location.start_line
        if line is not None and line in changed.get(f.location.path, set()):
            inline.append(finding_comment(f))
        else:
            leftover.append(f)
    return inline, leftover


def review_summary(total: int, inline_count: int, leftover: list[Finding]) -> str:
    """Markdown body for the review / PR comment."""
    if total == 0:
        return "### Argus: no new findings in this pull request."
    header = (
        f"### Argus found {total} new finding"
        f"{'s' if total != 1 else ''} in this pull request"
    )
    lines = [header, ""]
    if inline_count:
        lines.append(
            f"{inline_count} shown inline on the changed lines below."
            + (" Others are listed here:" if leftover else "")
        )
    for f in leftover:
        lines.append(f"- **{f.severity.label}** {md_code(f.rule_id)} "
                     f"- {md_text(f.title)} ({md_code(f.location.as_ref())})")
    lines += ["", "_Only findings introduced by this PR are shown "
              "(diff-aware). Nothing was modified._"]
    return "\n".join(lines)


@dataclass
class ReviewOutcome:
    total: int = 0
    inline: int = 0
    leftover: int = 0
    posted: bool = False
    summary: str = ""
    messages: list[str] = field(default_factory=list)


def post_findings_review(
    ref: RepoRef,
    number: int,
    findings: list[Finding],
    *,
    changed: dict[str, set[int]],
    token: str | None = None,
    dry_run: bool = False,
    post_clean: bool = False,
) -> ReviewOutcome:
    """Post ``findings`` to PR ``number`` as an inline review plus a summary.

    Inline comments go on findings that sit on changed lines; the rest go in the
    summary. With no findings, nothing is posted unless ``post_clean`` is set
    (then a short "no new findings" comment is left). ``dry_run`` builds the
    outcome without any network call.
    """
    inline, leftover = split_comments(findings, changed)
    summary = review_summary(len(findings), len(inline), leftover)
    outcome = ReviewOutcome(
        total=len(findings), inline=len(inline), leftover=len(leftover),
        summary=summary,
    )
    if dry_run:
        outcome.messages.append("dry run: no review posted")
        return outcome

    if inline:
        post_pr_review(ref, number, inline, summary=summary, token=token)
        outcome.posted = True
    elif findings or post_clean:
        # New findings but none on changed lines (or an explicit clean report):
        # leave the summary as a normal PR comment.
        post_issue_comment(ref, number, summary, token=token)
        outcome.posted = True
    return outcome
