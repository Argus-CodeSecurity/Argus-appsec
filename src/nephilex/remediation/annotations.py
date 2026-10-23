"""Build inline pull-request review comments from applied fixes.

When Nephilex opens a fix PR, each fixed line is annotated inline on the PR with the
rule it addressed and the before/after change, so a reviewer sees *why* the change
was made right where it was made, not only in the PR description. Findings that
appear as review comments on the changed lines get read; findings buried in a
separate report get ignored.

The comment-building here is pure and unit-tested; the network call lives in
:func:`nephilex.remediation.hosting.post_pr_review`.
"""

from __future__ import annotations

from nephilex.remediation.applier import ApplyReport
from nephilex.reporting.md_escape import md_code, md_fence


def build_fix_comments(report: ApplyReport) -> list[dict]:
    """Turn applied fixes into GitHub PR review-comment payloads (path/line/body)."""
    comments: list[dict] = []
    for fix in report.fixes:
        mark = "verified" if fix.verified else "proposed (unverified, please review)"
        fence = md_fence(f"- {fix.before.strip()}\n+ {fix.after.strip()}", "diff")
        body = f"**Nephilex fixed {md_code(fix.rule_id)}** ({mark}).\n\n" + "\n".join(fence)
        comments.append({"path": fix.path, "line": fix.line, "side": "RIGHT", "body": body})
    return comments
