"""PR review: summary size limits and hunk parsing edge cases."""

from __future__ import annotations

from argus.core.models import Finding, Location, Severity
from argus.remediation import pr_review


def _finding(i: int, title: str = "t") -> Finding:
    return Finding(
        id=f"r:{i}", rule_id="r", scanner="patterns", title=title, description="",
        location=Location(path="a.py", start_line=i), severity=Severity.LOW,
    )


def test_summary_lists_at_most_50_entries():
    leftover = [_finding(i) for i in range(1, 301)]
    body = pr_review.review_summary(300, 0, leftover)
    entries = [line for line in body.splitlines() if line.startswith("- **")]
    assert len(entries) == pr_review.MAX_SUMMARY_ENTRIES
    assert "...and 250 more" in body


def test_summary_body_is_hard_capped():
    leftover = [_finding(i, title="x" * 5000) for i in range(1, 40)]
    body = pr_review.review_summary(39, 0, leftover)
    assert len(body) <= pr_review.MAX_BODY_CHARS
    assert "more (see the full report)" in body


def test_pure_deletion_hunk_adds_no_lines():
    diff = (
        "+++ b/app.py\n"
        "@@ -5,2 +4,0 @@\n"
        "-gone\n"
        "-gone too\n"
        "@@ -9 +8,2 @@\n"
        "+new\n"
        "+new\n"
    )
    assert pr_review.parse_changed_lines(diff) == {"app.py": {8, 9}}
