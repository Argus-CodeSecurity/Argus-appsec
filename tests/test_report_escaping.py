"""Untrusted text must not inject Markdown, HTML or @mentions into reports/PRs."""

from __future__ import annotations

from datetime import datetime, timezone

from nephilex.core.models import Finding, Location, Remediation, ScanResult, Severity
from nephilex.remediation import pr_review
from nephilex.remediation.annotations import build_fix_comments
from nephilex.remediation.applier import AppliedFix, ApplyReport
from nephilex.remediation.pullrequest import _pr_body
from nephilex.reporting.markdown import MarkdownReporter
from nephilex.reporting.md_escape import md_code, md_fence, md_text

HOSTILE_TITLE = "Pwned @octo-org/admins [click](https://evil.example) <img src=x> **x**"
HOSTILE_PATH = "src/a`b|c @team.py"


def _hostile_finding() -> Finding:
    return Finding(
        id="x:1",
        rule_id="py.sqli",
        scanner="patterns",
        title=HOSTILE_TITLE,
        description="d",
        location=Location(path=HOSTILE_PATH, start_line=3),
        severity=Severity.HIGH,
        why_vulnerable="cc @everyone\n# Heading\n<script>alert(1)</script>",
        remediation=Remediation(summary="see [here](https://evil.example)"),
    )


def _assert_inert(text: str) -> None:
    assert "@octo-org" not in text
    assert "@everyone" not in text
    # A path keeps its "@" only inside a code span, where GitHub does not
    # turn it into a mention.
    assert "@team" not in text.replace(md_code(HOSTILE_PATH + ":3"), "")
    assert "](https://evil.example)" not in text
    assert "<img" not in text and "<script" not in text


def test_md_text_escapes_metacharacters_mentions_and_html():
    out = md_text("**b** [l](u) <i> @alice #1\nnext")
    assert "\\*\\*b\\*\\*" in out
    assert "\\[l\\]\\(u\\)" in out
    assert "&lt;i>" in out
    assert "@\u200dalice" in out
    assert "\n" not in out


def test_md_text_multiline_keeps_hard_breaks():
    out = md_text("one\n- two", multiline=True)
    assert out == "one  \n\\- two"


def test_md_code_cannot_be_broken_out_of():
    span = md_code("a``b")
    assert span.startswith("```") and span.endswith("```")
    assert md_code("`x`") == "`` `x` ``"
    assert md_code("a|b", in_table=True) == "`a\\|b`"


def test_md_fence_longer_than_content_backticks():
    fence = md_fence("````\ncode", "diff")
    assert fence[0] == "`````diff" and fence[-1] == "`````"


def test_markdown_report_escapes_untrusted_fields():
    result = ScanResult(
        target="t", started_at=datetime.now(timezone.utc), findings=[_hostile_finding()]
    )
    md = MarkdownReporter().render(result)
    _assert_inert(md)
    # No hostile heading line was created from the model/scanner prose.
    assert "\n# Heading" not in md


def test_pr_review_comment_and_summary_are_escaped():
    f = _hostile_finding()
    comment = pr_review.finding_comment(f)
    _assert_inert(comment["body"])
    # The API path itself stays raw; only the rendered body is escaped.
    assert comment["path"] == HOSTILE_PATH
    summary = pr_review.review_summary(1, 0, [f])
    _assert_inert(summary)


def test_fix_pr_body_and_annotations_escape_paths():
    fix = AppliedFix(
        path="x|y`@team.py",
        rule_id="r",
        line=1,
        before="a ```",
        after="b",
        finding_id="f",
        verified=True,
    )
    report = ApplyReport(fixes=[fix], changed_files=[fix.path])
    body = _pr_body(report)
    row = next(line for line in body.splitlines() if "x\\|y" in line)
    assert row.count(" | ") == 3  # path's "|" did not add a column
    comments = build_fix_comments(report)
    assert "````diff" in comments[0]["body"]  # fence outgrows the ``` in the line
