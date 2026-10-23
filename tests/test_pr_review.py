"""Tests for the PR-review (PR bot) flow: diff parsing, comments, posting."""

from __future__ import annotations

from nephilex.core.models import Finding, Location, Remediation, Severity
from nephilex.remediation import pr_review

SAMPLE_DIFF = """\
diff --git a/app.py b/app.py
index 111..222 100644
--- a/app.py
+++ b/app.py
@@ -10,0 +11,2 @@ def f():
+    dangerous = eval(x)
+    run(dangerous)
@@ -20 +22 @@ def g():
-    old = 1
+    new = 2
diff --git a/gone.py b/gone.py
deleted file mode 100644
--- a/gone.py
+++ /dev/null
@@ -1,3 +0,0 @@
-a
-b
-c
"""


def _finding(rule, sev, path="app.py", line=11, cwe=None):
    return Finding(
        id=f"{rule}:{line}",
        rule_id=rule,
        scanner="patterns",
        title=f"{rule} title",
        description="",
        location=Location(path=path, start_line=line),
        severity=sev,
        cwe=cwe or [],
        why_vulnerable="because reasons",
        remediation=Remediation(summary="do the fix"),
    )


# --- diff parsing ----------------------------------------------------------
def test_parse_changed_lines():
    changed = pr_review.parse_changed_lines(SAMPLE_DIFF)
    assert changed == {"app.py": {11, 12, 22}}  # gone.py had only deletions


def test_parse_changed_lines_empty():
    assert pr_review.parse_changed_lines("") == {}


# --- comment building ------------------------------------------------------
def test_finding_comment_shape():
    c = pr_review.finding_comment(_finding("patterns.eval", Severity.HIGH, line=11, cwe=["CWE-95"]))
    assert c["path"] == "app.py"
    assert c["line"] == 11
    assert c["side"] == "RIGHT"
    assert "High" in c["body"] and "patterns.eval" in c["body"]
    assert "do the fix" in c["body"] and "CWE-95" in c["body"]


def test_split_comments_partitions_by_changed_line():
    changed = {"app.py": {11, 12}}
    on = _finding("patterns.a", Severity.HIGH, line=11)
    off = _finding("patterns.b", Severity.LOW, line=99)  # not a changed line
    other_file = _finding("patterns.c", Severity.MEDIUM, path="other.py", line=11)
    inline, leftover = pr_review.split_comments([on, off, other_file], changed)
    assert [c["line"] for c in inline] == [11]
    assert {f.rule_id for f in leftover} == {"patterns.b", "patterns.c"}


def test_review_summary_clean_and_findings():
    assert "no new findings" in pr_review.review_summary(0, 0, []).lower()
    leftover = [_finding("patterns.x", Severity.HIGH, path="z.py", line=3)]
    body = pr_review.review_summary(2, 1, leftover)
    assert "2 new finding" in body
    assert "patterns.x" in body and "z.py:3" in body


# --- posting (network mocked) ----------------------------------------------
class _Ref:
    host = "github"
    owner = "o"
    repo = "r"


def test_post_findings_review_posts_inline(monkeypatch):
    calls = {}
    monkeypatch.setattr(
        pr_review,
        "post_pr_review",
        lambda ref, n, comments, **kw: calls.update(review=(n, comments, kw)),
    )
    monkeypatch.setattr(pr_review, "post_issue_comment", lambda *a, **k: calls.update(issue=True))

    findings = [
        _finding("patterns.a", Severity.HIGH, line=11),
        _finding("patterns.b", Severity.LOW, line=999),
    ]  # off-diff -> summary
    outcome = pr_review.post_findings_review(_Ref(), 7, findings, changed={"app.py": {11}})

    assert outcome.posted and outcome.inline == 1 and outcome.leftover == 1
    n, comments, kw = calls["review"]
    assert n == 7 and len(comments) == 1
    assert "summary" in kw and "2 new finding" in kw["summary"]
    assert "issue" not in calls  # inline path used, not the issue-comment path


def test_post_findings_review_summary_only_when_no_inline(monkeypatch):
    calls = {}
    monkeypatch.setattr(pr_review, "post_pr_review", lambda *a, **k: calls.update(review=True))
    monkeypatch.setattr(
        pr_review, "post_issue_comment", lambda ref, n, body, **kw: calls.update(issue=(n, body))
    )

    findings = [_finding("patterns.a", Severity.HIGH, line=999)]  # not on a changed line
    outcome = pr_review.post_findings_review(_Ref(), 7, findings, changed={"app.py": {1}})
    assert outcome.posted and outcome.inline == 0 and outcome.leftover == 1
    assert "review" not in calls
    assert calls["issue"][0] == 7


def test_post_findings_review_dry_run_posts_nothing(monkeypatch):
    posted = {"n": 0}
    monkeypatch.setattr(
        pr_review, "post_pr_review", lambda *a, **k: posted.__setitem__("n", posted["n"] + 1)
    )
    monkeypatch.setattr(
        pr_review, "post_issue_comment", lambda *a, **k: posted.__setitem__("n", posted["n"] + 1)
    )
    outcome = pr_review.post_findings_review(
        _Ref(),
        7,
        [_finding("patterns.a", Severity.HIGH, line=11)],
        changed={"app.py": {11}},
        dry_run=True,
    )
    assert posted["n"] == 0 and not outcome.posted and outcome.inline == 1


def test_post_findings_review_clean_no_post_by_default(monkeypatch):
    posted = {"n": 0}
    monkeypatch.setattr(
        pr_review, "post_pr_review", lambda *a, **k: posted.__setitem__("n", posted["n"] + 1)
    )
    monkeypatch.setattr(
        pr_review, "post_issue_comment", lambda *a, **k: posted.__setitem__("n", posted["n"] + 1)
    )
    outcome = pr_review.post_findings_review(_Ref(), 7, [], changed={})
    assert posted["n"] == 0 and not outcome.posted and outcome.total == 0
