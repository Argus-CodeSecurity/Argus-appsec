"""Tests for inline PR annotations (review comments from applied fixes)."""

from __future__ import annotations

import pytest

from nephilex.remediation import hosting
from nephilex.remediation.annotations import build_fix_comments
from nephilex.remediation.applier import AppliedFix, ApplyReport
from nephilex.remediation.hosting import HostingError, RepoRef, post_pr_review


def _report() -> ApplyReport:
    r = ApplyReport()
    r.fixes = [
        AppliedFix(
            path="a.py",
            rule_id="patterns.python-yaml-load",
            line=3,
            before="  yaml.load(x)",
            after="  yaml.safe_load(x)",
            finding_id="f",
            verified=True,
        )
    ]
    return r


def _github_ref() -> RepoRef:
    return RepoRef(host="github", owner="o", repo="r", web_base="https://github.com")


def test_build_fix_comments_shape():
    c = build_fix_comments(_report())[0]
    assert c["path"] == "a.py" and c["line"] == 3 and c["side"] == "RIGHT"
    assert "python-yaml-load" in c["body"]
    assert "```diff" in c["body"] and "yaml.safe_load" in c["body"]


def test_post_pr_review_builds_correct_request(monkeypatch):
    captured: dict = {}

    class FakeResp:
        status_code = 200
        text = ""

    def fake_post(url, headers=None, json=None, timeout=None):
        captured.update(url=url, headers=headers, json=json)
        return FakeResp()

    monkeypatch.setattr(hosting.httpx, "post", fake_post)
    post_pr_review(_github_ref(), 7, build_fix_comments(_report()), summary="hi", token="t")
    assert captured["url"].endswith("/repos/o/r/pulls/7/reviews")
    assert captured["headers"]["Authorization"] == "Bearer t"
    assert captured["json"]["event"] == "COMMENT"
    assert captured["json"]["comments"][0]["path"] == "a.py"


def test_post_pr_review_is_github_only():
    ref = RepoRef(host="gitlab", owner="o", repo="r", web_base="https://gitlab.com")
    with pytest.raises(HostingError):
        post_pr_review(ref, 1, [{"path": "a", "line": 1, "body": "x"}], token="t")


def test_post_pr_review_empty_is_noop(monkeypatch):
    calls = {"n": 0}
    monkeypatch.setattr(
        hosting.httpx, "post", lambda *a, **k: calls.__setitem__("n", calls["n"] + 1)
    )
    post_pr_review(_github_ref(), 1, [], token="t")
    assert calls["n"] == 0


def test_post_pr_review_raises_on_api_error(monkeypatch):
    class FakeResp:
        status_code = 422
        text = "unprocessable"

    monkeypatch.setattr(hosting.httpx, "post", lambda *a, **k: FakeResp())
    with pytest.raises(HostingError):
        post_pr_review(_github_ref(), 1, [{"path": "a", "line": 1, "body": "x"}], token="t")
