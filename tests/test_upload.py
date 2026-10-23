"""Tests for `nephilex push` upload: payload building and the HTTP push."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import httpx
import pytest

from nephilex.core.models import Finding, Location, ScanResult, Severity
from nephilex.upload import PushError, build_ingest_payload, push_result


def _finding(rule_id: str, sev: Severity, *, path="app.py", line=1, cwe=None) -> Finding:
    return Finding(
        id=f"{rule_id}:{line}",
        rule_id=rule_id,
        scanner="patterns",
        title=f"{rule_id} title",
        description="",
        location=Location(path=path, start_line=line),
        severity=sev,
        cwe=cwe or [],
    )


def _result() -> ScanResult:
    r = ScanResult(target="myrepo", started_at=datetime.now(timezone.utc), nephilex_version="9.9.9")
    r.findings = [
        _finding("patterns.a", Severity.CRITICAL, line=1, cwe=["CWE-89"]),
        _finding("patterns.b", Severity.HIGH, line=2),
        _finding("patterns.c", Severity.MEDIUM, line=3),
        _finding("patterns.d", Severity.LOW, line=4),
        _finding("patterns.e", Severity.INFO, line=5),  # filtered out by default
    ]
    return r


# --- payload ---------------------------------------------------------------
def test_build_ingest_payload_shape_and_counts():
    payload = build_ingest_payload(_result())
    assert payload["target"] == "myrepo"
    assert payload["nephilex_version"] == "9.9.9"
    assert isinstance(payload["risk_score"], int)
    # INFO is dropped at the default floor (LOW); the other four remain.
    assert payload["counts"] == {"critical": 1, "high": 1, "medium": 1, "low": 1}
    assert len(payload["findings"]) == 4
    top = payload["findings"][0]
    assert top["severity"] == "critical"
    assert top["rule"] == "patterns.a"
    assert top["location"] == "app.py:1"
    assert top["cwe"] == "CWE-89"
    assert payload["findings"][1]["cwe"] is None  # no CWE -> null, not ""


def test_build_ingest_payload_respects_min_severity():
    payload = build_ingest_payload(_result(), min_severity=Severity.HIGH)
    assert payload["counts"] == {"critical": 1, "high": 1, "medium": 0, "low": 0}
    assert [f["severity"] for f in payload["findings"]] == ["critical", "high"]


# --- push ------------------------------------------------------------------
def test_push_result_sends_bearer_and_returns_json():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["auth"] = request.headers.get("authorization")
        seen["body"] = json.loads(request.content)
        return httpx.Response(201, json={"scanId": "abc", "url": "/dashboard/scans/abc"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    resp = push_result(
        {"target": "t", "findings": []},
        url="https://cloud.example.com/",
        token="secret-token",
        client=client,
    )
    assert resp == {"scanId": "abc", "url": "/dashboard/scans/abc"}
    assert seen["url"] == "https://cloud.example.com/api/scans"
    assert seen["auth"] == "Bearer secret-token"
    assert seen["body"]["target"] == "t"


def test_push_result_auth_error_raises():
    client = httpx.Client(
        transport=httpx.MockTransport(lambda r: httpx.Response(401, json={"error": "no"}))
    )
    with pytest.raises(PushError, match="authentication failed"):
        push_result({}, url="https://c", token="bad", client=client)


def test_push_result_server_error_raises():
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(500, text="boom")))
    with pytest.raises(PushError, match="HTTP 500"):
        push_result({}, url="https://c", token="t", client=client)
