"""argus push: token only over HTTPS, one exception type, encoded job ids."""

from __future__ import annotations

import httpx
import pytest

from argus.upload import PushError, push_result, push_sbom


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


@pytest.mark.parametrize(
    "url",
    [
        "http://cloud.example.com",
        "http://10.0.0.5:8080",
        "ftp://cloud.example.com",
        "cloud.example.com",
    ],
)
def test_token_is_never_sent_over_plain_http(url):
    sent: list[httpx.Request] = []
    client = _client(lambda r: sent.append(r) or httpx.Response(200, json={}))
    with pytest.raises(PushError):
        push_result({}, url=url, token="secret", client=client)
    with pytest.raises(PushError):
        push_sbom({}, target="t", fmt="cyclonedx", url=url, token="secret", client=client)
    assert sent == []


@pytest.mark.parametrize(
    "url", ["http://127.0.0.1:8000", "http://localhost:8000", "http://[::1]:8000"]
)
def test_plain_http_allowed_for_loopback(url):
    client = _client(lambda r: httpx.Response(201, json={"scanId": "1"}))
    assert push_result({}, url=url, token="t", client=client) == {"scanId": "1"}


def test_job_id_is_path_encoded():
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.raw_path.decode())
        if request.method == "POST":
            return httpx.Response(202, json={"jobId": "../../admin?x=1"})
        return httpx.Response(200, json={"status": "completed", "scanId": "s1"})

    out = push_result({}, url="https://cloud.example.com", token="t", client=_client(handler))
    assert out["scanId"] == "s1"
    assert seen[1] == "/api/ingest/jobs/..%2F..%2Fadmin%3Fx%3D1"


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(202, text="not json"),
        httpx.Response(202, json=["unexpected", "shape"]),
    ],
)
def test_malformed_responses_raise_push_error(response):
    client = _client(lambda r: response)
    with pytest.raises(PushError):
        push_result({}, url="https://cloud.example.com", token="t", client=client)


def test_poll_network_error_is_push_error():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(202, json={"jobId": "j1"})
        raise httpx.ConnectError("reset")

    with pytest.raises(PushError, match="ConnectError"):
        push_result({}, url="https://cloud.example.com", token="t", client=_client(handler))
