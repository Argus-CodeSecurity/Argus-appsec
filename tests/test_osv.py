"""Tests for the hardened OSV client: batching, caching, and retry.

All tests use an injected httpx.MockTransport, they never touch the real
network. The `osv_network` marker opts each out of the global offline fixture.
"""

from __future__ import annotations

import httpx
import pytest

from argus.scanners import osv

pytestmark = pytest.mark.osv_network


def _mock_client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def _vuln_json(vid: str) -> dict:
    return {
        "id": vid,
        "summary": f"Issue {vid}",
        "aliases": ["CVE-2024-0001"],
        "database_specific": {"severity": "HIGH"},
        "affected": [{"ranges": [{"events": [{"fixed": "2.0.0"}]}]}],
    }


# --- batching: every package is queried, nothing silently dropped ----------
def test_query_batches_all_packages(monkeypatch):
    monkeypatch.setattr(osv, "_BATCH_SIZE", 2)  # force chunking with few packages
    batch_calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/querybatch":
            batch_calls["n"] += 1
            import json

            queries = json.loads(request.content)["queries"]
            # Each queried package is "vulnerable" so we can assert full coverage.
            return httpx.Response(
                200, json={"results": [{"vulns": [{"id": "OSV-1"}]} for _ in queries]}
            )
        return httpx.Response(200, json=_vuln_json("OSV-1"))

    deps = {"a": "1", "b": "2", "c": "3", "d": "4", "e": "5"}
    result = osv.query("PyPI", deps, use_cache=False, client=_mock_client(handler))

    # 5 packages, batch size 2 -> 3 requests, and every package resolved.
    assert batch_calls["n"] == 3
    assert len(result) == 5


# --- caching: a second lookup does not re-fetch the vuln record ------------
def test_query_uses_disk_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_CACHE_DIR", str(tmp_path))
    fetches = {"vulns": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/querybatch":
            return httpx.Response(200, json={"results": [{"vulns": [{"id": "OSV-9"}]}]})
        fetches["vulns"] += 1
        return httpx.Response(200, json=_vuln_json("OSV-9"))

    deps = {"pkg": "1.0.0"}
    osv.query("PyPI", deps, use_cache=True, client=_mock_client(handler))
    osv.query("PyPI", deps, use_cache=True, client=_mock_client(handler))

    # The vuln record is fetched once and served from cache the second time.
    assert fetches["vulns"] == 1


def test_cache_roundtrip_and_expiry(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_CACHE_DIR", str(tmp_path))
    cache_dir = osv._cache_dir()
    osv._cache_put("OSV-X", {"id": "OSV-X"}, cache_dir)
    assert osv._cache_get("OSV-X", cache_dir) == {"id": "OSV-X"}

    # Past the TTL, the entry is treated as absent.
    monkeypatch.setattr(osv, "_CACHE_TTL", -1)
    assert osv._cache_get("OSV-X", cache_dir) is None


def test_cache_filename_is_traversal_safe(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_CACHE_DIR", str(tmp_path))
    cache_dir = osv._cache_dir()
    # A malicious advisory id must not escape the cache directory.
    path = osv._cache_file(cache_dir, "../../etc/passwd")
    assert tmp_path in path.parents
    assert ".." not in path.name


# --- retry: transient failures are retried before giving up ----------------
class _Resp:
    def __init__(self, status: int) -> None:
        self.status_code = status


class _FlakyClient:
    """Minimal stand-in exposing the `.request` surface `_request_with_retry` uses."""

    def __init__(self, statuses: list[int]) -> None:
        self._statuses = statuses
        self.calls = 0

    def request(self, method, url, **kwargs):
        self.calls += 1
        return _Resp(self._statuses.pop(0))


def test_request_retries_transient_status(monkeypatch):
    monkeypatch.setattr(osv, "_SLEEP", lambda _s: None)  # no real backoff sleep
    client = _FlakyClient([503, 503, 200])
    resp = osv._request_with_retry(client, "GET", "https://x/y")  # type: ignore[arg-type]
    assert resp.status_code == 200
    assert client.calls == 3


def test_request_retries_network_error_then_succeeds(monkeypatch):
    monkeypatch.setattr(osv, "_SLEEP", lambda _s: None)
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            raise httpx.ConnectError("boom")
        return httpx.Response(200, json={"ok": True})

    resp = osv._request_with_retry(_mock_client(handler), "GET", "https://x/y")
    assert resp.status_code == 200
    assert calls["n"] == 2


def test_query_raises_osverror_on_persistent_failure(monkeypatch):
    monkeypatch.setattr(osv, "_SLEEP", lambda _s: None)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)  # always failing

    with pytest.raises(osv.OSVError):
        osv.query("PyPI", {"a": "1"}, use_cache=False, client=_mock_client(handler))
