"""OSV lookups never drop packages past a fixed count.

The client used to stop at 5000 packages and only log a warning, so a lockfile
padded with junk entries pushed real dependencies out of the scan.
"""

from __future__ import annotations

import json

import httpx
import pytest

from argus.scanners import osv

pytestmark = pytest.mark.osv_network


def test_every_package_is_queried_past_the_old_cap():
    queried: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/querybatch":
            queries = json.loads(request.content)["queries"]
            queried.extend(q["package"]["name"] for q in queries)
            return httpx.Response(200, json={"results": [
                {"vulns": [{"id": "OSV-REAL"}]} if q["package"]["name"] == "real-dep"
                else {} for q in queries]})
        return httpx.Response(200, json={"id": "OSV-REAL", "summary": "real issue"})

    deps = [(f"padding-{i}", "1.0.0") for i in range(6000)] + [("real-dep", "1.0.0")]
    client = httpx.Client(transport=httpx.MockTransport(handler))
    result = osv.query("npm", deps, use_cache=False, client=client)

    assert len(queried) == 6001
    assert [a.id for a in result[("real-dep", "1.0.0")]] == ["OSV-REAL"]
