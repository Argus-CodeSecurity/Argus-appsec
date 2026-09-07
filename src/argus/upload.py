"""Upload a scan result to an Argus Cloud control plane (``argus push``).

Turns a local :class:`~argus.core.models.ScanResult` into a small ingest payload
and POSTs it to the cloud's authenticated ``/api/scans`` endpoint, so scans land
in the hosted dashboard's history and trends. The cloud base URL and an API
token come from flags or the ``ARGUS_CLOUD_URL`` / ``ARGUS_CLOUD_TOKEN``
environment variables.

Privacy: the payload carries only finding *metadata* (rule id, severity, title,
location reference, CWE) plus the aggregate risk score and severity counts. It
never sends source code, snippets, or secret values. httpx does not follow
redirects by default, so the bearer token cannot be bounced to another host.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from argus.core.models import ScanResult, Severity

if TYPE_CHECKING:
    import httpx

_INGEST_PATH = "/api/scans"
_SBOM_PATH = "/api/sbom"
_COUNT_KEYS = ("critical", "high", "medium", "low")


class PushError(RuntimeError):
    """Uploading a scan to the cloud failed."""


def build_ingest_payload(
    result: ScanResult, *, min_severity: Severity = Severity.LOW
) -> dict[str, Any]:
    """Build the compact ingest payload the cloud's ``/api/scans`` expects.

    Findings below ``min_severity`` are dropped (info-level noise is not stored),
    and the severity counts are derived from the findings actually sent so the
    dashboard's headline counts and drill-down always agree.
    """
    counts = dict.fromkeys(_COUNT_KEYS, 0)
    findings: list[dict[str, Any]] = []
    for f in result.sorted_findings():
        if f.severity < min_severity:
            continue
        label = f.severity.label.lower()
        if label in counts:
            counts[label] += 1
        findings.append(
            {
                "severity": label,
                "rule": f.rule_id,
                "title": f.title,
                "location": f.location.as_ref(),
                "cwe": ";".join(f.cwe) or None,
                "fingerprint": f.fingerprint(),
            }
        )
    return {
        "target": result.target,
        "argus_version": result.argus_version,
        "risk_score": round(result.aggregate_risk()),
        "counts": counts,
        "findings": findings,
    }


def push_result(
    payload: dict[str, Any],
    *,
    url: str,
    token: str,
    timeout: float = 30.0,
    client: httpx.Client | None = None,
) -> dict[str, Any]:
    """POST an ingest payload to ``{url}/api/scans`` with a bearer token.

    Returns the decoded JSON response (e.g. ``{"scanId": ..., "url": ...}``).
    Raises :class:`PushError` on a network problem or a non-2xx response. A
    caller may pass its own ``client`` (used by tests with a mock transport).
    """
    import httpx

    endpoint = url.rstrip("/") + _INGEST_PATH
    headers = {"Authorization": f"Bearer {token}", "User-Agent": "argus-push"}
    owns_client = client is None
    # follow_redirects stays False (the default) so the Authorization header is
    # never replayed to a redirect target.
    client = client or httpx.Client(timeout=timeout)
    try:
        try:
            resp = client.post(endpoint, json=payload, headers=headers)
        except httpx.HTTPError as exc:
            raise PushError(f"could not reach {endpoint}: {exc}") from exc
        if resp.status_code in (401, 403):
            raise PushError(
                "authentication failed; check the cloud API token "
                "(--token / ARGUS_CLOUD_TOKEN)."
            )
        if resp.status_code >= 300:
            raise PushError(
                f"cloud rejected the scan (HTTP {resp.status_code}): "
                f"{resp.text[:300]}"
            )
        try:
            return resp.json()
        except ValueError:
            return {}
    finally:
        if owns_client:
            client.close()


def push_sbom(
    payload: dict[str, Any],
    *,
    target: str,
    fmt: str,
    url: str,
    token: str,
    timeout: float = 30.0,
    client: httpx.Client | None = None,
) -> dict[str, Any]:
    """POST a CycloneDX or SPDX document to ``{url}/api/sbom``."""
    import httpx

    endpoint = url.rstrip("/") + _SBOM_PATH
    headers = {"Authorization": f"Bearer {token}", "User-Agent": "argus-push"}
    body = {"target": target, "format": fmt, "payload": payload}
    owns_client = client is None
    client = client or httpx.Client(timeout=timeout)
    try:
        try:
            resp = client.post(endpoint, json=body, headers=headers)
        except httpx.HTTPError as exc:
            raise PushError(f"could not reach {endpoint}: {exc}") from exc
        if resp.status_code in (401, 403):
            raise PushError(
                "authentication failed; check the cloud API token "
                "(--token / ARGUS_CLOUD_TOKEN)."
            )
        if resp.status_code >= 300:
            raise PushError(
                f"cloud rejected the SBOM (HTTP {resp.status_code}): "
                f"{resp.text[:300]}"
            )
        try:
            return resp.json()
        except ValueError:
            return {}
    finally:
        if owns_client:
            client.close()
