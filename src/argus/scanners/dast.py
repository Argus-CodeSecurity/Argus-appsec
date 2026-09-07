"""Authorized DAST-lite: safe dynamic checks (spec §22)."""

from __future__ import annotations

import re
from collections.abc import Iterable
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from argus.core.models import Confidence, Finding, Likelihood, Location, Remediation, Severity
from argus.core.plugin import Scanner, ScannerContext, scanner
from argus.dynamic.posture import probe

_PROBE = "argus-dast-probe-7x3k"
_REFLECTED = re.compile(re.escape(_PROBE))


def _safe_get(url: str, timeout: float = 8.0) -> httpx.Response | None:
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True, verify=True) as client:
            return client.get(url, headers={"User-Agent": "Argus-DAST/1.0 (authorized)"})
    except httpx.HTTPError:
        return None


@scanner
class DastScanner(Scanner):
    name = "dast"
    category = "dynamic"
    description = (
        "Authorized dynamic checks: posture, reflected input, and safe header tests. "
        "Configure with scanner_options.dast.url or --live-target."
    )

    def applies_to(self, project) -> bool:
        return True

    def scan(self, ctx: ScannerContext) -> Iterable[Finding]:
        opts = ctx.config.options_for("dast")
        url = opts.get("url")
        if not url:
            return

        for finding in probe(str(url)):
            finding.scanner = "dast"
            finding.tags = list(set([*finding.tags, "dynamic", "dast"]))
            finding.metadata["verification"] = "verified"
            finding.metadata["finding_kind"] = "dynamic"
            yield finding

        parsed = urlparse(str(url))
        if parsed.query:
            qs = parse_qs(parsed.query, keep_blank_values=True)
            for key in list(qs.keys())[:5]:
                qs[key] = [_PROBE]
                test_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
                resp = _safe_get(test_url)
                if resp and _REFLECTED.search(resp.text[:50000]):
                    yield Finding(
                        id=f"dast:reflected:{key}",
                        rule_id="dast.reflected-input",
                        scanner="dast",
                        title=f"Reflected input in parameter '{key}'",
                        description="Benign probe string reflected in response (potential XSS vector).",
                        location=Location(path=test_url, snippet=key),
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        likelihood=Likelihood.POSSIBLE,
                        cwe=["CWE-79"],
                        owasp=["A03:2021-Injection"],
                        why_vulnerable="Reflected user input may enable cross-site scripting.",
                        remediation=Remediation(summary="Encode output and validate input server-side."),
                        tags=["dast", "dynamic", "xss"],
                        metadata={"verification": "verified", "finding_kind": "dynamic"},
                    )

        cors_resp = _safe_get(str(url))
        if cors_resp:
            acao = cors_resp.headers.get("access-control-allow-origin", "")
            if acao == "*":
                yield Finding(
                    id="dast:cors-wildcard",
                    rule_id="dast.cors-wildcard",
                    scanner="dast",
                    title="CORS allows any origin",
                    description="Access-Control-Allow-Origin: * may expose authenticated APIs.",
                    location=Location(path=str(url), snippet=acao),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    likelihood=Likelihood.POSSIBLE,
                    why_vulnerable="Wildcard CORS on sensitive endpoints enables cross-origin abuse.",
                    remediation=Remediation(summary="Restrict Access-Control-Allow-Origin to trusted domains."),
                    tags=["dast", "dynamic", "api"],
                    metadata={"verification": "verified", "finding_kind": "dynamic"},
                )
