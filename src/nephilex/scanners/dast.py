"""Authorized DAST-lite: safe dynamic checks (spec §22).

The target URL must come from the operator: ``--live-target`` (which the CLI
places in ``Config.dast_url``, a field config files cannot set), an explicit
config file outside the scanned project, or the ``NEPHILEX_DAST_URL`` environment
variable. A URL declared
in the scanned project's own ``.nephilex.yml`` is ignored: in CI that file comes
from whoever opened the pull request, and honoring it would let a fork point
the runner at cloud metadata or other internal services.
"""

from __future__ import annotations

import logging
import os
import re
from collections.abc import Iterable
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import yaml

from nephilex.core.config import CONFIG_FILENAMES
from nephilex.core.models import Confidence, Finding, Likelihood, Location, Remediation, Severity
from nephilex.core.plugin import Scanner, ScannerContext, scanner

if TYPE_CHECKING:
    from nephilex.dynamic.posture import FetchResult

log = logging.getLogger("nephilex.scanners.dast")


# The HTTP client (nephilex.dynamic.posture) is only needed when a target is
# probed, so it is imported on first use instead of when scanners register.
def guarded_get(url: str, **kwargs: Any) -> FetchResult | None:
    from nephilex.dynamic.posture import guarded_get as impl

    return impl(url, **kwargs)


def probe(url: str, **kwargs: Any) -> list[Finding]:
    from nephilex.dynamic.posture import probe as impl

    return impl(url, **kwargs)


_PROBE = "nephilex-dast-probe-7x3k"
_REFLECTED = re.compile(re.escape(_PROBE))
_UA = {"User-Agent": "Nephilex-DAST/1.0 (authorized)"}
_MAX_BODY = 1_000_000
ENV_URL = "NEPHILEX_DAST_URL"


def _safe_get(url: str, timeout: float = 8.0) -> FetchResult | None:
    # Redirects are walked with SSRF checks, the peer address is verified after
    # connect, and the body is capped; see nephilex.dynamic.posture.GuardedSession.
    return guarded_get(url, timeout=timeout, max_bytes=_MAX_BODY, headers=_UA)


def _project_declared_urls(root: Path) -> set[str]:
    """DAST URLs declared in the scanned project's own config files."""
    urls: set[str] = set()
    for name in CONFIG_FILENAMES:
        path = root / name
        try:
            if not path.is_file():
                continue
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError, UnicodeDecodeError, RecursionError):
            continue
        opts = data.get("scanner_options") if isinstance(data, dict) else None
        dast = opts.get("dast") if isinstance(opts, dict) else None
        url = dast.get("url") if isinstance(dast, dict) else None
        if url:
            urls.add(str(url).strip())
    return urls


def operator_target(ctx: ScannerContext) -> str | None:
    """The DAST URL the operator asked for, or None.

    ``NEPHILEX_DAST_URL`` wins. Otherwise ``scanner_options.dast.url`` is used
    unless the same value is declared in the scanned project's config, which
    means it came from the repository rather than from the operator.
    """
    env = os.environ.get(ENV_URL, "").strip()
    if env:
        return env
    if ctx.config.dast_url:
        return ctx.config.dast_url.strip()
    url = ctx.config.options_for("dast").get("url")
    if not url:
        return None
    url = str(url).strip()
    if url in _project_declared_urls(ctx.project.root):
        log.warning(
            "Ignoring the DAST URL from the scanned project's .nephilex.yml; "
            "pass --live-target or set %s to choose a target.",
            ENV_URL,
        )
        return None
    return url


@scanner
class DastScanner(Scanner):
    name = "dast"
    category = "dynamic"
    description = (
        "Authorized dynamic checks: posture, reflected input, and safe header tests. "
        "Set the target with --live-target or NEPHILEX_DAST_URL."
    )

    def applies_to(self, project) -> bool:
        return True

    def scan(self, ctx: ScannerContext) -> Iterable[Finding]:
        url = operator_target(ctx)
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
                        remediation=Remediation(
                            summary="Encode output and validate input server-side."
                        ),
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
                    remediation=Remediation(
                        summary="Restrict Access-Control-Allow-Origin to trusted domains."
                    ),
                    tags=["dast", "dynamic", "api"],
                    metadata={"verification": "verified", "finding_kind": "dynamic"},
                )
