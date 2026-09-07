"""Static API security analysis from OpenAPI / Swagger specs."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable

from argus.core.models import (
    Confidence,
    Finding,
    Likelihood,
    Location,
    Remediation,
    Severity,
)
from argus.core.plugin import Scanner, ScannerContext, scanner
from argus.scanners.dependencies import _loads

_OPENAPI_GLOB = re.compile(r"(?i)(openapi|swagger).*\.(ya?ml|json)$|/openapi\.(ya?ml|json)$")

_SENSITIVE = re.compile(
    r"/(?:admin|internal|users?|accounts?|secrets?|tokens?|keys?)(?:/|$)", re.I,
)


def _parse_openapi(text: str, path: str) -> dict | None:
    if path.endswith((".yaml", ".yml")):
        try:
            import yaml
            return yaml.safe_load(text)
        except Exception:
            return None
    return _loads(text)


@scanner
class ApiScanner(Scanner):
    name = "api"
    category = "api"
    description = "Analyzes OpenAPI specs for auth gaps and sensitive exposure."

    def applies_to(self, project) -> bool:
        return any(
            _OPENAPI_GLOB.search(f.rel_path) or f.rel_path.endswith(("openapi.yaml", "openapi.json"))
            for f in project.files()
        )

    def scan(self, ctx: ScannerContext) -> Iterable[Finding]:
        counter = 0
        for f in ctx.project.files():
            if not (
                _OPENAPI_GLOB.search(f.rel_path)
                or f.rel_path.endswith(("openapi.yaml", "openapi.json", "swagger.yaml", "swagger.json"))
            ):
                continue
            spec = _parse_openapi(f.text(), f.rel_path)
            if not isinstance(spec, dict):
                continue
            paths = spec.get("paths") or {}
            has_global_security = bool(spec.get("security"))
            security_schemes = (spec.get("components") or {}).get("securitySchemes") or {}

            for route, methods in paths.items():
                if not isinstance(methods, dict):
                    continue
                for method, op in methods.items():
                    if method.startswith("x-") or not isinstance(op, dict):
                        continue
                    op_security = op.get("security")
                    secured = (
                        has_global_security
                        or op_security is not None
                        or bool(security_schemes and op_security != [])
                    )
                    if _SENSITIVE.search(route) and not secured:
                        counter += 1
                        yield Finding(
                            id=f"api:no-auth:{counter}",
                            rule_id="api.missing-security",
                            scanner="api",
                            title=f"OpenAPI route lacks security: {method.upper()} {route}",
                            description=(
                                f"`{method.upper()} {route}` is sensitive but has no "
                                f"security requirement in the OpenAPI spec."
                            ),
                            location=Location(path=f.rel_path, snippet=f"{method} {route}"),
                            severity=Severity.HIGH,
                            confidence=Confidence.MEDIUM,
                            likelihood=Likelihood.POSSIBLE,
                            cwe=["CWE-306"],
                            owasp=["A01:2021-Broken Access Control", "A05:2021-Security Misconfiguration"],
                            why_vulnerable="Undocumented auth allows deployment without API protection.",
                            remediation=Remediation(
                                summary="Add securitySchemes and require them on sensitive operations.",
                            ),
                            tags=["api", "openapi"],
                            metadata={"method": method.upper(), "path": route},
                        )

            # GraphQL schema heuristic
            if "graphql" in f.rel_path.lower() or spec.get("graphql"):
                counter += 1
                yield Finding(
                    id=f"api:graphql:{counter}",
                    rule_id="api.graphql-review",
                    scanner="api",
                    title="GraphQL API surface requires manual auth review",
                    description="GraphQL introspection and batching need dedicated auth/rate-limit checks.",
                    location=Location(path=f.rel_path),
                    severity=Severity.INFO,
                    confidence=Confidence.LOW,
                    likelihood=Likelihood.POSSIBLE,
                    cwe=["CWE-770"],
                    owasp=["A04:2021-Insecure Design"],
                    why_vulnerable="GraphQL expands attack surface vs REST.",
                    remediation=Remediation(summary="Disable introspection in production; enforce auth per resolver."),
                    tags=["api", "graphql"],
                )
