"""Authentication and authorization analysis (foundation).

Maps route/endpoint definitions to likely auth requirements and flags common
misconfigurations: missing auth on sensitive routes, weak JWT handling, and
routes that accept object IDs without obvious ownership checks nearby.
"""

from __future__ import annotations

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

_FASTAPI_ROUTE = re.compile(
    r"""@(?:app|router)\.(get|post|put|patch|delete)\(\s*['"]([^'"]+)['"]""",
)
_FLASK_ROUTE = re.compile(
    r"""@(?:app|blueprint)\.route\(\s*['"]([^'"]+)['"]""",
)
_EXPRESS_ROUTE = re.compile(
    r"""\.(get|post|put|patch|delete)\(\s*['"]([^'"]+)['"]""",
)

_AUTH_DECORATORS = re.compile(
    r"@(?:login_required|requires_auth|authenticated|authorize|"
    r"permission_required|roles_required|Depends\([^)]*(?:auth|oauth|jwt|"
    r"get_current_user|Security))",
    re.IGNORECASE,
)
_JWT_WEAK = re.compile(
    r"jwt\.(?:decode|verify)\([^)]*(?:verify\s*=\s*False|algorithms\s*=\s*\[[^\]]*none)",
    re.IGNORECASE,
)
_JWT_NONE_ALG = re.compile(r"['\"]none['\"]", re.IGNORECASE)

_SENSITIVE_PATH = re.compile(
    r"/(?:admin|internal|manage|debug|users?|accounts?|billing|settings|"
    r"delete|export|backup|config|secrets?|tokens?|roles?|permissions?)(?:/|$)",
    re.IGNORECASE,
)
_ID_PARAM = re.compile(
    r"\{(\w*(?:id|uuid|user|account|tenant)\w*)\}|:(\w*(?:id|uuid)\w*)",
    re.IGNORECASE,
)
_OAUTH_STATE_MISSING = re.compile(
    r"(?:oauth|openid)[^;\n]{0,120}(?:callback|redirect)[^;\n]{0,80}(?:state|nonce)",
    re.IGNORECASE,
)
_SESSION_INSECURE = re.compile(
    r"(?:session|cookie)\.(?:set|cookie)\([^)]*(?:secure\s*=\s*False|httponly\s*=\s*False)",
    re.IGNORECASE,
)
_OAUTH_TOKEN_IN_URL = re.compile(
    r"(?:access_token|id_token|code)=['\"]?[^&\s'\"]+",
    re.IGNORECASE,
)
_OWNERSHIP_HINT = re.compile(
    r"(owner|tenant|user_id|account_id|current_user|request\.user|"
    r"get_current_user|authorize|permission|forbidden|403)",
    re.IGNORECASE,
)


def _lines(text: str) -> list[str]:
    return text.splitlines()


def _window(lines: list[str], idx: int, before: int = 8, after: int = 12) -> str:
    start = max(0, idx - before)
    end = min(len(lines), idx + after + 1)
    return "\n".join(lines[start:end])


def _route_path(line: str) -> str | None:
    m = _FASTAPI_ROUTE.search(line)
    if m:
        return m.group(2)
    m = _FLASK_ROUTE.search(line)
    if m:
        return m.group(1)
    m = _EXPRESS_ROUTE.search(line)
    if m:
        return m.group(2)
    return None


@scanner
class AuthzScanner(Scanner):
    name = "authz"
    category = "auth"
    description = (
        "Analyzes authentication/authorization patterns on routes and JWT usage."
    )

    def applies_to(self, project) -> bool:
        exts = (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs")
        return any(f.suffix in exts for f in project.files())

    def scan(self, ctx: ScannerContext) -> Iterable[Finding]:
        counter = 0
        for f in ctx.project.files():
            if f.suffix not in (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs"):
                continue
            text = f.text()
            lines = _lines(text)
            for i, line in enumerate(lines):
                for finding in self._check_jwt(f.rel_path, line, i + 1, counter):
                    counter += 1
                    yield finding
                for finding in self._check_oauth_session(f.rel_path, line, i + 1, counter):
                    counter += 1
                    yield finding
                for finding in self._check_routes(f.rel_path, lines, i, counter):
                    counter += 1
                    yield finding

    def _check_oauth_session(
        self, path: str, line: str, line_no: int, counter: int,
    ) -> Iterable[Finding]:
        lower = line.lower()
        if "oauth" in lower or "openid" in lower:
            if re.search(r"callback|redirect", lower) and not re.search(r"state|nonce|pkce", lower):
                yield Finding(
                    id=f"authz:oauth-state:{counter + 1}",
                    rule_id="authz.oauth-missing-state",
                    scanner="authz",
                    title="OAuth callback without state/nonce/PKCE hint",
                    description="OAuth flows should bind callbacks with state, nonce, or PKCE.",
                    location=Location(path=path, start_line=line_no, snippet=line.strip()[:200]),
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    likelihood=Likelihood.POSSIBLE,
                    cwe=["CWE-352"],
                    owasp=["A07:2021-Identification and Authentication Failures"],
                    why_vulnerable="Missing CSRF binding enables authorization code interception.",
                    remediation=Remediation(
                        summary="Use state parameter and PKCE for OAuth/OIDC callbacks.",
                    ),
                    tags=["auth", "oauth"],
                )
        if _OAUTH_TOKEN_IN_URL.search(line):
            yield Finding(
                id=f"authz:token-url:{counter + 1}",
                rule_id="authz.token-in-url",
                scanner="authz",
                title="Token or authorization code in URL",
                description="Tokens in URLs leak via logs, Referer headers, and browser history.",
                location=Location(path=path, start_line=line_no, snippet=line.strip()[:200]),
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                likelihood=Likelihood.POSSIBLE,
                cwe=["CWE-598"],
                owasp=["A07:2021-Identification and Authentication Failures"],
                why_vulnerable="URL query parameters are not a secure token channel.",
                remediation=Remediation(summary="Exchange codes server-side; never pass tokens in URLs."),
                tags=["auth", "oauth", "session"],
            )
        if _SESSION_INSECURE.search(line):
            yield Finding(
                id=f"authz:session-cookie:{counter + 1}",
                rule_id="authz.insecure-session-cookie",
                scanner="authz",
                title="Session cookie missing Secure or HttpOnly",
                description="Session cookies should set Secure and HttpOnly flags.",
                location=Location(path=path, start_line=line_no, snippet=line.strip()[:200]),
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                likelihood=Likelihood.LIKELY,
                cwe=["CWE-614"],
                owasp=["A07:2021-Identification and Authentication Failures"],
                why_vulnerable="Cookies without HttpOnly/Secure are easier to steal or replay.",
                remediation=Remediation(
                    summary="Set Secure=True and HttpOnly=True on session cookies.",
                ),
                tags=["auth", "session"],
            )

    def _check_jwt(self, path: str, line: str, line_no: int,
                   counter: int) -> Iterable[Finding]:
        if "jwt" not in line.lower() and "jsonwebtoken" not in line.lower():
            return
        if not (_JWT_WEAK.search(line) or (
            "algorithms" in line.lower() and _JWT_NONE_ALG.search(line)
        )):
            return
        yield Finding(
            id=f"authz:jwt-weak:{counter + 1}",
            rule_id="authz.jwt-weak-validation",
            scanner="authz",
            title="Insecure JWT validation",
            description=(
                "JWT verification is disabled or allows the 'none' algorithm, "
                "enabling token forgery."
            ),
            location=Location(path=path, start_line=line_no, snippet=line.strip()[:200]),
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            likelihood=Likelihood.LIKELY,
            cwe=["CWE-347"],
            owasp=["A07:2021-Identification and Authentication Failures"],
            why_vulnerable=(
                "Accepting unsigned JWTs or skipping verification lets attackers "
                "forge tokens and impersonate users."
            ),
            attacker_perspective=(
                "Craft a JWT with alg=none or tamper claims after stripping "
                "signature verification."
            ),
            business_impact="Full authentication bypass for affected endpoints.",
            remediation=Remediation(
                summary="Verify JWT signatures with an explicit allowlist of algorithms.",
                guidance=(
                    "Use jwt.decode(..., algorithms=['RS256']); never set verify=False "
                    "in production."
                ),
            ),
            tags=["auth", "jwt"],
        )

    def _check_routes(
        self, path: str, lines: list[str], idx: int, counter: int,
    ) -> Iterable[Finding]:
        route_path = _route_path(lines[idx])
        if not route_path or not _SENSITIVE_PATH.search(route_path):
            return

        window = _window(lines, idx)
        if not _AUTH_DECORATORS.search(window):
            yield Finding(
                id=f"authz:missing-auth:{counter + 1}",
                rule_id="authz.missing-authentication",
                scanner="authz",
                title=f"Sensitive route may lack authentication: {route_path}",
                description=(
                    f"Route `{route_path}` matches sensitive path patterns and has no "
                    f"obvious auth decorator or Depends() in the surrounding code."
                ),
                location=Location(path=path, start_line=idx + 1, snippet=lines[idx].strip()[:200]),
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                likelihood=Likelihood.POSSIBLE,
                cwe=["CWE-306"],
                owasp=["A01:2021-Broken Access Control"],
                why_vulnerable=(
                    "Administrative or sensitive endpoints without authentication allow "
                    "unauthenticated access."
                ),
                attacker_perspective="Call the endpoint directly without credentials.",
                business_impact="Unauthorized access to privileged functionality or data.",
                remediation=Remediation(
                    summary="Require authentication on sensitive routes.",
                    guidance=(
                        "Add framework-native auth (Depends(get_current_user), "
                        "@login_required, middleware) before handler logic."
                    ),
                ),
                tags=["auth", "authorization"],
                metadata={"route": route_path},
            )

        if _ID_PARAM.search(route_path) and not _OWNERSHIP_HINT.search(window):
            yield Finding(
                id=f"authz:idor-hint:{counter + 2}",
                rule_id="authz.idor-hint",
                scanner="authz",
                title=f"Object-ID route without obvious ownership check: {route_path}",
                description=(
                    f"Route `{route_path}` includes an object identifier parameter "
                    f"but no ownership/tenant check is visible nearby (IDOR/BOLA risk)."
                ),
                location=Location(path=path, start_line=idx + 1, snippet=lines[idx].strip()[:200]),
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
                likelihood=Likelihood.POSSIBLE,
                cwe=["CWE-639"],
                owasp=["A01:2021-Broken Access Control"],
                why_vulnerable=(
                    "Endpoints keyed by user-supplied IDs need authorization that the "
                    "caller owns or may access the referenced object."
                ),
                attacker_perspective="Iterate IDs to access other users' records (IDOR/BOLA).",
                business_impact="Cross-account data exposure or unauthorized actions.",
                remediation=Remediation(
                    summary="Verify the authenticated principal may access the requested ID.",
                    guidance=(
                        "Compare route/user ID to session tenant; return 403 on mismatch."
                    ),
                ),
                tags=["auth", "authorization", "idor"],
                metadata={"route": route_path},
            )
