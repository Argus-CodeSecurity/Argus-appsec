"""Authentication and authorization analysis (foundation).

Maps route/endpoint definitions to likely auth requirements and flags common
misconfigurations: missing auth on sensitive routes, weak JWT handling, and
routes that accept object IDs without obvious ownership checks nearby.
"""

from __future__ import annotations

import bisect
import re
from collections.abc import Iterable

from nephilex.core.models import (
    Confidence,
    Finding,
    Likelihood,
    Location,
    Remediation,
    Severity,
)
from nephilex.core.plugin import Scanner, ScannerContext, scanner
from nephilex.scanners._text import MAX_SCAN_LINE, snippet_line
from nephilex.scanners.patterns import _is_test_file

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
# Flask/Werkzeug, Django, Starlette and aiohttp all spell it
# ``response.set_cookie(key, value, ..., secure=..., httponly=...)``.
_SET_COOKIE = re.compile(r"\.set_cookie\s*\(")
_DEF_SET_COOKIE = re.compile(r"\bdef\s+set_cookie\b")
_FLAG_KW = {
    "secure": re.compile(r"(?i)(?<![\w])secure\s*=\s*([\w.]+)"),
    "httponly": re.compile(r"(?i)(?<![\w])httponly\s*=\s*([\w.]+)"),
}
#: Longest call text gathered for one set_cookie(...) across lines.
_MAX_CALL_TEXT = 4000
_OAUTH_TOKEN_IN_URL = re.compile(
    r"https?://[^\s'\"]+(?:\?|&)(?:access_token|id_token|code)=[^&\s'\"]+"
    r"|(?:\?|&)(?:access_token|id_token|code)=[A-Za-z0-9._\-]{8,}",
    re.IGNORECASE,
)
_TOKEN_URL_SUPPRESS = re.compile(
    r"(?i)(?:detail\s*=|message\s*=|description\s*=|Field\(|example|"
    r"HTTPException|raise\s+\w|#|//|invalid|missing|required|error|"
    r"schema|openapi|swagger|\"access_token\"\s*:|'access_token'\s*:)",
)
_PUBLIC_ROUTE = re.compile(
    r"/(?:login|signin|signout|logout|signup|register|forgot|reset|password|"
    r"verification|verify|callback|oauth|refresh|health|docs|openapi|swagger|"
    r"redoc|static|assets|favicon|metrics|probe)(?:/|$)",
    re.IGNORECASE,
)
_ROUTER_CALL = re.compile(r"APIRouter\s*\(", re.IGNORECASE)
_ROUTER_DEPS_KEY = re.compile(r"dependencies\s*=\s*\[", re.IGNORECASE)
_OWNERSHIP_HINT = re.compile(
    r"(owner|tenant|user_id|account_id|current_user|request\.user|"
    r"get_current_user|authorize|permission|forbidden|403)",
    re.IGNORECASE,
)


def _has_router_auth(text: str) -> bool:
    """True if some `APIRouter(` is followed by `dependencies=[` before any `)`,
    with `Depends` appearing before the list's closing `]`.

    This used to be one DOTALL regex over the whole file, which backtracked
    across the rest of the file for every unterminated `APIRouter(` (cubic on a
    hostile file). Here every token is located once and the ordering
    conditions are checked with binary search, so the cost is O(n log n).
    """
    calls = [m.end() for m in _ROUTER_CALL.finditer(text)]
    if not calls:
        return False
    closes = [m.start() for m in re.finditer(r"\)", text)]
    brackets = [m.start() for m in re.finditer(r"\]", text)]
    depends = [m.start() for m in re.finditer(r"(?i)Depends", text)]
    for key in _ROUTER_DEPS_KEY.finditer(text):
        # Nearest preceding APIRouter( call, with no `)` between it and the key.
        ci = bisect.bisect_right(calls, key.start()) - 1
        if ci < 0:
            continue
        pi = bisect.bisect_left(closes, calls[ci])
        if pi < len(closes) and closes[pi] < key.start():
            continue
        # `Depends` before the first `]` after the opening bracket.
        bi = bisect.bisect_left(brackets, key.end())
        limit = brackets[bi] if bi < len(brackets) else len(text)
        di = bisect.bisect_left(depends, key.end())
        if di < len(depends) and depends[di] + len("Depends") <= limit:
            return True
    return False


def _call_text(lines: list[str], idx: int, start: int) -> str:
    """Text of the call starting at ``lines[idx][start:]`` up to its closing ``)``.

    Bounded by :data:`_MAX_CALL_TEXT` characters and 40 lines; parentheses inside
    single-line string literals are ignored. Linear in the text it reads.
    """
    out: list[str] = []
    depth = 0
    seen = 0
    for li in range(idx, min(len(lines), idx + 40)):
        segment = lines[li][start:] if li == idx else lines[li]
        quote = ""
        for ch in segment:
            seen += 1
            if seen > _MAX_CALL_TEXT:
                return "".join(out)
            out.append(ch)
            if quote:
                if ch == quote:
                    quote = ""
            elif ch in "'\"":
                quote = ch
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth <= 0:
                    return "".join(out)
        out.append("\n")
    return "".join(out)


def _top_level_commas(call: str) -> int:
    """Commas between the outer parentheses of ``call``, outside nested brackets/strings."""
    depth = 0
    quote = ""
    count = 0
    for ch in call:
        if quote:
            if ch == quote:
                quote = ""
        elif ch in "'\"":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 1:
            count += 1
    return count


def _receiver_start(line: str, pos: int) -> int:
    """Start of the dotted receiver ending at ``pos`` (``resp`` in ``resp.set_cookie``)."""
    while pos > 0 and (line[pos - 1].isalnum() or line[pos - 1] in "_."):
        pos -= 1
    return pos


def _flag_state(value: str | None) -> str:
    """``missing``, ``on``, ``off`` or ``unknown`` for a keyword's source text."""
    if value is None:
        return "missing"
    if value in ("True", "1"):
        return "on"
    if value in ("False", "0", "None"):
        return "off"
    return "unknown"


def _lines(text: str) -> list[str]:
    # Lines are cut to the shared scan limit: the route and JWT checks below
    # run on them and on windows of them, and none needs more than that.
    return [line[:MAX_SCAN_LINE] for line in text.splitlines()]


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
    description = "Analyzes authentication/authorization patterns on routes and JWT usage."

    def applies_to(self, project) -> bool:
        exts = (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs")
        return any(f.suffix in exts for f in project.files())

    def scan(self, ctx: ScannerContext) -> Iterable[Finding]:
        counter = 0
        for f in ctx.project.files():
            if f.suffix not in (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs"):
                continue
            if _is_test_file(f.rel_path):
                continue
            text = f.text()
            lines = _lines(text)
            file_has_router_auth = _has_router_auth(text)
            for i, line in enumerate(lines):
                for finding in self._check_jwt(f.rel_path, line, i + 1, counter):
                    counter += 1
                    yield finding
                if f.suffix == ".py" and "set_cookie" in line:
                    for finding in self._check_set_cookie(f.rel_path, lines, i, counter):
                        counter += 1
                        yield finding
                for finding in self._check_oauth_session(f.rel_path, line, i + 1, counter):
                    counter += 1
                    yield finding
                for finding in self._check_routes(
                    f.rel_path,
                    lines,
                    i,
                    counter,
                    file_has_router_auth,
                ):
                    counter += 1
                    yield finding

    def _check_oauth_session(
        self,
        path: str,
        line: str,
        line_no: int,
        counter: int,
    ) -> Iterable[Finding]:
        lower = line.lower()
        if (
            ("oauth" in lower or "openid" in lower)
            and re.search(r"callback|redirect", lower)
            and not re.search(r"state|nonce|pkce", lower)
        ):
            yield Finding(
                id=f"authz:oauth-state:{counter + 1}",
                rule_id="authz.oauth-missing-state",
                scanner="authz",
                title="OAuth callback without state/nonce/PKCE hint",
                description="OAuth flows should bind callbacks with state, nonce, or PKCE.",
                location=Location(path=path, start_line=line_no, snippet=snippet_line(line, 200)),
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
        if _OAUTH_TOKEN_IN_URL.search(line) and not _TOKEN_URL_SUPPRESS.search(line):
            yield Finding(
                id=f"authz:token-url:{counter + 1}",
                rule_id="authz.token-in-url",
                scanner="authz",
                title="Token or authorization code in URL",
                description="Tokens in URLs leak via logs, Referer headers, and browser history.",
                location=Location(path=path, start_line=line_no, snippet=snippet_line(line, 200)),
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                likelihood=Likelihood.POSSIBLE,
                cwe=["CWE-598"],
                owasp=["A07:2021-Identification and Authentication Failures"],
                why_vulnerable="URL query parameters are not a secure token channel.",
                remediation=Remediation(
                    summary="Exchange codes server-side; never pass tokens in URLs."
                ),
                tags=["auth", "oauth", "session"],
            )
        if _SESSION_INSECURE.search(line):
            yield Finding(
                id=f"authz:session-cookie:{counter + 1}",
                rule_id="authz.insecure-session-cookie",
                scanner="authz",
                title="Session cookie missing Secure or HttpOnly",
                description="Session cookies should set Secure and HttpOnly flags.",
                location=Location(path=path, start_line=line_no, snippet=snippet_line(line, 200)),
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

    def _check_set_cookie(
        self, path: str, lines: list[str], idx: int, counter: int
    ) -> Iterable[Finding]:
        """``set_cookie(...)`` without ``secure=True`` / ``httponly=True``.

        The call usually spans several lines, so its text is gathered up to the
        closing parenthesis first. A flag set to anything other than a literal
        (``secure=app.config["SECURE"]``) is not judged.
        """
        line = lines[idx]
        m = _SET_COOKIE.search(line)
        if m is None or _DEF_SET_COOKIE.search(line):
            return
        before = line[: m.start()]
        if "#" in before or (before.count('"') + before.count("'")) % 2:
            return  # mentioned in a comment or a string, not called
        call = _call_text(lines, idx, m.start())
        if _top_level_commas(call) == 0 or "**" in call:
            # ``**kwargs`` may carry the flags, so the call cannot be judged.
            # ``jar.set_cookie(cookie)`` (http.cookiejar, requests) takes a ready
            # Cookie object; the web-framework form is set_cookie(key, value, ...).
            return
        flags = {}
        for name, rx in _FLAG_KW.items():
            fm = rx.search(call)
            flags[name] = fm.group(1) if fm else None
        location = Location(
            path=path,
            start_line=idx + 1,
            end_line=idx + 1,
            start_column=_receiver_start(line, m.start()) + 1,
            end_column=m.end() + 1,
            snippet=snippet_line(line),
        )
        secure = _flag_state(flags["secure"])
        if secure in ("off", "missing"):
            explicit = secure == "off"
            yield Finding(
                id=f"authz:session-cookie:{counter + 1}",
                rule_id="authz.insecure-session-cookie",
                scanner="authz",
                title="Cookie set without the Secure flag",
                description=(
                    "set_cookie() is called with secure=False."
                    if explicit
                    else "set_cookie() is called without secure=True (the default is False)."
                ),
                location=location,
                severity=Severity.MEDIUM if explicit else Severity.LOW,
                confidence=Confidence.HIGH if explicit else Confidence.MEDIUM,
                likelihood=Likelihood.LIKELY if explicit else Likelihood.POSSIBLE,
                cwe=["CWE-614"],
                owasp=["A05:2021-Security Misconfiguration"],
                why_vulnerable=(
                    "Without the Secure attribute the browser also sends the cookie over "
                    "plain HTTP, where anyone on the network path can read it."
                ),
                attacker_perspective="Sniff or downgrade one HTTP request to capture the cookie.",
                business_impact="Session hijacking or disclosure of the cookie's value.",
                remediation=Remediation(
                    summary="Pass secure=True (and httponly=True, samesite='Lax') to set_cookie().",
                ),
                tags=["auth", "session", "cookie"],
            )
        httponly = _flag_state(flags["httponly"])
        if httponly in ("off", "missing"):
            explicit = httponly == "off"
            yield Finding(
                id=f"authz:cookie-httponly:{counter + 2}",
                rule_id="authz.cookie-missing-httponly",
                scanner="authz",
                title="Cookie set without the HttpOnly flag",
                description=(
                    "set_cookie() is called with httponly=False."
                    if explicit
                    else "set_cookie() is called without httponly=True (the default is False)."
                ),
                location=location,
                severity=Severity.LOW,
                confidence=Confidence.HIGH if explicit else Confidence.MEDIUM,
                likelihood=Likelihood.POSSIBLE,
                cwe=["CWE-1004"],
                owasp=["A05:2021-Security Misconfiguration"],
                why_vulnerable=(
                    "Without HttpOnly, script running in the page (for example through "
                    "an XSS bug) can read the cookie."
                ),
                attacker_perspective="Use any script injection to read document.cookie.",
                business_impact="Session theft when combined with cross-site scripting.",
                remediation=Remediation(summary="Pass httponly=True to set_cookie()."),
                tags=["auth", "session", "cookie"],
            )

    def _check_jwt(self, path: str, line: str, line_no: int, counter: int) -> Iterable[Finding]:
        if "jwt" not in line.lower() and "jsonwebtoken" not in line.lower():
            return
        if not (
            _JWT_WEAK.search(line) or ("algorithms" in line.lower() and _JWT_NONE_ALG.search(line))
        ):
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
            location=Location(path=path, start_line=line_no, snippet=snippet_line(line, 200)),
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
                "Craft a JWT with alg=none or tamper claims after stripping signature verification."
            ),
            business_impact="Full authentication bypass for affected endpoints.",
            remediation=Remediation(
                summary="Verify JWT signatures with an explicit allowlist of algorithms.",
                guidance=(
                    "Use jwt.decode(..., algorithms=['RS256']); never disable signature verification "
                    "in production."
                ),
            ),
            tags=["auth", "jwt"],
        )

    def _check_routes(
        self,
        path: str,
        lines: list[str],
        idx: int,
        counter: int,
        file_has_router_auth: bool = False,
    ) -> Iterable[Finding]:
        route_path = _route_path(lines[idx])
        if not route_path or not _SENSITIVE_PATH.search(route_path):
            return
        if _PUBLIC_ROUTE.search(route_path):
            return

        window = _window(lines, idx)
        if file_has_router_auth or _AUTH_DECORATORS.search(window):
            # Still check IDOR hints below when auth is present.
            pass
        else:
            yield Finding(
                id=f"authz:missing-auth:{counter + 1}",
                rule_id="authz.missing-authentication",
                scanner="authz",
                title=f"Sensitive route may lack authentication: {route_path}",
                description=(
                    f"Route `{route_path}` matches sensitive path patterns and has no "
                    f"obvious auth decorator or Depends() in the surrounding code."
                ),
                location=Location(
                    path=path, start_line=idx + 1, snippet=snippet_line(lines[idx], 200)
                ),
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

        window = _window(lines, idx)
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
                location=Location(
                    path=path, start_line=idx + 1, snippet=snippet_line(lines[idx], 200)
                ),
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
                    guidance=("Compare route/user ID to session tenant; return 403 on mismatch."),
                ),
                tags=["auth", "authorization", "idor"],
                metadata={"route": route_path},
            )
