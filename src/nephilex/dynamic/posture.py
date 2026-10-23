"""Safe, read-only security-posture checks for a running URL (pre-DAST).

Given a deployed URL, ``probe`` makes a handful of ordinary GET requests and
reports runtime misconfigurations that source analysis cannot observe:

* **Transport**, plaintext HTTP, and HTTP that does not redirect to HTTPS.
* **Security headers**, HSTS, CSP, X-Frame-Options / frame-ancestors,
  X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
* **Cookie flags**, Secure, HttpOnly, SameSite on any Set-Cookie.
* **Exposed paths**, a short allowlist of well-known sensitive endpoints
  (``/.env``, ``/.git/config``, ``/actuator``, …) checked for accidental
  exposure.
* **Version disclosure**, Server / X-Powered-By advertising exact versions.

Deliberately non-intrusive: only GETs, only the paths listed here, one pass,
short timeout, redirects followed with SSRF guards. It never sends payloads,
mutates state, or attempts exploitation, so it is safe to point at systems you
are authorized to assess. It is not a substitute for full DAST.

Every request goes through :class:`GuardedSession`: redirects are walked by
hand and a hop to another host must resolve to public addresses; after the
connection is made, the peer address is checked again (so a DNS answer that
changes between the check and the connect cannot reach internal space);
bodies are streamed with a size cap and the whole session has a deadline.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import time
import urllib.request
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

from nephilex.core.models import (
    Confidence,
    Finding,
    Likelihood,
    Location,
    Remediation,
    Severity,
)

log = logging.getLogger("nephilex.dynamic.posture")

_TIMEOUT = 10.0
_UA = {"User-Agent": "nephilex-posture-check"}
_MAX_REDIRECTS = 5
_REDIRECT_STATUSES = {301, 302, 303, 307, 308}
#: Most response body kept per request; the rest is not read.
MAX_BODY_BYTES = 1_000_000
#: Wall-clock budget for one probe session (all requests together).
SESSION_DEADLINE = 60.0

# Header -> (severity, why, fix). Absence of the header is the finding.
_SECURITY_HEADERS = {
    "strict-transport-security": (
        Severity.MEDIUM,
        "No HSTS header, so browsers may connect over plaintext HTTP and are "
        "exposed to SSL-stripping downgrade attacks.",
        "Send `Strict-Transport-Security: max-age=63072000; includeSubDomains`.",
    ),
    "content-security-policy": (
        Severity.MEDIUM,
        "No Content-Security-Policy, so the app has no defense-in-depth against "
        "cross-site scripting and content injection.",
        "Define a restrictive CSP (start with `default-src 'self'`).",
    ),
    "x-content-type-options": (
        Severity.LOW,
        "No X-Content-Type-Options: nosniff, so browsers may MIME-sniff responses "
        "into an unintended, dangerous content type.",
        "Send `X-Content-Type-Options: nosniff`.",
    ),
    "referrer-policy": (
        Severity.LOW,
        "No Referrer-Policy, so full URLs (possibly with sensitive tokens) may leak "
        "to third parties via the Referer header.",
        "Send `Referrer-Policy: strict-origin-when-cross-origin` or stricter.",
    ),
}


def _clickjacking_missing(headers) -> bool:
    if "x-frame-options" in headers:
        return False
    csp = headers.get("content-security-policy", "").lower()
    return "frame-ancestors" not in csp


def _finding(
    rule: str,
    url: str,
    title: str,
    severity: Severity,
    why: str,
    fix: str,
    *,
    cwe,
    owasp,
    confidence=Confidence.HIGH,
    snippet: str | None = None,
) -> Finding:
    return Finding(
        id=f"posture:{rule}:{urlparse(url).netloc}:{urlparse(url).path or '/'}",
        rule_id=f"posture.{rule}",
        scanner="posture",
        title=title,
        description=why,
        location=Location(path=url, snippet=snippet),
        severity=severity,
        confidence=confidence,
        likelihood=Likelihood.POSSIBLE,
        cwe=cwe,
        owasp=owasp,
        why_vulnerable=why,
        attacker_perspective="Observable directly in the HTTP response by anyone "
        "who can reach the URL.",
        business_impact="Weakens the app's runtime security posture; exact impact "
        "depends on the specific misconfiguration.",
        remediation=Remediation(summary=fix, guidance=fix),
        tags=["dynamic", "posture"],
    )


# Well-known sensitive paths, accidental exposure is high-impact. GET only.
_SENSITIVE_PATHS = [
    (".env", "Environment file exposed"),
    (".git/config", "Git metadata exposed"),
    (".git/HEAD", "Git repository exposed"),
    (".aws/credentials", "AWS credentials file exposed"),
    ("actuator/env", "Spring Boot Actuator env exposed"),
    ("server-status", "Apache server-status exposed"),
    ("phpinfo.php", "phpinfo() exposed"),
    ("config.json", "Configuration file exposed"),
]


def _hostname_is_public(hostname: str) -> bool:
    """True if ``hostname`` resolves only to globally routable addresses.

    Literal IPs are checked directly. Names fail closed on DNS errors, and fail
    if *any* resolved address is private, loopback, link-local, or otherwise
    non-global (SSRF into cloud metadata / RFC1918).
    """
    host = hostname.strip("[]")
    try:
        return _ip_is_public(host)
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        return False
    if not infos:
        return False
    try:
        return all(_ip_is_public(str(info[4][0])) for info in infos)
    except ValueError:
        return False


def _ip_is_public(value: str) -> bool:
    """True if ``value`` is a globally routable IP (raises ValueError if not an IP)."""
    ip = ipaddress.ip_address(value.split("%", 1)[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped.is_global
    return ip.is_global


def _assert_http_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError(f"refusing non-http(s) URL: {url!r}")


def _assert_redirect_safe(origin_url: str, next_url: str) -> None:
    """Block open-redirect SSRF into non-public address space.

    Direct probes of localhost / private hosts are allowed (the operator chose
    the target). A public origin that redirects cross-host into private,
    loopback, or link-local space is not.
    """
    _assert_http_url(next_url)
    origin_host = (urlparse(origin_url).hostname or "").lower()
    next_host = (urlparse(next_url).hostname or "").lower()
    if not next_host:
        raise ValueError("redirect missing host")
    if next_host == origin_host:
        return
    if not _hostname_is_public(next_host):
        raise ValueError(f"refusing redirect from {origin_host!r} to non-public host {next_host!r}")


@dataclass
class FetchResult:
    """A capped, already-read HTTP response."""

    status_code: int
    headers: Any  # httpx.Headers (case-insensitive, supports get_list)
    url: str
    content: bytes = b""
    truncated: bool = False
    encoding: str = "utf-8"

    @property
    def text(self) -> str:
        return self.content.decode(self.encoding or "utf-8", errors="replace")


def _uses_env_proxy(url: str) -> bool:
    """True if httpx (trust_env) would route ``url`` through an env proxy.

    The connected peer is then the proxy, not the target, so the post-connect
    peer check cannot apply.
    """
    parsed = urlparse(url)
    proxies = urllib.request.getproxies_environment()
    if not (proxies.get(parsed.scheme) or proxies.get("all")):
        return False
    bypass = urllib.request.proxy_bypass_environment  # type: ignore[attr-defined]
    return not bypass(parsed.hostname or "")


def _verify_peer_public(resp: Any, url: str) -> None:
    """Fail unless the socket behind ``resp`` is connected to a public address.

    Closes the DNS-rebinding gap between ``_hostname_is_public`` (a lookup) and
    the connect (a second lookup inside httpx): the address actually used is
    read back from the connection. Fails closed if it cannot be determined.
    """
    if _uses_env_proxy(url):
        return
    stream = resp.extensions.get("network_stream")
    addr = stream.get_extra_info("server_addr") if stream is not None else None
    if not addr:
        raise ValueError(f"could not verify the address connected to for {url}")
    try:
        public = _ip_is_public(str(addr[0]))
    except ValueError as exc:
        raise ValueError(f"unexpected peer address {addr[0]!r} for {url}") from exc
    if not public:
        raise ValueError(f"refusing response from non-public address {addr[0]} for {url}")


@dataclass
class GuardedSession:
    """An httpx client wrapper that applies the SSRF and size guards.

    ``origin`` is the operator-chosen target. It may be private (probing a
    local app is legitimate); if it resolves to public addresses when the
    session starts, every later connection to it must also land on a public
    address. Other hosts, reached only through redirects, must always be
    public, both by DNS before the request and by peer address after connect.
    """

    origin: str
    timeout: float = _TIMEOUT
    max_bytes: int = MAX_BODY_BYTES
    deadline_seconds: float = SESSION_DEADLINE
    headers: dict[str, str] = field(default_factory=lambda: dict(_UA))
    client: Any = None

    def __post_init__(self) -> None:
        import httpx

        _assert_http_url(self.origin)
        self._origin_host = (urlparse(self.origin).hostname or "").lower()
        self._origin_public = _hostname_is_public(self._origin_host)
        self._deadline = time.monotonic() + self.deadline_seconds
        self._owns_client = self.client is None
        if self.client is None:
            # follow_redirects=False: hops are walked (and checked) in get().
            self.client = httpx.Client(
                follow_redirects=False, timeout=self.timeout, headers=self.headers
            )

    def __enter__(self) -> GuardedSession:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        if self._owns_client and self.client is not None:
            self.client.close()

    def _remaining(self) -> float:
        left = self._deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("posture probe exceeded its time budget")
        return left

    def _fetch_once(self, url: str) -> FetchResult:
        host = (urlparse(url).hostname or "").lower()
        must_be_public = self._origin_public or host != self._origin_host
        timeout = min(self.timeout, self._remaining())
        with self.client.stream("GET", url, timeout=timeout) as resp:
            if must_be_public:
                _verify_peer_public(resp, url)
            body = bytearray()
            truncated = False
            for chunk in resp.iter_bytes():
                body.extend(chunk)
                if len(body) > self.max_bytes:
                    truncated = True
                    break
                self._remaining()
            return FetchResult(
                status_code=resp.status_code,
                headers=resp.headers,
                url=str(resp.url),
                content=bytes(body[: self.max_bytes]),
                truncated=truncated,
                encoding=resp.encoding or "utf-8",
            )

    def get(self, url: str) -> FetchResult:
        """GET ``url``, following redirects by hand with SSRF checks per hop."""
        current = url
        for _ in range(_MAX_REDIRECTS + 1):
            # Same host as the origin passes; any other host must be public.
            _assert_redirect_safe(self.origin, current)
            resp = self._fetch_once(current)
            if resp.status_code not in _REDIRECT_STATUSES:
                return resp
            location = resp.headers.get("location")
            if not location:
                return resp
            current = urljoin(resp.url, location)
        raise ValueError(f"too many redirects while probing {url}")


def guarded_get(
    url: str,
    *,
    timeout: float = _TIMEOUT,
    max_bytes: int = MAX_BODY_BYTES,
    headers: dict[str, str] | None = None,
) -> FetchResult | None:
    """One guarded GET (redirect checks, peer check, size cap). None on failure."""
    try:
        with GuardedSession(
            url, timeout=timeout, max_bytes=max_bytes, headers=dict(headers or _UA)
        ) as session:
            return session.get(url)
    except Exception as exc:  # network, TLS, guard refusals, budget
        log.debug("guarded GET of %s failed: %s", url, exc)
        return None


def probe(url: str, *, check_paths: bool = True) -> list[Finding]:
    """Run posture checks against ``url``. Returns findings; never raises.

    Network/TLS/import errors degrade to a single informational finding rather
    than aborting, so a scan that includes ``--live-target`` always completes.
    """
    try:
        import httpx  # noqa: F401
    except ImportError:
        log.warning("httpx not available; skipping live-target checks")
        return []

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    findings: list[Finding] = []
    try:
        with GuardedSession(url) as session:
            resp = session.get(url)
            findings.extend(_check_transport(url, resp))
            findings.extend(_check_headers(resp.url, resp))
            findings.extend(_check_cookies(resp.url, resp))
            findings.extend(_check_version_disclosure(resp.url, resp))
            if check_paths:
                findings.extend(_check_sensitive_paths(session, resp.url))
    except Exception as exc:
        log.warning("live-target probe of %s failed: %s", url, exc)
        return [
            _finding(
                "unreachable",
                url,
                "Live target could not be probed",
                Severity.INFO,
                f"Nephilex could not complete posture checks against {url}: {exc}.",
                "Confirm the URL is reachable from this host and try again.",
                cwe=[],
                owasp=[],
                confidence=Confidence.LOW,
            )
        ]
    return findings


def _check_transport(url: str, resp: FetchResult) -> list[Finding]:
    out: list[Finding] = []
    final = resp.url
    if urlparse(url).scheme == "http" and urlparse(final).scheme != "https":
        out.append(
            _finding(
                "no-https",
                url,
                "Site served over plaintext HTTP",
                Severity.HIGH,
                "The URL is served over HTTP and does not redirect to HTTPS, so all "
                "traffic, including credentials and session cookies, is unencrypted.",
                "Serve the site over HTTPS and redirect all HTTP requests to it.",
                cwe=["CWE-319"],
                owasp=["A02:2021-Cryptographic Failures"],
            )
        )
    return out


def _check_headers(url: str, resp) -> list[Finding]:
    out: list[Finding] = []
    headers = {k.lower(): v for k, v in resp.headers.items()}
    is_https = urlparse(url).scheme == "https"
    for name, (severity, why, fix) in _SECURITY_HEADERS.items():
        if name == "strict-transport-security" and not is_https:
            continue  # HSTS is only meaningful over HTTPS
        if name not in headers:
            out.append(
                _finding(
                    f"missing-{name}",
                    url,
                    f"Missing security header: {name}",
                    severity,
                    why,
                    fix,
                    cwe=["CWE-693"],
                    owasp=["A05:2021-Security Misconfiguration"],
                )
            )
    if _clickjacking_missing(headers):
        out.append(
            _finding(
                "missing-frame-options",
                url,
                "No clickjacking protection (X-Frame-Options / frame-ancestors)",
                Severity.MEDIUM,
                "Neither X-Frame-Options nor a CSP frame-ancestors directive is set, so "
                "the page can be framed by any site and used for clickjacking.",
                "Send `X-Frame-Options: DENY` or a CSP `frame-ancestors 'none'`.",
                cwe=["CWE-1021"],
                owasp=["A05:2021-Security Misconfiguration"],
            )
        )
    return out


def _check_cookies(url: str, resp) -> list[Finding]:
    out: list[Finding] = []
    raw_cookies = (
        resp.headers.get_list("set-cookie")
        if hasattr(resp.headers, "get_list")
        else resp.headers.get_all("set-cookie")
        if hasattr(resp.headers, "get_all")
        else []
    )
    for raw in raw_cookies:
        low = raw.lower()
        name = raw.split("=", 1)[0].strip()
        missing = []
        if "secure" not in low:
            missing.append("Secure")
        if "httponly" not in low:
            missing.append("HttpOnly")
        if "samesite" not in low:
            missing.append("SameSite")
        if missing:
            out.append(
                _finding(
                    f"cookie-flags-{name}",
                    url,
                    f"Cookie '{name}' missing flags: {', '.join(missing)}",
                    Severity.MEDIUM
                    if ("Secure" in missing or "HttpOnly" in missing)
                    else Severity.LOW,
                    f"The Set-Cookie for '{name}' is missing {', '.join(missing)}. "
                    "Without HttpOnly it is readable by JavaScript (XSS theft); without "
                    "Secure it is sent over HTTP; without SameSite it is exposed to CSRF.",
                    "Set Secure, HttpOnly, and SameSite=Lax/Strict on session cookies.",
                    cwe=["CWE-1004", "CWE-614"],
                    owasp=["A05:2021-Security Misconfiguration"],
                    snippet=name,
                )
            )
    return out


def _check_version_disclosure(url: str, resp) -> list[Finding]:
    out: list[Finding] = []
    headers = {k.lower(): v for k, v in resp.headers.items()}
    for h in ("server", "x-powered-by"):
        val = headers.get(h, "")
        if val and any(c.isdigit() for c in val):
            out.append(
                _finding(
                    f"version-disclosure-{h}",
                    url,
                    f"Version disclosure via {h} header",
                    Severity.LOW,
                    f"The {h} header advertises `{val}`, telling an attacker exactly "
                    "which software and version to target with known exploits.",
                    f"Remove or genericize the {h} header.",
                    cwe=["CWE-200"],
                    owasp=["A05:2021-Security Misconfiguration"],
                    confidence=Confidence.MEDIUM,
                    snippet=f"{h}: {val}",
                )
            )
    return out


def _check_sensitive_paths(session: GuardedSession, base_url: str) -> list[Finding]:
    out: list[Finding] = []
    root = f"{urlparse(base_url).scheme}://{urlparse(base_url).netloc}/"
    for path, title in _SENSITIVE_PATHS:
        target = urljoin(root, path)
        try:
            r = session.get(target)
        except Exception:
            continue
        # A 200 with non-trivial, non-HTML body is a real exposure; many apps
        # return a 200 SPA shell for unknown paths, so require it not be HTML.
        ctype = r.headers.get("content-type", "").lower()
        if r.status_code == 200 and "text/html" not in ctype and r.content:
            out.append(
                _finding(
                    "exposed-path",
                    target,
                    f"{title} at /{path}",
                    Severity.HIGH,
                    f"{target} is publicly accessible and returned {r.status_code}. "
                    "Sensitive files exposed at well-known paths leak secrets, source, "
                    "or internal state.",
                    f"Block public access to /{path} at the web server or app layer.",
                    cwe=["CWE-538"],
                    owasp=["A05:2021-Security Misconfiguration"],
                    snippet=f"HTTP {r.status_code} {ctype}",
                )
            )
    return out
