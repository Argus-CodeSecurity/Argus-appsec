"""Endpoint authorization map for API surfaces."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any

from argus.core.project import Project

_FASTAPI = re.compile(
    r"""@(?:app|router)\.(get|post|put|patch|delete)\(\s*['"]([^'"]+)['"]""",
)
_FLASK = re.compile(r"""@(?:app|blueprint)\.route\(\s*['"]([^'"]+)['"]""")
# Only receivers that look like an Express app/router, and only paths that
# start with "/", so `axios.get('/x')`-style client calls and `map.get('k')`
# are not mistaken for routes.
_EXPRESS = re.compile(
    r"""\b[\w$]*(?:[Aa]pp|[Rr]outer|[Ss]erver|[Aa]pi|[Rr]outes?)\."""
    r"""(get|post|put|patch|delete)\(\s*['"`](/[^'"`]*)['"`]""",
)
# Decorators, or FastAPI dependencies in the signature (the old pattern
# required an "@" before Depends(), so signature dependencies never matched).
_AUTH = re.compile(
    r"@(?:login_required|requires_auth)\b|Depends\([^)]*(?:auth|get_current_user)|Security\(",
    re.I,
)
_JS_AUTH = re.compile(
    r"\b(?:passport\.authenticate|requireAuth\w*|ensureAuth\w*|isAuthenticated|"
    r"authenticate\w*|verifyToken|authMiddleware|checkJwt|requireLogin)\b",
)
_ROLE = re.compile(r"(?:roles?|permissions?)\s*=\s*\[([^\]]+)\]", re.I)
_SENSITIVE = re.compile(
    r"/(?:admin|internal|users?|accounts?|billing|secrets?|tokens?)(?:/|$)",
    re.I,
)
_PY_DEF = re.compile(r"^(?:async\s+)?def\b")

_PY_SUFFIXES = (".py",)
_JS_SUFFIXES = (".js", ".jsx", ".ts", ".tsx", ".mjs")

# Risk ordering for the report: most urgent first. Sorting the labels as
# strings would put MEDIUM before HIGH.
_RISK_RANK = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

# How far a route's own decorators / middleware may extend.
_MAX_SPAN = 30


@dataclass
class EndpointEntry:
    path: str
    method: str
    file: str
    line: int
    authentication: str
    authorization: str
    risk: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _py_route(line: str) -> tuple[str, str] | None:
    m = _FASTAPI.search(line)
    if m:
        return m.group(1).upper(), m.group(2)
    m = _FLASK.search(line)
    if m:
        return "ANY", m.group(1)
    return None


def _js_route(line: str) -> tuple[str, str] | None:
    m = _EXPRESS.search(line)
    if m:
        return m.group(1).upper(), m.group(2)
    return None


def _method_and_path(line: str, suffix: str = ".py") -> tuple[str, str] | None:
    if suffix in _PY_SUFFIXES:
        return _py_route(line)
    if suffix in _JS_SUFFIXES:
        return _js_route(line)
    return None


def _py_window(lines: list[str], i: int) -> list[str]:
    """The route's decorator stack plus its function signature.

    Walks up through the contiguous decorators and down to the end of the
    ``def`` signature, so auth on a neighbouring route is never counted.
    """
    start = i
    while start > 0 and i - start < _MAX_SPAN and lines[start - 1].lstrip().startswith("@"):
        start -= 1
    end = i + 1
    limit = min(len(lines), i + _MAX_SPAN)
    while end < limit:
        stripped = lines[end].strip()
        end += 1
        if _PY_DEF.match(stripped):
            # Consume the signature: until its parentheses close.
            depth = stripped.count("(") - stripped.count(")")
            while depth > 0 and end < limit:
                stripped = lines[end].strip()
                depth += stripped.count("(") - stripped.count(")")
                end += 1
            break
    return lines[start:end]


def _js_window(lines: list[str], i: int, next_route: int) -> list[str]:
    """The route call's own lines up to where its handler starts."""
    end = i
    limit = min(len(lines), next_route, i + _MAX_SPAN)
    while end < limit:
        line = lines[end]
        end += 1
        if "=>" in line or "function" in line or "{" in line:
            break
    return lines[i:end]


def _risk(path: str, authenticated: bool) -> str:
    if _SENSITIVE.search(path) and not authenticated:
        return "HIGH"
    if not authenticated:
        return "MEDIUM"
    return "LOW"


def build_auth_map(project: Project) -> list[EndpointEntry]:
    """Build route -> auth map from framework route decorators."""
    entries: list[EndpointEntry] = []
    for f in project.files():
        suffix = f.suffix
        if suffix not in _PY_SUFFIXES + _JS_SUFFIXES:
            continue
        lines = f.text().splitlines()
        routes = [
            (i, parsed)
            for i, line in enumerate(lines)
            if (parsed := _method_and_path(line, suffix)) is not None
        ]
        for n, (i, (method, path)) in enumerate(routes):
            if suffix in _PY_SUFFIXES:
                window = "\n".join(_py_window(lines, i))
                has_auth = bool(_AUTH.search(window))
            else:
                next_route = routes[n + 1][0] if n + 1 < len(routes) else len(lines)
                window = "\n".join(_js_window(lines, i, next_route))
                has_auth = bool(_JS_AUTH.search(window))
            role_m = _ROLE.search(window)
            authz = role_m.group(1).strip() if role_m else ("present" if has_auth else "none")
            entries.append(
                EndpointEntry(
                    path=path,
                    method=method,
                    file=f.rel_path,
                    line=i + 1,
                    authentication="required" if has_auth else "missing",
                    authorization=authz,
                    risk=_risk(path, has_auth),
                )
            )
    entries.sort(key=lambda e: (_RISK_RANK.get(e.risk, 99), e.file, e.line))
    return entries
