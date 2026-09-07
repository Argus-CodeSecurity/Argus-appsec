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
_EXPRESS = re.compile(r"""\.(get|post|put|patch|delete)\(\s*['"]([^'"]+)['"]""")
_AUTH = re.compile(
    r"@(?:login_required|requires_auth|Depends\([^)]*(?:auth|get_current_user|Security))",
    re.I,
)
_ROLE = re.compile(r"(?:roles?|permissions?)\s*=\s*\[([^\]]+)\]", re.I)
_SENSITIVE = re.compile(
    r"/(?:admin|internal|users?|accounts?|billing|secrets?|tokens?)(?:/|$)", re.I,
)


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


def _method_and_path(line: str) -> tuple[str, str] | None:
    m = _FASTAPI.search(line)
    if m:
        return m.group(1).upper(), m.group(2)
    m = _FLASK.search(line)
    if m:
        return "ANY", m.group(1)
    m = _EXPRESS.search(line)
    if m:
        return m.group(1).upper(), m.group(2)
    return None


def _risk(path: str, authenticated: bool) -> str:
    if _SENSITIVE.search(path) and not authenticated:
        return "HIGH"
    if not authenticated:
        return "MEDIUM"
    return "LOW"


def build_auth_map(project: Project) -> list[EndpointEntry]:
    """Build route → auth map from framework route decorators."""
    entries: list[EndpointEntry] = []
    for f in project.files():
        if f.suffix not in (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs"):
            continue
        lines = f.text().splitlines()
        for i, line in enumerate(lines):
            parsed = _method_and_path(line)
            if not parsed:
                continue
            method, path = parsed
            window = "\n".join(lines[max(0, i - 8): i + 12])
            has_auth = bool(_AUTH.search(window))
            role_m = _ROLE.search(window)
            authz = role_m.group(1).strip() if role_m else ("present" if has_auth else "none")
            entries.append(EndpointEntry(
                path=path,
                method=method,
                file=f.rel_path,
                line=i + 1,
                authentication="required" if has_auth else "missing",
                authorization=authz,
                risk=_risk(path, has_auth),
            ))
    entries.sort(key=lambda e: (e.risk, e.path, e.method), reverse=True)
    return entries
