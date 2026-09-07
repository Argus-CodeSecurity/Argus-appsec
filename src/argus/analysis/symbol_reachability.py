"""Python symbol-level reachability (tier 2, experimental).

Extends import-level reachability by tracing dotted attribute access and
``from pkg import symbol`` usage. When OSV provides affected symbol hints,
findings can be classified as ``symbol_reachable`` vs ``import_only``.
"""

from __future__ import annotations

import ast
import re

from argus.core.project import Project

SYMBOL_REACHABLE = "symbol_reachable"
IMPORT_ONLY = "import_only"
SYMBOL_UNKNOWN = "unknown"

_ATTR_RE = re.compile(
    r"\b([a-zA-Z_][\w]*)\.([a-zA-Z_][\w]*)\b",
)


def collect_python_symbols(project: Project) -> set[str]:
    """Dotted symbols used in Python source: ``module.func`` and imported names."""
    symbols: set[str] = set()
    for f in project.files():
        if f.suffix != ".py":
            continue
        text = f.text()
        try:
            tree = ast.parse(text)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                for alias in node.names:
                    name = alias.asname or alias.name
                    symbols.add(f"{node.module}.{name}")
                    symbols.add(name)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    mod = alias.asname or alias.name
                    symbols.add(mod.split(".")[0])
        for m in _ATTR_RE.finditer(text):
            symbols.add(f"{m.group(1)}.{m.group(2)}")
            symbols.add(m.group(1))
    return {s.lower() for s in symbols}


def extract_osv_symbols(vuln: dict, package: str) -> list[str]:
    """Best-effort affected symbols from an OSV record."""
    found: set[str] = set()
    pkg_lower = package.lower() if package else ""
    for aff in vuln.get("affected") or []:
        pkg = (aff.get("package") or {}).get("name", "")
        if pkg_lower and pkg and pkg.lower() != pkg_lower:
            continue
        eco = aff.get("ecosystem_specific") or {}
        for key in ("imports", "symbols", "functions"):
            val = eco.get(key)
            if isinstance(val, list):
                found.update(str(v).lower() for v in val)
            elif isinstance(val, str):
                found.add(val.lower())
    # Heuristic: pull ``module.func`` tokens from summary/details text.
    blob = f"{vuln.get('summary', '')} {vuln.get('details', '')}"
    for m in _ATTR_RE.finditer(blob):
        found.add(f"{m.group(1)}.{m.group(2)}".lower())
    return sorted(found)


def symbol_verdict(
    package: str,
    symbols_used: set[str],
    affected_symbols: list[str],
    *,
    imported: bool,
) -> str:
    """Classify symbol-level reachability for a dependency finding."""
    if not imported:
        return "not_imported"
    if not affected_symbols:
        return IMPORT_ONLY if imported else SYMBOL_UNKNOWN
    pkg = package.lower().replace("-", "_")
    for sym in affected_symbols:
        s = sym.lower()
        if s in symbols_used:
            return SYMBOL_REACHABLE
        if s.split(".")[-1] in symbols_used:
            return SYMBOL_REACHABLE
        if s.startswith(pkg) and s in symbols_used:
            return SYMBOL_REACHABLE
    return IMPORT_ONLY


def describe_symbol_verdict(verdict: str) -> str:
    if verdict == SYMBOL_REACHABLE:
        return (
            "Reachability (symbol-level, experimental): vulnerable symbol usage "
            "detected in first-party code — treat as likely affected."
        )
    if verdict == IMPORT_ONLY:
        return (
            "Reachability (symbol-level): package is imported but no affected "
            "symbol usage was found — lower priority, not proof of safety."
        )
    return ""
