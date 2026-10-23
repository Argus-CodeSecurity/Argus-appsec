"""The file-level MCP tools: ``nephilex_check_files``, ``nephilex_check_snippet``, ``nephilex_fix``.

They follow the same rules as ``nephilex_scan`` in :mod:`nephilex.mcp.server`:
paths are confined to the allowed roots, the checked tree is untrusted (its
``.nephilex.yml``, ``.nephilex/rules`` and ``nephilex-ignore`` comments are not
honoured), and the server applies its timeout around every call.

Findings from a check are remembered for the life of the server process so a
later ``nephilex_fix`` call can find them. Their ``id`` is the finding
fingerprint (rule, path and a digest of the flagged code, see
:meth:`Finding.fingerprint`), not the per-scan counter id (returned as
``scan_id``), because counter ids such as ``patterns:python-yaml-load:1``
repeat in every check. An id refers to the most recent check that reported it.
"""

from __future__ import annotations

import copy
import difflib
import re
import tempfile
import threading
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from nephilex.core.config import Config
from nephilex.core.models import Finding, ScanResult, Severity

_MAX_PATHS = 100
_MAX_SNIPPET_CHARS = 1_000_000
_MAX_FINDINGS = 200
_MAX_STORED = 2000

_LANG_EXT = {
    "python": ".py",
    "py": ".py",
    "javascript": ".js",
    "js": ".js",
    "jsx": ".jsx",
    "typescript": ".ts",
    "ts": ".ts",
    "tsx": ".tsx",
    "java": ".java",
    "kotlin": ".kt",
    "go": ".go",
    "golang": ".go",
    "ruby": ".rb",
    "php": ".php",
    "csharp": ".cs",
    "c#": ".cs",
    "rust": ".rs",
    "swift": ".swift",
    "scala": ".scala",
    "c": ".c",
    "cpp": ".cpp",
    "c++": ".cpp",
    "shell": ".sh",
    "bash": ".sh",
    "sh": ".sh",
    "powershell": ".ps1",
    "terraform": ".tf",
    "hcl": ".tf",
    "yaml": ".yml",
    "yml": ".yml",
    "json": ".json",
    "toml": ".toml",
    "xml": ".xml",
    "html": ".html",
    "sql": ".sql",
}
_LANG_FILENAME = {"dockerfile": "Dockerfile", "docker": "Dockerfile"}
_SAFE_PART = re.compile(r"[^A-Za-z0-9._-]")


@dataclass
class _Stored:
    finding: Finding
    root: Path | None = None  # project root, for a finding in a real file
    snippet: str | None = None  # the code, for a finding in a snippet


_STORE: OrderedDict[str, _Stored] = OrderedDict()
_STORE_LOCK = threading.Lock()


def _remember(entries: list[_Stored]) -> None:
    with _STORE_LOCK:
        for entry in entries:
            key = entry.finding.fingerprint()
            _STORE.pop(key, None)
            _STORE[key] = entry
        while len(_STORE) > _MAX_STORED:
            _STORE.popitem(last=False)


def _recall(finding_id: str) -> _Stored | None:
    with _STORE_LOCK:
        return _STORE.get(finding_id)


def forget_all() -> None:
    """Drop every remembered finding (used by tests)."""
    with _STORE_LOCK:
        _STORE.clear()


def _untrusted_config(min_severity: Severity) -> Config:
    from nephilex.integrations.filecheck import check_config

    cfg = Config(min_severity=min_severity)
    cfg.trust_project_config = False
    return check_config(cfg)


def _min_severity(arguments: dict[str, Any]) -> Severity:
    return Severity.parse(str(arguments.get("min_severity", "low")))


def finding_dict(f: Finding) -> dict[str, Any]:
    from nephilex.integrations.hookfmt import fix_hint, hook_line, severity_name
    from nephilex.remediation.rewrites import has_rewrite

    return {
        "id": f.fingerprint(),
        "scan_id": f.id,
        "rule_id": f.rule_id,
        "scanner": f.scanner,
        "severity": severity_name(f.severity),
        "title": f.title,
        "path": f.location.path,
        "line": f.location.start_line,
        "column": f.location.start_column,
        "cwe": f.cwe,
        "owasp": f.owasp,
        "fix": fix_hint(f),
        "fix_available": has_rewrite(f.rule_id),
        "hook": hook_line(f),
    }


def _summary(findings: list[Finding], errors: list[str]) -> dict[str, Any]:
    from nephilex.integrations.hookfmt import severity_name

    counts = {severity_name(s): 0 for s in reversed(Severity)}
    for f in findings:
        counts[severity_name(f.severity)] += 1
    return {
        "total_findings": len(findings),
        "returned": min(len(findings), _MAX_FINDINGS),
        "truncated": len(findings) > _MAX_FINDINGS,
        "by_severity": counts,
        "highest": severity_name(max(f.severity for f in findings)) if findings else None,
        "scanner_errors": errors,
    }


def _ordered(results: list[ScanResult]) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    errors: list[str] = []
    for r in results:
        findings.extend(r.sorted_findings())
        errors.extend(r.errors)
    return findings, errors


# --- nephilex_check_files -----------------------------------------------------
def check_files(arguments: dict[str, Any]) -> dict[str, Any]:
    from nephilex.integrations.filecheck import run_check, select_files
    from nephilex.mcp.server import allowed_roots, resolve_scan_path

    paths = arguments.get("paths")
    if (
        not isinstance(paths, list)
        or not paths
        or not all(isinstance(p, str) and p.strip() for p in paths)
    ):
        raise ValueError("'paths' must be a non-empty list of file paths")
    if len(paths) > _MAX_PATHS:
        raise ValueError(f"at most {_MAX_PATHS} paths per call; use nephilex_scan for a directory")
    cfg = _untrusted_config(_min_severity(arguments))

    # Confine first (raises for anything outside the roots), then group each
    # file under the most specific root that contains it.
    resolved = [resolve_scan_path(p) for p in paths]
    roots = sorted(allowed_roots(), key=lambda r: len(r.parts), reverse=True)
    groups: dict[Path, list[Path]] = {}
    for path in resolved:
        root = next(r for r in roots if path == r or path.is_relative_to(r))
        groups.setdefault(root, []).append(path)

    results: list[ScanResult] = []
    skipped: list[dict[str, object]] = []
    checked: list[str] = []
    stored: list[_Stored] = []
    for root, items in groups.items():
        files, skips = select_files(root, items, exclude_paths=cfg.exclude_paths)
        skipped += [s.to_dict() for s in skips]
        checked += [f.rel_path for f in files]
        result = run_check(root, files, cfg)
        results.append(result)
        stored += [_Stored(finding=f, root=root) for f in result.findings]
    _remember(stored)
    findings, errors = _ordered(results)
    return {
        "checked": checked,
        "skipped": skipped,
        "summary": _summary(findings, errors),
        "findings": [finding_dict(f) for f in findings[:_MAX_FINDINGS]],
    }


# --- nephilex_check_snippet ---------------------------------------------------
def snippet_relpath(filename: object, language: object) -> str:
    """A safe relative path for the temp file a snippet is scanned in.

    A filename hint keeps its directories (``.github/workflows/ci.yml`` matters
    to the CI scanner), but every part is sanitized and ``..`` or absolute
    parts are refused, so the file always lands inside the temp directory.
    """
    if isinstance(filename, str) and filename.strip():
        raw = filename.strip().replace("\\", "/")
        pure = PurePosixPath(raw)
        if pure.is_absolute() or re.match(r"^[A-Za-z]:", raw):
            raw = pure.name
        parts = [p for p in PurePosixPath(raw).parts if p not in ("", ".")]
        if not parts or any(p == ".." for p in parts) or len(parts) > 6:
            raise ValueError("'filename' must be a plain relative file name such as app.py")
        clean = [_SAFE_PART.sub("_", p)[:100] for p in parts]
        if any(p in ("", ".", "..") for p in clean):
            raise ValueError("'filename' must be a plain relative file name such as app.py")
        return "/".join(clean)
    if isinstance(language, str) and language.strip():
        key = language.strip().lower()
        if key in _LANG_FILENAME:
            return _LANG_FILENAME[key]
        if key in _LANG_EXT:
            return "snippet" + _LANG_EXT[key]
        raise ValueError(
            f"unknown language {language!r}; pass a filename hint such as app.py instead"
        )
    raise ValueError("give a 'language' (for example python) or a 'filename' hint")


def check_snippet(arguments: dict[str, Any]) -> dict[str, Any]:
    from nephilex.integrations.filecheck import check_config, run_check, select_files

    code = arguments.get("code")
    if not isinstance(code, str):
        raise ValueError("'code' (the source text to check) is required")
    if len(code) > _MAX_SNIPPET_CHARS:
        raise ValueError(f"'code' is larger than {_MAX_SNIPPET_CHARS} characters")
    rel = snippet_relpath(arguments.get("filename"), arguments.get("language"))
    # A snippet is scanned in a private temp directory, never in the project,
    # and without the cache (its path is new every time).
    cfg = check_config(_untrusted_config(_min_severity(arguments)), cache=False)
    with tempfile.TemporaryDirectory(prefix="nephilex-snippet-") as tmp:
        root = Path(tmp).resolve()
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(code, encoding="utf-8", newline="")
        files, skips = select_files(root, [target])
        result = run_check(root, files, cfg)
    for f in result.findings:
        f.metadata["snippet"] = True
    _remember([_Stored(finding=f, snippet=code) for f in result.findings])
    findings, errors = _ordered([result])
    return {
        "filename": rel,
        "skipped": [{"path": rel, "reason": s.reason} for s in skips],
        "summary": _summary(findings, errors),
        "findings": [finding_dict(f) for f in findings[:_MAX_FINDINGS]],
    }


# --- nephilex_fix -------------------------------------------------------------
def _norm(text: str) -> str:
    return re.sub(r"\s+", "", text)


def _lines(text: str) -> list[str]:
    """Split on real line breaks only, keeping them, as the fix applier does.

    ``str.splitlines`` also breaks on form feeds and Unicode separators, which
    would shift line numbers away from the ones the scanners reported.
    """
    parts = re.split(r"(\r?\n)", text)
    out = [line + brk for line, brk in zip(parts[0::2], parts[1::2], strict=False)]
    if parts[-1]:
        out.append(parts[-1])
    return out


def _unified(path: str, text: str, line_no: int, after: str) -> str:
    """A unified diff with context for replacing line ``line_no`` with ``after``."""
    old = _lines(text)
    new = list(old)
    original = old[line_no - 1]
    ending = original[len(original.rstrip("\r\n")) :]
    new[line_no - 1] = after + ending
    return "".join(difflib.unified_diff(old, new, fromfile=f"a/{path}", tofile=f"b/{path}", n=3))


def fix(arguments: dict[str, Any]) -> dict[str, Any]:
    """Propose Nephilex's deterministic, verified fix for a finding, as a diff.

    Nothing is written: the fix is computed on a dry run (and for a snippet,
    on a temp copy). The answer says when there is no deterministic fix, when
    the rewrite does not verify, and when the file changed since the check.
    """
    from nephilex.core.project import Project
    from nephilex.integrations.hookfmt import fix_hint
    from nephilex.mcp.server import resolve_scan_path
    from nephilex.remediation.applier import apply_fixes
    from nephilex.remediation.rewrites import has_rewrite, verify_line_fixed

    finding_id = arguments.get("finding_id")
    if not isinstance(finding_id, str) or not finding_id.strip():
        raise ValueError("'finding_id' (an id from nephilex_check_files or nephilex_check_snippet)")
    stored = _recall(finding_id.strip())
    if stored is None:
        raise ValueError(
            f"unknown finding id {finding_id!r}: run nephilex_check_files or "
            "nephilex_check_snippet first (ids are kept while this server runs)"
        )
    finding = copy.deepcopy(stored.finding)
    path = finding.location.path
    line_no = finding.location.start_line
    base: dict[str, Any] = {
        "finding_id": finding_id.strip(),
        "rule_id": finding.rule_id,
        "path": path,
        "line": line_no,
        "applied": False,
    }
    if not has_rewrite(finding.rule_id) or line_no is None:
        return {
            **base,
            "available": False,
            "reason": "Nephilex has no deterministic fix for this rule; follow the guidance.",
            "guidance": fix_hint(finding),
        }

    with tempfile.TemporaryDirectory(prefix="nephilex-fix-") as tmp:
        if stored.snippet is not None:
            root = Path(tmp).resolve()
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(stored.snippet, encoding="utf-8", newline="")
        else:
            assert stored.root is not None
            target = resolve_scan_path(str(stored.root / path))
            root = stored.root
        try:
            with target.open(encoding="utf-8", newline="") as fh:
                text = fh.read()
        except (OSError, UnicodeDecodeError) as exc:
            return {**base, "available": False, "reason": f"cannot read the file: {exc}"}
        lines = _lines(text)
        current = lines[line_no - 1].rstrip("\r\n") if 0 < line_no <= len(lines) else ""
        snippet = finding.location.snippet or ""
        if (
            not current
            or verify_line_fixed(finding.rule_id, current)
            or (snippet and _norm(snippet) not in _norm(current))
        ):
            return {
                **base,
                "available": False,
                "reason": "the line changed since the check; run the check again",
            }
        report = apply_fixes(Project(root=root, name=root.name), [finding], dry_run=True)
    if not report.fixes:
        reason = report.skipped[0] if report.skipped else "no fix produced"
        return {**base, "available": False, "reason": reason, "guidance": fix_hint(finding)}
    change = report.fixes[0]
    return {
        **base,
        "available": True,
        "verified": change.verified,
        "before": change.before,
        "after": change.after,
        "diff": _unified(path, text, line_no, change.after),
        "note": "Not applied. Review the diff and apply it yourself.",
    }
