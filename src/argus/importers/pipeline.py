"""Run imported findings through the same post-scan steps as Argus's own.

Imported findings skip the scanners, so they go through
:meth:`~argus.core.engine.ScanEngine.postprocess`, the same pipeline a scan
runs after its scanners: ``exclude_paths``, inline ``argus-ignore`` comments
and ``.argus/exceptions.yml`` (trusted projects only), the ``allow:`` list,
project context, attack chains, ``min_severity``, enrichment and patches as
configured, risk scoring and the audit log's suppression events. The one
step that differs is de-duplication: instead of the engine's cross-scanner
merge, :func:`~argus.importers.merge.merge_findings` folds each duplicate
into Argus's own finding (or the stronger imported one) and records the
other tools in ``metadata["also_reported_by"]``.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from argus import __version__
from argus.core.models import Finding, ScanResult
from argus.importers.merge import merge_findings
from argus.importers.sarif import SarifImport

if TYPE_CHECKING:
    from argus.core.config import Config
    from argus.core.project import Project

# Summary entries the post-processing of imported findings adds that a scan
# result already has; folded together by _fold_summary.
_FOLDED_SUMMARY_KEYS = ("audit", "exceptions_applied", "context")


def process_imported(
    findings: list[Finding],
    project: Project,
    config: Config,
    *,
    progress: Callable[[str], None] | None = None,
    native: list[Finding] | None = None,
) -> tuple[list[Finding], int]:
    """Filter and enrich imported findings; return them and the merge count.

    With ``native`` (findings from an Argus scan of the same project), imported
    findings that duplicate one of them are folded into it; the returned list
    then holds the native findings followed by the remaining imported ones.
    """
    processed, merged = _postprocess(findings, project, config, progress=progress, native=native)
    return [*(native or []), *processed.findings], merged


def _postprocess(
    findings: list[Finding],
    project: Project,
    config: Config,
    *,
    progress: Callable[[str], None] | None = None,
    native: list[Finding] | None = None,
) -> tuple[ScanResult, int]:
    """Post-process imported findings; return them as a result, and the merge count.

    With ``native`` (findings from an Argus scan of the same project),
    imported findings that duplicate one of them are folded into it, which
    may raise its severity and adds ``also_reported_by``; the returned result
    then holds only the remaining imported findings. Attack chains that a
    native finding list already contains are not repeated.
    """
    from argus.core.engine import ScanEngine

    natives = list(native or [])
    native_ids = {id(f) for f in natives}
    merged = 0

    def fold(candidates: list[Finding]) -> list[Finding]:
        nonlocal merged
        out, merged = merge_findings(natives, candidates)
        return [f for f in out if id(f) not in native_ids]

    holder = ScanResult(
        target=str(project.root),
        started_at=datetime.now(timezone.utc),
        argus_version=__version__,
        findings=list(findings),
    )
    ScanEngine(config, progress=progress).postprocess(holder, project, dedupe=fold)
    if natives:
        known = {f.id for f in natives if f.scanner == "chains"}
        holder.findings = [
            f for f in holder.findings if not (f.scanner == "chains" and f.id in known)
        ]
    return holder, merged


def import_result(
    imported: SarifImport,
    project: Project,
    config: Config,
    *,
    progress: Callable[[str], None] | None = None,
) -> ScanResult:
    """A :class:`ScanResult` holding only imported findings (``argus import``)."""
    started = datetime.now(timezone.utc)
    processed, merged = _postprocess(imported.findings, project, config, progress=progress)
    result = ScanResult(
        target=str(project.root),
        started_at=started,
        argus_version=__version__,
        scanners_run=list(imported.tools),
        findings=processed.findings,
    )
    result.project_summary = project.summary()
    result.project_summary.update(processed.project_summary)
    result.project_summary["origin"] = "sarif-import"
    result.project_summary["imported_sarif"] = {**imported.summary(), "merged": merged}
    result.findings = result.sorted_findings()
    result.finished_at = datetime.now(timezone.utc)
    return result


def merge_into(
    result: ScanResult,
    imported: SarifImport,
    project: Project,
    config: Config,
    *,
    progress: Callable[[str], None] | None = None,
) -> int:
    """Add imported findings to an Argus scan result in place (``scan --import-sarif``).

    Returns how many imported findings were folded into existing ones.
    """
    processed, merged = _postprocess(
        imported.findings, project, config, progress=progress, native=result.findings
    )
    result.findings = [*result.findings, *processed.findings]
    result.scanners_run.extend(t for t in imported.tools if t not in result.scanners_run)
    _fold_summary(result.project_summary, processed.project_summary)
    result.project_summary["imported_sarif"] = {**imported.summary(), "merged": merged}
    result.findings = result.sorted_findings()
    return merged


def _is_count(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _addable(a: Any, b: Any) -> bool:
    """Two counts, or two lists."""
    return (_is_count(a) and _is_count(b)) or (isinstance(a, list) and isinstance(b, list))


def _fold_summary(into: dict[str, Any], extra: dict[str, Any]) -> None:
    """Add the audit, exception and context totals of the imported pass to a scan's."""
    for key in _FOLDED_SUMMARY_KEYS:
        if key not in extra:
            continue
        mine, theirs = into.get(key), extra[key]
        if mine is None:
            into[key] = theirs
        elif _is_count(mine) and _is_count(theirs):
            into[key] = mine + theirs
        elif isinstance(mine, dict) and isinstance(theirs, dict):
            for sub, value in theirs.items():
                current = mine.get(sub)
                if current is None:
                    mine[sub] = value
                elif _addable(current, value):
                    mine[sub] = current + value
