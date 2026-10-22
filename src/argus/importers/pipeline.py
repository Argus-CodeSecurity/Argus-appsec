"""Run imported findings through the same post-scan steps as Argus's own.

:class:`~argus.core.engine.ScanEngine` applies suppressions, the allowlist,
the severity floor, enrichment and exceptions to the findings its scanners
produce. Imported findings skip the scanners, so this module applies those
same steps (reusing the engine's own implementations) before they join a
:class:`~argus.core.models.ScanResult`:

1. ``exclude_paths`` from config;
2. inline ``argus-ignore`` comments (trusted projects only);
3. the ``allow:`` list;
4. cross-tool de-duplication (:mod:`argus.importers.merge`);
5. ``min_severity``;
6. enrichment, attack simulation and patch agents, as configured;
7. ``.argus/exceptions.yml`` (trusted projects only).
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from argus import __version__
from argus.core.models import Finding, ScanResult
from argus.importers.merge import merge_findings
from argus.importers.sarif import SarifImport

if TYPE_CHECKING:
    from argus.core.config import Config
    from argus.core.project import Project


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
    from argus.ai.factory import build_provider
    from argus.core.engine import ScanEngine
    from argus.exceptions import apply_exceptions, default_exceptions_path, load_exceptions

    engine = ScanEngine(config, progress=progress)
    ignores = tuple(config.exclude_paths)
    scoped = dataclasses.replace(
        project,
        extra_ignores=ignores,
        _files_cache=project._files_cache if ignores == project.extra_ignores else None,
    )
    # Placeholder locations such as "(image)" are not paths and cannot match.
    kept = [
        f
        for f in findings
        if f.location.path.startswith("(") or not scoped._excluded(f.location.path)
    ]
    if config.trust_project_config:
        kept = engine._apply_inline_suppressions(kept, scoped)
    kept = engine._apply_allowlist(kept, config)
    merged_list, merged = merge_findings(native or [], kept)
    native_ids = {id(f) for f in native or []}
    new = [f for f in merged_list if id(f) not in native_ids]
    new = engine._filter(new)
    if config.ai.enabled and new:
        holder = ScanResult(target=str(project.root), started_at=datetime.now(timezone.utc))
        holder.findings = new
        engine._run_agents(holder, scoped, build_provider(config.ai))
    if config.trust_project_config:
        new, _ = apply_exceptions(new, load_exceptions(default_exceptions_path(project.root)))
    natives = [f for f in merged_list if id(f) in native_ids]
    return natives + new, merged


def import_result(
    imported: SarifImport,
    project: Project,
    config: Config,
    *,
    progress: Callable[[str], None] | None = None,
) -> ScanResult:
    """A :class:`ScanResult` holding only imported findings (``argus import``)."""
    started = datetime.now(timezone.utc)
    findings, merged = process_imported(imported.findings, project, config, progress=progress)
    result = ScanResult(
        target=str(project.root),
        started_at=started,
        argus_version=__version__,
        scanners_run=list(imported.tools),
        findings=findings,
    )
    result.project_summary = project.summary()
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
    findings, merged = process_imported(
        imported.findings, project, config, progress=progress, native=result.findings
    )
    result.findings = findings
    result.scanners_run.extend(t for t in imported.tools if t not in result.scanners_run)
    result.project_summary["imported_sarif"] = {**imported.summary(), "merged": merged}
    result.findings = result.sorted_findings()
    return merged
