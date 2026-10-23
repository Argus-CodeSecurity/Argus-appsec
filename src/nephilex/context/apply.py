"""Apply path-based project context to findings.

Three settings change findings after the scanners ran:

* ``internal_paths``: code that is not reachable from outside. Each finding
  there is lowered one severity level and tagged ``internal``. It is never
  dropped: "internal" is a claim about deployment that can stop being true.
* ``exposure``: per-path notes. ``public_api`` / ``public_web`` raise the
  likelihood one step, ``internal_service`` / ``offline`` lower it.
* ``data_classification``: paths or models holding sensitive data. A finding
  there (severity Low or above) is raised one severity level and tagged
  ``sensitive-data``.

Every finding that is changed gets ``metadata["context"]`` with the original
values and one entry per rule that applied, so a reviewer can see exactly
what the context file did and why.
"""

from __future__ import annotations

import fnmatch
import re
from typing import Any

from nephilex.context.schema import EXPOSURE_LEVELS, ProjectContext
from nephilex.core.models import Finding, Likelihood, Severity


def path_matches(path: str, glob: str) -> bool:
    """Whether a project-relative ``path`` matches ``glob``.

    The same rules as the allowlist: a full-path ``fnmatch`` (``*`` crosses
    ``/``), a ``dir/**`` prefix, and, for a glob without ``/``, the file name.
    """
    p = (path or "").replace("\\", "/").removeprefix("./")
    if fnmatch.fnmatchcase(p, glob):
        return True
    if glob.endswith("/**") and (p.startswith(glob[:-2]) or p == glob[:-3]):
        return True
    return "/" not in glob and fnmatch.fnmatchcase(p.rsplit("/", 1)[-1], glob)


def _model_in(model: str, finding: Finding) -> bool:
    text = finding.location.snippet or ""
    short = model.rsplit(".", 1)[-1]
    return bool(re.search(rf"(?<![A-Za-z0-9_$]){re.escape(short)}(?![A-Za-z0-9_$])", text))


def _record(
    finding: Finding,
    context: ProjectContext,
    change: dict[str, Any],
    original: tuple[Severity, Likelihood],
) -> None:
    meta = finding.metadata.get("context")
    if not isinstance(meta, dict):
        meta = {
            "source": context.source or ".nephilex/context.yml",
            "original_severity": original[0].name.lower(),
            "original_likelihood": original[1].name.lower(),
            "changes": [],
        }
        finding.metadata["context"] = meta
    meta["changes"].append(change)


def _tag(finding: Finding, *tags: str) -> None:
    for tag in tags:
        if tag not in finding.tags:
            finding.tags.append(tag)


def apply_context(findings: list[Finding], context: ProjectContext | None) -> dict[str, int]:
    """Adjust ``findings`` in place from the path-based context settings.

    Returns counts per effect for the scan summary.
    """
    counts = {"internal": 0, "exposure": 0, "sensitive_data": 0}
    if context is None or not (
        context.internal_paths or context.exposure or context.data_classification
    ):
        return counts
    for f in findings:
        path = f.location.path
        original = (f.severity, f.likelihood)

        # Sensitive data first: raising and then lowering keeps both visible
        # in the change log, and the net result does not depend on order.
        for dc in context.data_classification:
            by_path = dc.path is not None and path_matches(path, dc.path)
            by_model = dc.model is not None and _model_in(dc.model, f)
            if not (by_path or by_model):
                continue
            before = f.severity
            if f.severity >= Severity.LOW:
                f.severity = Severity(min(Severity.CRITICAL, f.severity + 1))
            _tag(f, "sensitive-data", *dc.classes)
            _record(
                f,
                context,
                {
                    "setting": "data_classification",
                    "match": f"path {dc.path}" if by_path else f"model {dc.model}",
                    "classes": list(dc.classes),
                    "effect": f"severity {before.name.lower()} -> {f.severity.name.lower()}",
                    "why": dc.note
                    or f"code here handles {', '.join(dc.classes)} data, so impact is higher",
                },
                original,
            )
            counts["sensitive_data"] += 1
            break

        for ip in context.internal_paths:
            if not path_matches(path, ip.path):
                continue
            before = f.severity
            f.severity = Severity(max(Severity.INFO, f.severity - 1))
            _tag(f, "internal")
            _record(
                f,
                context,
                {
                    "setting": "internal_paths",
                    "match": ip.path,
                    "effect": f"severity {before.name.lower()} -> {f.severity.name.lower()}",
                    "why": ip.note or "declared not reachable from outside the organisation",
                },
                original,
            )
            counts["internal"] += 1
            break

        for ex in context.exposure:
            if not path_matches(path, ex.path):
                continue
            step = EXPOSURE_LEVELS[ex.level]
            before_l = f.likelihood
            f.likelihood = Likelihood(
                max(Likelihood.RARE, min(Likelihood.ALMOST_CERTAIN, f.likelihood + step))
            )
            _tag(f, f"exposure:{ex.level}")
            _record(
                f,
                context,
                {
                    "setting": "exposure",
                    "match": ex.path,
                    "level": ex.level,
                    "effect": (
                        f"likelihood {before_l.name.lower()} -> {f.likelihood.name.lower()}"
                    ),
                    "why": ex.note or f"declared {ex.level.replace('_', ' ')}",
                },
                original,
            )
            counts["exposure"] += 1
            break
    return counts


def original_severity(finding: Finding) -> Severity:
    """The severity a finding had before the context changed it."""
    meta = finding.metadata.get("context")
    if isinstance(meta, dict) and isinstance(meta.get("original_severity"), str):
        try:
            return Severity.parse(meta["original_severity"])
        except ValueError:
            pass
    return finding.severity
