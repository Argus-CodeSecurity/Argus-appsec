"""De-duplicate imported findings against Argus's own and each other.

When Argus and an imported tool (or two imported tools) report the same
weakness at the same place, the report should show it once. Two findings are
treated as the same issue when they come from different scanners, are in the
same file, and either

* both have a line, their start lines are at most :data:`DEDUPE_WINDOW` apart
  and they share at least one CWE, or
* both name the same advisory (CVE or GHSA id), as a dependency scanner and
  Trivy do for one vulnerable package.

The finding that is kept is Argus's own when there is one (it carries the
reasoning, remediation and fix support), otherwise the imported one with the
higher (severity, confidence), the first given on a tie. The kept finding
records the others under ``metadata["also_reported_by"]`` so the
corroboration is not lost, and takes the highest severity among them, so
folding a duplicate in can never make a ``--fail-on`` gate pass.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable

from argus.core.models import Finding

#: Start lines this far apart (or closer) count as the same location. Tools
#: disagree by a line or two on multi-line statements (where a call starts
#: versus where the tainted argument is).
DEDUPE_WINDOW = 2

# Findings Argus derives from other findings (attack chains).
_SYNTHETIC = "chains"

_ADVISORY = re.compile(r"\b(CVE-\d{4}-\d{4,}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3})\b", re.I)


def _advisories(f: Finding) -> set[str]:
    ids = {m.group(1).upper() for m in _ADVISORY.finditer(f.rule_id)}
    cve = f.metadata.get("cve")
    if isinstance(cve, str) and cve:
        ids.add(cve.upper())
    extra = f.metadata.get("advisories")
    if isinstance(extra, list):
        ids.update(a.upper() for a in extra if isinstance(a, str))
    return ids


def _distance(a: Finding, b: Finding) -> int:
    la, lb = a.location.start_line, b.location.start_line
    return abs(la - lb) if la is not None and lb is not None else 0


def _same_issue(a: Finding, b: Finding) -> bool:
    if a.scanner == b.scanner or a.location.path != b.location.path:
        return False
    if _SYNTHETIC in (a.scanner, b.scanner):
        return False  # an attack chain combines findings; it is not a duplicate
    adv_a, adv_b = _advisories(a), _advisories(b)
    if adv_a and adv_a & adv_b:
        return True
    la, lb = a.location.start_line, b.location.start_line
    if la is None or lb is None or not set(a.cwe) & set(b.cwe):
        return False
    return abs(la - lb) <= DEDUPE_WINDOW


def _record(kept: Finding, dup: Finding) -> None:
    also = kept.metadata.setdefault("also_reported_by", [])
    if not isinstance(also, list):
        return
    earlier = dup.metadata.get("also_reported_by")
    for entry in [*(earlier if isinstance(earlier, list) else []), _entry(dup)]:
        if entry not in also:
            also.append(entry)
    if dup.severity > kept.severity:
        # Fail safe: a gate must not pass because a duplicate that another
        # tool rated higher was folded into a lower-rated finding.
        kept.metadata["severity_raised_by"] = dup.scanner
        kept.severity = dup.severity


def _entry(f: Finding) -> dict[str, str]:
    return {"scanner": f.scanner, "rule_id": f.rule_id, "id": f.id}


def merge_findings(
    native: Iterable[Finding], imported: Iterable[Finding]
) -> tuple[list[Finding], int]:
    """Return ``native`` plus the imported findings that are not duplicates.

    The second value is how many imported findings were folded into another
    finding. ``native`` findings are never dropped; between two imported
    findings the higher (severity, confidence) one is kept. The kept finding
    takes the higher severity of the two.
    """
    kept = list(native)
    native_ids = {id(f) for f in kept}
    by_path: dict[str, list[Finding]] = defaultdict(list)
    for f in kept:
        by_path[f.location.path].append(f)
    merged = 0
    for f in imported:
        bucket = by_path[f.location.path]
        candidates = [k for k in bucket if _same_issue(k, f)]
        # The closest report wins; on a tie, the earliest (Argus's own first).
        match = min(candidates, key=lambda k: _distance(k, f), default=None)
        if match is None:
            kept.append(f)
            bucket.append(f)
            continue
        merged += 1
        if id(match) not in native_ids and (f.severity, f.confidence) > (
            match.severity,
            match.confidence,
        ):
            # Both imported: the stronger report becomes the representative.
            _record(f, match)
            for seq in (kept, bucket):
                seq[next(i for i, k in enumerate(seq) if k is match)] = f
        else:
            _record(match, f)
    return kept, merged
