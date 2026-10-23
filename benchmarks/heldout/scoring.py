"""Pure scoring for the held-out benchmark (no I/O; unit tested).

A case is one file changed by an advisory's fix commit. Tool findings are
normalized to :class:`benchmarks.public.scoring.Finding` (file, line, rule id,
CWEs) and attributed to a case and a version (vulnerable or patched) by the
harness. Definitions (also in ``docs/benchmarks.md``):

* A finding is *in the window* when its line is within ``window`` lines of a
  line the fix changed on that side.
* *Detected*: the vulnerable version has a matching finding in the window.
* *Flagged after the fix*: the patched version has a matching finding in the
  window. *Still flagged*: detected and flagged after the fix.
* Recall = detected / cases; fix-aware recall = (detected and not flagged
  after the fix) / cases; precision proxy = detected / (detected + flagged
  after the fix).

``mapped`` and ``strict`` CWE matching reuse the public benchmark's code and
tables unchanged; ``any`` ignores the CWE.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass

from benchmarks.public.scoring import Finding, finding_matches

MODES = ("mapped", "strict", "any")
WINDOW = 3
SENSITIVITY_WINDOWS = (0, 10)


@dataclass(frozen=True)
class Case:
    case_id: str
    ghsa_id: str
    ecosystem: str
    language: str
    labels: tuple[int, ...]
    vulnerable_lines: frozenset[int]
    patched_lines: frozenset[int]


@dataclass(frozen=True)
class Outcome:
    case_id: str
    detected: bool
    flagged_after_fix: bool

    @property
    def still_flagged(self) -> bool:
        return self.detected and self.flagged_after_fix

    @property
    def fix_aware(self) -> bool:
        return self.detected and not self.flagged_after_fix


def in_window(line: int, changed: frozenset[int], window: int) -> bool:
    """Is ``line`` within ``window`` lines of any changed line?"""
    if line <= 0 or not changed:
        return False
    return any(n in changed for n in range(line - window, line + window + 1))


def matches(tool: str, finding: Finding, labels: Sequence[int], mode: str) -> bool:
    if mode == "any":
        return True
    return any(finding_matches(tool, finding, label, mode) for label in labels)


def hits(
    tool: str,
    findings: Iterable[Finding],
    labels: Sequence[int],
    changed: frozenset[int],
    mode: str,
    window: int,
) -> list[Finding]:
    """Findings of one case/version that count under ``mode`` and ``window``."""
    return [
        f for f in findings if in_window(f.line, changed, window) and matches(tool, f, labels, mode)
    ]


def score_case(
    tool: str,
    case: Case,
    vulnerable: Iterable[Finding],
    patched: Iterable[Finding],
    mode: str,
    window: int = WINDOW,
) -> Outcome:
    v = hits(tool, vulnerable, case.labels, case.vulnerable_lines, mode, window)
    p = hits(tool, patched, case.labels, case.patched_lines, mode, window)
    return Outcome(case.case_id, detected=bool(v), flagged_after_fix=bool(p))


def _ratio(num: int, den: int) -> float | None:
    return round(num / den, 4) if den else None


def summarize(outcomes: Sequence[Outcome]) -> dict[str, object]:
    """Counts and rates for a set of case outcomes."""
    n = len(outcomes)
    detected = sum(o.detected for o in outcomes)
    flagged = sum(o.flagged_after_fix for o in outcomes)
    still = sum(o.still_flagged for o in outcomes)
    fix_aware = sum(o.fix_aware for o in outcomes)
    return {
        "cases": n,
        "detected": detected,
        "missed": n - detected,
        "flagged_after_fix": flagged,
        "still_flagged": still,
        "fix_aware_detected": fix_aware,
        "recall": _ratio(detected, n),
        "fix_aware_recall": _ratio(fix_aware, n),
        "precision_proxy": _ratio(detected, detected + flagged),
    }


def summarize_advisories(cases: Sequence[Case], outcomes: Sequence[Outcome]) -> dict[str, object]:
    """Advisory level: detected when any of its files is detected.

    Flagged after the fix when any of its patched files is flagged.
    """
    by_id = {o.case_id: o for o in outcomes}
    groups: dict[str, list[Outcome]] = {}
    for c in cases:
        if c.case_id in by_id:
            groups.setdefault(c.ghsa_id, []).append(by_id[c.case_id])
    merged = [
        Outcome(
            ghsa,
            detected=any(o.detected for o in group),
            flagged_after_fix=any(o.flagged_after_fix for o in group),
        )
        for ghsa, group in sorted(groups.items())
    ]
    out = summarize(merged)
    out["advisories"] = out.pop("cases")
    return out


def breakdown(
    cases: Sequence[Case],
    outcomes: Sequence[Outcome],
    key: Callable[[Case], Iterable[str]],
) -> dict[str, dict[str, object]]:
    """``summarize`` per group; a case may belong to several groups."""
    by_id = {o.case_id: o for o in outcomes}
    groups: dict[str, list[Outcome]] = {}
    for c in cases:
        if c.case_id not in by_id:
            continue
        for k in key(c):
            groups.setdefault(k, []).append(by_id[c.case_id])
    return {k: summarize(v) for k, v in sorted(groups.items(), key=lambda kv: _sort_key(kv[0]))}


def _sort_key(name: str) -> tuple[int, str]:
    tail = name.rsplit("-", 1)[-1]
    return (int(tail), name) if tail.isdigit() else (1 << 30, name)
