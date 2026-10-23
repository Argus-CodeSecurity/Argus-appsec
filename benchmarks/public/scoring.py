"""Pure scoring functions for the public labeled-dataset benchmark.

Nothing here touches the filesystem or runs a tool, so it is unit tested in
``tests/test_public_benchmark_scoring.py``. Tool output is first normalized into
:class:`Finding` records (see ``tools.py``), then scored against the dataset
labels.

Conventions:

* A metric whose denominator is zero is ``None`` (reported as ``n/a``), never 1.0
  or 0.0, so an empty category cannot look like a perfect or a failed one.
* Metrics are rounded to 4 decimal places with Python's ``round`` (half to even)
  for every tool alike. Raw counts are always published next to them.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from benchmarks.public.mapping import accepted_cwes, mapped_cwes

MODES = ("strict", "mapped")

_CWE_RE = re.compile(r"(?i)^\s*(?:cwe-?)?0*(\d+)\b")
_OWASP_CASE_RE = re.compile(r"(?:^|/)(BenchmarkTest\d{5})\.py$")


@dataclass(frozen=True)
class Finding:
    """One tool finding, normalized across tools."""

    file: str  # POSIX path relative to the scanned root
    line: int
    rule_id: str
    cwes: frozenset[int]


@dataclass(frozen=True)
class OwaspCase:
    test_id: str
    category: str
    cwe: int
    vulnerable: bool


@dataclass(frozen=True)
class LabeledSample:
    """A sample that is labeled vulnerable to ``cwe`` (no negatives)."""

    sample_id: str
    cwe: int


def parse_cwe(value: object) -> int | None:
    """Parse ``78``, ``"78"``, ``"CWE-78"`` or ``"CWE-078: OS Command ..."``."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value > 0 else None
    if not isinstance(value, str):
        return None
    m = _CWE_RE.match(value)
    if not m:
        return None
    n = int(m.group(1))
    return n if n > 0 else None


def parse_cwes(values: Iterable[object]) -> frozenset[int]:
    return frozenset(c for c in (parse_cwe(v) for v in values) if c is not None)


def owasp_case_id(path: str) -> str | None:
    """Map a finding's file path to an OWASP Benchmark test case id."""
    m = _OWASP_CASE_RE.search(path.replace("\\", "/"))
    return m.group(1) if m else None


def finding_matches(tool: str, finding: Finding, label: int, mode: str) -> bool:
    """Does ``finding`` count as a detection of CWE ``label`` under ``mode``?"""
    if mode == "strict":
        return label in finding.cwes
    if mode == "mapped":
        return bool(mapped_cwes(tool, finding.rule_id, finding.cwes) & accepted_cwes(label))
    raise ValueError(f"unknown mode {mode!r}")


def _ratio(num: int, den: int) -> float | None:
    return num / den if den else None


def _r(x: float | None) -> float | None:
    return None if x is None else round(x, 4)


def confusion_metrics(tp: int, fp: int, tn: int, fn: int) -> dict[str, object]:
    """Counts plus TPR, FPR, precision, F1 and the OWASP score (TPR - FPR)."""
    tpr = _ratio(tp, tp + fn)
    fpr = _ratio(fp, fp + tn)
    precision = _ratio(tp, tp + fp)
    f1: float | None = None
    if precision is not None and tpr is not None and (precision + tpr) > 0:
        f1 = 2 * precision * tpr / (precision + tpr)
    elif precision is not None and tpr is not None:
        f1 = 0.0
    score = tpr - fpr if tpr is not None and fpr is not None else None
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "tpr": _r(tpr),
        "fpr": _r(fpr),
        "precision": _r(precision),
        "recall": _r(tpr),
        "f1": _r(f1),
        "score": _r(score),
    }


def _mean(values: list[float | None]) -> float | None:
    present = [v for v in values if v is not None]
    return sum(present) / len(present) if present else None


def score_owasp(
    cases: Iterable[OwaspCase], findings: Iterable[Finding], tool: str, mode: str
) -> dict[str, object]:
    """Score one tool on OWASP Benchmark cases.

    A test case is *flagged* when the tool reports at least one finding in that
    test case's file whose CWE matches the case's labeled CWE (OWASP Benchmark
    methodology). Findings with other CWEs in the same file are ignored for that
    case, exactly as the official scorecard ignores them.
    """
    cases = list(cases)
    cwe_of = {c.category: c.cwe for c in cases}
    by_case: dict[str, list[Finding]] = {}
    for f in findings:
        cid = owasp_case_id(f.file)
        if cid is not None:
            by_case.setdefault(cid, []).append(f)

    tallies: dict[str, dict[str, int]] = {}
    lists: dict[str, dict[str, list[str]]] = {}
    for case in sorted(cases, key=lambda c: c.test_id):
        t = tallies.setdefault(case.category, {"tp": 0, "fp": 0, "tn": 0, "fn": 0})
        lst = lists.setdefault(case.category, {"fp_cases": [], "fn_cases": []})
        flagged = any(
            finding_matches(tool, f, case.cwe, mode) for f in by_case.get(case.test_id, [])
        )
        if case.vulnerable and flagged:
            t["tp"] += 1
        elif case.vulnerable:
            t["fn"] += 1
            lst["fn_cases"].append(case.test_id)
        elif flagged:
            t["fp"] += 1
            lst["fp_cases"].append(case.test_id)
        else:
            t["tn"] += 1

    per_category: dict[str, dict[str, object]] = {}
    for name in sorted(tallies):
        t = tallies[name]
        entry: dict[str, object] = {"cwe": cwe_of[name]}
        entry.update(confusion_metrics(t["tp"], t["fp"], t["tn"], t["fn"]))
        entry.update(lists[name])
        per_category[name] = entry

    pooled = {k: sum(t[k] for t in tallies.values()) for k in ("tp", "fp", "tn", "fn")}
    overall = confusion_metrics(pooled["tp"], pooled["fp"], pooled["tn"], pooled["fn"])
    # The official OWASP scorecard reports the unweighted mean over categories.
    # Averages are taken over unrounded per-category values.
    raw = [_raw_rates(t["tp"], t["fp"], t["tn"], t["fn"]) for _, t in sorted(tallies.items())]
    overall["category_average"] = {
        "tpr": _r(_mean([r[0] for r in raw])),
        "fpr": _r(_mean([r[1] for r in raw])),
        "score": _r(_mean([r[2] for r in raw])),
    }
    return {"per_category": per_category, "overall": overall}


def _raw_rates(tp: int, fp: int, tn: int, fn: int) -> tuple[float | None, ...]:
    tpr = _ratio(tp, tp + fn)
    fpr = _ratio(fp, fp + tn)
    score = tpr - fpr if tpr is not None and fpr is not None else None
    return tpr, fpr, score


def score_labeled_recall(
    samples: Iterable[LabeledSample],
    findings: Iterable[Finding],
    tool: str,
    mode: str,
) -> dict[str, object]:
    """Recall on a positives-only dataset such as SecurityEval.

    ``mode`` is ``strict`` or ``mapped`` (CWE must match), or ``any`` (any
    finding in the sample's file counts, whatever its CWE). There are no
    negative samples, so precision, FPR and F1 cannot be computed.
    """
    if mode not in (*MODES, "any"):
        raise ValueError(f"unknown mode {mode!r}")
    by_file: dict[str, list[Finding]] = {}
    for f in findings:
        by_file.setdefault(f.file.replace("\\", "/").rsplit("/", 1)[-1], []).append(f)

    counts: dict[int, list[int]] = {}  # cwe -> [samples, detected]
    missed: dict[int, list[str]] = {}
    for s in sorted(samples, key=lambda x: x.sample_id):
        c = counts.setdefault(s.cwe, [0, 0])
        c[0] += 1
        hits = by_file.get(s.sample_id, [])
        if mode == "any":
            detected = bool(hits)
        else:
            detected = any(finding_matches(tool, f, s.cwe, mode) for f in hits)
        if detected:
            c[1] += 1
        else:
            missed.setdefault(s.cwe, []).append(s.sample_id)

    per_cwe: dict[str, object] = {}
    recalls: list[float | None] = []
    for cwe in sorted(counts):
        n, d = counts[cwe]
        rec = _ratio(d, n)
        recalls.append(rec)
        per_cwe[f"CWE-{cwe}"] = {
            "samples": n,
            "detected": d,
            "recall": _r(rec),
            "missed": missed.get(cwe, []),
        }
    total = sum(c[0] for c in counts.values())
    detected_total = sum(c[1] for c in counts.values())
    return {
        "per_cwe": per_cwe,
        "overall": {
            "samples": total,
            "detected": detected_total,
            "recall": _r(_ratio(detected_total, total)),
            "cwe_average_recall": _r(_mean(recalls)),
            "cwes": len(counts),
            "cwes_with_any_detection": sum(1 for c in counts.values() if c[1] > 0),
        },
    }
