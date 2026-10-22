"""Baseline / diff-aware scanning support.

A *baseline* is a previously written Argus JSON report. Comparing the current
scan against it lets CI report and gate on **only new findings**, the single
most important feature for adopting a scanner on an existing codebase without
drowning in pre-existing debt.

Matching is by :meth:`~argus.core.models.Finding.fingerprint`, which is keyed on
the (whitespace-normalized) offending code rather than the raw line number, so a
finding is still recognized as "known" after unrelated edits move it.
"""

from __future__ import annotations

from pathlib import Path

from argus.core.models import Finding, ScanResult


class BaselineError(RuntimeError):
    """The baseline file could not be read or parsed."""


def load_fingerprints(path: str | Path) -> set[str]:
    """Return the set of finding fingerprints recorded in a baseline JSON report."""
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise BaselineError(f"Cannot read baseline {p}: {exc}") from exc
    try:
        result = ScanResult.model_validate_json(text)
    except ValueError as exc:
        raise BaselineError(f"Baseline {p} is not a valid Argus JSON report: {exc}") from exc
    return {f.fingerprint() for f in result.findings}


def filter_new(findings: list[Finding], known: set[str]) -> tuple[list[Finding], int]:
    """Split findings into (new, number_suppressed) against a set of fingerprints."""
    new = [f for f in findings if f.fingerprint() not in known]
    return new, len(findings) - len(new)
