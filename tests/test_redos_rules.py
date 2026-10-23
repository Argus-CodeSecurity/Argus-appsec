"""ReDoS guard: Nephilex runs hundreds of regexes against untrusted files, so a rule
with catastrophic backtracking would let a crafted file hang a scan (a DoS on the
customer's CI pipeline). This test runs every rule/module regex against adversarial
inputs under a strict time budget. A vulnerable regex blows up to seconds on these
inputs, while a safe one stays sub-millisecond, so the budget cleanly separates
them and this fails CI if a new rule regresses.

The scanners cap matched lines at ~2000 chars, so the adversarial inputs stay at
that bound: this measures the worst case the engine can actually feed a regex.
"""

from __future__ import annotations

import re
import time

from nephilex.scanners import ast_python, llm, patterns

# Generous: catastrophic backtracking produces seconds-to-minutes on these inputs,
# a safe regex is microseconds, so 0.5s never false-fails yet always catches ReDoS.
_BUDGET_SECONDS = 0.5
_N = 2000  # the scanners' per-line length cap


def _adversarial_inputs() -> list[str]:
    return [
        "a" * _N,
        "a" * (_N - 1) + "!",
        "a=" * (_N // 2),
        '"' + "a" * (_N - 2) + '"',
        "(" * (_N // 2) + ")" * (_N // 2),
        " " * _N,
        "subprocess.run(" + "x," * 300 + "shell=True)",
        "execute(" + "'a'+" * 300 + "value)",
        "sk-" + "A" * (_N - 3),
    ]


def _all_patterns() -> dict[str, re.Pattern]:
    pats: dict[str, re.Pattern] = {}
    for mod in (patterns, llm, ast_python):
        for name, val in vars(mod).items():
            if isinstance(val, re.Pattern):
                pats[f"{mod.__name__}.{name}"] = val
    for rule in getattr(patterns, "RULES", []):
        pats[f"patterns.rule.{rule.id}"] = rule.pattern
        if rule.suppress:
            pats[f"patterns.rule.{rule.id}.suppress"] = rule.suppress
    for rule in getattr(llm, "RULES", []):
        pats[f"llm.rule.{rule.id}"] = rule.pattern
        if rule.suppress:
            pats[f"llm.rule.{rule.id}.suppress"] = rule.suppress
    for sink_id, sink_re, *_ in getattr(llm, "_OUTPUT_SINKS", []):
        pats[f"llm.sink.{sink_id}"] = sink_re
    for sink in getattr(ast_python, "SINKS", []):
        pats[f"ast_python.sink.{sink.id}"] = sink.fn
    return pats


def test_rule_regexes_have_no_catastrophic_backtracking():
    inputs = _adversarial_inputs()
    slow: list[str] = []
    for name, pat in _all_patterns().items():
        for s in inputs:
            start = time.perf_counter()
            pat.search(s)
            elapsed = time.perf_counter() - start
            if elapsed > _BUDGET_SECONDS:
                slow.append(f"{name} took {elapsed:.2f}s")
    assert not slow, "Potentially ReDoS-vulnerable regex(es): " + "; ".join(slow)


def test_pattern_inventory_is_non_trivial():
    # Guard against the collection silently returning nothing (which would make the
    # ReDoS test vacuously pass).
    assert len(_all_patterns()) > 20
