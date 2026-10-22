"""Committed CWE mapping tables used by the public benchmark.

Every tool in this benchmark reports its own CWE ids: Argus findings carry a
``cwe`` list, Bandit JSON carries ``issue_cwe``, and Semgrep registry rules carry
``metadata.cwe``. Scoring is done on those tool-reported CWEs. Two scoring modes
are published side by side so the effect of this file is visible:

* ``strict``: a finding counts only when one of its tool-reported CWEs equals the
  labeled CWE exactly. Nothing in this file is used.
* ``mapped``: a finding counts when one of its CWEs (tool-reported, plus any
  manual rule override below) is in the same equivalence group as the label.

Rules for editing this file, so the tables stay neutral between tools:

1. An equivalence group joins CWEs that describe the same weakness at different
   granularity (a parent and its children, or two ids the CWE list itself marks
   as overlapping). It applies to every tool equally.
2. A rule override is allowed only when the rule's documented purpose is exactly
   one weakness and the tool reports a generic or missing CWE for it. Each
   override names the tool, the rule id and the reason. Overrides only ever add
   a CWE; they never remove one.
"""

from __future__ import annotations

# Equivalence groups. The accepted set for a labeled CWE is the label itself plus
# every group that contains it.
EQUIVALENCE_GROUPS: dict[str, frozenset[int]] = {
    # CWE-22 path traversal and its relative/absolute children, CWE-73 external
    # control of a file name, CWE-99 resource injection (SecurityEval uses it for
    # file-path cases).
    "path-traversal": frozenset({22, 23, 36, 73, 99}),
    # CWE-78 is a child of CWE-77; CWE-88 is argument injection into a command.
    "os-command-injection": frozenset({77, 78, 88}),
    # CWE-95 eval injection is a child of CWE-94 code injection.
    "code-injection": frozenset({94, 95}),
    # CWE-564 Hibernate/ORM SQL injection is a child of CWE-89.
    "sql-injection": frozenset({89, 564}),
    # CWE-80 basic XSS is a child of CWE-79.
    "xss": frozenset({79, 80}),
    # Weak hash: CWE-328 is a child of CWE-327; CWE-916 is weak password hashing.
    # Tools commonly report MD5/SHA1 under CWE-327.
    "weak-hash": frozenset({327, 328, 916}),
    # CWE-338 weak PRNG and CWE-331 insufficient entropy are children of CWE-330.
    "weak-random": frozenset({330, 331, 338}),
    # XML external entities (CWE-611) and entity expansion (CWE-776).
    "xml-entities": frozenset({611, 776}),
    # CWE-297 is a child of CWE-295 improper certificate validation.
    "tls-validation": frozenset({295, 297}),
    # CWE-259 hard-coded password and CWE-321 hard-coded key are children of 798.
    "hard-coded-credentials": frozenset({259, 321, 798}),
}

# Manual rule overrides: (tool, rule id) -> (extra CWEs, reason). Added after
# auditing the per-rule CWE inventory that every results file carries (the
# ``inventory`` block): only rules seen firing on a dataset, plus the documented
# siblings of a rule family, and only where the tool's own CWE is generic or
# names a different weakness than the rule's documented purpose. No Argus rule
# met that bar: every Argus rule that fired reported a specific, matching CWE.
_BANDIT_XML = (
    "Bandit XML blacklist, documented as XML attacks (XXE, entity expansion); Bandit reports CWE-20"
)
RULE_OVERRIDES: dict[tuple[str, str], tuple[frozenset[int], str]] = {
    **{
        ("bandit", test_id): (frozenset({611}), _BANDIT_XML)
        for test_id in (
            "B313",
            "B314",
            "B315",
            "B316",
            "B317",
            "B318",
            "B319",
            "B320",
            "B405",
            "B406",
            "B407",
            "B408",
            "B409",
            "B410",
        )
    },
    ("bandit", "B506"): (
        frozenset({502}),
        "yaml.load without a safe loader is unsafe deserialization; Bandit reports CWE-20",
    ),
    ("bandit", "B102"): (
        frozenset({95}),
        "exec() use is code injection; Bandit reports CWE-78 (OS command injection)",
    ),
    ("bandit", "B307"): (
        frozenset({95}),
        "eval() use is code injection; Bandit reports CWE-78 (OS command injection)",
    ),
    ("semgrep", "python.flask.security.injection.tainted-sql-string.tainted-sql-string"): (
        frozenset({89}),
        "tainted SQL string rule; its registry metadata says CWE-704 (type conversion)",
    ),
}


def accepted_cwes(label: int) -> frozenset[int]:
    """CWEs that count as a match for ``label`` in ``mapped`` mode."""
    out = {label}
    for group in EQUIVALENCE_GROUPS.values():
        if label in group:
            out |= group
    return frozenset(out)


def mapped_cwes(tool: str, rule_id: str, reported: frozenset[int]) -> frozenset[int]:
    """Tool-reported CWEs plus any committed override for this rule."""
    extra = RULE_OVERRIDES.get((tool, rule_id))
    return reported | extra[0] if extra else reported


def tables_snapshot() -> dict[str, object]:
    """The mapping tables as plain JSON data, embedded in every results file."""
    return {
        "equivalence_groups": {k: sorted(v) for k, v in EQUIVALENCE_GROUPS.items()},
        "rule_overrides": [
            {"tool": tool, "rule_id": rule, "adds_cwes": sorted(cwes), "reason": reason}
            for (tool, rule), (cwes, reason) in sorted(RULE_OVERRIDES.items())
        ],
    }
