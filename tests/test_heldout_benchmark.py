"""Unit tests for the held-out benchmark (benchmarks/heldout).

The selection rule decides which real fix commits become cases and the scoring
code decides every published number, so both are pinned here with small
synthetic inputs: commit-link parsing, file eligibility, changed-line
extraction from a diff, the line window, CWE matching, the metrics and the
per-advisory roll-up.
"""

from __future__ import annotations

import pytest
from benchmarks.heldout import fetch, selection
from benchmarks.heldout import scoring as hs
from benchmarks.public.scoring import Finding

# --- selection ------------------------------------------------------------------


def test_fix_commits_parses_commit_and_pull_commit_links() -> None:
    refs = [
        "https://github.com/advisories/GHSA-xxxx-xxxx-xxxx",
        "https://github.com/Owner/Repo/commit/ABCDEF1234567890abcdef1234567890abcdef12",
        "https://github.com/owner/repo/commit/abcdef1234567890abcdef1234567890abcdef12",
        "https://github.com/o/r/pull/12/commits/1234567",
        "https://github.com/o/r/pull/12",
        "https://github.com/o/r/releases/tag/v1.0",
        "https://gitlab.com/o/r/-/commit/1234567",
    ]
    out = selection.fix_commits(refs)
    # The same commit written with different case is used once.
    assert [(c.repo, c.sha) for c in out] == [
        ("Owner/Repo", "abcdef1234567890abcdef1234567890abcdef12"),
        ("o/r", "1234567"),
    ]


@pytest.mark.parametrize(
    ("path", "reason"),
    [
        ("src/app/views.py", None),
        ("lib/server.ts", None),
        ("web/static/app.jsx", None),
        ("tests/test_views.py", "test file"),
        ("pkg/test_views.py", "test file"),
        ("pkg/views_test.py", "test file"),
        ("conftest.py", "test file"),
        ("weblate/api/tests.py", "test file"),
        ("test.py", "test file"),
        ("lib/tests.js", "test file"),
        ("app/testing_utils.py", None),
        ("src/__tests__/a.js", "test file"),
        ("src/a.spec.ts", "test file"),
        ("src/a.test.mjs", "test file"),
        ("docs/conf.py", "documentation or example file"),
        ("examples/demo.py", "documentation or example file"),
        ("vendor/lib.js", "vendored or build output"),
        ("app/dist/bundle.js", "vendored or build output"),
        ("static/jquery.min.js", "minified or generated file"),
        ("proto/api_pb2.py", "minified or generated file"),
        ("types/index.d.ts", "not a Python or JavaScript/TypeScript source file"),
        ("README.md", "not a Python or JavaScript/TypeScript source file"),
        ("templates/page.html", "not a Python or JavaScript/TypeScript source file"),
    ],
)
def test_exclusion_reason(path: str, reason: str | None) -> None:
    assert selection.exclusion_reason(path) == reason


def test_language_of() -> None:
    assert selection.language_of("a/b.py") == "python"
    assert selection.language_of("a/b.cjs") == "javascript"
    assert selection.language_of("a/b.tsx") == "typescript"
    assert selection.language_of("a/b.d.ts") is None
    assert selection.language_of("a/b.go") is None


def test_advisory_label_keeps_only_target_cwes() -> None:
    assert selection.advisory_label(["CWE-79", "CWE-20", "CWE-200"]) == [79]
    # Family members of a claimed CWE are targets too (CWE-23 is in the
    # path-traversal group, CWE-88 in the command-injection group).
    assert selection.advisory_label(["CWE-23", "CWE-88"]) == [23, 88]
    assert selection.advisory_label(["CWE-400"]) == []
    assert {22, 78, 79, 89, 94, 502, 611, 918, 601} <= selection.TARGET_CWES


def test_sample_order_is_stable_and_case_insensitive() -> None:
    a = selection.sample_order("GHSA-abcd-efgh-ijkl")
    assert a == selection.sample_order("ghsa-abcd-efgh-ijkl")
    assert a != selection.sample_order("GHSA-abcd-efgh-ijkm")


PATCH = """@@ -10,6 +10,7 @@ def view(request):
     a = 1
     b = 2
-    run(cmd + user)
+    check(user)
+    run(cmd, user)
     c = 3
     d = 4
     e = 5
@@ -40,4 +41,6 @@ def other():
     x = 1
     y = 2
+    guard()
+    guard2()
     z = 3
     w = 4
@@ -60,4 +63,3 @@ def gone():
     p = 1
-    q = 2
     r = 3
     s = 4
"""


def test_changed_lines_from_patch() -> None:
    ch = selection.changed_lines(PATCH)
    # Hunk 1: line 12 replaced by new lines 12-13.
    # Hunk 2: pure insertion of new lines 43-44 between old lines 41 and 42.
    # Hunk 3: pure deletion of old line 61, between new lines 63 and 64.
    assert ch.old == {12, 41, 42, 61}
    assert ch.new == {12, 13, 43, 44, 63, 64}


def test_changed_lines_ignores_no_newline_marker() -> None:
    patch = (
        "@@ -1,2 +1,2 @@\n a\n-b\n\\ No newline at end of file\n+c\n\\ No newline at end of file\n"
    )
    ch = selection.changed_lines(patch)
    assert ch.old == {2}
    assert ch.new == {2}


def test_ranges_round_trip() -> None:
    lines = {1, 2, 3, 7, 9, 10}
    ranges = selection.to_ranges(lines)
    assert ranges == [[1, 3], [7, 7], [9, 10]]
    assert selection.from_ranges(ranges) == lines


def test_local_relpath_keeps_tail_and_renames_skipped_dirs() -> None:
    assert fetch.local_relpath("a/b/c/d/views.py") == "c/d/views.py"
    assert fetch.local_relpath("src/env/target/x.py") == "env_/target_/x.py"
    assert fetch.local_relpath("x.py") == "x.py"
    assert fetch.local_relpath("../../etc/x.py") == "etc/x.py"


# --- scoring --------------------------------------------------------------------


def _case(
    cid: str = "c1",
    ghsa: str = "GHSA-1",
    labels: tuple[int, ...] = (78,),
    vuln: set[int] | None = None,
    patched: set[int] | None = None,
    language: str = "python",
) -> hs.Case:
    return hs.Case(
        case_id=cid,
        ghsa_id=ghsa,
        ecosystem="pip",
        language=language,
        labels=labels,
        vulnerable_lines=frozenset(vuln if vuln is not None else {20}),
        patched_lines=frozenset(patched if patched is not None else {20, 21}),
    )


def _f(line: int, *cwes: int, rule: str = "r") -> Finding:
    return Finding(file="x.py", line=line, rule_id=rule, cwes=frozenset(cwes))


def test_in_window() -> None:
    changed = frozenset({20})
    assert hs.in_window(20, changed, 0)
    assert not hs.in_window(21, changed, 0)
    assert hs.in_window(23, changed, 3)
    assert hs.in_window(17, changed, 3)
    assert not hs.in_window(24, changed, 3)
    assert not hs.in_window(0, changed, 100)  # line 0 means "no location"
    assert not hs.in_window(20, frozenset(), 3)


def test_detected_needs_matching_cwe_in_window() -> None:
    case = _case()
    assert hs.score_case("nephilex", case, [_f(22, 78)], [], "mapped").detected
    # Right CWE, outside the window.
    assert not hs.score_case("nephilex", case, [_f(30, 78)], [], "mapped").detected
    # In the window, wrong CWE: only the CWE-agnostic mode counts it.
    assert not hs.score_case("nephilex", case, [_f(20, 89)], [], "mapped").detected
    assert hs.score_case("nephilex", case, [_f(20, 89)], [], "any").detected
    # Findings without a CWE count only in ``any`` mode.
    assert not hs.score_case("nephilex", case, [_f(20)], [], "strict").detected
    assert hs.score_case("nephilex", case, [_f(20)], [], "any").detected


def test_mapped_uses_equivalence_groups_and_overrides() -> None:
    # CWE-88 (argument injection) is in the command-injection group with 78.
    case = _case(labels=(88,))
    assert hs.score_case("nephilex", case, [_f(20, 78)], [], "mapped").detected
    assert not hs.score_case("nephilex", case, [_f(20, 78)], [], "strict").detected
    # Bandit B307 (eval) reports CWE-78; the committed override adds CWE-95.
    case94 = _case(labels=(94,))
    b307 = Finding(file="x.py", line=20, rule_id="B307", cwes=frozenset({78}))
    assert hs.score_case("bandit", case94, [b307], [], "mapped").detected
    assert not hs.score_case("bandit", case94, [b307], [], "strict").detected
    # The override is per tool: the same rule id from another tool gets nothing.
    assert not hs.score_case("semgrep", case94, [b307], [], "mapped").detected


def test_any_label_cwe_counts() -> None:
    case = _case(labels=(79, 94))
    assert hs.score_case("nephilex", case, [_f(20, 95)], [], "mapped").detected
    assert hs.score_case("nephilex", case, [_f(20, 79)], [], "strict").detected


def test_flagged_after_fix_uses_patched_lines() -> None:
    case = _case(vuln={20}, patched={40})
    out = hs.score_case("nephilex", case, [_f(20, 78)], [_f(41, 78)], "mapped")
    assert out.detected and out.flagged_after_fix and out.still_flagged and not out.fix_aware
    # A patched finding near the *vulnerable* side's lines does not count.
    out = hs.score_case("nephilex", case, [_f(20, 78)], [_f(20, 78)], "mapped")
    assert out.detected and not out.flagged_after_fix and out.fix_aware
    # Flagged after the fix without detection is a false positive only.
    out = hs.score_case("nephilex", case, [], [_f(40, 78)], "mapped")
    assert not out.detected and out.flagged_after_fix and not out.still_flagged


def test_summarize_counts_and_rates() -> None:
    outcomes = [
        hs.Outcome("a", detected=True, flagged_after_fix=False),
        hs.Outcome("b", detected=True, flagged_after_fix=True),
        hs.Outcome("c", detected=False, flagged_after_fix=True),
        hs.Outcome("d", detected=False, flagged_after_fix=False),
    ]
    m = hs.summarize(outcomes)
    assert m == {
        "cases": 4,
        "detected": 2,
        "missed": 2,
        "flagged_after_fix": 2,
        "still_flagged": 1,
        "fix_aware_detected": 1,
        "recall": 0.5,
        "fix_aware_recall": 0.25,
        "precision_proxy": 0.5,
    }


def test_summarize_empty_is_undefined_not_zero() -> None:
    m = hs.summarize([])
    assert m["cases"] == 0
    assert m["recall"] is None
    assert m["precision_proxy"] is None


def test_precision_proxy_undefined_without_any_flag() -> None:
    m = hs.summarize([hs.Outcome("a", detected=False, flagged_after_fix=False)])
    assert m["recall"] == 0.0
    assert m["precision_proxy"] is None


def test_summarize_advisories_rolls_up_files() -> None:
    cases = [
        _case("c1", "GHSA-1"),
        _case("c2", "GHSA-1"),
        _case("c3", "GHSA-2"),
        _case("c4", "GHSA-3"),
    ]
    outcomes = [
        hs.Outcome("c1", detected=False, flagged_after_fix=False),
        hs.Outcome("c2", detected=True, flagged_after_fix=False),
        hs.Outcome("c3", detected=False, flagged_after_fix=True),
        hs.Outcome("c4", detected=False, flagged_after_fix=False),
    ]
    m = hs.summarize_advisories(cases, outcomes)
    assert m["advisories"] == 3
    assert m["detected"] == 1
    assert m["flagged_after_fix"] == 1
    assert m["recall"] == round(1 / 3, 4)


def test_breakdown_counts_multi_label_case_in_each_group() -> None:
    cases = [_case("c1", labels=(79, 94)), _case("c2", labels=(94,)), _case("c3", labels=(22,))]
    outcomes = [
        hs.Outcome("c1", detected=True, flagged_after_fix=False),
        hs.Outcome("c2", detected=False, flagged_after_fix=False),
        hs.Outcome("c3", detected=False, flagged_after_fix=False),
    ]
    by_cwe = hs.breakdown(cases, outcomes, lambda c: [f"CWE-{x}" for x in c.labels])
    assert list(by_cwe) == ["CWE-22", "CWE-79", "CWE-94"]  # numeric order
    assert by_cwe["CWE-94"]["cases"] == 2
    assert by_cwe["CWE-94"]["detected"] == 1
    assert by_cwe["CWE-79"]["detected"] == 1
    assert by_cwe["CWE-22"]["detected"] == 0


def test_breakdown_skips_cases_without_outcome() -> None:
    cases = [_case("c1"), _case("c2", language="typescript")]
    outcomes = [hs.Outcome("c1", detected=True, flagged_after_fix=False)]
    by_lang = hs.breakdown(cases, outcomes, lambda c: [c.language])
    assert list(by_lang) == ["python"]
